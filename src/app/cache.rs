use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::api::types::{Guest, Node, StoragePool};

/// Open a connection and apply concurrency-safe pragmas.
///
/// SPOF 4.3 (Category 4 audit): without these, two processes (e.g. the
/// TUI saving state while a `proxxx replay` CLI reads) collide on
/// `SQLite`'s default rollback-journal exclusive lock, surface
/// `SQLITE_BUSY` instantly (default `busy_timeout` is 0), and the
/// loser fails — silently in the writer's case (logged at warn but not
/// shown to the user), loudly in the reader's case (returns Err and the
/// CLI bails).
///
/// Pragmas applied:
/// - `journal_mode = WAL` — readers do not block writers and vice versa.
///   The WAL file lives next to the DB; standard `SQLite` tooling handles
///   it transparently.
/// - `busy_timeout = 5000` — if a write does contend (rare under WAL,
///   only on schema changes / WAL checkpoint), wait up to 5 s before
///   surfacing `SQLITE_BUSY`. Five seconds is comfortably above any
///   single transaction in this module.
/// - `synchronous = NORMAL` — appropriate durability for a cache
///   (we tolerate losing the last unflushed transaction on a kernel
///   crash; the data is recoverable from Proxmox API on next sync).
/// (macro audit) — current schema version.
///
/// Bumped whenever the on-disk `SQLite` schema changes (new column,
/// renamed table, etc.). The `migrate_schema` function runs every
/// `open_db` call and steps a stale DB forward to `SCHEMA_VERSION`.
///
/// Bump procedure:
/// 1. Increment `SCHEMA_VERSION`.
/// 2. Add a new arm in `migrate_schema` for the previous → new
///    transition. Use `ALTER TABLE … ADD COLUMN …` (idempotent under
///    `IF NOT EXISTS` is unfortunately not SQLite-supported, so wrap
///    in a `pragma_query` first to detect the column).
/// 3. The `serde` payload schema in `ClusterStateCache` /
///    `PersistedQueueEntry` is independently backward-compatible
///    because every nullable field carries `#[serde(default)]` —
///    old JSON loads cleanly into a new struct shape.
const SCHEMA_VERSION: u32 = 3;

fn open_db(path: &Path) -> anyhow::Result<Connection> {
    // Ensure the parent directory exists before SQLite tries to open the file.
    // Without this, SQLite returns error code 14 ("unable to open database file")
    // with no indication of the real cause (missing directory vs permissions).
    if let Some(parent) = path.parent() {
        // Custody: the cache holds a cluster-topology snapshot + the op_queue.
        // Create the dir 0700 (unix) so it isn't group/world-readable on a
        // multi-user host. `create_dir_all` no-ops on an existing dir and does
        // NOT tighten its mode — an operator who pre-created a lax dir owns that
        // (see ACCEPTED-RISKS AR-8). The 0700 dir is the real guard: it blocks a
        // different user from reading the db OR its WAL sidecars regardless of
        // their own file modes.
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| {
                    anyhow::anyhow!(
                        "cannot create cache directory {}: {e} — check permissions",
                        parent.display()
                    )
                })?;
        }
        #[cfg(not(unix))]
        {
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow::anyhow!(
                    "cannot create cache directory {}: {e} — check permissions",
                    parent.display()
                )
            })?;
        }
    }
    let conn = Connection::open(path)?;
    // Tighten the DB file — and its WAL/SHM sidecars — to owner-only (0600).
    // A fresh SQLite file is created with the process umask (~0644); fresh
    // sidecars inherit the main db's mode, but a legacy 0644 `-wal` left by a
    // pre-hardening unclean shutdown would otherwise keep receiving topology +
    // op_queue writes group/world-readable, so tighten them explicitly too.
    // Best-effort: a perms error must not fail the cache open. (The 0700 parent
    // dir is the real guard; this is belt-and-suspenders on the files.)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let tighten = |p: &std::path::Path| {
            if let Ok(meta) = std::fs::metadata(p) {
                let mut perms = meta.permissions();
                if perms.mode() & 0o077 != 0 {
                    perms.set_mode(0o600);
                    let _ = std::fs::set_permissions(p, perms);
                }
            }
        };
        tighten(path);
        for suffix in ["-wal", "-shm"] {
            let mut side = path.as_os_str().to_owned();
            side.push(suffix);
            tighten(std::path::Path::new(&side));
        }
    }

    // — `auto_vacuum` is sticky: persisted in the DB header,
    // applied at table-creation time, never changeable afterwards.
    // We read first and only WRITE if it isn't already set: writing
    // unconditionally would acquire the schema lock and collide with
    // any open writer (proven by the
    // `reader_does_not_block_on_concurrent_writer` regression). Read
    // is lock-free; the write only happens once, on a brand-new file.
    let current_av: i64 = conn
        .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
        .unwrap_or(0);
    if current_av == 0 {
        // INCREMENTAL = 2. SQLite ignores the write silently if any
        // table has already been created; that's fine — the warning
        // path is documented in the comment below.
        conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;
    }
    // For DBs created by older proxxx without auto_vacuum the user
    // migrates with a one-shot
    // `sqlite3 <db> "PRAGMA auto_vacuum=INCREMENTAL; VACUUM;"`.

    // `pragma_update` is the right knob here for these scalars; the
    // setter rejects malformed values at compile-time arity.
    // journal_mode change requires `query_row` because SQLite returns
    // the resulting mode, but `pragma_update` works for write-only set.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    // (Gemini audit) — bound WAL growth.
    //
    // `wal_autocheckpoint = 1000` (pages) is the SQLite default, but
    // we pin it explicitly so a future SQLite default change can't
    // silently disable our checkpoint cadence. At the standard 4 KiB
    // page size that's ≈ 4 MiB max WAL before the writer auto-folds
    // it back into the main DB file.
    //
    // `journal_size_limit = 64 MiB` is the absolute cap. After a
    // checkpoint, SQLite truncates the WAL file back to this size if
    // it has grown beyond. Without this, an exceptionally large
    // single transaction can leave the WAL pinned at its peak size.
    //
    // ENOSPC handling: every PRAGMA / INSERT in this module returns
    // `Err` on disk-full. Callers in `tui/mod.rs` (`save_queue`) and
    // `save_state` log the failure via `warn!` and continue —
    // graceful degradation, no panic. The user keeps a working TUI
    // with no cache rather than a crashed app.
    conn.pragma_update(None, "wal_autocheckpoint", 1000)?;
    conn.pragma_update(None, "journal_size_limit", 64 * 1024 * 1024_i64)?;

    // — schema versioning + migration. Run BEFORE any DDL
    // (`init_db`) so a stale DB is brought up to current shape first.
    migrate_schema(&conn)?;

    Ok(conn)
}

/// Read `PRAGMA user_version` and step the schema forward.
///
/// `SQLite`'s `user_version` is a 32-bit integer in the database header,
/// initially 0 on a brand-new file. We treat 0 as "fresh / current"
/// and only run migration steps when an older proxxx wrote a lower
/// non-zero version. Each migration arm is idempotent so running
/// `open_db` twice in quick succession is safe.
fn migrate_schema(conn: &Connection) -> anyhow::Result<()> {
    let current: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if current == SCHEMA_VERSION {
        return Ok(());
    }
    if current > SCHEMA_VERSION {
        // The DB was written by a NEWER proxxx than this binary. We
        // refuse to touch it rather than risk corrupting the user's
        // data with a downgraded write path. Callers degrade
        // gracefully (load_state returns Err → TUI starts with empty
        // cache, not a crash).
        anyhow::bail!(
            "cache DB schema version {current} is newer than this binary's {SCHEMA_VERSION}; \
             upgrade proxxx or remove the cache file"
        );
    }
    // current < SCHEMA_VERSION — step forward. Today there is only
    // version 1 (the initial shape), so the migration ladder is
    // empty. The match below documents the future shape.
    let mut step = current;
    while step < SCHEMA_VERSION {
        match step {
            // 0 → 1: initial schema. The CREATE TABLE statements in
            // `init_db` / `init_queue_table` are idempotent and
            // already cover this; nothing to do here.
            0 => {}
            // 1 → 2: persist the alert daemon dedup window across
            // restarts. Without this, a routine daemon restart
            // (config reload, kernel update, accidental SIGHUP)
            // re-fires every active alert immediately — a single
            // restart could flood Telegram with 50 duplicate notices
            // for problems the operator already saw and acknowledged.
            // Idempotent — safe to re-run.
            1 => {
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS alert_dedup (
                        rule TEXT NOT NULL,
                        target TEXT NOT NULL,
                        last_fired INTEGER NOT NULL,
                        PRIMARY KEY (rule, target)
                    )",
                    [],
                )?;
            }
            // 2 → 3: persist the `reconcile watch` drift-state so the
            // separate `metrics serve` / `mcp serve` processes can surface
            // the daemon's latest drift result. Idempotent.
            2 => {
                init_reconcile_tables(conn)?;
            }
            // Future migration arms go here, one per version step.
            _ => anyhow::bail!("no migration path from schema version {step}"),
        }
        step += 1;
    }
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct ClusterStateCache {
    pub nodes: Vec<Node>,
    pub guests: Vec<Guest>,
    pub storage: Vec<StoragePool>,
    pub timestamp: u64,
}

fn get_db_dir() -> PathBuf {
    let mut path = dirs::cache_dir().unwrap_or_else(|| PathBuf::from("."));
    path.push("proxxx");
    path
}

fn get_db_path(profile_name: Option<&str>) -> PathBuf {
    let mut path = get_db_dir();
    let profile = profile_name.unwrap_or("default");
    path.push(format!("{profile}_state.db"));
    path
}

fn init_db(conn: &Connection) -> anyhow::Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER NOT NULL,
            data TEXT NOT NULL
        )",
        [],
    )?;
    Ok(())
}

pub fn load_state(profile_name: Option<&str>) -> anyhow::Result<ClusterStateCache> {
    let path = get_db_path(profile_name);
    let conn = open_db(&path)?;
    init_db(&conn)?;

    let mut stmt = conn.prepare("SELECT data FROM snapshots ORDER BY timestamp DESC LIMIT 1")?;
    let mut rows = stmt.query([])?;

    if let Some(row) = rows.next()? {
        let data: String = row.get(0)?;
        let cache: ClusterStateCache = serde_json::from_str(&data)?;
        Ok(cache)
    } else {
        anyhow::bail!("No cache found")
    }
}

/// Async wrapper around [`save_state`] — see [`save_queue_async`] for
/// the rationale. The cluster-state Vecs are owned by the caller's
/// `AppState` and live across iterations of the TUI run loop, so the
/// caller clones into owned Vecs before handing them off here.
pub async fn save_state_async(
    profile_name: Option<String>,
    nodes: Vec<Node>,
    guests: Vec<Guest>,
    storage: Vec<StoragePool>,
) -> anyhow::Result<()> {
    tokio::task::spawn_blocking(move || {
        save_state(profile_name.as_deref(), &nodes, &guests, &storage)
    })
    .await
    .map_err(|e| anyhow::anyhow!("save_state spawn_blocking join error: {e}"))?
}

pub fn save_state(
    profile_name: Option<&str>,
    nodes: &[Node],
    guests: &[Guest],
    storage: &[StoragePool],
) -> anyhow::Result<()> {
    let path = get_db_path(profile_name);
    let mut conn = open_db(&path)?;
    init_db(&conn)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("system clock is before UNIX epoch: {e}"))?
        .as_secs();

    let cache = ClusterStateCache {
        nodes: nodes.to_vec(),
        guests: guests.to_vec(),
        storage: storage.to_vec(),
        timestamp: now,
    };
    let data = serde_json::to_string(&cache)?;

    let tx = conn.transaction()?;
    tx.execute(
        "INSERT INTO snapshots (timestamp, data) VALUES (?1, ?2)",
        params![now as i64, data],
    )?;

    // Retention: keep only last 7 days of snapshots (7 * 24 * 60 * 60 = 604800 seconds)
    let cutoff = now.saturating_sub(604800);
    tx.execute(
        "DELETE FROM snapshots WHERE timestamp < ?1",
        params![cutoff as i64],
    )?;

    tx.commit()?;

    // — reclaim freelist pages back to the OS. Without this
    // the .db file grows monotonically (deleted rows leave free
    // pages SQLite reuses internally but never returns to the
    // filesystem). `incremental_vacuum` is a no-op when there's
    // nothing to reclaim, so it's safe to run on every save.
    // Best-effort: a transient I/O error here should not fail the
    // user's save (the data is already committed).
    if let Err(e) = conn.execute("PRAGMA incremental_vacuum", []) {
        tracing::debug!("incremental_vacuum skipped: {e}");
    }

    Ok(())
}

pub fn load_state_at(
    profile_name: Option<&str>,
    timestamp: u64,
) -> anyhow::Result<ClusterStateCache> {
    let path = get_db_path(profile_name);
    let conn = open_db(&path)?;
    init_db(&conn)?;

    // Get the snapshot that was active at the requested timestamp (the latest one before or exactly at the timestamp)
    let mut stmt = conn.prepare(
        "SELECT data FROM snapshots WHERE timestamp <= ?1 ORDER BY timestamp DESC LIMIT 1",
    )?;
    let mut rows = stmt.query(params![timestamp as i64])?;

    if let Some(row) = rows.next()? {
        let data: String = row.get(0)?;
        let cache: ClusterStateCache = serde_json::from_str(&data)?;
        Ok(cache)
    } else {
        anyhow::bail!("No snapshot found for the requested time")
    }
}

// ── Operation queue persistence (architectural review #2) ────
//
// The op_queue is in-memory only by default — if proxxx crashes or the
// user quits mid-operation, they lose track of running disk moves and
// the like. We persist the queue to SQLite and reload it on startup so
// the user can pick up where they left off.
//
// Note: this stores INTENT, not running tasks. A queued op that was
// already dispatched (status = Running) is on the Proxmox side as a
// UPID — we re-render it from disk so the user sees it, but we don't
// re-execute. Status updates resume on next poll.

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PersistedOp {
    StartGuest {
        vmid: u32,
    },
    StopGuest {
        vmid: u32,
        force: bool,
    },
    RestartGuest {
        vmid: u32,
    },
    DeleteGuest {
        vmid: u32,
    },
    MigrateGuest {
        vmid: u32,
        target_node: String,
    },
    MoveDisk {
        vmid: u32,
        disk: String,
        target_storage: String,
        delete_source: bool,
    },
    ResizeDisk {
        vmid: u32,
        disk: String,
        size: String,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PersistedOpStatus {
    Pending,
    Running,
    Success,
    Error(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PersistedQueueEntry {
    pub id: String,
    pub description: String,
    pub diff: String,
    pub status: PersistedOpStatus,
    pub op: PersistedOp,
    /// Unix seconds when the op was originally enqueued. Default 0 for
    /// entries serialized before the GC field was added — those look
    /// "ancient" to the GC and are evicted on the next sweep, which is
    /// the right behaviour for a stale persistence schema.
    #[serde(default)]
    pub created_at_secs: u64,
}

fn init_queue_table(conn: &Connection) -> anyhow::Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS op_queue (
            id TEXT PRIMARY KEY,
            entry TEXT NOT NULL,
            saved_at INTEGER NOT NULL
        )",
        [],
    )?;
    Ok(())
}

/// Async wrapper around [`save_queue`] for tokio contexts.
///
/// Phase 12 audit fix: the TUI render loop and the alerts daemon both
/// call cache writers on every tick. Each writer opens a `Connection`,
/// runs a `transaction()`, and commits — under WAL-checkpoint contention
/// the writer can block for up to the configured `busy_timeout` (5000 ms).
/// Called synchronously from an async task, that pin the runtime worker
/// thread for the full window — `q` keypresses lag, alerts skip ticks.
/// Same pattern as [`config::keyring_get`](crate::config) which already
/// uses `spawn_blocking` for the same reason on the keychain side.
///
/// Takes owned arguments because `spawn_blocking` requires `'static`;
/// caller clones if they need the values afterwards (cheap — the cache
/// types are small Vecs).
pub async fn save_queue_async(
    profile_name: Option<String>,
    entries: Vec<PersistedQueueEntry>,
) -> anyhow::Result<()> {
    tokio::task::spawn_blocking(move || save_queue(profile_name.as_deref(), &entries))
        .await
        .map_err(|e| anyhow::anyhow!("save_queue spawn_blocking join error: {e}"))?
}

/// Replace the persisted queue with the given entries (full overwrite).
/// Cheap with WAL on a few-dozen-row table; called on every queue mutation.
pub fn save_queue(
    profile_name: Option<&str>,
    entries: &[PersistedQueueEntry],
) -> anyhow::Result<()> {
    let path = get_db_path(profile_name);
    let mut conn = open_db(&path)?;
    init_queue_table(&conn)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM op_queue", [])?;
    for entry in entries {
        let json = serde_json::to_string(entry)?;
        tx.execute(
            "INSERT INTO op_queue (id, entry, saved_at) VALUES (?1, ?2, ?3)",
            params![entry.id, json, now as i64],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Load the most recently persisted queue entries, oldest-first
/// (preserves user's enqueue order).
pub fn load_queue(profile_name: Option<&str>) -> anyhow::Result<Vec<PersistedQueueEntry>> {
    let path = get_db_path(profile_name);
    let conn = open_db(&path)?;
    init_queue_table(&conn)?;

    let mut stmt = conn.prepare("SELECT entry FROM op_queue ORDER BY saved_at ASC, id ASC")?;
    let rows = stmt.query_map([], |row| {
        let raw: String = row.get(0)?;
        Ok(raw)
    })?;
    let mut out = Vec::new();
    for r in rows {
        let raw = r?;
        match serde_json::from_str::<PersistedQueueEntry>(&raw) {
            Ok(e) => out.push(e),
            Err(e) => {
                tracing::warn!("dropping unparseable persisted queue entry: {e:#}");
            }
        }
    }
    Ok(out)
}

/// Idempotent — `CREATE TABLE IF NOT EXISTS`. The migration ladder
/// already covers fresh installs (schema v2 creates this table), but
/// older proxxx installs that wrote v1 data still need the table on
/// first save. Cheap enough to call on every save/load.
fn init_alert_dedup_table(conn: &Connection) -> anyhow::Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS alert_dedup (
            rule TEXT NOT NULL,
            target TEXT NOT NULL,
            last_fired INTEGER NOT NULL,
            PRIMARY KEY (rule, target)
        )",
        [],
    )?;
    Ok(())
}

/// Replace the persisted alert-dedup window with the given entries
/// (full overwrite — matches `save_queue` semantics). Wrapped in a
/// transaction so a crash mid-save can't leave partial state. Called
/// after each daemon tick; cheap with WAL on a few-hundred-row table.
/// Async wrapper around [`save_alert_dedup`] — see [`save_queue_async`]
/// for the rationale. The alerts daemon calls this on every tick (every
/// `interval` seconds, default 30) AND on graceful shutdown; either
/// path is async, so wrapping moves the `SQLite` I/O off the runtime
/// worker.
pub async fn save_alert_dedup_async(
    profile_name: Option<String>,
    entries: Vec<(String, String, u64)>,
) -> anyhow::Result<()> {
    tokio::task::spawn_blocking(move || save_alert_dedup(profile_name.as_deref(), &entries))
        .await
        .map_err(|e| anyhow::anyhow!("save_alert_dedup spawn_blocking join error: {e}"))?
}

pub fn save_alert_dedup(
    profile_name: Option<&str>,
    entries: &[(String, String, u64)],
) -> anyhow::Result<()> {
    let path = get_db_path(profile_name);
    let mut conn = open_db(&path)?;
    init_alert_dedup_table(&conn)?;

    let tx = conn.transaction()?;
    tx.execute("DELETE FROM alert_dedup", [])?;
    for (rule, target, last_fired) in entries {
        tx.execute(
            "INSERT INTO alert_dedup (rule, target, last_fired) VALUES (?1, ?2, ?3)",
            params![rule, target, *last_fired as i64],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Load persisted alert-dedup entries. Returns an empty Vec if the
/// table is empty or missing — callers treat that as "fresh state",
/// matching `DedupCache::default()` semantics.
pub fn load_alert_dedup(profile_name: Option<&str>) -> anyhow::Result<Vec<(String, String, u64)>> {
    let path = get_db_path(profile_name);
    let conn = open_db(&path)?;
    init_alert_dedup_table(&conn)?;

    let mut stmt =
        conn.prepare("SELECT rule, target, last_fired FROM alert_dedup ORDER BY rule, target")?;
    let rows = stmt.query_map([], |row| {
        let rule: String = row.get(0)?;
        let target: String = row.get(1)?;
        let last_fired: i64 = row.get(2)?;
        Ok((rule, target, last_fired as u64))
    })?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r?);
    }
    Ok(out)
}

// ── Reconcile drift-state ──────────────────────────────────────────────
//
// The `reconcile watch` daemon pillar writes its latest drift result here
// so the SEPARATE `metrics serve` and `mcp serve` processes can read it.
// Single per-profile DB file (`{profile}_state.db`), WAL mode → a reader
// never blocks the writer. `reconcile_status` holds one summary row;
// `reconcile_drift` holds the per-family counts for `proxxx_drift_resources`.

/// Latest reconcile drift result, persisted by the watch loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileStatus {
    /// Unix seconds of the check that produced this result.
    pub last_check_ts: u64,
    /// `true` when live matched declared (no changes).
    pub in_sync: bool,
    /// Total drifted resources across all families.
    pub total_changes: u32,
    /// One-line human summary (the same string the daemon logs / alerts).
    pub summary: String,
    /// Per-family drifted-resource counts, sorted by family.
    pub by_family: Vec<(String, u32)>,
}

fn init_reconcile_tables(conn: &Connection) -> anyhow::Result<()> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS reconcile_status (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 0),
            last_check_ts INTEGER NOT NULL,
            in_sync INTEGER NOT NULL,
            total_changes INTEGER NOT NULL,
            summary TEXT NOT NULL
        )",
        [],
    )?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS reconcile_drift (
            family TEXT PRIMARY KEY,
            count INTEGER NOT NULL
        )",
        [],
    )?;
    Ok(())
}

/// Async wrapper — the watch loop is on the Tokio runtime, and `SQLite`
/// I/O can block (`busy_timeout`). Mirrors [`save_alert_dedup_async`].
pub async fn save_reconcile_status_async(
    profile_name: Option<String>,
    status: ReconcileStatus,
) -> anyhow::Result<()> {
    tokio::task::spawn_blocking(move || save_reconcile_status(profile_name.as_deref(), &status))
        .await
        .map_err(|e| anyhow::anyhow!("save_reconcile_status spawn_blocking join error: {e}"))?
}

pub fn save_reconcile_status(
    profile_name: Option<&str>,
    status: &ReconcileStatus,
) -> anyhow::Result<()> {
    let mut conn = open_db(&get_db_path(profile_name))?;
    write_reconcile_status(&mut conn, status)
}

/// Connection-level write — split from the path wrapper so tests can drive
/// it against a temp DB without touching the real cache dir.
fn write_reconcile_status(conn: &mut Connection, status: &ReconcileStatus) -> anyhow::Result<()> {
    init_reconcile_tables(conn)?;
    let tx = conn.transaction()?;
    tx.execute("DELETE FROM reconcile_status", [])?;
    tx.execute(
        "INSERT INTO reconcile_status (singleton, last_check_ts, in_sync, total_changes, summary)
         VALUES (0, ?1, ?2, ?3, ?4)",
        params![
            status.last_check_ts as i64,
            i64::from(status.in_sync),
            i64::from(status.total_changes),
            status.summary,
        ],
    )?;
    tx.execute("DELETE FROM reconcile_drift", [])?;
    for (family, count) in &status.by_family {
        tx.execute(
            "INSERT INTO reconcile_drift (family, count) VALUES (?1, ?2)",
            params![family, i64::from(*count)],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Load the latest reconcile drift result. `Ok(None)` when the watch has
/// never reported (table empty / DB absent) — readers show no series, which
/// is correct: a drift gauge should appear only once a check has run.
pub fn load_reconcile_status(
    profile_name: Option<&str>,
) -> anyhow::Result<Option<ReconcileStatus>> {
    let conn = open_db(&get_db_path(profile_name))?;
    read_reconcile_status(&conn)
}

/// Connection-level read — split from the path wrapper for testing.
fn read_reconcile_status(conn: &Connection) -> anyhow::Result<Option<ReconcileStatus>> {
    init_reconcile_tables(conn)?;
    let row = conn.query_row(
        "SELECT last_check_ts, in_sync, total_changes, summary
         FROM reconcile_status WHERE singleton = 0",
        [],
        |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
            ))
        },
    );
    let (ts, in_sync, total, summary) = match row {
        Ok(v) => v,
        Err(rusqlite::Error::QueryReturnedNoRows) => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    let mut stmt = conn.prepare("SELECT family, count FROM reconcile_drift ORDER BY family")?;
    let rows = stmt.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u32))
    })?;
    let mut by_family = Vec::new();
    for r in rows {
        by_family.push(r?);
    }

    Ok(Some(ReconcileStatus {
        last_check_ts: ts as u64,
        in_sync: in_sync != 0,
        total_changes: total as u32,
        summary,
        by_family,
    }))
}

pub fn get_all_snapshots(profile_name: Option<&str>) -> anyhow::Result<Vec<u64>> {
    let path = get_db_path(profile_name);
    let conn = open_db(&path)?;
    init_db(&conn)?;

    let mut stmt = conn.prepare("SELECT timestamp FROM snapshots ORDER BY timestamp ASC")?;
    let rows = stmt.query_map([], |row| {
        let ts: i64 = row.get(0)?;
        Ok(ts as u64)
    })?;

    let mut timestamps = Vec::new();
    for ts in rows {
        timestamps.push(ts?);
    }

    Ok(timestamps)
}

#[cfg(test)]
mod concurrency_tests {
    use super::*;

    /// SPOF 4.3 regression: a fresh connection MUST report WAL journal
    /// mode and a non-zero `busy_timeout`. Without these, two processes
    /// hitting the same DB serialize on an exclusive lock and the
    /// loser fails immediately.
    ///
    /// (macro audit) regression: `open_db` MUST set
    /// `PRAGMA user_version` to the binary's `SCHEMA_VERSION` so a
    /// future v1.1.0 can detect "this DB was written by an older
    /// version" and run migrations. A bare DB starts at 0; after one
    /// `open_db` it must equal `SCHEMA_VERSION`.
    #[test]
    fn open_db_pins_user_version() {
        let dir = std::env::temp_dir().join(format!("proxxx-cache-test-uv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let path = dir.join("cache.db");
        let conn = open_db(&path).expect("open_db");
        let v: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .expect("pragma read");
        assert_eq!(v, super::SCHEMA_VERSION);
        drop(conn);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
        let _ = std::fs::remove_dir(&dir);
    }

    /// (audit) regression — `auto_vacuum` MUST be set to
    /// INCREMENTAL (mode 2) on a fresh DB so freelist pages get
    /// returned to the OS. Without it the .db file grows
    /// monotonically as old snapshots are deleted, eventually
    /// filling the disk on a long-lived install.
    #[test]
    fn open_db_pins_incremental_auto_vacuum() {
        let dir = std::env::temp_dir().join(format!("proxxx-cache-test-av-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let path = dir.join("cache.db");
        let conn = open_db(&path).expect("open_db");
        let mode: i64 = conn
            .query_row("PRAGMA auto_vacuum", [], |r| r.get(0))
            .expect("pragma read");
        // SQLite codes: 0 = NONE, 1 = FULL, 2 = INCREMENTAL.
        assert_eq!(
            mode, 2,
            "auto_vacuum must be INCREMENTAL (=2) on a fresh DB"
        );
        drop(conn);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
        let _ = std::fs::remove_dir(&dir);
    }

    /// — refuse to open a DB written by a NEWER proxxx.
    /// Simulates the "user downgraded the binary" scenario; we must
    /// surface a clear error rather than silently corrupting the
    /// future-shaped database.
    #[test]
    fn open_db_refuses_future_schema() {
        let dir =
            std::env::temp_dir().join(format!("proxxx-cache-test-fut-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let path = dir.join("cache.db");
        // Create a DB and stamp it with a far-future version.
        {
            let raw = Connection::open(&path).expect("plain open");
            raw.pragma_update(None, "user_version", 9999_u32)
                .expect("stamp future version");
        }
        let err = open_db(&path).expect_err("future schema must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("9999") && msg.contains("newer"),
            "expected newer-schema refusal, got: {msg}"
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    /// (Gemini audit) extension: also assert
    /// `wal_autocheckpoint` and `journal_size_limit` are pinned so the
    /// WAL file cannot grow unbounded between explicit checkpoints.
    #[test]
    fn open_db_applies_wal_and_busy_timeout() {
        let dir = std::env::temp_dir().join(format!("proxxx-cache-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let path = dir.join("cache.db");
        let conn = open_db(&path).expect("open_db");
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .expect("pragma read");
        assert_eq!(mode.to_lowercase(), "wal", "journal_mode must be WAL");
        let busy: i64 = conn
            .query_row("PRAGMA busy_timeout", [], |r| r.get(0))
            .expect("pragma read");
        assert!(
            busy >= 5000,
            "busy_timeout must be >= 5000 ms to absorb checkpoint contention, got {busy}"
        );
        let auto_ckpt: i64 = conn
            .query_row("PRAGMA wal_autocheckpoint", [], |r| r.get(0))
            .expect("pragma read");
        assert!(
            auto_ckpt > 0,
            "wal_autocheckpoint must be enabled (> 0 pages), got {auto_ckpt}"
        );
        let jsl: i64 = conn
            .query_row("PRAGMA journal_size_limit", [], |r| r.get(0))
            .expect("pragma read");
        assert!(
            jsl > 0,
            "journal_size_limit must be set so WAL is truncated after checkpoint, got {jsl}"
        );
        // Cleanup — best-effort.
        drop(conn);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
        let _ = std::fs::remove_dir(&dir);
    }

    /// SPOF 4.3 regression: under WAL, a reader on one connection MUST
    /// not block while a writer is mid-transaction on another. We open
    /// two connections to the same file, begin a write transaction on
    /// the first, and assert a SELECT on the second succeeds without
    /// `SQLITE_BUSY`. Pre-fix (rollback journal, no `busy_timeout`) this
    /// test fails immediately.
    #[test]
    fn reader_does_not_block_on_concurrent_writer() {
        let dir = std::env::temp_dir().join(format!("proxxx-cache-test-rw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let path = dir.join("cache.db");

        let writer = open_db(&path).expect("writer open");
        init_db(&writer).expect("init");
        writer
            .execute(
                "INSERT INTO snapshots (timestamp, data) VALUES (?1, ?2)",
                params![1_i64, "{}"],
            )
            .expect("seed");

        // Begin a write transaction on the writer connection but DON'T
        // commit yet — the WAL must allow the reader through.
        writer.execute("BEGIN IMMEDIATE", []).expect("begin");
        writer
            .execute(
                "INSERT INTO snapshots (timestamp, data) VALUES (?1, ?2)",
                params![2_i64, "{}"],
            )
            .expect("write while open");

        // Reader on a separate connection — must NOT see SQLITE_BUSY.
        let reader = open_db(&path).expect("reader open");
        let count: i64 = reader
            .query_row("SELECT COUNT(*) FROM snapshots", [], |r| r.get(0))
            .expect("read should not block");
        // The committed snapshot (timestamp=1) is visible. The
        // uncommitted one is not — that's correct WAL isolation.
        assert_eq!(count, 1, "reader should see exactly the one committed row");

        writer.execute("COMMIT", []).expect("commit");

        // Cleanup
        drop(reader);
        drop(writer);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
        let _ = std::fs::remove_dir(&dir);
    }

    /// Schema v1 → v2 migration regression. Stamp a fresh DB at
    /// `user_version = 1`, re-open it, and assert the migration ran
    /// (`user_version = 2`, `alert_dedup` table exists). Pre-fix (no
    /// 1 → 2 arm) this test fails because the migration ladder bails
    /// with "no migration path from schema version 1".
    #[test]
    fn migrates_v1_db_to_v2_and_creates_alert_dedup_table() {
        let dir =
            std::env::temp_dir().join(format!("proxxx-cache-test-mig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let path = dir.join("cache.db");

        // Bring up at v2, then forcibly downgrade the user_version
        // marker to v1 to simulate a DB written by an older proxxx
        // that pre-dates the alert_dedup table. Drop the table too so
        // the migration arm has actual work to do.
        {
            let conn = open_db(&path).expect("open at current");
            conn.execute("DROP TABLE IF EXISTS alert_dedup", [])
                .expect("drop dedup table");
            conn.pragma_update(None, "user_version", 1_u32)
                .expect("downgrade marker");
        }

        // Re-open: migration should run 1 → 2 idempotently.
        let conn = open_db(&path).expect("re-open should migrate");
        let v: u32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .expect("pragma read");
        assert_eq!(v, super::SCHEMA_VERSION, "should be at current schema");
        let table_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='alert_dedup'",
                [],
                |r| r.get(0),
            )
            .expect("table count");
        assert_eq!(
            table_count, 1,
            "alert_dedup table must exist after migration"
        );

        drop(conn);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
        let _ = std::fs::remove_dir(&dir);
    }

    /// End-to-end alert dedup persistence: write a snapshot via
    /// `save_alert_dedup`, read it back via `load_alert_dedup`,
    /// assert keys + timestamps round-trip. Uses a profile name
    /// scoped to the test PID so it doesn't trample real cache.
    #[test]
    fn alert_dedup_persistence_round_trip() {
        let profile = format!("alertdedup-test-{}", std::process::id());
        // Start clean — `save_alert_dedup` does a full overwrite, so
        // any leftovers from a previous run are wiped on first save.

        let entries = vec![
            ("storage_low".to_string(), "node:pve1".to_string(), 1000_u64),
            (
                "replication_failed".to_string(),
                "100-0".to_string(),
                1500_u64,
            ),
            (
                "guest_offline".to_string(),
                "vmid:9999".to_string(),
                2000_u64,
            ),
        ];
        save_alert_dedup(Some(&profile), &entries).expect("save");

        let loaded = load_alert_dedup(Some(&profile)).expect("load");
        assert_eq!(loaded.len(), 3);
        // Output is ordered by (rule, target) ASC — pin that for
        // determinism. Reorder the input to match.
        let mut expected = entries;
        expected.sort();
        let mut got = loaded;
        got.sort();
        assert_eq!(got, expected);

        // Cleanup — `get_db_path` derives the file from profile name.
        let path = get_db_path(Some(&profile));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    // ── Phase 12 — spawn_blocking async wrapper round-trips ───────
    //
    // Each test writes via the *_async wrapper (which routes through
    // tokio::task::spawn_blocking) and reads back via the sync impl.
    // Goal: pin that the wrapping doesn't break the data path, so a
    // future contributor extending the wrappers can refactor with
    // confidence. The performance claim ("doesn't block the runtime")
    // is structural — `spawn_blocking` does what its docs say; we
    // don't try to measure latency here.

    fn cleanup_profile(profile: &str) {
        let path = get_db_path(Some(profile));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[tokio::test]
    async fn save_queue_async_round_trips_through_load_queue() {
        let profile = format!("save-queue-async-{}", std::process::id());
        let entries = vec![
            PersistedQueueEntry {
                id: "op-stop-100".into(),
                description: "stop vmid 100".into(),
                diff: String::new(),
                status: PersistedOpStatus::Pending,
                op: PersistedOp::StopGuest {
                    vmid: 100,
                    force: false,
                },
                created_at_secs: 1_700_000_000,
            },
            PersistedQueueEntry {
                id: "op-restart-200".into(),
                description: "restart vmid 200".into(),
                diff: String::new(),
                status: PersistedOpStatus::Running,
                op: PersistedOp::RestartGuest { vmid: 200 },
                created_at_secs: 1_700_000_500,
            },
        ];
        super::save_queue_async(Some(profile.clone()), entries.clone())
            .await
            .expect("async save");

        let loaded = load_queue(Some(&profile)).expect("sync load");
        assert_eq!(loaded.len(), 2);
        // Both rows share saved_at (we save in one transaction) so the
        // tiebreaker is id ASC: "op-restart-200" < "op-stop-100".
        let ids: Vec<&str> = loaded.iter().map(|e| e.id.as_str()).collect();
        assert!(
            ids.contains(&"op-stop-100") && ids.contains(&"op-restart-200"),
            "expected both ids to round-trip, got {ids:?}"
        );
        let stop = loaded.iter().find(|e| e.id == "op-stop-100").expect("stop");
        assert!(matches!(stop.status, PersistedOpStatus::Pending));

        cleanup_profile(&profile);
    }

    #[tokio::test]
    async fn save_state_async_round_trips_through_load_state() {
        let profile = format!("save-state-async-{}", std::process::id());
        let nodes = vec![Node {
            node: "pve1".into(),
            ..Default::default()
        }];
        let guests = vec![Guest {
            vmid: 100,
            name: "vm-test".into(),
            node: "pve1".into(),
            ..Default::default()
        }];
        let storage = vec![StoragePool {
            storage: "local".into(),
            ..Default::default()
        }];
        super::save_state_async(
            Some(profile.clone()),
            nodes.clone(),
            guests.clone(),
            storage.clone(),
        )
        .await
        .expect("async save");

        let loaded = load_state(Some(&profile)).expect("sync load");
        assert_eq!(loaded.nodes.len(), 1);
        assert_eq!(loaded.nodes[0].node, "pve1");
        assert_eq!(loaded.guests.len(), 1);
        assert_eq!(loaded.guests[0].vmid, 100);
        assert_eq!(loaded.guests[0].name, "vm-test");
        assert_eq!(loaded.storage.len(), 1);
        assert_eq!(loaded.storage[0].storage, "local");

        cleanup_profile(&profile);
    }

    #[tokio::test]
    async fn save_alert_dedup_async_round_trips_through_load_alert_dedup() {
        let profile = format!("save-dedup-async-{}", std::process::id());
        let entries = vec![
            (
                "rule-a".to_string(),
                "vmid:100".to_string(),
                1_700_000_000_u64,
            ),
            (
                "rule-b".to_string(),
                "node:pve1".to_string(),
                1_700_000_100_u64,
            ),
        ];
        super::save_alert_dedup_async(Some(profile.clone()), entries.clone())
            .await
            .expect("async save");

        let mut loaded = load_alert_dedup(Some(&profile)).expect("sync load");
        loaded.sort();
        let mut expected = entries;
        expected.sort();
        assert_eq!(loaded, expected);

        cleanup_profile(&profile);
    }

    /// RBAC cache-segregation invariant: writing cluster state under
    /// profile "root" MUST NOT be visible to a load under profile
    /// "auditor". Two distinct profile names map to distinct DB files;
    /// a load on the other profile must return `Err("No cache found")`.
    ///
    /// This test closes the ❌ row in pre-commit/01-feature-coverage.md
    /// under "RBAC & multi-persona · `SQLite` cache segregation per-profile".
    /// The invariant was previously blocked on multi-profile support
    /// arriving (Gap #4); `get_db_path` has always segregated by name.
    #[test]
    fn cache_is_segregated_per_profile() {
        let pid = std::process::id();
        let root_profile = format!("seg-root-{pid}");
        let auditor_profile = format!("seg-auditor-{pid}");

        // Write root-only state: one node named "pve-root".
        let nodes = vec![Node {
            node: "pve-root".into(),
            ..Default::default()
        }];
        save_state(Some(&root_profile), &nodes, &[], &[]).expect("save root state");

        // Load under the auditor profile — MUST find nothing.
        let auditor_result = load_state(Some(&auditor_profile));
        assert!(
            auditor_result.is_err(),
            "auditor profile must not see root's state, got: {:?}",
            auditor_result.as_ref().map(|c| &c.nodes)
        );

        // Root profile load must still succeed and contain the correct node.
        let root_cache = load_state(Some(&root_profile)).expect("root state round-trips");
        assert_eq!(root_cache.nodes.len(), 1);
        assert_eq!(root_cache.nodes[0].node, "pve-root");

        cleanup_profile(&root_profile);
        cleanup_profile(&auditor_profile);
    }

    /// Complementary: writing to "auditor" then switching to "root"
    /// must not leak the auditor's VM list into root's view.
    #[test]
    fn cache_write_to_auditor_does_not_pollute_root() {
        let pid = std::process::id();
        let root_profile = format!("seg2-root-{pid}");
        let auditor_profile = format!("seg2-auditor-{pid}");

        let auditor_guests = vec![Guest {
            vmid: 7777,
            name: "auditor-vm".into(),
            node: "pve1".into(),
            ..Default::default()
        }];
        save_state(Some(&auditor_profile), &[], &auditor_guests, &[]).expect("save auditor state");

        // Root never wrote — its load must return Err.
        let root_result = load_state(Some(&root_profile));
        assert!(
            root_result.is_err(),
            "root profile must not see auditor's VMs"
        );

        cleanup_profile(&root_profile);
        cleanup_profile(&auditor_profile);
    }

    #[test]
    fn reconcile_status_round_trips_and_overwrites() {
        let profile = format!("test-reconcile-{}", std::process::id());
        cleanup_profile(&profile);

        // Never reported → None (no series until the watch runs once).
        assert!(load_reconcile_status(Some(&profile)).unwrap().is_none());

        // A drift result persists with its per-family counts.
        let drift = ReconcileStatus {
            last_check_ts: 1_700_000_000,
            in_sync: false,
            total_changes: 3,
            summary: "3 change(s) across 2 families".into(),
            by_family: vec![("pool".into(), 2), ("storage".into(), 1)],
        };
        save_reconcile_status(Some(&profile), &drift).unwrap();
        assert_eq!(
            load_reconcile_status(Some(&profile)).unwrap().unwrap(),
            drift
        );

        // A later in-sync check overwrites the single status row AND clears
        // the per-family drift rows — no stale `proxxx_drift_resources` gauges.
        let synced = ReconcileStatus {
            last_check_ts: 1_700_000_100,
            in_sync: true,
            total_changes: 0,
            summary: "in sync".into(),
            by_family: vec![],
        };
        save_reconcile_status(Some(&profile), &synced).unwrap();
        let got = load_reconcile_status(Some(&profile)).unwrap().unwrap();
        assert_eq!(got, synced);
        assert!(got.by_family.is_empty(), "drift rows must be cleared");

        cleanup_profile(&profile);
    }
}
