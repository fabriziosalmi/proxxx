//! Append-only audit log backed by `SQLite`.
//! Each entry is HMAC-SHA256 signed using a chained scheme. Two chain
//! formats coexist, selected per-row by the `chain_version` column:
//!   * **v1** (legacy): `HMAC(key, prev || ts || action || vmid || result)`
//!   * **v2** (current): `HMAC(key, "v2" || prev || ts || action || user ||
//!     vmid || node || params_json || result)` — additionally folds in WHO
//!     (`user`) and WHAT (`node`, `params_json`), closing the gap where a
//!     local tamperer could rewrite the actor/parameters of a record without
//!     breaking the chain (#173).
//! Rows written before the migration are kept as v1 and still verify under
//! the v1 formula; every new entry is written as v2. The chain is verifiable
//! offline via `proxxx audit verify`.

use anyhow::{Context, Result};
// hmac 0.13: `new_from_slice` lives on the `KeyInit` trait which is no
// longer re-exported by `Mac` like it was in 0.12. Explicit import.
use hmac::{Hmac, KeyInit, Mac};
use rusqlite::{params, Connection};
use sha2::Sha256;
use std::path::PathBuf;
use tracing::info;

type HmacSha256 = Hmac<Sha256>;

/// A single audit log entry.
#[derive(Debug, serde::Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: String,
    pub action: String,
    pub user: String,
    pub vmid: Option<i64>,
    pub node: Option<String>,
    pub params_json: Option<String>,
    pub result: String,
    pub chain_hmac: String,
}

/// Refusal returned when the write-ahead `"sent"` audit record cannot be
/// persisted before a mutation (`#344`). Carried via `anyhow` so `main.rs`
/// downcasts it to exit code 8 ("mutation refused by a local lock", shared
/// with `ReadOnlyRefusal`, `FreezeRefusal`, and `SecureModeRefusal`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("audit log refused mutation `{action}`: {reason}")]
pub struct AuditWriteRefusal {
    pub action: String,
    pub reason: String,
}

impl AuditWriteRefusal {
    /// Process exit code — matches the "mutation refused by a local lock"
    /// family (`read_only` / `incident freeze` / `--secure`, exit code 8).
    pub const EXIT_CODE: i32 = 8;
}

/// Append-only SQLite-backed audit logger.
pub struct AuditLogger {
    conn: Connection,
    key: Vec<u8>,
}

impl AuditLogger {
    pub fn open() -> Result<Self> {
        let path = audit_db_path()?;
        let key_path = audit_key_path()?;
        Self::open_at(&path, &key_path)
    }

    /// Open an [`AuditLogger`] rooted in an explicit directory (`dir/audit.db`
    /// + `dir/audit.key`) without reading or mutating `PROXXX_AUDIT_DIR`
    /// (`#344` Rev. 17).
    ///
    /// # Errors
    /// Returns an error if the directory, key, or database cannot be created
    /// or opened.
    pub fn open_in(dir: &std::path::Path) -> Result<Self> {
        ensure_audit_dir_exists(dir)?;
        Self::open_at(&dir.join("audit.db"), &dir.join("audit.key"))
    }

    fn open_at(path: &std::path::Path, key_path: &std::path::Path) -> Result<Self> {
        let key_existed = key_path.exists();
        let key = load_or_create_key(&key_path.to_path_buf())?;
        let conn = Connection::open(path)
            .with_context(|| format!("open audit db at {}", path.display()))?;
        let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         TEXT    NOT NULL,
                action     TEXT    NOT NULL,
                user       TEXT    NOT NULL DEFAULT '',
                vmid       INTEGER,
                node       TEXT,
                params_json TEXT,
                result     TEXT    NOT NULL DEFAULT '',
                chain_hmac TEXT    NOT NULL,
                chain_version INTEGER NOT NULL DEFAULT 1,
                key_id     TEXT    NOT NULL DEFAULT 'primary'
            );",
        )?;
        migrate_chain_version(&conn)?;
        migrate_key_id(&conn)?;
        if !key_existed {
            let existing_primary_rows: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM audit_log WHERE key_id = ?1",
                    params![PRIMARY_KEY_ID],
                    |r| r.get(0),
                )
                .unwrap_or(0);
            if existing_primary_rows > 0 {
                let _ = std::fs::remove_file(key_path);
                anyhow::bail!(
                    "audit key at {} was missing while {} already contains {existing_primary_rows} \
                     row(s) signed with `{PRIMARY_KEY_ID}` — refusing to start a forged chain",
                    key_path.display(),
                    path.display()
                );
            }
        }
        Ok(Self { conn, key })
    }

    pub fn log(
        &mut self,
        action: &str,
        user: &str,
        vmid: Option<u32>,
        node: Option<&str>,
        params_json: Option<&str>,
        result: &str,
    ) -> Result<()> {
        let prev_hmac = self.last_chain_hmac()?;
        let ts = chrono_now();
        let vmid_str = vmid.map(|v| v.to_string()).unwrap_or_default();
        // v2: the actor (`user`) and the parameters (`node`, `params_json`)
        // are now bound into the MAC, not just stored alongside it.
        let chain_hmac = compute_hmac_v2(
            &self.key,
            &prev_hmac,
            &ts,
            action,
            user,
            &vmid_str,
            node.unwrap_or(""),
            params_json.unwrap_or(""),
            result,
        );
        self.conn.execute(
            "INSERT INTO audit_log
                (ts, action, user, vmid, node, params_json, result, chain_hmac,
                 chain_version, key_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                ts,
                action,
                user,
                vmid.map(i64::from),
                node,
                params_json,
                result,
                chain_hmac,
                CHAIN_V2,
                PRIMARY_KEY_ID,
            ],
        )?;
        info!(action, vmid, result, "audit");
        Ok(())
    }

    pub fn query(&self, limit: usize, since_ts: Option<&str>) -> Result<Vec<AuditEntry>> {
        if let Some(since) = since_ts {
            let mut stmt = self.conn.prepare(
                "SELECT id,ts,action,user,vmid,node,params_json,result,chain_hmac
                 FROM audit_log WHERE ts >= ?1 ORDER BY id DESC LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![since, limit as i64], row_to_entry)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(anyhow::Error::from)
        } else {
            let mut stmt = self.conn.prepare(
                "SELECT id,ts,action,user,vmid,node,params_json,result,chain_hmac
                 FROM audit_log ORDER BY id DESC LIMIT ?1",
            )?;
            let rows = stmt.query_map(params![limit as i64], row_to_entry)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()
                .map_err(anyhow::Error::from)
        }
    }

    pub fn verify(&self) -> Result<(usize, usize)> {
        FULL_VERIFY_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut stmt = self.conn.prepare(
            "SELECT ts,action,user,vmid,node,params_json,result,chain_hmac,chain_version,key_id
             FROM audit_log ORDER BY id ASC",
        )?;
        let mut prev = String::new();
        let mut ok = 0usize;
        let mut fail = 0usize;
        let rows = stmt.query_map([], map_raw_audit_row)?;
        // #281 — a row is verified with the key it was signed with, so a
        // rotation does not invalidate everything written before it. The
        // primary key is already loaded; retired ones are read on first
        // use and cached for the walk.
        let mut retired: std::collections::HashMap<String, Option<Vec<u8>>> =
            std::collections::HashMap::new();
        for row in rows {
            let row = row?;
            let key_id = &row.9;
            let key: &[u8] = if key_id == PRIMARY_KEY_ID {
                &self.key
            } else {
                let entry = retired
                    .entry(key_id.clone())
                    .or_insert_with(|| load_retired_key(key_id).ok());
                let Some(k) = entry else {
                    // The key this row was signed with is gone, so its
                    // MAC cannot be recomputed. Count it as a failure
                    // rather than silently skipping: an unverifiable row
                    // IS a gap in the trail.
                    fail += 1;
                    prev.clone_from(&row.7);
                    continue;
                };
                k.as_slice()
            };
            if verify_raw_row(&row, &prev, key) {
                ok += 1;
            } else {
                fail += 1;
            }
            prev = row.7;
        }
        Ok((ok, fail))
    }

    /// O(1) tail-link verification (`#344` Rev. 16): checks only that the last
    /// row in `audit_log` (if any) verifies against its immediate predecessor
    /// (`ORDER BY id DESC LIMIT 2`).
    ///
    /// # Errors
    /// Returns an error if querying `audit_log` fails or if the tail row's
    /// signing key is missing or its MAC does not match.
    pub fn verify_tail(&self) -> Result<()> {
        TAIL_VERIFY_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut stmt = self.conn.prepare(
            "SELECT ts,action,user,vmid,node,params_json,result,chain_hmac,chain_version,key_id
             FROM audit_log ORDER BY id DESC LIMIT 2",
        )?;
        let rows: Vec<RawAuditRow> = stmt
            .query_map([], map_raw_audit_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let Some(last) = rows.first() else {
            return Ok(());
        };
        let prev = rows.get(1).map_or("", |r| r.7.as_str());
        let retired_key;
        let key: &[u8] = if last.9 == PRIMARY_KEY_ID {
            &self.key
        } else {
            let Ok(k) = load_retired_key(&last.9) else {
                anyhow::bail!(
                    "audit chain integrity check failed (1 tampered or unverifiable row(s))"
                );
            };
            retired_key = k;
            retired_key.as_slice()
        };
        if !verify_raw_row(last, prev, key) {
            anyhow::bail!("audit chain integrity check failed (1 tampered or unverifiable row(s))");
        }
        Ok(())
    }

    fn last_chain_hmac(&self) -> Result<String> {
        match self.conn.query_row(
            "SELECT chain_hmac FROM audit_log ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        ) {
            Ok(h) => Ok(h),
            // Empty log — this is the first entry; an empty prev-hmac is correct.
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(String::new()),
            // A real read error must not silently start a fresh chain segment.
            Err(e) => Err(anyhow::Error::from(e).context("read last chain hmac")),
        }
    }
}

static FULL_VERIFY_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static TAIL_VERIFY_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Number of times [`AuditLogger::verify`] (the O(N) full-chain walk) has been
/// called in this process (`#344` Rev. 16).
#[must_use]
pub fn full_verify_call_count() -> usize {
    FULL_VERIFY_CALLS.load(std::sync::atomic::Ordering::SeqCst)
}

/// Number of times [`AuditLogger::verify_tail`] (the O(1) tail-link check) has
/// been called in this process (`#344` Rev. 16).
#[must_use]
pub fn tail_verify_call_count() -> usize {
    TAIL_VERIFY_CALLS.load(std::sync::atomic::Ordering::SeqCst)
}

type RawAuditRow = (
    String,         // ts
    String,         // action
    String,         // user
    Option<i64>,    // vmid
    Option<String>, // node
    Option<String>, // params_json
    String,         // result
    String,         // chain_hmac
    i64,            // chain_version
    String,         // key_id
);

fn map_raw_audit_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawAuditRow> {
    Ok((
        r.get::<_, String>(0)?,         // ts
        r.get::<_, String>(1)?,         // action
        r.get::<_, String>(2)?,         // user
        r.get::<_, Option<i64>>(3)?,    // vmid
        r.get::<_, Option<String>>(4)?, // node
        r.get::<_, Option<String>>(5)?, // params_json
        r.get::<_, String>(6)?,         // result
        r.get::<_, String>(7)?,         // chain_hmac
        r.get::<_, i64>(8)?,            // chain_version
        r.get::<_, String>(9)?,         // key_id
    ))
}

fn verify_raw_row(row: &RawAuditRow, prev: &str, key: &[u8]) -> bool {
    let (ts, action, user, vmid, node, params, result, stored_hmac, version, _key_id) = row;
    let vmid_str = vmid.map(|v| v.to_string()).unwrap_or_default();
    // Recompute under each row's OWN chain format, so legacy v1 rows
    // keep verifying after the migration while new v2 rows get the
    // stronger who/what coverage.
    let expected = if *version == CHAIN_V2 {
        compute_hmac_v2(
            key,
            prev,
            ts,
            action,
            user,
            &vmid_str,
            node.as_deref().unwrap_or(""),
            params.as_deref().unwrap_or(""),
            result,
        )
    } else {
        compute_hmac(key, prev, ts, action, &vmid_str, result)
    };
    expected == *stored_hmac
}

fn row_to_entry(r: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
    Ok(AuditEntry {
        id: r.get(0)?,
        ts: r.get(1)?,
        action: r.get(2)?,
        user: r.get(3)?,
        vmid: r.get(4)?,
        node: r.get(5)?,
        params_json: r.get(6)?,
        result: r.get(7)?,
        chain_hmac: r.get(8)?,
    })
}

fn compute_hmac(
    key: &[u8],
    prev: &str,
    ts: &str,
    action: &str,
    vmid: &str,
    result: &str,
) -> String {
    // The key is validated to be exactly 32 bytes at load time
    // (`load_or_create_key`), so `new_from_slice` won't fail here. If it somehow
    // does, return an EMPTY MAC — which makes `audit verify` fail loudly — rather
    // than silently falling back to a known all-zeros key that anyone could forge.
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return String::new();
    };
    mac.update(prev.as_bytes());
    mac.update(b"|");
    mac.update(ts.as_bytes());
    mac.update(b"|");
    mac.update(action.as_bytes());
    mac.update(b"|");
    mac.update(vmid.as_bytes());
    mac.update(b"|");
    mac.update(result.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Current chain format. Folds the actor + parameters into the MAC.
const CHAIN_V2: i64 = 2;

/// v2 chain MAC. On top of v1's `(ts, action, vmid, result)` it binds in
/// `user` (WHO), `node` and `params_json` (WHAT) — so a local tamperer can no
/// longer rewrite the actor or the parameters of a record without breaking the
/// chain (#173). The `"v2"` prefix is domain separation: a v1 and a v2 row can
/// never collide on a MAC even with otherwise-identical fields.
#[allow(clippy::too_many_arguments)]
fn compute_hmac_v2(
    key: &[u8],
    prev: &str,
    ts: &str,
    action: &str,
    user: &str,
    vmid: &str,
    node: &str,
    params_json: &str,
    result: &str,
) -> String {
    // Same all-zeros-key avoidance as `compute_hmac`: an unusable key yields an
    // empty MAC that fails `verify` loudly rather than a forgeable constant.
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return String::new();
    };
    for field in [
        b"v2".as_slice(),
        prev.as_bytes(),
        ts.as_bytes(),
        action.as_bytes(),
        user.as_bytes(),
        vmid.as_bytes(),
        node.as_bytes(),
        params_json.as_bytes(),
    ] {
        mac.update(field);
        mac.update(b"|");
    }
    mac.update(result.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Add the `chain_version` column to an `audit_log` written before v2 (#173).
/// Pre-existing rows default to v1 and keep verifying under the v1 formula;
/// no-op once migrated (fresh DBs already carry the column).
fn migrate_chain_version(conn: &Connection) -> Result<()> {
    let has_col: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('audit_log') WHERE name = 'chain_version'",
        [],
        |r| r.get(0),
    )?;
    if has_col == 0 {
        conn.execute(
            "ALTER TABLE audit_log ADD COLUMN chain_version INTEGER NOT NULL DEFAULT 1",
            [],
        )?;
    }
    Ok(())
}

/// Add the `key_id` column to an `audit_log` written before key
/// rotation existed (audit 2026-09-09, #281). Pre-existing rows are
/// `primary`, which is the key they were signed with.
fn migrate_key_id(conn: &Connection) -> Result<()> {
    let has_col: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('audit_log') WHERE name = 'key_id'",
        [],
        |r| r.get(0),
    )?;
    if has_col == 0 {
        conn.execute(
            "ALTER TABLE audit_log ADD COLUMN key_id TEXT NOT NULL DEFAULT 'primary'",
            [],
        )?;
    }
    Ok(())
}

/// Identifier of the key currently being written with.
///
/// Retired keys keep their own id and stay on disk as
/// `audit.key.<id>`, so rows signed with them keep verifying. Before
/// this existed, rotating meant deleting `audit.key` and starting a new
/// chain — which destroyed the verifiability of exactly the history an
/// investigation would need, so in practice the key was permanent for
/// the life of the log.
pub const PRIMARY_KEY_ID: &str = "primary";

fn load_or_create_key(path: &PathBuf) -> Result<Vec<u8>> {
    if path.exists() {
        // Custody check: the HMAC key is the ONLY thing standing between a
        // local tamperer and a forged audit chain. A group/world-readable key
        // lets any other user on the host read it and recompute every MAC —
        // silently defeating tamper-evidence. Refuse it, mirroring the
        // `telegram.bot_token_file` 0600 enforcement. (The key we *create*
        // below is already 0600; this catches one restored from a backup, an
        // over-permissive umask, or a hand-placed key on a separate volume.)
        let bytes;
        #[cfg(unix)]
        {
            use std::io::Read as _;
            use std::os::unix::fs::PermissionsExt;
            // Open ONCE, then fstat the open fd — not a fresh path stat — so the
            // mode we check and the bytes we read come from the SAME inode. This
            // closes the TOCTOU / symlink-swap window between a path-based check
            // and a path-based read.
            let mut file = std::fs::File::open(path)
                .with_context(|| format!("open audit key {}", path.display()))?;
            // FAIL CLOSED: a stat error must REFUSE the key, not skip the check
            // and read it anyway. Custody we cannot verify is custody we do not
            // trust. (Was previously `if let Ok(meta)` — silently fail-open.)
            let mode = file
                .metadata()
                .with_context(|| format!("stat audit key {}", path.display()))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                anyhow::bail!(
                    "audit key {} has unsafe permissions {:o} — must be 0600 (owner-only). A \
                     group/world-readable HMAC key lets another local user forge the audit \
                     chain. Run: chmod 600 {}",
                    path.display(),
                    mode & 0o777,
                    path.display(),
                );
            }
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)
                .with_context(|| format!("read audit key {}", path.display()))?;
            bytes = buf;
        }
        #[cfg(not(unix))]
        {
            // No POSIX mode to enforce custody here. AR-5 scopes the tamper-
            // evidence guarantee to unix; release targets are darwin + linux-musl.
            bytes = std::fs::read(path)
                .with_context(|| format!("read audit key {}", path.display()))?;
        }
        // The HMAC chain is only as trustworthy as its key. A truncated or empty
        // key (e.g. an interrupted first write, or a `touch`'d file) MUST fail
        // loudly — an empty key would otherwise degrade to a forgeable all-zeros
        // MAC, and a wrong-length key produces a chain that won't re-derive.
        anyhow::ensure!(
            bytes.len() == 32,
            "audit key {} is {} bytes, expected 32 — refusing to use a malformed key. \
             Delete the file to regenerate (this starts a new chain; prior entries \
             will no longer verify under the new key).",
            path.display(),
            bytes.len()
        );
        return Ok(bytes);
    }
    let mut key = vec![0u8; 32];
    getrandom::fill(&mut key).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .and_then(|mut f| std::io::Write::write_all(&mut f, &key))
            .with_context(|| format!("write audit key {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &key)
            .with_context(|| format!("write audit key {}", path.display()))?;
    }
    Ok(key)
}

fn ensure_audit_dir_exists(dir: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("create audit dir {}", dir.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("create audit dir {}", dir.display()))?;
    }
    Ok(())
}

/// Directory holding the audit DB + key. Honors `PROXXX_AUDIT_DIR` (for
/// relocating the trail onto a dedicated volume in ops, or for subprocess CLI
/// tests); otherwise the platform data-local dir (or a process-local temp dir
/// in `#[cfg(test)]`). Mirrors the `PROXXX_CONFIG` / `PROXXX_FREEZE_PATH`
/// override convention. The directory is created if absent.
///
/// Custody: on unix the dir is created `0700`. Dir-write is the precondition for
/// *replacing* the HMAC key with an attacker-owned `0600` key (which the
/// mode-only load check would otherwise accept), so denying other users write
/// access to the dir closes that swap vector. Only tightens an existing dir's
/// perms is out of scope — `create_dir_all` no-ops if it exists; operators who
/// pre-create a lax `PROXXX_AUDIT_DIR` own that choice (see ACCEPTED-RISKS AR-5).
fn audit_data_dir() -> Result<PathBuf> {
    let dir = if let Ok(dir) = std::env::var("PROXXX_AUDIT_DIR") {
        PathBuf::from(dir)
    } else {
        #[cfg(test)]
        {
            static TEST_DEFAULT_AUDIT_DIR: std::sync::OnceLock<tempfile::TempDir> =
                std::sync::OnceLock::new();
            TEST_DEFAULT_AUDIT_DIR
                .get_or_init(|| tempfile::tempdir().expect("create fallback test audit dir"))
                .path()
                .to_path_buf()
        }
        #[cfg(not(test))]
        {
            directories::ProjectDirs::from("dev", "proxxx", "proxxx")
                .ok_or_else(|| anyhow::anyhow!("cannot resolve data dir"))?
                .data_local_dir()
                .to_path_buf()
        }
    };
    ensure_audit_dir_exists(&dir)?;
    Ok(dir)
}

fn audit_db_path() -> Result<PathBuf> {
    Ok(audit_data_dir()?.join("audit.db"))
}

/// Resolve the audit-key path. `PROXXX_AUDIT_KEY` (an explicit file path) wins
/// so an operator can relocate the key OFF the audit DB's volume — e.g. a
/// root-owned key on a separate mount, so an attacker with write access to
/// `audit.db` does not also get read access to the key. Absent = co-located
/// `audit.key` next to the DB (the default; see ACCEPTED-RISKS AR-5). Pure over
/// its inputs so the precedence is unit-tested without touching the environment.
fn resolve_audit_key_path(key_env: Option<String>, data_dir: &std::path::Path) -> PathBuf {
    match key_env {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => data_dir.join("audit.key"),
    }
}

fn audit_key_path() -> Result<PathBuf> {
    Ok(resolve_audit_key_path(
        std::env::var("PROXXX_AUDIT_KEY").ok(),
        &audit_data_dir()?,
    ))
}

/// Path a retired key is archived at: the primary key path with the
/// key id appended. Keeping them beside the primary means a backup of
/// the audit directory captures the whole verifiable history, which is
/// the property #281 is about.
fn retired_key_path(key_id: &str) -> Result<PathBuf> {
    let primary = audit_key_path()?;
    let name = primary
        .file_name()
        .map(|n| format!("{}.{key_id}", n.to_string_lossy()))
        .unwrap_or_else(|| format!("audit.key.{key_id}"));
    Ok(primary.with_file_name(name))
}

/// Read an existing key (primary or retired) with the 0600 custody check,
/// failing if the file does not exist instead of auto-generating a replacement.
fn load_existing_key(path: &PathBuf, label: &str) -> Result<Vec<u8>> {
    anyhow::ensure!(
        path.exists(),
        "audit key `{label}` is not present at {} — rows signed with it cannot \
         be verified",
        path.display()
    );
    load_or_create_key(path)
}

/// Read a retired key. Same 0600 custody check as the primary — a
/// retired key still proves every row it signed.
fn load_retired_key(key_id: &str) -> Result<Vec<u8>> {
    let path = retired_key_path(key_id)?;
    load_existing_key(&path, key_id)
}

/// Rotate the audit HMAC key (audit 2026-09-09, #281).
///
/// The current key is archived under a fresh id and a new primary is
/// generated. Rows already written keep their `key_id`, so `verify`
/// continues to check them against the key that signed them: rotation no
/// longer destroys the verifiability of the history it is supposed to
/// protect.
///
/// Returns the id the retired key was archived under.
///
/// # Errors
/// When the key directory cannot be read or written.
pub fn rotate_key() -> Result<String> {
    let primary = audit_key_path()?;
    anyhow::ensure!(
        primary.exists(),
        "no audit key at {} — nothing to rotate (one is created on first use)",
        primary.display()
    );
    // The id is a timestamp: sortable, and it says when the key stopped
    // being used, which is what an investigator wants to know.
    let key_id = format!("retired-{}", now_unix_secs());
    let dest = retired_key_path(&key_id)?;
    anyhow::ensure!(
        !dest.exists(),
        "a retired key already exists at {} — refusing to overwrite it, since \
         that would strand every row it signed",
        dest.display()
    );
    std::fs::rename(&primary, &dest)
        .with_context(|| format!("archiving {} to {}", primary.display(), dest.display()))?;
    crate::util::durable::sync_parent_dir(&dest)?;

    // Re-point every existing row at the key that actually signed it,
    // BEFORE creating the new primary — if this fails, the old key is
    // still the primary and nothing is stranded.
    let conn = Connection::open(audit_db_path()?)?;
    migrate_key_id(&conn)?;
    conn.execute(
        "UPDATE audit_log SET key_id = ?1 WHERE key_id = ?2",
        params![key_id, PRIMARY_KEY_ID],
    )?;

    // Generating the new primary is the last step.
    let _new = load_or_create_key(&primary)?;
    // Evict cached loggers so subsequent writes pick up the newly generated
    // primary key.
    if let Some(mutex) = PROCESS_AUDIT_LOGGERS.get() {
        if let Ok(mut guard) = mutex.lock() {
            guard.clear();
        }
    }
    info!(key_id = %key_id, "audit key rotated");
    Ok(key_id)
}

struct CachedAuditLogger {
    db_path: PathBuf,
    key_path: PathBuf,
    logger: AuditLogger,
    initial_fail_count: usize,
}

type LoggerCacheMap = std::collections::HashMap<(PathBuf, PathBuf), CachedAuditLogger>;

static PROCESS_AUDIT_LOGGERS: std::sync::OnceLock<std::sync::Mutex<LoggerCacheMap>> =
    std::sync::OnceLock::new();

fn logger_cache() -> &'static std::sync::Mutex<LoggerCacheMap> {
    PROCESS_AUDIT_LOGGERS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn open_cached_logger(db_path: PathBuf, key_path: PathBuf) -> Result<CachedAuditLogger> {
    let logger = AuditLogger::open_at(&db_path, &key_path)?;
    let (_ok, initial_fail_count) = logger.verify()?;
    Ok(CachedAuditLogger {
        db_path,
        key_path,
        logger,
        initial_fail_count,
    })
}

fn resolve_db_and_key_paths(audit_dir: Option<&std::path::Path>) -> Result<(PathBuf, PathBuf)> {
    if let Some(dir) = audit_dir {
        ensure_audit_dir_exists(dir)?;
        Ok((dir.join("audit.db"), dir.join("audit.key")))
    } else {
        Ok((audit_db_path()?, audit_key_path()?))
    }
}

fn with_cached_logger_at<F, R>(audit_dir: Option<&std::path::Path>, f: F) -> Result<R>
where
    F: FnOnce(&mut CachedAuditLogger) -> Result<R>,
{
    let mut guard = logger_cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (db_path, key_path) = resolve_db_and_key_paths(audit_dir)?;
    let cache_key = (db_path.clone(), key_path.clone());
    if let Some(cached) = guard.get(&cache_key) {
        let disk_key = match load_existing_key(&cached.key_path, PRIMARY_KEY_ID) {
            Ok(k) => k,
            Err(e) => {
                guard.remove(&cache_key);
                return Err(e);
            }
        };
        if disk_key != cached.logger.key || !cached.db_path.exists() {
            guard.remove(&cache_key);
        }
    }
    if !guard.contains_key(&cache_key) {
        let opened = open_cached_logger(db_path, key_path)?;
        guard.insert(cache_key.clone(), opened);
    }
    let Some(cached) = guard.get_mut(&cache_key) else {
        anyhow::bail!("process audit logger unavailable");
    };
    f(cached)
}

/// Access the process-wide lazy [`AuditLogger`] (`#344`, Decision 4 & Rev. 16).
///
/// Opens `SQLite` and runs a full [`AuditLogger::verify`] at most once per
/// `(db_path, key_path)` in the process (reopening only after key rotation or
/// if the key/DB file is replaced on disk).
///
/// # Errors
/// Returns an error if the audit directory, database, or signing key cannot
/// be opened or validated, or if `f` returns an error.
pub fn with_process_logger<F, R>(f: F) -> Result<R>
where
    F: FnOnce(&mut AuditLogger) -> Result<R>,
{
    with_cached_logger_at(None, |cached| f(&mut cached.logger))
}

/// Extract `(node, vmid)` from a Proxmox API path when present (`#344`,
/// Decision 2):
/// - `/nodes/<node>/...` -> `node = Some(<node>)`
/// - `/(qemu|lxc)/<vmid>` -> `vmid = Some(<vmid>)`
#[must_use]
pub fn parse_pve_path(path: &str) -> (Option<String>, Option<u32>) {
    let clean = path.split('?').next().unwrap_or(path);
    let segments: Vec<&str> = clean.split('/').filter(|s| !s.is_empty()).collect();
    let mut node = None;
    let mut vmid = None;
    let mut i = 0;
    while i < segments.len() {
        if let Some(&seg) = segments.get(i) {
            match seg {
                "nodes" => {
                    if let Some(&n) = segments.get(i + 1) {
                        if !n.is_empty() {
                            node = Some(n.to_string());
                        }
                    }
                }
                "qemu" | "lxc" => {
                    if let Some(&v) = segments.get(i + 1) {
                        if let Ok(parsed) = v.parse::<u32>() {
                            vmid = Some(parsed);
                        }
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    (node, vmid)
}

/// Build the `params_json` object for a mutation audit record (`#344`,
/// Decision 2), redacting secret parameter values and stamping the profile
/// name.
#[must_use]
pub fn redact_params_json(params: &[(&str, &str)], profile_label: &str) -> String {
    let mut map = serde_json::Map::with_capacity(params.len() + 1);
    map.insert(
        "profile".to_string(),
        serde_json::Value::String(profile_label.to_string()),
    );
    for &(k, v) in params {
        let key = if k == "profile" {
            "_form_profile".to_string()
        } else {
            k.to_string()
        };
        map.insert(
            key,
            serde_json::Value::String(crate::util::panic_hook::redact_param_value(k, v)),
        );
    }
    serde_json::Value::Object(map).to_string()
}

/// Context for a two-phase (write-ahead `"sent"` + post-call outcome) mutation
/// audit record (`#344`).
#[derive(Debug, Clone)]
pub struct MutationAuditCtx {
    pub action: String,
    pub user: String,
    pub node: Option<String>,
    pub vmid: Option<u32>,
    pub params_json: String,
    pub audit_dir: Option<PathBuf>,
}

impl MutationAuditCtx {
    /// Parse `(node, vmid)` from `path` (falling back to a `vmid` form field),
    /// redact secret parameters, and append the write-ahead `"sent"` audit
    /// entry before the network request leaves the process.
    ///
    /// # Errors
    /// Fails closed with [`AuditWriteRefusal`] (exit code 8) if the audit DB
    /// or key cannot be opened, if the existing HMAC chain is broken, or if
    /// the `"sent"` row cannot be inserted.
    pub fn write_ahead(
        method: &str,
        path: &str,
        params: &[(&str, &str)],
        profile_label: &str,
    ) -> Result<Self> {
        Self::write_ahead_at(method, path, params, profile_label, None)
    }

    /// Like [`Self::write_ahead`], but writes to an explicit `audit_dir` when
    /// `Some(dir)` is supplied (`#344` Rev. 17).
    ///
    /// # Errors
    /// Fails closed with [`AuditWriteRefusal`] (exit code 8) if the write-ahead
    /// entry cannot be persisted.
    pub fn write_ahead_at(
        method: &str,
        path: &str,
        params: &[(&str, &str)],
        profile_label: &str,
        audit_dir: Option<&std::path::Path>,
    ) -> Result<Self> {
        let action = format!("{method} {path}");
        let (node, mut vmid) = parse_pve_path(path);
        if vmid.is_none() {
            vmid = params
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("vmid"))
                .and_then(|(_, v)| v.parse::<u32>().ok());
        }
        Self::write_ahead_custom_at(
            &action,
            node.as_deref(),
            vmid,
            params,
            profile_label,
            audit_dir,
        )
    }

    /// Write-ahead `"sent"` audit entry for non-REST mutations such as
    /// `"SSH patch apply"` (`#344`, Decision 3).
    ///
    /// # Errors
    /// Fails closed with [`AuditWriteRefusal`] (exit code 8) if the write-ahead
    /// entry cannot be persisted.
    pub fn write_ahead_custom(
        action: &str,
        node: Option<&str>,
        vmid: Option<u32>,
        params: &[(&str, &str)],
        profile_label: &str,
    ) -> Result<Self> {
        Self::write_ahead_custom_at(action, node, vmid, params, profile_label, None)
    }

    /// Like [`Self::write_ahead_custom`], but writes to an explicit `audit_dir`
    /// when `Some(dir)` is supplied (`#344` Rev. 17).
    ///
    /// # Errors
    /// Fails closed with [`AuditWriteRefusal`] (exit code 8) if the write-ahead
    /// entry cannot be persisted.
    pub fn write_ahead_custom_at(
        action: &str,
        node: Option<&str>,
        vmid: Option<u32>,
        params: &[(&str, &str)],
        profile_label: &str,
        audit_dir: Option<&std::path::Path>,
    ) -> Result<Self> {
        let user = crate::incident::operator_label();
        let params_json = redact_params_json(params, profile_label);
        log_mutation_sent(action, &user, vmid, node, &params_json, audit_dir)?;
        Ok(Self {
            action: action.to_string(),
            user,
            node: node.map(str::to_string),
            vmid,
            params_json,
            audit_dir: audit_dir.map(std::path::Path::to_path_buf),
        })
    }

    /// Append the post-operation outcome entry (`"ok <status>"` or
    /// `"error <status or transport>"`). Best-effort per Decision 1: if the
    /// outcome write fails after the mutation has already completed, logs
    /// `tracing::error!` without altering the caller's result.
    pub fn record_outcome(&self, outcome: &str) {
        if let Err(e) = with_cached_logger_at(self.audit_dir.as_deref(), |cached| {
            cached.logger.log(
                &self.action,
                &self.user,
                self.vmid,
                self.node.as_deref(),
                Some(&self.params_json),
                outcome,
            )
        }) {
            tracing::error!(
                action = %self.action,
                outcome = %outcome,
                "audit: failed to record mutation outcome entry: {e:#}"
            );
        }
    }
}

fn log_mutation_sent(
    action: &str,
    user: &str,
    vmid: Option<u32>,
    node: Option<&str>,
    params_json: &str,
    audit_dir: Option<&std::path::Path>,
) -> Result<()> {
    with_cached_logger_at(audit_dir, |cached| {
        if cached.initial_fail_count > 0 {
            anyhow::bail!(
                "audit chain integrity check failed ({} tampered or unverifiable row(s))",
                cached.initial_fail_count
            );
        }
        cached.logger.verify_tail()?;
        cached
            .logger
            .log(action, user, vmid, node, Some(params_json), "sent")
    })
    .map_err(|e| {
        anyhow::Error::from(AuditWriteRefusal {
            action: action.to_string(),
            reason: format!("{e:#}"),
        })
    })
}

fn now_unix_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, mo, d, h, m, s) = unix_to_ymdhms(secs);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn unix_to_ymdhms(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    (y, mo, d, h, m, s)
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut y = 1970u64;
    loop {
        let leap = is_leap(y);
        let dy = if leap { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        y += 1;
    }
    let months: [u64; 12] = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut mo = 1u64;
    for &dm in &months {
        if days < dm {
            break;
        }
        days -= dm;
        mo += 1;
    }
    (y, mo, days + 1)
}

const fn is_leap(y: u64) -> bool {
    (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400)
}

#[cfg(test)]
impl AuditLogger {
    /// In-memory `AuditLogger` with a fixed test key. Used exclusively
    /// by the proptest harness below to drive the full log → verify
    /// cycle without touching the OS keychain / data dir / global
    /// audit.db. The schema is identical to `open()`.
    fn for_test() -> Self {
        let conn = Connection::open_in_memory().expect("in-memory sqlite");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         TEXT    NOT NULL,
                action     TEXT    NOT NULL,
                user       TEXT    NOT NULL DEFAULT '',
                vmid       INTEGER,
                node       TEXT,
                params_json TEXT,
                result     TEXT    NOT NULL DEFAULT '',
                chain_hmac TEXT    NOT NULL,
                chain_version INTEGER NOT NULL DEFAULT 1,
                key_id     TEXT    NOT NULL DEFAULT 'primary'
            );",
        )
        .expect("create audit_log");
        // Fixed 32-byte test key — deterministic regression repro.
        let key = (0..32u8).collect::<Vec<u8>>();
        Self { conn, key }
    }
}

/// Property tests — invariants the HMAC chain MUST hold for ANY
/// sequence of log calls and ANY single-byte mutation.
///
/// The chain is the load-bearing security primitive of the audit log:
/// `proxxx audit verify` walks every entry and recomputes its MAC under the
/// row's own chain format (v2 for anything `for_test`/`log` writes, which
/// covers `prev || ts || action || user || vmid || node || params_json ||
/// result`). Any 1-byte mutation in any covered column of any row MUST break
/// the chain at that row. Without this, a tamperer could swap a `delete` for
/// a `start`, or rewrite WHO ran it, and walk away clean.
///
/// `proptest` exercises 256 random sequences per property; failures
/// shrink to the minimal mutation that breaks the contract.
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::collection::vec;
    use proptest::prelude::*;

    /// Generate a tuple of strings + optional fields shaped like a real
    /// `log()` call. Action / user / result are short ASCII to keep
    /// shrinking fast; vmid is bounded to PVE's actual range; node /
    /// params are bounded-length or absent.
    fn arb_entry() -> impl Strategy<
        Value = (
            String,
            String,
            Option<u32>,
            Option<String>,
            Option<String>,
            String,
        ),
    > {
        (
            "[a-z_]{1,12}",                                // action
            "[a-z][a-z0-9_]{1,10}",                        // user
            proptest::option::of(100u32..10_000),          // vmid
            proptest::option::of("[a-z0-9-]{3,12}"),       // node
            proptest::option::of("[a-z0-9 \":,_-]{0,40}"), // params_json (loose — we don't parse it here)
            "[a-z_]{1,12}",                                // result
        )
    }

    proptest! {
        /// Round-trip: log any sequence of valid entries, then verify
        /// returns ok = N, fail = 0. No surprise: this is the "the
        /// audit log works at all" sanity check.
        #[test]
        fn chain_round_trips(entries in vec(arb_entry(), 0..30)) {
            let mut logger = AuditLogger::for_test();
            for (action, user, vmid, node, params, result) in &entries {
                logger
                    .log(action, user, *vmid, node.as_deref(), params.as_deref(), result)
                    .expect("log");
            }
            let (ok, fail) = logger.verify().expect("verify");
            prop_assert_eq!(ok, entries.len());
            prop_assert_eq!(fail, 0);
        }

        /// Mutation detection — the security claim. Log N entries,
        /// then mutate any single column of any single row, then
        /// verify must report at least one broken link. Pins the
        /// non-repudiation contract: a tamperer cannot edit the log
        /// without leaving a forensic trail.
        ///
        /// The columns we test are exactly the ones folded into the v2
        /// HMAC: ts, action, user, vmid, node, params_json, result, and the
        /// stored chain_hmac itself. `for_test` writes v2 rows, so the actor
        /// (`user`) and parameters (`node`, `params_json`) are now in scope —
        /// see compute_hmac_v2 / #173.
        #[test]
        fn single_column_mutation_breaks_chain(
            entries in vec(arb_entry(), 1..15),
            target_idx in 0usize..15,
            field_idx in 0usize..8,
        ) {
            let mut logger = AuditLogger::for_test();
            for (action, user, vmid, node, params, result) in &entries {
                logger
                    .log(action, user, *vmid, node.as_deref(), params.as_deref(), result)
                    .expect("log");
            }
            let n = entries.len();
            let id = (target_idx % n) + 1; // sqlite ids start at 1

            // Pick a column from the in-chain set. Each mutation is a
            // straight UPDATE to a sentinel value that's syntactically
            // valid SQL but byte-different from whatever was stored.
            let column = [
                "ts", "action", "user", "vmid", "node", "params_json", "result", "chain_hmac",
            ][field_idx % 8];
            let sql = if column == "vmid" {
                "UPDATE audit_log SET vmid = COALESCE(vmid, 0) + 1 WHERE id = ?1".to_string()
            } else {
                format!("UPDATE audit_log SET {column} = 'TAMPERED-BY-PROPTEST' WHERE id = ?1")
            };
            logger.conn.execute(&sql, [id as i64]).expect("mutate");

            let (_ok, fail) = logger.verify().expect("verify");
            prop_assert!(
                fail >= 1,
                "mutating column {column} at id={id} should break ≥1 chain link, got fail=0"
            );
        }

        /// Localised cascade — pins the exact blast radius of a
        /// chain_hmac mutation. With the current `verify()` design,
        /// `prev` is set from the STORED hmac, not the COMPUTED one,
        /// so a single mutation at row K invalidates EXACTLY:
        ///   * row K itself (its stored hmac no longer matches the
        ///     recomputed value from row K-1's stored hmac), AND
        ///   * row K+1 (if it exists — its recomputed value uses
        ///     row K's stored TAMPERED hmac as prev, mismatching its
        ///     own original stored hmac).
        /// Row K+2 onwards re-converges, because row K+1's STORED
        /// hmac is still the original chain link.
        ///
        /// This is a deliberate design trade-off: precise pinpointing
        /// (which rows were touched) over full-cascade alarm. An
        /// auditor sees "rows 5 and 6 are corrupt" instead of "rows
        /// 5–N are corrupt"; the former is actionable, the latter is
        /// noise.
        ///
        /// Pinning the exact fail count protects this design choice
        /// from a future "optimisation" that switches to `prev =
        /// computed` (which would cascade to the end of the log) or
        /// changes the chain shape some other way.
        #[test]
        fn chain_hmac_mutation_breaks_self_and_next_only(
            entries in vec(arb_entry(), 2..15),
            target_idx in 0usize..15,
        ) {
            let mut logger = AuditLogger::for_test();
            for (action, user, vmid, node, params, result) in &entries {
                logger
                    .log(action, user, *vmid, node.as_deref(), params.as_deref(), result)
                    .expect("log");
            }
            let n = entries.len();
            let id = (target_idx % n) + 1;
            logger
                .conn
                .execute(
                    "UPDATE audit_log SET chain_hmac = 'TAMPERED-BY-PROPTEST' WHERE id = ?1",
                    [id as i64],
                )
                .expect("mutate");
            let (_ok, fail) = logger.verify().expect("verify");
            // Last row mutated → 1 failure (no next row to taint).
            // Earlier rows → 2 failures (self + next).
            let expected_fail = if id == n { 1 } else { 2 };
            prop_assert_eq!(
                fail, expected_fail,
                "mutating chain_hmac at id={} of {} should produce {} failures, got {}",
                id, n, expected_fail, fail
            );
        }

        /// #173 regression. `user` (WHO), `node` and `params_json` (WHAT)
        /// ARE folded into the v2 chain. Mutating any of them MUST break at
        /// least one link — a local tamperer can no longer rewrite the actor
        /// or the parameters of a logged action and walk away clean.
        ///
        /// This is the inverse of the old `..._does_not_break_chain` property
        /// (pre-v2): if it ever flips back, the chain has silently regressed
        /// to leaving who/what unprotected.
        #[test]
        fn user_node_params_mutation_breaks_chain(
            entries in vec(arb_entry(), 1..10),
            target_idx in 0usize..10,
            col_idx in 0usize..3,
        ) {
            let mut logger = AuditLogger::for_test();
            for (action, user, vmid, node, params, result) in &entries {
                logger
                    .log(action, user, *vmid, node.as_deref(), params.as_deref(), result)
                    .expect("log");
            }
            let n = entries.len();
            let id = (target_idx % n) + 1;
            let col = ["user", "node", "params_json"][col_idx % 3];
            let sql = format!("UPDATE audit_log SET {col} = 'TAMPERED' WHERE id = ?1");
            logger.conn.execute(&sql, [id as i64]).expect("mutate");
            let (_ok, fail) = logger.verify().expect("verify");
            prop_assert!(
                fail >= 1,
                "{} is part of the v2 chain — mutating it MUST break ≥1 link, got fail=0",
                col
            );
        }
    }

    /// Backward-compatibility for the v1→v2 migration (#173): a hand-written
    /// legacy v1 row keeps verifying under the v1 formula even when v2 rows
    /// are appended on top, AND retains v1 semantics (its `user` is NOT
    /// chain-covered), while new v2 rows DO cover `user`. This is the exact
    /// contract that lets an existing `audit.db` survive the upgrade.
    #[test]
    fn legacy_v1_row_verifies_alongside_v2_and_keeps_v1_semantics() {
        let mut logger = AuditLogger::for_test();

        // Insert a legacy v1 row exactly as the pre-#173 code would have:
        // chain_version = 1, hmac over (prev="" || ts || action || vmid || result).
        let ts = "2026-01-01T00:00:00Z";
        let v1_hmac = compute_hmac(&logger.key, "", ts, "delete", "100", "ok");
        logger
            .conn
            .execute(
                "INSERT INTO audit_log
                    (ts, action, user, vmid, node, params_json, result, chain_hmac, chain_version)
                 VALUES (?1, 'delete', 'alice', 100, NULL, '{\"k\":1}', 'ok', ?2, 1)",
                params![ts, v1_hmac],
            )
            .expect("insert v1");

        // Append a v2 row; it chains onto the v1 row's stored hmac.
        logger
            .log(
                "apply",
                "bob",
                Some(200),
                Some("pve1"),
                Some("{\"k\":2}"),
                "ok",
            )
            .expect("log v2");

        let (ok, fail) = logger.verify().expect("verify");
        assert_eq!((ok, fail), (2, 0), "mixed v1+v2 chain must verify clean");

        // v1 semantics preserved: the legacy row does NOT cover `user`, so
        // rewriting its actor must NOT break the chain (it predates #173).
        logger
            .conn
            .execute("UPDATE audit_log SET user = 'mallory' WHERE id = 1", [])
            .unwrap();
        let (_ok, fail) = logger.verify().expect("verify");
        assert_eq!(fail, 0, "v1 row predates user coverage — must still verify");

        // But the v2 row DOES cover `user` — rewriting its actor must break it.
        logger
            .conn
            .execute("UPDATE audit_log SET user = 'mallory' WHERE id = 2", [])
            .unwrap();
        let (_ok, fail) = logger.verify().expect("verify");
        assert!(
            fail >= 1,
            "v2 row covers user — mutation must break the chain"
        );
    }
}

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn load_or_create_key_rejects_malformed_length() {
        // A wrong-length key must be refused — an empty/truncated key would
        // otherwise degrade the HMAC chain to a forgeable all-zeros MAC.
        let bad = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(bad.path(), b"short").unwrap(); // 5 bytes, not 32
        let err = load_or_create_key(&bad.path().to_path_buf()).unwrap_err();
        assert!(err.to_string().contains("expected 32"), "got: {err}");

        // A correct 32-byte key loads fine.
        let good = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(good.path(), [7u8; 32]).unwrap();
        // NamedTempFile is 0600 by default, so this exercises the happy path.
        let key = load_or_create_key(&good.path().to_path_buf()).unwrap();
        assert_eq!(key.len(), 32);
    }

    /// Custody: a group/world-readable audit key must be refused on load — a
    /// key another local user can read defeats the whole tamper-evidence
    /// scheme (they can recompute every MAC). Mirrors `bot_token_file` 0600.
    #[cfg(unix)]
    #[test]
    fn load_key_rejects_group_or_world_readable_perms() {
        use std::os::unix::fs::PermissionsExt;
        let f = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(f.path(), [3u8; 32]).unwrap(); // valid length…
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = load_or_create_key(&f.path().to_path_buf()).unwrap_err();
        assert!(
            err.to_string().contains("unsafe permissions") && err.to_string().contains("0600"),
            "lax-perms key must be refused with an actionable message, got: {err}"
        );

        // Tightening to 0600 makes the same key load.
        std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            load_or_create_key(&f.path().to_path_buf()).unwrap().len(),
            32
        );
    }

    #[test]
    fn audit_key_path_override_takes_precedence() {
        let data_dir = std::path::Path::new("/var/lib/proxxx");
        // Default: co-located next to the DB.
        assert_eq!(
            resolve_audit_key_path(None, data_dir),
            data_dir.join("audit.key")
        );
        assert_eq!(
            resolve_audit_key_path(Some(String::new()), data_dir),
            data_dir.join("audit.key"),
            "empty override is ignored"
        );
        // Override relocates the key off the DB's volume.
        assert_eq!(
            resolve_audit_key_path(Some("/secure/mnt/proxxx.key".into()), data_dir),
            PathBuf::from("/secure/mnt/proxxx.key")
        );
    }
}

#[cfg(test)]
mod key_rotation_tests {
    use super::{compute_hmac_v2, retired_key_path, CHAIN_V2};
    use rusqlite::{params, Connection};

    /// #281 — the whole point: rotating must NOT invalidate the history
    /// it exists to protect. Before this, rotation meant deleting the
    /// key and starting a new chain, so the correct response to a host
    /// compromise destroyed the evidence.
    ///
    /// Driven against an in-memory DB and explicit keys rather than the
    /// real paths: `PROXXX_AUDIT_DIR` is process-global and cargo runs
    /// these in parallel, so mutating it races every sibling test — a
    /// hazard this codebase already documents elsewhere.
    #[test]
    fn a_row_verifies_under_the_key_that_signed_it_not_the_current_one() {
        let old_key = vec![7u8; 32];
        let new_key = vec![9u8; 32];

        // A row signed with the OLD key.
        let ts = "2026-09-09T00:00:00Z";
        let mac_old = compute_hmac_v2(&old_key, "", ts, "test.before", "tester", "", "", "", "OK");

        // Verifying it against the NEW key must fail — this is what
        // "rotation invalidated the history" looked like.
        let mac_under_new =
            compute_hmac_v2(&new_key, "", ts, "test.before", "tester", "", "", "", "OK");
        assert_ne!(
            mac_old, mac_under_new,
            "sanity: the two keys must produce different MACs"
        );

        // Verifying it against the key it was signed with must pass.
        // That is exactly what `verify` now does, via the row's key_id.
        let recomputed =
            compute_hmac_v2(&old_key, "", ts, "test.before", "tester", "", "", "", "OK");
        assert_eq!(
            recomputed, mac_old,
            "a row must verify under the key that signed it"
        );
    }

    /// The schema carries the key id per row, so `verify` can make that
    /// choice at all. Without the column there is nothing to select on.
    #[test]
    fn the_schema_records_which_key_signed_each_row() {
        let conn = Connection::open_in_memory().expect("sqlite");
        conn.execute_batch(
            "CREATE TABLE audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL, action TEXT NOT NULL, user TEXT NOT NULL DEFAULT '',
                vmid INTEGER, node TEXT, params_json TEXT,
                result TEXT NOT NULL DEFAULT '', chain_hmac TEXT NOT NULL,
                chain_version INTEGER NOT NULL DEFAULT 1
            );",
        )
        .expect("create");

        // A pre-rotation database has no key_id column at all.
        super::migrate_key_id(&conn).expect("migrate");
        let has: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('audit_log') WHERE name = 'key_id'",
                [],
                |r| r.get(0),
            )
            .expect("query");
        assert_eq!(has, 1, "migration must add key_id");

        // Existing rows default to `primary` — the key they were signed
        // with — rather than to NULL or to the new key.
        conn.execute(
            "INSERT INTO audit_log (ts, action, chain_hmac, chain_version)
             VALUES (?1, ?2, ?3, ?4)",
            params!["2026-01-01T00:00:00Z", "legacy", "deadbeef", CHAIN_V2],
        )
        .expect("insert");
        let key_id: String = conn
            .query_row("SELECT key_id FROM audit_log LIMIT 1", [], |r| r.get(0))
            .expect("read");
        assert_eq!(key_id, super::PRIMARY_KEY_ID);

        // Migration is idempotent — `open()` runs it on every call.
        super::migrate_key_id(&conn).expect("second migrate is a no-op");
    }

    /// Retired keys are archived beside the primary, so a backup of the
    /// audit directory captures the whole verifiable history.
    #[test]
    fn a_retired_key_is_archived_next_to_the_primary() {
        let path = retired_key_path("retired-1757000000").expect("path");
        let name = path
            .file_name()
            .expect("filename")
            .to_string_lossy()
            .into_owned();
        assert!(
            name.ends_with(".retired-1757000000"),
            "the id must be in the filename so the pairing is obvious: {name}"
        );
        assert_eq!(
            path.parent(),
            super::audit_key_path().expect("primary").parent(),
            "retired keys live beside the primary, so one backup covers both"
        );
    }

    #[test]
    fn parse_pve_path_extracts_node_and_vmid_when_present() {
        assert_eq!(
            super::parse_pve_path("/nodes/pve1/qemu/100/status/stop"),
            (Some("pve1".to_string()), Some(100))
        );
        assert_eq!(
            super::parse_pve_path("/nodes/pve2/lxc/205/snapshot"),
            (Some("pve2".to_string()), Some(205))
        );
        assert_eq!(
            super::parse_pve_path("/nodes/pve1/qemu/100?purge=1&destroy-unreferenced-disks=1"),
            (Some("pve1".to_string()), Some(100))
        );
        assert_eq!(
            super::parse_pve_path("/nodes/pve3/apt/update"),
            (Some("pve3".to_string()), None)
        );
        assert_eq!(super::parse_pve_path("/access/users"), (None, None));
    }

    #[test]
    fn redact_params_json_redacts_secrets_and_includes_profile() {
        let json = super::redact_params_json(
            &[
                ("userid", "alice@pve"),
                ("password", "hunter2"),
                ("keys", "ssh-ed25519 AAAAsecret"),
                ("comment", "normal comment"),
            ],
            "prod",
        );
        assert!(!json.contains("hunter2"));
        assert!(!json.contains("AAAAsecret"));
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(parsed["profile"], "prod");
        assert_eq!(parsed["userid"], "alice@pve");
        assert_eq!(parsed["password"], "[REDACTED]");
        assert_eq!(parsed["keys"], "[REDACTED]");
        assert_eq!(parsed["comment"], "normal comment");
        assert_eq!(super::AuditWriteRefusal::EXIT_CODE, 8);
    }

    /// `#344` Rev. 17 regression guard: no file under `src/` or `tests/` may
    /// mutate the process-global `PROXXX_AUDIT_DIR` or `PROXXX_AUDIT_KEY` env
    /// vars at runtime (`set_var` / `remove_var`). Tests must inject an
    /// explicit audit directory via `with_audit_dir` / `open_in` /
    /// `write_ahead_at` (or pass `.env(...)` to child `Command` processes).
    #[test]
    fn no_source_or_test_file_mutates_proxxx_audit_env() {
        fn collect_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let entries = std::fs::read_dir(dir)
                .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()));
            for entry in entries {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    collect_rs_files(&path, out);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    out.push(path);
                }
            }
        }

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        collect_rs_files(&root.join("src"), &mut files);
        collect_rs_files(&root.join("tests"), &mut files);
        assert!(
            !files.is_empty(),
            "expected to scan .rs files under src/ and tests/"
        );

        let forbidden: Vec<String> = ["set_var", "remove_var"]
            .into_iter()
            .flat_map(|op| {
                ["PROXXX_AUDIT_DIR", "PROXXX_AUDIT_KEY"]
                    .into_iter()
                    .map(move |var| format!("{op}(\"{var}\""))
            })
            .collect();

        let mut violations = Vec::new();
        for file in files {
            let content = std::fs::read_to_string(&file)
                .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));
            for (line_no, line) in content.lines().enumerate() {
                for pat in &forbidden {
                    if line.contains(pat) {
                        violations.push(format!(
                            "{}:{}: forbidden `{}` (inject audit_dir instead of mutating process env)",
                            file.strip_prefix(root).unwrap_or(&file).display(),
                            line_no + 1,
                            pat
                        ));
                    }
                }
            }
        }
        assert!(
            violations.is_empty(),
            "process-global PROXXX_AUDIT_DIR / PROXXX_AUDIT_KEY mutation found:\n{}",
            violations.join("\n")
        );
    }
}
