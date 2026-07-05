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

/// Append-only SQLite-backed audit logger.
pub struct AuditLogger {
    conn: Connection,
    key: Vec<u8>,
}

impl AuditLogger {
    pub fn open() -> Result<Self> {
        let path = audit_db_path()?;
        let key = load_or_create_key(&audit_key_path()?)?;
        let conn = Connection::open(&path)
            .with_context(|| format!("open audit db at {}", path.display()))?;
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
                chain_version INTEGER NOT NULL DEFAULT 1
            );",
        )?;
        migrate_chain_version(&conn)?;
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
        let prev_hmac = self.last_chain_hmac();
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
                (ts, action, user, vmid, node, params_json, result, chain_hmac, chain_version)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
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
        let mut stmt = self.conn.prepare(
            "SELECT ts,action,user,vmid,node,params_json,result,chain_hmac,chain_version
             FROM audit_log ORDER BY id ASC",
        )?;
        let mut prev = String::new();
        let mut ok = 0usize;
        let mut fail = 0usize;
        let rows = stmt.query_map([], |r| {
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
            ))
        })?;
        for row in rows {
            let (ts, action, user, vmid, node, params, result, stored_hmac, version) = row?;
            let vmid_str = vmid.map(|v| v.to_string()).unwrap_or_default();
            // Recompute under each row's OWN chain format, so legacy v1 rows
            // keep verifying after the migration while new v2 rows get the
            // stronger who/what coverage.
            let expected = if version == CHAIN_V2 {
                compute_hmac_v2(
                    &self.key,
                    &prev,
                    &ts,
                    &action,
                    &user,
                    &vmid_str,
                    node.as_deref().unwrap_or(""),
                    params.as_deref().unwrap_or(""),
                    &result,
                )
            } else {
                compute_hmac(&self.key, &prev, &ts, &action, &vmid_str, &result)
            };
            if expected == stored_hmac {
                ok += 1;
            } else {
                fail += 1;
            }
            prev = stored_hmac;
        }
        Ok((ok, fail))
    }

    fn last_chain_hmac(&self) -> String {
        match self.conn.query_row(
            "SELECT chain_hmac FROM audit_log ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        ) {
            Ok(h) => h,
            // Empty log — this is the first entry; an empty prev-hmac is correct.
            Err(rusqlite::Error::QueryReturnedNoRows) => String::new(),
            // A real read error must not silently start a fresh chain segment.
            Err(e) => {
                tracing::warn!(
                    "audit: could not read last chain hmac ({e}) — starting a new chain segment"
                );
                String::new()
            }
        }
    }
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

fn load_or_create_key(path: &PathBuf) -> Result<Vec<u8>> {
    if path.exists() {
        // Custody check: the HMAC key is the ONLY thing standing between a
        // local tamperer and a forged audit chain. A group/world-readable key
        // lets any other user on the host read it and recompute every MAC —
        // silently defeating tamper-evidence. Refuse it, mirroring the
        // `telegram.bot_token_file` 0600 enforcement. (The key we *create*
        // below is already 0600; this catches one restored from a backup, an
        // over-permissive umask, or a hand-placed key on a separate volume.)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(path) {
                let mode = meta.permissions().mode();
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
            }
        }
        let bytes =
            std::fs::read(path).with_context(|| format!("read audit key {}", path.display()))?;
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

/// Directory holding the audit DB + key. Honors `PROXXX_AUDIT_DIR` (for
/// hermetic tests, and for relocating the trail onto a dedicated volume in
/// ops); otherwise the platform data-local dir. Mirrors the `PROXXX_CONFIG` /
/// `PROXXX_FREEZE_PATH` override convention. The directory is created if absent.
fn audit_data_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("PROXXX_AUDIT_DIR") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("create PROXXX_AUDIT_DIR {}", dir.display()))?;
        return Ok(dir);
    }
    let base = directories::ProjectDirs::from("dev", "proxxx", "proxxx")
        .ok_or_else(|| anyhow::anyhow!("cannot resolve data dir"))?;
    let dir = base.data_local_dir().to_path_buf();
    std::fs::create_dir_all(&dir)?;
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
                chain_version INTEGER NOT NULL DEFAULT 1
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
