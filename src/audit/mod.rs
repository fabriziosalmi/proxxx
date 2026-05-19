//! Append-only audit log backed by `SQLite`.
//! Each entry is HMAC-SHA256 signed using a chained scheme:
//! `chain_hmac = HMAC(key, prev_chain_hmac || ts || action || vmid_str || result)`
//! The chain is verifiable offline via `proxxx audit verify`.

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
                chain_hmac TEXT    NOT NULL
            );",
        )?;
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
        let chain_hmac = compute_hmac(&self.key, &prev_hmac, &ts, action, &vmid_str, result);
        self.conn.execute(
            "INSERT INTO audit_log (ts, action, user, vmid, node, params_json, result, chain_hmac)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                ts,
                action,
                user,
                vmid.map(i64::from),
                node,
                params_json,
                result,
                chain_hmac,
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
        let mut stmt = self
            .conn
            .prepare("SELECT id,ts,action,vmid,result,chain_hmac FROM audit_log ORDER BY id ASC")?;
        let mut prev = String::new();
        let mut ok = 0usize;
        let mut fail = 0usize;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Option<i64>>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?;
        for row in rows {
            let (_, ts, action, vmid, result, stored_hmac) = row?;
            let vmid_str = vmid.map(|v| v.to_string()).unwrap_or_default();
            let expected = compute_hmac(&self.key, &prev, &ts, &action, &vmid_str, &result);
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
        self.conn
            .query_row(
                "SELECT chain_hmac FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get::<_, String>(0),
            )
            .unwrap_or_default()
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
    // new_from_slice only fails if key is empty; we always pass a 32-byte key.
    // Fall back to a zeroed key rather than propagating an error through a non-Result fn.
    let key_used: &[u8] = if key.is_empty() { &[0u8; 32] } else { key };
    let Ok(mut mac) = HmacSha256::new_from_slice(key_used) else {
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

fn load_or_create_key(path: &PathBuf) -> Result<Vec<u8>> {
    if path.exists() {
        let bytes =
            std::fs::read(path).with_context(|| format!("read audit key {}", path.display()))?;
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

fn audit_db_path() -> Result<PathBuf> {
    let base = directories::ProjectDirs::from("dev", "proxxx", "proxxx")
        .ok_or_else(|| anyhow::anyhow!("cannot resolve data dir"))?;
    let dir = base.data_local_dir().to_path_buf();
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join("audit.db"))
}

fn audit_key_path() -> Result<PathBuf> {
    let base = directories::ProjectDirs::from("dev", "proxxx", "proxxx")
        .ok_or_else(|| anyhow::anyhow!("cannot resolve data dir"))?;
    Ok(base.data_local_dir().join("audit.key"))
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
                chain_hmac TEXT    NOT NULL
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
/// `proxxx audit verify` walks every entry and recomputes
/// `chain_hmac = HMAC(key, prev_chain_hmac || ts || action || vmid || result)`.
/// Any 1-byte mutation in any non-key column of any row MUST break the
/// chain at that row (and cascade to every following row). Without
/// this, a tamperer could swap a `delete` for a `start` and walk away
/// clean.
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
        /// The four columns we test are exactly the ones folded into
        /// the HMAC: ts, action, vmid (as i64), result, and the stored
        /// chain_hmac itself. (`user`, `node`, `params_json` are stored
        /// but intentionally NOT part of the chain — see compute_hmac.
        /// Mutating those does NOT break the chain by design.)
        #[test]
        fn single_column_mutation_breaks_chain(
            entries in vec(arb_entry(), 1..15),
            target_idx in 0usize..15,
            field_idx in 0usize..5,
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
            let column = ["ts", "action", "vmid", "result", "chain_hmac"][field_idx % 5];
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

        /// Out-of-chain columns (`user`, `node`, `params_json`) are
        /// stored but NOT folded into the HMAC — that's intentional
        /// per `compute_hmac` which only mixes in (ts, action, vmid,
        /// result). Verify pins this DESIGN BOUNDARY: mutating
        /// `user` / `node` / `params_json` MUST NOT break the chain.
        ///
        /// If this changes (and we extend chain coverage to those
        /// columns), this property fails loudly and the doc-comment
        /// at the top of the file needs updating in lockstep.
        #[test]
        fn user_node_params_mutation_does_not_break_chain(
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
            let (ok, fail) = logger.verify().expect("verify");
            prop_assert_eq!(
                fail, 0,
                "{} is not part of the chain — mutating it MUST NOT trigger fail, got fail={} ok={}",
                col, fail, ok
            );
        }
    }
}
