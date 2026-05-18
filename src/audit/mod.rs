//! Append-only audit log backed by SQLite.
//! Each entry is HMAC-SHA256 signed using a chained scheme:
//! `chain_hmac = HMAC(key, prev_chain_hmac || ts || action || vmid_str || result)`
//! The chain is verifiable offline via `proxxx audit verify`.

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
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
        let prev_hmac = self.last_chain_hmac()?;
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
                vmid.map(|v| v as i64),
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

    fn last_chain_hmac(&self) -> Result<String> {
        let result: rusqlite::Result<String> = self.conn.query_row(
            "SELECT chain_hmac FROM audit_log ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        );
        Ok(result.unwrap_or_default())
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
    getrandom::getrandom(&mut key).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
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

fn is_leap(y: u64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}
