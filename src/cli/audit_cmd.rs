//! `proxxx audit` subcommand — view, export, verify the append-only audit log.

use anyhow::Result;
use clap::Subcommand;
use serde_json::Value;

#[derive(Debug, Subcommand)]
pub enum AuditAction {
    /// Show recent audit log entries
    Log {
        /// Max entries to show (default 50)
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Show entries since this ISO timestamp (e.g. 2026-05-01T00:00:00Z)
        #[arg(long)]
        since: Option<String>,
    },
    /// Export audit log to JSON or CSV
    Export {
        /// Output format: json (default) or csv
        #[arg(long, default_value = "json")]
        format: String,
        /// Max entries to export (default all = 1000000)
        #[arg(long, default_value_t = 1_000_000)]
        limit: usize,
        /// Export entries since this ISO timestamp
        #[arg(long)]
        since: Option<String>,
    },
    /// Verify cryptographic integrity of the audit log chain
    Verify,
    /// Rotate the HMAC key, keeping existing entries verifiable.
    ///
    /// The current key is archived beside the primary under a
    /// timestamped id and every existing row is re-pointed at it, so
    /// `audit verify` keeps checking those rows against the key that
    /// actually signed them. Before this existed, rotating meant
    /// deleting the key and starting a new chain — which destroyed the
    /// verifiability of exactly the history an investigation needs, so
    /// in practice the key was permanent (audit #281).
    ///
    /// Rotate after a host compromise, or on whatever schedule your
    /// policy sets. Back up the retired keys: without them the rows they
    /// signed can no longer be verified.
    RotateKey,
}

pub fn execute_log(limit: usize, since: Option<&str>) -> Result<(Value, i32)> {
    let logger = crate::audit::AuditLogger::open()?;
    let entries = logger.query(limit, since)?;
    Ok((serde_json::to_value(&entries)?, 0))
}

pub fn execute_export(format: &str, limit: usize, since: Option<&str>) -> Result<(Value, i32)> {
    let logger = crate::audit::AuditLogger::open()?;
    let entries = logger.query(limit, since)?;
    if format == "csv" {
        let mut csv = String::from("id,ts,action,user,vmid,node,result,chain_hmac\n");
        for e in &entries {
            csv.push_str(&format!(
                "{},{},{},{},{},{},{},{}\n",
                e.id,
                e.ts,
                e.action,
                e.user,
                e.vmid.map(|v| v.to_string()).unwrap_or_default(),
                e.node.as_deref().unwrap_or(""),
                e.result,
                e.chain_hmac,
            ));
        }
        Ok((serde_json::json!({"csv": csv}), 0))
    } else {
        Ok((serde_json::to_value(&entries)?, 0))
    }
}

pub fn execute_verify() -> Result<(Value, i32)> {
    let logger = crate::audit::AuditLogger::open()?;
    let (ok, fail) = logger.verify()?;
    let status = if fail == 0 { "ok" } else { "tampered" };
    let exit_code = i32::from(fail != 0);
    Ok((
        serde_json::json!({"verified": ok, "failed": fail, "status": status}),
        exit_code,
    ))
}

/// `proxxx audit rotate-key` — see [`AuditAction::RotateKey`].
///
/// # Errors
/// When there is no key to rotate, or the archive/write fails.
pub fn execute_rotate_key() -> Result<(Value, i32)> {
    let key_id = crate::audit::rotate_key()?;
    Ok((
        serde_json::json!({
            "status": "rotated",
            "retired_key_id": key_id,
            "note": "Existing entries remain verifiable under the retired key. \
                     Back it up: without it those rows cannot be verified.",
        }),
        0,
    ))
}
