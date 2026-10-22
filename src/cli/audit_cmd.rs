//! `proxxx audit` subcommand — view, export, verify the append-only audit log.

use anyhow::Result;
use clap::{Subcommand, ValueEnum};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum AuditExportFormat {
    #[default]
    Json,
    Csv,
}

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
        #[arg(long, value_enum, default_value_t = AuditExportFormat::Json)]
        export_format: AuditExportFormat,
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

pub fn execute_export(
    export_format: AuditExportFormat,
    limit: usize,
    since: Option<&str>,
) -> Result<(Value, i32)> {
    let logger = crate::audit::AuditLogger::open()?;
    let entries = logger.query(limit, since)?;
    if export_format == AuditExportFormat::Csv {
        // raw-output: CSV for spreadsheets and scripts; the format pipeline would wrap it in JSON
        print!("{}", entries_to_csv(&entries));
        Ok((Value::Null, 0))
    } else {
        Ok((serde_json::to_value(&entries)?, 0))
    }
}

/// Render audit entries as RFC 4180 CSV: a header row, CRLF-free `\n`
/// line ends, and any field holding a comma, quote, CR or LF quoted with
/// its quotes doubled (audit #383: fields were written unquoted, so a
/// comma in a result message shifted every later column).
#[must_use]
pub fn entries_to_csv(entries: &[crate::audit::AuditEntry]) -> String {
    fn field(out: &mut String, value: &str) {
        if value.contains([',', '"', '\r', '\n']) {
            out.push('"');
            out.push_str(&value.replace('"', "\"\""));
            out.push('"');
        } else {
            out.push_str(value);
        }
    }
    let mut csv = String::from("id,ts,action,user,vmid,node,result,chain_hmac\n");
    for e in entries {
        let vmid = e.vmid.map(|v| v.to_string()).unwrap_or_default();
        let row = [
            e.id.to_string(),
            e.ts.clone(),
            e.action.clone(),
            e.user.clone(),
            vmid,
            e.node.clone().unwrap_or_default(),
            e.result.clone(),
            e.chain_hmac.clone(),
        ];
        for (i, value) in row.iter().enumerate() {
            if i > 0 {
                csv.push(',');
            }
            field(&mut csv, value);
        }
        csv.push('\n');
    }
    csv
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

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(result: &str, node: Option<&str>) -> crate::audit::AuditEntry {
        crate::audit::AuditEntry {
            id: 7,
            ts: "2026-10-22T10:00:00Z".into(),
            action: "vm_stop".into(),
            user: "fab".into(),
            vmid: Some(100),
            node: node.map(Into::into),
            params_json: None,
            result: result.into(),
            chain_hmac: "abc".into(),
        }
    }

    #[test]
    fn csv_quotes_fields_that_hold_separators_quotes_or_newlines() {
        let csv = entries_to_csv(&[
            entry("ok", Some("pve1")),
            entry("error: 500, \"busy\"\nretry", None),
        ]);
        let lines: Vec<&str> = csv.split_inclusive('\n').collect();
        assert_eq!(lines[0], "id,ts,action,user,vmid,node,result,chain_hmac\n");
        assert_eq!(
            lines[1],
            "7,2026-10-22T10:00:00Z,vm_stop,fab,100,pve1,ok,abc\n"
        );
        // The second row spans two physical lines inside one quoted field.
        assert_eq!(
            &csv[lines[0].len() + lines[1].len()..],
            "7,2026-10-22T10:00:00Z,vm_stop,fab,100,,\"error: 500, \"\"busy\"\"\nretry\",abc\n"
        );
    }
}
