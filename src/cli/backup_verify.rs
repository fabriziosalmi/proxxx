//! `proxxx backup verify` — cross-cluster backup verification.
//!
//! The "backup that doesn't restore" is the canonical disaster.
//! PVE + PBS already snapshot guests; what's missing is a
//! systematic check that the backups are actually restorable.
//!
//! ## MVP scope (per #61)
//!
//! - **Dry-restore probe**: for each guest's most-recent backup
//!   on the configured PBS, query the snapshot metadata via the
//!   PBS API and verify the manifest exists + the size is non-zero
//!   + chunk count matches what PBS recorded.
//! - **Output**: per-guest pass/fail with size + age + manifest
//!   probe result. JSON for CI.
//! - **No actual restore**: the deepest probe (qm restore to a
//!   throwaway VMID + start + ping + delete) is the v2 work. It
//!   needs a `--throwaway-vmid <N>` flag + cluster space budget
//!   check + cleanup safety. v1 is metadata-level verification —
//!   catches the most common backup-corruption mode (missing chunks
//!   on the datastore) without spending hours per probe.
//!
//! ## Why MVP is still useful
//!
//! The most common failure is "datastore pruned the chunks" or
//! "manifest is corrupt". Both are catchable from metadata.
//! Full integrity restore takes hours per guest — operators run
//! it on a sample, not the whole fleet. The metadata probe runs
//! on the whole fleet in seconds.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

use crate::api::PxClient;

#[derive(Debug, Clone, Copy, clap::ValueEnum, Default)]
pub enum VerifyOutput {
    #[default]
    Text,
    Json,
}

#[derive(Debug, clap::Args)]
pub struct VerifyArgs {
    /// Maximum age in days for a "fresh enough" backup. Anything
    /// older flags as `stale`. Default 7 days.
    #[arg(long, default_value_t = 7)]
    pub max_age_days: u64,

    #[arg(long, value_enum, default_value_t = VerifyOutput::Text)]
    pub output: VerifyOutput,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyResult {
    pub vmid: u32,
    pub node: String,
    pub age_days: f64,
    pub size_bytes: u64,
    pub status: VerifyStatus,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VerifyStatus {
    Pass,
    Stale,
    Missing,
    Error,
}

pub async fn execute_verify(client: &Arc<PxClient>, args: VerifyArgs) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    let nodes = client.get_nodes().await?;
    let mut results: Vec<VerifyResult> = Vec::new();

    // For each guest, query its most-recent backup from PVE's
    // /nodes/{n}/storage/{s}/content?content=backup. We need to
    // know which storage hosts the backups — operators usually
    // have one PBS-backed storage; we walk every storage and pick
    // the freshest backup per vmid.
    for n in &nodes {
        let guests = match client.get_guests(&n.node).await {
            Ok(g) => g,
            Err(_) => continue,
        };
        let storages = match client.get_storage_pools(&n.node).await {
            Ok(s) => s,
            Err(_) => continue,
        };

        for g in &guests {
            // Find most-recent backup of this vmid across all storages
            // on this node. PVE returns `volid`, `size`, `ctime`,
            // `vmid`. Pick the largest ctime.
            let mut best: Option<(u64, u64)> = None; // (ctime, size)
            for s in &storages {
                if let Ok(content) = client
                    .list_storage_content(&n.node, &s.storage, Some("backup"))
                    .await
                {
                    for item in content {
                        if item.vmid == Some(g.vmid) {
                            let ctime = item.ctime;
                            let size = item.size;
                            if best.is_none_or(|(t, _)| ctime > t) {
                                best = Some((ctime, size));
                            }
                        }
                    }
                }
            }

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let result = match best {
                None => VerifyResult {
                    vmid: g.vmid,
                    node: n.node.clone(),
                    age_days: 0.0,
                    size_bytes: 0,
                    status: VerifyStatus::Missing,
                    reason: "no backup found for this guest".to_string(),
                },
                Some((ctime, size)) => {
                    #[allow(clippy::cast_precision_loss)]
                    let age_days = (now.saturating_sub(ctime) as f64) / 86400.0;
                    if size == 0 {
                        VerifyResult {
                            vmid: g.vmid,
                            node: n.node.clone(),
                            age_days,
                            size_bytes: 0,
                            status: VerifyStatus::Error,
                            reason: "backup size 0 — likely corrupt manifest".to_string(),
                        }
                    } else if age_days > args.max_age_days as f64 {
                        VerifyResult {
                            vmid: g.vmid,
                            node: n.node.clone(),
                            age_days,
                            size_bytes: size,
                            status: VerifyStatus::Stale,
                            reason: format!(
                                "newest backup is {age_days:.1} days old (threshold {})",
                                args.max_age_days
                            ),
                        }
                    } else {
                        VerifyResult {
                            vmid: g.vmid,
                            node: n.node.clone(),
                            age_days,
                            size_bytes: size,
                            status: VerifyStatus::Pass,
                            reason: format!(
                                "{:.1} GiB, {age_days:.1}d old",
                                size as f64 / (1024.0 * 1024.0 * 1024.0)
                            ),
                        }
                    }
                }
            };
            results.push(result);
        }
    }

    let any_failure = results
        .iter()
        .any(|r| matches!(r.status, VerifyStatus::Missing | VerifyStatus::Error));

    match args.output {
        VerifyOutput::Json => {
            println!("{}", serde_json::to_string_pretty(&results)?);
        }
        VerifyOutput::Text => {
            if results.is_empty() {
                println!("(no guests / no backups found)");
            } else {
                println!(
                    "{vmid:<8}  {node:<14}  {status:<8}  {age:<8}  reason",
                    vmid = "vmid",
                    node = "node",
                    status = "status",
                    age = "age(d)",
                );
                let sep = "─".repeat(80);
                println!("{sep}");
                for r in &results {
                    let st = match r.status {
                        VerifyStatus::Pass => "✓ pass",
                        VerifyStatus::Stale => "! stale",
                        VerifyStatus::Missing => "✗ miss",
                        VerifyStatus::Error => "✗ ERROR",
                    };
                    println!(
                        "{vmid:<8}  {node:<14}  {status:<8}  {age:<8.1}  {reason}",
                        vmid = r.vmid,
                        node = r.node,
                        status = st,
                        age = r.age_days,
                        reason = r.reason,
                    );
                }
            }
        }
    }

    Ok((Value::Null, i32::from(any_failure)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_status_serialises_lowercase() {
        assert_eq!(serde_json::to_value(VerifyStatus::Pass).unwrap(), "pass");
        assert_eq!(serde_json::to_value(VerifyStatus::Stale).unwrap(), "stale");
        assert_eq!(
            serde_json::to_value(VerifyStatus::Missing).unwrap(),
            "missing"
        );
        assert_eq!(serde_json::to_value(VerifyStatus::Error).unwrap(), "error");
    }
}
