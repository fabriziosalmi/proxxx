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
    /// Absent on a node-level row (the node's guests could not be listed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vmid: Option<u32>,
    pub node: String,
    /// Absent when no backup was found or the state is unknown (#357):
    /// `0.0` read as "a backup from today".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_days: Option<f64>,
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
    /// The backups could not be checked: a backup storage or the node's
    /// guest list could not be read (#357). Not the same as `missing`.
    Unknown,
}

/// One node's backups, read once per backup-capable storage: the newest
/// `(ctime, size)` per vmid, and the storages that could not be read.
struct NodeBackups {
    newest: std::collections::HashMap<u32, (u64, u64)>,
    unreadable: Vec<String>,
}

async fn read_node_backups(
    client: &Arc<PxClient>,
    node: &str,
    storages: &[crate::api::types::StoragePool],
) -> NodeBackups {
    use crate::api::ProxmoxGateway;
    let mut out = NodeBackups {
        newest: std::collections::HashMap::new(),
        unreadable: Vec::new(),
    };
    // Only storages that can hold backups. Listing `content=backup` on the
    // others returns nothing, and an unrelated storage that is down must
    // not make every guest unknown.
    for s in storages
        .iter()
        .filter(|s| s.content.split(',').any(|c| c.trim() == "backup"))
    {
        match client
            .list_storage_content(node, &s.storage, Some("backup"))
            .await
        {
            Ok(content) => {
                for item in content {
                    if let Some(vmid) = item.vmid {
                        let e = out.newest.entry(vmid).or_insert((item.ctime, item.size));
                        if item.ctime > e.0 {
                            *e = (item.ctime, item.size);
                        }
                    }
                }
            }
            // #357: this used to be skipped, and a guest whose backups
            // live on an unreachable storage was reported "missing".
            Err(e) => out.unreadable.push(format!("{}: {e:#}", s.storage)),
        }
    }
    out
}

#[allow(clippy::too_many_lines)] // audit #272: wide, flat dispatch — see Cargo.toml
pub async fn execute_verify(client: &Arc<PxClient>, args: VerifyArgs) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    let nodes = client.get_nodes().await?;
    let mut results: Vec<VerifyResult> = Vec::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // For each guest, find its most-recent backup across the node's
    // backup-capable storages (`/nodes/{n}/storage/{s}/content?content=backup`).
    for n in &nodes {
        let unknown_node = |reason: String| VerifyResult {
            vmid: None,
            node: n.node.clone(),
            age_days: None,
            size_bytes: 0,
            status: VerifyStatus::Unknown,
            reason,
        };
        let guests = match client.get_guests(&n.node).await {
            Ok(g) => g,
            Err(e) => {
                results.push(unknown_node(format!("could not list guests: {e:#}")));
                continue;
            }
        };
        if guests.is_empty() {
            continue;
        }
        let backups = match client.get_storage_pools(&n.node).await {
            Ok(storages) => read_node_backups(client, &n.node, &storages).await,
            Err(e) => NodeBackups {
                newest: std::collections::HashMap::new(),
                unreadable: vec![format!("storage list: {e:#}")],
            },
        };

        for g in &guests {
            let result = match backups.newest.get(&g.vmid).copied() {
                None if !backups.unreadable.is_empty() => VerifyResult {
                    vmid: Some(g.vmid),
                    node: n.node.clone(),
                    age_days: None,
                    size_bytes: 0,
                    status: VerifyStatus::Unknown,
                    reason: format!(
                        "no backup in the readable storages; could not read {}",
                        backups.unreadable.join("; ")
                    ),
                },
                None => VerifyResult {
                    vmid: Some(g.vmid),
                    node: n.node.clone(),
                    age_days: None,
                    size_bytes: 0,
                    status: VerifyStatus::Missing,
                    reason: "no backup found for this guest".to_string(),
                },
                Some((ctime, size)) => {
                    #[allow(clippy::cast_precision_loss)]
                    let age_days = (now.saturating_sub(ctime) as f64) / 86400.0;
                    // A newer backup may sit on a storage that could not
                    // be read; say so instead of judging silently.
                    let caveat = if backups.unreadable.is_empty() {
                        String::new()
                    } else {
                        format!(" (could not read {})", backups.unreadable.join("; "))
                    };
                    let (status, reason) = if size == 0 {
                        (
                            VerifyStatus::Error,
                            "backup size 0 — likely corrupt manifest".to_string(),
                        )
                    } else if age_days > args.max_age_days as f64 {
                        (
                            VerifyStatus::Stale,
                            format!(
                                "newest backup is {age_days:.1} days old (threshold {})",
                                args.max_age_days
                            ),
                        )
                    } else {
                        (
                            VerifyStatus::Pass,
                            format!(
                                "{:.1} GiB, {age_days:.1}d old",
                                size as f64 / (1024.0 * 1024.0 * 1024.0)
                            ),
                        )
                    };
                    VerifyResult {
                        vmid: Some(g.vmid),
                        node: n.node.clone(),
                        age_days: Some(age_days),
                        size_bytes: size,
                        status,
                        reason: reason + &caveat,
                    }
                }
            };
            results.push(result);
        }
    }

    let any_failure = results.iter().any(|r| {
        matches!(
            r.status,
            VerifyStatus::Missing | VerifyStatus::Error | VerifyStatus::Unknown
        )
    });

    match args.output {
        VerifyOutput::Json => {
            // raw-output: JSON for machines; removing characters would change the data
            println!("{}", serde_json::to_string_pretty(&results)?);
        }
        VerifyOutput::Text => {
            if results.is_empty() {
                crate::outln!("(no guests / no backups found)");
            } else {
                crate::outln!(
                    "{vmid:<8}  {node:<14}  {status:<9}  {age:<8}  reason",
                    vmid = "vmid",
                    node = "node",
                    status = "status",
                    age = "age(d)",
                );
                let sep = "─".repeat(80);
                crate::outln!("{sep}");
                for r in &results {
                    let st = match r.status {
                        VerifyStatus::Pass => "✓ pass",
                        VerifyStatus::Stale => "! stale",
                        VerifyStatus::Missing => "✗ miss",
                        VerifyStatus::Error => "✗ ERROR",
                        VerifyStatus::Unknown => "? unknown",
                    };
                    let vmid = r.vmid.map_or_else(|| "-".to_string(), |v| v.to_string());
                    let age = r
                        .age_days
                        .map_or_else(|| "-".to_string(), |a| format!("{a:.1}"));
                    crate::outln!(
                        "{vmid:<8}  {node:<14}  {status:<9}  {age:<8}  {reason}",
                        node = r.node,
                        status = st,
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
        assert_eq!(
            serde_json::to_value(VerifyStatus::Unknown).unwrap(),
            "unknown"
        );
    }
}
