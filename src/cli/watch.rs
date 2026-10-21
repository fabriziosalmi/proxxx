use anyhow::Result;
use serde_json::Value;

use crate::api::{ProxmoxGateway, PxClient};
use crate::config::ProfileConfig;

pub async fn execute_watch(
    client: &std::sync::Arc<PxClient>,
    config: &ProfileConfig,
    since: Option<String>,
    target: Option<String>,
    until: Option<String>,
    timeout: u64,
    notify: Option<String>,
) -> Result<(Value, i32)> {
    if let Some(target) = target {
        watch_until(client, config, target, until, timeout, notify).await
    } else if let Some(since) = since {
        watch_since(config.profile_label(), &since)
    } else {
        anyhow::bail!("Watch requires either --since or --target");
    }
}

async fn watch_until(
    client: &std::sync::Arc<PxClient>,
    config: &ProfileConfig,
    target: String,
    until: Option<String>,
    timeout: u64,
    notify: Option<String>,
) -> Result<(Value, i32)> {
    use tokio::time::{sleep, Duration, Instant};

    let until = until.unwrap_or_else(|| "status=running".to_string());
    let (key, raw_value) = if let Some((k, v)) = until.split_once('=') {
        (k.trim().to_lowercase(), v.trim().to_lowercase())
    } else {
        anyhow::bail!("Invalid condition format. Use key=value, key=<value or key=>value");
    };
    let (comparator, value_str) = if raw_value.starts_with('<') {
        ('<', raw_value.trim_start_matches('<'))
    } else if raw_value.starts_with('>') {
        ('>', raw_value.trim_start_matches('>'))
    } else {
        ('=', raw_value.as_str())
    };

    let mut met = false;
    tracing::info!("Watching {} until {}={}", target, key, raw_value);
    let deadline = Instant::now() + Duration::from_secs(timeout);

    while !met {
        if Instant::now() >= deadline {
            anyhow::bail!("watch timed out after {timeout}s — condition not met: {until}");
        }
        sleep(Duration::from_secs(2)).await;

        if target.starts_with("vm-") || target.chars().all(char::is_numeric) {
            met = check_guest_condition(client, &target, &key, value_str).await?;
        } else if target.starts_with("storage-") {
            met = check_storage_condition(client, &target, &key, comparator, value_str).await?;
        } else {
            anyhow::bail!(
                "Unsupported target format. Use vm-<id>, storage-<id> or storage-<id>@<node>"
            );
        }
    }

    let msg = format!("Watch condition met: {target} is now {until}");
    if notify.as_deref() == Some("telegram") {
        if let Some(tg) = config.telegram.as_ref() {
            let gateway = crate::hitl::telegram::TelegramGateway::from_config(tg).await?;
            gateway.send_message(&msg).await?;
        }
    }

    Ok((
        serde_json::json!({"status": "condition_met", "target": target, "condition": until}),
        0,
    ))
}

async fn check_guest_condition(
    client: &std::sync::Arc<PxClient>,
    target: &str,
    key: &str,
    value_str: &str,
) -> Result<bool> {
    let vmid_str = target.trim_start_matches("vm-");
    let vmid = vmid_str
        .parse::<u32>()
        .map_err(|_| anyhow::anyhow!("Invalid VMID format: {target}"))?;
    let guest = crate::cli::common::find_guest_full(client, vmid).await?;
    let current_val = match key {
        "status" => format!("{:?}", guest.status).to_lowercase(),
        _ => anyhow::bail!("Unsupported condition key: {key}"),
    };
    Ok(current_val == value_str)
}

async fn check_storage_condition(
    client: &std::sync::Arc<PxClient>,
    target: &str,
    key: &str,
    comparator: char,
    value_str: &str,
) -> Result<bool> {
    if key != "usage" {
        anyhow::bail!("Unsupported condition key for storage: {key}");
    }
    let pool = select_storage_row(client.get_all_storage_pools().await?, target)?;
    // #352: total 0 gave NaN, which never matched; say why instead.
    if pool.total == 0 {
        anyhow::bail!(
            "storage {} on {} reports a size of 0 (inactive or not mounted?)",
            pool.storage,
            pool.node
        );
    }
    let usage_pct = (pool.used as f64 / pool.total as f64) * 100.0;
    let threshold: f64 = value_str.trim_end_matches('%').parse()?;
    Ok(match comparator {
        '<' => usage_pct < threshold,
        '>' => usage_pct > threshold,
        _ => (usage_pct - threshold).abs() < 0.01,
    })
}

/// Pick the row a `storage-<id>[@<node>]` target means (#352). A storage
/// on several nodes has one row per node; the first one found used to be
/// taken, from an arbitrary node. With `@<node>` that node's row is used.
/// Without it, one row, or a shared storage (one volume seen from every
/// node), is unambiguous; a node-local storage on several nodes is an
/// error that names the nodes.
fn select_storage_row(
    pools: Vec<crate::api::types::StoragePool>,
    target: &str,
) -> Result<crate::api::types::StoragePool> {
    let spec = target.trim_start_matches("storage-");
    let (id, node) = match spec.split_once('@') {
        Some((id, node)) => (id, Some(node)),
        None => (spec, None),
    };
    let mut rows: Vec<_> = pools
        .into_iter()
        .filter(|p| p.storage == id && node.is_none_or(|n| p.node == n))
        .collect();
    let not_found =
        || crate::api::ApiError::NotFound(format!("Target storage {target} not found")).into();
    match rows.len() {
        0 => Err(not_found()),
        1 => Ok(rows.remove(0)),
        _ if rows.iter().all(|p| p.shared) => Ok(rows.remove(0)),
        _ => {
            let nodes: Vec<String> = rows.iter().map(|p| p.node.clone()).collect();
            anyhow::bail!(
                "storage {id} is node-local and exists on {}; pick one with storage-{id}@<node>",
                nodes.join(", ")
            )
        }
    }
}

fn watch_since(profile_label: &str, since: &str) -> Result<(Value, i32)> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let seconds = if since.ends_with('h') {
        since.trim_end_matches('h').parse::<u64>().unwrap_or(1) * 3600
    } else if since.ends_with('m') {
        since.trim_end_matches('m').parse::<u64>().unwrap_or(30) * 60
    } else {
        since.parse::<u64>().unwrap_or(3600)
    };

    let past = now.saturating_sub(seconds);
    let state_past = crate::app::cache::load_state_at(profile_label, past)?;
    let state_now = crate::app::cache::load_state(profile_label)?;

    let mut diff = Vec::new();
    let past_map: std::collections::HashMap<_, _> =
        state_past.guests.into_iter().map(|g| (g.vmid, g)).collect();
    let now_map: std::collections::HashMap<_, _> =
        state_now.guests.into_iter().map(|g| (g.vmid, g)).collect();

    for (vmid, guest_now) in &now_map {
        if let Some(guest_past) = past_map.get(vmid) {
            if guest_past.status != guest_now.status {
                diff.push(serde_json::json!({
                    "vmid": vmid,
                    "type": "status_change",
                    "from": format!("{:?}", guest_past.status),
                    "to": format!("{:?}", guest_now.status)
                }));
            }
        } else {
            diff.push(serde_json::json!({
                "vmid": vmid,
                "type": "created",
                "status": format!("{:?}", guest_now.status)
            }));
        }
    }

    for vmid in past_map.keys() {
        if !now_map.contains_key(vmid) {
            diff.push(serde_json::json!({
                "vmid": vmid,
                "type": "deleted"
            }));
        }
    }

    Ok((
        serde_json::json!({
            "past_timestamp": state_past.timestamp,
            "now_timestamp": state_now.timestamp,
            "diff": diff
        }),
        0,
    ))
}

#[cfg(test)]
mod storage_target_tests {
    use super::select_storage_row;
    use crate::api::types::StoragePool;

    fn row(storage: &str, node: &str, used: u64, shared: bool) -> StoragePool {
        StoragePool {
            storage: storage.into(),
            node: node.into(),
            used,
            total: 100,
            shared,
            ..StoragePool::default()
        }
    }

    /// #352: a node-local storage on several nodes is ambiguous; the first
    /// row found used to be taken, from an arbitrary node.
    #[test]
    fn a_node_local_storage_on_several_nodes_needs_a_node() {
        let pools = vec![
            row("local-lvm", "pve1", 26, false),
            row("local-lvm", "pve2", 0, false),
        ];
        let err = select_storage_row(pools.clone(), "storage-local-lvm").unwrap_err();
        assert!(
            format!("{err}").contains("storage-local-lvm@<node>"),
            "{err}"
        );
        let r = select_storage_row(pools, "storage-local-lvm@pve2").unwrap();
        assert_eq!((r.node.as_str(), r.used), ("pve2", 0));
    }

    #[test]
    fn a_shared_storage_or_a_single_row_needs_no_node() {
        let shared = vec![row("nfs", "pve1", 25, true), row("nfs", "pve2", 25, true)];
        assert_eq!(select_storage_row(shared, "storage-nfs").unwrap().used, 25);
        let single = vec![row("local", "pve1", 10, false)];
        assert_eq!(
            select_storage_row(single, "storage-local").unwrap().node,
            "pve1"
        );
        assert!(select_storage_row(vec![], "storage-x").is_err());
        let one = vec![row("local", "pve1", 10, false)];
        assert!(select_storage_row(one, "storage-local@pve9").is_err());
    }
}
