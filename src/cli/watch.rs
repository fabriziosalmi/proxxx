use anyhow::Result;
use serde_json::Value;

use crate::api::{ProxmoxGateway, PxClient};
use crate::config::ProfileConfig;

pub async fn execute_watch(
    client: &std::sync::Arc<PxClient>,
    config: &ProfileConfig,
    profile: Option<&str>,
    since: Option<String>,
    target: Option<String>,
    until: Option<String>,
    timeout: u64,
    notify: Option<String>,
) -> Result<(Value, i32)> {
    if let Some(target) = target {
        watch_until(client, config, target, until, timeout, notify).await
    } else if let Some(since) = since {
        watch_since(profile, &since)
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
            anyhow::bail!("Unsupported target format. Use vm-<id> or storage-<id>");
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
    let guest = client
        .get_all_guests()
        .await?
        .into_iter()
        .find(|g| g.vmid == vmid)
        .ok_or_else(|| anyhow::anyhow!("Target guest {target} not found"))?;
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
    let pool_id = target.trim_start_matches("storage-");
    let pool = client
        .get_all_storage_pools()
        .await?
        .into_iter()
        .find(|p| p.storage == pool_id)
        .ok_or_else(|| anyhow::anyhow!("Target storage {target} not found"))?;
    if key != "usage" {
        anyhow::bail!("Unsupported condition key for storage: {key}");
    }
    let usage_pct = (pool.used as f64 / pool.total as f64) * 100.0;
    let threshold: f64 = value_str.trim_end_matches('%').parse()?;
    Ok(match comparator {
        '<' => usage_pct < threshold,
        '>' => usage_pct > threshold,
        _ => (usage_pct - threshold).abs() < 0.01,
    })
}

fn watch_since(profile: Option<&str>, since: &str) -> Result<(Value, i32)> {
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
    let state_past = crate::app::cache::load_state_at(profile, past)?;
    let state_now = crate::app::cache::load_state(profile)?;

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
