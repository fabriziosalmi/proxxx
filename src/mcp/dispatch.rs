// MCP dispatch — transport-agnostic tool execution.
//
// Both the stdio server and the HTTP server share this module.
// Neither transport knows how tool calls are routed; dispatch knows
// nothing about framing or wire format.

use anyhow::Result;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::api::PxClient;
use crate::config::ProfileConfig;
use crate::mcp::tools::{ToolAction, TOOLS};

/// Execute a single MCP tool call and return the MCP content envelope.
///
/// Returns `Ok(json!({"content": [{"type":"text","text":...}]}))` on success.
/// The caller wraps this in a JSON-RPC result or HTTP response body.
pub async fn handle_tool_call(
    client: &PxClient,
    config: &ProfileConfig,
    name: &str,
    args: &Value,
) -> Result<Value> {
    let tool_def = TOOLS
        .iter()
        .find(|t| t.name == name)
        .ok_or_else(|| anyhow::anyhow!("Tool not found: {name}"))?;

    for p in tool_def.params {
        if p.required && args.get(p.name).is_none() {
            anyhow::bail!("Missing required parameter: {}", p.name);
        }
    }

    use crate::api::ProxmoxGateway;
    let mut is_hitl_pending = false;
    let mut hitl_msg = String::new();

    if tool_def.destructive {
        if let Some(guest_id) = args.get("guest_id").and_then(serde_json::Value::as_u64) {
            let vmid = guest_id as u32;
            let action_str = name;

            let mut tags = Vec::new();
            if let Ok(nodes) = client.get_nodes().await {
                for n in nodes {
                    if let Ok(guests) = client.get_guests(&n.node).await {
                        if let Some(g) = guests.iter().find(|g| g.vmid == vmid) {
                            tags = g
                                .tag_list()
                                .into_iter()
                                .map(std::string::ToString::to_string)
                                .collect();
                            break;
                        }
                    }
                }
            }

            let policies = config.policies.as_deref().unwrap_or_default();
            let tags_ref: Vec<&str> = tags.iter().map(std::string::String::as_str).collect();

            if let Some(policy) = crate::hitl::policy::check_policies(
                policies,
                action_str,
                &vmid.to_string(),
                &tags_ref,
            ) {
                is_hitl_pending = true;
                let txn_id = format!("{action_str}:{vmid}");

                if let Some(ref tg) = config.telegram {
                    match crate::hitl::telegram::TelegramGateway::from_config(tg).await {
                        Ok(tg_gateway) => {
                            let reason = format!("MCP requested action: {name}");
                            let _ = tg_gateway
                                .request_approval(action_str, &vmid.to_string(), &reason, &txn_id)
                                .await;
                        }
                        Err(e) => {
                            tracing::warn!("Telegram gateway init failed for MCP HITL: {e:#}");
                        }
                    }
                }

                hitl_msg = format!(
                    "Action intercepted by HITL policy. Requires {} approval(s) via {}. Transaction: {}",
                    policy.require, policy.channel, txn_id
                );
            }
        }
    }

    if is_hitl_pending {
        return Ok(json!({
            "content": [{"type": "text", "text": hitl_msg}]
        }));
    }

    let content = match tool_def.action {
        ToolAction::ListNodes => {
            let nodes = client.get_nodes().await?;
            serde_json::to_string_pretty(&nodes)?
        }
        ToolAction::ListGuests => {
            let mut all_guests = Vec::new();
            if let Some(node) = args.get("node").and_then(|v| v.as_str()) {
                all_guests = client.get_guests(node).await?;
            } else {
                let nodes = client.get_nodes().await?;
                for n in nodes {
                    if let Ok(guests) = client.get_guests(&n.node).await {
                        all_guests.extend(guests);
                    }
                }
            }
            serde_json::to_string_pretty(&all_guests)?
        }
        ToolAction::GetGuestStatus => {
            let vmid = args
                .get("guest_id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let (node, _gt) = find_node_and_type(client, vmid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {vmid} not found"))?;
            let status = client.get_guest_status(&node, vmid).await?;
            serde_json::to_string_pretty(&status)?
        }
        ToolAction::StartGuest => {
            let vmid = args
                .get("guest_id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let (node, gt) = find_node_and_type(client, vmid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {vmid} not found"))?;
            let upid = client.start_guest(&node, vmid, gt).await?;
            format!("Started guest {vmid}. UPID: {upid}")
        }
        ToolAction::StopGuest => {
            let vmid = args
                .get("guest_id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let force = args
                .get("force")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let (node, gt) = find_node_and_type(client, vmid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {vmid} not found"))?;
            let upid = if force {
                client.stop_guest(&node, vmid, gt, true).await?
            } else {
                client.shutdown_guest(&node, vmid, gt, 60).await?
            };
            format!("Stopped guest {vmid}. UPID: {upid}")
        }
        ToolAction::RestartGuest => {
            let vmid = args
                .get("guest_id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let (node, gt) = find_node_and_type(client, vmid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {vmid} not found"))?;
            let upid = client.restart_guest(&node, vmid, gt).await?;
            format!("Restarted guest {vmid}. UPID: {upid}")
        }
        ToolAction::DeleteGuest => {
            let vmid = args
                .get("guest_id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let (node, gt) = find_node_and_type(client, vmid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {vmid} not found"))?;
            let upid = client.delete_guest(&node, vmid, gt).await?;
            format!("Deleted guest {vmid}. UPID: {upid}")
        }
        ToolAction::CreateSnapshot => {
            let vmid = args
                .get("guest_id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let snap_name = args
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("mcp-snap");
            let (node, gt) = find_node_and_type(client, vmid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {vmid} not found"))?;
            let upid = client.create_snapshot(&node, vmid, gt, snap_name).await?;
            format!("Snapshot '{snap_name}' created for guest {vmid}. UPID: {upid}")
        }
        ToolAction::DeleteSnapshot => {
            let vmid = args
                .get("guest_id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let snap_name = args.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let (node, gt) = find_node_and_type(client, vmid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {vmid} not found"))?;
            client.delete_snapshot(&node, vmid, gt, snap_name).await?;
            format!("Snapshot '{snap_name}' deleted for guest {vmid}")
        }
        ToolAction::ListSnapshots => {
            let vmid = args
                .get("guest_id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let (node, gt) = find_node_and_type(client, vmid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {vmid} not found"))?;
            let snaps = client.list_snapshots(&node, vmid, gt).await?;
            serde_json::to_string_pretty(&snaps)?
        }
        ToolAction::GetNodeResources => {
            let node_name = args.get("node").and_then(|v| v.as_str()).unwrap_or("");
            let nodes = client.get_nodes().await?;
            let node = nodes
                .into_iter()
                .find(|n| n.node == node_name)
                .ok_or_else(|| anyhow::anyhow!("Node '{node_name}' not found"))?;
            serde_json::to_string_pretty(&node)?
        }
        ToolAction::GetStoragePools => {
            let node_name = args.get("node").and_then(|v| v.as_str()).unwrap_or("");
            let pools = client.get_storage_pools(node_name).await?;
            serde_json::to_string_pretty(&pools)?
        }
        ToolAction::GetTaskLog => {
            let upid = args.get("upid").and_then(|v| v.as_str()).unwrap_or("");
            let node = args.get("node").and_then(|v| v.as_str()).unwrap_or("");
            let log = client.get_task_log(node, upid, 0, 500).await?;
            serde_json::to_string_pretty(&log)?
        }
        ToolAction::SuspendGuest => {
            let vmid = args
                .get("guest_id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let (node, gt) = find_node_and_type(client, vmid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {vmid} not found"))?;
            let upid = client.suspend_guest(&node, vmid, gt).await?;
            format!("Suspended guest {vmid}. UPID: {upid}")
        }
        ToolAction::ResumeGuest => {
            let vmid = args
                .get("guest_id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let (node, gt) = find_node_and_type(client, vmid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {vmid} not found"))?;
            let upid = client.resume_guest(&node, vmid, gt).await?;
            format!("Resumed guest {vmid}. UPID: {upid}")
        }
        ToolAction::CloneGuest => {
            let vmid = args
                .get("guest_id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let (node, gt) = find_node_and_type(client, vmid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {vmid} not found"))?;
            let newid_arg = args
                .get("newid")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let newid = if newid_arg == 0 {
                client.next_free_vmid().await?
            } else {
                newid_arg
            };
            let name = args.get("name").and_then(|v| v.as_str());
            let full = args
                .get("full")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            let upid = client
                .clone_guest(&node, vmid, gt, newid, name, None, None, full, None, None)
                .await?;
            format!("Cloned guest {vmid} → {newid}. UPID: {upid}")
        }
        ToolAction::MigrateGuest => {
            let vmid = args
                .get("guest_id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let target_node = args
                .get("target_node")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let online = args
                .get("online")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            let (node, gt) = find_node_and_type(client, vmid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {vmid} not found"))?;
            let upid = client
                .migrate_guest(&node, vmid, gt, target_node, online, false, false)
                .await?;
            format!("Migrating guest {vmid} → {target_node}. UPID: {upid}")
        }
        ToolAction::GetClusterStatus => {
            let status = client.cluster_status().await?;
            serde_json::to_string_pretty(&status)?
        }
        ToolAction::ListTasks => {
            let tasks = client.get_cluster_tasks().await?;
            let node_filter = args.get("node").and_then(|v| v.as_str());
            let filtered: Vec<_> = if let Some(n) = node_filter {
                tasks.into_iter().filter(|t| t.node == n).collect()
            } else {
                tasks
            };
            serde_json::to_string_pretty(&filtered)?
        }
        ToolAction::GetNodeStatus => {
            let node_name = args.get("node").and_then(|v| v.as_str()).unwrap_or("");
            let status = client.node_status_detail(node_name).await?;
            serde_json::to_string_pretty(&status)?
        }
        ToolAction::ListBackupJobs => {
            let jobs = client.list_backup_jobs().await?;
            serde_json::to_string_pretty(&jobs)?
        }
        ToolAction::GetReplicationStatus => {
            let node_name = args.get("node").and_then(|v| v.as_str()).unwrap_or("");
            let status = client.list_replication_status(node_name).await?;
            serde_json::to_string_pretty(&status)?
        }
    };

    Ok(json!({
        "content": [{"type": "text", "text": content}]
    }))
}

pub(crate) async fn find_node_and_type(
    client: &PxClient,
    vmid: u32,
) -> Result<Option<(String, crate::api::types::GuestType)>> {
    use crate::api::ProxmoxGateway;
    let nodes = client.get_nodes().await?;
    for n in nodes {
        if let Ok(guests) = client.get_guests(&n.node).await {
            if let Some(g) = guests.iter().find(|g| g.vmid == vmid) {
                return Ok(Some((n.node.clone(), g.guest_type)));
            }
        }
    }
    Ok(None)
}

/// Shared JSON-RPC response builders — used by both transports.
#[must_use]
#[allow(clippy::needless_pass_by_value)]
pub fn ok_result(id: Value, result: &Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

#[must_use]
pub fn err_result(id: &Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Dispatch a parsed JSON-RPC request against the MCP protocol.
/// Returns the complete JSON-RPC response value.
pub async fn dispatch_rpc(
    client: Arc<PxClient>,
    config: Arc<ProfileConfig>,
    method: &str,
    id: Value,
    params: Option<Value>,
) -> Value {
    use crate::mcp::tools::DEFAULT_TIMEOUT_SECS;
    use std::time::Duration;

    match method {
        "initialize" => ok_result(
            id,
            &json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {"listChanged": false}},
                "serverInfo": {"name": "proxxx-mcp", "version": env!("CARGO_PKG_VERSION")}
            }),
        ),
        // JSON-RPC 2.0 §4: notifications have no "id" field and MUST NOT
        // receive a response. Returning Value::Null signals callers to skip
        // the write step. "ping" is a request (has id) → respond normally.
        "notifications/initialized" => Value::Null,
        "ping" => ok_result(id, &json!({})),
        "tools/list" => {
            let tools = crate::mcp::tools::tools_list_schema();
            ok_result(id, &json!({"tools": tools}))
        }
        "tools/call" => {
            let params = match params {
                Some(p) => p,
                None => return err_result(&id, -32602, "Invalid params"),
            };
            let name = match params.get("name").and_then(|v| v.as_str()) {
                Some(n) => n.to_owned(),
                None => return err_result(&id, -32602, "Missing tool name"),
            };
            let args = params.get("arguments").cloned().unwrap_or(json!({}));

            let budget_secs = TOOLS
                .iter()
                .find(|t| t.name == name)
                .map_or(DEFAULT_TIMEOUT_SECS, |t| t.timeout_secs);

            match tokio::time::timeout(
                Duration::from_secs(budget_secs),
                handle_tool_call(&client, &config, &name, &args),
            )
            .await
            {
                Ok(Ok(res)) => ok_result(id, &res),
                Ok(Err(e)) => err_result(&id, -32603, &e.to_string()),
                Err(_) => err_result(
                    &id,
                    -32001,
                    &format!("tool '{name}' exceeded {budget_secs}s execution budget"),
                ),
            }
        }
        _ => err_result(&id, -32601, "Method not found"),
    }
}
