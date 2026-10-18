// MCP dispatch — transport-agnostic tool execution.
//
// Both the stdio server and the HTTP server share this module.
// Neither transport knows how tool calls are routed; dispatch knows
// nothing about framing or wire format.

use anyhow::Result;
use serde_json::{json, Value};
use std::sync::Arc;

use crate::api::PxClient;
use crate::config::{ConfigHandle, ProfileConfig};
use crate::mcp::tools::{ToolAction, TOOLS};

/// Execute a single MCP tool call and return the MCP content envelope.
///
/// Returns `Ok(json!({"content": [{"type":"text","text":...}]}))` on success.
/// The caller wraps this in a JSON-RPC result or HTTP response body.
///
/// # Errors
///
/// Propagates parameter validation errors or underlying Proxmox gateway errors.
pub async fn handle_tool_call(
    client: &Arc<PxClient>,
    config: &ProfileConfig,
    name: &str,
    args: &Value,
) -> Result<Value> {
    handle_tool_call_with_store(client.as_ref(), config, name, args, None).await
}

/// Execute a single MCP tool call using an optional caller-supplied
/// [`crate::hitl::pending::PendingStore`] (`#340`).
///
/// Production callers use [`handle_tool_call`], which opens the default on-disk
/// store (`<config_dir>/hitl_pending.db`) whenever a HITL policy matches. Tests
/// pass `Some(&store)` to keep pending-request persistence hermetic in a temp
/// directory.
///
/// # Errors
///
/// Propagates parameter validation errors, store persistence errors, or
/// underlying Proxmox gateway errors.
#[allow(clippy::too_many_lines)] // audit #272: wide, flat dispatch — see Cargo.toml
pub async fn handle_tool_call_with_store(
    client: &(dyn crate::api::ProxmoxGateway + Send + Sync),
    config: &ProfileConfig,
    name: &str,
    args: &Value,
    pending_store: Option<&crate::hitl::pending::PendingStore>,
) -> Result<Value> {
    let tool_def = TOOLS
        .iter()
        .find(|t| t.name == name)
        .ok_or_else(|| anyhow::anyhow!("Tool not found: {name}"))?;

    for p in tool_def.params {
        if p.required && args.get(p.name).is_none() {
            anyhow::bail!("Missing required parameter: {}", p.name);
        }
        if let Some(val) = args.get(p.name) {
            use crate::mcp::tools::ParamType;
            match p.param_type {
                ParamType::Int => {
                    if !val.is_u64() && !val.is_i64() {
                        anyhow::bail!("Parameter '{}': expected integer, got {}", p.name, val);
                    }
                }
                ParamType::Bool => {
                    if !val.is_boolean() {
                        anyhow::bail!("Parameter '{}': expected boolean, got {}", p.name, val);
                    }
                }
                ParamType::Str => {
                    let Some(text) = val.as_str() else {
                        anyhow::bail!("Parameter '{}': expected string, got {}", p.name, val);
                    };
                    // #254 — enforce the registry's declared shape. Until
                    // v0.13.4 a string parameter was only checked for
                    // being a string, so values that become PVE path
                    // segments arrived unconstrained.
                    if let Err(why) = p.shape.check(text) {
                        anyhow::bail!("Parameter '{}': {}", p.name, why);
                    }
                }
            }
        }
    }

    let mut is_hitl_pending = false;
    let mut hitl_msg = String::new();

    // SECURITY — fail-closed gate for destructive MCP tools.
    //
    // The MCP transport is reachable by any caller who can talk to the
    // server (over HTTP, potentially unauthenticated; see the bind
    // preflight in `http_server::run_http_server`). A destructive tool
    // (stop/restart/delete/migrate/clone/create) must therefore NEVER
    // execute inline off the MCP path. The only sanctioned route is:
    //
    //   a matching `[[policies]]` entry → HITL approval requested here,
    //   op executed later by the HITL daemon on human approval.
    //
    // If NO policy governs the call, we REFUSE — we do not fall through
    // to execution. This closes the prior fail-open where an operator
    // who never wrote a policy (or left `mcp_token` unset on a
    // network-exposed server) let an unauthenticated caller delete a
    // guest. There is intentionally no "ungated inline" escape hatch:
    // to permit a destructive MCP op, declare a policy for it.
    if tool_def.destructive {
        let policies = config.policies.as_deref().unwrap_or_default();
        let guest_id_arg = args
            .get("guest_id")
            .and_then(serde_json::Value::as_u64)
            .map(|g| g as u32);
        let create_vmid_arg = args
            .get("vmid")
            .and_then(serde_json::Value::as_u64)
            .map(|g| g as u32);
        let vmid = guest_id_arg.or(create_vmid_arg);

        // Tag-targeted policies need the guest's live tags; only fetch
        // them when there are policies to evaluate AND the call carries a
        // guest_id. `create_guest` / `clone_*` have no pre-existing
        // guest_id — they can only ever match a wildcard/action policy.
        let mut fetched_guest: Option<crate::api::types::Guest> = None;
        let matched = if policies.is_empty() {
            None
        } else {
            // Only pay the `find_guest` round-trip when a policy actually
            // targets tags — action/vmid/wildcard policies decide offline.
            let needs_tags = policies.iter().any(|p| p.target.starts_with("tag:"));
            let tags: Vec<String> = if needs_tags {
                if let Some(v) = guest_id_arg {
                    fetched_guest = client.find_guest(v).await?;
                    fetched_guest
                        .as_ref()
                        .map(|g| {
                            g.tag_list()
                                .into_iter()
                                .map(std::string::ToString::to_string)
                                .collect()
                        })
                        .unwrap_or_default()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };
            let target = vmid.map(|v| v.to_string()).unwrap_or_default();
            let tags_ref: Vec<&str> = tags.iter().map(std::string::String::as_str).collect();
            crate::hitl::policy::check_policies(policies, name, &target, &tags_ref)
        };

        if let Some(policy) = matched {
            is_hitl_pending = true;
            let target = vmid.map(|v| v.to_string()).unwrap_or_default();

            let txn_id = if config.telegram.is_some() || pending_store.is_some() {
                let (resolved_node, resolved_gt) = if let Some(v) = guest_id_arg {
                    let g = match fetched_guest {
                        Some(g) => g,
                        None => client
                            .find_guest(v)
                            .await?
                            .ok_or_else(|| anyhow::anyhow!("Guest {v} not found"))?,
                    };
                    if g.node.is_empty() {
                        anyhow::bail!(
                            "cannot record HITL request for guest {v}: guest has no resolved node"
                        );
                    }
                    (g.node, g.guest_type)
                } else {
                    let node = args
                        .get("node")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .ok_or_else(|| {
                            anyhow::anyhow!("Missing required 'node' for HITL request '{name}'")
                        })?;
                    let gt = match args.get("type").and_then(Value::as_str) {
                        Some("qemu") => crate::api::types::GuestType::Qemu,
                        Some("lxc") => crate::api::types::GuestType::Lxc,
                        other => {
                            anyhow::bail!(
                                "Invalid or missing guest type {other:?} for HITL request '{name}'"
                            );
                        }
                    };
                    (node, gt)
                };
                let new_req =
                    crate::hitl::pending::NewPendingRequest::new(name, vmid, policy.require)
                        .with_node(resolved_node)
                        .with_guest_type(resolved_gt)
                        .with_params(args.clone());
                let row = match pending_store {
                    Some(store) => store.insert(&new_req)?,
                    None => crate::hitl::pending::PendingStore::open_default()
                        .and_then(|store| store.insert(&new_req))?,
                };
                let id = row.id;
                if let Some(ref tg) = config.telegram {
                    match crate::hitl::telegram::TelegramGateway::from_config(tg).await {
                        Ok(tg_gateway) => {
                            let reason = format!("MCP requested action: {name}");
                            let _ = tg_gateway
                                .request_approval(name, &target, &reason, &id, policy.require)
                                .await;
                        }
                        Err(e) => {
                            tracing::warn!("Telegram gateway init failed for MCP HITL: {e:#}");
                        }
                    }
                }
                id
            } else {
                crate::hitl::pending::generate_request_id()?
            };

            hitl_msg = format!(
                "Action intercepted by HITL policy. Requires {} approval(s) via {}. Transaction: {}",
                policy.require, policy.channel, txn_id
            );
        } else {
            // FAIL-CLOSED: destructive tool with no governing policy.
            tracing::warn!(
                "Refused ungated destructive MCP call '{name}' (no matching HITL policy)"
            );
            return Ok(json!({
                "content": [{"type": "text", "text": format!(
                    "Refused: '{name}' is a destructive operation and no HITL policy governs it. \
                     proxxx does not execute ungated destructive MCP calls. Declare a matching \
                     [[policies]] entry to route this operation through approval."
                )}],
                "isError": true
            }));
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
            let all_guests = if let Some(node) = args.get("node").and_then(|v| v.as_str()) {
                client.get_guests(node).await?
            } else {
                client.get_all_guests().await?
            };
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
            let params: crate::hitl::daemon::McpStopGuestParams =
                serde_json::from_value(args.clone())?;
            let (node, gt) = find_node_and_type(client, params.guest_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {} not found", params.guest_id))?;
            let upid = exec_stop_guest(client, &node, gt, &params).await?;
            format!("Stopped guest {}. UPID: {upid}", params.guest_id)
        }
        ToolAction::RestartGuest => {
            let params: crate::hitl::daemon::McpGuestIdParams =
                serde_json::from_value(args.clone())?;
            let (node, gt) = find_node_and_type(client, params.guest_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {} not found", params.guest_id))?;
            let upid = exec_restart_guest(client, &node, gt, &params).await?;
            format!("Restarted guest {}. UPID: {upid}", params.guest_id)
        }
        ToolAction::DeleteGuest => {
            let params: crate::hitl::daemon::McpGuestIdParams =
                serde_json::from_value(args.clone())?;
            let (node, gt) = find_node_and_type(client, params.guest_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {} not found", params.guest_id))?;
            let upid = exec_delete_guest(client, &node, gt, &params).await?;
            format!("Deleted guest {}. UPID: {upid}", params.guest_id)
        }
        ToolAction::CreateSnapshot => {
            let params: crate::hitl::daemon::McpSnapshotParams =
                serde_json::from_value(args.clone())?;
            let (node, gt) = find_node_and_type(client, params.guest_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {} not found", params.guest_id))?;
            let upid = exec_create_snapshot(client, &node, gt, &params).await?;
            format!(
                "Snapshot '{}' created for guest {}. UPID: {upid}",
                params.name, params.guest_id
            )
        }
        ToolAction::DeleteSnapshot => {
            let params: crate::hitl::daemon::McpSnapshotParams =
                serde_json::from_value(args.clone())?;
            let (node, gt) = find_node_and_type(client, params.guest_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {} not found", params.guest_id))?;
            let _upid = exec_delete_snapshot(client, &node, gt, &params).await?;
            format!(
                "Snapshot '{}' deleted for guest {}",
                params.name, params.guest_id
            )
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
            let params: crate::hitl::daemon::McpGuestIdParams =
                serde_json::from_value(args.clone())?;
            let (node, gt) = find_node_and_type(client, params.guest_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {} not found", params.guest_id))?;
            let upid = exec_suspend_guest(client, &node, gt, &params).await?;
            format!("Suspended guest {}. UPID: {upid}", params.guest_id)
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
            let params: crate::hitl::daemon::McpCloneGuestParams =
                serde_json::from_value(args.clone())?;
            let (node, gt) = find_node_and_type(client, params.guest_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {} not found", params.guest_id))?;
            let (newid, upid) = exec_clone_guest(client, &node, gt, &params).await?;
            format!("Cloned guest {} → {newid}. UPID: {upid}", params.guest_id)
        }
        ToolAction::MigrateGuest => {
            let params: crate::hitl::daemon::McpMigrateGuestParams =
                serde_json::from_value(args.clone())?;
            let (node, gt) = find_node_and_type(client, params.guest_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {} not found", params.guest_id))?;
            let upid = exec_migrate_guest(client, &node, gt, &params).await?;
            format!(
                "Migrating guest {} → {}. UPID: {upid}",
                params.guest_id, params.target_node
            )
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
        ToolAction::CreateGuest => {
            let params: crate::hitl::daemon::McpCreateGuestParams =
                serde_json::from_value(args.clone())?;
            let (vmid, upid) = exec_create_guest(client, &params).await?;
            return Ok(json!({
                "content": [{
                    "type": "text",
                    "text": format!(
                        "Guest {vmid} ({}) creation started on {}. UPID: {upid}",
                        params.guest_type, params.node
                    )
                }]
            }));
        }
        ToolAction::ListClusterEvents => {
            let limit = args
                .get("limit")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(50)
                .min(200) as usize;
            let running_only = args
                .get("running_only")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            let mut tasks = client.get_cluster_tasks().await?;
            if running_only {
                tasks.retain(|t| t.endtime.is_none());
            }
            tasks.truncate(limit);

            let enriched: Vec<serde_json::Value> = tasks
                .iter()
                .map(|t| {
                    let elapsed_secs = if let Some(end) = t.endtime {
                        end.saturating_sub(t.starttime)
                    } else if t.starttime > 0 {
                        now.saturating_sub(t.starttime)
                    } else {
                        0
                    };
                    serde_json::json!({
                        "upid":         t.upid,
                        "node":         t.node,
                        "type":         t.task_type,
                        "id":           t.id,
                        "user":         t.user,
                        "status":       t.status,
                        "starttime":    t.starttime,
                        "endtime":      t.endtime,
                        "elapsed_secs": elapsed_secs,
                        "running":      t.endtime.is_none(),
                    })
                })
                .collect();

            serde_json::to_string_pretty(&serde_json::json!({
                "total": enriched.len(),
                "running_only": running_only,
                "events": enriched,
            }))?
        }
        ToolAction::CloneWithCloudinit => {
            let params: crate::hitl::daemon::McpCloneWithCloudinitParams =
                serde_json::from_value(args.clone())?;
            let (node, gt) = find_node_and_type(client, params.guest_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {} not found", params.guest_id))?;
            let (newid, upid, ci) = exec_clone_with_cloudinit(client, &node, gt, &params).await?;
            format!(
                "Cloned guest {} → {newid} (UPID: {upid}); cloud-init applied: {ci}",
                params.guest_id
            )
        }
    };

    Ok(json!({
        "content": [{"type": "text", "text": content}]
    }))
}

/// Shared `stop_guest` executor used by both MCP dispatch and the HITL daemon (`#340`).
///
/// # Errors
///
/// Propagates any error from [`crate::api::ProxmoxGateway::stop_guest`] or
/// [`crate::api::ProxmoxGateway::shutdown_guest`].
pub async fn exec_stop_guest(
    client: &(dyn crate::api::ProxmoxGateway + Send + Sync),
    node: &str,
    gt: crate::api::types::GuestType,
    params: &crate::hitl::daemon::McpStopGuestParams,
) -> Result<String> {
    if params.force {
        client.stop_guest(node, params.guest_id, gt, true).await
    } else {
        client.shutdown_guest(node, params.guest_id, gt, 60).await
    }
}

/// Shared `restart_guest` executor used by both MCP dispatch and the HITL daemon (`#340`).
///
/// # Errors
///
/// Propagates any error from [`crate::api::ProxmoxGateway::restart_guest`].
pub async fn exec_restart_guest(
    client: &(dyn crate::api::ProxmoxGateway + Send + Sync),
    node: &str,
    gt: crate::api::types::GuestType,
    params: &crate::hitl::daemon::McpGuestIdParams,
) -> Result<String> {
    client.restart_guest(node, params.guest_id, gt).await
}

/// Shared `delete_guest` executor used by both MCP dispatch and the HITL daemon (`#340`).
///
/// # Errors
///
/// Propagates any error from [`crate::api::ProxmoxGateway::delete_guest`].
pub async fn exec_delete_guest(
    client: &(dyn crate::api::ProxmoxGateway + Send + Sync),
    node: &str,
    gt: crate::api::types::GuestType,
    params: &crate::hitl::daemon::McpGuestIdParams,
) -> Result<String> {
    client.delete_guest(node, params.guest_id, gt).await
}

/// Shared `create_snapshot` executor used by both MCP dispatch and the HITL daemon (`#340`).
///
/// # Errors
///
/// Propagates any error from [`crate::api::ProxmoxGateway::create_snapshot`].
pub async fn exec_create_snapshot(
    client: &(dyn crate::api::ProxmoxGateway + Send + Sync),
    node: &str,
    gt: crate::api::types::GuestType,
    params: &crate::hitl::daemon::McpSnapshotParams,
) -> Result<String> {
    client
        .create_snapshot(node, params.guest_id, gt, &params.name)
        .await
}

/// Shared `delete_snapshot` executor used by both MCP dispatch and the HITL daemon (`#340`).
///
/// # Errors
///
/// Propagates any error from [`crate::api::ProxmoxGateway::delete_snapshot`].
pub async fn exec_delete_snapshot(
    client: &(dyn crate::api::ProxmoxGateway + Send + Sync),
    node: &str,
    gt: crate::api::types::GuestType,
    params: &crate::hitl::daemon::McpSnapshotParams,
) -> Result<String> {
    client
        .delete_snapshot(node, params.guest_id, gt, &params.name)
        .await
}

/// Shared `suspend_guest` executor used by both MCP dispatch and the HITL daemon (`#340`).
///
/// # Errors
///
/// Propagates any error from [`crate::api::ProxmoxGateway::suspend_guest`].
pub async fn exec_suspend_guest(
    client: &(dyn crate::api::ProxmoxGateway + Send + Sync),
    node: &str,
    gt: crate::api::types::GuestType,
    params: &crate::hitl::daemon::McpGuestIdParams,
) -> Result<String> {
    client.suspend_guest(node, params.guest_id, gt).await
}

/// Shared `clone_guest` executor used by both MCP dispatch and the HITL daemon (`#340`).
///
/// # Errors
///
/// Propagates any error from [`crate::api::ProxmoxGateway::next_free_vmid`] or
/// [`crate::api::ProxmoxGateway::clone_guest`].
pub async fn exec_clone_guest(
    client: &(dyn crate::api::ProxmoxGateway + Send + Sync),
    node: &str,
    gt: crate::api::types::GuestType,
    params: &crate::hitl::daemon::McpCloneGuestParams,
) -> Result<(u32, String)> {
    let newid = if params.newid == 0 {
        client.next_free_vmid().await?
    } else {
        params.newid
    };
    let upid = client
        .clone_guest(
            node,
            params.guest_id,
            gt,
            newid,
            params.name.as_deref(),
            None,
            None,
            params.full,
            None,
            None,
        )
        .await?;
    Ok((newid, upid))
}

/// Shared `migrate_guest` executor used by both MCP dispatch and the HITL daemon (`#340`).
///
/// # Errors
///
/// Propagates any error from [`crate::api::ProxmoxGateway::migrate_guest`].
pub async fn exec_migrate_guest(
    client: &(dyn crate::api::ProxmoxGateway + Send + Sync),
    node: &str,
    gt: crate::api::types::GuestType,
    params: &crate::hitl::daemon::McpMigrateGuestParams,
) -> Result<String> {
    client
        .migrate_guest(
            node,
            params.guest_id,
            gt,
            &params.target_node,
            params.online,
            false,
            false,
        )
        .await
}

/// Shared `create_guest` executor used by both MCP dispatch and the HITL daemon (`#340`).
///
/// # Errors
///
/// Returns an error if required parameters (`template` for LXC) are missing or
/// the underlying [`crate::api::ProxmoxGateway::create_lxc`] /
/// [`crate::api::ProxmoxGateway::create_qemu`] call fails.
pub async fn exec_create_guest(
    client: &(dyn crate::api::ProxmoxGateway + Send + Sync),
    params: &crate::hitl::daemon::McpCreateGuestParams,
) -> Result<(u32, String)> {
    let node = params.node.as_str();
    let guest_type = params.guest_type.as_str();
    if guest_type != "qemu" && guest_type != "lxc" {
        anyhow::bail!("create_guest: invalid type '{guest_type}' (expected 'qemu' or 'lxc')");
    }
    let vmid = if let Some(id) = params.vmid.filter(|&v| v > 0) {
        id
    } else {
        client.get_next_vmid().await?
    };

    let name = params.name.as_deref();
    let memory = params
        .memory
        .unwrap_or(if guest_type == "lxc" { 512 } else { 1024 });
    let cores = params.cores.unwrap_or(1);
    let bridge = params.bridge.as_deref().unwrap_or("vmbr0");
    let storage = params.storage.as_deref();
    let disk_size = params.disk_size;

    let upid = if guest_type == "lxc" {
        let template = params
            .template
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("create_guest lxc: missing 'template'"))?;
        let size = disk_size.unwrap_or(8);
        let rootfs_storage = storage.unwrap_or("local-lvm");
        let rootfs = format!("{rootfs_storage}:{size}");
        let mut kv: Vec<(String, String)> = vec![
            ("vmid".into(), vmid.to_string()),
            ("ostemplate".into(), template.to_string()),
            ("memory".into(), memory.to_string()),
            ("cores".into(), cores.to_string()),
            ("rootfs".into(), rootfs),
            ("net0".into(), format!("name=eth0,bridge={bridge},ip=dhcp")),
        ];
        if let Some(n) = name {
            kv.push(("hostname".into(), n.to_string()));
        }
        let as_refs: Vec<(&str, &str)> = kv.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        client.create_lxc(node, &as_refs).await?
    } else {
        let iso = params.iso.as_deref();
        let size = disk_size.unwrap_or(32);
        let mut kv: Vec<(String, String)> = vec![
            ("vmid".into(), vmid.to_string()),
            ("memory".into(), memory.to_string()),
            ("cores".into(), cores.to_string()),
            ("ostype".into(), "l26".into()),
            ("scsihw".into(), "virtio-scsi-pci".into()),
            ("net0".into(), format!("virtio,bridge={bridge}")),
        ];
        if let Some(n) = name {
            kv.push(("name".into(), n.to_string()));
        }
        if let Some(st) = storage {
            kv.push(("scsi0".into(), format!("{st}:{size}")));
        }
        if let Some(i) = iso {
            kv.push(("cdrom".into(), i.to_string()));
        }
        let as_refs: Vec<(&str, &str)> = kv.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        client.create_qemu(node, &as_refs).await?
    };

    Ok((vmid, upid))
}

/// Shared `clone_with_cloudinit` executor used by both MCP dispatch and the HITL daemon (`#340`).
///
/// # Errors
///
/// Returns an error if the source guest is not QEMU, the clone task fails, or
/// cloud-init application/regeneration fails.
pub async fn exec_clone_with_cloudinit(
    client: &(dyn crate::api::ProxmoxGateway + Send + Sync),
    node: &str,
    gt: crate::api::types::GuestType,
    params: &crate::hitl::daemon::McpCloneWithCloudinitParams,
) -> Result<(u32, String, Value)> {
    let vmid = params.guest_id;
    if !matches!(gt, crate::api::types::GuestType::Qemu) {
        anyhow::bail!("clone_with_cloudinit: VMID {vmid} is LXC — cloud-init is QEMU-only");
    }
    let newid = if params.newid == 0 {
        client.next_free_vmid().await?
    } else {
        params.newid
    };
    let name = params.name.as_deref();
    let full = params.full;

    let profile = crate::cli::vm::CloudInitProfile {
        ciuser: params.ciuser.clone(),
        cipassword: None,
        sshkey: params.sshkey.clone(),
        sshkey_file: None,
        ipconfig0: params.ipconfig0.clone(),
        searchdomain: params.searchdomain.clone(),
        nameserver: params.nameserver.clone(),
    };

    let upid = client
        .clone_guest(node, vmid, gt, newid, name, None, None, full, None, None)
        .await?;
    // Block until clone lands — applying cloudinit before
    // the disk image is ready races PVE's own locking.
    let status = crate::cli::common::poll_task_until_done(client, node, &upid, 0).await?;
    if !status.is_success() {
        anyhow::bail!(
            "clone task did not succeed (status={:?}); cloud-init not applied",
            status.exitstatus
        );
    }
    let ci = crate::cli::vm::apply_cloudinit_and_regen(client, node, newid, gt, &profile).await?;
    Ok((newid, upid, ci))
}

pub(crate) async fn find_node_and_type(
    client: &(dyn crate::api::ProxmoxGateway + Send + Sync),
    vmid: u32,
) -> Result<Option<(String, crate::api::types::GuestType)>> {
    Ok(client
        .find_guest(vmid)
        .await?
        .map(|g| (g.node, g.guest_type)))
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
    config: ConfigHandle,
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
        // Per MCP spec 2025-03-26, server-sent notifications flow
        // automatically over the SSE channel — there's no formal
        // `notifications/subscribe` request in the protocol. We
        // accept it anyway as an informational ack so clients that
        // explicitly subscribe (per #71's spec text) get a clear
        // "yes, you'll receive these kinds" response. The actual
        // delivery is via the SSE `GET /mcp` channel; stdio
        // delivery is deferred to a follow-up (see notifications.rs
        // module rustdoc).
        "notifications/subscribe" => ok_result(
            id,
            &json!({
                "accepted": true,
                "available_kinds": ["task_state_change", "incident"],
                "transport_note":
                    "Server-sent notifications stream on the SSE channel (HTTP transport) or \
                     interleaved with the request/response stream on stdout (stdio transport).",
            }),
        ),
        "notifications/unsubscribe" => ok_result(id, &json!({"accepted": true})),
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

            // Snapshot the config once for the duration of this tool call so
            // a concurrent SIGHUP reload can't change policies mid-dispatch.
            let config_snap = config.read().await.clone();

            let budget_secs = TOOLS
                .iter()
                .find(|t| t.name == name)
                .map_or(DEFAULT_TIMEOUT_SECS, |t| t.timeout_secs);

            match tokio::time::timeout(
                Duration::from_secs(budget_secs),
                handle_tool_call(&client, &config_snap, &name, &args),
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
