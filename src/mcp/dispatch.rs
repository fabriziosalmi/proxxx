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
                    if !val.is_string() {
                        anyhow::bail!("Parameter '{}': expected string, got {}", p.name, val);
                    }
                }
            }
        }
    }

    use crate::api::ProxmoxGateway;
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
        let vmid = args
            .get("guest_id")
            .and_then(serde_json::Value::as_u64)
            .map(|g| g as u32);

        // Tag-targeted policies need the guest's live tags; only fetch
        // them when there are policies to evaluate AND the call carries a
        // guest_id. `create_guest` / `clone_*` have no pre-existing
        // guest_id — they can only ever match a wildcard/action policy.
        let matched = if policies.is_empty() {
            None
        } else {
            // Only pay the `find_guest` round-trip when a policy actually
            // targets tags — action/vmid/wildcard policies decide offline.
            let needs_tags = policies.iter().any(|p| p.target.starts_with("tag:"));
            let tags: Vec<String> = if needs_tags {
                if let Some(v) = vmid {
                    client
                        .find_guest(v)
                        .await?
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
            let txn_id = match vmid {
                Some(v) => format!("{name}:{v}"),
                None => name.to_string(),
            };

            if let Some(ref tg) = config.telegram {
                match crate::hitl::telegram::TelegramGateway::from_config(tg).await {
                    Ok(tg_gateway) => {
                        let reason = format!("MCP requested action: {name}");
                        let _ = tg_gateway
                            .request_approval(name, &target, &reason, &txn_id)
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
        ToolAction::CreateGuest => {
            use crate::api::ProxmoxGateway;
            let node = args
                .get("node")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("create_guest: missing required param 'node'"))?;
            let guest_type = args
                .get("type")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("create_guest: missing required param 'type'"))?;

            let vmid = if let Some(id) = args.get("vmid").and_then(serde_json::Value::as_u64) {
                id as u32
            } else {
                client.get_next_vmid().await?
            };

            let name = args.get("name").and_then(serde_json::Value::as_str);
            let memory = args
                .get("memory")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(if guest_type == "lxc" { 512 } else { 1024 });
            let cores = args
                .get("cores")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(1);
            let bridge = args
                .get("bridge")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("vmbr0");
            let storage = args.get("storage").and_then(serde_json::Value::as_str);
            let disk_size = args.get("disk_size").and_then(serde_json::Value::as_u64);

            let upid = if guest_type == "lxc" {
                let template = args
                    .get("template")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("create_guest lxc: missing 'template'"))?;
                let size = disk_size.unwrap_or(8);
                let rootfs_storage = storage.unwrap_or("local-lvm");
                let rootfs = format!("{rootfs_storage}:{size}");
                let mut params: Vec<(String, String)> = vec![
                    ("vmid".into(), vmid.to_string()),
                    ("ostemplate".into(), template.to_string()),
                    ("memory".into(), memory.to_string()),
                    ("cores".into(), cores.to_string()),
                    ("rootfs".into(), rootfs),
                    ("net0".into(), format!("name=eth0,bridge={bridge},ip=dhcp")),
                ];
                if let Some(n) = name {
                    params.push(("hostname".into(), n.to_string()));
                }
                let as_refs: Vec<(&str, &str)> = params
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                client.create_lxc(node, &as_refs).await?
            } else {
                let iso = args.get("iso").and_then(serde_json::Value::as_str);
                let size = disk_size.unwrap_or(32);
                let mut params: Vec<(String, String)> = vec![
                    ("vmid".into(), vmid.to_string()),
                    ("memory".into(), memory.to_string()),
                    ("cores".into(), cores.to_string()),
                    ("ostype".into(), "l26".into()),
                    ("scsihw".into(), "virtio-scsi-pci".into()),
                    ("net0".into(), format!("virtio,bridge={bridge}")),
                ];
                if let Some(n) = name {
                    params.push(("name".into(), n.to_string()));
                }
                if let Some(st) = storage {
                    params.push(("scsi0".into(), format!("{st}:{size}")));
                }
                if let Some(i) = iso {
                    params.push(("cdrom".into(), i.to_string()));
                }
                let as_refs: Vec<(&str, &str)> = params
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect();
                client.create_qemu(node, &as_refs).await?
            };

            return Ok(json!({
                "content": [{
                    "type": "text",
                    "text": format!("Guest {vmid} ({guest_type}) creation started on {node}. UPID: {upid}")
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
            let vmid = args
                .get("guest_id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let (node, gt) = find_node_and_type(client, vmid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest {vmid} not found"))?;
            if !matches!(gt, crate::api::types::GuestType::Qemu) {
                anyhow::bail!("clone_with_cloudinit: VMID {vmid} is LXC — cloud-init is QEMU-only");
            }
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

            let profile = crate::cli::vm::CloudInitProfile {
                ciuser: args
                    .get("ciuser")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                cipassword: None,
                sshkey: args
                    .get("sshkey")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                sshkey_file: None,
                ipconfig0: args
                    .get("ipconfig0")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                searchdomain: args
                    .get("searchdomain")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                nameserver: args
                    .get("nameserver")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
            };

            let upid = client
                .clone_guest(&node, vmid, gt, newid, name, None, None, full, None, None)
                .await?;
            // Block until clone lands — applying cloudinit before
            // the disk image is ready races PVE's own locking.
            let status = crate::cli::common::poll_task_until_done(client, &node, &upid, 0).await?;
            if !status.is_success() {
                anyhow::bail!(
                    "clone task did not succeed (status={:?}); cloud-init not applied",
                    status.exitstatus
                );
            }
            let ci = crate::cli::vm::apply_cloudinit_and_regen(client, &node, newid, gt, &profile)
                .await?;
            format!("Cloned guest {vmid} → {newid} (UPID: {upid}); cloud-init applied: {ci}")
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
