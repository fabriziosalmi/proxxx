use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// (Gemini audit) — hard cap on a single JSON-RPC line.
///
/// Without this, an MCP client (legitimate or hostile) could send
/// 500 MiB without a `\n` and `BufReader::lines().next_line()` would
/// allocate the whole thing in a single `String` before returning,
/// OOM-killing proxxx.
///
/// 16 MiB is generous: the largest MCP `tools/call` payload we expect
/// is a few KiB of JSON. Anything beyond is malformed or hostile and
/// we reject it cleanly with a JSON-RPC parse error rather than
/// crashing.
const MAX_RPC_LINE_BYTES: usize = 16 * 1024 * 1024;

use crate::api::PxClient;
use crate::config::ProfileConfig;
use crate::mcp::tools::{ToolAction, TOOLS};

#[derive(Deserialize, Debug)]
struct RpcRequest {
    /// JSON-RPC 2.0 envelope marker. Required for spec compliance; we
    /// validate by deserialisation but don't consume the value at runtime.
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

#[derive(Serialize, Debug)]
struct RpcResponse {
    jsonrpc: String,
    id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
}

pub async fn run_server(client: Arc<PxClient>, config: Arc<ProfileConfig>) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line_buf: Vec<u8> = Vec::with_capacity(4096);

    loop {
        line_buf.clear();
        // read at most MAX_RPC_LINE_BYTES via the `take`
        // adapter. Either we find a `\n` within the budget (good),
        // or we hit the cap and the buffer ends WITHOUT a newline
        // (oversize line — drain to next newline and reject).
        let n = (&mut reader)
            .take(MAX_RPC_LINE_BYTES as u64)
            .read_until(b'\n', &mut line_buf)
            .await?;
        if n == 0 && line_buf.is_empty() {
            break; // clean EOF
        }
        let truncated = !line_buf.ends_with(b"\n") && line_buf.len() >= MAX_RPC_LINE_BYTES;
        if truncated {
            // Drain the rest of this oversize line in bounded chunks,
            // discarding bytes, so the next iteration starts on a
            // fresh JSON-RPC line. The cap on each drain chunk
            // guarantees we still bound RAM during the drain.
            let mut drain_buf: Vec<u8> = Vec::with_capacity(4096);
            loop {
                drain_buf.clear();
                let m = (&mut reader)
                    .take(MAX_RPC_LINE_BYTES as u64)
                    .read_until(b'\n', &mut drain_buf)
                    .await?;
                if m == 0 || drain_buf.ends_with(b"\n") {
                    break;
                }
            }
            send_error(
                &mut stdout,
                Value::Null,
                -32700,
                &format!("Parse error: request exceeds {MAX_RPC_LINE_BYTES} byte limit"),
            )
            .await?;
            continue;
        }
        if n == 0 {
            break; // EOF after partial line
        }

        let line = if let Ok(s) = std::str::from_utf8(&line_buf) {
            s.trim()
        } else {
            send_error(
                &mut stdout,
                Value::Null,
                -32700,
                "Parse error: invalid UTF-8",
            )
            .await?;
            continue;
        };
        if line.is_empty() {
            continue;
        }

        let req: RpcRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                send_error(
                    &mut stdout,
                    Value::Null,
                    -32700,
                    &format!("Parse error: {e}"),
                )
                .await?;
                continue;
            }
        };

        let id = req.id.unwrap_or(Value::Null);

        match req.method.as_str() {
            "initialize" => {
                let result = json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {
                            "listChanged": false
                        }
                    },
                    "serverInfo": {
                        "name": "proxxx-mcp",
                        "version": "0.1.0"
                    }
                });
                send_result(&mut stdout, id, result).await?;
            }
            "notifications/initialized" => {
                // Ignore
            }
            "tools/list" => {
                let registry = crate::mcp::tools::registry_json();
                let tools = registry.get("tools").unwrap_or(&json!([])).clone();
                send_result(&mut stdout, id, json!({ "tools": tools })).await?;
            }
            "tools/call" => {
                if let Some(params) = req.params {
                    let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    let args = params.get("arguments").cloned().unwrap_or(json!({}));

                    match handle_tool_call(&client, &config, name, &args).await {
                        Ok(res) => send_result(&mut stdout, id, res).await?,
                        Err(e) => send_error(&mut stdout, id, -32603, &e.to_string()).await?,
                    }
                } else {
                    send_error(&mut stdout, id, -32602, "Invalid params").await?;
                }
            }
            _ => {
                send_error(&mut stdout, id, -32601, "Method not found").await?;
            }
        }
    }

    Ok(())
}

async fn send_result(stdout: &mut tokio::io::Stdout, id: Value, result: Value) -> Result<()> {
    let res = RpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: Some(result),
        error: None,
    };
    let json_str = serde_json::to_string(&res)?;
    stdout.write_all(format!("{json_str}\n").as_bytes()).await?;
    stdout.flush().await?;
    Ok(())
}

async fn send_error(
    stdout: &mut tokio::io::Stdout,
    id: Value,
    code: i32,
    message: &str,
) -> Result<()> {
    let res = RpcResponse {
        jsonrpc: "2.0".to_string(),
        id,
        result: None,
        error: Some(json!({ "code": code, "message": message })),
    };
    let json_str = serde_json::to_string(&res)?;
    stdout.write_all(format!("{json_str}\n").as_bytes()).await?;
    stdout.flush().await?;
    Ok(())
}

async fn handle_tool_call(
    client: &PxClient,
    config: &ProfileConfig,
    name: &str,
    args: &Value,
) -> Result<Value> {
    let tool_def = TOOLS
        .iter()
        .find(|t| t.name == name)
        .ok_or_else(|| anyhow::anyhow!("Tool not found: {name}"))?;

    // Basic Validation
    for p in tool_def.params {
        if p.required && args.get(p.name).is_none() {
            anyhow::bail!("Missing required parameter: {}", p.name);
        }
    }

    use crate::api::ProxmoxGateway;
    let mut is_hitl_pending = false;
    let mut hitl_msg = String::new();

    // Check HITL for destructive actions if it concerns a guest
    if tool_def.destructive {
        if let Some(guest_id) = args.get("guest_id").and_then(serde_json::Value::as_u64) {
            let vmid = guest_id as u32;
            let action_str = name.split('_').next().unwrap_or("unknown");

            // Try to find the node and tags to evaluate policy
            // In a real scenario we'd do a quick lookup across nodes
            // For brevity, we assume we fetch the guest
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

                hitl_msg = format!("Action intercepted by HITL policy. Requires {} approval(s) via {}. Transaction: {}", policy.require, policy.channel, txn_id);
            }
        }
    }

    if is_hitl_pending {
        return Ok(json!({
            "content": [{
                "type": "text",
                "text": hitl_msg
            }]
        }));
    }

    // Execute tool
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
        ToolAction::StartGuest => {
            let vmid = args
                .get("guest_id")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as u32;
            let (node, gt) = find_node_and_type(client, vmid)
                .await?
                .ok_or_else(|| anyhow::anyhow!("Guest not found"))?;
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
                .ok_or_else(|| anyhow::anyhow!("Guest not found"))?;
            // Bug #2 fix: force=false → graceful shutdown.
            let upid = if force {
                client.stop_guest(&node, vmid, gt, true).await?
            } else {
                client.shutdown_guest(&node, vmid, gt).await?
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
                .ok_or_else(|| anyhow::anyhow!("Guest not found"))?;
            let upid = client.restart_guest(&node, vmid, gt).await?;
            format!("Restarted guest {vmid}. UPID: {upid}")
        }
        _ => {
            anyhow::bail!("Tool not yet fully implemented in MCP server")
        }
    };

    Ok(json!({
        "content": [{
            "type": "text",
            "text": content
        }]
    }))
}

#[allow(dead_code)]
async fn find_node_for_guest(client: &PxClient, vmid: u32) -> Result<Option<String>> {
    Ok(find_node_and_type(client, vmid).await?.map(|(n, _)| n))
}

/// Locate a guest's node AND its `GuestType` (QEMU vs LXC) — required by
/// the trait's write methods after bug #1 fix.
async fn find_node_and_type(
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
