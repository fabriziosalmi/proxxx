// MCP stdio transport — JSON-RPC 2.0 over stdin/stdout.
//
// Tool execution is delegated to `mcp::dispatch` which is shared with the
// HTTP transport. This module only handles framing: line-delimited JSON,
// oversize-line rejection, and the stdio read/write loop.

use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// Hard cap on a single JSON-RPC line.
///
/// Without this, a hostile client could send 500 MiB without a `\n` and
/// `read_until` would allocate the whole thing before returning.
/// 16 MiB is well above any legitimate MCP payload.
const MAX_RPC_LINE_BYTES: usize = 16 * 1024 * 1024;

use crate::api::PxClient;
use crate::config::ProfileConfig;
use crate::mcp::dispatch;

#[derive(Deserialize, Debug)]
struct RpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

pub async fn run_server(client: Arc<PxClient>, config: Arc<ProfileConfig>) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line_buf: Vec<u8> = Vec::with_capacity(4096);

    loop {
        line_buf.clear();
        let n = (&mut reader)
            .take(MAX_RPC_LINE_BYTES as u64)
            .read_until(b'\n', &mut line_buf)
            .await?;
        if n == 0 && line_buf.is_empty() {
            break;
        }
        let truncated = !line_buf.ends_with(b"\n") && line_buf.len() >= MAX_RPC_LINE_BYTES;
        if truncated {
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
            write_response(
                &mut stdout,
                dispatch::err_result(
                    &Value::Null,
                    -32700,
                    &format!("Parse error: request exceeds {MAX_RPC_LINE_BYTES} byte limit"),
                ),
            )
            .await?;
            continue;
        }
        if n == 0 {
            break;
        }

        #[allow(clippy::single_match_else)]
        let line = match std::str::from_utf8(&line_buf) {
            Ok(s) => s.trim(),
            Err(_) => {
                write_response(
                    &mut stdout,
                    dispatch::err_result(&Value::Null, -32700, "Parse error: invalid UTF-8"),
                )
                .await?;
                continue;
            }
        };
        if line.is_empty() {
            continue;
        }

        let req: RpcRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                write_response(
                    &mut stdout,
                    dispatch::err_result(&Value::Null, -32700, &format!("Parse error: {e}")),
                )
                .await?;
                continue;
            }
        };

        let id = req.id.unwrap_or(Value::Null);
        let response = dispatch::dispatch_rpc(
            Arc::clone(&client),
            Arc::clone(&config),
            &req.method,
            id,
            req.params,
        )
        .await;

        write_response(&mut stdout, response).await?;
    }

    Ok(())
}

async fn write_response(stdout: &mut tokio::io::Stdout, response: Value) -> Result<()> {
    let json_str = serde_json::to_string(&response)?;
    stdout.write_all(format!("{json_str}\n").as_bytes()).await?;
    stdout.flush().await?;
    Ok(())
}
