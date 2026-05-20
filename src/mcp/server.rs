// MCP stdio transport — JSON-RPC 2.0 over stdin/stdout.
//
// Tool execution is delegated to `mcp::dispatch` which is shared with the
// HTTP transport. This module handles framing (line-delimited JSON,
// oversize-line rejection) AND server-initiated notification emission —
// every `notifications::McpNotification` from the in-process broker is
// serialised as a JSON-RPC 2.0 notification line on stdout, interleaved
// with the request/response stream.
//
// ## Why a stdin-reader background task
//
// The naïve approach — `tokio::select!` between `reader.read_until` and
// `notifications_rx.recv()` — is unsound: `read_until` is NOT cancel-safe
// (tokio docs). If a notification arrives mid-line, cancelling the read
// future leaves the buffered bytes in an indeterminate state — the next
// iteration would mis-parse them as a fresh request.
//
// Fix: spawn a stdin-reader task that does the (potentially cancel-unsafe)
// read on its own, then pushes complete `LineEvent`s to an mpsc channel.
// The main loop selects on the mpsc receiver (cancel-safe) and the broker
// receiver (cancel-safe). Both arms can be cancelled by select! with no
// data loss.

use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, mpsc};

/// Hard cap on a single JSON-RPC line.
///
/// Without this, a hostile client could send 500 MiB without a `\n` and
/// `read_until` would allocate the whole thing before returning.
/// 16 MiB is well above any legitimate MCP payload.
const MAX_RPC_LINE_BYTES: usize = 16 * 1024 * 1024;

use crate::api::PxClient;
use crate::config::ConfigHandle;
use crate::mcp::{dispatch, notifications};

#[derive(Deserialize, Debug)]
struct RpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<Value>,
    method: String,
    params: Option<Value>,
}

/// Events the stdin-reader task can push to the main loop.
#[derive(Debug)]
pub(crate) enum LineEvent {
    /// A complete line (still includes the trailing `\n`; the
    /// consumer trims).
    Line(Vec<u8>),
    /// A request that exceeded `MAX_RPC_LINE_BYTES` — the reader
    /// drained to the next newline and signals this so the main
    /// loop can emit the canonical `-32700 Parse error` reply.
    OversizeRejected,
    /// `read` returned `Ok(0)` — peer closed the pipe. The
    /// reader task exits after sending this and the main loop
    /// breaks.
    Eof,
}

pub async fn run_server(client: Arc<PxClient>, config: ConfigHandle) -> Result<()> {
    // Notification broker + pollers — same wiring as the HTTP
    // transport. When no peer is reading the stdout pipe the
    // broker drops messages silently; the pollers run for the
    // process lifetime regardless.
    let broker = notifications::Broker::new();
    let _task_poller = notifications::spawn_task_poller(Arc::clone(&client), broker.clone());
    let _incident_watcher = notifications::spawn_incident_watcher(broker.clone());
    let mut notification_rx = broker.subscribe();

    // Stdin reader runs as a separate task because `read_until`
    // is not cancel-safe. The mpsc receiver IS cancel-safe, so
    // the outer select! can pre-empt freely.
    let (lines_tx, mut lines_rx) = mpsc::channel::<LineEvent>(8);
    let stdin_task = tokio::spawn(stdin_reader_task(lines_tx));

    let mut stdout = tokio::io::stdout();

    loop {
        tokio::select! {
            biased;

            // Incoming JSON-RPC line (or sentinel) from stdin.
            event = lines_rx.recv() => {
                let Some(event) = event else { break }; // channel closed
                match event {
                    LineEvent::Eof => break,
                    LineEvent::OversizeRejected => {
                        write_response(
                            &mut stdout,
                            dispatch::err_result(
                                &Value::Null,
                                -32700,
                                &format!(
                                    "Parse error: request exceeds {MAX_RPC_LINE_BYTES} byte limit",
                                ),
                            ),
                        )
                        .await?;
                    }
                    LineEvent::Line(buf) => {
                        handle_line(&client, &config, &mut stdout, &buf).await?;
                    }
                }
            }

            // Server-initiated notification from the broker.
            n = notification_rx.recv() => {
                match n {
                    Ok(notif) => {
                        let envelope = notifications::rpc_envelope(&notif);
                        write_response(&mut stdout, envelope).await?;
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        // Surface the loss instead of silently
                        // continuing — same shape the HTTP SSE
                        // channel uses, so clients with both
                        // transports key off the same field.
                        let lagged = serde_json::json!({
                            "jsonrpc": "2.0",
                            "method": "notifications/lagged",
                            "params": {"missed": skipped}
                        });
                        write_response(&mut stdout, lagged).await?;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        // Broker dropped (process shutting down).
                        // Drain stdin to EOF cleanly via the
                        // stdin-task signal rather than abandon it.
                        break;
                    }
                }
            }
        }
    }

    // Abort the stdin reader so the process doesn't hang on its
    // tokio::spawn handle after the loop exits.
    stdin_task.abort();
    Ok(())
}

/// Background task: read lines from stdin, push complete events
/// to the channel. Owns its own `BufReader<Stdin>`.
async fn stdin_reader_task(tx: mpsc::Sender<LineEvent>) {
    let stdin = tokio::io::stdin();
    let reader = BufReader::new(stdin);
    stdin_reader_loop(reader, tx).await;
}

/// Generic-reader form of the stdin loop. Extracted so tests can
/// feed synthetic byte streams via `tokio::io::duplex` without
/// touching process stdin. The contract is identical to the stdin
/// caller above.
pub(crate) async fn stdin_reader_loop<R>(mut reader: BufReader<R>, tx: mpsc::Sender<LineEvent>)
where
    R: AsyncRead + Unpin,
{
    let mut line_buf: Vec<u8> = Vec::with_capacity(4096);

    loop {
        line_buf.clear();
        let n = match (&mut reader)
            .take(MAX_RPC_LINE_BYTES as u64)
            .read_until(b'\n', &mut line_buf)
            .await
        {
            Ok(0) if line_buf.is_empty() => {
                let _ = tx.send(LineEvent::Eof).await;
                return;
            }
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("stdio reader: read failure: {e}");
                let _ = tx.send(LineEvent::Eof).await;
                return;
            }
        };
        let truncated = !line_buf.ends_with(b"\n") && line_buf.len() >= MAX_RPC_LINE_BYTES;
        if truncated {
            // Drain to next newline so we don't mis-frame the
            // continuation as a fresh request. Same logic as the
            // original synchronous loop.
            let mut drain_buf: Vec<u8> = Vec::with_capacity(4096);
            loop {
                drain_buf.clear();
                let m = (&mut reader)
                    .take(MAX_RPC_LINE_BYTES as u64)
                    .read_until(b'\n', &mut drain_buf)
                    .await
                    .unwrap_or_default();
                if m == 0 || drain_buf.ends_with(b"\n") {
                    break;
                }
            }
            if tx.send(LineEvent::OversizeRejected).await.is_err() {
                return;
            }
            continue;
        }
        if n == 0 {
            let _ = tx.send(LineEvent::Eof).await;
            return;
        }
        if tx.send(LineEvent::Line(line_buf.clone())).await.is_err() {
            return;
        }
    }
}

/// Parse + dispatch one line. Extracted so the select! arm stays
/// readable. Writes either an error envelope (parse failure) or
/// the dispatch result (success); JSON-RPC §4 notifications
/// (returning `Value::Null`) write nothing.
async fn handle_line(
    client: &Arc<PxClient>,
    config: &ConfigHandle,
    stdout: &mut tokio::io::Stdout,
    buf: &[u8],
) -> Result<()> {
    let Ok(decoded) = std::str::from_utf8(buf) else {
        write_response(
            stdout,
            dispatch::err_result(&Value::Null, -32700, "Parse error: invalid UTF-8"),
        )
        .await?;
        return Ok(());
    };
    let line = decoded.trim();
    if line.is_empty() {
        return Ok(());
    }

    let req: RpcRequest = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            write_response(
                stdout,
                dispatch::err_result(&Value::Null, -32700, &format!("Parse error: {e}")),
            )
            .await?;
            return Ok(());
        }
    };

    let id = req.id.unwrap_or(Value::Null);
    let response = dispatch::dispatch_rpc(
        Arc::clone(client),
        Arc::clone(config),
        &req.method,
        id,
        req.params,
    )
    .await;

    // Notifications return Value::Null — do not write a response (JSON-RPC §4).
    if response.is_null() {
        return Ok(());
    }
    write_response(stdout, response).await
}

async fn write_response(stdout: &mut tokio::io::Stdout, response: Value) -> Result<()> {
    let json_str = serde_json::to_string(&response)?;
    stdout.write_all(format!("{json_str}\n").as_bytes()).await?;
    stdout.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::notifications::{Broker, McpNotification};
    use std::time::Duration;

    /// The stdio loop's notification path is hard to test
    /// end-to-end (stdin/stdout are process-globals). Instead we
    /// pin the smaller, composable pieces:
    ///
    /// 1. The broker fans out to the same kind of receiver
    ///    `run_server` uses.
    /// 2. Notification envelopes are stable JSON-RPC 2.0 shape.
    ///
    /// Combined with the existing `mcp::notifications` tests
    /// (which already cover serialisation + broker semantics),
    /// the wiring confidence here is "the receiver hands us a
    /// notification, we'd write it as JSON-RPC". The actual
    /// serialise+writeln chain is trivial code with no branches.
    #[tokio::test]
    async fn broker_receiver_yields_notifications_in_order() {
        let broker = Broker::new();
        let mut rx = broker.subscribe();
        broker.publish(McpNotification::Incident {
            event: "frozen",
            reason: "x".into(),
        });
        broker.publish(McpNotification::Incident {
            event: "thawed",
            reason: String::new(),
        });
        // Both should be available immediately.
        let first = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("recv timed out")
            .expect("recv failed");
        let second = tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .expect("recv timed out")
            .expect("recv failed");
        assert!(matches!(
            first,
            McpNotification::Incident {
                event: "frozen",
                ..
            }
        ));
        assert!(matches!(
            second,
            McpNotification::Incident {
                event: "thawed",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn lagged_recv_error_surfaces_after_buffer_overflow() {
        // Broker capacity is 256 per the const; publish > 256
        // without consuming → first recv returns Lagged.
        let broker = Broker::new();
        let mut rx = broker.subscribe();
        for i in 0..300 {
            broker.publish(McpNotification::Incident {
                event: "frozen",
                reason: format!("{i}"),
            });
        }
        let err = rx.recv().await.unwrap_err();
        assert!(matches!(err, broadcast::error::RecvError::Lagged(_)));
    }

    // ───────────────────────────────────────────────────────────
    // pre-commit/02-error-handling.md — stdin reader contracts
    //
    // These two tests pin the DoS / malformed-input invariants of
    // the MCP stdio loop. They use `stdin_reader_loop` (the
    // generic-reader extraction of `stdin_reader_task`) fed via a
    // `tokio::io::duplex` pipe — no subprocess, no real stdin.
    // ───────────────────────────────────────────────────────────

    /// 02-row · "Malformed stdin (no newline) truncated at
    ///           `MAX_RPC_LINE_BYTES` (V10)"
    ///
    /// Write `2 * MAX_RPC_LINE_BYTES` bytes of payload to the input
    /// side of a duplex pipe with NO newline, then EOF. The reader
    /// loop must emit `LineEvent::OversizeRejected` (the denial-of-service guard
    /// path) and NOT buffer unboundedly.
    #[tokio::test]
    async fn stdin_oversize_line_emits_oversize_rejected_not_buffered() {
        use tokio::io::{AsyncWriteExt, BufReader};

        let (mut tx_pipe, rx_pipe) = tokio::io::duplex(64 * 1024);
        let (tx_events, mut rx_events) = mpsc::channel(8);

        let reader_task = tokio::spawn(async move {
            let reader = BufReader::new(rx_pipe);
            super::stdin_reader_loop(reader, tx_events).await;
        });

        // Write 2 * MAX_RPC_LINE_BYTES of 'A' with no newline, then drop tx
        // to signal EOF. Use `MAX_RPC_LINE_BYTES + 1024` to keep the
        // test cheap: enough to trip the cap, not enough to thrash
        // memory on the CI runner.
        let oversize_len = super::MAX_RPC_LINE_BYTES + 1024;
        let chunk = vec![b'A'; 4096];
        let mut sent = 0usize;
        while sent < oversize_len {
            let to_send = chunk.len().min(oversize_len - sent);
            tx_pipe.write_all(&chunk[..to_send]).await.expect("write");
            sent += to_send;
        }
        drop(tx_pipe); // EOF

        // Bounded wait: the DoS guard must fire well before any sane
        // ceiling.
        let evt = tokio::time::timeout(Duration::from_secs(30), rx_events.recv())
            .await
            .expect("reader must emit event within 30s — DoS guard regressed")
            .expect("channel must not close");
        assert!(
            matches!(evt, super::LineEvent::OversizeRejected),
            "expected OversizeRejected, got: {evt:?}"
        );

        // Subsequent event should be Eof (we wrote no further data).
        let next = tokio::time::timeout(Duration::from_secs(5), rx_events.recv())
            .await
            .expect("EOF event must follow")
            .expect("channel must not close");
        assert!(matches!(next, super::LineEvent::Eof));

        reader_task.await.expect("reader task joins");
    }

    /// 02-row · "Invalid UTF-8 sequence in stdin yields JSON-RPC Parse Error"
    ///
    /// The stdin reader is byte-level: it delivers raw `Vec<u8>` to
    /// `handle_line`. The Parse Error response is produced by
    /// `handle_line`, not by the reader. We attest the reader half
    /// (it delivers the bytes faithfully + does NOT crash on non-UTF-8
    /// bytes that happen to contain a newline) and the response
    /// half (the canonical Parse Error envelope is shaped correctly).
    #[tokio::test]
    async fn stdin_non_utf8_bytes_delivered_as_line_event_no_crash() {
        use tokio::io::{AsyncWriteExt, BufReader};

        let (mut tx_pipe, rx_pipe) = tokio::io::duplex(1024);
        let (tx_events, mut rx_events) = mpsc::channel(8);

        let reader_task = tokio::spawn(async move {
            let reader = BufReader::new(rx_pipe);
            super::stdin_reader_loop(reader, tx_events).await;
        });

        // Three invalid-UTF-8 bytes followed by newline.
        tx_pipe
            .write_all(&[0xFF, 0xFE, 0xFD, b'\n'])
            .await
            .expect("write");
        drop(tx_pipe);

        let evt = tokio::time::timeout(Duration::from_secs(5), rx_events.recv())
            .await
            .expect("reader must deliver event")
            .expect("channel must not close");
        let bytes = match evt {
            super::LineEvent::Line(b) => b,
            other => panic!("expected Line, got {other:?}"),
        };
        assert_eq!(bytes, vec![0xFF, 0xFE, 0xFD, b'\n']);
        // The byte slice does NOT parse as UTF-8 — the contract is
        // that handle_line() then writes the Parse Error envelope.
        assert!(std::str::from_utf8(&bytes).is_err());
        reader_task.await.expect("reader task joins");
    }

    /// 02-row · companion — the JSON-RPC parse-error envelope shape
    /// is what `handle_line` writes on invalid UTF-8 (and on JSON
    /// parse failure). Pin the canonical shape so a future refactor
    /// of `dispatch::err_result` can't silently change the wire.
    #[tokio::test]
    async fn parse_error_envelope_shape_is_jsonrpc_2_0_with_neg32700() {
        let env =
            crate::mcp::dispatch::err_result(&Value::Null, -32700, "Parse error: invalid UTF-8");
        assert_eq!(env["jsonrpc"], "2.0");
        assert_eq!(env["error"]["code"], -32700);
        assert!(env["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("Parse error"));
    }
}
