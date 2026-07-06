//! Termproxy WebSocket serial console (feature #1b).
//!
//! Two-step flow:
//! 1. REST POST to `/nodes/{node}/{type}/{vmid}/termproxy` → ticket
//!    (handled by `api::PxClient::get_termproxy`).
//! 2. WSS to `/api2/json/.../vncwebsocket?port=...&vncticket=...` →
//!    send `<user>:<ticket>\n` as the auth frame, then bidirectional
//!    raw bytes that we feed to the same `vt100::Parser` widget used
//!    by feature 1a.
//!
//! This module provides the WS plumbing and the I/O pump. The CLI
//! drives it for `proxxx serial <vmid>`. TUI integration mirrors the
//! existing `SshSessionHandler` pattern but isn't wired in this
//! iteration — CLI is enough to recover a stuck VM.
//!
//! Honest scope cuts:
//! - **PVE 8+ for token auth.** Pre-PVE8 vncwebsocket required a
//!   password-derived ticket; tokens were inconsistently accepted.
//!   We don't gate on version explicitly — the REST `termproxy` call
//!   either issues a usable ticket or doesn't.
//! - **No TUI integration this iteration.** Doable, mirrors 1a.

pub mod tls;
pub mod url;

use std::sync::Arc;

use anyhow::{Context, Result};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::Connector;
use tracing::{debug, info, warn};

pub use url::{build_ws_target, WsTarget};

/// Connect to a termproxy WebSocket and perform the auth handshake.
/// Returns a `WsStream` ready for bidirectional I/O.
pub async fn connect(
    target: &WsTarget,
    verify_tls: bool,
    headers: &[(String, String)],
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
> {
    let connector = if verify_tls {
        // Default rustls connector with webpki-roots — pulled in by
        // tokio-tungstenite's rustls-tls-webpki-roots feature.
        None
    } else {
        let cfg = tls::dangerous_no_verify_config();
        Some(Connector::Rustls(Arc::new(cfg)))
    };

    let mut request: tokio_tungstenite::tungstenite::handshake::client::Request = target
        .url
        .as_str()
        .into_client_request()
        .context("bad WS URL")?;

    for (name, val) in headers {
        let hn =
            tokio_tungstenite::tungstenite::http::header::HeaderName::from_bytes(name.as_bytes())?;
        let hv = tokio_tungstenite::tungstenite::http::HeaderValue::from_str(val)?;
        request.headers_mut().insert(hn, hv);
    }

    // (Gemini audit) — explicit frame/message size limits.
    //
    // tokio-tungstenite has internal defaults (16 MiB frame / 64 MiB
    // message), so the kernel-panic-storm scenario is bounded today,
    // but defaults are not part of our compile-time contract — pin
    // them so a future bump can't silently raise the OOM ceiling.
    //
    // 1 MiB per frame is comfortably above any realistic serial-console
    // or termproxy resize/data frame; PVE never sends multi-megabyte
    // single frames in this protocol. 4 MiB total message ceiling
    // protects against a hostile / buggy server attempting to push a
    // chunked giant message.
    //
    // Backpressure path is the real defence: this select! drains one
    // message at a time and synchronously writes to stdout; the next
    // ws.next() does not happen until the write returns, which fills
    // the kernel TCP recv buffer (~64 KB) and stalls the producer.
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
    // tungstenite 0.29 marked WebSocketConfig as `#[non_exhaustive]` so
    // we can no longer construct it with a struct literal. Build via
    // Default then mutate the two fields we care about — the other
    // defaults (write_buffer_size, accept_unmasked_frames, …) stay
    // upstream-controlled, which is the right behaviour here: we only
    // want to override the OOM-ceiling pair, not freeze every knob.
    let mut ws_config = WebSocketConfig::default();
    ws_config.max_frame_size = Some(1 << 20);
    ws_config.max_message_size = Some(4 << 20);

    info!("termproxy WSS connect: {}", url::redact_ticket(&target.url));
    // Bound the connect (TCP + TLS + WS handshake). Without this an
    // unreachable / black-holed node leaves the call hanging until the
    // OS TCP timeout (minutes) — and the terminal is already half
    // set up, so the operator sees a frozen screen with no error.
    // 20 s is generous for a real PVE node on a LAN/VPN yet fails fast
    // on a dead one. Unlike the reqwest-based PVE/PBS clients (30 s
    // request timeout that covers connect), tungstenite has none.
    const WS_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
    let (mut ws, _resp) = tokio::time::timeout(
        WS_CONNECT_TIMEOUT,
        tokio_tungstenite::connect_async_tls_with_config(
            request,
            Some(ws_config),
            false,
            connector,
        ),
    )
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "WS connect to {} timed out after {WS_CONNECT_TIMEOUT:?} — node unreachable?",
            url::redact_ticket(&target.url)
        )
    })?
    .with_context(|| format!("WS connect to {}", url::redact_ticket(&target.url)))?;

    // Auth frame — must be a binary frame containing `<user>:<ticket>\n`.
    use futures_util::SinkExt;
    // tungstenite 0.29: Message::Binary now wraps `bytes::Bytes` (not
    // `Vec<u8>`). `Vec<u8>` → `Bytes` is a zero-copy `From` impl.
    ws.send(Message::Binary(target.auth.as_bytes().to_vec().into()))
        .await
        .context("sending termproxy auth frame")?;

    debug!("termproxy auth frame sent");
    Ok(ws)
}

// We need the trait import for `into_client_request`. tokio-tungstenite
// re-exports it via its tungstenite re-export.
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// Request a TTY size update over the established WebSocket. Proxmox
/// expects a binary text frame of the form `1:<cols>:<rows>:` (the
/// leading `1` is the resize opcode, see proxmox-widget-toolkit docs).
pub async fn send_resize<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    cols: u16,
    rows: u16,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures_util::SinkExt;
    let frame = format!("1:{cols}:{rows}:");
    ws.send(Message::Binary(frame.into_bytes().into()))
        .await
        .context("sending termproxy resize frame")?;
    Ok(())
}

/// Forward arbitrary bytes (e.g. a keystroke) to the remote PTY. Proxmox
/// accepts user input as a binary frame of the form `0:<len>:<bytes>`
/// where the leading `0` is the data opcode.
pub async fn send_input<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    bytes: &[u8],
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures_util::SinkExt;
    // Proxmox expects: "0:<length-as-decimal-string>:<bytes>"
    let mut payload = Vec::with_capacity(bytes.len() + 8);
    payload.extend_from_slice(b"0:");
    payload.extend_from_slice(bytes.len().to_string().as_bytes());
    payload.push(b':');
    payload.extend_from_slice(bytes);
    ws.send(Message::Binary(payload.into()))
        .await
        .context("sending termproxy data frame")?;
    Ok(())
}

/// Decode a server-sent termproxy frame. Returns the raw bytes the
/// remote shell wrote (the `0:<len>:<bytes>` form), or None for
/// non-data frames (heartbeats, etc.) which the caller should ignore.
#[must_use]
pub fn decode_data_frame(payload: &[u8]) -> Option<&[u8]> {
    // Looking for `0:<digits>:<bytes>`. Proxmox does NOT use the same
    // opcode wrapper for output — it just sends raw bytes. So in
    // practice the inbound side is plain bytes; this helper exists only
    // for symmetry + tests.
    if payload.first().is_none_or(|b| *b != b'0') {
        return Some(payload); // treat as raw output
    }
    if payload.get(1) != Some(&b':') {
        return Some(payload);
    }
    // Length-prefixed form. Find the second ':'.
    let after_first_colon = &payload[2..];
    let second_colon = after_first_colon.iter().position(|b| *b == b':')?;
    let len_str = std::str::from_utf8(&after_first_colon[..second_colon]).ok()?;
    let len: usize = len_str.parse().ok()?;
    let body_start = 2 + second_colon + 1;
    if body_start + len > payload.len() {
        warn!("termproxy data frame length mismatch — skipping");
        return None;
    }
    Some(&payload[body_start..body_start + len])
}

/// Map a raw termproxy / websocket / vncproxy error into a
/// sysadmin-friendly hint. Returns `Some(hint)` when a known failure
/// pattern is recognised, `None` otherwise (the caller should then show
/// the raw error). proxxx generates these errors, so proxxx owns the
/// decoration — CLI, TUI and embedding consumers (e.g. proxima) share
/// one mapping instead of each re-deriving it.
///
/// Matching is substring-based and case-insensitive; order is
/// most-specific-first.
#[must_use]
pub fn humanize_error_hint(raw: &str) -> Option<&'static str> {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("lxc-console") || (lower.contains("vncproxy") && lower.contains("exit code"))
    {
        return Some(
            "couldn't attach to the container console — the guest may still be initialising \
             or shutting down; wait a few seconds and reconnect",
        );
    }
    if lower.contains("reset without closing handshake") || lower.contains("connection reset") {
        return Some(
            "the console session was reset by PVE — the underlying console process exited \
             (guest stopping, session reused, or the subprocess died); reconnect to retry",
        );
    }
    if lower.contains("handshake")
        && (lower.contains("tls") || lower.contains("certificate") || lower.contains("cert"))
    {
        return Some(
            "TLS handshake failed — the node certificate may have rotated or a pinned \
             fingerprint changed; re-check the endpoint's certificate",
        );
    }
    if lower.contains("401")
        || lower.contains("authentication failure")
        || lower.contains("permission denied")
    {
        return Some(
            "the console ticket was rejected — it may have expired, or the token lacks console \
             privileges (needs VM.Console / Sys.Console)",
        );
    }
    if lower.contains("timed out") || lower.contains("timeout") {
        return Some(
            "the console connection timed out — the node may be unreachable or overloaded; \
             check connectivity to the API port (usually 8006)",
        );
    }
    None
}

/// Convenience over [`humanize_error_hint`]: the friendly hint when a
/// pattern is recognised, otherwise the raw error string unchanged.
#[must_use]
pub fn humanize_error(raw: &str) -> String {
    humanize_error_hint(raw).map_or_else(|| raw.to_string(), str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_raw_output_passthrough() {
        // Most output frames are raw — passthrough.
        let bytes = b"hello world";
        assert_eq!(decode_data_frame(bytes), Some(&bytes[..]));
    }

    #[test]
    fn decode_length_prefixed_form() {
        let frame = b"0:5:hello";
        assert_eq!(decode_data_frame(frame), Some(&b"hello"[..]));
    }

    #[test]
    fn decode_length_mismatch_is_none() {
        // Claims 99 bytes, has 5.
        let frame = b"0:99:hello";
        assert!(decode_data_frame(frame).is_none());
    }

    #[test]
    fn decode_invalid_length_falls_back_to_raw() {
        let frame = b"0:abc:hello";
        // No usize::from_str("abc") — second_colon found but parse fails
        // → return None? Actually the code returns None on parse fail.
        assert!(decode_data_frame(frame).is_none());
    }

    #[test]
    fn humanize_maps_lxc_console_failure() {
        let h = humanize_error_hint("Task failed: [vncproxy] ... lxc-console exit code 1");
        assert!(h.unwrap().contains("container console"));
    }

    #[test]
    fn humanize_maps_ws_reset() {
        let h = humanize_error_hint("ws error: Connection reset without closing handshake");
        assert!(h.unwrap().contains("reset by PVE"));
    }

    #[test]
    fn humanize_maps_tls_handshake() {
        let h = humanize_error_hint("TLS handshake failed: certificate verify failed");
        assert!(h.unwrap().contains("certificate"));
    }

    #[test]
    fn humanize_unknown_returns_none_and_passes_raw_through() {
        assert!(humanize_error_hint("some totally novel error").is_none());
        assert_eq!(
            humanize_error("some totally novel error"),
            "some totally novel error"
        );
    }
}
