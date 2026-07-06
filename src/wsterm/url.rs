//! URL builder for the Proxmox vncwebsocket endpoint (feature #1b).
//!
//! Pure logic — no I/O. Tested independently because every PVE version
//! is fussy about exact path + query encoding, and a bad URL silently
//! 404s with no useful error.

use crate::api::types::GuestType;

/// Result of building the WebSocket URL + auth payload.
#[derive(Clone, PartialEq, Eq)]
pub struct WsTarget {
    /// Full `wss://...` URL ready for `connect_async`.
    pub url: String,
    /// Auth payload to send as the FIRST WebSocket message
    /// (`<user>:<ticket>\n`). Must be a binary frame; the trailing
    /// newline is required by the Proxmox protocol.
    pub auth: String,
}

// Hand-written Debug so the ticket can NEVER reach a log via `{:?}` — both
// fields carry the credential (url has `?…&vncticket=…`, auth is
// `user:ticket`). Redaction is thus a property of the type, not just the
// three hand-patched log sites in `mod.rs`.
impl std::fmt::Debug for WsTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsTarget")
            .field("url", &redact_ticket(&self.url))
            .field("auth", &"<user>:[REDACTED]")
            .finish()
    }
}

/// Build the WebSocket target from the REST base URL + termproxy reply.
///
/// `api_base_url` is the same URL the REST client uses (e.g.
/// `"https://pve1.lan:8006"`). We swap the scheme to `wss` and append
/// the canonical websocket path with URL-encoded ticket.
#[must_use]
pub fn build_ws_target(
    api_base_url: &str,
    node: &str,
    vmid: u32,
    guest_type: GuestType,
    port: u32,
    ticket: &str,
    user: &str,
) -> WsTarget {
    let kind = match guest_type {
        GuestType::Qemu => "qemu",
        GuestType::Lxc => "lxc",
    };
    // Strip the scheme + path from the REST base, keep host:port.
    let host_port = api_base_url
        .split_once("://")
        .map_or(api_base_url, |(_, rest)| rest)
        .split_once('/')
        .map_or(
            api_base_url
                .split_once("://")
                .map_or(api_base_url, |(_, rest)| rest),
            |(h, _)| h,
        );
    let url = format!(
        "wss://{host_port}/api2/json/nodes/{node}/{kind}/{vmid}/vncwebsocket?port={port}&vncticket={ticket_enc}",
        ticket_enc = urlencode(ticket),
    );
    let auth = format!("{user}:{ticket}\n");
    WsTarget { url, auth }
}

/// Redact the `vncticket` value from a WS URL before it reaches a log line or
/// an error message. The ticket is a short-lived credential; in cleartext logs
/// it lets anyone who can read the log (or a shipped log) hijack the console
/// session within the ticket's TTL. Everything else — host, path, port — is
/// preserved so the log stays diagnostically useful.
#[must_use]
pub fn redact_ticket(url: &str) -> String {
    const KEY: &str = "vncticket=";
    // Case-insensitive search: a URL is ASCII, so `to_ascii_lowercase` keeps
    // byte offsets aligned with the original — a future builder emitting a
    // differently-cased param can't silently defeat redaction.
    let lower = url.to_ascii_lowercase();
    match lower.find(KEY) {
        Some(i) => {
            let val_start = i + KEY.len();
            let val_end = url[val_start..]
                .find('&')
                .map_or(url.len(), |off| val_start + off);
            format!("{}[REDACTED]{}", &url[..val_start], &url[val_end..])
        }
        None => url.to_string(),
    }
}

/// Minimal URL-encode for the ticket query parameter. PVE tickets
/// contain `:` `=` and base64 `/+`, all of which need encoding when
/// they appear in a query value. We encode anything outside the
/// unreserved set per RFC 3986.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_qemu_url_with_encoded_ticket() {
        let t = build_ws_target(
            "https://pve1.lan:8006",
            "pve1",
            100,
            GuestType::Qemu,
            5900,
            "PVE:user@pam:abc/def+xyz",
            "user@pam",
        );
        assert!(t
            .url
            .starts_with("wss://pve1.lan:8006/api2/json/nodes/pve1/qemu/100/vncwebsocket?"));
        assert!(t.url.contains("port=5900"));
        // `:` and `+` and `/` MUST be %-encoded in the query.
        assert!(t
            .url
            .contains("vncticket=PVE%3Auser%40pam%3Aabc%2Fdef%2Bxyz"));
        assert_eq!(t.auth, "user@pam:PVE:user@pam:abc/def+xyz\n");
    }

    #[test]
    fn builds_lxc_url_with_lxc_path() {
        let t = build_ws_target(
            "https://pve.local:8006",
            "pve1",
            200,
            GuestType::Lxc,
            5901,
            "T",
            "u",
        );
        assert!(t.url.contains("/lxc/200/vncwebsocket"));
        assert!(!t.url.contains("/qemu/"));
    }

    #[test]
    fn handles_base_url_with_trailing_path() {
        // Some users store URLs with a path component — we must keep
        // host:port only, not append the trailing path.
        let t = build_ws_target(
            "https://pve.local:8006/api2/json",
            "pve1",
            100,
            GuestType::Qemu,
            5900,
            "x",
            "u",
        );
        assert!(t.url.contains("//pve.local:8006/"));
        assert!(t
            .url
            .contains("/api2/json/nodes/pve1/qemu/100/vncwebsocket"));
    }

    #[test]
    fn redact_ticket_hides_the_credential_keeps_the_rest() {
        let t = build_ws_target(
            "https://pve1.lan:8006",
            "pve1",
            100,
            GuestType::Qemu,
            5900,
            "PVE:user@pam:abc/def+xyz",
            "user@pam",
        );
        let red = redact_ticket(&t.url);
        // The ticket value is gone…
        assert!(red.contains("vncticket=[REDACTED]"), "got: {red}");
        assert!(!red.contains("abc"), "ticket residue leaked: {red}");
        assert!(!red.contains("%2F"), "encoded ticket residue leaked: {red}");
        // …but the diagnostically-useful parts survive.
        assert!(red.contains("port=5900"));
        assert!(red.contains("/qemu/100/vncwebsocket"));
        // A URL without a ticket passes through unchanged.
        assert_eq!(redact_ticket("wss://x/y?port=1"), "wss://x/y?port=1");
        // Case-insensitive: a differently-cased param is still redacted.
        assert_eq!(
            redact_ticket("wss://x/y?port=1&VNCTICKET=secretvalue"),
            "wss://x/y?port=1&VNCTICKET=[REDACTED]"
        );
        // A trailing param after the ticket is preserved (value-run stops at &).
        assert_eq!(
            redact_ticket("wss://x?vncticket=abc&extra=1"),
            "wss://x?vncticket=[REDACTED]&extra=1"
        );
    }

    #[test]
    fn wstarget_debug_never_leaks_the_ticket() {
        let t = build_ws_target(
            "https://x:8006",
            "n",
            1,
            GuestType::Qemu,
            5900,
            "SUPER-SECRET-TICKET",
            "alice@pve",
        );
        let dbg = format!("{t:?}");
        assert!(
            !dbg.contains("SUPER-SECRET-TICKET"),
            "ticket leaked in Debug: {dbg}"
        );
        assert!(dbg.contains("vncticket=[REDACTED]"));
        assert!(dbg.contains("[REDACTED]")); // auth field redacted too
    }

    #[test]
    fn auth_frame_is_user_colon_ticket_with_newline() {
        let t = build_ws_target(
            "https://x:8006",
            "n",
            1,
            GuestType::Qemu,
            1,
            "tkt",
            "alice@pve",
        );
        // Trailing \n is required by the termproxy handshake.
        assert!(t.auth.ends_with('\n'));
        assert_eq!(t.auth.trim_end(), "alice@pve:tkt");
    }
}
