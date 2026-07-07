use serde::{Deserialize, Serialize};

use super::deserialize_u32_from_str_or_num;

// These are console-handoff wire types: `Serialize`/`Deserialize` are
// load-bearing (parsed from PVE, and the ticket is emitted to the ws
// client by design — see ACCEPTED-RISKS AR-7). But the one-shot
// `ticket` and the SPICE `password` are live bearer credentials, so
// `Debug` is hand-written to redact them — a derived `{:?}` at any
// future log/error site would leak the exact `vncticket` class the
// SecretString work (and v0.13.1's WsTarget fix) set out to close.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpiceConfig {
    /// All key/value pairs from the spiceproxy response. Examples:
    ///   host, port, tls-port, password, ca, host-subject, proxy,
    ///   title, release-cursor, secure-attention, delete-this-file.
    /// Stored as strings because the .vv file is INI-style.
    #[serde(flatten)]
    pub keys: std::collections::HashMap<String, String>,
}

impl std::fmt::Debug for SpiceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Mask any credential-shaped key (password / ticket / secret);
        // show the rest verbatim so diagnostics (host, port, proxy…)
        // stay useful.
        let mut m = f.debug_map();
        for (k, v) in &self.keys {
            let lower = k.to_ascii_lowercase();
            if lower.contains("password") || lower.contains("ticket") || lower.contains("secret") {
                m.entry(k, &"[REDACTED]");
            } else {
                m.entry(k, v);
            }
        }
        m.finish()
    }
}

impl SpiceConfig {
    /// Render to `.vv` (virt-viewer `ConfigFile`) format. Output starts
    /// with `[virt-viewer]\n` followed by `key=value` lines, sorted by
    /// key for deterministic test snapshots. Missing-but-required keys
    /// are NOT injected — Proxmox always includes them.
    #[must_use]
    pub fn to_vv_file(&self) -> String {
        let mut keys: Vec<&String> = self.keys.keys().collect();
        keys.sort();
        let mut out = String::from("[virt-viewer]\n");
        for k in keys {
            if let Some(v) = self.keys.get(k) {
                // Sanitise: strip CR/LF from values to avoid breaking
                // the INI grammar. Proxmox-supplied values shouldn't
                // contain newlines but the `ca` PEM does — `.vv` accepts
                // multi-line values via `\n` ESCAPE, NOT raw newlines.
                let escaped = v.replace('\n', "\\n");
                out.push_str(&format!("{k}={escaped}\n"));
            }
        }
        out
    }

    /// Helper for tests + UI: extract the `host` key (always present).
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        self.keys.get("host").map(String::as_str)
    }
}

#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TermproxyTicket {
    /// Backend port the websocket should connect to (e.g. 5900).
    /// PVE returns this as a JSON string on 9.x; the tolerant
    /// deserializer accepts both string and numeric forms.
    #[serde(deserialize_with = "deserialize_u32_from_str_or_num")]
    pub port: u32,
    /// One-shot ticket — must be sent in the WS auth frame.
    pub ticket: String,
    /// User the ticket was issued to (echoed back so we know what to
    /// send in the auth frame).
    pub user: String,
    /// UPID of the spawned termproxy task on the node. Useful for
    /// observability — proxxx can poll it for liveness.
    #[serde(default)]
    pub upid: String,
}

// Hand-written Debug: redact the one-shot `ticket` (a live WS bearer
// credential) while keeping port/user/upid for diagnostics.
impl std::fmt::Debug for TermproxyTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TermproxyTicket")
            .field("port", &self.port)
            .field("ticket", &"[REDACTED]")
            .field("user", &self.user)
            .field("upid", &self.upid)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct VncTicket {
    /// Backend port the websocket should connect to (e.g. 5900).
    /// PVE 9 returns this as a JSON string; older versions used int.
    /// `deserialize_u32_from_str_or_num` accepts both transparently.
    #[serde(deserialize_with = "deserialize_u32_from_str_or_num")]
    pub port: u32,
    /// One-shot ticket — must be sent in the WS auth frame.
    pub ticket: String,
    /// User the ticket was issued to.
    pub user: String,
    /// UPID of the spawned vncproxy task on the node.
    #[serde(default)]
    pub upid: String,
    /// Server TLS certificate when `verify_tls=true` was negotiated.
    /// Empty when proxxx connected with `verify_tls=false`.
    #[serde(default)]
    pub cert: String,
}

// Hand-written Debug: redact the one-shot `ticket`. `cert` is a public
// server certificate, not a secret, so it stays visible.
impl std::fmt::Debug for VncTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VncTicket")
            .field("port", &self.port)
            .field("ticket", &"[REDACTED]")
            .field("user", &self.user)
            .field("upid", &self.upid)
            .field("cert", &self.cert)
            .finish()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AplTemplate {
    /// Template filename, e.g. `debian-12-standard_12.7-1_amd64.tar.zst`.
    pub template: String,
    /// `system` | `turnkeylinux` | `mailserver` | etc.
    pub section: String,
    /// `iso` | `vztmpl`.
    #[serde(rename = "type")]
    pub template_type: String,
    /// Where the template comes from (PVE | `TurnKey` | etc).
    pub source: String,
    pub headline: String,
    pub description: String,
    pub version: String,
    pub os: String,
    pub package: String,
    /// SHA-512 checksum (PVE 8+).
    pub sha512sum: String,
    /// Bytes — handy for "will this fit in /var/lib/vz" pre-checks.
    pub infopage: String,
    pub maintainer: String,
}
