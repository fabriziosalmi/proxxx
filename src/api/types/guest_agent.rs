use serde::{Deserialize, Serialize};

use super::deserialize_bool_from_int;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentExecResponse {
    pub pid: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentExecStatusResponse {
    /// Whether the command has finished. PVE serializes this as 0/1
    /// rather than a JSON bool.
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub exited: bool,
    /// Exit code reported by the command. Only meaningful once
    /// `exited == true`.
    pub exitcode: i32,
    /// Captured stdout (may be truncated — see `out_truncated`).
    #[serde(rename = "out-data")]
    pub out_data: String,
    /// Captured stderr (may be truncated — see `err_truncated`).
    #[serde(rename = "err-data")]
    pub err_data: String,
    /// True if PVE truncated stdout (default cap is ~16 KiB).
    #[serde(
        rename = "out-truncated",
        deserialize_with = "deserialize_bool_from_int"
    )]
    pub out_truncated: bool,
    /// True if PVE truncated stderr.
    #[serde(
        rename = "err-truncated",
        deserialize_with = "deserialize_bool_from_int"
    )]
    pub err_truncated: bool,
    /// Signal that terminated the command, if any (POSIX signal number).
    pub signal: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GuestExecResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Result of `GET /nodes/{n}/qemu/{vmid}/agent/file-read?file=…`. PVE
/// caps file size at the QGA buffer (default ~16 KiB) and sets
/// `truncated=1` when the file was bigger — surfaced here so callers
/// can warn the operator instead of silently using a partial read.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuestAgentFileContent {
    pub content: String,
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub truncated: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuestAgentIpAddress {
    /// `"ipv4"` | `"ipv6"`. Some QGA versions also report `"ipv4-link-local"`.
    #[serde(rename = "ip-address-type")]
    pub ip_address_type: String,
    #[serde(rename = "ip-address")]
    pub ip_address: String,
    /// CIDR prefix length. 32 for IPv4 host routes, 128 for IPv6 host.
    pub prefix: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GuestAgentNetworkInterface {
    pub name: String,
    /// MAC address (kebab-case on the wire).
    #[serde(rename = "hardware-address")]
    pub hardware_address: String,
    /// Each interface can have multiple IPs (link-local + DHCP + static).
    #[serde(rename = "ip-addresses")]
    pub ip_addresses: Vec<GuestAgentIpAddress>,
}
