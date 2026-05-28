use serde::{Deserialize, Serialize};

use super::deserialize_bool_from_int;

/// One row of `GET /cluster/acme/account`. Just the account `name`
/// (operator-chosen) — full registration details require the per-name
/// GET (returns `AcmeAccountDetails`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmeAccount {
    pub name: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmeAccountDetails {
    pub account: serde_json::Value,
    pub tos: String,
    pub directory: String,
    pub location: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmePlugin {
    /// Plugin id (operator-chosen name).
    pub plugin: String,
    /// `dns` | `standalone` (HTTP-01 default).
    #[serde(rename = "type")]
    pub plugin_type: String,
    /// DNS plugin name (e.g. `cloudflare`, `route53`, `gandi_livedns`).
    /// Empty for HTTP-01.
    pub api: String,
    /// DNS API credentials (encoded sub-spec, masked on read).
    pub data: String,
    /// Time the plugin gives DNS records to propagate before validating.
    pub validation_delay: u32,
    /// Disable without deleting.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub disable: bool,
    /// Comment / description.
    pub nodes: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AcmeDirectory {
    pub name: String,
    pub url: String,
}
