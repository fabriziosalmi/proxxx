use serde::{Deserialize, Serialize};

use super::deserialize_bool_from_int;

/// One notification endpoint from `GET /cluster/notifications/endpoints`.
/// Heterogeneous shape — fields vary by `endpoint_type`. The typed
/// fields below cover the shared subset; type-specific knobs (smtp's
/// `server`, gotify's `server`, webhook's `url`) round-trip via
/// raw flow on PVE update — operators pass them via `--raw KEY=VAL`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationEndpoint {
    pub name: String,
    /// `sendmail` | `smtp` | `gotify` | `webhook`.
    #[serde(rename = "type")]
    pub endpoint_type: String,
    pub comment: String,
    /// `builtin` | `modified-builtin` | `user-created`. PVE-version-
    /// dependent — older clusters omit it.
    pub origin: String,
    /// 1 = disabled (kept for re-enable, not deleted).
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub disable: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationMatcher {
    pub name: String,
    pub comment: String,
    pub origin: String,
    /// CSV of endpoint/group names to deliver matching events to.
    pub target: Vec<String>,
    /// Per-field match patterns, e.g. `type=vzdump,hostname=pve1`.
    #[serde(rename = "match-field", default)]
    pub match_field: Vec<String>,
    /// Severity filters, e.g. `error,warning`.
    #[serde(rename = "match-severity", default)]
    pub match_severity: Vec<String>,
    /// `all` | `any` — how multi-clause matchers combine.
    #[serde(rename = "mode", default)]
    pub mode: String,
    /// 1 = invert the match decision.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub invert_match: bool,
    /// 1 = disabled.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub disable: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationTarget {
    pub name: String,
    /// `sendmail` | `smtp` | `gotify` | `webhook` | `group`.
    #[serde(rename = "type")]
    pub target_type: String,
    pub comment: String,
    pub origin: String,
}
