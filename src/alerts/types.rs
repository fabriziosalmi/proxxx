//! Alert types (feature #8).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    /// Parse a string severity tolerantly. Default fallback: Warning.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "info" | "informational" => Self::Info,
            "critical" | "crit" | "fatal" => Self::Critical,
            _ => Self::Warning,
        }
    }

    /// Emoji prefix for the human-facing message body.
    #[must_use]
    pub const fn icon(self) -> &'static str {
        match self {
            Self::Info => "ℹ️",
            Self::Warning => "⚠️",
            Self::Critical => "🚨",
        }
    }
}

/// One alert event produced by the engine. Doesn't know about channels —
/// the notifier renders this into per-channel formats.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertEvent {
    pub rule: String,
    pub severity: Severity,
    /// Stable identifier of the affected target (e.g. `"node:pve1"`,
    /// `"storage:local-lvm"`, `"replication:100-0"`). Used for dedup.
    pub target: String,
    /// Human-readable summary, ~one line.
    pub summary: String,
    /// Optional structured details for renderers that want more (the
    /// webhook channel ships these as JSON).
    #[serde(default)]
    pub detail: serde_json::Value,
    /// Wall-clock timestamp of detection (Unix seconds).
    pub at: u64,
}

impl AlertEvent {
    /// Compose the canonical text used by Telegram/ntfy.
    #[must_use]
    pub fn render_text(&self) -> String {
        format!(
            "{} [{}] {} — {}",
            self.severity.icon(),
            self.rule,
            self.target,
            self.summary
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_parse_handles_synonyms_and_default() {
        assert_eq!(Severity::parse("INFO"), Severity::Info);
        assert_eq!(Severity::parse("warning"), Severity::Warning);
        assert_eq!(Severity::parse("crit"), Severity::Critical);
        assert_eq!(Severity::parse("fatal"), Severity::Critical);
        assert_eq!(Severity::parse("garbage"), Severity::Warning);
    }

    #[test]
    fn render_text_includes_all_pieces() {
        let e = AlertEvent {
            rule: "node_offline".into(),
            severity: Severity::Critical,
            target: "node:pve1".into(),
            summary: "offline 75s".into(),
            detail: serde_json::Value::Null,
            at: 0,
        };
        let s = e.render_text();
        assert!(s.contains("node_offline"));
        assert!(s.contains("node:pve1"));
        assert!(s.contains("offline 75s"));
        assert!(s.starts_with("🚨"));
    }
}
