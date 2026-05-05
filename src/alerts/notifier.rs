//! Per-channel alert delivery (feature #8).
//!
//! Three channels supported:
//! - `telegram` — reuses the existing `hitl::telegram` gateway. The
//!   chat id is taken from `[telegram]` block in profile config.
//! - `ntfy:<topic>` — POST to `https://ntfy.sh/<topic>` (free, no auth).
//! - `webhook:<url>` — POST application/json to the URL.
//!
//! Cuts dichiarati: no email/SMTP, no Gotify, no syslog. Every channel
//! we add brings a new dep + edge cases — we ship 3 working ones first.

use anyhow::{Context, Result};
use reqwest::Client;
use tracing::{info, warn};

use crate::alerts::types::AlertEvent;

/// One configured destination, parsed from a route string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Channel {
    /// Use the configured Telegram bot — chat id from profile config.
    Telegram,
    /// ntfy.sh topic. Topic name must be URL-safe; we don't validate.
    Ntfy { topic: String },
    /// Generic webhook receiving JSON.
    Webhook { url: String },
}

/// Parse a route string. Recognised forms:
/// - `"telegram"`
/// - `"ntfy:<topic>"`
/// - `"webhook:<url>"`
///
/// Anything else returns `None` — callers log a warning and skip it,
/// rather than failing the whole rule.
#[must_use]
pub fn parse_route(s: &str) -> Option<Channel> {
    let trimmed = s.trim();
    if trimmed.eq_ignore_ascii_case("telegram") {
        return Some(Channel::Telegram);
    }
    if let Some(topic) = trimmed.strip_prefix("ntfy:") {
        if topic.is_empty() {
            return None;
        }
        return Some(Channel::Ntfy {
            topic: topic.to_string(),
        });
    }
    if let Some(url) = trimmed.strip_prefix("webhook:") {
        if url.is_empty() || !url.starts_with("http") {
            return None;
        }
        return Some(Channel::Webhook {
            url: url.to_string(),
        });
    }
    None
}

/// Send an event over a channel. `tg` is optional — if the route is
/// Telegram and `tg` is None, we log + skip rather than fail.
pub async fn send_event(
    channel: &Channel,
    event: &AlertEvent,
    http: &Client,
    tg: Option<&crate::hitl::telegram::TelegramGateway>,
) -> Result<()> {
    match channel {
        Channel::Telegram => {
            let Some(t) = tg else {
                warn!("alert routed to Telegram but [telegram] not configured — skipping");
                return Ok(());
            };
            t.send_message(&event.render_text()).await?;
            info!("alert {} routed to Telegram", event.rule);
            Ok(())
        }
        Channel::Ntfy { topic } => {
            let url = format!("https://ntfy.sh/{topic}");
            let title = format!("{} {}", event.severity.icon(), event.rule);
            let resp = http
                .post(&url)
                .header("Title", title)
                .header("Priority", priority_for(event))
                .header("Tags", tags_for(event))
                .body(event.render_text())
                .send()
                .await
                .context("ntfy POST failed")?;
            if !resp.status().is_success() {
                anyhow::bail!("ntfy returned {}", resp.status());
            }
            info!("alert {} routed to ntfy:{topic}", event.rule);
            Ok(())
        }
        Channel::Webhook { url } => {
            let body = serde_json::json!({
                "rule": event.rule,
                "severity": event.severity,
                "target": event.target,
                "summary": event.summary,
                "detail": event.detail,
                "at": event.at,
            });
            let resp = http
                .post(url)
                .json(&body)
                .send()
                .await
                .with_context(|| format!("webhook POST {url}"))?;
            if !resp.status().is_success() {
                anyhow::bail!("webhook {url} returned {}", resp.status());
            }
            info!("alert {} routed to webhook {url}", event.rule);
            Ok(())
        }
    }
}

const fn priority_for(e: &AlertEvent) -> &'static str {
    // ntfy "Priority" header: 1 (min) … 5 (max).
    match e.severity {
        crate::alerts::types::Severity::Info => "2",
        crate::alerts::types::Severity::Warning => "3",
        crate::alerts::types::Severity::Critical => "5",
    }
}

fn tags_for(e: &AlertEvent) -> String {
    // ntfy renders these as emojis when they match its known set.
    match e.severity {
        crate::alerts::types::Severity::Info => "information_source".to_string(),
        crate::alerts::types::Severity::Warning => "warning".to_string(),
        crate::alerts::types::Severity::Critical => "rotating_light,red_circle".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_telegram_case_insensitive() {
        assert_eq!(parse_route("telegram"), Some(Channel::Telegram));
        assert_eq!(parse_route("Telegram"), Some(Channel::Telegram));
        assert_eq!(parse_route("TELEGRAM"), Some(Channel::Telegram));
    }

    #[test]
    fn parse_ntfy_with_topic() {
        assert_eq!(
            parse_route("ntfy:proxxx-prod"),
            Some(Channel::Ntfy {
                topic: "proxxx-prod".into()
            })
        );
    }

    #[test]
    fn parse_ntfy_empty_topic_rejected() {
        assert!(parse_route("ntfy:").is_none());
    }

    #[test]
    fn parse_webhook_requires_http_prefix() {
        assert_eq!(
            parse_route("webhook:https://hooks.example/notify"),
            Some(Channel::Webhook {
                url: "https://hooks.example/notify".into()
            })
        );
        // Bare hostname rejected — too easy to trip on.
        assert!(parse_route("webhook:hooks.example").is_none());
        assert!(parse_route("webhook:").is_none());
    }

    #[test]
    fn parse_unknown_returns_none() {
        assert!(parse_route("email:ops@example.com").is_none());
        assert!(parse_route("gotify:abc").is_none());
        assert!(parse_route("garbage").is_none());
    }

    #[test]
    fn priority_scales_with_severity() {
        let make = |s| AlertEvent {
            rule: "x".into(),
            severity: s,
            target: "x".into(),
            summary: "x".into(),
            detail: serde_json::Value::Null,
            at: 0,
        };
        assert_eq!(
            priority_for(&make(crate::alerts::types::Severity::Info)),
            "2"
        );
        assert_eq!(
            priority_for(&make(crate::alerts::types::Severity::Warning)),
            "3"
        );
        assert_eq!(
            priority_for(&make(crate::alerts::types::Severity::Critical)),
            "5"
        );
    }
}
