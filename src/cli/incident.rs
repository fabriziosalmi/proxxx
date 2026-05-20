//! `proxxx incident {freeze, thaw, status}` — cluster-wide write
//! kill-switch.
//!
//! Thin CLI wrapper over [`crate::incident`]. Every subcommand
//! audit-logs the operation under the `incident.*` action prefix
//! so the freeze trail survives even after the lock is gone.

use anyhow::Result;
use clap::Subcommand;
use serde_json::Value;

use crate::incident;

#[derive(Debug, Subcommand)]
pub enum IncidentCommand {
    /// Freeze the cluster — every mutation entry point refuses
    /// until you `thaw` (or the TTL expires).
    ///
    /// Reads keep working: investigators need observation. The lock
    /// is local to this machine — for multi-operator coordination
    /// during an incident, distribute the lock file via your usual
    /// secret-sync (Ansible, Salt, manual `scp`).
    ///
    /// Examples:
    ///   proxxx incident freeze --reason 'pveuser-bot token leaked'
    ///   proxxx incident freeze --reason 'SIEM alert NXLog-42' --ttl 4h
    Freeze {
        /// Required free-form text. Surfaced in every refusal and
        /// in the audit log; future-you / teammates need to know why.
        #[arg(long)]
        reason: String,

        /// Auto-thaw after this duration. Accepts `30s`, `5m`, `2h`,
        /// `1d`. Omit for "until explicitly thawed". A forgotten
        /// freeze with no TTL is the operational nightmare we're
        /// trying to avoid — pass a TTL when in doubt.
        #[arg(long)]
        ttl: Option<String>,
    },

    /// Lift the freeze. Idempotent — thawing when nothing is frozen
    /// is a no-op (returns `null`).
    Thaw {
        /// Free-form text recording why the freeze is being lifted.
        /// Audit-logged.
        #[arg(long)]
        reason: String,
    },

    /// Report the current freeze status (active / inactive +
    /// metadata). Exits 0 either way — use `--format json` and
    /// match on `active` for scripting.
    Status,
}

pub fn execute_incident(action: IncidentCommand) -> Result<(Value, i32)> {
    match action {
        IncidentCommand::Freeze { reason, ttl } => {
            let ttl_secs = match ttl.as_deref() {
                Some(s) => Some(parse_duration_secs(s)?),
                None => None,
            };
            let state = incident::freeze(&reason, ttl_secs)?;
            audit_event("incident.freeze", &reason, &state);
            Ok((serde_json::to_value(&state)?, 0))
        }
        IncidentCommand::Thaw { reason } => {
            let prior = incident::thaw()?;
            audit_thaw(&reason, prior.as_ref());
            let payload = serde_json::json!({
                "thawed": prior.is_some(),
                "reason": reason,
                "prior_state": prior,
            });
            Ok((payload, 0))
        }
        IncidentCommand::Status => {
            let state = incident::current_state()?;
            let payload = serde_json::json!({
                "active": state.is_some(),
                "state": state,
            });
            Ok((payload, 0))
        }
    }
}

/// Append an audit-log entry for a freeze / thaw event. Failures
/// are downgraded to a warning — we don't want auditing to be the
/// reason an incident-response command fails.
fn audit_event(action: &str, reason: &str, state: &incident::FreezeState) {
    let params = serde_json::to_string(&serde_json::json!({
        "reason": reason,
        "operator": state.operator,
        "ttl_secs": state.ttl_secs,
    }))
    .unwrap_or_default();
    if let Err(e) = with_logger(|l| l.log(action, &state.operator, None, None, Some(&params), "OK"))
    {
        tracing::warn!("incident: audit log failure (continuing anyway): {e:#}");
    }
}

fn audit_thaw(reason: &str, prior: Option<&incident::FreezeState>) {
    let operator = prior
        .map(|s| s.operator.clone())
        .unwrap_or_else(default_operator);
    let params = serde_json::to_string(&serde_json::json!({
        "reason": reason,
        "prior_reason": prior.map(|s| s.reason.as_str()),
    }))
    .unwrap_or_default();
    if let Err(e) =
        with_logger(|l| l.log("incident.thaw", &operator, None, None, Some(&params), "OK"))
    {
        tracing::warn!("incident: audit log failure (continuing anyway): {e:#}");
    }
}

fn default_operator() -> String {
    let user = std::env::var("USER").unwrap_or_else(|_| "unknown".into());
    format!("{user}@unknown")
}

/// Open the audit logger, call `f`, then drop it. Encapsulates the
/// open/close boilerplate so the two audit hooks stay tidy.
fn with_logger<F, R>(f: F) -> Result<R>
where
    F: FnOnce(&mut crate::audit::AuditLogger) -> Result<R>,
{
    let mut logger = crate::audit::AuditLogger::open()?;
    f(&mut logger)
}

/// Parse `30s`, `5m`, `2h`, `1d` into seconds. Hand-rolled; the
/// codebase already avoids the `humantime` dep.
fn parse_duration_secs(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty duration");
    }
    let (num_str, suffix) = s.split_at(s.len() - 1);
    // If the last char wasn't a recognised suffix, treat the whole
    // thing as bare seconds.
    let (n_str, mult): (&str, u64) = match suffix {
        "s" => (num_str, 1),
        "m" => (num_str, 60),
        "h" => (num_str, 3600),
        "d" => (num_str, 86400),
        _ => (s, 1),
    };
    let n: u64 = n_str
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration `{s}` — try `30s`, `5m`, `2h`, `1d`"))?;
    Ok(n.saturating_mul(mult))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_supports_all_suffixes() {
        assert_eq!(parse_duration_secs("30s").unwrap(), 30);
        assert_eq!(parse_duration_secs("5m").unwrap(), 300);
        assert_eq!(parse_duration_secs("2h").unwrap(), 7200);
        assert_eq!(parse_duration_secs("1d").unwrap(), 86400);
        // Bare number = seconds.
        assert_eq!(parse_duration_secs("42").unwrap(), 42);
    }

    #[test]
    fn parse_duration_rejects_garbage() {
        assert!(parse_duration_secs("").is_err());
        assert!(parse_duration_secs("forever").is_err());
        assert!(parse_duration_secs("foo-bar").is_err());
    }
}
