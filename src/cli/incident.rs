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
    /// Freeze writes — every mutation entry point refuses until you
    /// `thaw` (or the TTL expires).
    ///
    /// Scope: without `--profile` this is the global (fleet-wide)
    /// kill-switch — it blocks mutations to *every* profile. With
    /// `--profile <name>` only that cluster is frozen; the rest stay
    /// writable. A client is refused if the global lock OR its own
    /// profile's lock is active.
    ///
    /// Reads keep working: investigators need observation. The lock
    /// is local to this machine — for multi-operator coordination
    /// during an incident, distribute the lock file via your usual
    /// secret-sync (Ansible, Salt, manual `scp`).
    ///
    /// Examples:
    ///   proxxx incident freeze --reason 'pveuser-bot token leaked'
    ///   proxxx incident freeze --reason 'SIEM alert NXLog-42' --ttl 4h
    ///   proxxx incident freeze --profile prod --reason 'rotating prod token'
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

        /// Freeze only this profile (cluster) instead of the whole
        /// fleet. Omit for the global kill-switch.
        #[arg(long)]
        profile: Option<String>,
    },

    /// Lift the freeze. Idempotent — thawing when nothing is frozen
    /// is a no-op (returns `null`).
    Thaw {
        /// Free-form text recording why the freeze is being lifted.
        /// Audit-logged.
        #[arg(long)]
        reason: String,

        /// Thaw only this profile's freeze. Must match the `--profile`
        /// used to freeze it; omit to lift the global freeze.
        #[arg(long)]
        profile: Option<String>,
    },

    /// Report the current freeze status — the global freeze plus any
    /// per-profile freezes, each with metadata. Exits 0 either way —
    /// use `--format json` and match on `active` for scripting.
    Status,
}

pub fn execute_incident(action: IncidentCommand) -> Result<(Value, i32)> {
    match action {
        IncidentCommand::Freeze {
            reason,
            ttl,
            profile,
        } => {
            let ttl_secs = match ttl.as_deref() {
                Some(s) => Some(parse_duration_secs(s)?),
                None => None,
            };
            let state = incident::freeze_for(profile.as_deref(), &reason, ttl_secs)?;
            audit_event("incident.freeze", &reason, &state);
            Ok((serde_json::to_value(&state)?, 0))
        }
        IncidentCommand::Thaw { reason, profile } => {
            let prior = incident::thaw_for(profile.as_deref())?;
            audit_thaw(&reason, profile.as_deref(), prior.as_ref());
            let payload = serde_json::json!({
                "thawed": prior.is_some(),
                "reason": reason,
                "profile": profile,
                "prior_state": prior,
            });
            Ok((payload, 0))
        }
        IncidentCommand::Status => {
            // `state` keeps its original meaning (the GLOBAL freeze, or null)
            // so existing `--format json` consumers stay valid — additive-only
            // per the SemVer contract. `freezes` is the new per-profile list.
            let all = incident::list_active_freezes()?;
            let global = all.iter().find(|s| s.profile.is_none()).cloned();
            let per_profile: Vec<_> = all.into_iter().filter(|s| s.profile.is_some()).collect();
            let payload = serde_json::json!({
                "active": global.is_some() || !per_profile.is_empty(),
                "state": global,
                "freezes": per_profile,
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
        "profile": state.profile,
    }))
    .unwrap_or_default();
    if let Err(e) = with_logger(|l| l.log(action, &state.operator, None, None, Some(&params), "OK"))
    {
        tracing::warn!("incident: audit log failure (continuing anyway): {e:#}");
    }
}

fn audit_thaw(reason: &str, profile: Option<&str>, prior: Option<&incident::FreezeState>) {
    let operator = prior
        .map(|s| s.operator.clone())
        .unwrap_or_else(default_operator);
    let params = serde_json::to_string(&serde_json::json!({
        "reason": reason,
        "profile": profile,
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
    // Match on the trailing CHAR, not a byte split. `split_at(len-1)`
    // panics when the last char is multi-byte (e.g. `5µ`); the suffix
    // units are all ASCII, so byte-slicing `len-1` is only safe inside
    // the matched branches. If the last char wasn't a recognised
    // suffix, treat the whole thing as bare seconds.
    let last = s.chars().next_back().unwrap_or('\0');
    let (n_str, mult): (&str, u64) = match last {
        's' => (&s[..s.len() - 1], 1),
        'm' => (&s[..s.len() - 1], 60),
        'h' => (&s[..s.len() - 1], 3600),
        'd' => (&s[..s.len() - 1], 86400),
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

    #[test]
    fn parse_duration_does_not_panic_on_multibyte_suffix() {
        // Regression: `split_at(len-1)` panicked when the trailing char
        // was multi-byte. These must return Err cleanly, never panic.
        assert!(parse_duration_secs("5µ").is_err());
        assert!(parse_duration_secs("10€").is_err());
        assert!(parse_duration_secs("3🔥").is_err());
        assert!(parse_duration_secs("ч").is_err());
    }
}
