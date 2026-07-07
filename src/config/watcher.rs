// Config hot-reload — SIGHUP-triggered atomic swap.
//
// Long-running daemons (alerts watch, mcp serve, mcp serve-http) hold a
// `ConfigHandle` instead of a plain `ProfileConfig`.  On SIGHUP they
// transparently pick up new `[[alerts]]` rules, `[[policies]]`, `[telegram]`
// structure, `mcp_token`, and `rate_limit` without restarting.
//
// Fields baked into `PxClient` at startup (`url`, `user`, `token_id`,
// `token_secret`) are NOT re-applied on reload — those require a full
// restart.  The same applies to Telegram bot credentials used by the HITL
// and alert daemons (credentials are resolved once at init time).

use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::ProfileConfig;

/// Shared live-config handle.  Clone-cheap (`Arc` inside).
pub type ConfigHandle = Arc<RwLock<ProfileConfig>>;

/// Wrap a freshly-loaded `ProfileConfig` in a `ConfigHandle`.
#[must_use]
pub fn new_handle(config: ProfileConfig) -> ConfigHandle {
    Arc::new(RwLock::new(config))
}

/// Perform one reload cycle: run `load`, and on success atomically swap
/// the handle's inner value; on failure keep the last-known-good config.
/// Returns `true` iff the swap happened.
///
/// Extracted from the SIGHUP loop so the swap/keep-last-known-good policy
/// is unit-testable without registering a signal handler or touching
/// disk — tests inject a `load` closure that returns `Ok`/`Err`. The
/// production loop passes `|| crate::config::load_config(profile)`.
///
/// This is the mitigation AR-1 leans on: a live `mcp_token` rotation via
/// SIGHUP takes effect here, and a reload that fails to parse must NOT
/// tear down the running daemon's authentication.
pub(crate) async fn reload_once<F>(handle: &ConfigHandle, load: F) -> bool
where
    F: FnOnce() -> anyhow::Result<ProfileConfig>,
{
    match load() {
        Ok(new_cfg) => {
            *handle.write().await = new_cfg;
            tracing::info!("config watcher: reload OK");
            true
        }
        Err(e) => {
            tracing::warn!("config watcher: reload failed, keeping current config: {e:#}");
            false
        }
    }
}

/// Spawn a background task that reloads the config on `SIGHUP`.
///
/// - On success: atomically replaces the inner value and emits `tracing::info`.
/// - On parse / IO error: keeps the old config and emits `tracing::warn` —
///   the daemon stays up with its last-known-good config.
///
/// The task runs until the process exits.  Dropping the returned handle does
/// NOT cancel the task; it is detached.
///
/// No-op on non-Unix platforms (no `SIGHUP` on Windows).
#[cfg(unix)]
pub fn spawn_reload_on_sighup(handle: ConfigHandle, profile: Option<String>) {
    tokio::spawn(async move {
        let mut sighup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("config watcher: cannot register SIGHUP handler: {e:#}");
                return;
            }
        };
        loop {
            sighup.recv().await;
            tracing::info!("config watcher: SIGHUP received — reloading config");
            reload_once(&handle, || crate::config::load_config(profile.as_deref())).await;
        }
    });
}

#[cfg(not(unix))]
pub fn spawn_reload_on_sighup(_handle: ConfigHandle, _profile: Option<String>) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_from(toml_src: &str) -> ProfileConfig {
        toml::from_str(toml_src).expect("test config parses")
    }

    // AR-1 dependency: a successful reload swaps the live values a running
    // daemon reads — mcp_token (auth), policies (HITL gate), rate_limit.
    #[tokio::test]
    async fn reload_swaps_mcp_token_policies_and_rate_limit() {
        let v1 = cfg_from(
            r#"
url = "https://pve:8006"
user = "root@pam"
mcp_token = "old-token"
rate_limit = 5
"#,
        );
        let handle = new_handle(v1);
        assert_eq!(handle.read().await.rate_limit, Some(5));
        assert!(handle.read().await.policies.is_none());

        let swapped = reload_once(&handle, || {
            Ok(cfg_from(
                r#"
url = "https://pve:8006"
user = "root@pam"
mcp_token = "new-token"
rate_limit = 20

[[policies]]
action = "delete"
target = "*"
channel = "telegram"
require = 1
"#,
            ))
        })
        .await;

        assert!(swapped, "a successful reload must return true");
        let live = handle.read().await;
        assert_eq!(
            live.mcp_token.as_ref().map(|s| s.as_str()),
            Some("new-token")
        );
        assert_eq!(live.rate_limit, Some(20));
        assert_eq!(
            live.policies.as_ref().map(Vec::len),
            Some(1),
            "the new [[policies]] must be live after reload"
        );
    }

    // A reload that fails to parse must keep the last-known-good config —
    // a bad edit + SIGHUP must never tear down a running daemon's auth.
    #[tokio::test]
    async fn failed_reload_keeps_last_known_good() {
        let handle = new_handle(cfg_from(
            r#"
url = "https://pve:8006"
user = "root@pam"
mcp_token = "keep-me"
"#,
        ));

        let swapped = reload_once(&handle, || anyhow::bail!("simulated parse error")).await;

        assert!(!swapped, "a failed reload must return false");
        assert_eq!(
            handle.read().await.mcp_token.as_ref().map(|s| s.as_str()),
            Some("keep-me"),
            "the last-known-good token must survive a failed reload"
        );
    }
}
