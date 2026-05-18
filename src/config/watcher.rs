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
            match crate::config::load_config(profile.as_deref()) {
                Ok(new_cfg) => {
                    *handle.write().await = new_cfg;
                    tracing::info!("config watcher: reload OK");
                }
                Err(e) => {
                    tracing::warn!("config watcher: reload failed, keeping current config: {e:#}");
                }
            }
        }
    });
}

#[cfg(not(unix))]
pub fn spawn_reload_on_sighup(_handle: ConfigHandle, _profile: Option<String>) {}
