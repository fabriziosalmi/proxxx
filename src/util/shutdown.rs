//! (macro audit) — graceful shutdown signal handling.
//!
//! Long-running daemons (`proxxx alerts watch`, `proxxx hitl serve`)
//! may run for months under systemd or launchd. When the system
//! reboots, the supervisor sends SIGTERM and waits up to 90 s before
//! escalating to SIGKILL. Without an explicit listener we'd be in
//! the SIGKILL bucket — no `SQLite` WAL flush, no SSH pool close, no
//! audit log final entry.
//!
//! `wait_for_shutdown_signal` resolves on either SIGINT (Ctrl+C) or
//! SIGTERM (systemd, kill, launchd). Callers `tokio::select!` it
//! against their main work loop and can then run cleanup before
//! returning from `main`.
//!
//! On Windows there is no SIGTERM; we fall back to Ctrl+C only via
//! `tokio::signal::ctrl_c()`. The proxxx daemons are documented as
//! Linux/macOS-targeted, so this is a safe degradation.

#[cfg(unix)]
pub async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    // Construct both streams up-front; if either fails to install
    // (e.g. inside a very locked-down sandbox), fall back to ctrl_c
    // alone — better one signal than none.
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("could not install SIGTERM handler: {e}; ctrl_c only");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    let mut int = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("could not install SIGINT handler: {e}; SIGTERM only");
            let _ = term.recv().await;
            return;
        }
    };
    tokio::select! {
        _ = term.recv() => {
            tracing::info!("received SIGTERM — initiating graceful shutdown");
        }
        _ = int.recv() => {
            tracing::info!("received SIGINT — initiating graceful shutdown");
        }
    }
}

#[cfg(not(unix))]
pub async fn wait_for_shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("received Ctrl+C — initiating graceful shutdown");
}
