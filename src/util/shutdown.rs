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
//!
//! #366 — one process-wide shutdown state. Each call used to install its
//! own signal streams, and a tokio signal stream only sees signals that
//! arrive after it is created. Once the first stream existed, the default
//! "terminate" action was gone for the life of the process, so a SIGTERM
//! or Ctrl-C that arrived while no stream was alive (a loop processing a
//! tick, sleeping inside a `select!` arm, or between two iterations) was
//! dropped, and `systemctl stop` waited for SIGKILL. Now a single listener
//! task, started on first use, flips a `watch` flag that stays set: every
//! waiter, including one created after the signal, sees it.

use std::sync::OnceLock;
use tokio::sync::watch;

static SHUTDOWN: OnceLock<watch::Sender<bool>> = OnceLock::new();
static LISTENER: std::sync::Once = std::sync::Once::new();

/// The process-wide flag (`true` once a shutdown is requested).
fn shutdown_flag() -> &'static watch::Sender<bool> {
    SHUTDOWN.get_or_init(|| watch::channel(false).0)
}

#[cfg(unix)]
fn install_listener() {
    use tokio::signal::unix::{signal, SignalKind};

    // Streams are created here, synchronously, so the handlers are in place
    // before the first waiter returns to its caller.
    let term = signal(SignalKind::terminate())
        .map_err(|e| tracing::warn!("could not install SIGTERM handler: {e}"))
        .ok();
    let int = signal(SignalKind::interrupt())
        .map_err(|e| tracing::warn!("could not install SIGINT handler: {e}"))
        .ok();
    tokio::spawn(async move {
        let which = match (term, int) {
            (Some(mut term), Some(mut int)) => tokio::select! {
                _ = term.recv() => "SIGTERM",
                _ = int.recv() => "SIGINT",
            },
            (Some(mut term), None) => {
                term.recv().await;
                "SIGTERM"
            }
            (None, Some(mut int)) => {
                int.recv().await;
                "SIGINT"
            }
            (None, None) => {
                let _ = tokio::signal::ctrl_c().await;
                "Ctrl+C"
            }
        };
        tracing::info!("received {which} — initiating graceful shutdown");
        request_shutdown();
    });
}

#[cfg(not(unix))]
fn install_listener() {
    tokio::spawn(async {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("received Ctrl+C — initiating graceful shutdown");
        request_shutdown();
    });
}

/// Resolve once a shutdown has been requested (SIGTERM, SIGINT, or
/// [`request_shutdown`]); immediately if it already was.
///
/// Cancel-safe and cheap to call again: a loop may create a new future on
/// every iteration without missing a signal that arrived in between.
/// The first call must run inside a tokio runtime (it starts the listener).
pub async fn wait_for_shutdown_signal() {
    LISTENER.call_once(install_listener);
    let mut rx = shutdown_flag().subscribe();
    // `wait_for` checks the current value first, so a flag set before this
    // call resolves at once.
    let _ = rx.wait_for(|requested| *requested).await;
}

/// Whether a shutdown has been requested. Does not start the listener.
#[must_use]
pub fn is_shutting_down() -> bool {
    *shutdown_flag().borrow()
}

/// Request a shutdown, as a signal would.
pub fn request_shutdown() {
    shutdown_flag().send_replace(true);
}

/// Sleep for `d`, or less if a shutdown is requested first. Returns `true`
/// when the full duration elapsed, `false` on shutdown.
pub async fn sleep_unless_shutdown(d: std::time::Duration) -> bool {
    tokio::select! {
        biased;
        () = wait_for_shutdown_signal() => false,
        () = tokio::time::sleep(d) => true,
    }
}
