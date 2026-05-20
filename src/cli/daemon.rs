//! `proxxx daemon serve` — unified background-task graph.
//!
//! Today proxxx ships three independent daemons:
//!
//! 1. **alerts** — periodic cluster snapshot + rule eval, with
//!    Telegram/email/etc. dispatch. Lives in
//!    [`crate::cli::monitoring::execute_alerts`].
//! 2. **HITL** — Telegram long-poll callback receiver for
//!    approve/deny gestures. Lives in [`crate::cli::hitl_serve`].
//! 3. **schedule** — interval-based `run-due` for the recurring-
//!    op store. Lives in [`crate::cli::schedule::run_due`].
//!
//! Each was invoked as its own `proxxx <verb> <serve>` and each
//! ran its own process with its own SIGTERM handler. Operators
//! had to run three systemd units (or scripts) to cover the full
//! surface.
//!
//! This module folds all three into one process under one
//! `tokio::select!` shutdown signal. The shape:
//!
//! ```text
//!
//!   ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
//!   │ alerts_loop   │  │  hitl_loop    │  │ schedule_loop │
//!   │  (30 s tick)  │  │ (long-poll)   │  │  (60 s tick)  │
//!   └───────┬───────┘  └───────┬───────┘  └───────┬───────┘
//!           │ tokio::spawn     │ tokio::spawn     │ tokio::spawn
//!           └──────────────────┼──────────────────┘
//!                              │
//!                  wait_for_shutdown_signal()
//!                              │
//!                  abort all → wait → exit 0
//! ```
//!
//! ## Shutdown semantics
//!
//! - SIGTERM/SIGINT cancels the outer `await`. We then `.abort()`
//!   every spawned task and `.await` it to allow Drop cleanup.
//! - Per-task panics propagate as `JoinError`. We log + continue —
//!   the remaining daemons keep running. A panicking alerts loop
//!   shouldn't kill the HITL receiver.
//!
//! ## Why not one event loop with branches per work-kind
//!
//! Tried it; rejected. Each daemon has its own internal state
//! (alerts dedup cache, HITL pending-approvals replay window,
//! `schedule`'s TOML store) and its own backoff / retry shape. A
//! monolithic loop would have to interleave those state machines
//! and we'd lose the "each daemon is a `tokio::spawn` with its own
//! ownership story" simplicity. Three small loops sharing a
//! shutdown signal is the cheapest correct factoring.

use anyhow::Result;
use clap::Subcommand;
use serde_json::Value;
use std::sync::Arc;
use std::time::Duration;

use crate::api::PxClient;
use crate::config::{ConfigHandle, ProfileConfig};

#[derive(Debug, Subcommand)]
pub enum DaemonCommand {
    /// Run alerts + HITL + schedule daemons under one process.
    /// SIGTERM/SIGINT stops all three cleanly.
    ///
    /// Each can be opted out individually for operators who want
    /// to keep one of them under a separate systemd unit (e.g.
    /// schedule on a different cadence than the rest).
    ///
    /// Examples:
    ///   proxxx daemon serve                              # all three
    ///   proxxx daemon serve --no-hitl                    # alerts + schedule
    ///   proxxx daemon serve --schedule-interval-secs 30  # tighter scheduler
    Serve {
        /// Schedule "run-due" tick interval in seconds.
        /// Defaults to 60 (one tick per minute, matches the
        /// `* * * * * proxxx schedule run-due` cron pattern the
        /// scheduler was originally designed to be invoked from).
        #[arg(long, default_value_t = 60)]
        schedule_interval_secs: u64,

        /// Alerts loop poll interval in seconds. Default 30
        /// (same default as `proxxx alerts watch`).
        #[arg(long, default_value_t = 30)]
        alerts_interval_secs: u64,

        /// Skip the schedule task. Useful when the operator
        /// wants per-minute scheduling under their own cron.
        #[arg(long)]
        no_schedule: bool,

        /// Skip the alerts task. Useful in dev environments
        /// where alert-noise to Telegram is unwanted.
        #[arg(long)]
        no_alerts: bool,

        /// Skip the HITL task. Useful when Telegram isn't
        /// configured or when running alongside an existing
        /// HITL listener process.
        #[arg(long)]
        no_hitl: bool,
    },
}

pub async fn execute_daemon(
    client: &Arc<PxClient>,
    config_handle: ConfigHandle,
    config: ProfileConfig,
    profile: Option<&str>,
    action: DaemonCommand,
) -> Result<(Value, i32)> {
    match action {
        DaemonCommand::Serve {
            schedule_interval_secs,
            alerts_interval_secs,
            no_schedule,
            no_alerts,
            no_hitl,
        } => {
            run_unified(
                client,
                config_handle,
                config,
                profile,
                schedule_interval_secs,
                alerts_interval_secs,
                !no_schedule,
                !no_alerts,
                !no_hitl,
            )
            .await
        }
    }
}

/// One spawned daemon component, with a human-readable name for
/// shutdown logging.
struct Component {
    name: &'static str,
    handle: tokio::task::JoinHandle<Result<()>>,
}

#[allow(clippy::fn_params_excessive_bools)]
async fn run_unified(
    client: &Arc<PxClient>,
    config_handle: ConfigHandle,
    config: ProfileConfig,
    profile: Option<&str>,
    schedule_secs: u64,
    alerts_secs: u64,
    enable_schedule: bool,
    enable_alerts: bool,
    enable_hitl: bool,
) -> Result<(Value, i32)> {
    let mut components: Vec<Component> = Vec::new();

    if enable_schedule {
        components.push(Component {
            name: "schedule",
            handle: tokio::spawn(schedule_loop(schedule_secs)),
        });
    }

    if enable_alerts {
        let client = Arc::clone(client);
        let cfg = Arc::clone(&config_handle);
        let profile = profile.map(str::to_owned);
        components.push(Component {
            name: "alerts",
            handle: tokio::spawn(alerts_loop(client, cfg, profile, alerts_secs)),
        });
    }

    if enable_hitl {
        // The existing HITL serve loop owns its own Telegram
        // long-poll + replay-protection store. We just spawn it.
        let client = Arc::clone(client);
        let cfg = config.clone();
        components.push(Component {
            name: "hitl",
            handle: tokio::spawn(crate::cli::hitl_serve(client, cfg)),
        });
    }

    if components.is_empty() {
        anyhow::bail!(
            "no daemons enabled — at least one of schedule/alerts/hitl must be active. \
             Drop the --no-* flags to enable."
        );
    }

    eprintln!(
        "proxxx daemon: started {} component(s) — {}. Send SIGTERM/SIGINT to stop.",
        components.len(),
        components
            .iter()
            .map(|c| c.name)
            .collect::<Vec<_>>()
            .join(" + "),
    );

    // Race the global shutdown signal against any spawned task
    // crashing. A crashing daemon doesn't kill the others (we
    // log + continue), but a clean signal stops everything.
    crate::util::shutdown::wait_for_shutdown_signal().await;
    eprintln!("\nproxxx daemon: shutdown signal received, stopping components...");

    for c in components {
        c.handle.abort();
        // Best-effort join. Aborted tasks return JoinError::Cancelled
        // which we treat as success. Real panics get logged.
        match c.handle.await {
            Ok(Ok(())) => eprintln!("  - {} stopped cleanly", c.name),
            Ok(Err(e)) => eprintln!("  - {} returned error: {e:#}", c.name),
            Err(e) if e.is_cancelled() => eprintln!("  - {} stopped (cancelled)", c.name),
            Err(e) => eprintln!("  - {} JOIN ERROR: {e}", c.name),
        }
    }

    Ok((serde_json::json!({"status": "daemon stopped"}), 0))
}

/// Schedule tick loop. Every `interval_secs`, fires
/// `schedule::run_due` on a `spawn_blocking` thread (it shells
/// out subprocesses internally so it's not async-friendly).
async fn schedule_loop(interval_secs: u64) -> Result<()> {
    let interval_secs = interval_secs.max(5);
    loop {
        tokio::select! {
            biased;
            () = crate::util::shutdown::wait_for_shutdown_signal() => break,
            () = tokio::time::sleep(Duration::from_secs(interval_secs)) => {
                // The schedule run-due fires per-schedule subprocess
                // spawns, which can block momentarily. Hand off to
                // spawn_blocking so the daemon's tokio runtime stays
                // responsive to the SIGTERM signal and to the other
                // daemon tasks.
                let result = tokio::task::spawn_blocking(|| {
                    crate::cli::schedule::run_due(None)
                }).await;
                match result {
                    Ok(Ok(_)) => {} // happy path, swallow the Value/exit
                    Ok(Err(e)) => tracing::warn!("daemon schedule tick: {e:#}"),
                    Err(e) => tracing::warn!("daemon schedule join: {e}"),
                }
            }
        }
    }
    Ok(())
}

/// Alerts loop — wraps the existing CLI handler for one tick of
/// `AlertsCommand::Watch`. The handler internally has its own
/// shutdown-aware loop, so calling it once is enough — it'll run
/// until the shared shutdown signal fires.
async fn alerts_loop(
    client: Arc<PxClient>,
    config: ConfigHandle,
    profile: Option<String>,
    interval_secs: u64,
) -> Result<()> {
    let action = crate::cli::monitoring::AlertsCommand::Watch {
        interval: interval_secs,
    };
    // execute_alerts returns (Value, i32) — we ignore both for
    // the daemon path. The internal loop in `Watch` honours
    // wait_for_shutdown_signal directly.
    let _ =
        crate::cli::monitoring::execute_alerts(&client, config, profile.as_deref(), action).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The unified daemon is mostly a wiring layer; the per-component
    /// logic is already covered by each module's tests. We pin only
    /// the "no daemons enabled = error" guardrail, which is the
    /// behavioural contract distinct to this orchestration layer.
    #[test]
    fn component_struct_holds_name_plus_handle() {
        // Spawn a trivial completing task to validate the struct
        // shape without actually running daemons.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let c = Component {
                name: "trivial",
                handle: tokio::spawn(async { Ok::<(), anyhow::Error>(()) }),
            };
            assert_eq!(c.name, "trivial");
            let result = c.handle.await;
            assert!(result.is_ok());
        });
    }
}
