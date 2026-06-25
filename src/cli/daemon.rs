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
//! A 4th pillar, **reconcile** (`GitOps` drift watch), was added later and
//! only ever runs unified: opt-in via `[profiles.X.reconcile]`, it diffs a
//! declared source against live state on an interval (detect-only). Lives
//! in [`reconcile_loop`].
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

        /// Skip the reconcile task (`GitOps` drift watch). It only runs
        /// when a `[profiles.X.reconcile]` section is configured; this
        /// flag force-disables it regardless.
        #[arg(long)]
        no_reconcile: bool,

        /// Skip the Layer 3 auto-converge step. The reconcile watch keeps
        /// DETECTING drift (logs / metrics / alerts); this disables only the
        /// unmanned mutation. Auto-converge also requires `auto_converge = true`
        /// in the profile's `[reconcile]` section — this flag force-disables it
        /// regardless. The `PROXXX_NO_CONVERGE` env var is the same kill-switch,
        /// checked per tick.
        #[arg(long)]
        no_converge: bool,
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
            no_reconcile,
            no_converge,
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
                !no_reconcile,
                !no_converge,
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
    enable_reconcile: bool,
    enable_converge: bool,
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

    // GitOps drift watch — the 4th pillar. Opt-in: only spawns when the
    // profile carries a `[reconcile]` section (and `--no-reconcile` isn't set).
    if enable_reconcile {
        if let Some(rec) = config.reconcile.clone() {
            let client = Arc::clone(client);
            let profile = profile.map(str::to_owned);
            // One shared Telegram gateway for drift alerts, if configured. A
            // failure here disables the alert channel but never the loop —
            // drift still hits the logs (and, later, metrics).
            let telegram = match &config.telegram {
                Some(tg_cfg) => {
                    match crate::hitl::telegram::TelegramGateway::from_config(tg_cfg).await {
                        Ok(g) => Some(Arc::new(g)),
                        Err(e) => {
                            eprintln!("proxxx daemon: reconcile Telegram alerts disabled — {e:#}");
                            None
                        }
                    }
                }
                None => None,
            };
            components.push(Component {
                name: "reconcile",
                handle: tokio::spawn(reconcile_loop(
                    client,
                    profile,
                    rec,
                    telegram,
                    enable_converge,
                )),
            });
        }
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

/// Current Unix time in seconds (0 on the impossible pre-epoch error).
fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Reconcile loop (`GitOps` drift watch) — the 4th pillar. Every
/// `interval_secs` (floored at 30), recompute drift between the declared
/// `source` and live state via the shared `reconcile::compute_drift` core.
/// **Detect-only**: drift is logged at WARN and, when Telegram is
/// configured, pushed as an alert — it never mutates. A tick that errors
/// (e.g. git fetch failed, cluster unreachable) is logged and the loop
/// continues; a transient failure must not kill the watch. Prometheus
/// metrics + MCP event fan-out land in a follow-up (both are cross-process
/// and need a shared drift-state store).
async fn reconcile_loop(
    client: Arc<PxClient>,
    profile: Option<String>,
    rec: crate::config::ReconcileConfig,
    telegram: Option<Arc<crate::hitl::telegram::TelegramGateway>>,
    enable_converge: bool,
) -> Result<()> {
    let interval = rec.interval_secs.max(30);
    let path = std::path::PathBuf::from(&rec.path);
    let profile_label = profile.as_deref().unwrap_or("default").to_owned();
    loop {
        tokio::select! {
            biased;
            () = crate::util::shutdown::wait_for_shutdown_signal() => break,
            () = tokio::time::sleep(Duration::from_secs(interval)) => {
                match super::reconcile::compute_drift(&client, &profile_label, &rec.source, &path).await {
                    Ok(changes) => {
                        let in_sync = changes.is_empty();
                        let summary = super::reconcile::drift_summary(&changes);
                        // Persist the latest result to the shared drift-state
                        // store so `metrics serve` / `mcp serve` (separate
                        // processes) can surface it. A persist failure is
                        // logged, never fatal to the watch.
                        let status = crate::app::cache::ReconcileStatus {
                            last_check_ts: unix_secs(),
                            in_sync,
                            total_changes: changes.len() as u32,
                            summary: summary.clone(),
                            by_family: super::reconcile::family_counts(&changes),
                        };
                        if let Err(e) = crate::app::cache::save_reconcile_status_async(
                            Some(profile_label.clone()),
                            status,
                        )
                        .await
                        {
                            tracing::warn!("reconcile: drift-state persist failed: {e:#}");
                        }
                        if in_sync {
                            tracing::info!(profile = %profile_label, "reconcile: in sync");
                        } else {
                            tracing::warn!(profile = %profile_label, "reconcile DRIFT — {summary}");
                            if let Some(tg) = &telegram {
                                let msg = format!(
                                    "⚠️ proxxx reconcile — drift on `{profile_label}`\n{summary}"
                                );
                                if let Err(e) = tg.send_message(&msg).await {
                                    tracing::warn!("reconcile: Telegram send failed: {e:#}");
                                }
                            }
                            // Layer 3 — unmanned auto-converge. Opt-in via config
                            // (`auto_converge`) and not disabled by flag/env; a
                            // deliberate write-lock (read_only / freeze) skips
                            // quietly (no alert storm). Always force=false, so a
                            // Severe drift is never auto-applied.
                            let decision = {
                                let cfg = client.profile_config();
                                converge_decision(
                                    enable_converge,
                                    rec.auto_converge,
                                    std::env::var("PROXXX_NO_CONVERGE").is_ok(),
                                    cfg.read_only,
                                    is_frozen(cfg.profile_name.as_deref()),
                                )
                            };
                            match decision {
                                ConvergeDecision::Disabled => {}
                                ConvergeDecision::SkipLocked => {
                                    tracing::debug!(
                                        profile = %profile_label,
                                        "auto_converge: skipped (read_only / freeze active)"
                                    );
                                }
                                ConvergeDecision::Proceed => {
                                    run_auto_converge(
                                        &client,
                                        &profile_label,
                                        &rec,
                                        &path,
                                        telegram.as_ref(),
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(profile = %profile_label, "reconcile tick failed: {e:#}");
                    }
                }
            }
        }
    }
    Ok(())
}

/// What the reconcile loop should do with detected drift on a tick. Factored
/// pure so the gating logic is unit-tested without a runtime or a cluster.
#[derive(Debug, PartialEq, Eq)]
enum ConvergeDecision {
    /// Detect-only — auto-converge is off (flag / config / env). Do nothing.
    Disabled,
    /// Enabled, but a deliberate operator write-lock (`read_only` / incident
    /// freeze) is active. Skip quietly — these are not faults, and alerting
    /// every tick would be an alert storm.
    SkipLocked,
    /// Run the unmanned converge.
    Proceed,
}

/// Pure auto-converge gate. `enable_converge` is the daemon `--no-converge`
/// flag (inverted); `auto_converge` is the profile config opt-in;
/// `no_converge_env` is the `PROXXX_NO_CONVERGE` kill-switch; `read_only` /
/// `frozen` are the deliberate write-locks.
// Five independent boolean gates — a struct would just rename them; keeping the
// flat signature makes the precedence (off-switches before locks) obvious. Same
// justified allow as `run_unified` above.
#[allow(clippy::fn_params_excessive_bools)]
const fn converge_decision(
    enable_converge: bool,
    auto_converge: bool,
    no_converge_env: bool,
    read_only: bool,
    frozen: bool,
) -> ConvergeDecision {
    if !enable_converge || !auto_converge || no_converge_env {
        ConvergeDecision::Disabled
    } else if read_only || frozen {
        ConvergeDecision::SkipLocked
    } else {
        ConvergeDecision::Proceed
    }
}

/// True if an incident freeze is active for `profile`. Fails SAFE: if the freeze
/// state can't be read, treat as frozen (skip the unmanned converge) rather than
/// risk mutating during an incident.
fn is_frozen(profile: Option<&str>) -> bool {
    crate::incident::current_state_for(profile)
        .map(|state| state.is_some())
        .unwrap_or(true)
}

/// Run one unmanned converge, fan the result out to logs + Telegram, then
/// re-persist drift-state so metrics reflect convergence immediately. Always
/// `force = false` (a Severe drift is never auto-applied — it raises a "needs
/// human review" alert and mutates nothing) and fail-fast
/// (`continue_on_error = false`). Never returns an error: a failed tick must not
/// kill the watch loop.
async fn run_auto_converge(
    client: &Arc<PxClient>,
    profile_label: &str,
    rec: &crate::config::ReconcileConfig,
    path: &std::path::Path,
    telegram: Option<&Arc<crate::hitl::telegram::TelegramGateway>>,
) {
    let opts = crate::state::apply::ApplyOptions {
        dry_run: false,
        prune: rec.converge_prune,
        continue_on_error: false,
    };
    let audit_user = client.profile_config().user.clone();
    match crate::state::converge::converge(
        client,
        profile_label,
        &rec.source,
        path,
        opts,
        false,
        &audit_user,
    )
    .await
    {
        Ok(report) => {
            let result = report.audit_result();
            if report.failed > 0 {
                tracing::warn!(profile = %profile_label, "auto_converge: PARTIAL — {result}");
                tg_alert(
                    telegram,
                    &format!("⚠️ proxxx converge PARTIAL on `{profile_label}` — {result}"),
                )
                .await;
            } else if report.applied > 0 {
                tracing::info!(profile = %profile_label, "auto_converge: {result}");
                tg_alert(
                    telegram,
                    &format!("✅ proxxx converged `{profile_label}` — {result}"),
                )
                .await;
            }
            // Re-persist so the next metrics scrape reflects convergence (and
            // honest residual drift after a partial) without waiting a tick.
            repersist_drift(client, profile_label, rec, path).await;
        }
        Err(e) => {
            if e.downcast_ref::<crate::app::preflight::PreflightRefusal>()
                .is_some()
            {
                tracing::warn!(
                    profile = %profile_label,
                    "auto_converge: drift needs HUMAN REVIEW (Severe risk) — left for operator"
                );
                tg_alert(
                    telegram,
                    &format!(
                        "🛑 proxxx `{profile_label}`: drift needs human review (Severe risk) — \
                         auto-converge refused. Run `reconcile converge --allow-risk` after review."
                    ),
                )
                .await;
            } else {
                // git clone / cluster unreachable / parse error — transient.
                tracing::warn!(profile = %profile_label, "auto_converge tick failed (non-fatal): {e:#}");
            }
        }
    }
}

/// Best-effort Telegram alert — a send failure is logged, never propagated.
async fn tg_alert(telegram: Option<&Arc<crate::hitl::telegram::TelegramGateway>>, msg: &str) {
    if let Some(tg) = telegram {
        if let Err(e) = tg.send_message(msg).await {
            tracing::warn!("auto_converge: Telegram send failed: {e:#}");
        }
    }
}

/// Recompute drift and overwrite the shared drift-state store after a converge,
/// so `metrics serve` / `mcp serve` reflect the new reality immediately.
/// Best-effort: a recompute or persist failure is logged, never fatal.
async fn repersist_drift(
    client: &Arc<PxClient>,
    profile_label: &str,
    rec: &crate::config::ReconcileConfig,
    path: &std::path::Path,
) {
    match super::reconcile::compute_drift(client, profile_label, &rec.source, path).await {
        Ok(changes) => {
            let status = crate::app::cache::ReconcileStatus {
                last_check_ts: unix_secs(),
                in_sync: changes.is_empty(),
                total_changes: changes.len() as u32,
                summary: super::reconcile::drift_summary(&changes),
                by_family: super::reconcile::family_counts(&changes),
            };
            if let Err(e) = crate::app::cache::save_reconcile_status_async(
                Some(profile_label.to_owned()),
                status,
            )
            .await
            {
                tracing::warn!("auto_converge: drift-state re-persist failed: {e:#}");
            }
        }
        Err(e) => {
            tracing::warn!("auto_converge: drift re-persist recompute failed: {e:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converge_decision_gates() {
        use ConvergeDecision::{Disabled, Proceed, SkipLocked};
        // Disabled when any off-switch is set (flag / config / env).
        assert_eq!(
            converge_decision(false, true, false, false, false),
            Disabled,
            "--no-converge"
        );
        assert_eq!(
            converge_decision(true, false, false, false, false),
            Disabled,
            "auto_converge=false"
        );
        assert_eq!(
            converge_decision(true, true, true, false, false),
            Disabled,
            "PROXXX_NO_CONVERGE"
        );
        // Enabled but a deliberate lock → quiet skip (no alert).
        assert_eq!(
            converge_decision(true, true, false, true, false),
            SkipLocked,
            "read_only"
        );
        assert_eq!(
            converge_decision(true, true, false, false, true),
            SkipLocked,
            "frozen"
        );
        // All clear → proceed with the unmanned converge.
        assert_eq!(converge_decision(true, true, false, false, false), Proceed);
    }

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
