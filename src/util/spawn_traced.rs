//! Panic-visible wrapper around `tokio::spawn` for fire-and-forget tasks.
//!
//! Phase 14 audit fix. The TUI dispatch in `src/tui/mod.rs` fires off
//! ~18 background tasks per user action (start/stop/migrate/snapshot
//! /grep/HITL/ISO download/…). Each was a bare `tokio::spawn` whose
//! `JoinHandle` was immediately dropped on the floor — so any panic
//! inside (e.g. an `unreachable!` reached, an `as` truncation that
//! triggered `panic = "abort"` in release, a serde deserialise on
//! malformed cluster data) was eaten by the runtime: the task simply
//! disappeared, the user never saw a row update, and the log was
//! silent. "Operation appears to have done nothing" with no trace.
//!
//! `spawn_traced` keeps the fire-and-forget ergonomics — caller still
//! ignores the handle — but funnels panics through `tracing::error!`
//! with a stable `task = "<name>"` field so:
//!   1. The TUI log file (`tracing-subscriber` → `proxxx.log`) shows
//!      every panic with a human label.
//!   2. The flight recorder (`util::panic_hook`) still captures the
//!      backtrace; this layer is complementary, not duplicative.
//!   3. `grep "task panicked" proxxx.log` becomes a usable triage
//!      command after an operator reports "the TUI froze".
//!
//! Implementation: spawn the future, then spawn a tiny observer task
//! that awaits the inner `JoinHandle`. If the inner task panicked,
//! `JoinError::is_panic()` is true and `into_panic()` recovers the
//! payload — usually `&'static str` or `String`. Cancellation is
//! quiet (expected on runtime teardown).
//!
//! Cost: one extra `tokio::spawn` per call. Spawns are ~200 ns each
//! on a warm tokio worker — negligible next to the per-task work
//! (HTTP round-trips, disk I/O) the TUI dispatch is doing.

use std::future::Future;

/// Spawn `future` on the tokio runtime; if it panics, log the panic
/// payload at `error!` level with `task = name` so the operator gets
/// a visible signal in `proxxx.log` instead of a silent disappearance.
///
/// The returned `JoinHandle` is for the **observer** task, not the
/// inner work — call sites can (and usually do) drop it. The observer
/// task self-completes once the inner task finishes; it does not leak.
///
/// `name` should be a stable, short identifier for log-grepping:
/// `"start_guest"`, `"hitl_approval"`, `"fetch_ha_console"`. Prefer
/// `snake_case` verbs over English phrases — easier to filter on.
pub fn spawn_traced<F>(name: &'static str, future: F) -> tokio::task::JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let handle = tokio::spawn(future);
    tokio::spawn(async move {
        match handle.await {
            Ok(()) => {}
            Err(e) if e.is_cancelled() => {
                // Expected on runtime shutdown — no need to log.
            }
            Err(e) if e.is_panic() => {
                let payload = e.into_panic();
                let msg = if let Some(s) = payload.downcast_ref::<&'static str>() {
                    (*s).to_string()
                } else if let Some(s) = payload.downcast_ref::<String>() {
                    s.clone()
                } else {
                    "<non-string panic payload>".to_string()
                };
                tracing::error!(task = name, "background task panicked: {msg}");
            }
            Err(e) => {
                tracing::error!(task = name, "background task ended unexpectedly: {e:#}");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn spawn_traced_runs_to_completion_for_normal_task() {
        let done = Arc::new(AtomicBool::new(false));
        let done_clone = Arc::clone(&done);
        let handle = spawn_traced("test_normal", async move {
            done_clone.store(true, Ordering::SeqCst);
        });
        handle.await.expect("observer task joins cleanly");
        assert!(done.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn spawn_traced_observer_completes_after_panic() {
        // The observer task should JOIN cleanly even when the inner
        // task panics — that's the whole point: the panic gets logged,
        // not propagated, so the parent stays alive.
        let handle = spawn_traced("test_panic", async move {
            panic!("intentional test panic");
        });
        // If the panic were not caught, the observer's `handle.await`
        // would itself return Err and this would propagate up.
        let result = handle.await;
        assert!(result.is_ok(), "observer task swallowed the panic");
    }

    #[tokio::test]
    async fn spawn_traced_observer_handles_string_panic() {
        // `panic!("{}", String)` vs `panic!("&str literal")` go through
        // different downcast paths — exercise both.
        let handle = spawn_traced("test_string_panic", async move {
            let dynamic = String::from("dynamic panic message");
            panic!("{dynamic}");
        });
        let result = handle.await;
        assert!(result.is_ok());
    }
}
