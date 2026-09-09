//! Liveness of proxxx's own daemon components (audit 2026-09-09, #271).
//!
//! The exporter reports thoroughly on the cluster and said nothing about
//! proxxx itself, so a daemon pillar that had stopped running was
//! indistinguishable from one that was running with nothing to report.
//! From outside, a panicked alerts loop or HITL loop looked exactly like
//! a quiet one: alerts stopped arriving, approvals stopped being
//! answered, and the natural check — "is the process up?" — was true and
//! useless.
//!
//! The reconcile pillar was the accidental exception, because
//! `proxxx_reconcile_last_check_timestamp` goes stale if it dies. That is
//! the shape the other pillars needed, so this generalises it:
//!
//! * `proxxx_daemon_component_up{component}` — 1 while the component's
//!   task is alive, 0 once it has exited.
//! * `proxxx_daemon_component_last_tick_timestamp{component}` — unix
//!   seconds of that component's last completed loop iteration, so
//!   "running but wedged" is distinguishable from "running and idle".
//!
//! In-process state rather than a persisted store: these describe THIS
//! process, and a scrape served by a different process would be lying.
//! `proxxx daemon serve` runs the metrics exporter alongside the pillars,
//! which is the deployment this is for.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy)]
struct ComponentHealth {
    up: bool,
    last_tick: u64,
}

fn registry() -> &'static Mutex<BTreeMap<&'static str, ComponentHealth>> {
    static REG: OnceLock<Mutex<BTreeMap<&'static str, ComponentHealth>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Record that `component` has started. Called once per pillar at spawn.
pub fn register(component: &'static str) {
    let mut g = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    g.insert(
        component,
        ComponentHealth {
            up: true,
            last_tick: now_secs(),
        },
    );
}

/// Record that `component` completed a loop iteration.
///
/// Call at the END of each tick, so the timestamp means "last time this
/// pillar finished useful work" rather than "last time it woke up".
pub fn tick(component: &'static str) {
    let mut g = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    g.entry(component)
        .and_modify(|h| h.last_tick = now_secs())
        .or_insert(ComponentHealth {
            up: true,
            last_tick: now_secs(),
        });
}

/// Record that `component` has stopped. The series stays published with
/// value 0 — a disappearing series looks the same as a scrape failure,
/// and the whole point is to make the difference visible.
pub fn mark_down(component: &'static str) {
    let mut g = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    g.entry(component).and_modify(|h| h.up = false);
}

/// Snapshot for the exporter: `(component, up, last_tick_unix_secs)`.
#[must_use]
pub fn snapshot() -> Vec<(&'static str, bool, u64)> {
    registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .map(|(name, h)| (*name, h.up, h.last_tick))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{mark_down, register, snapshot, tick};

    fn find(name: &str) -> Option<(bool, u64)> {
        snapshot()
            .into_iter()
            .find(|(n, _, _)| *n == name)
            .map(|(_, up, ts)| (up, ts))
    }

    #[test]
    fn a_registered_component_reports_up() {
        register("test_pillar_up");
        let (up, ts) = find("test_pillar_up").expect("registered");
        assert!(up);
        assert!(ts > 0, "registration must stamp a timestamp");
    }

    /// The point of the finding: a stopped pillar must be visibly down,
    /// not merely absent. An absent series is indistinguishable from a
    /// failed scrape.
    #[test]
    fn a_stopped_component_reports_down_rather_than_vanishing() {
        register("test_pillar_down");
        mark_down("test_pillar_down");
        let (up, _) = find("test_pillar_down").expect("the series must remain published");
        assert!(!up, "a stopped component must report 0, not disappear");
    }

    #[test]
    fn ticking_advances_the_timestamp() {
        register("test_pillar_tick");
        let (_, first) = find("test_pillar_tick").expect("registered");
        std::thread::sleep(std::time::Duration::from_millis(1100));
        tick("test_pillar_tick");
        let (_, second) = find("test_pillar_tick").expect("still there");
        assert!(
            second > first,
            "a tick must advance the last-tick timestamp ({first} → {second})"
        );
    }
}
