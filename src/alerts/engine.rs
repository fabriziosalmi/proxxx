//! Alert rule evaluator (feature #8).
//!
//! Pure function: given a cluster snapshot + previous engine state +
//! configured rules, return the events to emit and the new state.
//!
//! "State" is small: per-node "offline since" timestamps, so the
//! `node_offline for X seconds` rule can fire only after the threshold
//! has elapsed across calls. Caller is responsible for persisting this
//! state between ticks (the daemon keeps it in-memory; one-shot `eval`
//! starts fresh).
//!
//! Predicates supported (closed enum — see config docs):
//! - `node_offline` — any node offline for >= `for_secs`
//! - `storage_above` — storage usage >= `threshold_percent`
//! - `replication_failing` — any replication status with `fail_count` > 0
//!   or non-empty error.

use std::collections::HashMap;

use tracing::warn;

use crate::alerts::types::{AlertEvent, Severity};
use crate::api::types::{Node, NodeStatus, ReplicationStatus, StoragePool};
use crate::config::AlertRuleConfig;

/// Across-call state: when did each node first go offline?
/// Keyed by node name, value = Unix seconds of first detection.
/// Re-entered as Online wipes the entry.
#[derive(Debug, Clone, Default)]
pub struct EngineState {
    pub node_offline_since: HashMap<String, u64>,
}

/// Snapshot of cluster state the engine evaluates against. We pass it
/// in by value to keep the function pure — no live pointers to mutable
/// `AppState` fields.
#[derive(Debug, Clone, Default)]
pub struct ClusterSnapshot {
    pub nodes: Vec<Node>,
    pub storage: Vec<StoragePool>,
    pub replication: Vec<ReplicationStatus>,
}

/// Evaluate every rule against the snapshot. Returns:
/// - the events that should fire NOW (subject to caller-side dedup)
/// - the updated `EngineState` to feed back into the next call
pub fn evaluate(
    rules: &[AlertRuleConfig],
    snap: &ClusterSnapshot,
    prev: EngineState,
    now: u64,
) -> (Vec<AlertEvent>, EngineState) {
    // ── Update per-node offline-since map BEFORE rule eval ────
    let mut state = prev;
    for n in &snap.nodes {
        match n.status {
            NodeStatus::Offline | NodeStatus::Unknown => {
                state
                    .node_offline_since
                    .entry(n.node.clone())
                    .or_insert(now);
            }
            NodeStatus::Online => {
                state.node_offline_since.remove(&n.node);
            }
        }
    }

    let mut events = Vec::new();
    for rule in rules {
        match rule.when.as_str() {
            "node_offline" => {
                for n in &snap.nodes {
                    if let Some(since) = state.node_offline_since.get(&n.node) {
                        let elapsed = now.saturating_sub(*since);
                        if elapsed >= rule.for_secs {
                            events.push(AlertEvent {
                                rule: rule.name.clone(),
                                severity: Severity::parse(&rule.severity),
                                target: format!("node:{}", n.node),
                                summary: format!("node {} offline for {}s", n.node, elapsed),
                                detail: serde_json::json!({
                                    "node": n.node,
                                    "elapsed_secs": elapsed,
                                    "threshold_secs": rule.for_secs,
                                }),
                                at: now,
                            });
                        }
                    }
                }
            }
            "storage_above" => {
                for s in &snap.storage {
                    if !rule.storage.is_empty() && s.storage != rule.storage {
                        continue;
                    }
                    if s.total == 0 {
                        continue;
                    }
                    let pct = ((s.used as f64 / s.total as f64) * 100.0).round() as u64;
                    if pct >= u64::from(rule.threshold_percent) {
                        events.push(AlertEvent {
                            rule: rule.name.clone(),
                            severity: Severity::parse(&rule.severity),
                            target: format!("storage:{}", s.storage),
                            summary: format!(
                                "storage {} at {pct}% (threshold {})",
                                s.storage, rule.threshold_percent
                            ),
                            detail: serde_json::json!({
                                "storage": s.storage,
                                "used_pct": pct,
                                "threshold_pct": rule.threshold_percent,
                                "used_bytes": s.used,
                                "total_bytes": s.total,
                            }),
                            at: now,
                        });
                    }
                }
            }
            "replication_failing" => {
                for r in &snap.replication {
                    let failing = r.fail_count > 0 || !r.error.is_empty();
                    if failing {
                        events.push(AlertEvent {
                            rule: rule.name.clone(),
                            severity: Severity::parse(&rule.severity),
                            target: format!("replication:{}", r.id),
                            summary: format!(
                                "replication {} failing: {} (fail_count {})",
                                r.id,
                                if r.error.is_empty() {
                                    "—"
                                } else {
                                    r.error.as_str()
                                },
                                r.fail_count
                            ),
                            detail: serde_json::json!({
                                "id": r.id,
                                "fail_count": r.fail_count,
                                "error": r.error,
                                "source": r.source,
                                "target": r.target,
                            }),
                            at: now,
                        });
                    }
                }
            }
            other => {
                warn!(
                    "alert rule {} uses unknown predicate '{other}' — skipping",
                    rule.name
                );
            }
        }
    }
    (events, state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{NodeStatus, StoragePool};

    fn rule(name: &str, when: &str) -> AlertRuleConfig {
        AlertRuleConfig {
            name: name.into(),
            when: when.into(),
            for_secs: 60,
            threshold_percent: 90,
            storage: String::new(),
            severity: "warning".into(),
            route: vec![],
            dedup_secs: 300,
        }
    }

    fn online(name: &str) -> Node {
        Node {
            node: name.into(),
            status: NodeStatus::Online,
            cpu: 0.0,
            maxcpu: 1,
            mem: 0,
            maxmem: 1,
            disk: 0,
            maxdisk: 1,
            uptime: 0,
        }
    }

    fn offline(name: &str) -> Node {
        Node {
            node: name.into(),
            status: NodeStatus::Offline,
            cpu: 0.0,
            maxcpu: 1,
            mem: 0,
            maxmem: 1,
            disk: 0,
            maxdisk: 1,
            uptime: 0,
        }
    }

    #[test]
    fn node_offline_does_not_fire_below_threshold() {
        let r = vec![rule("n_off", "node_offline")];
        let snap = ClusterSnapshot {
            nodes: vec![offline("pve1")],
            ..Default::default()
        };
        // First eval: just observed offline. Threshold = 60s. Should not fire.
        let (events, state) = evaluate(&r, &snap, EngineState::default(), 1000);
        assert!(events.is_empty(), "below threshold");
        assert!(state.node_offline_since.contains_key("pve1"));

        // 30s later — still below 60s threshold.
        let (events, _) = evaluate(&r, &snap, state, 1030);
        assert!(events.is_empty(), "still below threshold");
    }

    #[test]
    fn node_offline_fires_after_threshold() {
        let r = vec![rule("n_off", "node_offline")];
        let snap = ClusterSnapshot {
            nodes: vec![offline("pve1")],
            ..Default::default()
        };
        let (_, state) = evaluate(&r, &snap, EngineState::default(), 1000);
        // 90s later — over the 60s threshold.
        let (events, _) = evaluate(&r, &snap, state, 1090);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].target, "node:pve1");
        assert!(events[0].summary.contains("90s"));
    }

    #[test]
    fn node_back_online_clears_state() {
        let r = vec![rule("n_off", "node_offline")];
        let snap_off = ClusterSnapshot {
            nodes: vec![offline("pve1")],
            ..Default::default()
        };
        let (_, state) = evaluate(&r, &snap_off, EngineState::default(), 1000);
        assert!(state.node_offline_since.contains_key("pve1"));

        let snap_on = ClusterSnapshot {
            nodes: vec![online("pve1")],
            ..Default::default()
        };
        let (events, state) = evaluate(&r, &snap_on, state, 1100);
        assert!(events.is_empty(), "online clears the alert state");
        assert!(!state.node_offline_since.contains_key("pve1"));
    }

    #[test]
    fn storage_above_fires_at_threshold() {
        let mut r = rule("s_full", "storage_above");
        r.threshold_percent = 80;
        let snap = ClusterSnapshot {
            storage: vec![StoragePool {
                storage: "local-lvm".into(),
                storage_type: "lvm".into(),
                used: 850,
                avail: 150,
                total: 1000,
                active: true,
                content: String::new(),
                shared: false,
            }],
            ..Default::default()
        };
        let (events, _) = evaluate(&[r], &snap, EngineState::default(), 1000);
        assert_eq!(events.len(), 1);
        assert!(events[0].summary.contains("85%"));
    }

    #[test]
    fn storage_above_filters_by_storage_name() {
        let mut r = rule("s_full", "storage_above");
        r.threshold_percent = 80;
        r.storage = "ceph".into();
        let snap = ClusterSnapshot {
            storage: vec![
                StoragePool {
                    storage: "local-lvm".into(),
                    storage_type: "lvm".into(),
                    used: 950,
                    avail: 50,
                    total: 1000,
                    active: true,
                    content: String::new(),
                    shared: false,
                },
                StoragePool {
                    storage: "ceph".into(),
                    storage_type: "rbd".into(),
                    used: 300,
                    avail: 700,
                    total: 1000,
                    active: true,
                    content: String::new(),
                    shared: false,
                },
            ],
            ..Default::default()
        };
        let (events, _) = evaluate(&[r], &snap, EngineState::default(), 1000);
        // local-lvm is over threshold but filtered out; ceph is below.
        assert!(events.is_empty());
    }

    #[test]
    fn storage_above_skips_zero_total() {
        // Defensive: storage with total=0 (uninitialised / inactive)
        // must not divide by zero.
        let r = rule("s_full", "storage_above");
        let snap = ClusterSnapshot {
            storage: vec![StoragePool {
                storage: "broken".into(),
                storage_type: "lvm".into(),
                used: 100,
                avail: 0,
                total: 0,
                active: false,
                content: String::new(),
                shared: false,
            }],
            ..Default::default()
        };
        let (events, _) = evaluate(&[r], &snap, EngineState::default(), 1000);
        assert!(events.is_empty());
    }

    #[test]
    fn replication_failing_fires_on_fail_count() {
        let r = rule("repl_fail", "replication_failing");
        let snap = ClusterSnapshot {
            replication: vec![ReplicationStatus {
                id: "100-0".into(),
                fail_count: 3,
                error: "ssh: timeout".into(),
                source: "pve1".into(),
                target: "pve2".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let (events, _) = evaluate(&[r], &snap, EngineState::default(), 1000);
        assert_eq!(events.len(), 1);
        assert!(events[0].summary.contains("ssh: timeout"));
    }

    #[test]
    fn replication_failing_does_not_fire_when_healthy() {
        let r = rule("repl_fail", "replication_failing");
        let snap = ClusterSnapshot {
            replication: vec![ReplicationStatus {
                id: "100-0".into(),
                fail_count: 0,
                error: String::new(),
                last_sync: 1000,
                ..Default::default()
            }],
            ..Default::default()
        };
        let (events, _) = evaluate(&[r], &snap, EngineState::default(), 1000);
        assert!(events.is_empty());
    }

    #[test]
    fn unknown_predicate_does_not_panic() {
        let r = rule("ghost", "this_does_not_exist");
        let snap = ClusterSnapshot::default();
        let (events, _) = evaluate(&[r], &snap, EngineState::default(), 1000);
        assert!(events.is_empty());
    }
}
