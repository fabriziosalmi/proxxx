//! MCP server-sent notifications — broker + tracked-event poller.
//!
//! Per the MCP spec, a server can emit `notifications/*` messages
//! at any time over the same transport. This module provides:
//!
//! 1. A [`Broker`] backed by a `tokio::sync::broadcast` channel —
//!    transport-agnostic fan-out. HTTP SSE subscribes for the
//!    lifetime of the connection; stdio (future work) would do
//!    the same from a writer task.
//! 2. A background **task poller** that polls `/cluster/tasks` on
//!    a 2 s tick and publishes [`McpNotification::TaskStateChange`]
//!    when a task starts or finishes.
//! 3. A background **incident watcher** that polls the freeze lock
//!    every 5 s and publishes [`McpNotification::Incident`] on
//!    transitions (freeze→thaw and thaw→freeze).
//!
//! ## Delivery semantics
//!
//! Best-effort, no replay on disconnect. The broadcast channel has
//! a bounded buffer; slow consumers drop oldest messages first
//! (`tokio::sync::broadcast::error::RecvError::Lagged`). This
//! matches the issue's honesty-about-delivery requirement — the
//! API doesn't promise anything that the broker doesn't deliver.
//!
//! ## Transport coverage
//!
//! Both stdio and HTTP/SSE emit broker events:
//!
//! * **HTTP `GET /mcp`** — SSE stream subscribes to the broker
//!   for the lifetime of the connection. `event:
//!   notifications/cluster-event` per notification; lagged
//!   consumers see a single `notifications/lagged` advisory.
//! * **stdio** — `mcp::server::run_server` `select!`s on the
//!   stdin-reader channel + a broker receiver. Notifications
//!   write one JSON-RPC 2.0 envelope per line on stdout,
//!   interleaved with the request/response stream. The
//!   stdin-reader runs as a separate task because `read_until`
//!   is NOT cancel-safe — see the comment at the top of
//!   `server.rs`.
//!
//! ## Scope deferred per #71
//!
//! - Per-subscription filters — v1 fan-outs every event to every
//!   subscriber. Filtering happens client-side. A future API
//!   `notifications/subscribe { filter: { types: [...] } }` can
//!   keep state per-receiver.
//! - Cross-process event broker (Redis / NATS) — explicitly out
//!   of scope per #71.

use serde::Serialize;
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::api::{ProxmoxGateway, PxClient};

/// Bounded buffer per subscriber. Slow consumers lose oldest first
/// (broadcast channel semantics) — fine for "best-effort" notifications.
/// 256 is a few seconds of cluster events on a busy cluster.
const BROKER_CAPACITY: usize = 256;

/// Tick rate for the task-event poller. Matches the existing
/// `events stream` default (2 s) so subscribers see the same
/// resolution as the CLI command.
const TASK_POLL_INTERVAL_SECS: u64 = 2;

/// Tick rate for the incident watcher. Slower than tasks because
/// freeze transitions are rare; we just need "within 5s" detection.
const INCIDENT_POLL_INTERVAL_SECS: u64 = 5;

/// Tick rate for the reconcile drift-state watcher. It reads a `SQLite`
/// store the daemon writes on its own (≥30 s) cadence, so a 5 s poll is
/// plenty to surface a transition promptly.
const RECONCILE_POLL_INTERVAL_SECS: u64 = 5;

/// One MCP notification. Serialised as the `params` of a
/// JSON-RPC `notifications/cluster-event` message.
///
/// The `#[serde(tag = "kind", rename_all = "snake_case")]` shape
/// gives JSON consumers a flat object: `{kind: "task_state_change",
/// upid: "...", node: "...", ...}`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpNotification {
    /// A PVE task started, completed, or failed. Mirrors the
    /// `events stream` event types but in MCP notification shape.
    TaskStateChange {
        /// One of "started", "completed", "failed".
        event: &'static str,
        upid: String,
        node: String,
        #[serde(rename = "type")]
        task_type: String,
        id: String,
        user: String,
        starttime: i64,
        endtime: Option<i64>,
        status: Option<String>,
    },
    /// A freeze / thaw transition just happened. Carries the
    /// new state so subscribers can react ("our cluster just got
    /// locked, halt scheduled ops").
    Incident {
        /// "frozen" or "thawed".
        event: &'static str,
        /// Operator-supplied reason (`""` for `thawed` when the
        /// lock was already gone).
        reason: String,
    },
    /// The reconcile drift-state changed — a `reconcile watch` reported a
    /// new sync↔drift transition or an updated drift result for a profile.
    Reconciliation {
        /// "drifted" or "in_sync".
        event: &'static str,
        /// Profile whose drift state changed.
        profile: String,
        /// Total drifted resources (0 when `in_sync`).
        drift_total: u32,
        /// One-line human summary (same text the daemon logs / alerts).
        summary: String,
    },
}

/// Notification fan-out. Holds the sender end of a tokio
/// broadcast channel. `subscribe()` hands out receivers; HTTP SSE
/// streams + the future stdio writer each take one.
#[derive(Clone)]
pub struct Broker {
    tx: broadcast::Sender<McpNotification>,
}

impl Default for Broker {
    fn default() -> Self {
        Self::new()
    }
}

impl Broker {
    #[must_use]
    pub fn new() -> Self {
        let (tx, _rx) = broadcast::channel(BROKER_CAPACITY);
        Self { tx }
    }

    /// Hand out a new receiver. Each transport-connection should
    /// hold exactly one and read from it until the connection
    /// closes.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<McpNotification> {
        self.tx.subscribe()
    }

    /// Fire a notification. If no subscribers are listening, the
    /// message is dropped — no error. This is exactly the
    /// semantics we want: a poller that's running 24/7 shouldn't
    /// fail just because no MCP client is connected right now.
    pub fn publish(&self, n: McpNotification) {
        // `send` returns the number of receivers; we deliberately
        // ignore failure (which would mean "no receivers" — fine).
        let _ = self.tx.send(n);
    }

    /// Receiver count for diagnostics / tests.
    #[must_use]
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }
}

/// Spawn the task-event poller. Polls `/cluster/tasks` every
/// 2 s and publishes a notification per state change. Mirrors the
/// `events stream` logic but in broker shape.
///
/// Returns the spawned `JoinHandle` so the caller can detach (the
/// poller exits when the broker drops + last receiver is gone, but
/// the typical caller just calls `tokio::spawn` and forgets).
#[must_use = "spawning a poller without holding the handle leaks the background task"]
pub fn spawn_task_poller(client: Arc<PxClient>, broker: Broker) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        use std::collections::HashMap;

        let mut seen: HashMap<String, crate::api::types::TaskInfo> = HashMap::new();
        let interval = std::time::Duration::from_secs(TASK_POLL_INTERVAL_SECS);

        // Initial snapshot — record what's already there, don't
        // emit. Otherwise every subscriber would see every task
        // currently in PVE's recent-tasks window as "started".
        if let Ok(tasks) = client.get_cluster_tasks().await {
            for t in tasks {
                seen.insert(t.upid.clone(), t);
            }
        }

        loop {
            tokio::time::sleep(interval).await;
            let current = match client.get_cluster_tasks().await {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!("mcp notifications: task poll failed: {e:#}");
                    continue;
                }
            };

            for t in &current {
                match seen.get(&t.upid) {
                    None => {
                        let event = if t.endtime.is_some() {
                            task_outcome(t)
                        } else {
                            "started"
                        };
                        broker.publish(notif_from(t, event));
                    }
                    Some(old) => {
                        if old.endtime.is_none() && t.endtime.is_some() {
                            let event = task_outcome(t);
                            broker.publish(notif_from(t, event));
                        }
                    }
                }
                seen.insert(t.upid.clone(), t.clone());
            }

            // Cap seen-map size so a long-running poller doesn't
            // grow unboundedly. PVE's /cluster/tasks itself is
            // bounded by its retention window; ours mirrors that.
            if seen.len() > 4096 {
                // Drop oldest by starttime.
                let mut entries: Vec<(String, crate::api::types::TaskInfo)> =
                    seen.drain().collect();
                entries.sort_by_key(|(_, t)| t.starttime);
                let keep_from = entries.len().saturating_sub(2048);
                for (k, v) in entries.into_iter().skip(keep_from) {
                    seen.insert(k, v);
                }
            }
        }
    })
}

/// Spawn the incident-state watcher. Polls the freeze lock every
/// 5 s and publishes a notification on transition.
#[must_use = "spawning a watcher without holding the handle leaks the background task"]
pub fn spawn_incident_watcher(broker: Broker) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(INCIDENT_POLL_INTERVAL_SECS);
        let mut was_frozen = matches!(crate::incident::current_state(), Ok(Some(_)));
        loop {
            tokio::time::sleep(interval).await;
            let now_frozen = match crate::incident::current_state() {
                Ok(Some(_)) => true,
                Ok(None) => false,
                Err(e) => {
                    tracing::warn!("mcp notifications: incident poll failed: {e:#}");
                    continue;
                }
            };
            if now_frozen && !was_frozen {
                let reason = crate::incident::current_state()
                    .ok()
                    .flatten()
                    .map_or_else(String::new, |s| s.reason);
                broker.publish(McpNotification::Incident {
                    event: "frozen",
                    reason,
                });
            }
            if !now_frozen && was_frozen {
                broker.publish(McpNotification::Incident {
                    event: "thawed",
                    reason: String::new(),
                });
            }
            was_frozen = now_frozen;
        }
    })
}

/// Decide whether a drift observation warrants a notification: on the FIRST
/// observation only if drifted, on any sync↔drift flip, and on a fresh drift
/// result (new timestamp while still drifted) — never on an unchanged in-sync
/// poll. `last` is the prior `(in_sync, last_check_ts)`.
fn should_publish_reconcile(last: Option<(bool, u64)>, in_sync: bool, ts: u64) -> bool {
    match last {
        None => !in_sync,
        Some((prev_sync, prev_ts)) => prev_sync != in_sync || (!in_sync && ts != prev_ts),
    }
}

/// Spawn the reconcile drift-state watcher. Polls the shared per-profile
/// `SQLite` drift-state store (written by the `reconcile watch` daemon —
/// possibly a different process) every 5 s and publishes a `Reconciliation`
/// notification on a sync↔drift transition or a fresh drift result. Stays
/// quiet while nothing changes, and silent until the watch first reports.
#[must_use = "spawning a watcher without holding the handle leaks the background task"]
pub fn spawn_reconcile_watcher(
    profile: Option<String>,
    broker: Broker,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(RECONCILE_POLL_INTERVAL_SECS);
        let mut last: Option<(bool, u64)> = None;
        loop {
            tokio::time::sleep(interval).await;
            let status = match crate::app::cache::load_reconcile_status(profile.as_deref()) {
                Ok(Some(s)) => s,
                Ok(None) => continue, // watch hasn't reported yet
                Err(e) => {
                    tracing::warn!("mcp notifications: reconcile poll failed: {e:#}");
                    continue;
                }
            };
            if should_publish_reconcile(last, status.in_sync, status.last_check_ts) {
                broker.publish(McpNotification::Reconciliation {
                    event: if status.in_sync { "in_sync" } else { "drifted" },
                    profile: profile.as_deref().unwrap_or("default").to_owned(),
                    drift_total: status.total_changes,
                    summary: status.summary.clone(),
                });
            }
            last = Some((status.in_sync, status.last_check_ts));
        }
    })
}

/// `"completed"` for OK exitstatus, `"failed"` for anything else.
fn task_outcome(t: &crate::api::types::TaskInfo) -> &'static str {
    match t.status.as_deref() {
        None | Some("OK") => "completed",
        _ => "failed",
    }
}

fn notif_from(t: &crate::api::types::TaskInfo, event: &'static str) -> McpNotification {
    McpNotification::TaskStateChange {
        event,
        upid: t.upid.clone(),
        node: t.node.clone(),
        task_type: t.task_type.clone(),
        id: t.id.clone(),
        user: t.user.clone(),
        starttime: t.starttime as i64,
        endtime: t.endtime.map(|e| e as i64),
        status: t.status.clone(),
    }
}

/// Wrap a notification in the canonical JSON-RPC 2.0 notification
/// envelope: `{"jsonrpc":"2.0","method":"notifications/cluster-event","params":<n>}`.
///
/// Same shape goes out over both stdio (one line) and HTTP/SSE
/// (`data:` field of the SSE event).
#[must_use]
pub fn rpc_envelope(n: &McpNotification) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/cluster-event",
        "params": n,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_state_change_serialises_with_kind_tag() {
        let n = McpNotification::TaskStateChange {
            event: "completed",
            upid: "UPID:pve-1:1:1:1:qmstart:100:root:".into(),
            node: "pve-1".into(),
            task_type: "qmstart".into(),
            id: "100".into(),
            user: "root@pam".into(),
            starttime: 1_700_000_000,
            endtime: Some(1_700_000_010),
            status: Some("OK".into()),
        };
        let v = serde_json::to_value(&n).unwrap();
        assert_eq!(v["kind"], "task_state_change");
        assert_eq!(v["event"], "completed");
        assert_eq!(v["upid"], "UPID:pve-1:1:1:1:qmstart:100:root:");
        // serde rename: `type` not `task_type`
        assert_eq!(v["type"], "qmstart");
    }

    #[test]
    fn incident_notification_serialises_flat() {
        let n = McpNotification::Incident {
            event: "frozen",
            reason: "token leaked".into(),
        };
        let v = serde_json::to_value(&n).unwrap();
        assert_eq!(v["kind"], "incident");
        assert_eq!(v["event"], "frozen");
        assert_eq!(v["reason"], "token leaked");
    }

    #[test]
    fn reconciliation_notification_serialises_flat() {
        let n = McpNotification::Reconciliation {
            event: "drifted",
            profile: "prod".into(),
            drift_total: 3,
            summary: "3 change(s) across 2 families".into(),
        };
        let v = serde_json::to_value(&n).unwrap();
        assert_eq!(v["kind"], "reconciliation");
        assert_eq!(v["event"], "drifted");
        assert_eq!(v["profile"], "prod");
        assert_eq!(v["drift_total"], 3);
    }

    #[test]
    fn should_publish_reconcile_only_on_change() {
        // First observation: announce drift, stay quiet on in-sync.
        assert!(should_publish_reconcile(None, false, 100));
        assert!(!should_publish_reconcile(None, true, 100));
        // A sync↔drift flip always publishes.
        assert!(should_publish_reconcile(Some((true, 100)), false, 200));
        assert!(should_publish_reconcile(Some((false, 100)), true, 200));
        // Still drifted but a newer check → updated drift, publish.
        assert!(should_publish_reconcile(Some((false, 100)), false, 200));
        // No change (in-sync stays in-sync, or identical drift) → quiet.
        assert!(!should_publish_reconcile(Some((true, 100)), true, 200));
        assert!(!should_publish_reconcile(Some((false, 100)), false, 100));
    }

    #[test]
    fn rpc_envelope_wraps_in_jsonrpc_2_0() {
        let n = McpNotification::Incident {
            event: "thawed",
            reason: String::new(),
        };
        let env = rpc_envelope(&n);
        assert_eq!(env["jsonrpc"], "2.0");
        assert_eq!(env["method"], "notifications/cluster-event");
        assert_eq!(env["params"]["kind"], "incident");
    }

    #[tokio::test]
    async fn broker_fans_out_to_multiple_receivers() {
        let broker = Broker::new();
        let mut rx1 = broker.subscribe();
        let mut rx2 = broker.subscribe();
        broker.publish(McpNotification::Incident {
            event: "frozen",
            reason: "x".into(),
        });
        let n1 = rx1.recv().await.unwrap();
        let n2 = rx2.recv().await.unwrap();
        assert!(matches!(
            n1,
            McpNotification::Incident {
                event: "frozen",
                ..
            }
        ));
        assert!(matches!(
            n2,
            McpNotification::Incident {
                event: "frozen",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn broker_drops_messages_when_no_receivers() {
        let broker = Broker::new();
        // No subscribers — publish should not error, just drop.
        broker.publish(McpNotification::Incident {
            event: "frozen",
            reason: "x".into(),
        });
        // Subscribe AFTER — should NOT see the dropped message.
        let mut rx = broker.subscribe();
        let timeout = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        // Either the recv pending forever (Elapsed) or returns immediately
        // — never a stale message. `Elapsed` confirms the "no replay" contract.
        assert!(timeout.is_err());
    }

    #[test]
    fn task_outcome_is_ok_means_completed_else_failed() {
        let mk = |status: Option<&str>| crate::api::types::TaskInfo {
            upid: "u".into(),
            node: "n".into(),
            task_type: "t".into(),
            id: "i".into(),
            user: "u".into(),
            starttime: 0,
            endtime: Some(1),
            status: status.map(str::to_owned),
        };
        assert_eq!(task_outcome(&mk(Some("OK"))), "completed");
        assert_eq!(task_outcome(&mk(None)), "completed");
        assert_eq!(task_outcome(&mk(Some("FAIL"))), "failed");
        assert_eq!(task_outcome(&mk(Some("ERR: stuff"))), "failed");
    }
}
