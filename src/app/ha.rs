//! HA + replication inspector (feature #5).
//!
//! Honest scope cut (per the draconian review):
//! - We do NOT reimplement `pve-ha-manager`'s CRM scoring algorithm.
//!   That's Perl, drift-prone, and a portability tax we'd carry forever.
//! - Instead, we offer a **read-only "what-if" inspector**: given the
//!   current cluster topology and an HA group's priority list, compute
//!   "if node X goes offline, where would the resource land?".
//! - The answer is the highest-priority remaining online node from the
//!   group's `nodes` field. If `restricted=true` and no online node is
//!   in the list, the resource fences. We don't simulate fencing —
//!   we report it as `Stuck`.
//!
//! Also exposes `summarise_replication_health()` to roll up per-job
//! status into a single colour for the cluster overview.

use std::collections::HashSet;

use crate::api::types::{
    ClusterStatusEntry, HaGroup, HaResource, ReplicationHealth, ReplicationStatus,
};

/// Set of currently-online node names, derived from `cluster_status()`.
pub fn online_nodes(entries: &[ClusterStatusEntry]) -> HashSet<String> {
    entries
        .iter()
        .filter(|e| e.entry_type == "node" && e.online)
        .map(|e| e.name.clone())
        .collect()
}

/// Outcome of a "what if this node fails?" preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailoverPreview {
    /// Resource would relocate to this node (highest-priority online
    /// member of the group, after excluding the failing one).
    Relocate { target: String, priority: i32 },
    /// No online node in the group can host the resource. With
    /// `restricted=true`, this means the service stays stopped.
    /// With `restricted=false`, Proxmox falls back to any online node;
    /// `chosen` is empty if no node at all is online.
    Stuck {
        restricted: bool,
        chosen: Option<String>,
    },
    /// The failing node didn't host this resource — no relocation.
    NotAffected,
}

/// Predict where a resource lands if `failed_node` goes offline.
///
/// Inputs:
/// - `resource` — the HA service to inspect
/// - `groups`   — all HA groups, for priority lookup
/// - `online`   — set of currently-online nodes (from `online_nodes`)
/// - `current_node` — where the resource is currently running (Proxmox
///   exposes this via the cluster resource API; we accept it directly
///   to keep this function pure and testable)
/// - `failed_node` — the hypothetical failure
///
/// Returns the deterministic "next hop" the user should expect.
pub fn preview_failover(
    resource: &HaResource,
    groups: &[HaGroup],
    online: &HashSet<String>,
    current_node: &str,
    failed_node: &str,
) -> FailoverPreview {
    // No-op if the resource isn't on the failing node.
    if current_node != failed_node {
        return FailoverPreview::NotAffected;
    }

    let group = groups.iter().find(|g| g.name == resource.group);
    let Some(g) = group else {
        // Resource has no group → Proxmox picks any online node. We
        // can't be more specific without quorum data.
        let any_online: Option<String> = online.iter().find(|n| n.as_str() != failed_node).cloned();
        return match any_online {
            Some(n) => FailoverPreview::Relocate {
                target: n,
                priority: 0,
            },
            None => FailoverPreview::Stuck {
                restricted: false,
                chosen: None,
            },
        };
    };

    // Walk the group's priority list, skip the failing node, pick the
    // first online member.
    let prio_list = g.parse_priority_list();
    for (node, prio) in &prio_list {
        if node == failed_node {
            continue;
        }
        if online.contains(node) {
            return FailoverPreview::Relocate {
                target: node.clone(),
                priority: *prio,
            };
        }
    }

    // No group-listed node is online (other than the failed one).
    if g.restricted {
        FailoverPreview::Stuck {
            restricted: true,
            chosen: None,
        }
    } else {
        // Unrestricted: Proxmox would consider any online node. Pick
        // the alphabetically-first as a deterministic "best guess".
        let mut anywhere: Vec<String> = online
            .iter()
            .filter(|n| n.as_str() != failed_node)
            .cloned()
            .collect();
        anywhere.sort();
        FailoverPreview::Stuck {
            restricted: false,
            chosen: anywhere.into_iter().next(),
        }
    }
}

/// Cluster-wide replication health roll-up. Returns the worst observed
/// health across all jobs — a single Failing job sets the cluster red.
#[must_use]
pub fn summarise_replication_health(
    statuses: &[ReplicationStatus],
    now: u64,
    period_secs: u64,
) -> ReplicationHealth {
    let mut worst = ReplicationHealth::Healthy;
    for s in statuses {
        let h = s.health(now, period_secs);
        // Order: Healthy < Stale < Failing.
        worst = match (worst, h) {
            (_, ReplicationHealth::Failing) => ReplicationHealth::Failing,
            (ReplicationHealth::Failing, _) => ReplicationHealth::Failing,
            (ReplicationHealth::Stale, _) | (_, ReplicationHealth::Stale) => {
                ReplicationHealth::Stale
            }
            _ => ReplicationHealth::Healthy,
        };
    }
    worst
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{HaGroup, HaResource, ReplicationStatus};

    fn online_set(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    fn group(name: &str, nodes: &str, restricted: bool) -> HaGroup {
        HaGroup {
            name: name.into(),
            nodes: nodes.into(),
            restricted,
            nofailback: false,
            comment: String::new(),
        }
    }

    fn resource(sid: &str, group: &str) -> HaResource {
        HaResource {
            sid: sid.into(),
            group: group.into(),
            state: "started".into(),
            max_restart: 1,
            max_relocate: 1,
            comment: String::new(),
        }
    }

    #[test]
    fn preview_unaffected_when_resource_elsewhere() {
        let r = resource("vm:100", "g1");
        let g = vec![group("g1", "pve1:2,pve2:1", false)];
        let online = online_set(&["pve1", "pve2", "pve3"]);
        let result = preview_failover(&r, &g, &online, "pve1", "pve3");
        assert_eq!(result, FailoverPreview::NotAffected);
    }

    #[test]
    fn preview_picks_highest_priority_remaining() {
        let r = resource("vm:100", "g1");
        let g = vec![group("g1", "pve1:2,pve2:1,pve3", false)];
        let online = online_set(&["pve1", "pve2", "pve3"]);
        // pve1 fails → next priority is pve2 (1).
        assert_eq!(
            preview_failover(&r, &g, &online, "pve1", "pve1"),
            FailoverPreview::Relocate {
                target: "pve2".into(),
                priority: 1
            }
        );
    }

    #[test]
    fn preview_skips_offline_priority_node() {
        let r = resource("vm:100", "g1");
        let g = vec![group("g1", "pve1:3,pve2:2,pve3:1", false)];
        // pve2 is offline. pve1 fails → must pick pve3 (1), not pve2 (2).
        let online = online_set(&["pve1", "pve3"]);
        assert_eq!(
            preview_failover(&r, &g, &online, "pve1", "pve1"),
            FailoverPreview::Relocate {
                target: "pve3".into(),
                priority: 1
            }
        );
    }

    #[test]
    fn preview_restricted_no_fallback() {
        let r = resource("vm:100", "g1");
        let g = vec![group("g1", "pve1:2,pve2:1", true)];
        // Both group-listed nodes are unreachable; restricted=true
        // means no fallback.
        let online = online_set(&["pve3"]); // pve3 not in group
        assert_eq!(
            preview_failover(&r, &g, &online, "pve1", "pve1"),
            FailoverPreview::Stuck {
                restricted: true,
                chosen: None
            }
        );
    }

    #[test]
    fn preview_unrestricted_falls_back_to_any() {
        let r = resource("vm:100", "g1");
        let g = vec![group("g1", "pve1,pve2", false)];
        let online = online_set(&["pve3", "pve4"]);
        // pve1 fails, no group node online → unrestricted falls back to
        // alphabetically-first online (pve3).
        assert_eq!(
            preview_failover(&r, &g, &online, "pve1", "pve1"),
            FailoverPreview::Stuck {
                restricted: false,
                chosen: Some("pve3".into())
            }
        );
    }

    #[test]
    fn preview_no_group_picks_any_online() {
        let r = resource("vm:100", "");
        let online = online_set(&["pve1", "pve2"]);
        let result = preview_failover(&r, &[], &online, "pve1", "pve1");
        // With no group, the "any online" pick isn't deterministic
        // (HashSet iter order varies), but it must NOT pick the failed
        // node and MUST find someone online.
        match result {
            FailoverPreview::Relocate { target, .. } => {
                assert_ne!(target, "pve1");
                assert!(online.contains(&target));
            }
            other => panic!("expected Relocate, got {other:?}"),
        }
    }

    #[test]
    fn preview_total_outage_returns_stuck_no_chosen() {
        let r = resource("vm:100", "g1");
        let g = vec![group("g1", "pve1,pve2", false)];
        let online: HashSet<String> = HashSet::new(); // nothing online
        assert_eq!(
            preview_failover(&r, &g, &online, "pve1", "pve1"),
            FailoverPreview::Stuck {
                restricted: false,
                chosen: None
            }
        );
    }

    #[test]
    fn online_nodes_filters_summary_entries() {
        let entries = vec![
            ClusterStatusEntry {
                entry_type: "cluster".into(),
                name: "homelab".into(),
                online: true,
                quorate: true,
                nodes: 3,
                local: false,
            },
            ClusterStatusEntry {
                entry_type: "node".into(),
                name: "pve1".into(),
                online: true,
                quorate: true,
                nodes: 0,
                local: true,
            },
            ClusterStatusEntry {
                entry_type: "node".into(),
                name: "pve2".into(),
                online: false,
                quorate: false,
                nodes: 0,
                local: false,
            },
        ];
        let online = online_nodes(&entries);
        assert_eq!(
            online.len(),
            1,
            "only pve1 is online; cluster summary excluded"
        );
        assert!(online.contains("pve1"));
    }

    #[test]
    fn summary_health_failing_dominates() {
        let now = 1_700_000_300;
        let s = vec![
            ReplicationStatus {
                id: "100-0".into(),
                last_sync: 1_700_000_000,
                ..Default::default()
            },
            ReplicationStatus {
                id: "200-0".into(),
                last_sync: 1_700_000_000,
                fail_count: 2,
                ..Default::default()
            },
        ];
        assert_eq!(
            summarise_replication_health(&s, now, 900),
            ReplicationHealth::Failing
        );
    }

    #[test]
    fn summary_health_all_healthy() {
        let now = 1_700_000_300;
        let s = vec![
            ReplicationStatus {
                id: "100-0".into(),
                last_sync: 1_700_000_100,
                ..Default::default()
            },
            ReplicationStatus {
                id: "200-0".into(),
                last_sync: 1_700_000_200,
                ..Default::default()
            },
        ];
        assert_eq!(
            summarise_replication_health(&s, now, 900),
            ReplicationHealth::Healthy
        );
    }

    #[test]
    fn summary_health_empty_is_healthy() {
        assert_eq!(
            summarise_replication_health(&[], 1_700_000_000, 900),
            ReplicationHealth::Healthy
        );
    }
}
