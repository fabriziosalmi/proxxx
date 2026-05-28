use serde::{Deserialize, Serialize};

use super::deserialize_bool_from_int;

/// HA group definition. Returned by `GET /cluster/ha/groups`.
///
/// The `nodes` field is Proxmox-encoded as a comma-separated list with
/// optional `:priority` suffixes per node, e.g. `"pve1:2,pve2:1,pve3"`.
/// Higher priority = preferred. We parse it into structured form via
/// `parse_priority_list()`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HaGroup {
    #[serde(rename = "group")]
    pub name: String,
    #[serde(default)]
    pub nodes: String,
    /// If true, resources can only run on nodes in `nodes` list.
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub restricted: bool,
    /// If true, don't auto-fall-back when the preferred node returns.
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub nofailback: bool,
    #[serde(default)]
    pub comment: String,
}

impl HaGroup {
    /// Parse the `nodes` field into `(node_name, priority)` pairs.
    /// Default priority when the suffix is absent is 0 — same as Proxmox.
    /// Output is stable: sorted by descending priority then name.
    #[must_use]
    pub fn parse_priority_list(&self) -> Vec<(String, i32)> {
        let mut out: Vec<(String, i32)> = self
            .nodes
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|piece| {
                if let Some((n, p)) = piece.split_once(':') {
                    let prio = p.trim().parse::<i32>().unwrap_or(0);
                    (n.trim().to_string(), prio)
                } else {
                    (piece.to_string(), 0)
                }
            })
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HaRule {
    /// Rule identifier (the URL last-segment). Operator-chosen on create
    /// — readable names like `keep-db-on-pve1`, `web-spread-cluster-a`.
    pub rule: String,
    /// `"node-affinity"` or `"resource-affinity"`. Future PVE versions
    /// may add more; consumers should default-handle unknown types.
    #[serde(rename = "type")]
    pub rule_type: String,
    /// Comma-separated HA SIDs the rule binds, e.g. `"vm:100,ct:200"`.
    /// Parse with `parse_resource_list()` for structured access.
    #[serde(default)]
    pub resources: String,
    /// Free-text comment.
    #[serde(default)]
    pub comment: String,
    /// 1 = rule defined but inactive (CRM ignores it).
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub disable: bool,
    /// Server-generated config digest. Used as the `digest=` param on PUT
    /// for optimistic concurrency; empty (or default) means "don't check".
    #[serde(default)]
    pub digest: String,

    // ── node-affinity specific ─────────────────────────────────────
    /// Target-node list, comma-separated with optional `:priority`
    /// suffixes (`pve1:5,pve2`). Only meaningful when
    /// `rule_type == "node-affinity"`. Parse with
    /// `parse_priority_list()` for structured access.
    #[serde(default)]
    pub nodes: String,
    /// 1 = resources must run on `nodes` (no fallback). 0 = `nodes` is a
    /// preference; other nodes can host on failure. Only meaningful for
    /// `node-affinity`.
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub strict: bool,

    // ── resource-affinity specific ─────────────────────────────────
    /// `"positive"` (collocate) or `"negative"` (anti-collocate). Only
    /// meaningful for `rule_type == "resource-affinity"`.
    #[serde(default)]
    pub affinity: String,
}

impl HaRule {
    /// Parse `resources` (`"vm:100,ct:200"`) into a sorted, de-duplicated
    /// `Vec<String>`. Empty input → empty Vec.
    #[must_use]
    pub fn parse_resource_list(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .resources
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Parse `nodes` (`"pve1:5,pve2,pve3:2"`) into `(name, priority)`
    /// pairs (priority defaults to 0 when no suffix), sorted by
    /// descending priority then name — same ordering as `HaGroup`.
    #[must_use]
    pub fn parse_priority_list(&self) -> Vec<(String, i32)> {
        let mut out: Vec<(String, i32)> = self
            .nodes
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|piece| {
                if let Some((n, p)) = piece.split_once(':') {
                    let prio = p.trim().parse::<i32>().unwrap_or(0);
                    (n.trim().to_string(), prio)
                } else {
                    (piece.to_string(), 0)
                }
            })
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HaResource {
    /// Service ID, e.g. `"vm:100"` or `"ct:200"`.
    pub sid: String,
    #[serde(default)]
    pub group: String,
    /// Desired state: `"started"` or `"stopped"` or `"disabled"`.
    #[serde(default)]
    pub state: String,
    /// Max number of restart attempts before giving up.
    #[serde(default)]
    pub max_restart: u32,
    /// Max number of relocations to other nodes.
    #[serde(default)]
    pub max_relocate: u32,
    #[serde(default)]
    pub comment: String,
}

impl HaResource {
    /// Extract the VMID portion of the SID (`"vm:100"` → 100).
    /// Returns None for malformed SIDs.
    #[must_use]
    pub fn vmid(&self) -> Option<u32> {
        self.sid
            .split_once(':')
            .and_then(|(_, n)| n.parse::<u32>().ok())
    }

    /// `"vm"` or `"ct"` from the SID prefix.
    #[must_use]
    pub fn kind(&self) -> &str {
        self.sid.split_once(':').map_or("", |(k, _)| k)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HaManagerStatus {
    /// Active master node name (the one running pve-ha-manager).
    #[serde(default)]
    pub master: String,
    /// `"active"`, `"unsafe"`, etc. — `unsafe` means quorum lost.
    #[serde(default)]
    pub mode: String,
    /// Per-node service runtime states (key = node, value = state).
    /// Proxmox returns `node_status` as a map; we keep it flat here.
    #[serde(default)]
    pub node_status: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct HaStatusEntry {
    /// `id` is the row key — `node/<name>`, `service:<sid>`, `master`.
    pub id: String,
    /// `node` | `service` | `master` | `quorum` (PVE-version-dependent).
    #[serde(rename = "type")]
    pub entry_type: String,
    /// Node name on `type=node` and `type=service` rows; absent on master/quorum.
    pub node: String,
    /// Service id (`vm:100`) on `type=service` rows.
    pub sid: String,
    /// Current state — for nodes: `online|offline|unknown|fence|maintenance`;
    /// for services: `started|stopped|error|fence|migrate|relocate|recovery`.
    pub status: String,
    /// Free-form status text from PVE (e.g. quorum messages).
    #[serde(rename = "crm_state")]
    pub crm_state: String,
    /// Quorate flag on the quorum/master row. PVE serializes 0/1.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub quorate: bool,
    /// On service rows, which group it belongs to.
    pub group: String,
    /// Free-form text — error message on failed services, etc.
    pub timestamp: u64,
}

#[cfg(test)]
mod ha_tests {
    use super::*;

    #[test]
    fn ha_group_priority_list_parses_full_form() {
        let g = HaGroup {
            name: "g1".into(),
            nodes: "pve1:2,pve2:1,pve3".into(),
            restricted: false,
            nofailback: false,
            comment: String::new(),
        };
        let parsed = g.parse_priority_list();
        // Sorted descending priority: pve1(2), pve2(1), pve3(0)
        assert_eq!(parsed[0], ("pve1".to_string(), 2));
        assert_eq!(parsed[1], ("pve2".to_string(), 1));
        assert_eq!(parsed[2], ("pve3".to_string(), 0));
    }

    #[test]
    fn ha_group_priority_list_handles_whitespace_and_empty() {
        let g = HaGroup {
            name: "g".into(),
            nodes: " pve1:5 , , pve2 ".into(),
            restricted: true,
            nofailback: false,
            comment: String::new(),
        };
        let parsed = g.parse_priority_list();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "pve1");
        assert_eq!(parsed[0].1, 5);
        assert_eq!(parsed[1].0, "pve2");
    }

    #[test]
    fn ha_group_priority_list_empty_nodes() {
        let g = HaGroup {
            name: "g".into(),
            nodes: String::new(),
            restricted: false,
            nofailback: false,
            comment: String::new(),
        };
        assert!(g.parse_priority_list().is_empty());
    }

    #[test]
    fn ha_resource_parses_sid() {
        let r = HaResource {
            sid: "vm:100".into(),
            group: String::new(),
            state: "started".into(),
            max_restart: 1,
            max_relocate: 1,
            comment: String::new(),
        };
        assert_eq!(r.vmid(), Some(100));
        assert_eq!(r.kind(), "vm");

        let ct = HaResource {
            sid: "ct:200".into(),
            group: String::new(),
            state: "started".into(),
            max_restart: 1,
            max_relocate: 1,
            comment: String::new(),
        };
        assert_eq!(ct.vmid(), Some(200));
        assert_eq!(ct.kind(), "ct");

        let bad = HaResource {
            sid: "garbage".into(),
            group: String::new(),
            state: String::new(),
            max_restart: 0,
            max_relocate: 0,
            comment: String::new(),
        };
        assert_eq!(bad.vmid(), None);
        assert_eq!(bad.kind(), "");
    }
}
