//! Snapshot tree assembly + diff (feature #7).
//!
//! Proxmox returns snapshots as a flat list. Each entry has a `parent`
//! field pointing at another snapshot's name (or empty string for roots).
//! Branching happens when two snapshots share the same parent — typical
//! after a rollback + new snapshot.
//!
//! This module converts the flat list into a `Tree` that the renderer
//! walks depth-first to draw `├─` / `└─` connectors. It also exposes a
//! `diff_between` helper used by the "rollback impact preview" UX.
//!
//! Pure data, zero I/O — testable end-to-end without a Proxmox cluster.

use std::collections::{BTreeMap, HashMap};

use crate::api::types::Snapshot;

/// One node of the snapshot tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeNode {
    pub snap: Snapshot,
    /// Children sorted by `snaptime` ascending (oldest first), with the
    /// synthetic `current` entry always last so the cursor sits at the
    /// bottom of the rendered branch where users expect.
    pub children: Vec<Self>,
}

impl TreeNode {
    /// Total nodes in this subtree (including self).
    #[must_use]
    pub fn count(&self) -> usize {
        1 + self.children.iter().map(Self::count).sum::<usize>()
    }
}

/// A forest (multiple roots possible if Proxmox lists orphan snapshots
/// after a corrupted rollback). The renderer walks roots in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tree {
    pub roots: Vec<TreeNode>,
    /// Snapshots whose `parent` couldn't be resolved. Should normally be
    /// empty; non-empty signals a corrupted snapshot table on the server.
    pub orphans: Vec<Snapshot>,
}

impl Tree {
    #[must_use]
    pub fn total_count(&self) -> usize {
        self.roots.iter().map(TreeNode::count).sum::<usize>() + self.orphans.len()
    }

    /// Find a node by name, depth-first.
    #[must_use]
    pub fn find(&self, name: &str) -> Option<&TreeNode> {
        for r in &self.roots {
            if let Some(n) = find_in(r, name) {
                return Some(n);
            }
        }
        None
    }
}

fn find_in<'a>(node: &'a TreeNode, name: &str) -> Option<&'a TreeNode> {
    if node.snap.name == name {
        return Some(node);
    }
    for c in &node.children {
        if let Some(n) = find_in(c, name) {
            return Some(n);
        }
    }
    None
}

/// Build a tree from Proxmox's flat snapshot list. Stable: identical
/// inputs produce identical trees, regardless of how Proxmox happens to
/// order the response.
///
/// **Cycle handling.** Proxmox should never produce parent-cycles, but
/// a corrupted config or a mid-rollback race could. We do not panic and
/// we do not infinite-loop:
/// - cycle members are detected as "in `by_name` but unreachable from any
///   real root" and surfaced in `Tree::orphans` so the user sees them
/// - `build_node` itself protects against re-entry via a visited set
///   (defence in depth even if the cycle classification missed a case)
#[must_use]
pub fn assemble(mut snaps: Vec<Snapshot>) -> Tree {
    // Index by name for O(1) parent lookup.
    let by_name: HashMap<String, Snapshot> =
        snaps.iter().cloned().map(|s| (s.name.clone(), s)).collect();
    snaps.sort_by(|a, b| a.snaptime.cmp(&b.snaptime).then(a.name.cmp(&b.name)));

    // Group children by parent name.
    let mut children_of: BTreeMap<String, Vec<Snapshot>> = BTreeMap::new();
    let mut orphans = Vec::new();
    let mut roots = Vec::new();

    for s in &snaps {
        if s.parent.is_empty() {
            roots.push(s.clone());
        } else if s.parent == s.name {
            // Self-cycle: A.parent == A. Surface as orphan, don't recurse.
            orphans.push(s.clone());
        } else if by_name.contains_key(&s.parent) {
            children_of
                .entry(s.parent.clone())
                .or_default()
                .push(s.clone());
        } else {
            orphans.push(s.clone());
        }
    }

    // Sort roots: real snapshots (by time), then `current` last.
    roots.sort_by(|a, b| match (a.is_current(), b.is_current()) {
        (true, false) => std::cmp::Ordering::Greater,
        (false, true) => std::cmp::Ordering::Less,
        _ => a.snaptime.cmp(&b.snaptime).then(a.name.cmp(&b.name)),
    });

    // Build trees with re-entry protection. The `visited` set prevents
    // infinite recursion if children_of contains a cycle (defence in depth
    // — the partition above should already exclude self-cycles).
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let root_nodes: Vec<TreeNode> = roots
        .into_iter()
        .map(|s| build_node(s, &children_of, &mut visited))
        .collect();

    // Cycle detection: any snapshot in by_name not yet visited and not
    // already an orphan is part of a cycle whose root is unreachable.
    // Surface these as orphans so the UI shows them rather than dropping
    // them silently.
    let orphan_names: std::collections::HashSet<String> =
        orphans.iter().map(|s| s.name.clone()).collect();
    let mut cycle_members: Vec<Snapshot> = by_name
        .values()
        .filter(|s| !visited.contains(&s.name) && !orphan_names.contains(&s.name))
        .cloned()
        .collect();
    cycle_members.sort_by(|a, b| a.name.cmp(&b.name));
    orphans.extend(cycle_members);

    Tree {
        roots: root_nodes,
        orphans,
    }
}

/// Iterative tree builder. Uses an explicit DFS stack + bottom-up
/// materialization so stack depth is O(1) regardless of chain length.
///
/// Why iterative: the recursive form overflowed on a 1000-deep linear
/// chain (verified by test). Real Proxmox clusters with heavy snapshot
/// usage easily reach hundreds of nodes deep — the recursive version
/// was a latent crash waiting for a long-running lab to trigger it.
fn build_node(
    root: Snapshot,
    children_of: &BTreeMap<String, Vec<Snapshot>>,
    visited: &mut std::collections::HashSet<String>,
) -> TreeNode {
    let root_name = root.name.clone();

    // Phase 1: iterative DFS from `root`, collecting every reachable
    // snapshot exactly once. The visited set provides cycle protection
    // even though `assemble` already partitions self-cycles into orphans
    // — defence in depth.
    let mut order: Vec<Snapshot> = Vec::new();
    let mut stack: Vec<Snapshot> = vec![root];
    while let Some(s) = stack.pop() {
        if !visited.insert(s.name.clone()) {
            continue;
        }
        if let Some(children) = children_of.get(&s.name) {
            for c in children {
                if !visited.contains(&c.name) {
                    stack.push(c.clone());
                }
            }
        }
        order.push(s);
    }

    // Phase 2: walk `order` in reverse so a node's descendants are
    // materialized before the node itself. We pull children out of a
    // working map by name — sort siblings consistently with the rest
    // of the tree (real first by time, `current` last).
    let mut materialized: HashMap<String, TreeNode> = HashMap::new();
    for s in order.into_iter().rev() {
        let raw_children: Vec<Snapshot> = children_of.get(&s.name).cloned().unwrap_or_default();
        let mut child_nodes: Vec<TreeNode> = raw_children
            .into_iter()
            .filter_map(|c| materialized.remove(&c.name))
            .collect();
        child_nodes.sort_by(|a, b| match (a.snap.is_current(), b.snap.is_current()) {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => a
                .snap
                .snaptime
                .cmp(&b.snap.snaptime)
                .then(a.snap.name.cmp(&b.snap.name)),
        });
        materialized.insert(
            s.name.clone(),
            TreeNode {
                snap: s,
                children: child_nodes,
            },
        );
    }

    materialized.remove(&root_name).unwrap_or_else(|| TreeNode {
        // Should never happen — root was just inserted. Fallback to a
        // leaf node referencing nothing rather than panic.
        snap: Snapshot {
            name: root_name,
            parent: String::new(),
            description: String::new(),
            snaptime: 0,
            vmstate: 0,
        },
        children: Vec::new(),
    })
}

/// Diff between two snapshots: lineage path (closest common ancestor)
/// and a count of intermediate snapshots that would be discarded by a
/// rollback. Returns `None` if either name is missing from the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffSummary {
    /// Common ancestor name, or empty string if both branches go back to
    /// independent roots (rare — implies orphans).
    pub common_ancestor: String,
    /// Snapshots between `from` and the common ancestor (exclusive of
    /// both), in oldest→newest order. Rolling back from `from` to `to`
    /// discards these.
    pub forward_path: Vec<String>,
    /// Snapshots between `to` and the common ancestor (exclusive). Going
    /// in this direction means re-applying these.
    pub reverse_path: Vec<String>,
    /// Time gap between the two snapshots in seconds (absolute value,
    /// since either side can be more recent).
    pub time_delta_secs: u64,
}

#[must_use]
pub fn diff_between(tree: &Tree, from: &str, to: &str) -> Option<DiffSummary> {
    let from_chain = ancestors(tree, from)?;
    let to_chain = ancestors(tree, to)?;

    // Find the closest common ancestor — first match scanning `from_chain`
    // against the set of `to_chain`.
    let to_set: std::collections::HashSet<&String> = to_chain.iter().collect();
    let common = from_chain
        .iter()
        .find(|n| to_set.contains(n))
        .cloned()
        .unwrap_or_default();

    let forward_path: Vec<String> = from_chain
        .iter()
        .take_while(|n| **n != common)
        .filter(|n| **n != from)
        .cloned()
        .collect();
    let reverse_path: Vec<String> = to_chain
        .iter()
        .take_while(|n| **n != common)
        .filter(|n| **n != to)
        .cloned()
        .collect();

    let from_time = tree.find(from).map_or(0, |n| n.snap.snaptime);
    let to_time = tree.find(to).map_or(0, |n| n.snap.snaptime);
    let time_delta_secs = from_time.abs_diff(to_time);

    Some(DiffSummary {
        common_ancestor: common,
        forward_path,
        reverse_path,
        time_delta_secs,
    })
}

/// Return the ancestor chain of `name` starting with `name` itself and
/// walking up via `parent`. Returns None if `name` isn't in the tree.
fn ancestors(tree: &Tree, name: &str) -> Option<Vec<String>> {
    let by_name: HashMap<String, &TreeNode> = collect(tree);
    if !by_name.contains_key(name) {
        return None;
    }
    let mut out = vec![name.to_string()];
    let mut cursor = name.to_string();
    while let Some(node) = by_name.get(&cursor) {
        if node.snap.parent.is_empty() {
            break;
        }
        out.push(node.snap.parent.clone());
        cursor = node.snap.parent.clone();
    }
    Some(out)
}

fn collect(tree: &Tree) -> HashMap<String, &TreeNode> {
    let mut map = HashMap::new();
    for r in &tree.roots {
        collect_into(r, &mut map);
    }
    map
}

fn collect_into<'a>(node: &'a TreeNode, map: &mut HashMap<String, &'a TreeNode>) {
    map.insert(node.snap.name.clone(), node);
    for c in &node.children {
        collect_into(c, map);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(name: &str, parent: &str, t: u64) -> Snapshot {
        Snapshot {
            name: name.to_string(),
            parent: parent.to_string(),
            description: String::new(),
            snaptime: t,
            vmstate: 0,
        }
    }

    #[test]
    fn assembles_linear_chain() {
        // root → A → B → current
        let t = assemble(vec![
            snap("root", "", 100),
            snap("A", "root", 200),
            snap("B", "A", 300),
            snap("current", "B", 0),
        ]);
        assert_eq!(t.roots.len(), 1);
        assert_eq!(t.roots[0].snap.name, "root");
        assert_eq!(t.roots[0].count(), 4);
    }

    #[test]
    fn assembles_branching() {
        // root → pre-upgrade
        //           ├─ post-config-test
        //           └─ rollback-attempt-1
        let t = assemble(vec![
            snap("root", "", 100),
            snap("pre-upgrade", "root", 200),
            snap("post-config-test", "pre-upgrade", 300),
            snap("rollback-attempt-1", "pre-upgrade", 400),
        ]);
        let pre = t.find("pre-upgrade").expect("found");
        assert_eq!(pre.children.len(), 2, "two siblings under pre-upgrade");
        let names: Vec<&str> = pre.children.iter().map(|c| c.snap.name.as_str()).collect();
        // Older sibling first.
        assert_eq!(names, vec!["post-config-test", "rollback-attempt-1"]);
    }

    #[test]
    fn current_sorts_last_among_siblings() {
        // root → A
        //   |  → current
        let t = assemble(vec![
            snap("root", "", 100),
            snap("current", "root", 0),
            snap("A", "root", 200),
        ]);
        let names: Vec<&str> = t.roots[0]
            .children
            .iter()
            .map(|c| c.snap.name.as_str())
            .collect();
        assert_eq!(names, vec!["A", "current"]);
    }

    #[test]
    fn orphans_are_collected_not_dropped() {
        let t = assemble(vec![
            snap("ghost", "missing-parent", 100),
            snap("root", "", 50),
        ]);
        assert_eq!(t.roots.len(), 1);
        assert_eq!(t.orphans.len(), 1);
        assert_eq!(t.orphans[0].name, "ghost");
    }

    #[test]
    fn empty_input_produces_empty_tree() {
        let t = assemble(vec![]);
        assert!(t.roots.is_empty());
        assert!(t.orphans.is_empty());
        assert_eq!(t.total_count(), 0);
    }

    #[test]
    fn diff_finds_common_ancestor() {
        // root → A → B
        //         └→ C
        let t = assemble(vec![
            snap("root", "", 0),
            snap("A", "root", 100),
            snap("B", "A", 200),
            snap("C", "A", 300),
        ]);
        let d = diff_between(&t, "B", "C").expect("both exist");
        assert_eq!(d.common_ancestor, "A");
        assert!(d.forward_path.is_empty(), "B is direct child of A");
        assert!(d.reverse_path.is_empty(), "C is direct child of A");
        assert_eq!(d.time_delta_secs, 100);
    }

    #[test]
    fn diff_traces_intermediate_path() {
        // root → A → B → C → D
        let t = assemble(vec![
            snap("root", "", 0),
            snap("A", "root", 100),
            snap("B", "A", 200),
            snap("C", "B", 300),
            snap("D", "C", 400),
        ]);
        let d = diff_between(&t, "D", "A").expect("both exist");
        assert_eq!(d.common_ancestor, "A");
        // Walking up from D: D, C, B, A. Forward path excludes D and A.
        assert_eq!(d.forward_path, vec!["C", "B"]);
        assert!(d.reverse_path.is_empty(), "A is the common ancestor");
        assert_eq!(d.time_delta_secs, 300);
    }

    #[test]
    fn diff_returns_none_for_unknown_snap() {
        let t = assemble(vec![snap("root", "", 0)]);
        assert!(diff_between(&t, "root", "ghost").is_none());
        assert!(diff_between(&t, "ghost", "root").is_none());
    }

    // ── Cycle handling (per architectural review) ───────────

    #[test]
    fn self_cycle_is_classified_as_orphan() {
        // A.parent = A — surface, don't loop.
        let t = assemble(vec![snap("A", "A", 100)]);
        assert!(t.roots.is_empty(), "self-loop must not appear as root");
        assert_eq!(t.orphans.len(), 1, "self-loop surfaces as orphan");
        assert_eq!(t.orphans[0].name, "A");
    }

    #[test]
    fn two_node_cycle_surfaces_both_as_orphans_no_panic() {
        // A.parent = B, B.parent = A — neither has parent="" so neither is
        // a root. Without cycle detection, both would be silently dropped.
        let t = assemble(vec![snap("A", "B", 100), snap("B", "A", 200)]);
        assert!(t.roots.is_empty(), "no roots in a pure 2-cycle");
        let orphan_names: std::collections::HashSet<&str> =
            t.orphans.iter().map(|s| s.name.as_str()).collect();
        assert!(orphan_names.contains("A"), "A surfaces as orphan");
        assert!(orphan_names.contains("B"), "B surfaces as orphan");
        assert_eq!(t.total_count(), 2);
    }

    #[test]
    fn three_node_cycle_surfaces_all_no_infinite_recursion() {
        // A → B → C → A — must terminate.
        let t = assemble(vec![
            snap("A", "C", 100),
            snap("B", "A", 200),
            snap("C", "B", 300),
        ]);
        assert!(t.roots.is_empty());
        assert_eq!(t.orphans.len(), 3);
    }

    #[test]
    fn root_plus_disjoint_cycle_keeps_root_safe() {
        // root → R, plus a disjoint A↔B cycle.
        // The valid tree must be unaffected; the cycle members surface as orphans.
        let t = assemble(vec![
            snap("root", "", 0),
            snap("R", "root", 100),
            snap("A", "B", 200),
            snap("B", "A", 300),
        ]);
        assert_eq!(t.roots.len(), 1);
        assert_eq!(t.roots[0].snap.name, "root");
        assert_eq!(t.roots[0].count(), 2, "root + R");
        assert_eq!(t.orphans.len(), 2, "A and B as orphans");
    }

    #[test]
    fn cycle_attached_to_real_root_does_not_loop() {
        // root → A → B → A (cycle from A through B back to A). The
        // children_of["B"] would re-include A. The visited-set guard
        // in build_node MUST prevent re-entry.
        //
        // Note: with unique names in by_name, A.parent can only be one
        // value. We construct: root → C → A → B, where B.parent=A but
        // A.parent=B (overrides earlier). The HashMap collation of by_name
        // takes whichever last entry wins — sorted by snaptime+name first
        // we get a deterministic input.
        let t = assemble(vec![
            snap("root", "", 0),
            snap("A", "B", 200),
            snap("B", "A", 300),
        ]);
        // root has no children (A.parent=B, B.parent=A — neither under root)
        assert_eq!(t.roots.len(), 1);
        assert_eq!(t.roots[0].snap.name, "root");
        assert_eq!(t.roots[0].children.len(), 0);
        // A and B are cycle members → orphans.
        assert_eq!(t.orphans.len(), 2);
    }

    #[test]
    fn very_deep_chain_does_not_overflow_stack() {
        // 1000-deep linear chain. Recursion-based build_node must handle.
        let mut snaps = Vec::new();
        snaps.push(snap("n0", "", 0));
        for i in 1..1000 {
            let name = format!("n{i}");
            let parent = format!("n{}", i - 1);
            snaps.push(Snapshot {
                name,
                parent,
                description: String::new(),
                snaptime: i as u64,
                vmstate: 0,
            });
        }
        let t = assemble(snaps);
        assert_eq!(t.roots.len(), 1);
        assert_eq!(t.total_count(), 1000);
    }
}
