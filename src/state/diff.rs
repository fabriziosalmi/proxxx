//! Structural diff between two [`ClusterState`] values.
//!
//! Pure functional: `diff(declared, live)` returns a [`Vec<Change>`]
//! describing what the apply layer would need to do to converge
//! `live` toward `declared`. No I/O, no side effects, fully unit-
//! testable.
//!
//! ## Semantics
//!
//! For each resource family present in either `declared` or `live`:
//! * **Create** — identity exists in `declared` but not `live`.
//! * **Update** — identity exists in both but the value differs.
//! * **Delete** — identity exists in `live` but not `declared`.
//!
//! All three kinds are always computed; the apply layer chooses
//! which subset to actually execute (e.g. `apply` without `--prune`
//! skips `Delete` changes by policy, surfacing them as warnings).
//!
//! ## Identity keys
//!
//! Each resource has a stable PVE-side identity:
//! * Pool — `poolid`
//! * ACL — `(path, kind, ugid, roleid)` 4-tuple, rendered as
//!   `"<path>:<kind>/<ugid>/<roleid>"` for display
//! * Storage — `storage` (the operator-chosen id)
//! * Backup job — `id` (the job id, operator- or PVE-assigned)
//! * Firewall options — singleton (rendered identity `"cluster"`);
//!   only ever an Update, never create/delete
//! * Firewall alias / IP set — `name`
//! * Firewall security group — `group` (create/delete only)
//! * Notification matcher — `name`
//!
//! Update detection compares the full `*Decl` value with `PartialEq`
//! — every non-identity field is part of the value. Touching any
//! one (e.g. flipping `propagate` on an ACL grant, adding a member
//! to a pool, enabling `shared` on a storage) produces exactly one
//! Update for that identity.

use serde::Serialize;

use crate::state::model::{
    AclDecl, BackupJobDecl, ClusterState, FirewallAliasDecl, FirewallGroupDecl, FirewallIpsetDecl,
    FirewallOptionsDecl, HaRuleDecl, NotificationMatcherDecl, PoolDecl, StorageDecl,
};

/// Kind of mutation a change represents. `Create` + `Delete` are
/// self-evident; `Update` is "identity matches, value differs".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ChangeKind {
    Create,
    Update,
    Delete,
}

/// One structural difference between declared and live state.
///
/// The `resource` field is a stable lowercase string (`"pool"`,
/// `"acl"`, `"storage"`) — useful for filtering / grouping in the
/// JSON output. `identity` is a single string rendering of the
/// PVE-side identity key, chosen to be human-grep'able. `before`
/// and `after` carry the full per-resource value as JSON; the apply
/// layer reads these to perform the actual PVE API calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Change {
    pub kind: ChangeKind,
    /// `"pool"` | `"acl"` | `"storage"` — stable lowercase.
    pub resource: &'static str,
    /// Display identity: `"<poolid>"` for pools, `"<path> [<kind>/<ugid>] <roleid>"`
    /// for ACL, `"<storage>"` for storage.
    pub identity: String,
    /// Pre-change state. `None` on `Create`. For `Update` and
    /// `Delete` it carries the full live value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    /// Post-change state. `None` on `Delete`. For `Update` and
    /// `Create` it carries the full declared value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
}

/// Diff two cluster states. Returns every difference (create + update
/// + delete) across all resource families. Caller filters by `kind`
/// to enforce `--prune` semantics.
///
/// The output order is stable: changes for `pool` first, then `acl`,
/// then `storage`, then `backup_job`, then the firewall families
/// (`firewall_options`, `firewall_alias`, `firewall_ipset`,
/// `firewall_group`), then `notification_matcher`, each sorted by
/// identity. Within a family the order is `Delete` (so apply-with-prune
/// teardown runs before create), then `Update`, then `Create` — but the
/// apply layer re-orders by dependency where needed.
#[must_use]
pub fn diff(declared: &ClusterState, live: &ClusterState) -> Vec<Change> {
    let mut out = Vec::new();
    diff_pools(&declared.pools, &live.pools, &mut out);
    diff_acl(&declared.acl, &live.acl, &mut out);
    diff_storage(&declared.storage, &live.storage, &mut out);
    diff_backup_jobs(&declared.backup_jobs, &live.backup_jobs, &mut out);
    diff_firewall_options(
        declared.firewall_options.as_ref(),
        live.firewall_options.as_ref(),
        &mut out,
    );
    diff_firewall_aliases(&declared.firewall_aliases, &live.firewall_aliases, &mut out);
    diff_firewall_ipsets(&declared.firewall_ipsets, &live.firewall_ipsets, &mut out);
    diff_firewall_groups(&declared.firewall_groups, &live.firewall_groups, &mut out);
    diff_notification_matchers(
        &declared.notification_matchers,
        &live.notification_matchers,
        &mut out,
    );
    diff_ha_rules(&declared.ha_rules, &live.ha_rules, &mut out);
    out
}

fn diff_pools(declared: &[PoolDecl], live: &[PoolDecl], out: &mut Vec<Change>) {
    use std::collections::HashMap;
    let live_by: HashMap<&str, &PoolDecl> = live.iter().map(|p| (p.poolid.as_str(), p)).collect();
    let decl_by: HashMap<&str, &PoolDecl> =
        declared.iter().map(|p| (p.poolid.as_str(), p)).collect();

    // Delete first (Vec::push order; the caller filters by kind).
    let mut deletes: Vec<_> = live_by
        .keys()
        .filter(|k| !decl_by.contains_key(*k))
        .collect();
    deletes.sort_unstable();
    for k in deletes {
        let live_p = live_by[k];
        out.push(Change {
            kind: ChangeKind::Delete,
            resource: "pool",
            identity: (*k).to_string(),
            before: serde_json::to_value(live_p).ok(),
            after: None,
        });
    }

    // Updates (both sides have the identity, values differ).
    let mut updates: Vec<_> = decl_by
        .keys()
        .filter(|k| live_by.get(*k).is_some_and(|live_p| *live_p != decl_by[*k]))
        .collect();
    updates.sort_unstable();
    for k in updates {
        let live_p = live_by[k];
        let decl_p = decl_by[k];
        out.push(Change {
            kind: ChangeKind::Update,
            resource: "pool",
            identity: (*k).to_string(),
            before: serde_json::to_value(live_p).ok(),
            after: serde_json::to_value(decl_p).ok(),
        });
    }

    // Creates (in declared, not in live).
    let mut creates: Vec<_> = decl_by
        .keys()
        .filter(|k| !live_by.contains_key(*k))
        .collect();
    creates.sort_unstable();
    for k in creates {
        let decl_p = decl_by[k];
        out.push(Change {
            kind: ChangeKind::Create,
            resource: "pool",
            identity: (*k).to_string(),
            before: None,
            after: serde_json::to_value(decl_p).ok(),
        });
    }
}

fn diff_acl(declared: &[AclDecl], live: &[AclDecl], out: &mut Vec<Change>) {
    use std::collections::HashMap;

    // ACL identity is a 4-tuple. Use a struct-keyed map.
    let identity = |a: &AclDecl| {
        (
            a.path.clone(),
            a.kind.clone(),
            a.ugid.clone(),
            a.roleid.clone(),
        )
    };
    let identity_display = |a: &AclDecl| format!("{} [{}/{}] {}", a.path, a.kind, a.ugid, a.roleid);

    let live_by: HashMap<_, &AclDecl> = live.iter().map(|a| (identity(a), a)).collect();
    let decl_by: HashMap<_, &AclDecl> = declared.iter().map(|a| (identity(a), a)).collect();

    let mut delete_keys: Vec<_> = live_by
        .keys()
        .filter(|k| !decl_by.contains_key(*k))
        .collect();
    delete_keys.sort();
    for k in delete_keys {
        let live_a = live_by[k];
        out.push(Change {
            kind: ChangeKind::Delete,
            resource: "acl",
            identity: identity_display(live_a),
            before: serde_json::to_value(live_a).ok(),
            after: None,
        });
    }

    let mut update_keys: Vec<_> = decl_by
        .keys()
        .filter(|k| live_by.get(*k).is_some_and(|live_a| *live_a != decl_by[*k]))
        .collect();
    update_keys.sort();
    for k in update_keys {
        let live_a = live_by[k];
        let decl_a = decl_by[k];
        out.push(Change {
            kind: ChangeKind::Update,
            resource: "acl",
            identity: identity_display(decl_a),
            before: serde_json::to_value(live_a).ok(),
            after: serde_json::to_value(decl_a).ok(),
        });
    }

    let mut create_keys: Vec<_> = decl_by
        .keys()
        .filter(|k| !live_by.contains_key(*k))
        .collect();
    create_keys.sort();
    for k in create_keys {
        let decl_a = decl_by[k];
        out.push(Change {
            kind: ChangeKind::Create,
            resource: "acl",
            identity: identity_display(decl_a),
            before: None,
            after: serde_json::to_value(decl_a).ok(),
        });
    }
}

fn diff_storage(declared: &[StorageDecl], live: &[StorageDecl], out: &mut Vec<Change>) {
    use std::collections::HashMap;
    let live_by: HashMap<&str, &StorageDecl> =
        live.iter().map(|s| (s.storage.as_str(), s)).collect();
    let decl_by: HashMap<&str, &StorageDecl> =
        declared.iter().map(|s| (s.storage.as_str(), s)).collect();

    let mut deletes: Vec<_> = live_by
        .keys()
        .filter(|k| !decl_by.contains_key(*k))
        .collect();
    deletes.sort_unstable();
    for k in deletes {
        let live_s = live_by[k];
        out.push(Change {
            kind: ChangeKind::Delete,
            resource: "storage",
            identity: (*k).to_string(),
            before: serde_json::to_value(live_s).ok(),
            after: None,
        });
    }

    let mut updates: Vec<_> = decl_by
        .keys()
        .filter(|k| live_by.get(*k).is_some_and(|live_s| *live_s != decl_by[*k]))
        .collect();
    updates.sort_unstable();
    for k in updates {
        let live_s = live_by[k];
        let decl_s = decl_by[k];
        out.push(Change {
            kind: ChangeKind::Update,
            resource: "storage",
            identity: (*k).to_string(),
            before: serde_json::to_value(live_s).ok(),
            after: serde_json::to_value(decl_s).ok(),
        });
    }

    let mut creates: Vec<_> = decl_by
        .keys()
        .filter(|k| !live_by.contains_key(*k))
        .collect();
    creates.sort_unstable();
    for k in creates {
        let decl_s = decl_by[k];
        out.push(Change {
            kind: ChangeKind::Create,
            resource: "storage",
            identity: (*k).to_string(),
            before: None,
            after: serde_json::to_value(decl_s).ok(),
        });
    }
}

fn diff_backup_jobs(declared: &[BackupJobDecl], live: &[BackupJobDecl], out: &mut Vec<Change>) {
    use std::collections::HashMap;
    let live_by: HashMap<&str, &BackupJobDecl> = live.iter().map(|j| (j.id.as_str(), j)).collect();
    let decl_by: HashMap<&str, &BackupJobDecl> =
        declared.iter().map(|j| (j.id.as_str(), j)).collect();

    let mut deletes: Vec<_> = live_by
        .keys()
        .filter(|k| !decl_by.contains_key(*k))
        .collect();
    deletes.sort_unstable();
    for k in deletes {
        out.push(Change {
            kind: ChangeKind::Delete,
            resource: "backup_job",
            identity: (*k).to_string(),
            before: serde_json::to_value(live_by[k]).ok(),
            after: None,
        });
    }

    let mut updates: Vec<_> = decl_by
        .keys()
        .filter(|k| live_by.get(*k).is_some_and(|live_j| *live_j != decl_by[*k]))
        .collect();
    updates.sort_unstable();
    for k in updates {
        out.push(Change {
            kind: ChangeKind::Update,
            resource: "backup_job",
            identity: (*k).to_string(),
            before: serde_json::to_value(live_by[k]).ok(),
            after: serde_json::to_value(decl_by[k]).ok(),
        });
    }

    let mut creates: Vec<_> = decl_by
        .keys()
        .filter(|k| !live_by.contains_key(*k))
        .collect();
    creates.sort_unstable();
    for k in creates {
        out.push(Change {
            kind: ChangeKind::Create,
            resource: "backup_job",
            identity: (*k).to_string(),
            before: None,
            after: serde_json::to_value(decl_by[k]).ok(),
        });
    }
}

/// Diff the firewall options singleton. Unlike the list families this
/// has no create/delete — the firewall always has exactly one options
/// object. A `None` declared value means "don't manage" (no change). A
/// `Some` declared value that differs from live yields one `Update`
/// (identity `"cluster"`).
fn diff_firewall_options(
    declared: Option<&FirewallOptionsDecl>,
    live: Option<&FirewallOptionsDecl>,
    out: &mut Vec<Change>,
) {
    let Some(decl) = declared else {
        return;
    };
    if live == Some(decl) {
        return;
    }
    out.push(Change {
        kind: ChangeKind::Update,
        resource: "firewall_options",
        identity: "cluster".to_string(),
        before: live.and_then(|l| serde_json::to_value(l).ok()),
        after: serde_json::to_value(decl).ok(),
    });
}

fn diff_firewall_aliases(
    declared: &[FirewallAliasDecl],
    live: &[FirewallAliasDecl],
    out: &mut Vec<Change>,
) {
    use std::collections::HashMap;
    let live_by: HashMap<&str, &FirewallAliasDecl> =
        live.iter().map(|a| (a.name.as_str(), a)).collect();
    let decl_by: HashMap<&str, &FirewallAliasDecl> =
        declared.iter().map(|a| (a.name.as_str(), a)).collect();

    let mut deletes: Vec<_> = live_by
        .keys()
        .filter(|k| !decl_by.contains_key(*k))
        .collect();
    deletes.sort_unstable();
    for k in deletes {
        out.push(Change {
            kind: ChangeKind::Delete,
            resource: "firewall_alias",
            identity: (*k).to_string(),
            before: serde_json::to_value(live_by[k]).ok(),
            after: None,
        });
    }

    let mut updates: Vec<_> = decl_by
        .keys()
        .filter(|k| live_by.get(*k).is_some_and(|l| *l != decl_by[*k]))
        .collect();
    updates.sort_unstable();
    for k in updates {
        out.push(Change {
            kind: ChangeKind::Update,
            resource: "firewall_alias",
            identity: (*k).to_string(),
            before: serde_json::to_value(live_by[k]).ok(),
            after: serde_json::to_value(decl_by[k]).ok(),
        });
    }

    let mut creates: Vec<_> = decl_by
        .keys()
        .filter(|k| !live_by.contains_key(*k))
        .collect();
    creates.sort_unstable();
    for k in creates {
        out.push(Change {
            kind: ChangeKind::Create,
            resource: "firewall_alias",
            identity: (*k).to_string(),
            before: None,
            after: serde_json::to_value(decl_by[k]).ok(),
        });
    }
}

/// Diff IP sets by `name`. An `Update` carries the full before/after
/// ipset (comment + CIDR membership); the apply layer decodes both to
/// compute the minimal API calls (comment change → delete+recreate;
/// CIDR delta → incremental add/remove).
fn diff_firewall_ipsets(
    declared: &[FirewallIpsetDecl],
    live: &[FirewallIpsetDecl],
    out: &mut Vec<Change>,
) {
    use std::collections::HashMap;
    let live_by: HashMap<&str, &FirewallIpsetDecl> =
        live.iter().map(|s| (s.name.as_str(), s)).collect();
    let decl_by: HashMap<&str, &FirewallIpsetDecl> =
        declared.iter().map(|s| (s.name.as_str(), s)).collect();

    let mut deletes: Vec<_> = live_by
        .keys()
        .filter(|k| !decl_by.contains_key(*k))
        .collect();
    deletes.sort_unstable();
    for k in deletes {
        out.push(Change {
            kind: ChangeKind::Delete,
            resource: "firewall_ipset",
            identity: (*k).to_string(),
            before: serde_json::to_value(live_by[k]).ok(),
            after: None,
        });
    }

    let mut updates: Vec<_> = decl_by
        .keys()
        .filter(|k| live_by.get(*k).is_some_and(|l| *l != decl_by[*k]))
        .collect();
    updates.sort_unstable();
    for k in updates {
        out.push(Change {
            kind: ChangeKind::Update,
            resource: "firewall_ipset",
            identity: (*k).to_string(),
            before: serde_json::to_value(live_by[k]).ok(),
            after: serde_json::to_value(decl_by[k]).ok(),
        });
    }

    let mut creates: Vec<_> = decl_by
        .keys()
        .filter(|k| !live_by.contains_key(*k))
        .collect();
    creates.sort_unstable();
    for k in creates {
        out.push(Change {
            kind: ChangeKind::Create,
            resource: "firewall_ipset",
            identity: (*k).to_string(),
            before: None,
            after: serde_json::to_value(decl_by[k]).ok(),
        });
    }
}

/// Diff security groups by `group`. **Create + Delete only** — PVE has
/// no group-update endpoint and the group's rules are read-only here,
/// so a comment-only drift on an existing group is deliberately NOT
/// emitted (applying it would mean delete+recreate, silently dropping
/// the group's rules). See [`ClusterState::firewall_groups`].
fn diff_firewall_groups(
    declared: &[FirewallGroupDecl],
    live: &[FirewallGroupDecl],
    out: &mut Vec<Change>,
) {
    use std::collections::HashMap;
    let live_by: HashMap<&str, &FirewallGroupDecl> =
        live.iter().map(|g| (g.group.as_str(), g)).collect();
    let decl_by: HashMap<&str, &FirewallGroupDecl> =
        declared.iter().map(|g| (g.group.as_str(), g)).collect();

    let mut deletes: Vec<_> = live_by
        .keys()
        .filter(|k| !decl_by.contains_key(*k))
        .collect();
    deletes.sort_unstable();
    for k in deletes {
        out.push(Change {
            kind: ChangeKind::Delete,
            resource: "firewall_group",
            identity: (*k).to_string(),
            before: serde_json::to_value(live_by[k]).ok(),
            after: None,
        });
    }

    let mut creates: Vec<_> = decl_by
        .keys()
        .filter(|k| !live_by.contains_key(*k))
        .collect();
    creates.sort_unstable();
    for k in creates {
        out.push(Change {
            kind: ChangeKind::Create,
            resource: "firewall_group",
            identity: (*k).to_string(),
            before: None,
            after: serde_json::to_value(decl_by[k]).ok(),
        });
    }
}

/// Diff notification matchers by `name` — standard create/update/
/// delete. The full matcher (targets + match clauses + flags) is the
/// value; touching any field is an `Update`.
fn diff_notification_matchers(
    declared: &[NotificationMatcherDecl],
    live: &[NotificationMatcherDecl],
    out: &mut Vec<Change>,
) {
    use std::collections::HashMap;
    let live_by: HashMap<&str, &NotificationMatcherDecl> =
        live.iter().map(|m| (m.name.as_str(), m)).collect();
    let decl_by: HashMap<&str, &NotificationMatcherDecl> =
        declared.iter().map(|m| (m.name.as_str(), m)).collect();

    let mut deletes: Vec<_> = live_by
        .keys()
        .filter(|k| !decl_by.contains_key(*k))
        .collect();
    deletes.sort_unstable();
    for k in deletes {
        out.push(Change {
            kind: ChangeKind::Delete,
            resource: "notification_matcher",
            identity: (*k).to_string(),
            before: serde_json::to_value(live_by[k]).ok(),
            after: None,
        });
    }

    let mut updates: Vec<_> = decl_by
        .keys()
        .filter(|k| live_by.get(*k).is_some_and(|l| *l != decl_by[*k]))
        .collect();
    updates.sort_unstable();
    for k in updates {
        out.push(Change {
            kind: ChangeKind::Update,
            resource: "notification_matcher",
            identity: (*k).to_string(),
            before: serde_json::to_value(live_by[k]).ok(),
            after: serde_json::to_value(decl_by[k]).ok(),
        });
    }

    let mut creates: Vec<_> = decl_by
        .keys()
        .filter(|k| !live_by.contains_key(*k))
        .collect();
    creates.sort_unstable();
    for k in creates {
        out.push(Change {
            kind: ChangeKind::Create,
            resource: "notification_matcher",
            identity: (*k).to_string(),
            before: None,
            after: serde_json::to_value(decl_by[k]).ok(),
        });
    }
}

/// Diff HA rules by `rule` (identifier). Identity-by-`rule`; any other
/// field change (type / resources / nodes / strict / affinity / disable
/// / comment) is an Update. A `rule_type` change between an existing
/// and a declared rule with the same `rule` id surfaces as an Update;
/// PVE will refuse the PUT (type is immutable) and the apply error
/// surfaces actionable next-step text. Operators wanting to switch
/// type must Delete + re-Create.
fn diff_ha_rules(declared: &[HaRuleDecl], live: &[HaRuleDecl], out: &mut Vec<Change>) {
    use std::collections::HashMap;
    let live_by: HashMap<&str, &HaRuleDecl> = live.iter().map(|r| (r.rule.as_str(), r)).collect();
    let decl_by: HashMap<&str, &HaRuleDecl> =
        declared.iter().map(|r| (r.rule.as_str(), r)).collect();

    let mut deletes: Vec<_> = live_by
        .keys()
        .filter(|k| !decl_by.contains_key(*k))
        .collect();
    deletes.sort_unstable();
    for k in deletes {
        out.push(Change {
            kind: ChangeKind::Delete,
            resource: "ha_rule",
            identity: (*k).to_string(),
            before: serde_json::to_value(live_by[k]).ok(),
            after: None,
        });
    }

    let mut updates: Vec<_> = decl_by
        .keys()
        .filter(|k| live_by.get(*k).is_some_and(|l| *l != decl_by[*k]))
        .collect();
    updates.sort_unstable();
    for k in updates {
        out.push(Change {
            kind: ChangeKind::Update,
            resource: "ha_rule",
            identity: (*k).to_string(),
            before: serde_json::to_value(live_by[k]).ok(),
            after: serde_json::to_value(decl_by[k]).ok(),
        });
    }

    let mut creates: Vec<_> = decl_by
        .keys()
        .filter(|k| !live_by.contains_key(*k))
        .collect();
    creates.sort_unstable();
    for k in creates {
        out.push(Change {
            kind: ChangeKind::Create,
            resource: "ha_rule",
            identity: (*k).to_string(),
            before: None,
            after: serde_json::to_value(decl_by[k]).ok(),
        });
    }
}

/// Human-readable single-line summary of one change. Used by the
/// CLI's default output mode. Keep it grep-friendly:
/// `<sigil> <resource>: <identity>`.
///
/// `+` = Create, `-` = Delete, `~` = Update — matches `diff(1)`
/// convention close enough that operators eyeballing output
/// recognize it.
#[must_use]
pub fn summary_line(c: &Change) -> String {
    let sigil = match c.kind {
        ChangeKind::Create => '+',
        ChangeKind::Update => '~',
        ChangeKind::Delete => '-',
    };
    format!("{} {}: {}", sigil, c.resource, c.identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::model::{
        AclDecl, BackupJobDecl, ClusterState, FirewallAliasDecl, FirewallGroupDecl,
        FirewallIpsetCidrDecl, FirewallIpsetDecl, FirewallOptionsDecl, NotificationMatcherDecl,
        PoolDecl, StorageDecl,
    };

    fn empty() -> ClusterState {
        ClusterState::default()
    }

    #[test]
    fn diff_empty_states_is_empty() {
        let d = diff(&empty(), &empty());
        assert!(d.is_empty());
    }

    #[test]
    fn diff_pool_create() {
        let declared = ClusterState {
            pools: vec![PoolDecl {
                poolid: "platform".into(),
                comment: "p".into(),
                members: vec!["qemu/100".into()],
            }],
            ..ClusterState::default()
        };
        let d = diff(&declared, &empty());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Create);
        assert_eq!(d[0].resource, "pool");
        assert_eq!(d[0].identity, "platform");
        assert!(d[0].before.is_none());
        assert!(d[0].after.is_some());
    }

    #[test]
    fn diff_pool_delete() {
        let live = ClusterState {
            pools: vec![PoolDecl {
                poolid: "orphan".into(),
                comment: String::new(),
                members: vec![],
            }],
            ..ClusterState::default()
        };
        let d = diff(&empty(), &live);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Delete);
        assert_eq!(d[0].resource, "pool");
        assert_eq!(d[0].identity, "orphan");
        assert!(d[0].before.is_some());
        assert!(d[0].after.is_none());
    }

    #[test]
    fn diff_pool_update_on_comment_change() {
        // Same poolid, different comment → exactly one Update.
        let declared = ClusterState {
            pools: vec![PoolDecl {
                poolid: "p1".into(),
                comment: "updated".into(),
                members: vec![],
            }],
            ..ClusterState::default()
        };
        let live = ClusterState {
            pools: vec![PoolDecl {
                poolid: "p1".into(),
                comment: "original".into(),
                members: vec![],
            }],
            ..ClusterState::default()
        };
        let d = diff(&declared, &live);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Update);
        assert_eq!(d[0].identity, "p1");
        // before carries the live (original) value, after the declared.
        let before_obj = d[0].before.as_ref().unwrap();
        let after_obj = d[0].after.as_ref().unwrap();
        assert_eq!(before_obj.get("comment").unwrap(), "original");
        assert_eq!(after_obj.get("comment").unwrap(), "updated");
    }

    #[test]
    fn diff_pool_update_on_members_change() {
        let declared = ClusterState {
            pools: vec![PoolDecl {
                poolid: "p1".into(),
                comment: String::new(),
                members: vec!["qemu/100".into(), "qemu/101".into()],
            }],
            ..ClusterState::default()
        };
        let live = ClusterState {
            pools: vec![PoolDecl {
                poolid: "p1".into(),
                comment: String::new(),
                members: vec!["qemu/100".into()],
            }],
            ..ClusterState::default()
        };
        let d = diff(&declared, &live);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Update);
    }

    #[test]
    fn diff_identical_pools_produces_no_change() {
        let p = PoolDecl {
            poolid: "p1".into(),
            comment: "same".into(),
            members: vec!["qemu/100".into()],
        };
        let s = ClusterState {
            pools: vec![p],
            ..ClusterState::default()
        };
        let d = diff(&s, &s);
        assert!(d.is_empty());
    }

    #[test]
    fn diff_acl_4_tuple_identity_keys_correctly() {
        // Same path + ugid + roleid but different `kind` are TWO
        // distinct identities (user vs token). Pins that the 4-tuple
        // identity doesn't collapse `kind`.
        let user_grant = AclDecl {
            path: "/vms/100".into(),
            kind: "user".into(),
            ugid: "alice@pve".into(),
            roleid: "PVEVMAdmin".into(),
            propagate: true,
        };
        let token_grant = AclDecl {
            path: "/vms/100".into(),
            kind: "token".into(),
            ugid: "alice@pve".into(),
            roleid: "PVEVMAdmin".into(),
            propagate: true,
        };
        let declared = ClusterState {
            acl: vec![user_grant, token_grant.clone()],
            ..ClusterState::default()
        };
        let live = ClusterState {
            acl: vec![token_grant],
            ..ClusterState::default()
        };
        // Only the user grant is missing live → 1 Create, 0 others.
        let d = diff(&declared, &live);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Create);
        assert!(d[0].identity.contains("user"));
        assert!(!d[0].identity.contains("token"));
    }

    #[test]
    fn diff_acl_propagate_toggle_is_an_update() {
        let on = AclDecl {
            path: "/".into(),
            kind: "user".into(),
            ugid: "alice@pve".into(),
            roleid: "PVEAuditor".into(),
            propagate: true,
        };
        let off = AclDecl {
            propagate: false,
            ..on.clone()
        };
        let d = diff(
            &ClusterState {
                acl: vec![off],
                ..ClusterState::default()
            },
            &ClusterState {
                acl: vec![on],
                ..ClusterState::default()
            },
        );
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Update);
    }

    #[test]
    fn diff_storage_update_on_shared_flag() {
        let declared = ClusterState {
            storage: vec![StorageDecl {
                storage: "s1".into(),
                storage_type: "nfs".into(),
                content: "backup".into(),
                shared: true,
                ..StorageDecl::default()
            }],
            ..ClusterState::default()
        };
        let live = ClusterState {
            storage: vec![StorageDecl {
                storage: "s1".into(),
                storage_type: "nfs".into(),
                content: "backup".into(),
                shared: false,
                ..StorageDecl::default()
            }],
            ..ClusterState::default()
        };
        let d = diff(&declared, &live);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Update);
        assert_eq!(d[0].resource, "storage");
    }

    #[test]
    fn diff_multi_family_emits_in_order() {
        // Spread changes across pool, acl, storage, backup_job;
        // pinning the emit order: pool → acl → storage → backup_job
        // (matches `ClusterState` field order, matches the iteration
        // order in `diff()`).
        let declared = ClusterState {
            pools: vec![PoolDecl {
                poolid: "new-pool".into(),
                ..PoolDecl::default()
            }],
            acl: vec![AclDecl {
                path: "/".into(),
                kind: "user".into(),
                ugid: "new@pve".into(),
                roleid: "PVEAuditor".into(),
                propagate: true,
            }],
            storage: vec![StorageDecl {
                storage: "new-storage".into(),
                storage_type: "dir".into(),
                content: "iso".into(),
                path: "/srv/iso".into(),
                ..StorageDecl::default()
            }],
            backup_jobs: vec![BackupJobDecl {
                id: "new-job".into(),
                schedule: "daily".into(),
                storage: "local".into(),
                ..BackupJobDecl::default()
            }],
            ..ClusterState::default()
        };
        let d = diff(&declared, &empty());
        assert_eq!(d.len(), 4);
        assert_eq!(d[0].resource, "pool");
        assert_eq!(d[1].resource, "acl");
        assert_eq!(d[2].resource, "storage");
        assert_eq!(d[3].resource, "backup_job");
    }

    #[test]
    fn diff_backup_job_create() {
        let declared = ClusterState {
            backup_jobs: vec![BackupJobDecl {
                id: "nightly".into(),
                schedule: "*-*-* 02:00".into(),
                storage: "pbs".into(),
                all: true,
                ..BackupJobDecl::default()
            }],
            ..ClusterState::default()
        };
        let d = diff(&declared, &empty());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Create);
        assert_eq!(d[0].resource, "backup_job");
        assert_eq!(d[0].identity, "nightly");
        assert!(d[0].before.is_none());
        assert!(d[0].after.is_some());
    }

    #[test]
    fn diff_backup_job_delete() {
        let live = ClusterState {
            backup_jobs: vec![BackupJobDecl {
                id: "orphan".into(),
                schedule: "daily".into(),
                storage: "local".into(),
                ..BackupJobDecl::default()
            }],
            ..ClusterState::default()
        };
        let d = diff(&empty(), &live);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Delete);
        assert_eq!(d[0].resource, "backup_job");
        assert_eq!(d[0].identity, "orphan");
        assert!(d[0].before.is_some());
        assert!(d[0].after.is_none());
    }

    #[test]
    fn diff_backup_job_update_on_schedule_change() {
        // Same id, different schedule → exactly one Update with the
        // live value in `before` and declared in `after`.
        let declared = ClusterState {
            backup_jobs: vec![BackupJobDecl {
                id: "j1".into(),
                schedule: "*-*-* 04:00".into(),
                storage: "local".into(),
                ..BackupJobDecl::default()
            }],
            ..ClusterState::default()
        };
        let live = ClusterState {
            backup_jobs: vec![BackupJobDecl {
                id: "j1".into(),
                schedule: "*-*-* 02:00".into(),
                storage: "local".into(),
                ..BackupJobDecl::default()
            }],
            ..ClusterState::default()
        };
        let d = diff(&declared, &live);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Update);
        assert_eq!(d[0].identity, "j1");
        let before = d[0].before.as_ref().unwrap();
        let after = d[0].after.as_ref().unwrap();
        assert_eq!(before.get("schedule").unwrap(), "*-*-* 02:00");
        assert_eq!(after.get("schedule").unwrap(), "*-*-* 04:00");
    }

    #[test]
    fn diff_backup_job_update_on_enabled_flag() {
        // Flipping `enabled` is the most common drift (operator pauses
        // a job in the UI); pin that it's detected as an Update.
        let declared = ClusterState {
            backup_jobs: vec![BackupJobDecl {
                id: "j1".into(),
                schedule: "daily".into(),
                storage: "local".into(),
                enabled: false,
                ..BackupJobDecl::default()
            }],
            ..ClusterState::default()
        };
        let live = ClusterState {
            backup_jobs: vec![BackupJobDecl {
                id: "j1".into(),
                schedule: "daily".into(),
                storage: "local".into(),
                enabled: true,
                ..BackupJobDecl::default()
            }],
            ..ClusterState::default()
        };
        let d = diff(&declared, &live);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Update);
        assert_eq!(d[0].resource, "backup_job");
    }

    #[test]
    fn diff_identical_backup_jobs_produces_no_change() {
        let j = BackupJobDecl {
            id: "j1".into(),
            schedule: "*-*-* 03:00".into(),
            storage: "pbs".into(),
            all: true,
            prune_backups: "keep-last=7".into(),
            ..BackupJobDecl::default()
        };
        let s = ClusterState {
            backup_jobs: vec![j],
            ..ClusterState::default()
        };
        let d = diff(&s, &s);
        assert!(d.is_empty());
    }

    // ── Firewall options (singleton) ──────────────────────

    #[test]
    fn diff_firewall_options_none_declared_is_no_change() {
        // A declared state without a [firewall_options] block must not
        // touch the live firewall, even if live has one.
        let live = ClusterState {
            firewall_options: Some(FirewallOptionsDecl {
                enable: true,
                policy_in: "DROP".into(),
                ..FirewallOptionsDecl::default()
            }),
            ..ClusterState::default()
        };
        let d = diff(&empty(), &live);
        assert!(d.is_empty(), "None declared = unmanaged, got {d:?}");
    }

    #[test]
    fn diff_firewall_options_differing_is_single_update() {
        let declared = ClusterState {
            firewall_options: Some(FirewallOptionsDecl {
                enable: true,
                policy_in: "DROP".into(),
                ..FirewallOptionsDecl::default()
            }),
            ..ClusterState::default()
        };
        let live = ClusterState {
            firewall_options: Some(FirewallOptionsDecl {
                enable: false,
                policy_in: "ACCEPT".into(),
                ..FirewallOptionsDecl::default()
            }),
            ..ClusterState::default()
        };
        let d = diff(&declared, &live);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Update);
        assert_eq!(d[0].resource, "firewall_options");
        assert_eq!(d[0].identity, "cluster");
    }

    #[test]
    fn diff_firewall_options_equal_is_no_change() {
        let o = FirewallOptionsDecl {
            enable: true,
            policy_in: "DROP".into(),
            policy_out: "ACCEPT".into(),
            ..FirewallOptionsDecl::default()
        };
        let s = ClusterState {
            firewall_options: Some(o),
            ..ClusterState::default()
        };
        assert!(diff(&s, &s).is_empty());
    }

    // ── Firewall aliases (full CRUD) ──────────────────────

    #[test]
    fn diff_firewall_alias_create_update_delete() {
        let mk = |cidr: &str| FirewallAliasDecl {
            name: "web".into(),
            cidr: cidr.into(),
            comment: String::new(),
        };
        // create
        let declared = ClusterState {
            firewall_aliases: vec![mk("10.0.0.0/8")],
            ..ClusterState::default()
        };
        let d = diff(&declared, &empty());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Create);
        assert_eq!(d[0].resource, "firewall_alias");
        assert_eq!(d[0].identity, "web");
        // delete
        let d = diff(&empty(), &declared);
        assert_eq!(d[0].kind, ChangeKind::Delete);
        // update (cidr change)
        let live = ClusterState {
            firewall_aliases: vec![mk("192.168.0.0/16")],
            ..ClusterState::default()
        };
        let d = diff(&declared, &live);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Update);
    }

    // ── Firewall IP sets (CRUD; update carries full value) ──

    #[test]
    fn diff_firewall_ipset_update_on_cidr_membership() {
        let with = |cidrs: Vec<&str>| FirewallIpsetDecl {
            name: "blocklist".into(),
            comment: "bad actors".into(),
            cidrs: cidrs
                .into_iter()
                .map(|c| FirewallIpsetCidrDecl {
                    cidr: c.into(),
                    ..FirewallIpsetCidrDecl::default()
                })
                .collect(),
        };
        let declared = ClusterState {
            firewall_ipsets: vec![with(vec!["1.2.3.0/24", "5.6.7.0/24"])],
            ..ClusterState::default()
        };
        let live = ClusterState {
            firewall_ipsets: vec![with(vec!["1.2.3.0/24"])],
            ..ClusterState::default()
        };
        let d = diff(&declared, &live);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Update);
        assert_eq!(d[0].resource, "firewall_ipset");
        // before + after both carry the full ipset (apply computes the delta).
        assert!(d[0].before.is_some() && d[0].after.is_some());
    }

    // ── Firewall groups (create/delete only — no update) ──

    #[test]
    fn diff_firewall_group_comment_drift_is_not_an_update() {
        // PVE has no group-update endpoint and rules are read-only, so
        // a comment-only change must NOT produce a (destructive) change.
        let declared = ClusterState {
            firewall_groups: vec![FirewallGroupDecl {
                group: "web-tier".into(),
                comment: "new comment".into(),
            }],
            ..ClusterState::default()
        };
        let live = ClusterState {
            firewall_groups: vec![FirewallGroupDecl {
                group: "web-tier".into(),
                comment: "old comment".into(),
            }],
            ..ClusterState::default()
        };
        let d = diff(&declared, &live);
        assert!(
            d.is_empty(),
            "group comment drift must not emit a change, got {d:?}"
        );
    }

    #[test]
    fn diff_firewall_group_create_and_delete() {
        let declared = ClusterState {
            firewall_groups: vec![FirewallGroupDecl {
                group: "web-tier".into(),
                comment: String::new(),
            }],
            ..ClusterState::default()
        };
        let create = diff(&declared, &empty());
        assert_eq!(create.len(), 1);
        assert_eq!(create[0].kind, ChangeKind::Create);
        assert_eq!(create[0].resource, "firewall_group");
        let delete = diff(&empty(), &declared);
        assert_eq!(delete.len(), 1);
        assert_eq!(delete[0].kind, ChangeKind::Delete);
    }

    // ── Notification matchers ─────────────────────────────

    #[test]
    fn diff_notification_matcher_create_update_delete() {
        let mk = |targets: Vec<&str>| NotificationMatcherDecl {
            name: "oncall".into(),
            target: targets.into_iter().map(String::from).collect(),
            mode: "all".into(),
            ..NotificationMatcherDecl::default()
        };
        // create
        let declared = ClusterState {
            notification_matchers: vec![mk(vec!["gotify"])],
            ..ClusterState::default()
        };
        let d = diff(&declared, &empty());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Create);
        assert_eq!(d[0].resource, "notification_matcher");
        assert_eq!(d[0].identity, "oncall");
        // delete
        let d = diff(&empty(), &declared);
        assert_eq!(d[0].kind, ChangeKind::Delete);
        // update (target set changes)
        let live = ClusterState {
            notification_matchers: vec![mk(vec!["email"])],
            ..ClusterState::default()
        };
        let d = diff(&declared, &live);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Update);
    }

    #[test]
    fn diff_identical_matchers_produces_no_change() {
        let m = NotificationMatcherDecl {
            name: "m".into(),
            target: vec!["gotify".into()],
            match_severity: vec!["error".into()],
            disable: true,
            ..NotificationMatcherDecl::default()
        };
        let s = ClusterState {
            notification_matchers: vec![m],
            ..ClusterState::default()
        };
        assert!(diff(&s, &s).is_empty());
    }

    // ── HA rules (epic #74) ───────────────────────────────────────

    #[test]
    fn diff_ha_rule_create_update_delete() {
        let mk_node = |rule: &str, nodes: &str, strict: bool| HaRuleDecl {
            rule: rule.into(),
            rule_type: "node-affinity".into(),
            resources: vec!["vm:100".into(), "vm:101".into()],
            nodes: nodes.into(),
            strict,
            ..HaRuleDecl::default()
        };
        // CREATE: declared has the rule, live empty.
        let declared = ClusterState {
            ha_rules: vec![mk_node("pin-db", "pve1:5,pve2", false)],
            ..ClusterState::default()
        };
        let d = diff(&declared, &ClusterState::default());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Create);
        assert_eq!(d[0].resource, "ha_rule");
        assert_eq!(d[0].identity, "pin-db");

        // DELETE: declared empty, live has the rule.
        let d = diff(&ClusterState::default(), &declared);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Delete);
        assert_eq!(d[0].resource, "ha_rule");

        // UPDATE: same id, different `nodes` priority encoding.
        let live = ClusterState {
            ha_rules: vec![mk_node("pin-db", "pve1,pve2", false)],
            ..ClusterState::default()
        };
        let d = diff(&declared, &live);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Update);
        assert_eq!(d[0].identity, "pin-db");
        // Both sides serialised — preflight needs the before/after pair
        // to detect a `strict` flip (Severe-tier).
        assert!(d[0].before.is_some() && d[0].after.is_some());
    }

    #[test]
    fn diff_ha_rule_resource_affinity_create() {
        // Different rule_type — exercise the resource-affinity branch.
        let declared = ClusterState {
            ha_rules: vec![HaRuleDecl {
                rule: "web-spread".into(),
                rule_type: "resource-affinity".into(),
                resources: vec!["vm:200".into(), "vm:201".into(), "vm:202".into()],
                affinity: "negative".into(),
                ..HaRuleDecl::default()
            }],
            ..ClusterState::default()
        };
        let d = diff(&declared, &ClusterState::default());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Create);
        assert_eq!(d[0].identity, "web-spread");
    }

    #[test]
    fn diff_identical_ha_rules_produces_no_change() {
        let r = HaRuleDecl {
            rule: "pin-db".into(),
            rule_type: "node-affinity".into(),
            resources: vec!["vm:100".into()],
            nodes: "pve1".into(),
            strict: true,
            ..HaRuleDecl::default()
        };
        let s = ClusterState {
            ha_rules: vec![r],
            ..ClusterState::default()
        };
        assert!(diff(&s, &s).is_empty());
    }

    #[test]
    fn diff_ha_rule_strict_flip_is_an_update() {
        // Regression guard for the Severe-tier preflight path: a
        // `strict` flip must produce an Update with before+after so
        // preflight can detect it.
        let live_rule = HaRuleDecl {
            rule: "pin-db".into(),
            rule_type: "node-affinity".into(),
            resources: vec!["vm:100".into()],
            nodes: "pve1".into(),
            strict: false,
            ..HaRuleDecl::default()
        };
        let mut decl_rule = live_rule.clone();
        decl_rule.strict = true;
        let declared = ClusterState {
            ha_rules: vec![decl_rule],
            ..ClusterState::default()
        };
        let live = ClusterState {
            ha_rules: vec![live_rule],
            ..ClusterState::default()
        };
        let d = diff(&declared, &live);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, ChangeKind::Update);
        let before: HaRuleDecl = serde_json::from_value(d[0].before.clone().unwrap()).unwrap();
        let after: HaRuleDecl = serde_json::from_value(d[0].after.clone().unwrap()).unwrap();
        assert!(
            !before.strict && after.strict,
            "strict flip must be visible"
        );
    }

    #[test]
    fn summary_line_uses_diff_sigils() {
        let c = |k| Change {
            kind: k,
            resource: "pool",
            identity: "p1".into(),
            before: None,
            after: None,
        };
        assert_eq!(summary_line(&c(ChangeKind::Create)), "+ pool: p1");
        assert_eq!(summary_line(&c(ChangeKind::Update)), "~ pool: p1");
        assert_eq!(summary_line(&c(ChangeKind::Delete)), "- pool: p1");
    }

    #[test]
    fn diff_is_symmetric_with_apply_meaning() {
        // Property: applying diff(declared, live) to `live` should
        // converge it to `declared`. We can't run apply yet (PR 5),
        // but we can pin a weaker claim: diff(a, b) and diff(b, a)
        // have the same length, and the kinds are inverted
        // (Create ↔ Delete, Update ↔ Update).
        let a = ClusterState {
            pools: vec![PoolDecl {
                poolid: "p1".into(),
                comment: "a".into(),
                ..PoolDecl::default()
            }],
            ..ClusterState::default()
        };
        let b = ClusterState {
            pools: vec![PoolDecl {
                poolid: "p2".into(),
                comment: "b".into(),
                ..PoolDecl::default()
            }],
            ..ClusterState::default()
        };

        let d_ab = diff(&a, &b);
        let d_ba = diff(&b, &a);

        assert_eq!(d_ab.len(), d_ba.len(), "diff length symmetric");

        // Both diffs have one Create + one Delete (p1 in `a` is
        // Create when `a` is declared, Delete when `b` is declared).
        let kinds_ab: Vec<_> = d_ab.iter().map(|c| c.kind).collect();
        let kinds_ba: Vec<_> = d_ba.iter().map(|c| c.kind).collect();
        assert!(kinds_ab.contains(&ChangeKind::Create));
        assert!(kinds_ab.contains(&ChangeKind::Delete));
        assert!(kinds_ba.contains(&ChangeKind::Create));
        assert!(kinds_ba.contains(&ChangeKind::Delete));
    }
}
