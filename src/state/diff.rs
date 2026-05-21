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
//!
//! Update detection compares the full `*Decl` value with `PartialEq`
//! — every non-identity field is part of the value. Touching any
//! one (e.g. flipping `propagate` on an ACL grant, adding a member
//! to a pool, enabling `shared` on a storage) produces exactly one
//! Update for that identity.

use serde::Serialize;

use crate::state::model::{AclDecl, BackupJobDecl, ClusterState, PoolDecl, StorageDecl};

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
/// then `storage`, then `backup_job`, each family sorted by identity.
/// Within a family the order is `Delete` (so apply-with-prune teardown
/// runs before create), then `Update`, then `Create` — but the apply
/// layer re-orders by dependency where needed.
#[must_use]
pub fn diff(declared: &ClusterState, live: &ClusterState) -> Vec<Change> {
    let mut out = Vec::new();
    diff_pools(&declared.pools, &live.pools, &mut out);
    diff_acl(&declared.acl, &live.acl, &mut out);
    diff_storage(&declared.storage, &live.storage, &mut out);
    diff_backup_jobs(&declared.backup_jobs, &live.backup_jobs, &mut out);
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
    use crate::state::model::{AclDecl, BackupJobDecl, ClusterState, PoolDecl, StorageDecl};

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
