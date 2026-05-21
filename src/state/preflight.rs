//! Pre-flight risk gates for `proxxx state apply`.
//!
//! The existing per-guest pre-flight ([`crate::app::preflight`])
//! grades destructive ops on a single [`Guest`](crate::api::types::Guest)
//! against a fixed `Op` enum. State-apply changes are a different
//! shape: they touch resources (pools, ACL grants, storages) that
//! have their own risk profile distinct from "the guest is running".
//!
//! ## Risk model
//!
//! We grade each [`Change`] by *blast radius* — what's the worst
//! thing that happens if this change goes wrong?
//!
//! | Risk                          | Why it's classified that way |
//! | :---------------------------- | :--------------------------- |
//! | [`StateRisk::PoolDeleteNonEmpty`] | Severe — orphans the members; PVE refuses but the error is opaque. We catch it up-front. |
//! | [`StateRisk::AclDeleteRootRole`]  | Severe — removing root-equivalent ACL on `/` is a lock-out risk. |
//! | [`StateRisk::AclDeleteAuditor`]   | Warning — removing audit/observation grants; not fatal but visibility loss. |
//! | [`StateRisk::StorageDeleteShared`] | Severe — shared storages typically host live guest disks. |
//! | [`StateRisk::StoragePropertyChange { what }`] | Warning — content-list or path changes can break running guests. |
//! | [`StateRisk::AclPropagateFlip`]   | Warning — `propagate` change cascades to every descendant path. |
//! | [`StateRisk::BackupJobDelete`]    | Warning — guests silently stop being backed up; nothing breaks now, the safety net just disappears. |
//! | [`StateRisk::BulkChangeCount { n }`] | Notice → Warning if `n ≥ 10`, Severe if `n ≥ 50` (very large batches = high attention cost). |
//!
//! ## Decision contract
//!
//! [`enforce_state_preflight`] returns `Ok(())` only when:
//!   * Every change is below `Severe`, **OR**
//!   * `force == true` (operator passed `--allow-risk`).
//!
//! On refusal it returns a typed [`crate::app::preflight::PreflightRefusal`]
//! so `main.rs` maps to exit code **6** (matches the existing per-guest
//! pre-flight contract). The risk list is printed to stderr first.

use anyhow::Result;
use serde::Serialize;

use crate::app::preflight::{PreflightRefusal, RiskLevel};
use crate::state::diff::{Change, ChangeKind};
use crate::state::model::{AclDecl, ClusterState, PoolDecl, StorageDecl};

/// State-change-specific risk taxonomy. Each variant carries
/// enough context for the operator to understand WHAT'S RISKY,
/// not just THAT IT'S RISKY.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StateRisk {
    /// Delete change against a pool that has members in the
    /// live state. PVE refuses with a 500 + opaque error;
    /// catching it here gives the operator a clearer signal.
    PoolDeleteNonEmpty { poolid: String, member_count: usize },

    /// Delete of an ACL grant that gave a root-equivalent role
    /// (`PVEAdmin` / `Administrator`). High lock-out risk.
    AclDeleteRootRole {
        path: String,
        ugid: String,
        role: String,
    },

    /// Delete of an audit/observer grant. Not fatal, but loses
    /// visibility from a known principal.
    AclDeleteAuditor {
        path: String,
        ugid: String,
        role: String,
    },

    /// Delete of a shared storage. Live guest disks almost
    /// certainly live there.
    StorageDeleteShared { storage: String },

    /// Update of a storage's content list or other operationally
    /// significant property. Running guests may rely on the
    /// removed content type.
    StoragePropertyChange { storage: String, what: &'static str },

    /// Propagate flag change on an ACL grant. Cascades to every
    /// descendant path; small change with cluster-wide reach.
    AclPropagateFlip {
        path: String,
        ugid: String,
        new_value: bool,
    },

    /// Delete of a scheduled backup job. The guests it covered stop
    /// being backed up — a silent loss of data protection (no error,
    /// no immediate breakage, just an absent safety net).
    BackupJobDelete { id: String },

    /// Very-large-batch warning. Increases attention cost
    /// proportionally; defer with `--allow-risk` if intentional.
    BulkChangeCount { n: usize },
}

impl StateRisk {
    /// Severity ladder. Notice < Warning < Severe.
    #[must_use]
    pub const fn level(&self) -> RiskLevel {
        match self {
            Self::PoolDeleteNonEmpty { .. }
            | Self::AclDeleteRootRole { .. }
            | Self::StorageDeleteShared { .. } => RiskLevel::Severe,
            Self::StoragePropertyChange { .. }
            | Self::AclPropagateFlip { .. }
            | Self::AclDeleteAuditor { .. }
            | Self::BackupJobDelete { .. } => RiskLevel::Warning,
            Self::BulkChangeCount { n } => {
                if *n >= 50 {
                    RiskLevel::Severe
                } else if *n >= 10 {
                    RiskLevel::Warning
                } else {
                    RiskLevel::Notice
                }
            }
        }
    }

    /// Human-readable one-liner for stderr output.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::PoolDeleteNonEmpty {
                poolid,
                member_count,
            } => format!(
                "delete pool `{poolid}` — still has {member_count} members \
                 (PVE will refuse with an opaque 500)"
            ),
            Self::AclDeleteRootRole { path, ugid, role } => format!(
                "delete ACL grant on `{path}` for `{ugid}` (role `{role}`) — \
                 LOCK-OUT RISK if this was the last admin grant"
            ),
            Self::AclDeleteAuditor { path, ugid, role } => format!(
                "delete ACL grant on `{path}` for `{ugid}` (role `{role}`) — \
                 you'll lose visibility from this principal"
            ),
            Self::StorageDeleteShared { storage } => format!(
                "delete shared storage `{storage}` — live guests likely \
                 depend on it"
            ),
            Self::StoragePropertyChange { storage, what } => format!(
                "update storage `{storage}` — changing `{what}` may break \
                 running guests that rely on the current value"
            ),
            Self::AclPropagateFlip {
                path,
                ugid,
                new_value,
            } => format!(
                "ACL grant on `{path}` for `{ugid}`: propagate → {new_value} — \
                 cascades to every descendant path"
            ),
            Self::BackupJobDelete { id } => format!(
                "delete backup job `{id}` — the guests it covered will \
                 silently stop being backed up"
            ),
            Self::BulkChangeCount { n } => {
                format!("{n} changes in one apply — attention cost proportional")
            }
        }
    }
}

/// Roles considered root-equivalent for the lock-out check.
/// Conservative: anything that grants `Sys.PowerMgmt` or
/// `Sys.Modify` against `/` is treated as admin-tier. We keep
/// this list explicit and small; the operator can re-grant
/// after a careful review.
const ROOT_LIKE_ROLES: &[&str] = &["Administrator", "PVEAdmin", "Root"];

/// Audit/observer roles. Removing them is warning-tier.
const AUDITOR_LIKE_ROLES: &[&str] = &["PVEAuditor", "Auditor"];

/// Assess every change against the live state, return the full
/// risk list (one element per detected risk). Empty Vec means
/// the apply is risk-free at this layer.
///
/// `declared` is what the operator wants the cluster to look
/// like; `live` is the current state from `state::export`.
/// Both are needed because some risks (pool member counts,
/// shared-storage classification) come from live state, not
/// from the change itself.
#[must_use]
pub fn assess(changes: &[Change], live: &ClusterState) -> Vec<StateRisk> {
    let mut risks = Vec::new();

    // Bulk-count gate first — independent of per-change checks.
    if changes.len() >= 10 {
        risks.push(StateRisk::BulkChangeCount { n: changes.len() });
    }

    for c in changes {
        risks.extend(assess_one(c, live));
    }
    risks
}

/// Per-change risk surface. Pure function; no I/O.
fn assess_one(change: &Change, live: &ClusterState) -> Vec<StateRisk> {
    let mut out = Vec::new();
    match (change.kind, change.resource) {
        (ChangeKind::Delete, "pool") => {
            // Look up the live pool to count members.
            if let Some(pool) = live
                .pools
                .iter()
                .find(|p: &&PoolDecl| p.poolid == change.identity)
            {
                if !pool.members.is_empty() {
                    out.push(StateRisk::PoolDeleteNonEmpty {
                        poolid: pool.poolid.clone(),
                        member_count: pool.members.len(),
                    });
                }
            }
        }
        (ChangeKind::Delete, "acl") => {
            // Find the live ACL grant being deleted to classify
            // its role tier. Identity format defined by the diff
            // layer: `<path> [<kind>/<ugid>] <role>`.
            if let Some(acl) = find_acl_by_identity(&change.identity, &live.acl) {
                let path = acl.path.clone();
                let ugid = acl.ugid.clone();
                let role = acl.roleid.clone();
                if ROOT_LIKE_ROLES
                    .iter()
                    .any(|r| r.eq_ignore_ascii_case(&role))
                {
                    out.push(StateRisk::AclDeleteRootRole { path, ugid, role });
                } else if AUDITOR_LIKE_ROLES
                    .iter()
                    .any(|r| r.eq_ignore_ascii_case(&role))
                {
                    out.push(StateRisk::AclDeleteAuditor { path, ugid, role });
                }
            }
        }
        (ChangeKind::Update, "acl") => {
            // Identity-key changes (path/kind/ugid/role) trigger
            // delete+create, not update. The remaining update is
            // a propagate flip — flag it.
            if let Some(declared) = find_acl_by_identity_in(&change.identity, change.after.as_ref())
            {
                if let Some(current) = find_acl_by_identity(&change.identity, &live.acl) {
                    if declared.propagate != current.propagate {
                        out.push(StateRisk::AclPropagateFlip {
                            path: current.path.clone(),
                            ugid: current.ugid.clone(),
                            new_value: declared.propagate,
                        });
                    }
                }
            }
        }
        (ChangeKind::Delete, "storage") => {
            if let Some(storage) = live
                .storage
                .iter()
                .find(|s: &&StorageDecl| s.storage == change.identity)
            {
                if storage.shared {
                    out.push(StateRisk::StorageDeleteShared {
                        storage: storage.storage.clone(),
                    });
                }
            }
        }
        (ChangeKind::Update, "storage") => {
            // Updates to storage are usually small (a comment
            // change), but the operationally-significant fields
            // — `content`, `path`, `server` for NFS — can break
            // running guests. Detect them by diffing before/after
            // serialised JSON.
            if let (Some(before), Some(after)) = (change.before.as_ref(), change.after.as_ref()) {
                for field in &["content", "path", "server", "shared"] {
                    if before.get(field) != after.get(field) {
                        out.push(StateRisk::StoragePropertyChange {
                            storage: change.identity.clone(),
                            what: field,
                        });
                    }
                }
            }
        }
        (ChangeKind::Delete, "backup_job") => {
            // Deleting a backup job is silent data-protection loss:
            // no error, nothing breaks now, the covered guests just
            // stop being backed up. Always warn (identity is the id).
            out.push(StateRisk::BackupJobDelete {
                id: change.identity.clone(),
            });
        }
        _ => {}
    }
    out
}

/// Find an ACL grant in `live.acl` by the same identity string
/// the diff layer produced. The identity format is documented in
/// `src/state/diff.rs::summary_line`; we re-parse it here so we
/// don't need to thread the original ACL through every Change.
fn find_acl_by_identity<'a>(identity: &str, acls: &'a [AclDecl]) -> Option<&'a AclDecl> {
    let (path, rest) = identity.split_once(' ')?;
    // rest = "[token/foo@pve!bar] PVEAdmin"
    let rest = rest.trim_start_matches('[');
    let (kind_ugid, role) = rest.split_once("] ")?;
    let (kind, ugid) = kind_ugid.split_once('/')?;
    acls.iter()
        .find(|a| a.path == path && a.kind == kind && a.ugid == ugid && a.roleid == role)
}

/// Same lookup against a `serde_json::Value` representation
/// (used when matching against `change.after`, which is the
/// declared state in JSON form).
fn find_acl_by_identity_in(identity: &str, value: Option<&serde_json::Value>) -> Option<AclDecl> {
    let v = value?;
    let acl: AclDecl = serde_json::from_value(v.clone()).ok()?;
    let (path, rest) = identity.split_once(' ')?;
    let rest = rest.trim_start_matches('[');
    let (kind_ugid, role) = rest.split_once("] ")?;
    let (kind, ugid) = kind_ugid.split_once('/')?;
    if acl.path == path && acl.kind == kind && acl.ugid == ugid && acl.roleid == role {
        Some(acl)
    } else {
        None
    }
}

/// Refuse the apply if any risk is Severe and `force` is false.
/// Prints the risk list to stderr regardless (so the operator
/// always sees what was flagged, even on a successful pass).
///
/// Mirrors the `enforce_preflight` contract from `cli::common`
/// so main.rs's exit-code dispatch needs no changes — the same
/// `PreflightRefusal` carries through.
pub fn enforce_state_preflight(changes: &[Change], live: &ClusterState, force: bool) -> Result<()> {
    let risks = assess(changes, live);
    if risks.is_empty() {
        return Ok(());
    }
    eprintln!(
        "STATE PRE-FLIGHT ({} change{}):",
        changes.len(),
        if changes.len() == 1 { "" } else { "s" }
    );
    for r in &risks {
        eprintln!("  [{:7}] {}", r.level().as_str(), r.describe());
    }
    let max = risks
        .iter()
        .map(StateRisk::level)
        .max()
        .unwrap_or(RiskLevel::Notice);
    if max == RiskLevel::Severe && !force {
        return Err(anyhow::Error::from(PreflightRefusal));
    }
    if max == RiskLevel::Severe && force {
        eprintln!("  --allow-risk passed; overriding SEVERE risk(s) and proceeding.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::diff::{Change, ChangeKind};
    use crate::state::model::{AclDecl, ClusterState, PoolDecl, StorageDecl};

    fn sample_live() -> ClusterState {
        ClusterState {
            meta: None,
            pools: vec![
                PoolDecl {
                    poolid: "empty-pool".into(),
                    comment: String::new(),
                    members: vec![],
                },
                PoolDecl {
                    poolid: "prod-pool".into(),
                    comment: String::new(),
                    members: vec!["qemu/100".into(), "qemu/101".into()],
                },
            ],
            acl: vec![
                AclDecl {
                    path: "/".into(),
                    kind: "user".into(),
                    ugid: "root@pam".into(),
                    roleid: "Administrator".into(),
                    propagate: true,
                },
                AclDecl {
                    path: "/".into(),
                    kind: "user".into(),
                    ugid: "auditor@pve".into(),
                    roleid: "PVEAuditor".into(),
                    propagate: true,
                },
            ],
            storage: vec![
                StorageDecl {
                    storage: "shared-nfs".into(),
                    storage_type: "nfs".into(),
                    shared: true,
                    ..Default::default()
                },
                StorageDecl {
                    storage: "local".into(),
                    storage_type: "dir".into(),
                    shared: false,
                    ..Default::default()
                },
            ],
            backup_jobs: vec![],
        }
    }

    fn delete_change(resource: &'static str, identity: &str) -> Change {
        Change {
            kind: ChangeKind::Delete,
            resource,
            identity: identity.to_string(),
            before: None,
            after: None,
        }
    }

    #[test]
    fn pool_delete_empty_is_clean() {
        let live = sample_live();
        let changes = vec![delete_change("pool", "empty-pool")];
        let risks = assess(&changes, &live);
        assert!(risks.is_empty(), "got: {risks:?}");
    }

    #[test]
    fn pool_delete_non_empty_is_severe() {
        let live = sample_live();
        let changes = vec![delete_change("pool", "prod-pool")];
        let risks = assess(&changes, &live);
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].level(), RiskLevel::Severe);
        assert!(matches!(
            &risks[0],
            StateRisk::PoolDeleteNonEmpty {
                member_count: 2,
                ..
            }
        ));
    }

    #[test]
    fn acl_delete_root_role_is_severe() {
        let live = sample_live();
        let changes = vec![delete_change("acl", "/ [user/root@pam] Administrator")];
        let risks = assess(&changes, &live);
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].level(), RiskLevel::Severe);
        assert!(matches!(&risks[0], StateRisk::AclDeleteRootRole { .. }));
    }

    #[test]
    fn acl_delete_auditor_is_warning() {
        let live = sample_live();
        let changes = vec![delete_change("acl", "/ [user/auditor@pve] PVEAuditor")];
        let risks = assess(&changes, &live);
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].level(), RiskLevel::Warning);
        assert!(matches!(&risks[0], StateRisk::AclDeleteAuditor { .. }));
    }

    #[test]
    fn storage_delete_shared_is_severe() {
        let live = sample_live();
        let changes = vec![delete_change("storage", "shared-nfs")];
        let risks = assess(&changes, &live);
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].level(), RiskLevel::Severe);
    }

    #[test]
    fn storage_delete_local_is_clean() {
        let live = sample_live();
        let changes = vec![delete_change("storage", "local")];
        let risks = assess(&changes, &live);
        assert!(risks.is_empty());
    }

    #[test]
    fn storage_content_change_is_warning() {
        let live = sample_live();
        let changes = vec![Change {
            kind: ChangeKind::Update,
            resource: "storage",
            identity: "local".to_string(),
            before: Some(serde_json::json!({"content": "iso,backup"})),
            after: Some(serde_json::json!({"content": "iso,backup,images"})),
        }];
        let risks = assess(&changes, &live);
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].level(), RiskLevel::Warning);
        assert!(matches!(
            &risks[0],
            StateRisk::StoragePropertyChange {
                what: "content",
                ..
            }
        ));
    }

    #[test]
    fn backup_job_delete_is_warning() {
        // Deleting a backup job is silent data-protection loss — it
        // must surface as a Warning even though the live lookup finds
        // nothing operationally "broken".
        let live = sample_live();
        let changes = vec![delete_change("backup_job", "nightly-all")];
        let risks = assess(&changes, &live);
        assert_eq!(risks.len(), 1);
        assert_eq!(risks[0].level(), RiskLevel::Warning);
        assert!(matches!(&risks[0], StateRisk::BackupJobDelete { id } if id == "nightly-all"));
    }

    #[test]
    fn backup_job_create_and_update_are_clean() {
        // Adding or editing a job is not a risk at this layer — only
        // deletion (the safety-net removal) is flagged.
        let live = sample_live();
        let create = Change {
            kind: ChangeKind::Create,
            resource: "backup_job",
            identity: "new".to_string(),
            before: None,
            after: Some(serde_json::json!({"id": "new"})),
        };
        let update = Change {
            kind: ChangeKind::Update,
            resource: "backup_job",
            identity: "new".to_string(),
            before: Some(serde_json::json!({"schedule": "daily"})),
            after: Some(serde_json::json!({"schedule": "weekly"})),
        };
        assert!(assess(&[create], &live).is_empty());
        assert!(assess(&[update], &live).is_empty());
    }

    #[test]
    fn bulk_count_severity_ladder() {
        let live = sample_live();
        // 9 changes — no bulk risk.
        let nine: Vec<Change> = (0..9)
            .map(|i| delete_change("pool", &format!("p{i}")))
            .collect();
        let r9 = assess(&nine, &live);
        assert!(!r9
            .iter()
            .any(|r| matches!(r, StateRisk::BulkChangeCount { .. })));

        // 10 changes — Warning.
        let ten: Vec<Change> = (0..10)
            .map(|i| delete_change("pool", &format!("p{i}")))
            .collect();
        let r10 = assess(&ten, &live);
        let bulk = r10
            .iter()
            .find(|r| matches!(r, StateRisk::BulkChangeCount { .. }))
            .expect("expected BulkChangeCount risk");
        assert_eq!(bulk.level(), RiskLevel::Warning);

        // 50 changes — Severe.
        let fifty: Vec<Change> = (0..50)
            .map(|i| delete_change("pool", &format!("p{i}")))
            .collect();
        let r50 = assess(&fifty, &live);
        let bulk = r50
            .iter()
            .find(|r| matches!(r, StateRisk::BulkChangeCount { n: 50 }))
            .expect("expected BulkChangeCount(50)");
        assert_eq!(bulk.level(), RiskLevel::Severe);
    }

    #[test]
    fn enforce_passes_when_no_severe() {
        let live = sample_live();
        let changes = vec![delete_change("pool", "empty-pool")];
        // No risks → passes regardless of force flag.
        assert!(enforce_state_preflight(&changes, &live, false).is_ok());
        assert!(enforce_state_preflight(&changes, &live, true).is_ok());
    }

    #[test]
    fn enforce_refuses_severe_without_force() {
        let live = sample_live();
        let changes = vec![delete_change("pool", "prod-pool")];
        let err = enforce_state_preflight(&changes, &live, false).unwrap_err();
        // Typed PreflightRefusal so main.rs exit-code dispatch
        // doesn't need a new arm.
        assert!(err.downcast_ref::<PreflightRefusal>().is_some());
    }

    #[test]
    fn enforce_overrides_severe_with_force() {
        let live = sample_live();
        let changes = vec![delete_change("pool", "prod-pool")];
        // --allow-risk → proceeds.
        assert!(enforce_state_preflight(&changes, &live, true).is_ok());
    }

    #[test]
    fn risk_levels_serialise_lowercase_kind() {
        let r = StateRisk::PoolDeleteNonEmpty {
            poolid: "x".into(),
            member_count: 1,
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["kind"], "pool_delete_non_empty");
    }
}
