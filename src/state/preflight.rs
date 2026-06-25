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
//! | [`StateRisk::FirewallDisabled`]   | Severe — flips the cluster firewall master switch off; all enforcement stops at once. |
//! | [`StateRisk::FirewallPolicyLoosened`] | Warning — a default policy goes to ACCEPT; every unmatched packet in that direction now passes. |
//! | [`StateRisk::FirewallAliasDelete`] / [`StateRisk::FirewallIpsetDelete`] | Warning — rules referencing `+name` break. |
//! | [`StateRisk::FirewallGroupDelete`] | Severe — drops the group's rules (not modelled, so unrecoverable) and breaks group-direction rules. |
//! | [`StateRisk::NotificationMatcherDelete`] | Warning — events that matched it stop being routed; alerting silently goes quiet. |
//! | [`StateRisk::HaRuleDelete`] | Warning — resources fall back to global HA defaults (no node preference / no affinity); does not stop them, just removes the constraint. |
//! | [`StateRisk::HaRuleStrictChange`] | Severe — flipping `strict` on a node-affinity rule can force-migrate every constrained guest (or refuse them placement) within seconds. |
//! | [`StateRisk::HaResourceDelete`] | Severe — removes a VM/CT from HA management entirely (CRM stops restarting/relocating it) AND auto-purges referencing rules via PVE's `purge=1` default. Operator-visible behaviour shift; not destructive to the guest itself, but a meaningful HA-policy change. |
//! | [`StateRisk::HaResourceStateChange`] | Warning — changing the desired CRM state (e.g. `started` → `disabled`, or `started` → `ignored`) shifts how the guest is managed. Going to `disabled` or `ignored` makes CRM stop enforcing; going to `stopped` makes CRM keep it stopped. |
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

    /// The cluster firewall master switch is being turned off
    /// (`enable` true→false). Disables ALL enforcement at once.
    FirewallDisabled,

    /// A default firewall policy is being loosened to `ACCEPT` (from
    /// `REJECT`/`DROP`). Every unmatched packet in that direction
    /// now passes.
    FirewallPolicyLoosened { direction: &'static str },

    /// Delete of a firewall alias. Any rule referencing `+name` breaks.
    FirewallAliasDelete { name: String },

    /// Delete of a firewall IP set. Any rule referencing `+name` breaks.
    FirewallIpsetDelete { name: String },

    /// Delete of a security group. Drops the group's rules (not
    /// modelled here, so unrecoverable via apply) and breaks any
    /// group-direction rule that references it.
    FirewallGroupDelete { group: String },

    /// Delete of a PCI passthrough resource mapping. Severe UNCONDITIONALLY:
    /// proxxx doesn't model which guests reference it (`hostpciN: mapping=<id>`),
    /// so it cannot prove the safe case — a guest bound to it loses its device
    /// on next start and hard-fails migration.
    MappingPciDelete { id: String },

    /// Delete of a USB passthrough resource mapping. Severe for the same reason
    /// as PCI (guests reference it via `usbN: mapping=<id>`, unmodelled here).
    MappingUsbDelete { id: String },

    /// Delete of a notification matcher. Events that matched it stop
    /// being routed to their targets — alerting silently goes quiet
    /// (no error, the notifications just stop arriving).
    NotificationMatcherDelete { name: String },

    /// Delete of an HA rule. Resources the rule constrained revert to
    /// the global HA defaults (no node preference for node-affinity,
    /// no collocation for resource-affinity). The guests don't stop —
    /// they just lose the placement constraint.
    HaRuleDelete { rule: String },

    /// `strict` flag on a node-affinity HA rule flipped on an existing
    /// rule. PVE's CRM enforces strict mode by force-migrating any
    /// guest the rule binds that's not currently on one of `nodes` —
    /// this can be a fleet-wide move within ~30s of apply. The
    /// reverse direction (strict → non-strict) is non-destructive (the
    /// constraint just relaxes), but the diff/apply layer can't tell
    /// the direction here cheaply so we surface both as Severe.
    HaRuleStrictChange { rule: String },

    /// Delete of an HA resource. Removes a VM/CT from HA management
    /// entirely (CRM stops restarting/relocating it on failure) and,
    /// via PVE's `purge=1` default, auto-removes the SID from any
    /// referencing HA rules — deleting a rule entirely if it had only
    /// this resource. The guest itself isn't affected, but the
    /// HA-policy footprint shifts meaningfully. Severe because the
    /// operator-perceived behaviour (CRM no longer recovers this
    /// guest if its node dies) is a step change.
    HaResourceDelete { sid: String },

    /// State change on an HA resource that disables CRM enforcement
    /// for it (`started`/`enabled` → `disabled` / `ignored` / `stopped`,
    /// where `stopped` means CRM keeps it stopped — not the same as
    /// the guest being stopped). Warning because the guest itself
    /// continues running (or stays stopped) by inertia, but CRM's
    /// recovery posture toward it changes. Going the other direction
    /// (re-enabling) is not flagged — additive HA management is benign.
    HaResourceStateChange {
        sid: String,
        before: String,
        after: String,
    },

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
            | Self::StorageDeleteShared { .. }
            | Self::FirewallDisabled
            | Self::FirewallGroupDelete { .. }
            | Self::MappingPciDelete { .. }
            | Self::MappingUsbDelete { .. }
            | Self::HaRuleStrictChange { .. }
            | Self::HaResourceDelete { .. } => RiskLevel::Severe,
            Self::StoragePropertyChange { .. }
            | Self::AclPropagateFlip { .. }
            | Self::AclDeleteAuditor { .. }
            | Self::BackupJobDelete { .. }
            | Self::FirewallPolicyLoosened { .. }
            | Self::FirewallAliasDelete { .. }
            | Self::FirewallIpsetDelete { .. }
            | Self::NotificationMatcherDelete { .. }
            | Self::HaRuleDelete { .. }
            | Self::HaResourceStateChange { .. } => RiskLevel::Warning,
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
            Self::FirewallDisabled => "disable the cluster firewall (enable → false) — ALL \
                 enforcement stops cluster-wide"
                .to_string(),
            Self::FirewallPolicyLoosened { direction } => format!(
                "loosen firewall {direction} default policy to ACCEPT — \
                 every unmatched packet in that direction now passes"
            ),
            Self::FirewallAliasDelete { name } => format!(
                "delete firewall alias `{name}` — rules referencing \
                 `+{name}` will break"
            ),
            Self::FirewallIpsetDelete { name } => format!(
                "delete firewall IP set `{name}` — rules referencing \
                 `+{name}` will break"
            ),
            Self::FirewallGroupDelete { group } => format!(
                "delete security group `{group}` — drops its rules \
                 (unrecoverable here) and breaks rules that reference it"
            ),
            Self::MappingPciDelete { id } => format!(
                "delete PCI passthrough mapping `{id}` — any guest with \
                 `hostpciN: mapping={id}` loses its device on next start and \
                 hard-fails migration; proxxx cannot see which guests reference it"
            ),
            Self::MappingUsbDelete { id } => format!(
                "delete USB passthrough mapping `{id}` — any guest with \
                 `usbN: mapping={id}` loses its device; proxxx cannot see which \
                 guests reference it"
            ),
            Self::NotificationMatcherDelete { name } => format!(
                "delete notification matcher `{name}` — events it matched \
                 will silently stop being routed"
            ),
            Self::HaRuleDelete { rule } => format!(
                "delete HA rule `{rule}` — constrained resources revert to \
                 global HA defaults (no node preference, no affinity)"
            ),
            Self::HaRuleStrictChange { rule } => format!(
                "node-affinity rule `{rule}` `strict` flag changed — CRM may \
                 force-migrate every constrained guest within seconds"
            ),
            Self::HaResourceDelete { sid } => format!(
                "delete HA resource `{sid}` — CRM stops restarting/relocating it; \
                 PVE's purge=1 default also auto-removes the SID from referencing \
                 rules (deleting rules that had only this resource)"
            ),
            Self::HaResourceStateChange { sid, before, after } => format!(
                "HA resource `{sid}` state changed `{before}` → `{after}` — CRM \
                 enforcement posture shifts (a move to disabled/ignored stops \
                 enforcement; a move to stopped keeps the guest stopped)"
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
        (ChangeKind::Update, "firewall_options") => {
            // Two distinct dangers hide in an options update: flipping
            // the master switch off, and loosening a default policy to
            // ACCEPT. Detect each by diffing before/after JSON.
            if let (Some(before), Some(after)) = (change.before.as_ref(), change.after.as_ref()) {
                let was_on = before.get("enable").and_then(serde_json::Value::as_bool);
                let now_off = after.get("enable").and_then(serde_json::Value::as_bool);
                if was_on == Some(true) && now_off == Some(false) {
                    out.push(StateRisk::FirewallDisabled);
                }
                for direction in ["policy_in", "policy_out"] {
                    let before_v = before.get(direction).and_then(serde_json::Value::as_str);
                    let after_v = after.get(direction).and_then(serde_json::Value::as_str);
                    if after_v == Some("ACCEPT") && before_v != Some("ACCEPT") {
                        out.push(StateRisk::FirewallPolicyLoosened { direction });
                    }
                }
            }
        }
        (ChangeKind::Delete, "firewall_alias") => {
            out.push(StateRisk::FirewallAliasDelete {
                name: change.identity.clone(),
            });
        }
        (ChangeKind::Delete, "firewall_ipset") => {
            out.push(StateRisk::FirewallIpsetDelete {
                name: change.identity.clone(),
            });
        }
        (ChangeKind::Delete, "firewall_group") => {
            out.push(StateRisk::FirewallGroupDelete {
                group: change.identity.clone(),
            });
        }
        (ChangeKind::Delete, "mapping_pci") => {
            out.push(StateRisk::MappingPciDelete {
                id: change.identity.clone(),
            });
        }
        (ChangeKind::Delete, "mapping_usb") => {
            out.push(StateRisk::MappingUsbDelete {
                id: change.identity.clone(),
            });
        }
        (ChangeKind::Delete, "notification_matcher") => {
            out.push(StateRisk::NotificationMatcherDelete {
                name: change.identity.clone(),
            });
        }
        (ChangeKind::Delete, "ha_rule") => {
            out.push(StateRisk::HaRuleDelete {
                rule: change.identity.clone(),
            });
        }
        (ChangeKind::Update, "ha_rule") => {
            // Surface `strict` flips on node-affinity rules as Severe.
            // Other Updates (resources list, comment, etc.) are routine.
            let before: Option<crate::state::model::HaRuleDecl> = change
                .before
                .as_ref()
                .and_then(|v| serde_json::from_value(v.clone()).ok());
            let after: Option<crate::state::model::HaRuleDecl> = change
                .after
                .as_ref()
                .and_then(|v| serde_json::from_value(v.clone()).ok());
            if let (Some(b), Some(a)) = (before, after) {
                if a.rule_type == "node-affinity" && b.strict != a.strict {
                    out.push(StateRisk::HaRuleStrictChange {
                        rule: change.identity.clone(),
                    });
                }
            }
        }
        (ChangeKind::Delete, "ha_resource") => {
            out.push(StateRisk::HaResourceDelete {
                sid: change.identity.clone(),
            });
        }
        (ChangeKind::Update, "ha_resource") => {
            // Surface CRM-enforcement-disabling state changes as
            // Warning. Going from `started`/`enabled` to `disabled`/
            // `ignored`/`stopped` is the worth-flagging direction.
            let before: Option<crate::state::model::HaResourceDecl> = change
                .before
                .as_ref()
                .and_then(|v| serde_json::from_value(v.clone()).ok());
            let after: Option<crate::state::model::HaResourceDecl> = change
                .after
                .as_ref()
                .and_then(|v| serde_json::from_value(v.clone()).ok());
            if let (Some(b), Some(a)) = (before, after) {
                // Normalise — empty string at PVE side means "default"
                // which is `started`. Empty stays empty for comparison
                // intent (operator didn't set it explicitly).
                let became_less_enforced =
                    matches!(a.state.as_str(), "disabled" | "ignored" | "stopped")
                        && !matches!(b.state.as_str(), "disabled" | "ignored" | "stopped");
                if became_less_enforced {
                    out.push(StateRisk::HaResourceStateChange {
                        sid: change.identity.clone(),
                        before: b.state,
                        after: a.state,
                    });
                }
            }
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
            ..Default::default()
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

    // ── Firewall ──────────────────────────────────────────

    fn fw_options_update(before: serde_json::Value, after: serde_json::Value) -> Change {
        Change {
            kind: ChangeKind::Update,
            resource: "firewall_options",
            identity: "cluster".to_string(),
            before: Some(before),
            after: Some(after),
        }
    }

    #[test]
    fn firewall_disable_is_severe() {
        let live = sample_live();
        let change = fw_options_update(
            serde_json::json!({"enable": true}),
            serde_json::json!({"enable": false}),
        );
        let risks = assess(&[change], &live);
        assert!(risks
            .iter()
            .any(|r| matches!(r, StateRisk::FirewallDisabled)));
        assert_eq!(
            risks
                .iter()
                .find(|r| matches!(r, StateRisk::FirewallDisabled))
                .unwrap()
                .level(),
            RiskLevel::Severe
        );
    }

    #[test]
    fn firewall_policy_loosened_to_accept_is_warning() {
        let live = sample_live();
        let change = fw_options_update(
            serde_json::json!({"enable": true, "policy_in": "DROP"}),
            serde_json::json!({"enable": true, "policy_in": "ACCEPT"}),
        );
        let risks = assess(&[change], &live);
        let r = risks
            .iter()
            .find(|r| matches!(r, StateRisk::FirewallPolicyLoosened { .. }))
            .expect("expected policy-loosened risk");
        assert_eq!(r.level(), RiskLevel::Warning);
        // Tightening (ACCEPT → DROP) must NOT flag.
        let tighten = fw_options_update(
            serde_json::json!({"enable": true, "policy_in": "ACCEPT"}),
            serde_json::json!({"enable": true, "policy_in": "DROP"}),
        );
        assert!(assess(&[tighten], &live).is_empty());
    }

    #[test]
    fn firewall_alias_and_ipset_delete_are_warnings() {
        let live = sample_live();
        let a = assess(&[delete_change("firewall_alias", "web")], &live);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].level(), RiskLevel::Warning);
        assert!(matches!(&a[0], StateRisk::FirewallAliasDelete { name } if name == "web"));

        let i = assess(&[delete_change("firewall_ipset", "blocklist")], &live);
        assert_eq!(i[0].level(), RiskLevel::Warning);
        assert!(matches!(&i[0], StateRisk::FirewallIpsetDelete { .. }));
    }

    #[test]
    fn firewall_group_delete_is_severe() {
        // Deleting a group drops its (unmodelled, unrecoverable) rules.
        let live = sample_live();
        let g = assess(&[delete_change("firewall_group", "web-tier")], &live);
        assert_eq!(g.len(), 1);
        assert_eq!(g[0].level(), RiskLevel::Severe);
        assert!(matches!(&g[0], StateRisk::FirewallGroupDelete { group } if group == "web-tier"));
    }

    #[test]
    fn mapping_pci_delete_is_severe() {
        // proxxx can't see which guests reference a mapping, so delete is
        // unconditionally Severe (a bound guest loses its device on next start).
        let live = sample_live();
        let r = assess(&[delete_change("mapping_pci", "gpu-rtx")], &live);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].level(), RiskLevel::Severe);
        assert!(matches!(&r[0], StateRisk::MappingPciDelete { id } if id == "gpu-rtx"));
    }

    #[test]
    fn mapping_usb_delete_is_severe() {
        let live = sample_live();
        let r = assess(&[delete_change("mapping_usb", "yubikey")], &live);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].level(), RiskLevel::Severe);
        assert!(matches!(&r[0], StateRisk::MappingUsbDelete { id } if id == "yubikey"));
    }

    #[test]
    fn notification_matcher_delete_is_warning() {
        // Deleting a matcher silently stops routing matched events.
        let live = sample_live();
        let r = assess(&[delete_change("notification_matcher", "oncall")], &live);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].level(), RiskLevel::Warning);
        assert!(matches!(&r[0], StateRisk::NotificationMatcherDelete { name } if name == "oncall"));
    }

    #[test]
    fn ha_rule_delete_is_warning() {
        let live = sample_live();
        let r = assess(&[delete_change("ha_rule", "pin-db")], &live);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].level(), RiskLevel::Warning);
        assert!(matches!(&r[0], StateRisk::HaRuleDelete { rule } if rule == "pin-db"));
    }

    #[test]
    fn ha_rule_strict_flip_is_severe() {
        // node-affinity rule with strict flipping false → true.
        // The diff layer emits Update with both sides serialised;
        // preflight inspects before/after to detect the flip.
        let before = crate::state::model::HaRuleDecl {
            rule: "pin-db".into(),
            rule_type: "node-affinity".into(),
            nodes: "pve1".into(),
            strict: false,
            ..crate::state::model::HaRuleDecl::default()
        };
        let after = crate::state::model::HaRuleDecl {
            strict: true,
            ..before.clone()
        };
        let change = Change {
            kind: ChangeKind::Update,
            resource: "ha_rule",
            identity: "pin-db".into(),
            before: Some(serde_json::to_value(&before).unwrap()),
            after: Some(serde_json::to_value(&after).unwrap()),
        };
        let live = sample_live();
        let r = assess(&[change], &live);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].level(), RiskLevel::Severe);
        assert!(matches!(&r[0], StateRisk::HaRuleStrictChange { rule } if rule == "pin-db"));
    }

    #[test]
    fn ha_rule_update_without_strict_flip_emits_no_risk() {
        // Routine Updates (resources, comment) shouldn't trigger any
        // risk — only `strict` flips on node-affinity rules do.
        let before = crate::state::model::HaRuleDecl {
            rule: "pin-db".into(),
            rule_type: "node-affinity".into(),
            nodes: "pve1".into(),
            comment: "old".into(),
            ..crate::state::model::HaRuleDecl::default()
        };
        let after = crate::state::model::HaRuleDecl {
            comment: "new".into(),
            ..before.clone()
        };
        let change = Change {
            kind: ChangeKind::Update,
            resource: "ha_rule",
            identity: "pin-db".into(),
            before: Some(serde_json::to_value(&before).unwrap()),
            after: Some(serde_json::to_value(&after).unwrap()),
        };
        let live = sample_live();
        let r = assess(&[change], &live);
        assert!(r.is_empty(), "comment-only Update must be risk-free");
    }

    // ── HA resources (epic #74 epilogue, 7/6) ─────────────────────

    #[test]
    fn ha_resource_delete_is_severe() {
        // Deleting an HA resource removes the guest from HA management
        // AND auto-purges referencing rules via PVE's purge=1 default.
        // Operator-perceived behaviour shift → Severe-tier.
        let live = sample_live();
        let r = assess(&[delete_change("ha_resource", "vm:8888")], &live);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].level(), RiskLevel::Severe);
        assert!(matches!(&r[0], StateRisk::HaResourceDelete { sid } if sid == "vm:8888"));
    }

    #[test]
    fn ha_resource_state_change_to_disabled_is_warning() {
        let before = crate::state::model::HaResourceDecl {
            sid: "vm:8888".into(),
            state: "started".into(),
            ..crate::state::model::HaResourceDecl::default()
        };
        let after = crate::state::model::HaResourceDecl {
            state: "disabled".into(),
            ..before.clone()
        };
        let change = Change {
            kind: ChangeKind::Update,
            resource: "ha_resource",
            identity: "vm:8888".into(),
            before: Some(serde_json::to_value(&before).unwrap()),
            after: Some(serde_json::to_value(&after).unwrap()),
        };
        let live = sample_live();
        let r = assess(&[change], &live);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].level(), RiskLevel::Warning);
        assert!(matches!(
            &r[0],
            StateRisk::HaResourceStateChange { sid, before, after }
                if sid == "vm:8888" && before == "started" && after == "disabled"
        ));
    }

    #[test]
    fn ha_resource_state_change_re_enable_emits_no_risk() {
        // The Warning fires only on enforcement-DISABLING transitions.
        // Going from disabled → started (re-enabling HA management)
        // is additive and risk-free.
        let before = crate::state::model::HaResourceDecl {
            sid: "vm:8888".into(),
            state: "disabled".into(),
            ..crate::state::model::HaResourceDecl::default()
        };
        let after = crate::state::model::HaResourceDecl {
            state: "started".into(),
            ..before.clone()
        };
        let change = Change {
            kind: ChangeKind::Update,
            resource: "ha_resource",
            identity: "vm:8888".into(),
            before: Some(serde_json::to_value(&before).unwrap()),
            after: Some(serde_json::to_value(&after).unwrap()),
        };
        let live = sample_live();
        let r = assess(&[change], &live);
        assert!(
            r.is_empty(),
            "re-enabling HA management (disabled → started) must not trigger a warning"
        );
    }

    #[test]
    fn ha_resource_update_routine_field_change_emits_no_risk() {
        // Tweaking max_restart / comment / failback without flipping
        // the enforcement posture is risk-free.
        let before = crate::state::model::HaResourceDecl {
            sid: "ct:7777".into(),
            state: "started".into(),
            max_restart: 3,
            ..crate::state::model::HaResourceDecl::default()
        };
        let after = crate::state::model::HaResourceDecl {
            max_restart: 5,
            ..before.clone()
        };
        let change = Change {
            kind: ChangeKind::Update,
            resource: "ha_resource",
            identity: "ct:7777".into(),
            before: Some(serde_json::to_value(&before).unwrap()),
            after: Some(serde_json::to_value(&after).unwrap()),
        };
        let live = sample_live();
        let r = assess(&[change], &live);
        assert!(
            r.is_empty(),
            "max_restart tweak (state preserved) must not flag any risk"
        );
    }
}
