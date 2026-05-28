//! Apply layer — converge live cluster state toward declared state.
//!
//! Consumes a [`Vec<Change>`] from [`crate::state::diff`] and
//! dispatches each change to the right PVE API call. Returns one
//! [`ApplyOutcome`] per change so the caller can render a per-row
//! summary (applied / skipped / failed).
//!
//! ## Safety model
//!
//! * **`--dry-run`** — every change is reported as `Skipped { reason:
//!   DryRun }`; no PVE call is issued. Always safe.
//! * **`--prune`** — required to actually execute `Delete` changes.
//!   Without it, `Delete` reports as `Skipped { reason: PrunePolicy }`
//!   — useful as a "what would prune?" preview.
//! * **Failure semantics** — by default, the first failure halts the
//!   apply (the remaining changes report as `Skipped { reason:
//!   AbortedByPrior }`). `--continue-on-error` reverses this.
//!
//! Pre-flight + HITL gating per change is layered ON TOP of this
//! dispatch (shipped v0.3.0): the apply layer dispatches via the raw
//! `StateWriteView` trait, and `state::preflight` interposes the risk
//! gate (refusing Severe changes without `--allow-risk`, with optional
//! `--interactive` per-Severe stdin prompts) before the dispatch runs.
//! Keeping the gate in an outer layer is why this module stays a clean
//! pure-dispatch unit.
//!
//! ## What apply supports today (per epic #74)
//!
//! | Resource | Create | Update | Delete |
//! | :--- | :---: | :---: | :---: |
//! | Pool | ✓ | ✓ (comment + membership diff) | ✓ |
//! | ACL | ✓ | ✓ (delete + recreate with new propagate) | ✓ |
//! | Storage | ✓ | ✓ (mutable fields only) | ✓ |
//! | Backup job | ✓ | ✓ (all mutable fields) | ✓ |
//! | Firewall options | — | ✓ (singleton, update-only) | — |
//! | Firewall alias | ✓ | ✓ (cidr + comment) | ✓ |
//! | Firewall ipset | ✓ | ✓ (comment → recreate; CIDR delta) | ✓ |
//! | Firewall group | ✓ | — (no PVE update; rules read-only) | ✓ |
//! | Notification matcher | ✓ | ✓ (all fields) | ✓ |

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Serialize;

use crate::api::types::{Pool, PoolDetails};
use crate::state::diff::{Change, ChangeKind};
use crate::state::model::{
    AclDecl, BackupJobDecl, FirewallAliasDecl, FirewallGroupDecl, FirewallIpsetCidrDecl,
    FirewallIpsetDecl, FirewallOptionsDecl, HaRuleDecl, NotificationMatcherDecl, PoolDecl,
    StorageDecl,
};

/// Options controlling apply behaviour.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApplyOptions {
    /// If true, no PVE call is issued — every change is reported as
    /// `Skipped { reason: DryRun }`.
    pub dry_run: bool,
    /// If true, `Delete` changes are executed. Without `--prune`,
    /// deletes report as `Skipped { reason: PrunePolicy }`.
    pub prune: bool,
    /// If true, individual change failures don't halt the apply —
    /// the remainder of the changes continues. Default behaviour
    /// is fail-fast.
    pub continue_on_error: bool,
}

/// Why a change was skipped instead of applied. Surfaced verbatim in
/// the JSON output so operators can grep for the exact policy that
/// blocked an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// `--dry-run` was set; no PVE call issued for any change.
    DryRun,
    /// `Delete` change but `--prune` was NOT set.
    PrunePolicy,
    /// A previous change in this apply failed and
    /// `--continue-on-error` was not set, so the rest of the apply
    /// is aborted.
    AbortedByPrior,
}

/// Outcome of attempting to apply a single change.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ApplyResult {
    /// Change was applied successfully — PVE returned 2xx.
    Applied,
    /// Change was deliberately not attempted; see `reason`.
    Skipped { reason: SkipReason },
    /// PVE rejected the change. `error` carries the full error
    /// chain for operator diagnosis.
    Failed { error: String },
}

/// One row in the apply output. Pairs the original [`Change`] with
/// what happened. The full original `Change` is kept so JSON
/// consumers can correlate without a second lookup.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyOutcome {
    pub change: Change,
    #[serde(flatten)]
    pub result: ApplyResult,
}

/// Narrow write-side trait. Blanket impl over [`ProxmoxGateway`]
/// covers production; tests implement this directly so the apply
/// dispatch logic can be unit-tested without the 200+ methods of
/// `ProxmoxGateway`.
#[async_trait]
pub trait StateWriteView: Send + Sync {
    // ── Pool surface ──────────────────────────────────────
    async fn list_pools_view(&self) -> Result<Vec<Pool>>;
    async fn get_pool_view(&self, poolid: &str) -> Result<PoolDetails>;
    async fn create_pool_view(&self, params: &[(&str, &str)]) -> Result<()>;
    async fn update_pool_view(&self, poolid: &str, params: &[(&str, &str)]) -> Result<()>;
    async fn delete_pool_view(&self, poolid: &str) -> Result<()>;

    // ── ACL surface ───────────────────────────────────────
    #[allow(clippy::too_many_arguments)]
    async fn modify_acl_view(
        &self,
        path: &str,
        roles: &str,
        users: Option<&str>,
        groups: Option<&str>,
        tokens: Option<&str>,
        propagate: bool,
        delete: bool,
    ) -> Result<()>;

    // ── Storage surface ───────────────────────────────────
    async fn create_cluster_storage_view(&self, params: &[(&str, &str)]) -> Result<()>;
    async fn update_cluster_storage_view(
        &self,
        storage: &str,
        params: &[(&str, &str)],
    ) -> Result<()>;
    async fn delete_cluster_storage_view(&self, storage: &str) -> Result<()>;

    // ── Backup-job surface ────────────────────────────────
    async fn create_backup_job_view(&self, params: &[(&str, &str)]) -> Result<()>;
    async fn update_backup_job_view(&self, id: &str, params: &[(&str, &str)]) -> Result<()>;
    async fn delete_backup_job_view(&self, id: &str) -> Result<()>;

    // ── Cluster-firewall surface ──────────────────────────
    async fn update_cluster_firewall_options_view(&self, params: &[(&str, &str)]) -> Result<()>;
    async fn create_cluster_firewall_alias_view(&self, params: &[(&str, &str)]) -> Result<()>;
    async fn update_cluster_firewall_alias_view(
        &self,
        name: &str,
        params: &[(&str, &str)],
    ) -> Result<()>;
    async fn delete_cluster_firewall_alias_view(&self, name: &str) -> Result<()>;
    async fn create_cluster_firewall_ipset_view(&self, params: &[(&str, &str)]) -> Result<()>;
    async fn delete_cluster_firewall_ipset_view(&self, name: &str) -> Result<()>;
    async fn add_cluster_firewall_ipset_cidr_view(
        &self,
        name: &str,
        params: &[(&str, &str)],
    ) -> Result<()>;
    async fn remove_cluster_firewall_ipset_cidr_view(&self, name: &str, cidr: &str) -> Result<()>;
    async fn create_cluster_firewall_group_view(&self, params: &[(&str, &str)]) -> Result<()>;
    async fn delete_cluster_firewall_group_view(&self, group: &str) -> Result<()>;

    // ── Notification matchers ─────────────────────────────
    async fn create_notification_matcher_view(&self, params: &[(&str, &str)]) -> Result<()>;
    async fn update_notification_matcher_view(
        &self,
        name: &str,
        params: &[(&str, &str)],
    ) -> Result<()>;
    async fn delete_notification_matcher_view(&self, name: &str) -> Result<()>;

    // ── HA rules (PVE 9, epic #74) ────────────────────────
    async fn create_ha_rule_view(&self, params: &[(&str, &str)]) -> Result<()>;
    async fn update_ha_rule_view(&self, rule: &str, params: &[(&str, &str)]) -> Result<()>;
    async fn delete_ha_rule_view(&self, rule: &str) -> Result<()>;
}

#[async_trait]
impl<T> StateWriteView for T
where
    T: crate::api::ProxmoxGateway + Send + Sync + ?Sized,
{
    async fn list_pools_view(&self) -> Result<Vec<Pool>> {
        crate::api::ProxmoxGateway::list_pools(self).await
    }
    async fn get_pool_view(&self, poolid: &str) -> Result<PoolDetails> {
        crate::api::ProxmoxGateway::get_pool(self, poolid).await
    }
    async fn create_pool_view(&self, params: &[(&str, &str)]) -> Result<()> {
        crate::api::ProxmoxGateway::create_pool(self, params).await
    }
    async fn update_pool_view(&self, poolid: &str, params: &[(&str, &str)]) -> Result<()> {
        crate::api::ProxmoxGateway::update_pool(self, poolid, params).await
    }
    async fn delete_pool_view(&self, poolid: &str) -> Result<()> {
        crate::api::ProxmoxGateway::delete_pool(self, poolid).await
    }

    async fn modify_acl_view(
        &self,
        path: &str,
        roles: &str,
        users: Option<&str>,
        groups: Option<&str>,
        tokens: Option<&str>,
        propagate: bool,
        delete: bool,
    ) -> Result<()> {
        crate::api::ProxmoxGateway::modify_acl(
            self, path, roles, users, groups, tokens, propagate, delete,
        )
        .await
    }

    async fn create_cluster_storage_view(&self, params: &[(&str, &str)]) -> Result<()> {
        crate::api::ProxmoxGateway::create_cluster_storage(self, params).await
    }
    async fn update_cluster_storage_view(
        &self,
        storage: &str,
        params: &[(&str, &str)],
    ) -> Result<()> {
        crate::api::ProxmoxGateway::update_cluster_storage(self, storage, params).await
    }
    async fn create_backup_job_view(&self, params: &[(&str, &str)]) -> Result<()> {
        crate::api::ProxmoxGateway::create_backup_job(self, params).await
    }
    async fn update_backup_job_view(&self, id: &str, params: &[(&str, &str)]) -> Result<()> {
        crate::api::ProxmoxGateway::update_backup_job(self, id, params).await
    }
    async fn delete_backup_job_view(&self, id: &str) -> Result<()> {
        crate::api::ProxmoxGateway::delete_backup_job(self, id).await
    }

    async fn delete_cluster_storage_view(&self, storage: &str) -> Result<()> {
        crate::api::ProxmoxGateway::delete_cluster_storage(self, storage).await
    }

    async fn update_cluster_firewall_options_view(&self, params: &[(&str, &str)]) -> Result<()> {
        crate::api::ProxmoxGateway::update_cluster_firewall_options(self, params).await
    }
    async fn create_cluster_firewall_alias_view(&self, params: &[(&str, &str)]) -> Result<()> {
        crate::api::ProxmoxGateway::create_cluster_firewall_alias(self, params).await
    }
    async fn update_cluster_firewall_alias_view(
        &self,
        name: &str,
        params: &[(&str, &str)],
    ) -> Result<()> {
        crate::api::ProxmoxGateway::update_cluster_firewall_alias(self, name, params).await
    }
    async fn delete_cluster_firewall_alias_view(&self, name: &str) -> Result<()> {
        crate::api::ProxmoxGateway::delete_cluster_firewall_alias(self, name).await
    }
    async fn create_cluster_firewall_ipset_view(&self, params: &[(&str, &str)]) -> Result<()> {
        crate::api::ProxmoxGateway::create_cluster_firewall_ipset(self, params).await
    }
    async fn delete_cluster_firewall_ipset_view(&self, name: &str) -> Result<()> {
        crate::api::ProxmoxGateway::delete_cluster_firewall_ipset(self, name).await
    }
    async fn add_cluster_firewall_ipset_cidr_view(
        &self,
        name: &str,
        params: &[(&str, &str)],
    ) -> Result<()> {
        crate::api::ProxmoxGateway::add_cluster_firewall_ipset_cidr(self, name, params).await
    }
    async fn remove_cluster_firewall_ipset_cidr_view(&self, name: &str, cidr: &str) -> Result<()> {
        crate::api::ProxmoxGateway::remove_cluster_firewall_ipset_cidr(self, name, cidr).await
    }
    async fn create_cluster_firewall_group_view(&self, params: &[(&str, &str)]) -> Result<()> {
        crate::api::ProxmoxGateway::create_cluster_firewall_group(self, params).await
    }
    async fn delete_cluster_firewall_group_view(&self, group: &str) -> Result<()> {
        crate::api::ProxmoxGateway::delete_cluster_firewall_group(self, group).await
    }

    async fn create_notification_matcher_view(&self, params: &[(&str, &str)]) -> Result<()> {
        crate::api::ProxmoxGateway::create_notification_matcher(self, params).await
    }
    async fn update_notification_matcher_view(
        &self,
        name: &str,
        params: &[(&str, &str)],
    ) -> Result<()> {
        crate::api::ProxmoxGateway::update_notification_matcher(self, name, params).await
    }
    async fn delete_notification_matcher_view(&self, name: &str) -> Result<()> {
        crate::api::ProxmoxGateway::delete_notification_matcher(self, name).await
    }

    async fn create_ha_rule_view(&self, params: &[(&str, &str)]) -> Result<()> {
        crate::api::ProxmoxGateway::create_ha_rule(self, params).await
    }
    async fn update_ha_rule_view(&self, rule: &str, params: &[(&str, &str)]) -> Result<()> {
        crate::api::ProxmoxGateway::update_ha_rule(self, rule, params).await
    }
    async fn delete_ha_rule_view(&self, rule: &str) -> Result<()> {
        crate::api::ProxmoxGateway::delete_ha_rule(self, rule).await
    }
}

/// Apply a list of changes, in order, against a live cluster.
///
/// Order matters: the caller (typically `state::diff::diff`) already
/// produces a sensible order — Delete → Update → Create per family,
/// and pool → acl → storage across families. We honour that.
pub async fn apply<C: StateWriteView + ?Sized>(
    client: &C,
    changes: Vec<Change>,
    opts: ApplyOptions,
) -> Vec<ApplyOutcome> {
    let mut out: Vec<ApplyOutcome> = Vec::with_capacity(changes.len());
    let mut aborted = false;

    for change in changes {
        if aborted {
            out.push(ApplyOutcome {
                change,
                result: ApplyResult::Skipped {
                    reason: SkipReason::AbortedByPrior,
                },
            });
            continue;
        }
        if opts.dry_run {
            out.push(ApplyOutcome {
                change,
                result: ApplyResult::Skipped {
                    reason: SkipReason::DryRun,
                },
            });
            continue;
        }
        if change.kind == ChangeKind::Delete && !opts.prune {
            out.push(ApplyOutcome {
                change,
                result: ApplyResult::Skipped {
                    reason: SkipReason::PrunePolicy,
                },
            });
            continue;
        }

        let result = apply_one(client, &change).await;
        let failed = matches!(result, ApplyResult::Failed { .. });
        out.push(ApplyOutcome { change, result });
        if failed && !opts.continue_on_error {
            aborted = true;
        }
    }

    out
}

async fn apply_one<C: StateWriteView + ?Sized>(client: &C, change: &Change) -> ApplyResult {
    let res = match (change.resource, change.kind) {
        ("pool", ChangeKind::Create) => apply_pool_create(client, change).await,
        ("pool", ChangeKind::Update) => apply_pool_update(client, change).await,
        ("pool", ChangeKind::Delete) => apply_pool_delete(client, change).await,
        ("acl", ChangeKind::Create) => apply_acl_create(client, change).await,
        ("acl", ChangeKind::Update) => apply_acl_update(client, change).await,
        ("acl", ChangeKind::Delete) => apply_acl_delete(client, change).await,
        ("storage", ChangeKind::Create) => apply_storage_create(client, change).await,
        ("storage", ChangeKind::Update) => apply_storage_update(client, change).await,
        ("storage", ChangeKind::Delete) => apply_storage_delete(client, change).await,
        ("backup_job", ChangeKind::Create) => apply_backupjob_create(client, change).await,
        ("backup_job", ChangeKind::Update) => apply_backupjob_update(client, change).await,
        ("backup_job", ChangeKind::Delete) => apply_backupjob_delete(client, change).await,
        ("firewall_options", ChangeKind::Update) => apply_fw_options_update(client, change).await,
        ("firewall_alias", ChangeKind::Create) => apply_fw_alias_create(client, change).await,
        ("firewall_alias", ChangeKind::Update) => apply_fw_alias_update(client, change).await,
        ("firewall_alias", ChangeKind::Delete) => apply_fw_alias_delete(client, change).await,
        ("firewall_ipset", ChangeKind::Create) => apply_fw_ipset_create(client, change).await,
        ("firewall_ipset", ChangeKind::Update) => apply_fw_ipset_update(client, change).await,
        ("firewall_ipset", ChangeKind::Delete) => apply_fw_ipset_delete(client, change).await,
        ("firewall_group", ChangeKind::Create) => apply_fw_group_create(client, change).await,
        ("firewall_group", ChangeKind::Delete) => apply_fw_group_delete(client, change).await,
        ("notification_matcher", ChangeKind::Create) => {
            apply_notif_matcher_create(client, change).await
        }
        ("notification_matcher", ChangeKind::Update) => {
            apply_notif_matcher_update(client, change).await
        }
        ("notification_matcher", ChangeKind::Delete) => {
            apply_notif_matcher_delete(client, change).await
        }
        ("ha_rule", ChangeKind::Create) => apply_ha_rule_create(client, change).await,
        ("ha_rule", ChangeKind::Update) => apply_ha_rule_update(client, change).await,
        ("ha_rule", ChangeKind::Delete) => apply_ha_rule_delete(client, change).await,
        (resource, kind) => Err(anyhow::anyhow!(
            "unhandled change shape: resource={resource} kind={kind:?}"
        )),
    };
    match res {
        Ok(()) => ApplyResult::Applied,
        Err(e) => ApplyResult::Failed {
            error: format!("{e:#}"),
        },
    }
}

// ── Pool ─────────────────────────────────────────────────────

async fn apply_pool_create<C: StateWriteView + ?Sized>(client: &C, change: &Change) -> Result<()> {
    let decl: PoolDecl = serde_json::from_value(
        change
            .after
            .clone()
            .context("pool create change missing `after` value")?,
    )
    .context("decoding PoolDecl from change.after")?;

    let mut params: Vec<(&str, &str)> = vec![("poolid", decl.poolid.as_str())];
    if !decl.comment.is_empty() {
        params.push(("comment", decl.comment.as_str()));
    }
    client.create_pool_view(&params).await?;

    // Membership is set in a follow-up update — `create_pool` doesn't
    // accept members. Translate the declared members into the
    // `vms` / `storage` CSV split PVE expects.
    let (vms_csv, storage_csv) = split_pool_members(&decl.members);
    if !vms_csv.is_empty() || !storage_csv.is_empty() {
        let mut params: Vec<(&str, &str)> = Vec::new();
        if !vms_csv.is_empty() {
            params.push(("vms", vms_csv.as_str()));
        }
        if !storage_csv.is_empty() {
            params.push(("storage", storage_csv.as_str()));
        }
        client.update_pool_view(&decl.poolid, &params).await?;
    }
    Ok(())
}

async fn apply_pool_update<C: StateWriteView + ?Sized>(client: &C, change: &Change) -> Result<()> {
    let before: PoolDecl = serde_json::from_value(
        change
            .before
            .clone()
            .context("pool update change missing `before` value")?,
    )
    .context("decoding PoolDecl from change.before")?;
    let after: PoolDecl = serde_json::from_value(
        change
            .after
            .clone()
            .context("pool update change missing `after` value")?,
    )
    .context("decoding PoolDecl from change.after")?;

    // Comment change → single PUT.
    if before.comment != after.comment {
        let params: Vec<(&str, &str)> = vec![("comment", after.comment.as_str())];
        client.update_pool_view(&after.poolid, &params).await?;
    }

    // Membership change → compute add + remove sets, fire as two
    // PUTs (PVE doesn't have a "replace members" operation).
    let to_remove = members_diff(&before.members, &after.members);
    let to_add = members_diff(&after.members, &before.members);

    if !to_remove.is_empty() {
        let (vms_csv, storage_csv) = split_pool_members(&to_remove);
        let mut params: Vec<(&str, &str)> = vec![("delete", "1")];
        if !vms_csv.is_empty() {
            params.push(("vms", vms_csv.as_str()));
        }
        if !storage_csv.is_empty() {
            params.push(("storage", storage_csv.as_str()));
        }
        client.update_pool_view(&after.poolid, &params).await?;
    }
    if !to_add.is_empty() {
        let (vms_csv, storage_csv) = split_pool_members(&to_add);
        let mut params: Vec<(&str, &str)> = Vec::new();
        if !vms_csv.is_empty() {
            params.push(("vms", vms_csv.as_str()));
        }
        if !storage_csv.is_empty() {
            params.push(("storage", storage_csv.as_str()));
        }
        client.update_pool_view(&after.poolid, &params).await?;
    }
    Ok(())
}

async fn apply_pool_delete<C: StateWriteView + ?Sized>(client: &C, change: &Change) -> Result<()> {
    let decl: PoolDecl = serde_json::from_value(
        change
            .before
            .clone()
            .context("pool delete change missing `before` value")?,
    )
    .context("decoding PoolDecl from change.before")?;

    // PVE refuses to delete a non-empty pool. Drain members first.
    if !decl.members.is_empty() {
        let (vms_csv, storage_csv) = split_pool_members(&decl.members);
        let mut params: Vec<(&str, &str)> = vec![("delete", "1")];
        if !vms_csv.is_empty() {
            params.push(("vms", vms_csv.as_str()));
        }
        if !storage_csv.is_empty() {
            params.push(("storage", storage_csv.as_str()));
        }
        client.update_pool_view(&decl.poolid, &params).await?;
    }
    client.delete_pool_view(&decl.poolid).await
}

/// Split a `Vec<"qemu/100" | "lxc/200" | "storage/foo">` into the
/// `(vms_csv, storage_csv)` pair PVE expects on `POST /pools/<id>`.
/// Member references with unknown prefixes are dropped (would have
/// been logged as warnings at export time).
fn split_pool_members(members: &[String]) -> (String, String) {
    let mut vms: Vec<&str> = Vec::new();
    let mut storage: Vec<&str> = Vec::new();
    for m in members {
        if let Some(id) = m.strip_prefix("qemu/").or_else(|| m.strip_prefix("lxc/")) {
            vms.push(id);
        } else if let Some(name) = m.strip_prefix("storage/") {
            storage.push(name);
        }
    }
    (vms.join(","), storage.join(","))
}

/// Set-difference: items in `a` but not in `b`. Order-preserving.
fn members_diff(a: &[String], b: &[String]) -> Vec<String> {
    use std::collections::HashSet;
    let b_set: HashSet<&str> = b.iter().map(String::as_str).collect();
    a.iter()
        .filter(|m| !b_set.contains(m.as_str()))
        .cloned()
        .collect()
}

// ── ACL ──────────────────────────────────────────────────────

async fn apply_acl_create<C: StateWriteView + ?Sized>(client: &C, change: &Change) -> Result<()> {
    let decl: AclDecl = serde_json::from_value(
        change
            .after
            .clone()
            .context("acl create change missing `after` value")?,
    )
    .context("decoding AclDecl from change.after")?;
    modify_acl_for_decl(client, &decl, false).await
}

async fn apply_acl_delete<C: StateWriteView + ?Sized>(client: &C, change: &Change) -> Result<()> {
    let decl: AclDecl = serde_json::from_value(
        change
            .before
            .clone()
            .context("acl delete change missing `before` value")?,
    )
    .context("decoding AclDecl from change.before")?;
    modify_acl_for_decl(client, &decl, true).await
}

async fn apply_acl_update<C: StateWriteView + ?Sized>(client: &C, change: &Change) -> Result<()> {
    // PVE's `PUT /access/acl` is set-or-clear, no in-place update. So
    // an Update on ACL (typically a propagate toggle, since the
    // identity 4-tuple covers everything else) is delete + recreate.
    let before: AclDecl = serde_json::from_value(
        change
            .before
            .clone()
            .context("acl update change missing `before` value")?,
    )
    .context("decoding AclDecl from change.before")?;
    let after: AclDecl = serde_json::from_value(
        change
            .after
            .clone()
            .context("acl update change missing `after` value")?,
    )
    .context("decoding AclDecl from change.after")?;

    modify_acl_for_decl(client, &before, true).await?;
    modify_acl_for_decl(client, &after, false).await?;
    Ok(())
}

async fn modify_acl_for_decl<C: StateWriteView + ?Sized>(
    client: &C,
    decl: &AclDecl,
    delete: bool,
) -> Result<()> {
    // PVE's `modify_acl` takes the subject in one of three optional
    // CSV fields depending on `kind`. Map the AclDecl's discriminator
    // here.
    let (users, groups, tokens) = match decl.kind.as_str() {
        "user" => (Some(decl.ugid.as_str()), None, None),
        "group" => (None, Some(decl.ugid.as_str()), None),
        "token" => (None, None, Some(decl.ugid.as_str())),
        other => anyhow::bail!(
            "ACL kind '{other}' not supported by `modify_acl` — expected user / group / token"
        ),
    };
    client
        .modify_acl_view(
            &decl.path,
            &decl.roleid,
            users,
            groups,
            tokens,
            decl.propagate,
            delete,
        )
        .await
}

// ── Storage ──────────────────────────────────────────────────

async fn apply_storage_create<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let decl: StorageDecl = serde_json::from_value(
        change
            .after
            .clone()
            .context("storage create change missing `after` value")?,
    )
    .context("decoding StorageDecl from change.after")?;

    let mut params: Vec<(String, String)> = Vec::new();
    params.push(("storage".to_string(), decl.storage.clone()));
    params.push(("type".to_string(), decl.storage_type.clone()));
    if !decl.content.is_empty() {
        params.push(("content".to_string(), decl.content.clone()));
    }
    if !decl.nodes.is_empty() {
        params.push(("nodes".to_string(), decl.nodes.clone()));
    }
    if decl.disable {
        params.push(("disable".to_string(), "1".to_string()));
    }
    if decl.shared {
        params.push(("shared".to_string(), "1".to_string()));
    }
    push_optional(&mut params, "path", &decl.path);
    push_optional(&mut params, "pool", &decl.pool);
    push_optional(&mut params, "server", &decl.server);
    push_optional(&mut params, "export", &decl.export);
    push_optional(&mut params, "datastore", &decl.datastore);
    push_optional(&mut params, "fingerprint", &decl.fingerprint);
    push_optional(&mut params, "username", &decl.username);
    push_optional(&mut params, "vgname", &decl.vgname);
    push_optional(&mut params, "thinpool", &decl.thinpool);

    let borrowed: Vec<(&str, &str)> = params
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    client.create_cluster_storage_view(&borrowed).await
}

async fn apply_storage_update<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let after: StorageDecl = serde_json::from_value(
        change
            .after
            .clone()
            .context("storage update change missing `after` value")?,
    )
    .context("decoding StorageDecl from change.after")?;

    // `type` and `storage` are immutable; PVE rejects PUT with them
    // in the body. Build the mutable subset.
    let mut params: Vec<(String, String)> = Vec::new();
    if !after.content.is_empty() {
        params.push(("content".to_string(), after.content.clone()));
    }
    if !after.nodes.is_empty() {
        params.push(("nodes".to_string(), after.nodes.clone()));
    }
    params.push((
        "disable".to_string(),
        if after.disable { "1" } else { "0" }.to_string(),
    ));
    push_optional(&mut params, "fingerprint", &after.fingerprint);
    push_optional(&mut params, "username", &after.username);
    // path/pool/server/export/datastore/vgname/thinpool/shared are
    // immutable in PVE — operator must recreate the storage to change
    // them. We don't error on attempt; PVE will reject and the
    // outcome surfaces the message verbatim.

    let borrowed: Vec<(&str, &str)> = params
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    client
        .update_cluster_storage_view(&after.storage, &borrowed)
        .await
}

async fn apply_storage_delete<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let decl: StorageDecl = serde_json::from_value(
        change
            .before
            .clone()
            .context("storage delete change missing `before` value")?,
    )
    .context("decoding StorageDecl from change.before")?;
    client.delete_cluster_storage_view(&decl.storage).await
}

// ── Backup job ───────────────────────────────────────────────

/// Build the `POST`/`PUT /cluster/backup` param set from a decl.
/// `include_id` is true for create (PVE accepts a caller id) and
/// false for update (the id is the URL segment, not a body param).
fn backup_job_params(decl: &BackupJobDecl, include_id: bool) -> Vec<(String, String)> {
    let mut params: Vec<(String, String)> = Vec::new();
    if include_id {
        params.push(("id".to_string(), decl.id.clone()));
    }
    push_optional(&mut params, "schedule", &decl.schedule);
    push_optional(&mut params, "storage", &decl.storage);
    push_optional(&mut params, "mode", &decl.mode);
    // `enabled` is always sent (0/1) so an Update that flips it to
    // false actually disables the job rather than leaving it enabled.
    params.push((
        "enabled".to_string(),
        if decl.enabled { "1" } else { "0" }.to_string(),
    ));
    // `all` and `vmid` are mutually exclusive in PVE — send whichever
    // the decl set. `all = true` wins; otherwise the explicit vmid CSV.
    if decl.all {
        params.push(("all".to_string(), "1".to_string()));
    } else {
        push_optional(&mut params, "vmid", &decl.vmid);
    }
    push_optional(&mut params, "node", &decl.node);
    push_optional(&mut params, "mailto", &decl.mailto);
    push_optional(&mut params, "compress", &decl.compress);
    push_optional(&mut params, "comment", &decl.comment);
    // PVE serialises these two with hyphens.
    push_optional(&mut params, "notes-template", &decl.notes_template);
    push_optional(&mut params, "prune-backups", &decl.prune_backups);
    params
}

async fn apply_backupjob_create<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let decl: BackupJobDecl = serde_json::from_value(
        change
            .after
            .clone()
            .context("backup_job create change missing `after` value")?,
    )
    .context("decoding BackupJobDecl from change.after")?;
    let params = backup_job_params(&decl, true);
    let borrowed: Vec<(&str, &str)> = params
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    client.create_backup_job_view(&borrowed).await
}

async fn apply_backupjob_update<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let after: BackupJobDecl = serde_json::from_value(
        change
            .after
            .clone()
            .context("backup_job update change missing `after` value")?,
    )
    .context("decoding BackupJobDecl from change.after")?;
    let params = backup_job_params(&after, false);
    let borrowed: Vec<(&str, &str)> = params
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    client.update_backup_job_view(&after.id, &borrowed).await
}

async fn apply_backupjob_delete<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let decl: BackupJobDecl = serde_json::from_value(
        change
            .before
            .clone()
            .context("backup_job delete change missing `before` value")?,
    )
    .context("decoding BackupJobDecl from change.before")?;
    client.delete_backup_job_view(&decl.id).await
}

// ── Cluster firewall ─────────────────────────────────────────

fn decode<T: serde::de::DeserializeOwned>(v: Option<&serde_json::Value>, what: &str) -> Result<T> {
    let val = v
        .cloned()
        .with_context(|| format!("{what}: missing value"))?;
    serde_json::from_value(val).with_context(|| format!("decoding {what}"))
}

fn borrow(params: &[(String, String)]) -> Vec<(&str, &str)> {
    params
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect()
}

/// Update the firewall options singleton. `enable` and `ebtables` are
/// always sent (0/1) — the declared block is authoritative, so an
/// omitted bool means "off". Policy / ratelimit strings are sent only
/// when non-empty (empty = leave PVE's current value).
async fn apply_fw_options_update<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let after: FirewallOptionsDecl = decode(change.after.as_ref(), "firewall options")?;
    let mut params: Vec<(String, String)> = Vec::new();
    params.push((
        "enable".to_string(),
        if after.enable { "1" } else { "0" }.to_string(),
    ));
    params.push((
        "ebtables".to_string(),
        if after.ebtables { "1" } else { "0" }.to_string(),
    ));
    push_optional(&mut params, "policy_in", &after.policy_in);
    push_optional(&mut params, "policy_out", &after.policy_out);
    push_optional(&mut params, "log_ratelimit", &after.log_ratelimit);
    client
        .update_cluster_firewall_options_view(&borrow(&params))
        .await
}

fn fw_alias_params(decl: &FirewallAliasDecl, include_name: bool) -> Vec<(String, String)> {
    let mut params: Vec<(String, String)> = Vec::new();
    if include_name {
        params.push(("name".to_string(), decl.name.clone()));
    }
    params.push(("cidr".to_string(), decl.cidr.clone()));
    push_optional(&mut params, "comment", &decl.comment);
    params
}

async fn apply_fw_alias_create<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let decl: FirewallAliasDecl = decode(change.after.as_ref(), "firewall alias")?;
    let params = fw_alias_params(&decl, true);
    client
        .create_cluster_firewall_alias_view(&borrow(&params))
        .await
}

async fn apply_fw_alias_update<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let after: FirewallAliasDecl = decode(change.after.as_ref(), "firewall alias")?;
    let params = fw_alias_params(&after, false);
    client
        .update_cluster_firewall_alias_view(&after.name, &borrow(&params))
        .await
}

async fn apply_fw_alias_delete<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let decl: FirewallAliasDecl = decode(change.before.as_ref(), "firewall alias")?;
    client.delete_cluster_firewall_alias_view(&decl.name).await
}

fn fw_cidr_params(c: &FirewallIpsetCidrDecl) -> Vec<(String, String)> {
    let mut params: Vec<(String, String)> = vec![("cidr".to_string(), c.cidr.clone())];
    push_optional(&mut params, "comment", &c.comment);
    if c.nomatch {
        params.push(("nomatch".to_string(), "1".to_string()));
    }
    params
}

/// Create an IP set, then add every declared CIDR. Order: the set must
/// exist before its members can be attached.
async fn apply_fw_ipset_create<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let decl: FirewallIpsetDecl = decode(change.after.as_ref(), "firewall ipset")?;
    let mut set_params: Vec<(String, String)> = vec![("name".to_string(), decl.name.clone())];
    push_optional(&mut set_params, "comment", &decl.comment);
    client
        .create_cluster_firewall_ipset_view(&borrow(&set_params))
        .await?;
    for c in &decl.cidrs {
        let p = fw_cidr_params(c);
        client
            .add_cluster_firewall_ipset_cidr_view(&decl.name, &borrow(&p))
            .await?;
    }
    Ok(())
}

/// Delete an IP set. Members are removed first (some PVE versions
/// refuse to delete a non-empty set), then the set itself.
async fn apply_fw_ipset_delete<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let decl: FirewallIpsetDecl = decode(change.before.as_ref(), "firewall ipset")?;
    for c in &decl.cidrs {
        client
            .remove_cluster_firewall_ipset_cidr_view(&decl.name, &c.cidr)
            .await?;
    }
    client.delete_cluster_firewall_ipset_view(&decl.name).await
}

/// Reconcile an IP set update. A `comment` change forces delete+
/// recreate (PVE has no set-update endpoint) — the declared CIDRs are
/// re-added afterwards, so it's lossless. When only the membership
/// changed, apply the minimal CIDR delta (a changed entry = remove +
/// re-add, since CIDR entries have no in-place update either).
async fn apply_fw_ipset_update<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    use std::collections::HashMap;
    let before: FirewallIpsetDecl = decode(change.before.as_ref(), "firewall ipset")?;
    let after: FirewallIpsetDecl = decode(change.after.as_ref(), "firewall ipset")?;

    if before.comment != after.comment {
        // No set-update endpoint: delete (members first) then recreate
        // with the new comment and re-add every declared CIDR.
        for c in &before.cidrs {
            client
                .remove_cluster_firewall_ipset_cidr_view(&before.name, &c.cidr)
                .await?;
        }
        client
            .delete_cluster_firewall_ipset_view(&before.name)
            .await?;
        let mut set_params: Vec<(String, String)> = vec![("name".to_string(), after.name.clone())];
        push_optional(&mut set_params, "comment", &after.comment);
        client
            .create_cluster_firewall_ipset_view(&borrow(&set_params))
            .await?;
        for c in &after.cidrs {
            let p = fw_cidr_params(c);
            client
                .add_cluster_firewall_ipset_cidr_view(&after.name, &borrow(&p))
                .await?;
        }
        return Ok(());
    }

    // Comment unchanged: incremental CIDR delta keyed on the cidr string.
    let before_by: HashMap<&str, &FirewallIpsetCidrDecl> =
        before.cidrs.iter().map(|c| (c.cidr.as_str(), c)).collect();
    let after_by: HashMap<&str, &FirewallIpsetCidrDecl> =
        after.cidrs.iter().map(|c| (c.cidr.as_str(), c)).collect();

    // Remove entries that vanished or whose attributes changed.
    for bc in &before.cidrs {
        match after_by.get(bc.cidr.as_str()) {
            Some(ac) if *ac == bc => {}
            _ => {
                client
                    .remove_cluster_firewall_ipset_cidr_view(&before.name, &bc.cidr)
                    .await?;
            }
        }
    }
    // Add entries that are new or whose attributes changed (re-added).
    for ac in &after.cidrs {
        match before_by.get(ac.cidr.as_str()) {
            Some(bc) if *bc == ac => {}
            _ => {
                let p = fw_cidr_params(ac);
                client
                    .add_cluster_firewall_ipset_cidr_view(&after.name, &borrow(&p))
                    .await?;
            }
        }
    }
    Ok(())
}

async fn apply_fw_group_create<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let decl: FirewallGroupDecl = decode(change.after.as_ref(), "firewall group")?;
    let mut params: Vec<(String, String)> = vec![("group".to_string(), decl.group.clone())];
    push_optional(&mut params, "comment", &decl.comment);
    client
        .create_cluster_firewall_group_view(&borrow(&params))
        .await
}

async fn apply_fw_group_delete<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let decl: FirewallGroupDecl = decode(change.before.as_ref(), "firewall group")?;
    client.delete_cluster_firewall_group_view(&decl.group).await
}

// ── Notification matchers ────────────────────────────────────

/// Build the `POST`/`PUT /cluster/notifications/matchers` param set.
/// The three list fields go as repeated form keys (PVE's array
/// convention). `invert-match` + `disable` are always sent (0/1) so an
/// update that flips them off actually takes effect. `include_name` is
/// true for create (name is a body param) and false for update (name is
/// the URL segment).
fn notif_matcher_params(
    decl: &NotificationMatcherDecl,
    include_name: bool,
) -> Vec<(String, String)> {
    let mut params: Vec<(String, String)> = Vec::new();
    if include_name {
        params.push(("name".to_string(), decl.name.clone()));
    }
    push_optional(&mut params, "comment", &decl.comment);
    for t in &decl.target {
        params.push(("target".to_string(), t.clone()));
    }
    for m in &decl.match_field {
        params.push(("match-field".to_string(), m.clone()));
    }
    for s in &decl.match_severity {
        params.push(("match-severity".to_string(), s.clone()));
    }
    push_optional(&mut params, "mode", &decl.mode);
    params.push((
        "invert-match".to_string(),
        if decl.invert_match { "1" } else { "0" }.to_string(),
    ));
    params.push((
        "disable".to_string(),
        if decl.disable { "1" } else { "0" }.to_string(),
    ));
    params
}

async fn apply_notif_matcher_create<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let decl: NotificationMatcherDecl = decode(change.after.as_ref(), "notification matcher")?;
    let params = notif_matcher_params(&decl, true);
    client
        .create_notification_matcher_view(&borrow(&params))
        .await
}

async fn apply_notif_matcher_update<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let after: NotificationMatcherDecl = decode(change.after.as_ref(), "notification matcher")?;
    let mut params = notif_matcher_params(&after, false);
    // PVE keeps an optional field's old value unless explicitly told to
    // unset it. So any field the declared state leaves empty is sent in
    // `delete` — otherwise "clear all match-fields" would never converge
    // (the diff would show a perpetual Update). The matchers endpoint
    // wants `delete` as REPEATED keys (`delete=a&delete=b`), not a CSV —
    // a CSV is rejected as one malformed config-id (verified live).
    let mut del: Vec<&str> = Vec::new();
    if after.comment.is_empty() {
        del.push("comment");
    }
    if after.target.is_empty() {
        del.push("target");
    }
    if after.match_field.is_empty() {
        del.push("match-field");
    }
    if after.match_severity.is_empty() {
        del.push("match-severity");
    }
    if after.mode.is_empty() {
        del.push("mode");
    }
    for key in del {
        params.push(("delete".to_string(), key.to_string()));
    }
    client
        .update_notification_matcher_view(&after.name, &borrow(&params))
        .await
}

async fn apply_notif_matcher_delete<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let decl: NotificationMatcherDecl = decode(change.before.as_ref(), "notification matcher")?;
    client.delete_notification_matcher_view(&decl.name).await
}

/// Build the form-encoded params for `POST /cluster/ha/rules` and
/// `PUT /cluster/ha/rules/{rule}`. The wire shape is flat: `type` (PVE
/// requires this on BOTH create AND update — see below), `rule` (POST
/// only; PUT identifies via the URL), `resources` as a CSV, `nodes`
/// already-encoded with priority suffixes, `affinity` for
/// resource-affinity, plus the common `comment`/`disable`/`strict`.
///
/// PVE's params parser accepts `0`/`1` for booleans uniformly across
/// the API; we serialize that way (matches the notification matcher
/// pattern and avoids `true`/`false` edge cases on older PVE versions).
///
/// ## `type` on PUT — live-caught gotcha (v0.7.0 → v0.7.1)
///
/// Reading pve-ha-manager.git's `Rules.pm` made it look like `type` was
/// "immutable on PUT" (the API rejects type *changes*) — so v0.7.0's
/// original impl omitted `type` from PUT params. Live-tested against
/// PVE 9.1.1: that's wrong. PVE *requires* the `type` field on PUT and
/// 400s with `{"errors":{"type":"property is missing and it is not
/// optional"}}` if it's absent. "Immutable" means *you must send it
/// AND it must equal the existing value* — not "omit it". So we send
/// it on both verbs; the diff/apply layer (`apply_ha_rule_update`)
/// guards against actual type *changes* with a clear pre-call bail.
fn ha_rule_params(decl: &HaRuleDecl, include_rule_id: bool) -> Vec<(String, String)> {
    let mut params: Vec<(String, String)> = Vec::new();
    // `type` always emitted — PVE requires it on both POST and PUT.
    params.push(("type".to_string(), decl.rule_type.clone()));
    if include_rule_id {
        // `rule` is the URL last-segment on PUT; only sent in the body
        // on POST where there's no URL to read it from.
        params.push(("rule".to_string(), decl.rule.clone()));
    }
    // resources: rejoin the sorted Vec<String> into the wire CSV.
    if !decl.resources.is_empty() {
        params.push(("resources".to_string(), decl.resources.join(",")));
    }
    push_optional(&mut params, "comment", &decl.comment);
    params.push((
        "disable".to_string(),
        if decl.disable { "1" } else { "0" }.to_string(),
    ));
    // node-affinity-only fields. Sending these for a resource-affinity
    // rule is harmless — PVE's plugin layer drops fields not in the
    // active plugin's schema with a 400 only when an unknown KEY is
    // sent; `nodes`/`strict`/`affinity` are all *known* across both
    // plugins (just dropped by the irrelevant one). Test this with a
    // live cluster before relying on it; safer to filter by `rule_type`.
    if decl.rule_type == "node-affinity" {
        push_optional(&mut params, "nodes", &decl.nodes);
        params.push((
            "strict".to_string(),
            if decl.strict { "1" } else { "0" }.to_string(),
        ));
    }
    // resource-affinity-only field.
    if decl.rule_type == "resource-affinity" {
        push_optional(&mut params, "affinity", &decl.affinity);
    }
    params
}

async fn apply_ha_rule_create<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let decl: HaRuleDecl = decode(change.after.as_ref(), "HA rule")?;
    if decl.rule_type.is_empty() {
        anyhow::bail!(
            "HA rule '{}' missing `type` — must be 'node-affinity' or 'resource-affinity'",
            decl.rule
        );
    }
    let params = ha_rule_params(&decl, true);
    client.create_ha_rule_view(&borrow(&params)).await
}

async fn apply_ha_rule_update<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let after: HaRuleDecl = decode(change.after.as_ref(), "HA rule")?;
    // PUT cannot change `type` — PVE rejects with `type is immutable`.
    // Detect a type change against `before` and surface an actionable
    // error rather than letting PVE produce the cryptic one.
    if let Some(before_val) = change.before.as_ref() {
        let before: HaRuleDecl = decode(Some(before_val), "HA rule (before)")?;
        if !before.rule_type.is_empty()
            && !after.rule_type.is_empty()
            && before.rule_type != after.rule_type
        {
            anyhow::bail!(
                "HA rule '{}' type change ({} -> {}) is not supported by PVE — \
                 delete + re-create the rule with the new type",
                after.rule,
                before.rule_type,
                after.rule_type
            );
        }
    }
    let mut params = ha_rule_params(&after, false);
    // PVE keeps unspecified fields at their old values (same trap the
    // notification matcher hit). Send `delete=<key>` for fields that are
    // now empty so the cluster converges. Per the matcher live-caught
    // lesson, `delete` must be REPEATED keys (one per cleared field),
    // never a CSV.
    let mut del: Vec<&str> = Vec::new();
    if after.comment.is_empty() {
        del.push("comment");
    }
    if after.resources.is_empty() {
        del.push("resources");
    }
    if after.rule_type == "node-affinity" && after.nodes.is_empty() {
        del.push("nodes");
    }
    if after.rule_type == "resource-affinity" && after.affinity.is_empty() {
        del.push("affinity");
    }
    for key in del {
        params.push(("delete".to_string(), key.to_string()));
    }
    client
        .update_ha_rule_view(&after.rule, &borrow(&params))
        .await
}

async fn apply_ha_rule_delete<C: StateWriteView + ?Sized>(
    client: &C,
    change: &Change,
) -> Result<()> {
    let decl: HaRuleDecl = decode(change.before.as_ref(), "HA rule")?;
    client.delete_ha_rule_view(&decl.rule).await
}

fn push_optional(params: &mut Vec<(String, String)>, key: &str, value: &str) {
    if !value.is_empty() {
        params.push((key.to_string(), value.to_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::diff::ChangeKind;

    #[test]
    fn split_pool_members_partitions_qemu_lxc_storage() {
        let m = vec![
            "qemu/100".to_string(),
            "lxc/200".to_string(),
            "storage/local".to_string(),
            "qemu/101".to_string(),
        ];
        let (vms, storage) = split_pool_members(&m);
        assert_eq!(vms, "100,200,101");
        assert_eq!(storage, "local");
    }

    #[test]
    fn split_pool_members_drops_unknown_prefixes() {
        // SDN / future kinds — defensive: we don't crash.
        let m = vec!["qemu/100".to_string(), "sdn/dev-net".to_string()];
        let (vms, storage) = split_pool_members(&m);
        assert_eq!(vms, "100");
        assert!(storage.is_empty());
    }

    #[test]
    fn members_diff_set_semantics() {
        let a = vec!["qemu/100".to_string(), "qemu/101".to_string()];
        let b = vec!["qemu/100".to_string()];
        assert_eq!(members_diff(&a, &b), vec!["qemu/101".to_string()]);
        assert!(members_diff(&b, &a).is_empty());
    }

    /// In-process implementation of `StateWriteView` that records
    /// every method call. Used by the dispatch tests below to verify
    /// `apply` translates `Change` → API calls correctly.
    #[derive(Default)]
    struct RecordingClient {
        log: tokio::sync::Mutex<Vec<String>>,
        fail_on: Option<String>,
    }

    impl RecordingClient {
        async fn record(&self, entry: String) -> Result<()> {
            if let Some(fail) = &self.fail_on {
                if entry.contains(fail) {
                    return Err(anyhow::anyhow!("synthetic failure on {entry}"));
                }
            }
            self.log.lock().await.push(entry);
            Ok(())
        }
        async fn lines(&self) -> Vec<String> {
            self.log.lock().await.clone()
        }
    }

    #[async_trait]
    impl StateWriteView for RecordingClient {
        async fn list_pools_view(&self) -> Result<Vec<Pool>> {
            Ok(vec![])
        }
        async fn get_pool_view(&self, _: &str) -> Result<PoolDetails> {
            Ok(PoolDetails::default())
        }
        async fn create_pool_view(&self, params: &[(&str, &str)]) -> Result<()> {
            self.record(format!("create_pool {params:?}")).await
        }
        async fn update_pool_view(&self, poolid: &str, params: &[(&str, &str)]) -> Result<()> {
            self.record(format!("update_pool({poolid}) {params:?}"))
                .await
        }
        async fn delete_pool_view(&self, poolid: &str) -> Result<()> {
            self.record(format!("delete_pool({poolid})")).await
        }
        async fn modify_acl_view(
            &self,
            path: &str,
            roles: &str,
            users: Option<&str>,
            groups: Option<&str>,
            tokens: Option<&str>,
            propagate: bool,
            delete: bool,
        ) -> Result<()> {
            self.record(format!(
                "modify_acl path={path} roles={roles} users={users:?} groups={groups:?} tokens={tokens:?} propagate={propagate} delete={delete}"
            ))
            .await
        }
        async fn create_cluster_storage_view(&self, params: &[(&str, &str)]) -> Result<()> {
            self.record(format!("create_storage {params:?}")).await
        }
        async fn update_cluster_storage_view(
            &self,
            storage: &str,
            params: &[(&str, &str)],
        ) -> Result<()> {
            self.record(format!("update_storage({storage}) {params:?}"))
                .await
        }
        async fn delete_cluster_storage_view(&self, storage: &str) -> Result<()> {
            self.record(format!("delete_storage({storage})")).await
        }
        async fn create_backup_job_view(&self, params: &[(&str, &str)]) -> Result<()> {
            self.record(format!("create_backup_job {params:?}")).await
        }
        async fn update_backup_job_view(&self, id: &str, params: &[(&str, &str)]) -> Result<()> {
            self.record(format!("update_backup_job({id}) {params:?}"))
                .await
        }
        async fn delete_backup_job_view(&self, id: &str) -> Result<()> {
            self.record(format!("delete_backup_job({id})")).await
        }
        async fn update_cluster_firewall_options_view(
            &self,
            params: &[(&str, &str)],
        ) -> Result<()> {
            self.record(format!("update_fw_options {params:?}")).await
        }
        async fn create_cluster_firewall_alias_view(&self, params: &[(&str, &str)]) -> Result<()> {
            self.record(format!("create_fw_alias {params:?}")).await
        }
        async fn update_cluster_firewall_alias_view(
            &self,
            name: &str,
            params: &[(&str, &str)],
        ) -> Result<()> {
            self.record(format!("update_fw_alias({name}) {params:?}"))
                .await
        }
        async fn delete_cluster_firewall_alias_view(&self, name: &str) -> Result<()> {
            self.record(format!("delete_fw_alias({name})")).await
        }
        async fn create_cluster_firewall_ipset_view(&self, params: &[(&str, &str)]) -> Result<()> {
            self.record(format!("create_fw_ipset {params:?}")).await
        }
        async fn delete_cluster_firewall_ipset_view(&self, name: &str) -> Result<()> {
            self.record(format!("delete_fw_ipset({name})")).await
        }
        async fn add_cluster_firewall_ipset_cidr_view(
            &self,
            name: &str,
            params: &[(&str, &str)],
        ) -> Result<()> {
            self.record(format!("add_fw_cidr({name}) {params:?}")).await
        }
        async fn remove_cluster_firewall_ipset_cidr_view(
            &self,
            name: &str,
            cidr: &str,
        ) -> Result<()> {
            self.record(format!("remove_fw_cidr({name}, {cidr})")).await
        }
        async fn create_cluster_firewall_group_view(&self, params: &[(&str, &str)]) -> Result<()> {
            self.record(format!("create_fw_group {params:?}")).await
        }
        async fn delete_cluster_firewall_group_view(&self, group: &str) -> Result<()> {
            self.record(format!("delete_fw_group({group})")).await
        }
        async fn create_notification_matcher_view(&self, params: &[(&str, &str)]) -> Result<()> {
            self.record(format!("create_matcher {params:?}")).await
        }
        async fn update_notification_matcher_view(
            &self,
            name: &str,
            params: &[(&str, &str)],
        ) -> Result<()> {
            self.record(format!("update_matcher({name}) {params:?}"))
                .await
        }
        async fn delete_notification_matcher_view(&self, name: &str) -> Result<()> {
            self.record(format!("delete_matcher({name})")).await
        }
        async fn create_ha_rule_view(&self, params: &[(&str, &str)]) -> Result<()> {
            self.record(format!("create_ha_rule {params:?}")).await
        }
        async fn update_ha_rule_view(&self, rule: &str, params: &[(&str, &str)]) -> Result<()> {
            self.record(format!("update_ha_rule({rule}) {params:?}"))
                .await
        }
        async fn delete_ha_rule_view(&self, rule: &str) -> Result<()> {
            self.record(format!("delete_ha_rule({rule})")).await
        }
    }

    fn pool_create_change(poolid: &str, members: Vec<&str>) -> Change {
        let decl = PoolDecl {
            poolid: poolid.into(),
            comment: "test pool".into(),
            members: members.into_iter().map(String::from).collect(),
        };
        Change {
            kind: ChangeKind::Create,
            resource: "pool",
            identity: poolid.into(),
            before: None,
            after: serde_json::to_value(&decl).ok(),
        }
    }

    fn pool_delete_change(poolid: &str) -> Change {
        let decl = PoolDecl {
            poolid: poolid.into(),
            comment: String::new(),
            members: vec![],
        };
        Change {
            kind: ChangeKind::Delete,
            resource: "pool",
            identity: poolid.into(),
            before: serde_json::to_value(&decl).ok(),
            after: None,
        }
    }

    #[tokio::test]
    async fn dry_run_skips_every_change() {
        let c = RecordingClient::default();
        let changes = vec![pool_create_change("p1", vec![])];
        let out = apply(
            &c,
            changes,
            ApplyOptions {
                dry_run: true,
                ..ApplyOptions::default()
            },
        )
        .await;
        assert_eq!(out.len(), 1);
        assert!(matches!(
            out[0].result,
            ApplyResult::Skipped {
                reason: SkipReason::DryRun
            }
        ));
        assert!(c.lines().await.is_empty(), "no PVE calls under dry-run");
    }

    #[tokio::test]
    async fn delete_skipped_without_prune() {
        let c = RecordingClient::default();
        let changes = vec![pool_delete_change("p1")];
        let out = apply(&c, changes, ApplyOptions::default()).await;
        assert_eq!(out.len(), 1);
        assert!(matches!(
            out[0].result,
            ApplyResult::Skipped {
                reason: SkipReason::PrunePolicy
            }
        ));
        assert!(c.lines().await.is_empty());
    }

    #[tokio::test]
    async fn delete_executed_with_prune() {
        let c = RecordingClient::default();
        let changes = vec![pool_delete_change("p1")];
        let out = apply(
            &c,
            changes,
            ApplyOptions {
                prune: true,
                ..ApplyOptions::default()
            },
        )
        .await;
        assert!(matches!(out[0].result, ApplyResult::Applied));
        let lines = c.lines().await;
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("delete_pool(p1)"));
    }

    #[tokio::test]
    async fn pool_create_with_members_fires_create_then_update() {
        let c = RecordingClient::default();
        let changes = vec![pool_create_change("p1", vec!["qemu/100", "storage/local"])];
        let out = apply(&c, changes, ApplyOptions::default()).await;
        assert!(matches!(out[0].result, ApplyResult::Applied));
        let lines = c.lines().await;
        assert_eq!(lines.len(), 2, "expected create + member-add");
        assert!(lines[0].starts_with("create_pool"));
        assert!(lines[1].contains("update_pool(p1)"));
        assert!(lines[1].contains("vms"));
        assert!(lines[1].contains("storage"));
    }

    #[tokio::test]
    async fn fail_fast_aborts_remaining_changes() {
        let c = RecordingClient {
            fail_on: Some("create_pool".into()),
            ..Default::default()
        };
        let changes = vec![
            pool_create_change("p1", vec![]),
            pool_create_change("p2", vec![]),
            pool_create_change("p3", vec![]),
        ];
        let out = apply(&c, changes, ApplyOptions::default()).await;
        assert_eq!(out.len(), 3);
        assert!(matches!(out[0].result, ApplyResult::Failed { .. }));
        assert!(matches!(
            out[1].result,
            ApplyResult::Skipped {
                reason: SkipReason::AbortedByPrior
            }
        ));
        assert!(matches!(
            out[2].result,
            ApplyResult::Skipped {
                reason: SkipReason::AbortedByPrior
            }
        ));
    }

    #[tokio::test]
    async fn continue_on_error_processes_every_change() {
        let c = RecordingClient {
            fail_on: Some("\"poolid\", \"p2\"".into()),
            ..Default::default()
        };
        let changes = vec![
            pool_create_change("p1", vec![]),
            pool_create_change("p2", vec![]),
            pool_create_change("p3", vec![]),
        ];
        let out = apply(
            &c,
            changes,
            ApplyOptions {
                continue_on_error: true,
                ..ApplyOptions::default()
            },
        )
        .await;
        assert!(matches!(out[0].result, ApplyResult::Applied));
        assert!(matches!(out[1].result, ApplyResult::Failed { .. }));
        assert!(matches!(out[2].result, ApplyResult::Applied));
    }

    fn backup_job_change(kind: ChangeKind, decl: &BackupJobDecl) -> Change {
        let v = serde_json::to_value(decl).ok();
        Change {
            kind,
            resource: "backup_job",
            identity: decl.id.clone(),
            before: if kind == ChangeKind::Delete {
                v.clone()
            } else {
                None
            },
            after: if kind == ChangeKind::Delete { None } else { v },
        }
    }

    #[test]
    fn backup_job_params_create_includes_id_update_omits_it() {
        let decl = BackupJobDecl {
            id: "nightly".into(),
            schedule: "*-*-* 02:00".into(),
            storage: "pbs".into(),
            ..BackupJobDecl::default()
        };
        let create = backup_job_params(&decl, true);
        assert!(create.iter().any(|(k, v)| k == "id" && v == "nightly"));
        let update = backup_job_params(&decl, false);
        assert!(
            !update.iter().any(|(k, _)| k == "id"),
            "id is the URL segment on update, never a body param"
        );
    }

    #[test]
    fn backup_job_params_always_sends_enabled_and_hyphenates_keys() {
        // `enabled` must always be present (0/1) so an Update that
        // disables a job actually takes effect. notes-template /
        // prune-backups must be hyphenated to match PVE's param names.
        let decl = BackupJobDecl {
            id: "j".into(),
            schedule: "daily".into(),
            storage: "local".into(),
            enabled: false,
            notes_template: "{{guestname}}".into(),
            prune_backups: "keep-last=3".into(),
            ..BackupJobDecl::default()
        };
        let p = backup_job_params(&decl, true);
        assert!(p.iter().any(|(k, v)| k == "enabled" && v == "0"));
        assert!(p
            .iter()
            .any(|(k, v)| k == "notes-template" && v == "{{guestname}}"));
        assert!(p
            .iter()
            .any(|(k, v)| k == "prune-backups" && v == "keep-last=3"));
        assert!(!p.iter().any(|(k, _)| k == "notes_template"));
    }

    #[test]
    fn backup_job_params_all_and_vmid_are_mutually_exclusive() {
        // `all = true` sends `all=1` and suppresses any vmid CSV.
        let all = BackupJobDecl {
            id: "j".into(),
            all: true,
            vmid: "100,200".into(),
            ..BackupJobDecl::default()
        };
        let p = backup_job_params(&all, true);
        assert!(p.iter().any(|(k, v)| k == "all" && v == "1"));
        assert!(
            !p.iter().any(|(k, _)| k == "vmid"),
            "vmid must be suppressed when all=true"
        );

        // all = false sends the explicit vmid list, no `all` key.
        let list = BackupJobDecl {
            id: "j".into(),
            all: false,
            vmid: "100,200".into(),
            ..BackupJobDecl::default()
        };
        let p2 = backup_job_params(&list, true);
        assert!(p2.iter().any(|(k, v)| k == "vmid" && v == "100,200"));
        assert!(!p2.iter().any(|(k, _)| k == "all"));
    }

    #[tokio::test]
    async fn backup_job_create_dispatches_to_create_view() {
        let c = RecordingClient::default();
        let decl = BackupJobDecl {
            id: "nightly".into(),
            schedule: "*-*-* 02:00".into(),
            storage: "pbs".into(),
            all: true,
            ..BackupJobDecl::default()
        };
        let out = apply(
            &c,
            vec![backup_job_change(ChangeKind::Create, &decl)],
            ApplyOptions::default(),
        )
        .await;
        assert!(matches!(out[0].result, ApplyResult::Applied));
        let lines = c.lines().await;
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with("create_backup_job"));
        assert!(lines[0].contains("\"id\", \"nightly\""));
    }

    #[tokio::test]
    async fn backup_job_delete_dispatches_only_with_prune() {
        let decl = BackupJobDecl {
            id: "old".into(),
            ..BackupJobDecl::default()
        };
        // Without prune: skipped.
        let c = RecordingClient::default();
        let out = apply(
            &c,
            vec![backup_job_change(ChangeKind::Delete, &decl)],
            ApplyOptions::default(),
        )
        .await;
        assert!(matches!(
            out[0].result,
            ApplyResult::Skipped {
                reason: SkipReason::PrunePolicy
            }
        ));
        assert!(c.lines().await.is_empty());

        // With prune: fires delete_backup_job(old).
        let c2 = RecordingClient::default();
        let out2 = apply(
            &c2,
            vec![backup_job_change(ChangeKind::Delete, &decl)],
            ApplyOptions {
                prune: true,
                ..ApplyOptions::default()
            },
        )
        .await;
        assert!(matches!(out2[0].result, ApplyResult::Applied));
        assert_eq!(c2.lines().await, vec!["delete_backup_job(old)".to_string()]);
    }

    // ── Cluster firewall ─────────────────────────────────

    fn fw_change(
        kind: ChangeKind,
        resource: &'static str,
        identity: &str,
        before: Option<serde_json::Value>,
        after: Option<serde_json::Value>,
    ) -> Change {
        Change {
            kind,
            resource,
            identity: identity.to_string(),
            before,
            after,
        }
    }

    #[tokio::test]
    async fn fw_options_update_always_sends_enable_and_ebtables() {
        let after = FirewallOptionsDecl {
            enable: true,
            policy_in: "DROP".into(),
            ebtables: false,
            ..FirewallOptionsDecl::default()
        };
        let c = RecordingClient::default();
        let change = fw_change(
            ChangeKind::Update,
            "firewall_options",
            "cluster",
            Some(serde_json::json!({"enable": false})),
            Some(serde_json::to_value(&after).unwrap()),
        );
        let out = apply(&c, vec![change], ApplyOptions::default()).await;
        assert!(matches!(out[0].result, ApplyResult::Applied));
        let line = &c.lines().await[0];
        assert!(line.starts_with("update_fw_options"));
        assert!(line.contains("\"enable\", \"1\""));
        assert!(line.contains("\"ebtables\", \"0\""), "ebtables always sent");
        assert!(line.contains("\"policy_in\", \"DROP\""));
    }

    #[tokio::test]
    async fn fw_alias_create_and_delete_dispatch() {
        let decl = FirewallAliasDecl {
            name: "web".into(),
            cidr: "10.0.0.0/8".into(),
            comment: "web tier".into(),
        };
        let c = RecordingClient::default();
        let create = fw_change(
            ChangeKind::Create,
            "firewall_alias",
            "web",
            None,
            Some(serde_json::to_value(&decl).unwrap()),
        );
        let out = apply(&c, vec![create], ApplyOptions::default()).await;
        assert!(matches!(out[0].result, ApplyResult::Applied));
        let line = &c.lines().await[0];
        assert!(line.starts_with("create_fw_alias"));
        assert!(line.contains("\"name\", \"web\"") && line.contains("\"cidr\", \"10.0.0.0/8\""));

        // delete requires prune
        let c2 = RecordingClient::default();
        let delete = fw_change(
            ChangeKind::Delete,
            "firewall_alias",
            "web",
            Some(serde_json::to_value(&decl).unwrap()),
            None,
        );
        let out2 = apply(
            &c2,
            vec![delete],
            ApplyOptions {
                prune: true,
                ..ApplyOptions::default()
            },
        )
        .await;
        assert!(matches!(out2[0].result, ApplyResult::Applied));
        assert_eq!(c2.lines().await, vec!["delete_fw_alias(web)".to_string()]);
    }

    #[tokio::test]
    async fn fw_ipset_create_fires_create_then_add_per_cidr() {
        let decl = FirewallIpsetDecl {
            name: "blocklist".into(),
            comment: "bad".into(),
            cidrs: vec![
                FirewallIpsetCidrDecl {
                    cidr: "1.2.3.0/24".into(),
                    ..Default::default()
                },
                FirewallIpsetCidrDecl {
                    cidr: "5.6.7.8".into(),
                    nomatch: true,
                    ..Default::default()
                },
            ],
        };
        let c = RecordingClient::default();
        let change = fw_change(
            ChangeKind::Create,
            "firewall_ipset",
            "blocklist",
            None,
            Some(serde_json::to_value(&decl).unwrap()),
        );
        let out = apply(&c, vec![change], ApplyOptions::default()).await;
        assert!(matches!(out[0].result, ApplyResult::Applied));
        let lines = c.lines().await;
        assert_eq!(lines.len(), 3, "create + 2 add_cidr");
        assert!(lines[0].starts_with("create_fw_ipset"));
        assert!(lines[1].starts_with("add_fw_cidr(blocklist)") && lines[1].contains("1.2.3.0/24"));
        assert!(lines[2].contains("5.6.7.8") && lines[2].contains("\"nomatch\", \"1\""));
    }

    #[tokio::test]
    async fn fw_ipset_delete_removes_cidrs_then_deletes() {
        let decl = FirewallIpsetDecl {
            name: "blocklist".into(),
            comment: String::new(),
            cidrs: vec![FirewallIpsetCidrDecl {
                cidr: "1.2.3.0/24".into(),
                ..Default::default()
            }],
        };
        let c = RecordingClient::default();
        let change = fw_change(
            ChangeKind::Delete,
            "firewall_ipset",
            "blocklist",
            Some(serde_json::to_value(&decl).unwrap()),
            None,
        );
        let out = apply(
            &c,
            vec![change],
            ApplyOptions {
                prune: true,
                ..ApplyOptions::default()
            },
        )
        .await;
        assert!(matches!(out[0].result, ApplyResult::Applied));
        assert_eq!(
            c.lines().await,
            vec![
                "remove_fw_cidr(blocklist, 1.2.3.0/24)".to_string(),
                "delete_fw_ipset(blocklist)".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn fw_ipset_update_comment_change_recreates_with_cidrs() {
        // A comment change has no PVE update endpoint → delete (members
        // first) + recreate + re-add all declared CIDRs.
        let cidr = FirewallIpsetCidrDecl {
            cidr: "1.2.3.0/24".into(),
            ..Default::default()
        };
        let before = FirewallIpsetDecl {
            name: "s".into(),
            comment: "old".into(),
            cidrs: vec![cidr.clone()],
        };
        let after = FirewallIpsetDecl {
            name: "s".into(),
            comment: "new".into(),
            cidrs: vec![cidr],
        };
        let c = RecordingClient::default();
        let change = fw_change(
            ChangeKind::Update,
            "firewall_ipset",
            "s",
            Some(serde_json::to_value(&before).unwrap()),
            Some(serde_json::to_value(&after).unwrap()),
        );
        let out = apply(&c, vec![change], ApplyOptions::default()).await;
        assert!(matches!(out[0].result, ApplyResult::Applied));
        let lines = c.lines().await;
        assert_eq!(
            lines,
            vec![
                "remove_fw_cidr(s, 1.2.3.0/24)".to_string(),
                "delete_fw_ipset(s)".to_string(),
                "create_fw_ipset [(\"name\", \"s\"), (\"comment\", \"new\")]".to_string(),
                "add_fw_cidr(s) [(\"cidr\", \"1.2.3.0/24\")]".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn fw_ipset_update_cidr_delta_is_minimal() {
        // Comment unchanged → only the CIDR delta is applied: add the
        // new one, remove the gone one, leave the unchanged one alone.
        let mk = |c: &str| FirewallIpsetCidrDecl {
            cidr: c.into(),
            ..Default::default()
        };
        let before = FirewallIpsetDecl {
            name: "s".into(),
            comment: "same".into(),
            cidrs: vec![mk("1.1.1.0/24"), mk("2.2.2.0/24")],
        };
        let after = FirewallIpsetDecl {
            name: "s".into(),
            comment: "same".into(),
            cidrs: vec![mk("1.1.1.0/24"), mk("3.3.3.0/24")],
        };
        let c = RecordingClient::default();
        let change = fw_change(
            ChangeKind::Update,
            "firewall_ipset",
            "s",
            Some(serde_json::to_value(&before).unwrap()),
            Some(serde_json::to_value(&after).unwrap()),
        );
        let out = apply(&c, vec![change], ApplyOptions::default()).await;
        assert!(matches!(out[0].result, ApplyResult::Applied));
        let lines = c.lines().await;
        // No delete_fw_ipset / create_fw_ipset — set stays put.
        assert!(!lines.iter().any(|l| l.contains("delete_fw_ipset")));
        assert!(lines.iter().any(|l| l == "remove_fw_cidr(s, 2.2.2.0/24)"));
        assert!(lines
            .iter()
            .any(|l| l.starts_with("add_fw_cidr(s)") && l.contains("3.3.3.0/24")));
        // 1.1.1.0/24 was unchanged → neither added nor removed.
        assert!(!lines.iter().any(|l| l.contains("1.1.1.0/24")));
    }

    #[tokio::test]
    async fn fw_group_create_and_delete_dispatch() {
        let decl = FirewallGroupDecl {
            group: "web-tier".into(),
            comment: "frontend".into(),
        };
        let c = RecordingClient::default();
        let create = fw_change(
            ChangeKind::Create,
            "firewall_group",
            "web-tier",
            None,
            Some(serde_json::to_value(&decl).unwrap()),
        );
        let out = apply(&c, vec![create], ApplyOptions::default()).await;
        assert!(matches!(out[0].result, ApplyResult::Applied));
        assert!(c.lines().await[0].starts_with("create_fw_group"));

        let c2 = RecordingClient::default();
        let delete = fw_change(
            ChangeKind::Delete,
            "firewall_group",
            "web-tier",
            Some(serde_json::to_value(&decl).unwrap()),
            None,
        );
        let out2 = apply(
            &c2,
            vec![delete],
            ApplyOptions {
                prune: true,
                ..ApplyOptions::default()
            },
        )
        .await;
        assert!(matches!(out2[0].result, ApplyResult::Applied));
        assert_eq!(
            c2.lines().await,
            vec!["delete_fw_group(web-tier)".to_string()]
        );
    }

    // ── Notification matchers ─────────────────────────────

    #[test]
    fn matcher_params_arrays_repeat_and_bools_always_sent() {
        let decl = NotificationMatcherDecl {
            name: "oncall".into(),
            target: vec!["gotify".into(), "email".into()],
            match_field: vec!["exact:type=vzdump".into()],
            match_severity: vec!["error".into(), "warning".into()],
            mode: "any".into(),
            invert_match: true,
            disable: false,
            ..NotificationMatcherDecl::default()
        };
        let p = notif_matcher_params(&decl, true);
        // name only on create
        assert!(p.iter().any(|(k, v)| k == "name" && v == "oncall"));
        // arrays as repeated keys
        assert_eq!(p.iter().filter(|(k, _)| k == "target").count(), 2);
        assert_eq!(p.iter().filter(|(k, _)| k == "match-severity").count(), 2);
        assert!(p
            .iter()
            .any(|(k, v)| k == "match-field" && v == "exact:type=vzdump"));
        assert!(p.iter().any(|(k, v)| k == "mode" && v == "any"));
        // bools always present
        assert!(p.iter().any(|(k, v)| k == "invert-match" && v == "1"));
        assert!(p.iter().any(|(k, v)| k == "disable" && v == "0"));
        // update omits name
        assert!(!notif_matcher_params(&decl, false)
            .iter()
            .any(|(k, _)| k == "name"));
    }

    #[tokio::test]
    async fn matcher_update_sends_delete_for_emptied_fields() {
        // A matcher stripped down to just a target must `delete` the
        // fields it no longer sets, or PVE keeps the stale values.
        let after = NotificationMatcherDecl {
            name: "m".into(),
            target: vec!["gotify".into()],
            // comment, match_field, match_severity, mode all empty
            ..NotificationMatcherDecl::default()
        };
        let c = RecordingClient::default();
        let change = Change {
            kind: ChangeKind::Update,
            resource: "notification_matcher",
            identity: "m".into(),
            before: Some(serde_json::json!({"name": "m", "match_severity": ["error"]})),
            after: Some(serde_json::to_value(&after).unwrap()),
        };
        let out = apply(&c, vec![change], ApplyOptions::default()).await;
        assert!(matches!(out[0].result, ApplyResult::Applied));
        let line = &c.lines().await[0];
        assert!(line.starts_with("update_matcher(m)"));
        assert!(line.contains("\"delete\""), "delete CSV present: {line}");
        assert!(
            line.contains("comment")
                && line.contains("match-field")
                && line.contains("match-severity")
                && line.contains("mode")
        );
    }

    #[tokio::test]
    async fn matcher_create_and_delete_dispatch() {
        let decl = NotificationMatcherDecl {
            name: "oncall".into(),
            target: vec!["gotify".into()],
            ..NotificationMatcherDecl::default()
        };
        let c = RecordingClient::default();
        let create = Change {
            kind: ChangeKind::Create,
            resource: "notification_matcher",
            identity: "oncall".into(),
            before: None,
            after: Some(serde_json::to_value(&decl).unwrap()),
        };
        let out = apply(&c, vec![create], ApplyOptions::default()).await;
        assert!(matches!(out[0].result, ApplyResult::Applied));
        assert!(c.lines().await[0].starts_with("create_matcher"));

        let c2 = RecordingClient::default();
        let delete = Change {
            kind: ChangeKind::Delete,
            resource: "notification_matcher",
            identity: "oncall".into(),
            before: Some(serde_json::to_value(&decl).unwrap()),
            after: None,
        };
        let out2 = apply(
            &c2,
            vec![delete],
            ApplyOptions {
                prune: true,
                ..ApplyOptions::default()
            },
        )
        .await;
        assert!(matches!(out2[0].result, ApplyResult::Applied));
        assert_eq!(c2.lines().await, vec!["delete_matcher(oncall)".to_string()]);
    }

    // ── HA rules (epic #74) ───────────────────────────────────────

    #[tokio::test]
    async fn ha_rule_create_node_affinity_dispatches_with_type_and_strict() {
        let decl = HaRuleDecl {
            rule: "pin-db".into(),
            rule_type: "node-affinity".into(),
            resources: vec!["vm:100".into(), "vm:101".into()],
            nodes: "pve1:5,pve2".into(),
            strict: true,
            ..HaRuleDecl::default()
        };
        let c = RecordingClient::default();
        let create = Change {
            kind: ChangeKind::Create,
            resource: "ha_rule",
            identity: "pin-db".into(),
            before: None,
            after: Some(serde_json::to_value(&decl).unwrap()),
        };
        let out = apply(&c, vec![create], ApplyOptions::default()).await;
        assert!(matches!(out[0].result, ApplyResult::Applied));
        let line = &c.lines().await[0];
        assert!(line.starts_with("create_ha_rule"));
        // Type, rule id, resources CSV, nodes, strict=1 all wired.
        assert!(line.contains("\"type\""));
        assert!(line.contains("\"node-affinity\""));
        assert!(line.contains("\"pin-db\""));
        assert!(line.contains("vm:100,vm:101"), "resources CSV: {line}");
        assert!(line.contains("\"nodes\""));
        assert!(line.contains("\"strict\""));
        assert!(line.contains("\"1\""), "strict serialised as 1: {line}");
        // `affinity` is resource-affinity-only — must not be sent for
        // a node-affinity rule.
        assert!(!line.contains("\"affinity\""), "leak: {line}");
    }

    #[tokio::test]
    async fn ha_rule_create_resource_affinity_omits_node_fields() {
        let decl = HaRuleDecl {
            rule: "web-spread".into(),
            rule_type: "resource-affinity".into(),
            resources: vec!["vm:200".into(), "vm:201".into()],
            affinity: "negative".into(),
            ..HaRuleDecl::default()
        };
        let c = RecordingClient::default();
        let change = Change {
            kind: ChangeKind::Create,
            resource: "ha_rule",
            identity: "web-spread".into(),
            before: None,
            after: Some(serde_json::to_value(&decl).unwrap()),
        };
        let out = apply(&c, vec![change], ApplyOptions::default()).await;
        assert!(matches!(out[0].result, ApplyResult::Applied));
        let line = &c.lines().await[0];
        assert!(line.starts_with("create_ha_rule"));
        assert!(line.contains("\"affinity\""));
        assert!(line.contains("\"negative\""));
        // node-affinity-only fields must NOT leak through for a
        // resource-affinity rule.
        assert!(!line.contains("\"nodes\""), "leak: {line}");
        assert!(!line.contains("\"strict\""), "leak: {line}");
    }

    #[tokio::test]
    async fn ha_rule_update_clears_emptied_fields_via_repeated_delete_keys() {
        // PVE keeps old values unless explicitly told to unset them;
        // declaring an empty `comment` must send `delete=comment` as a
        // standalone key. Same matcher-lesson: repeated keys, never a
        // CSV list.
        let after = HaRuleDecl {
            rule: "pin-db".into(),
            rule_type: "node-affinity".into(),
            resources: vec!["vm:100".into()],
            // intentionally empty: comment cleared, nodes kept
            comment: String::new(),
            nodes: "pve1".into(),
            ..HaRuleDecl::default()
        };
        let before = HaRuleDecl {
            rule: "pin-db".into(),
            rule_type: "node-affinity".into(),
            resources: vec!["vm:100".into()],
            comment: "old".into(),
            nodes: "pve1".into(),
            ..HaRuleDecl::default()
        };
        let c = RecordingClient::default();
        let change = Change {
            kind: ChangeKind::Update,
            resource: "ha_rule",
            identity: "pin-db".into(),
            before: Some(serde_json::to_value(&before).unwrap()),
            after: Some(serde_json::to_value(&after).unwrap()),
        };
        let out = apply(&c, vec![change], ApplyOptions::default()).await;
        assert!(matches!(out[0].result, ApplyResult::Applied));
        let line = &c.lines().await[0];
        assert!(line.starts_with("update_ha_rule(pin-db)"));
        // `type` MUST be sent on Update — live PVE 9.1.1 rejects PUT
        // with HTTP 400 `{"errors":{"type":"property is missing and it
        // is not optional"}}` if absent. v0.7.0 omitted it (mis-read
        // of "type is immutable on PUT" — that means cannot CHANGE,
        // not must omit). v0.7.1 always sends it.
        assert!(line.contains("\"type\""), "type missing on PUT: {line}");
        assert!(
            line.contains("\"node-affinity\""),
            "type value should echo existing rule_type: {line}"
        );
        // `delete=comment` repeated key must be present.
        assert!(
            line.contains("\"delete\""),
            "delete keys absent for cleared comment: {line}"
        );
        assert!(line.contains("\"comment\""));
    }

    #[tokio::test]
    async fn ha_rule_update_rejects_type_change_with_actionable_error() {
        // Switching `rule_type` on the same identifier is rejected by
        // PVE with a cryptic message; we catch it upstream with a
        // human-readable bail.
        let before = HaRuleDecl {
            rule: "r1".into(),
            rule_type: "node-affinity".into(),
            ..HaRuleDecl::default()
        };
        let after = HaRuleDecl {
            rule: "r1".into(),
            rule_type: "resource-affinity".into(),
            affinity: "positive".into(),
            ..HaRuleDecl::default()
        };
        let c = RecordingClient::default();
        let change = Change {
            kind: ChangeKind::Update,
            resource: "ha_rule",
            identity: "r1".into(),
            before: Some(serde_json::to_value(&before).unwrap()),
            after: Some(serde_json::to_value(&after).unwrap()),
        };
        let out = apply(&c, vec![change], ApplyOptions::default()).await;
        match &out[0].result {
            ApplyResult::Failed { error, .. } => {
                assert!(
                    error.contains("type change") && error.contains("delete + re-create"),
                    "expected actionable type-change error, got: {error}"
                );
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        // Apply should not have called the gateway at all for the
        // rejected change.
        assert!(c.lines().await.is_empty());
    }

    #[tokio::test]
    async fn ha_rule_delete_dispatches() {
        let decl = HaRuleDecl {
            rule: "pin-db".into(),
            rule_type: "node-affinity".into(),
            ..HaRuleDecl::default()
        };
        let c = RecordingClient::default();
        let change = Change {
            kind: ChangeKind::Delete,
            resource: "ha_rule",
            identity: "pin-db".into(),
            before: Some(serde_json::to_value(&decl).unwrap()),
            after: None,
        };
        let out = apply(
            &c,
            vec![change],
            ApplyOptions {
                prune: true,
                ..ApplyOptions::default()
            },
        )
        .await;
        assert!(matches!(out[0].result, ApplyResult::Applied));
        assert_eq!(c.lines().await, vec!["delete_ha_rule(pin-db)".to_string()]);
    }
}
