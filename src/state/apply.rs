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

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Serialize;

use crate::api::types::{Pool, PoolDetails};
use crate::state::diff::{Change, ChangeKind};
use crate::state::model::{AclDecl, BackupJobDecl, PoolDecl, StorageDecl};

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
}
