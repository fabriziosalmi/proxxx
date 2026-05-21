//! Read live cluster state into a `ClusterState`.
//!
//! Pure read: this layer never mutates. All read calls go through a
//! narrow [`StateReadView`] trait that's a strict subset of the full
//! [`ProxmoxGateway`](crate::api::ProxmoxGateway) — the blanket impl
//! below means any production [`ProxmoxGateway`] auto-satisfies it,
//! and unit tests implement the small trait directly without having
//! to stub 200+ unrelated methods. As new resource families come
//! online the trait grows by exactly the methods the new exporter
//! needs.
//!
//! Diff-stability: every collection is sorted on the way out by its
//! identity field. Two calls to `export_state` against an unchanged
//! cluster produce byte-identical TOML, so a `git diff` after a
//! re-export only shows actual cluster drift.

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::api::types::{
    AclEntry, ApiVersion, BackupJob, Pool, PoolDetails, PoolMember, StorageDefinition,
};
use crate::state::model::{AclDecl, BackupJobDecl, ClusterState, PoolDecl, StateMeta, StorageDecl};

/// Which resource families to export. Parsed from the CLI `--resource`
/// argument. New variants are added per the ladder in epic #74.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    Pools,
    Acl,
    Storage,
    BackupJobs,
}

impl Resource {
    /// Parse a `--resource` argument. Case-insensitive. Unknown
    /// values produce an `Err` carrying the full set of currently-
    /// valid options — operators see "what should I have typed" at
    /// the point of failure. `all` selects every supported family.
    pub fn parse(s: &str) -> Result<Vec<Self>> {
        match s.trim().to_lowercase().as_str() {
            "pools" => Ok(vec![Self::Pools]),
            "acl" => Ok(vec![Self::Acl]),
            "storage" => Ok(vec![Self::Storage]),
            "backup-jobs" => Ok(vec![Self::BackupJobs]),
            "all" => Ok(Self::all()),
            other => anyhow::bail!(
                "unknown resource '{other}' (valid: pools | acl | storage | backup-jobs | all — see https://github.com/fabriziosalmi/proxxx/issues/74 for the roadmap)"
            ),
        }
    }

    /// Every supported resource family, in canonical (struct-field)
    /// order. The single source of truth for "all families" — used by
    /// `--resource all` AND by `state diff` / `state apply` to build
    /// the live snapshot they compare against. Adding a family here
    /// wires it into the full `GitOps` loop in one place, so the diff/
    /// apply live-fetch can never silently omit a family (which would
    /// make that family's declared entries diff as perpetual creates).
    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![Self::Pools, Self::Acl, Self::Storage, Self::BackupJobs]
    }

    /// Human-readable name for logs / error messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pools => "pools",
            Self::Acl => "acl",
            Self::Storage => "storage",
            Self::BackupJobs => "backup-jobs",
        }
    }
}

/// Minimal read-only surface the state exporter needs from PVE. A
/// blanket impl below means anything that implements
/// `ProxmoxGateway` auto-satisfies `StateReadView`; tests implement
/// this small trait directly to avoid stubbing the 200+ methods of
/// `ProxmoxGateway`. As new resource families ship, the trait grows
/// by exactly the read methods the new exporter needs (e.g.
/// `list_storage_view` for storage defs, `get_cluster_firewall_view`
/// for firewall).
#[async_trait]
pub trait StateReadView: Send + Sync {
    async fn list_pools_view(&self) -> Result<Vec<Pool>>;
    async fn get_pool_view(&self, poolid: &str) -> Result<PoolDetails>;
    async fn list_acl_view(&self) -> Result<Vec<AclEntry>>;
    async fn list_cluster_storages_view(&self) -> Result<Vec<StorageDefinition>>;
    async fn list_backup_jobs_view(&self) -> Result<Vec<BackupJob>>;
    async fn get_api_version_view(&self) -> Result<ApiVersion>;
}

#[async_trait]
impl<T> StateReadView for T
where
    T: crate::api::ProxmoxGateway + Send + Sync + ?Sized,
{
    async fn list_pools_view(&self) -> Result<Vec<Pool>> {
        crate::api::ProxmoxGateway::list_pools(self).await
    }
    async fn get_pool_view(&self, poolid: &str) -> Result<PoolDetails> {
        crate::api::ProxmoxGateway::get_pool(self, poolid).await
    }
    async fn list_acl_view(&self) -> Result<Vec<AclEntry>> {
        crate::api::ProxmoxGateway::list_acl(self).await
    }
    async fn list_cluster_storages_view(&self) -> Result<Vec<StorageDefinition>> {
        crate::api::ProxmoxGateway::list_cluster_storages(self).await
    }
    async fn list_backup_jobs_view(&self) -> Result<Vec<BackupJob>> {
        crate::api::ProxmoxGateway::list_backup_jobs(self).await
    }
    async fn get_api_version_view(&self) -> Result<ApiVersion> {
        crate::api::ProxmoxGateway::get_api_version(self).await
    }
}

/// Top-level entry: read everything in `resources` from the live
/// cluster and return a `ClusterState`. Always populates `meta` with
/// the export provenance.
pub async fn export_state<C: StateReadView + ?Sized>(
    client: &C,
    resources: &[Resource],
    profile: &str,
) -> Result<ClusterState> {
    let pve_version = client
        .get_api_version_view()
        .await
        .map(|v| v.version)
        .unwrap_or_default();

    let mut state = ClusterState {
        meta: Some(StateMeta {
            profile: profile.to_string(),
            exported_at: rfc3339_now(),
            exported_from_proxxx: env!("CARGO_PKG_VERSION").to_string(),
            pve_version,
        }),
        pools: Vec::new(),
        acl: Vec::new(),
        storage: Vec::new(),
        backup_jobs: Vec::new(),
    };

    for r in resources {
        match r {
            Resource::Pools => {
                state.pools = export_pools(client)
                    .await
                    .with_context(|| "exporting pools")?;
            }
            Resource::Acl => {
                state.acl = export_acl(client).await.with_context(|| "exporting acl")?;
            }
            Resource::Storage => {
                state.storage = export_storage(client)
                    .await
                    .with_context(|| "exporting storage")?;
            }
            Resource::BackupJobs => {
                state.backup_jobs = export_backup_jobs(client)
                    .await
                    .with_context(|| "exporting backup-jobs")?;
            }
        }
    }

    Ok(state)
}

/// Read every pool + its membership and project to `Vec<PoolDecl>`.
/// Pools sorted by `poolid`; members within each pool sorted by their
/// `kind/id` string. Two calls against an unchanged cluster produce
/// the identical Vec.
async fn export_pools<C: StateReadView + ?Sized>(client: &C) -> Result<Vec<PoolDecl>> {
    let mut pools = client.list_pools_view().await.context("listing pools")?;
    pools.sort_by(|a, b| a.poolid.cmp(&b.poolid));

    let mut out = Vec::with_capacity(pools.len());
    for p in pools {
        let detail: PoolDetails = client
            .get_pool_view(&p.poolid)
            .await
            .with_context(|| format!("reading pool '{}'", p.poolid))?;

        let mut members: Vec<String> = detail
            .members
            .into_iter()
            .filter_map(|m| pool_member_to_ref(&m))
            .collect();
        members.sort();

        out.push(PoolDecl {
            // `list_pools` and `get_pool` both carry `poolid` and
            // `comment`; prefer the detail's comment as the source of
            // truth since the index is a separate query that could
            // theoretically be slightly stale (PVE keeps them
            // synchronised in practice).
            poolid: p.poolid,
            comment: detail.comment,
            members,
        });
    }
    Ok(out)
}

/// Read every ACL grant and project to `Vec<AclDecl>`. Sorted by
/// the identity 4-tuple `(path, kind, ugid, roleid)` so the
/// resulting TOML is diff-stable across runs against an unchanged
/// cluster (PVE's `/access/acl` response order is not stable).
async fn export_acl<C: StateReadView + ?Sized>(client: &C) -> Result<Vec<AclDecl>> {
    let entries = client.list_acl_view().await.context("listing ACL")?;
    let mut out: Vec<AclDecl> = entries
        .into_iter()
        .map(|e| AclDecl {
            path: e.path,
            kind: e.kind,
            ugid: e.ugid,
            roleid: e.roleid,
            propagate: e.propagate,
        })
        .collect();
    out.sort_by(|a, b| {
        a.path
            .cmp(&b.path)
            .then(a.kind.cmp(&b.kind))
            .then(a.ugid.cmp(&b.ugid))
            .then(a.roleid.cmp(&b.roleid))
    });
    Ok(out)
}

/// Read every cluster-wide storage definition and project to
/// `Vec<StorageDecl>`. Sorted by `storage` (the operator-chosen id,
/// unique across the cluster).
///
/// The `digest` field from PVE's response is dropped — it's a stale-
/// check identifier returned to support `If-Match` headers on PUT,
/// not desired state. Including it would make the TOML churn on
/// every API call even when the storage's configuration hasn't
/// actually changed.
async fn export_storage<C: StateReadView + ?Sized>(client: &C) -> Result<Vec<StorageDecl>> {
    let mut storages = client
        .list_cluster_storages_view()
        .await
        .context("listing cluster storages")?;
    storages.sort_by(|a, b| a.storage.cmp(&b.storage));

    Ok(storages
        .into_iter()
        .map(|s| StorageDecl {
            storage: s.storage,
            storage_type: s.storage_type,
            // PVE returns the `content` and `nodes` CSVs in non-
            // deterministic order across API calls — `local` might
            // come back as `"backup,iso"` one call and
            // `"iso,backup"` the next. Sort the comma-separated
            // tokens on export so the resulting TOML is byte-stable
            // across runs. Confirmed by the live smoke test.
            content: normalize_csv(&s.content),
            nodes: normalize_csv(&s.nodes),
            disable: s.disable,
            shared: s.shared,
            path: s.path,
            pool: s.pool,
            server: s.server,
            export: s.export,
            datastore: s.datastore,
            fingerprint: s.fingerprint,
            username: s.username,
            vgname: s.vgname,
            thinpool: s.thinpool,
        })
        .collect())
}

/// Read every scheduled (recurring) backup job and project to
/// `Vec<BackupJobDecl>`. Sorted by `id` (the operator/PVE-assigned
/// job id, unique cluster-wide) for diff-stability.
///
/// Two PVE response fields are deliberately dropped:
/// * `next-run` — scheduler-computed epoch of the next fire. The
///   backup-job analogue of storage's `digest`: pure derived state
///   that would churn the TOML on every export even when the job
///   hasn't changed.
/// * `mailnotification` — deprecated in PVE 8+ in favour of the
///   notification-target system; not a field operators manage
///   declaratively here, so it stays unmanaged rather than being
///   round-tripped (and possibly rejected) on apply.
async fn export_backup_jobs<C: StateReadView + ?Sized>(client: &C) -> Result<Vec<BackupJobDecl>> {
    let mut jobs = client
        .list_backup_jobs_view()
        .await
        .context("listing backup jobs")?;
    jobs.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(jobs
        .into_iter()
        .map(|j| BackupJobDecl {
            id: j.id,
            schedule: j.schedule,
            storage: j.storage,
            mode: j.mode,
            enabled: j.enabled,
            all: j.all,
            vmid: j.vmid,
            node: j.node,
            mailto: j.mailto,
            compress: j.compress,
            comment: j.comment,
            notes_template: j.notes_template,
            prune_backups: j.prune_backups,
        })
        .collect())
}

/// Sort the comma-separated tokens of a CSV-style PVE field. Empty
/// input maps to empty output. Whitespace around commas is preserved
/// (PVE doesn't emit any; if it ever does, we'd reformat on round-
/// trip rather than break declared-vs-live equality on whitespace).
fn normalize_csv(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }
    let mut parts: Vec<&str> = s.split(',').collect();
    parts.sort_unstable();
    parts.join(",")
}

/// Project one `PoolMember` to its identity string (`qemu/100`,
/// `lxc/200`, `storage/<name>`). Returns `None` for unknown member
/// types — PVE may add new kinds in future versions (SDN objects, for
/// example), and unknown members are dropped on export rather than
/// crashing the dump. The dropped count is logged via `tracing::warn`.
fn pool_member_to_ref(m: &PoolMember) -> Option<String> {
    match m.member_type.as_str() {
        "qemu" => Some(format!("qemu/{}", m.vmid)),
        "lxc" => Some(format!("lxc/{}", m.vmid)),
        "storage" => Some(format!("storage/{}", m.storage)),
        other => {
            tracing::warn!(
                kind = other,
                id = %m.id,
                "pool member of unknown kind skipped on export"
            );
            None
        }
    }
}

/// RFC 3339 timestamp in UTC for the export's `meta.exported_at`.
/// Hand-rolled to avoid pulling chrono just for one timestamp; the
/// audit module has the same algorithm and we deliberately don't
/// share the helper to keep the two modules' formatters independent
/// (a future change to one shouldn't silently rebase the other).
fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

const fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    let mut y = 1970u64;
    loop {
        let leap = (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400);
        let dy = if leap { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        y += 1;
    }
    let leap = (y.is_multiple_of(4) && !y.is_multiple_of(100)) || y.is_multiple_of(400);
    let months: [u64; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut mo = 1u64;
    let mut i = 0;
    while i < months.len() {
        if days < months[i] {
            break;
        }
        days -= months[i];
        mo += 1;
        i += 1;
    }
    (y, mo, days + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{Pool, PoolDetails, PoolMember};

    #[test]
    fn member_to_ref_qemu() {
        let m = PoolMember {
            id: "qemu/100".into(),
            member_type: "qemu".into(),
            vmid: 100,
            ..Default::default()
        };
        assert_eq!(pool_member_to_ref(&m).as_deref(), Some("qemu/100"));
    }

    #[test]
    fn member_to_ref_lxc() {
        let m = PoolMember {
            id: "lxc/200".into(),
            member_type: "lxc".into(),
            vmid: 200,
            ..Default::default()
        };
        assert_eq!(pool_member_to_ref(&m).as_deref(), Some("lxc/200"));
    }

    #[test]
    fn member_to_ref_storage_uses_storage_field_not_vmid() {
        // PVE returns storage members with vmid=0 and the real id in
        // the `storage` field. Pins that we read the right column.
        let m = PoolMember {
            id: "storage/pve-test-1/ceph-rbd".into(),
            member_type: "storage".into(),
            vmid: 0,
            storage: "ceph-rbd".into(),
            ..Default::default()
        };
        assert_eq!(pool_member_to_ref(&m).as_deref(), Some("storage/ceph-rbd"));
    }

    #[test]
    fn member_to_ref_unknown_kind_is_skipped() {
        // SDN objects, future PVE additions, etc. We log + drop
        // rather than crash; the dropped count is observable via
        // the tracing layer at warn level.
        let m = PoolMember {
            id: "sdn/somenet".into(),
            member_type: "sdn".into(),
            ..Default::default()
        };
        assert!(pool_member_to_ref(&m).is_none());
    }

    #[test]
    fn resource_parse_accepts_pools_case_insensitive() {
        assert_eq!(Resource::parse("pools").unwrap(), vec![Resource::Pools]);
        assert_eq!(Resource::parse("Pools").unwrap(), vec![Resource::Pools]);
        assert_eq!(Resource::parse("POOLS").unwrap(), vec![Resource::Pools]);
        assert_eq!(Resource::parse(" pools ").unwrap(), vec![Resource::Pools]);
    }

    #[test]
    fn resource_parse_accepts_acl_case_insensitive() {
        assert_eq!(Resource::parse("acl").unwrap(), vec![Resource::Acl]);
        assert_eq!(Resource::parse("ACL").unwrap(), vec![Resource::Acl]);
    }

    #[test]
    fn resource_parse_all_returns_every_supported_family() {
        // `--resource all` is the stable shortcut for "every family
        // this proxxx binary supports". Order matters: pools first,
        // then ACL (matching `export_state`'s iteration order) so
        // a `--resource all` export hits resources in a deterministic
        // sequence regardless of input ordering.
        let v = Resource::parse("all").unwrap();
        assert_eq!(
            v,
            vec![
                Resource::Pools,
                Resource::Acl,
                Resource::Storage,
                Resource::BackupJobs
            ]
        );
        // `parse("all")` and `Resource::all()` must stay in lockstep —
        // the latter is what `state diff` / `state apply` use to build
        // the live snapshot. If they diverge, a family could be diffed
        // but never fetched (perpetual-create bug).
        assert_eq!(v, Resource::all());
    }

    #[test]
    fn resource_all_includes_every_variant() {
        // Guards the diff/apply live-fetch set: every family the
        // exporter knows must be in `all()`, or its declared entries
        // would diff as perpetual creates (they'd never appear in the
        // live snapshot diff/apply compares against).
        let all = Resource::all();
        for r in [
            Resource::Pools,
            Resource::Acl,
            Resource::Storage,
            Resource::BackupJobs,
        ] {
            assert!(all.contains(&r), "Resource::all() is missing {r:?}");
        }
    }

    #[test]
    fn resource_parse_accepts_backup_jobs_hyphenated() {
        // The CLI value is hyphenated (`backup-jobs`), matching the
        // `as_str()` round-trip and PVE's own `/cluster/backup`
        // resource. Case-insensitive like the others.
        assert_eq!(
            Resource::parse("backup-jobs").unwrap(),
            vec![Resource::BackupJobs]
        );
        assert_eq!(
            Resource::parse("Backup-Jobs").unwrap(),
            vec![Resource::BackupJobs]
        );
        assert_eq!(Resource::BackupJobs.as_str(), "backup-jobs");
    }

    #[test]
    fn resource_parse_rejects_unknown_with_helpful_message() {
        // The error message should tell the operator what they
        // SHOULD have typed — pinning so a future regression
        // doesn't collapse to a generic "invalid argument".
        let err = Resource::parse("bogus").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown resource 'bogus'"), "msg: {msg}");
        assert!(
            msg.contains("pools"),
            "should hint at valid values, msg: {msg}"
        );
    }

    /// In-process implementation of the narrow `StateReadView` trait
    /// for unit testing `export_pools` / `export_acl` / `export_state`
    /// without stubbing the 200+ methods of `ProxmoxGateway`.
    #[derive(Default)]
    struct FakeStateView {
        pools: Vec<Pool>,
        details: std::collections::HashMap<String, PoolDetails>,
        acl: Vec<AclEntry>,
        storage: Vec<StorageDefinition>,
        backup_jobs: Vec<BackupJob>,
    }

    #[async_trait]
    impl StateReadView for FakeStateView {
        async fn list_pools_view(&self) -> Result<Vec<Pool>> {
            Ok(self.pools.clone())
        }
        async fn get_pool_view(&self, poolid: &str) -> Result<PoolDetails> {
            self.details
                .get(poolid)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("pool '{poolid}' not in fake view"))
        }
        async fn list_acl_view(&self) -> Result<Vec<AclEntry>> {
            Ok(self.acl.clone())
        }
        async fn list_cluster_storages_view(&self) -> Result<Vec<StorageDefinition>> {
            Ok(self.storage.clone())
        }
        async fn list_backup_jobs_view(&self) -> Result<Vec<BackupJob>> {
            Ok(self.backup_jobs.clone())
        }
        async fn get_api_version_view(&self) -> Result<ApiVersion> {
            Ok(ApiVersion {
                version: "9.1.9-test".into(),
                release: "9.1".into(),
                repoid: "fake".into(),
            })
        }
    }

    #[tokio::test]
    async fn export_pools_sorts_pools_by_poolid() {
        // Even if PVE returns pools in random order, the export must
        // be sorted by poolid so the TOML is diff-stable across runs.
        let mut fake = FakeStateView::default();
        fake.pools = vec![
            Pool {
                poolid: "z-platform".into(),
                comment: "z".into(),
            },
            Pool {
                poolid: "a-dev".into(),
                comment: "a".into(),
            },
            Pool {
                poolid: "m-staging".into(),
                comment: "m".into(),
            },
        ];
        for p in &fake.pools {
            fake.details.insert(
                p.poolid.clone(),
                PoolDetails {
                    poolid: p.poolid.clone(),
                    comment: p.comment.clone(),
                    members: vec![],
                },
            );
        }

        let out = export_pools(&fake).await.expect("export");
        let ids: Vec<&str> = out.iter().map(|p| p.poolid.as_str()).collect();
        assert_eq!(ids, vec!["a-dev", "m-staging", "z-platform"]);
    }

    #[tokio::test]
    async fn export_pools_sorts_members_within_each_pool() {
        let mut fake = FakeStateView::default();
        fake.pools = vec![Pool {
            poolid: "p1".into(),
            comment: String::new(),
        }];
        fake.details.insert(
            "p1".into(),
            PoolDetails {
                poolid: "p1".into(),
                comment: String::new(),
                members: vec![
                    PoolMember {
                        id: "qemu/200".into(),
                        member_type: "qemu".into(),
                        vmid: 200,
                        ..Default::default()
                    },
                    PoolMember {
                        id: "storage/ceph-rbd".into(),
                        member_type: "storage".into(),
                        storage: "ceph-rbd".into(),
                        ..Default::default()
                    },
                    PoolMember {
                        id: "qemu/100".into(),
                        member_type: "qemu".into(),
                        vmid: 100,
                        ..Default::default()
                    },
                ],
            },
        );

        let out = export_pools(&fake).await.expect("export");
        assert_eq!(out.len(), 1);
        // Sorted: "qemu/100" < "qemu/200" < "storage/ceph-rbd"
        // (lexical compare; member identity is a `kind/id` string).
        assert_eq!(
            out[0].members,
            vec![
                "qemu/100".to_string(),
                "qemu/200".to_string(),
                "storage/ceph-rbd".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn export_state_populates_meta_with_profile_and_pve_version() {
        let fake = FakeStateView::default();
        let s = export_state(&fake, &[Resource::Pools], "test-profile")
            .await
            .expect("export");
        let meta = s.meta.expect("meta present");
        assert_eq!(meta.profile, "test-profile");
        assert_eq!(meta.pve_version, "9.1.9-test");
        // exported_from_proxxx comes from CARGO_PKG_VERSION — should
        // match the binary's compile-time version.
        assert_eq!(meta.exported_from_proxxx, env!("CARGO_PKG_VERSION"));
        // exported_at is RFC 3339 — basic shape check.
        assert!(
            meta.exported_at.ends_with('Z'),
            "expected RFC 3339 Z suffix, got {:?}",
            meta.exported_at
        );
        assert!(
            meta.exported_at.contains('T'),
            "expected RFC 3339 'T' separator, got {:?}",
            meta.exported_at
        );
    }

    #[tokio::test]
    async fn export_state_is_byte_stable_on_two_runs_against_unchanged_state() {
        // Diff-stability contract: two consecutive exports against
        // identical input yield identical TOML modulo `exported_at`.
        // This is the load-bearing property for GitOps — without it,
        // every `git diff` post-re-export is noise.
        let mut fake = FakeStateView::default();
        fake.pools = vec![
            Pool {
                poolid: "alpha".into(),
                comment: "a".into(),
            },
            Pool {
                poolid: "beta".into(),
                comment: "b".into(),
            },
        ];
        for p in &fake.pools {
            fake.details.insert(
                p.poolid.clone(),
                PoolDetails {
                    poolid: p.poolid.clone(),
                    comment: p.comment.clone(),
                    members: vec![],
                },
            );
        }

        let s1 = export_state(&fake, &[Resource::Pools], "p").await.unwrap();
        let s2 = export_state(&fake, &[Resource::Pools], "p").await.unwrap();

        // The only field that legitimately differs is meta.exported_at
        // (wall-clock-dependent). Strip it for the comparison.
        let strip_ts = |mut s: ClusterState| {
            if let Some(m) = s.meta.as_mut() {
                m.exported_at.clear();
            }
            s
        };
        assert_eq!(strip_ts(s1), strip_ts(s2));
    }

    #[tokio::test]
    async fn export_acl_sorts_by_identity_tuple() {
        // PVE's `/access/acl` response order is not stable; the
        // export must canonicalise by the identity 4-tuple `(path,
        // kind, ugid, roleid)` so the resulting TOML is byte-stable.
        let mut fake = FakeStateView::default();
        fake.acl = vec![
            AclEntry {
                path: "/vms/200".into(),
                kind: "user".into(),
                ugid: "bob@pve".into(),
                roleid: "PVEVMUser".into(),
                propagate: true,
            },
            AclEntry {
                path: "/vms/100".into(),
                kind: "user".into(),
                ugid: "alice@pve".into(),
                roleid: "PVEVMAdmin".into(),
                propagate: true,
            },
            AclEntry {
                path: "/vms/100".into(),
                kind: "group".into(),
                ugid: "devops".into(),
                roleid: "PVEVMAdmin".into(),
                propagate: false,
            },
        ];

        let out = export_acl(&fake).await.expect("export");
        // Sort order: path then kind then ugid then roleid.
        assert_eq!(out[0].path, "/vms/100");
        assert_eq!(out[0].kind, "group");
        assert_eq!(out[1].path, "/vms/100");
        assert_eq!(out[1].kind, "user");
        assert_eq!(out[2].path, "/vms/200");
    }

    #[tokio::test]
    async fn export_acl_preserves_propagate_value() {
        let mut fake = FakeStateView::default();
        fake.acl = vec![AclEntry {
            path: "/storage/local".into(),
            kind: "user".into(),
            ugid: "ops@pve".into(),
            roleid: "PVEDatastoreUser".into(),
            propagate: false,
        }];
        let out = export_acl(&fake).await.expect("export");
        assert_eq!(out.len(), 1);
        assert!(!out[0].propagate);
    }

    #[tokio::test]
    async fn export_state_all_runs_every_family_in_order() {
        // `Resource::Pools` then `Resource::Acl` — the canonical
        // `all` ordering. Pinning so a future refactor doesn't flip
        // the iteration order under us (byte-stability would still
        // hold, but the diff would be massive on the flip).
        let mut fake = FakeStateView::default();
        fake.pools = vec![Pool {
            poolid: "p1".into(),
            comment: "x".into(),
        }];
        fake.details.insert(
            "p1".into(),
            PoolDetails {
                poolid: "p1".into(),
                comment: "x".into(),
                members: vec![],
            },
        );
        fake.acl = vec![AclEntry {
            path: "/".into(),
            kind: "user".into(),
            ugid: "root@pam".into(),
            roleid: "Administrator".into(),
            propagate: true,
        }];

        let s = export_state(&fake, &[Resource::Pools, Resource::Acl], "p")
            .await
            .unwrap();
        assert_eq!(s.pools.len(), 1, "pools populated");
        assert_eq!(s.acl.len(), 1, "acl populated");

        // TOML serialisation must list `[[pools]]` before `[[acl]]`
        // (matches struct field declaration order in `ClusterState`).
        let toml_str = toml::to_string(&s).expect("serialize");
        let pools_idx = toml_str.find("[[pools]]").expect("[[pools]] present");
        let acl_idx = toml_str.find("[[acl]]").expect("[[acl]] present");
        assert!(
            pools_idx < acl_idx,
            "pools must come before acl in TOML, got pools_idx={pools_idx} acl_idx={acl_idx}"
        );
    }

    #[tokio::test]
    async fn export_storage_sorts_by_storage_id() {
        // PVE returns storages in roughly creation order; the export
        // must canonicalise to alphabetical by `storage` id so the
        // TOML is byte-stable.
        let mut fake = FakeStateView::default();
        fake.storage = vec![
            StorageDefinition {
                storage: "zfs-fast".into(),
                storage_type: "zfspool".into(),
                pool: "rpool/data".into(),
                content: "images,rootdir".into(),
                shared: false,
                ..Default::default()
            },
            StorageDefinition {
                storage: "local".into(),
                storage_type: "dir".into(),
                path: "/var/lib/vz".into(),
                content: "iso,backup,vztmpl".into(),
                ..Default::default()
            },
            StorageDefinition {
                storage: "ceph-rbd".into(),
                storage_type: "rbd".into(),
                pool: "rbd".into(),
                content: "images".into(),
                shared: true,
                ..Default::default()
            },
        ];

        let out = export_storage(&fake).await.expect("export");
        let ids: Vec<&str> = out.iter().map(|s| s.storage.as_str()).collect();
        assert_eq!(ids, vec!["ceph-rbd", "local", "zfs-fast"]);
    }

    #[tokio::test]
    async fn export_storage_drops_digest_from_pve_response() {
        // PVE's `GET /storage` includes a `digest` field for ETag-
        // style stale-check. It's not desired state; including it in
        // the export would make the TOML churn on every API call.
        // The model has no `digest` field; the export must not
        // synthesise one. (Confirms by checking the serialised TOML.)
        let mut fake = FakeStateView::default();
        fake.storage = vec![StorageDefinition {
            storage: "local".into(),
            storage_type: "dir".into(),
            content: "iso".into(),
            path: "/var/lib/vz".into(),
            digest: "abc123".into(),
            ..Default::default()
        }];
        let out = export_storage(&fake).await.expect("export");
        let toml_str = toml::to_string(&out[0]).expect("serialize");
        assert!(
            !toml_str.contains("digest"),
            "digest must not survive export, got:\n{toml_str}"
        );
        assert!(
            !toml_str.contains("abc123"),
            "digest value must not survive export, got:\n{toml_str}"
        );
    }

    #[tokio::test]
    async fn export_backup_jobs_sorts_by_id() {
        // PVE's `/cluster/backup` order is creation order; the export
        // must canonicalise to alphabetical by `id` so the TOML is
        // byte-stable across runs.
        let mut fake = FakeStateView::default();
        fake.backup_jobs = vec![
            BackupJob {
                id: "weekly-prod".into(),
                schedule: "sun 01:00".into(),
                storage: "pbs".into(),
                ..Default::default()
            },
            BackupJob {
                id: "daily-all".into(),
                schedule: "*-*-* 02:00".into(),
                storage: "local".into(),
                ..Default::default()
            },
            BackupJob {
                id: "hourly-db".into(),
                schedule: "*-*-* *:00".into(),
                storage: "pbs".into(),
                ..Default::default()
            },
        ];
        let out = export_backup_jobs(&fake).await.expect("export");
        let ids: Vec<&str> = out.iter().map(|j| j.id.as_str()).collect();
        assert_eq!(ids, vec!["daily-all", "hourly-db", "weekly-prod"]);
    }

    #[tokio::test]
    async fn export_backup_jobs_drops_next_run_and_mailnotification() {
        // `next-run` is scheduler-derived (would churn the TOML) and
        // `mailnotification` is deprecated/unmanaged — neither is a
        // `BackupJobDecl` field, so neither may survive the export.
        let mut fake = FakeStateView::default();
        fake.backup_jobs = vec![BackupJob {
            id: "nightly".into(),
            schedule: "*-*-* 03:00".into(),
            storage: "local".into(),
            mailnotification: "always".into(),
            next_run: 1_900_000_000,
            ..Default::default()
        }];
        let out = export_backup_jobs(&fake).await.expect("export");
        assert_eq!(out.len(), 1);
        let toml_str = toml::to_string(&out[0]).expect("serialize");
        assert!(
            !toml_str.contains("next") && !toml_str.contains("1900000000"),
            "next-run must not survive export, got:\n{toml_str}"
        );
        assert!(
            !toml_str.contains("mailnotification") && !toml_str.contains("always"),
            "mailnotification must not survive export, got:\n{toml_str}"
        );
    }

    #[tokio::test]
    async fn export_backup_jobs_preserves_enabled_and_all_selectors() {
        // The two booleans carry real intent: a disabled job and the
        // `all`-guests selector. Pin that both survive the projection.
        let mut fake = FakeStateView::default();
        fake.backup_jobs = vec![BackupJob {
            id: "j".into(),
            schedule: "daily".into(),
            storage: "local".into(),
            enabled: false,
            all: true,
            ..Default::default()
        }];
        let out = export_backup_jobs(&fake).await.expect("export");
        assert!(!out[0].enabled, "disabled flag must survive");
        assert!(out[0].all, "all-guests selector must survive");
    }
}
