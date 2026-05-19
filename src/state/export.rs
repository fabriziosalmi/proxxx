//! Read live cluster state into a `ClusterState`.
//!
//! Pure read: this layer never mutates. Pools-side calls go through a
//! narrow [`PoolReadView`] trait that's a strict subset of the full
//! [`ProxmoxGateway`](crate::api::ProxmoxGateway) — the blanket impl
//! below means any production [`ProxmoxGateway`] auto-satisfies it,
//! and unit tests implement the small trait directly without having
//! to stub 200+ unrelated methods.
//!
//! Diff-stability: every collection is sorted on the way out by its
//! identity field. Two calls to `export_state` against an unchanged
//! cluster produce byte-identical TOML, so a `git diff` after a
//! re-export only shows actual cluster drift.

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::api::types::{ApiVersion, Pool, PoolDetails, PoolMember};
use crate::state::model::{ClusterState, PoolDecl, StateMeta};

/// Which resource families to export. Parsed from the CLI `--resource`
/// argument; v1 supports `pools` only. Future variants will be added
/// as the per-PR ladder in epic #74 lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    Pools,
}

impl Resource {
    /// Parse a `--resource` argument. Case-insensitive. Unknown values
    /// produce an `Err` carrying the full set of currently-valid
    /// options — operators see "what should I have typed" at the
    /// point of failure.
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_lowercase().as_str() {
            "pools" => Ok(Self::Pools),
            other => anyhow::bail!(
                "unknown resource '{other}' (valid in v1: pools — see https://github.com/fabriziosalmi/proxxx/issues/74 for the roadmap)"
            ),
        }
    }

    /// Human-readable name for logs / error messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pools => "pools",
        }
    }
}

/// Minimal read-only surface the pools exporter needs from PVE. A
/// blanket impl below means anything that implements
/// `ProxmoxGateway` auto-satisfies `PoolReadView`; tests implement
/// this small trait directly to avoid stubbing the 200+ methods of
/// `ProxmoxGateway`.
#[async_trait]
pub trait PoolReadView: Send + Sync {
    async fn list_pools_view(&self) -> Result<Vec<Pool>>;
    async fn get_pool_view(&self, poolid: &str) -> Result<PoolDetails>;
    async fn get_api_version_view(&self) -> Result<ApiVersion>;
}

#[async_trait]
impl<T> PoolReadView for T
where
    T: crate::api::ProxmoxGateway + Send + Sync + ?Sized,
{
    async fn list_pools_view(&self) -> Result<Vec<Pool>> {
        crate::api::ProxmoxGateway::list_pools(self).await
    }
    async fn get_pool_view(&self, poolid: &str) -> Result<PoolDetails> {
        crate::api::ProxmoxGateway::get_pool(self, poolid).await
    }
    async fn get_api_version_view(&self) -> Result<ApiVersion> {
        crate::api::ProxmoxGateway::get_api_version(self).await
    }
}

/// Top-level entry: read everything in `resources` from the live
/// cluster and return a `ClusterState`. Always populates `meta` with
/// the export provenance.
pub async fn export_state<C: PoolReadView + ?Sized>(
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
    };

    for r in resources {
        match r {
            Resource::Pools => {
                state.pools = export_pools(client)
                    .await
                    .with_context(|| "exporting pools")?;
            }
        }
    }

    Ok(state)
}

/// Read every pool + its membership and project to `Vec<PoolDecl>`.
/// Pools sorted by `poolid`; members within each pool sorted by their
/// `kind/id` string. Two calls against an unchanged cluster produce
/// the identical Vec.
async fn export_pools<C: PoolReadView + ?Sized>(client: &C) -> Result<Vec<PoolDecl>> {
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
        assert_eq!(Resource::parse("pools").unwrap(), Resource::Pools);
        assert_eq!(Resource::parse("Pools").unwrap(), Resource::Pools);
        assert_eq!(Resource::parse("POOLS").unwrap(), Resource::Pools);
        assert_eq!(Resource::parse(" pools ").unwrap(), Resource::Pools);
    }

    #[test]
    fn resource_parse_rejects_unknown_with_helpful_message() {
        // The error message should tell the operator what they
        // SHOULD have typed — pinning so a future regression
        // doesn't collapse to a generic "invalid argument".
        let err = Resource::parse("acl").unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("unknown resource 'acl'"), "msg: {msg}");
        assert!(
            msg.contains("pools"),
            "should hint at valid value, msg: {msg}"
        );
    }

    /// In-process implementation of the narrow `PoolReadView` trait
    /// for unit testing `export_pools` / `export_state` without
    /// stubbing the 200+ methods of `ProxmoxGateway`.
    #[derive(Default)]
    struct FakePoolView {
        pools: Vec<Pool>,
        details: std::collections::HashMap<String, PoolDetails>,
    }

    #[async_trait]
    impl PoolReadView for FakePoolView {
        async fn list_pools_view(&self) -> Result<Vec<Pool>> {
            Ok(self.pools.clone())
        }
        async fn get_pool_view(&self, poolid: &str) -> Result<PoolDetails> {
            self.details
                .get(poolid)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("pool '{poolid}' not in fake view"))
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
        let mut fake = FakePoolView::default();
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
        let mut fake = FakePoolView::default();
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
        let fake = FakePoolView::default();
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
        let mut fake = FakePoolView::default();
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
}
