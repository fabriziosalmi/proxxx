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
    AclEntry, ApiVersion, BackupJob, FirewallAlias, FirewallIpset, FirewallIpsetCidr,
    FirewallOptions, FirewallSecurityGroup, HaRule, NotificationMatcher, Pool, PoolDetails,
    PoolMember, StorageDefinition,
};
use crate::state::model::{
    AclDecl, BackupJobDecl, ClusterState, FirewallAliasDecl, FirewallGroupDecl,
    FirewallIpsetCidrDecl, FirewallIpsetDecl, FirewallOptionsDecl, HaRuleDecl,
    NotificationMatcherDecl, PoolDecl, StateMeta, StorageDecl,
};

/// Which resource families to export. Parsed from the CLI `--resource`
/// argument. New variants are added per the ladder in epic #74.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    Pools,
    Acl,
    Storage,
    BackupJobs,
    /// The whole cluster-firewall surface in one selector: options
    /// (singleton) + aliases + IP sets + security groups. Exporting
    /// them together keeps the `--resource firewall-cluster` UX simple
    /// (operators don't juggle four sub-selectors) and matches how the
    /// pieces are reasoned about as a unit.
    FirewallCluster,
    /// Notification matchers (routing rules). Endpoints are excluded by
    /// design — they carry secrets PVE won't disclose on `GET`, so they
    /// can't round-trip; see [`ClusterState::notification_matchers`].
    Notifications,
    /// HA placement rules (`/cluster/ha/rules`, PVE 9+) — node-affinity
    /// and resource-affinity. Closes epic
    /// [#74](https://github.com/fabriziosalmi/proxxx/issues/74). Legacy
    /// `/cluster/ha/groups` (PVE 8) is intentionally NOT modelled — PVE 9
    /// migrated it to rules, and we don't ship two parallel families for
    /// the same desired-state surface.
    HaRules,
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
            "firewall-cluster" => Ok(vec![Self::FirewallCluster]),
            "notifications" => Ok(vec![Self::Notifications]),
            "ha-rules" => Ok(vec![Self::HaRules]),
            "all" => Ok(Self::all()),
            other => anyhow::bail!(
                "unknown resource '{other}' (valid: pools | acl | storage | backup-jobs | firewall-cluster | notifications | ha-rules | all)"
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
        vec![
            Self::Pools,
            Self::Acl,
            Self::Storage,
            Self::BackupJobs,
            Self::FirewallCluster,
            Self::Notifications,
            Self::HaRules,
        ]
    }

    /// Human-readable name for logs / error messages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pools => "pools",
            Self::Acl => "acl",
            Self::Storage => "storage",
            Self::BackupJobs => "backup-jobs",
            Self::FirewallCluster => "firewall-cluster",
            Self::Notifications => "notifications",
            Self::HaRules => "ha-rules",
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
    async fn get_cluster_firewall_options_view(&self) -> Result<FirewallOptions>;
    async fn list_cluster_firewall_aliases_view(&self) -> Result<Vec<FirewallAlias>>;
    async fn list_cluster_firewall_ipsets_view(&self) -> Result<Vec<FirewallIpset>>;
    async fn list_cluster_firewall_ipset_cidrs_view(
        &self,
        name: &str,
    ) -> Result<Vec<FirewallIpsetCidr>>;
    async fn list_cluster_firewall_groups_view(&self) -> Result<Vec<FirewallSecurityGroup>>;
    async fn list_notification_matchers_view(&self) -> Result<Vec<NotificationMatcher>>;
    async fn list_ha_rules_view(&self) -> Result<Vec<HaRule>>;
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
    async fn get_cluster_firewall_options_view(&self) -> Result<FirewallOptions> {
        crate::api::ProxmoxGateway::get_cluster_firewall_options(self).await
    }
    async fn list_cluster_firewall_aliases_view(&self) -> Result<Vec<FirewallAlias>> {
        crate::api::ProxmoxGateway::list_cluster_firewall_aliases(self).await
    }
    async fn list_cluster_firewall_ipsets_view(&self) -> Result<Vec<FirewallIpset>> {
        crate::api::ProxmoxGateway::list_cluster_firewall_ipsets(self).await
    }
    async fn list_cluster_firewall_ipset_cidrs_view(
        &self,
        name: &str,
    ) -> Result<Vec<FirewallIpsetCidr>> {
        crate::api::ProxmoxGateway::list_cluster_firewall_ipset_cidrs(self, name).await
    }
    async fn list_cluster_firewall_groups_view(&self) -> Result<Vec<FirewallSecurityGroup>> {
        crate::api::ProxmoxGateway::list_cluster_firewall_groups(self).await
    }
    async fn list_notification_matchers_view(&self) -> Result<Vec<NotificationMatcher>> {
        crate::api::ProxmoxGateway::list_notification_matchers(self).await
    }
    async fn list_ha_rules_view(&self) -> Result<Vec<HaRule>> {
        crate::api::ProxmoxGateway::list_ha_rules(self).await
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
        firewall_options: None,
        firewall_aliases: Vec::new(),
        firewall_ipsets: Vec::new(),
        firewall_groups: Vec::new(),
        notification_matchers: Vec::new(),
        ha_rules: Vec::new(),
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
            Resource::FirewallCluster => {
                state.firewall_options = Some(
                    export_firewall_options(client)
                        .await
                        .with_context(|| "exporting firewall options")?,
                );
                state.firewall_aliases = export_firewall_aliases(client)
                    .await
                    .with_context(|| "exporting firewall aliases")?;
                state.firewall_ipsets = export_firewall_ipsets(client)
                    .await
                    .with_context(|| "exporting firewall ipsets")?;
                state.firewall_groups = export_firewall_groups(client)
                    .await
                    .with_context(|| "exporting firewall groups")?;
            }
            Resource::Notifications => {
                state.notification_matchers = export_notification_matchers(client)
                    .await
                    .with_context(|| "exporting notification matchers")?;
            }
            Resource::HaRules => {
                state.ha_rules = export_ha_rules(client)
                    .await
                    .with_context(|| "exporting HA rules")?;
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

/// Read the cluster firewall options singleton and project to
/// `FirewallOptionsDecl`. The `digest` stale-check token is dropped
/// (it would churn the TOML on every export).
async fn export_firewall_options<C: StateReadView + ?Sized>(
    client: &C,
) -> Result<FirewallOptionsDecl> {
    let o = client
        .get_cluster_firewall_options_view()
        .await
        .context("reading firewall options")?;
    Ok(FirewallOptionsDecl {
        enable: o.enable,
        policy_in: o.policy_in,
        policy_out: o.policy_out,
        ebtables: o.ebtables,
        log_ratelimit: o.log_ratelimit,
    })
}

/// Read every cluster firewall alias and project to
/// `Vec<FirewallAliasDecl>`, sorted by `name`. The derived `ipversion`
/// (inferred from the CIDR) and the `digest` token are dropped.
async fn export_firewall_aliases<C: StateReadView + ?Sized>(
    client: &C,
) -> Result<Vec<FirewallAliasDecl>> {
    let mut aliases = client
        .list_cluster_firewall_aliases_view()
        .await
        .context("listing firewall aliases")?;
    aliases.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(aliases
        .into_iter()
        .map(|a| FirewallAliasDecl {
            name: a.name,
            cidr: a.cidr,
            comment: a.comment,
        })
        .collect())
}

/// Read every cluster firewall IP set + its CIDR membership and
/// project to `Vec<FirewallIpsetDecl>`. IP sets sorted by `name`,
/// CIDRs within each set sorted by `cidr`, both for diff-stability.
/// The per-set and per-CIDR `digest` tokens are dropped.
async fn export_firewall_ipsets<C: StateReadView + ?Sized>(
    client: &C,
) -> Result<Vec<FirewallIpsetDecl>> {
    let mut ipsets = client
        .list_cluster_firewall_ipsets_view()
        .await
        .context("listing firewall ipsets")?;
    ipsets.sort_by(|a, b| a.name.cmp(&b.name));

    let mut out = Vec::with_capacity(ipsets.len());
    for s in ipsets {
        let mut cidrs = client
            .list_cluster_firewall_ipset_cidrs_view(&s.name)
            .await
            .with_context(|| format!("listing CIDRs of ipset '{}'", s.name))?;
        cidrs.sort_by(|a, b| a.cidr.cmp(&b.cidr));
        out.push(FirewallIpsetDecl {
            name: s.name,
            comment: s.comment,
            cidrs: cidrs
                .into_iter()
                .map(|c| FirewallIpsetCidrDecl {
                    cidr: c.cidr,
                    comment: c.comment,
                    nomatch: c.nomatch,
                })
                .collect(),
        });
    }
    Ok(out)
}

/// Read every cluster firewall security group and project to
/// `Vec<FirewallGroupDecl>`, sorted by `group`. The group's *rules*
/// are not read here (they're read-only in the state model); only the
/// group's existence + comment is captured. The `digest` is dropped.
async fn export_firewall_groups<C: StateReadView + ?Sized>(
    client: &C,
) -> Result<Vec<FirewallGroupDecl>> {
    let mut groups = client
        .list_cluster_firewall_groups_view()
        .await
        .context("listing firewall groups")?;
    groups.sort_by(|a, b| a.group.cmp(&b.group));
    Ok(groups
        .into_iter()
        .map(|g| FirewallGroupDecl {
            group: g.group,
            comment: g.comment,
        })
        .collect())
}

/// Read every notification matcher and project to
/// `Vec<NotificationMatcherDecl>`, sorted by `name`. The three list
/// fields (`target` / `match_field` / `match_severity`) are sorted
/// too — order is not semantically meaningful for `all`/`any` matching,
/// and sorting keeps the TOML byte-stable across runs. The derived
/// `origin` provenance field is dropped.
async fn export_notification_matchers<C: StateReadView + ?Sized>(
    client: &C,
) -> Result<Vec<NotificationMatcherDecl>> {
    let mut matchers = client
        .list_notification_matchers_view()
        .await
        .context("listing notification matchers")?;
    matchers.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(matchers
        .into_iter()
        .map(|m| {
            let mut target = m.target;
            let mut match_field = m.match_field;
            let mut match_severity = m.match_severity;
            target.sort();
            match_field.sort();
            match_severity.sort();
            NotificationMatcherDecl {
                name: m.name,
                comment: m.comment,
                target,
                match_field,
                match_severity,
                mode: m.mode,
                invert_match: m.invert_match,
                disable: m.disable,
            }
        })
        .collect())
}

/// Read every HA rule and project to `Vec<HaRuleDecl>`, sorted by
/// `rule`. The wire-side `resources` comma-string is split, sorted, and
/// deduped into a `Vec<String>` for TOML-friendly editing and for
/// diff-stable identity equality (set equality vs string equality). The
/// wire `nodes` priority-encoded string is kept verbatim — splitting
/// would lose PVE's parser validation (duplicate-node rejection),
/// recomposing risks reordering, and operators write the canonical
/// `nodes` form by hand. `digest` is dropped (server-derived churn).
async fn export_ha_rules<C: StateReadView + ?Sized>(client: &C) -> Result<Vec<HaRuleDecl>> {
    let mut rules = client
        .list_ha_rules_view()
        .await
        .context("listing HA rules")?;
    rules.sort_by(|a, b| a.rule.cmp(&b.rule));

    Ok(rules
        .into_iter()
        .map(|r| {
            let mut resources: Vec<String> = r
                .resources
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            resources.sort();
            resources.dedup();
            HaRuleDecl {
                rule: r.rule,
                rule_type: r.rule_type,
                resources,
                comment: r.comment,
                disable: r.disable,
                nodes: r.nodes,
                strict: r.strict,
                affinity: r.affinity,
            }
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
                Resource::BackupJobs,
                Resource::FirewallCluster,
                Resource::Notifications,
                Resource::HaRules,
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
            Resource::FirewallCluster,
            Resource::Notifications,
            Resource::HaRules,
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
        fw_options: FirewallOptions,
        fw_aliases: Vec<FirewallAlias>,
        fw_ipsets: Vec<FirewallIpset>,
        fw_ipset_cidrs: std::collections::HashMap<String, Vec<FirewallIpsetCidr>>,
        fw_groups: Vec<FirewallSecurityGroup>,
        notif_matchers: Vec<NotificationMatcher>,
        ha_rules: Vec<HaRule>,
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
        async fn get_cluster_firewall_options_view(&self) -> Result<FirewallOptions> {
            Ok(self.fw_options.clone())
        }
        async fn list_cluster_firewall_aliases_view(&self) -> Result<Vec<FirewallAlias>> {
            Ok(self.fw_aliases.clone())
        }
        async fn list_cluster_firewall_ipsets_view(&self) -> Result<Vec<FirewallIpset>> {
            Ok(self.fw_ipsets.clone())
        }
        async fn list_cluster_firewall_ipset_cidrs_view(
            &self,
            name: &str,
        ) -> Result<Vec<FirewallIpsetCidr>> {
            Ok(self.fw_ipset_cidrs.get(name).cloned().unwrap_or_default())
        }
        async fn list_cluster_firewall_groups_view(&self) -> Result<Vec<FirewallSecurityGroup>> {
            Ok(self.fw_groups.clone())
        }
        async fn list_notification_matchers_view(&self) -> Result<Vec<NotificationMatcher>> {
            Ok(self.notif_matchers.clone())
        }
        async fn list_ha_rules_view(&self) -> Result<Vec<HaRule>> {
            Ok(self.ha_rules.clone())
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

    // ── Firewall ──────────────────────────────────────────

    #[tokio::test]
    async fn export_firewall_options_drops_digest() {
        let mut fake = FakeStateView::default();
        fake.fw_options = FirewallOptions {
            enable: true,
            policy_in: "DROP".into(),
            policy_out: "ACCEPT".into(),
            ebtables: true,
            log_ratelimit: "enable=1".into(),
            digest: "abc123".into(),
        };
        let o = export_firewall_options(&fake).await.expect("export");
        assert!(o.enable && o.ebtables);
        assert_eq!(o.policy_in, "DROP");
        let toml_str = toml::to_string(&o).expect("serialize");
        assert!(!toml_str.contains("digest") && !toml_str.contains("abc123"));
    }

    #[tokio::test]
    async fn export_firewall_aliases_sorts_and_drops_derived_fields() {
        let mut fake = FakeStateView::default();
        fake.fw_aliases = vec![
            FirewallAlias {
                name: "z-net".into(),
                cidr: "10.0.0.0/8".into(),
                ipversion: 4,
                digest: "d1".into(),
                ..Default::default()
            },
            FirewallAlias {
                name: "a-net".into(),
                cidr: "192.168.0.0/16".into(),
                ipversion: 4,
                digest: "d2".into(),
                ..Default::default()
            },
        ];
        let out = export_firewall_aliases(&fake).await.expect("export");
        let names: Vec<&str> = out.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["a-net", "z-net"]);
        let toml_str = toml::to_string(&out[0]).expect("serialize");
        assert!(!toml_str.contains("ipversion"), "derived ipversion dropped");
        assert!(!toml_str.contains("digest"));
    }

    #[tokio::test]
    async fn export_firewall_ipsets_sorts_sets_and_cidrs() {
        let mut fake = FakeStateView::default();
        fake.fw_ipsets = vec![
            FirewallIpset {
                name: "z-set".into(),
                comment: "z".into(),
                digest: "d".into(),
            },
            FirewallIpset {
                name: "a-set".into(),
                comment: "a".into(),
                digest: "d".into(),
            },
        ];
        fake.fw_ipset_cidrs.insert(
            "a-set".into(),
            vec![
                FirewallIpsetCidr {
                    cidr: "9.9.9.0/24".into(),
                    ..Default::default()
                },
                FirewallIpsetCidr {
                    cidr: "1.1.1.0/24".into(),
                    ..Default::default()
                },
            ],
        );
        let out = export_firewall_ipsets(&fake).await.expect("export");
        let names: Vec<&str> = out.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["a-set", "z-set"], "sets sorted by name");
        let cidrs: Vec<&str> = out[0].cidrs.iter().map(|c| c.cidr.as_str()).collect();
        assert_eq!(cidrs, vec!["1.1.1.0/24", "9.9.9.0/24"], "cidrs sorted");
    }

    #[tokio::test]
    async fn export_firewall_groups_sorts_by_group() {
        let mut fake = FakeStateView::default();
        fake.fw_groups = vec![
            FirewallSecurityGroup {
                group: "web".into(),
                comment: String::new(),
                digest: "d".into(),
            },
            FirewallSecurityGroup {
                group: "db".into(),
                comment: String::new(),
                digest: "d".into(),
            },
        ];
        let out = export_firewall_groups(&fake).await.expect("export");
        let names: Vec<&str> = out.iter().map(|g| g.group.as_str()).collect();
        assert_eq!(names, vec!["db", "web"]);
    }

    #[tokio::test]
    async fn export_state_firewall_cluster_populates_all_four() {
        let mut fake = FakeStateView::default();
        fake.fw_options = FirewallOptions {
            enable: true,
            ..Default::default()
        };
        fake.fw_aliases = vec![FirewallAlias {
            name: "a".into(),
            cidr: "1.2.3.0/24".into(),
            ..Default::default()
        }];
        fake.fw_ipsets = vec![FirewallIpset {
            name: "s".into(),
            ..Default::default()
        }];
        fake.fw_groups = vec![FirewallSecurityGroup {
            group: "g".into(),
            ..Default::default()
        }];
        let s = export_state(&fake, &[Resource::FirewallCluster], "p")
            .await
            .expect("export");
        assert!(s.firewall_options.is_some());
        assert_eq!(s.firewall_aliases.len(), 1);
        assert_eq!(s.firewall_ipsets.len(), 1);
        assert_eq!(s.firewall_groups.len(), 1);
    }

    // ── Notification matchers ─────────────────────────────

    #[tokio::test]
    async fn export_notification_matchers_sorts_and_canonicalises() {
        // Matchers sorted by name; the list fields sorted within each;
        // `origin` dropped.
        let mut fake = FakeStateView::default();
        fake.notif_matchers = vec![
            NotificationMatcher {
                name: "z-oncall".into(),
                target: vec!["gotify".into(), "email".into()],
                match_severity: vec!["warning".into(), "error".into()],
                origin: "user-created".into(),
                ..Default::default()
            },
            NotificationMatcher {
                name: "a-default".into(),
                origin: "builtin".into(),
                ..Default::default()
            },
        ];
        let out = export_notification_matchers(&fake).await.expect("export");
        let names: Vec<&str> = out.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, vec!["a-default", "z-oncall"], "matchers sorted");
        // z-oncall's list fields canonicalised (sorted).
        let z = &out[1];
        assert_eq!(z.target, vec!["email", "gotify"]);
        assert_eq!(z.match_severity, vec!["error", "warning"]);
        // origin is not a Decl field; serialised TOML must not carry it.
        let toml_str = toml::to_string(&out[0]).expect("serialize");
        assert!(
            !toml_str.contains("origin"),
            "origin dropped, got:\n{toml_str}"
        );
    }
}
