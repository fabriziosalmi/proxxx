//! Serde model for cluster state — the on-disk schema of the
//! declaratively-managed slice of a Proxmox cluster.
//!
//! Each resource family is a separate `*Decl` struct. The top-level
//! [`ClusterState`] is a forest of those: a partial state (e.g. only
//! `[[pools]]`) is a valid file, since every field defaults to empty.
//! This lets operators export only what they care about and merge
//! cross-PR without conflict.
//!
//! Identity rules:
//! * Pools — keyed by `poolid`.
//! * Members of a pool — encoded as stable strings (`qemu/100`,
//!   `lxc/200`, `storage/<name>`) so a member set is a `Vec<String>`
//!   directly serialisable as a TOML array.
//!
//! Future resource families (ACL, storage, firewall, backup jobs,
//! notifications) will follow the same shape: a `*Decl` struct with
//! the PVE-side identifier as the first field, a `default` impl so
//! empty fields don't bloat the TOML, and a stable serialise order
//! enforced at the export layer.

use serde::{Deserialize, Serialize};

/// Top-level cluster state — the union of every declared resource.
///
/// Every field is optional (defaults to empty / `None`) so partial
/// exports are valid documents. `meta` is emitted on export but
/// optional on import; a hand-written declared state can omit it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ClusterState {
    /// Provenance: where this state came from and when. Skipped on
    /// serialisation when absent so hand-authored declared states
    /// don't need it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<StateMeta>,

    /// Pools — `GET /pools` + `GET /pools/{poolid}` for membership.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pools: Vec<PoolDecl>,

    /// ACL entries — `GET /access/acl`. Identity is the 4-tuple
    /// `(path, kind, ugid, roleid)`; PVE's response is flat, one row
    /// per (subject, role, path) combination. `propagate` is part of
    /// the value, not the identity (toggling it is an update).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub acl: Vec<AclDecl>,

    /// Cluster-wide storage definitions — `GET /storage`. Identity
    /// is the `storage` field (operator-chosen storage id). Type-
    /// specific fields (path, pool, server, export, datastore, …)
    /// are emitted only when present, so a `dir` storage doesn't
    /// pollute the TOML with empty `server=""`/`pool=""` lines.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub storage: Vec<StorageDecl>,
}

/// Metadata header emitted by the export layer. Captures *which*
/// cluster the state was read from, *when*, and *with what proxxx
/// version*. Useful for audit trail and forensic comparison; ignored
/// by the apply layer (apply consults live state, not metadata).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StateMeta {
    /// proxxx profile name the state was exported from.
    pub profile: String,
    /// RFC 3339 timestamp at export.
    pub exported_at: String,
    /// proxxx version that produced the export (from `CARGO_PKG_VERSION`).
    pub exported_from_proxxx: String,
    /// PVE API version reported by `GET /version` (e.g. `"9.1.9"`).
    pub pve_version: String,
}

/// One pool declaration — poolid + comment + members.
///
/// Members are emitted as `kind/id` strings (`qemu/<vmid>`,
/// `lxc/<vmid>`, `storage/<name>`) so the TOML is diff-readable: the
/// PVE API returns a richer object per member, but only the kind + id
/// is identity-bearing — every other field is recomputable.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PoolDecl {
    pub poolid: String,
    /// Free-form description. Empty by default; suppressed in the
    /// serialised TOML when empty so the file stays terse.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub comment: String,
    /// Sorted, deduplicated list of member references. Serialised as
    /// a TOML array of strings.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
}

/// One ACL grant — the 4-tuple `(path, kind, ugid, roleid)` is the
/// identity, plus the `propagate` bit as a value field.
///
/// PVE's `GET /access/acl` returns one row per (subject, role, path)
/// combination — a single user can hold N roles on M paths and each
/// shows up as a separate entry. We mirror that 1:1: the on-disk
/// state is a flat array of `AclDecl`, identity-keyed at apply time.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AclDecl {
    /// ACL path — e.g. `/`, `/vms/100`, `/pool/team-platform`,
    /// `/storage/ceph-rbd`.
    pub path: String,
    /// `"user"` | `"group"` | `"token"`. PVE's discriminator
    /// between the three subject kinds; matters because the same
    /// `ugid` string could in principle conflict across kinds (it
    /// doesn't in practice, but PVE's API requires the explicit
    /// type on every mutation).
    pub kind: String,
    /// Subject identifier. For `user`: `<user>@<realm>` (e.g.
    /// `alice@pve`, `root@pam`). For `group`: just the group name.
    /// For `token`: `<userid>!<tokenid>`.
    pub ugid: String,
    /// PVE role id — e.g. `Administrator`, `PVEAuditor`,
    /// `PVEVMAdmin`, `PVEPoolUser`, or any custom role created with
    /// `proxxx access user-create` / `pveum role add`.
    pub roleid: String,
    /// Whether the grant propagates to child paths. PVE's API
    /// default is `true`; mirroring that here so a hand-written TOML
    /// without an explicit `propagate` line behaves the same as one
    /// with `propagate = true`. To pin "this role applies ONLY to
    /// the path itself, not children", set `propagate = false`
    /// explicitly.
    #[serde(default = "default_true")]
    pub propagate: bool,
}

const fn default_true() -> bool {
    true
}

/// Serde `skip_serializing_if` helper. The signature is fixed by serde
/// (`fn(&T) -> bool`), so we must take `&bool` here even though clippy
/// would prefer `bool` by value — passing by reference is the contract.
#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(b: &bool) -> bool {
    !*b
}

/// One cluster-wide storage definition — `GET /storage`. The
/// `storage` field is the identity; everything else is value.
///
/// Type-specific fields (path / pool / server / export / datastore /
/// fingerprint / username / vgname / thinpool) are all `#[serde(
/// skip_serializing_if = "String::is_empty")]` so a `dir` storage's
/// TOML doesn't carry empty `server=""`/`pool=""` lines. PVE's API
/// returns the full union shape; we mirror that on disk but emit
/// only the populated subset.
///
/// Deliberately NOT exported:
/// * `digest` — PVE's stale-check identifier, not desired state.
///   Including it would make the TOML churn on every API call even
///   when nothing's changed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageDecl {
    /// Storage id (operator-chosen name, unique across the cluster).
    pub storage: String,
    /// Storage type: `dir` | `lvm` | `lvmthin` | `zfspool` | `nfs` |
    /// `cifs` | `iscsi` | `glusterfs` | `cephfs` | `rbd` | `pbs` |
    /// `btrfs` | `esxi`.
    #[serde(rename = "type")]
    pub storage_type: String,
    /// CSV of allowed content kinds, e.g.
    /// `"vztmpl,iso,backup,images,rootdir,snippets"`. PVE accepts
    /// CSV on input and emits CSV on output; we keep it as a string
    /// rather than parsing into an array, since the order PVE
    /// preserves on read-back is not stable.
    pub content: String,
    /// CSV of nodes this storage is restricted to. Empty = all
    /// nodes (the default).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub nodes: String,
    /// `true` = config kept but storage is administratively disabled.
    #[serde(skip_serializing_if = "is_false")]
    pub disable: bool,
    /// `true` = visible to every node (NFS, PBS, `CephFS`, …). Local
    /// storages (`dir`, `lvm`, `zfspool` against a node-local pool)
    /// have this `false`.
    #[serde(skip_serializing_if = "is_false")]
    pub shared: bool,
    // ── Type-specific subset (skip when empty) ──
    /// `dir` / `btrfs`: filesystem path on the host.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// `zfspool` / `rbd`: ZFS dataset / Ceph pool name.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pool: String,
    /// `nfs` / `cifs` / `pbs` / `iscsi`: server hostname / IP.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub server: String,
    /// `nfs`: export path on the server.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub export: String,
    /// `pbs`: PBS datastore name.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub datastore: String,
    /// `pbs` / `cifs`: TLS fingerprint for verification (SHA-256
    /// over the leaf cert).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub fingerprint: String,
    /// `cifs` / `pbs`: auth username. For PBS, this is
    /// `user@realm!tokenname`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub username: String,
    /// `lvm` / `lvmthin`: volume group name.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub vgname: String,
    /// `lvmthin`: thin pool name within `vgname`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub thinpool: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_cluster_state_serializes_to_empty_toml() {
        // Default ClusterState has no meta, no pools — every field is
        // `skip_serializing_if` empty, so the resulting TOML is the
        // empty string. Pinning this so an "all fields empty" export
        // produces a stable, smallest possible file (useful for diffs
        // against a freshly-provisioned cluster).
        let s = ClusterState::default();
        let toml_str = toml::to_string(&s).expect("serialize empty state");
        assert!(toml_str.is_empty(), "expected empty, got {toml_str:?}");
    }

    #[test]
    fn pool_decl_with_only_id_omits_comment_and_members() {
        let p = PoolDecl {
            poolid: "team-platform".to_string(),
            comment: String::new(),
            members: Vec::new(),
        };
        let s = ClusterState {
            meta: None,
            pools: vec![p],
            acl: vec![],
            storage: vec![],
        };
        let toml_str = toml::to_string(&s).expect("serialize");
        // No "comment = " line, no "members = " line — only poolid.
        assert!(toml_str.contains("poolid = \"team-platform\""));
        assert!(!toml_str.contains("comment"));
        assert!(!toml_str.contains("members"));
    }

    #[test]
    fn pool_decl_with_members_emits_sorted_array() {
        let p = PoolDecl {
            poolid: "team-platform".to_string(),
            comment: "platform engineering".to_string(),
            members: vec![
                "qemu/100".to_string(),
                "qemu/101".to_string(),
                "storage/ceph-rbd".to_string(),
            ],
        };
        let toml_str = toml::to_string(&p).expect("serialize");
        assert!(toml_str.contains("poolid = \"team-platform\""));
        assert!(toml_str.contains("comment = \"platform engineering\""));
        assert!(toml_str.contains("\"qemu/100\""));
        assert!(toml_str.contains("\"storage/ceph-rbd\""));
    }

    #[test]
    fn round_trip_preserves_pool_membership() {
        // Build a state, serialize, deserialize, compare. Pins the
        // serde contract: every field that round-trips through TOML
        // survives unchanged. Catches accidental case-sensitivity
        // issues, missing #[serde(default)], etc.
        let s = ClusterState {
            meta: Some(StateMeta {
                profile: "prod".into(),
                exported_at: "2026-05-19T22:00:00Z".into(),
                exported_from_proxxx: "0.2.1".into(),
                pve_version: "9.1.9".into(),
            }),
            acl: vec![],
            storage: vec![],
            pools: vec![
                PoolDecl {
                    poolid: "p1".into(),
                    comment: "first".into(),
                    members: vec!["qemu/100".into(), "lxc/200".into()],
                },
                PoolDecl {
                    poolid: "p2".into(),
                    comment: String::new(),
                    members: vec![],
                },
            ],
        };
        let toml_str = toml::to_string(&s).expect("serialize");
        let parsed: ClusterState = toml::from_str(&toml_str).expect("deserialize");
        assert_eq!(s, parsed);
    }

    #[test]
    fn acl_decl_defaults_to_propagate_true() {
        // PVE's API default for `propagate` is true; a hand-written
        // TOML without an explicit `propagate` line should behave
        // identically. Pins this so a future schema change can't
        // silently flip the default.
        let toml_str = r#"
[[acl]]
path = "/vms/100"
kind = "user"
ugid = "alice@pve"
roleid = "PVEVMAdmin"
"#;
        let s: ClusterState = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(s.acl.len(), 1);
        assert!(s.acl[0].propagate, "default should be true");
    }

    #[test]
    fn acl_decl_round_trip_preserves_all_fields() {
        let entry = AclDecl {
            path: "/pool/team-platform".into(),
            kind: "group".into(),
            ugid: "platform-engineers".into(),
            roleid: "PVEPoolUser".into(),
            propagate: false,
        };
        let s = ClusterState {
            meta: None,
            pools: vec![],
            acl: vec![entry.clone()],
            storage: vec![],
        };
        let toml_str = toml::to_string(&s).expect("serialize");
        let parsed: ClusterState = toml::from_str(&toml_str).expect("deserialize");
        assert_eq!(s, parsed);
        assert_eq!(parsed.acl[0], entry);
    }

    #[test]
    fn acl_explicit_propagate_false_is_preserved() {
        // The non-default value — propagate=false — must survive
        // the round trip. Pins that we don't accidentally collapse
        // it to the default.
        let toml_str = r#"
[[acl]]
path = "/storage/local"
kind = "user"
ugid = "ops@pve"
roleid = "PVEDatastoreUser"
propagate = false
"#;
        let s: ClusterState = toml::from_str(toml_str).expect("deserialize");
        assert_eq!(s.acl.len(), 1);
        assert!(!s.acl[0].propagate);
    }

    #[test]
    fn storage_decl_omits_type_specific_empty_fields() {
        // A `dir` storage doesn't have a `server`, `pool`, `datastore`,
        // etc. — its `StorageDecl` must serialise to TOML without any
        // of those empty fields appearing. Pins the
        // `skip_serializing_if = "String::is_empty"` discipline so a
        // future "add a default" regression doesn't pollute the
        // diff.
        let s = StorageDecl {
            storage: "local".into(),
            storage_type: "dir".into(),
            content: "iso,backup".into(),
            path: "/var/lib/vz".into(),
            ..Default::default()
        };
        let toml_str = toml::to_string(&s).expect("serialize");
        assert!(toml_str.contains("storage = \"local\""));
        assert!(toml_str.contains("type = \"dir\""));
        assert!(toml_str.contains("path = \"/var/lib/vz\""));
        // None of the type-specific empties survive.
        for k in &[
            "server",
            "pool",
            "export",
            "datastore",
            "fingerprint",
            "username",
            "vgname",
            "thinpool",
        ] {
            assert!(
                !toml_str.contains(&format!("{k} =")),
                "field '{k}' should be omitted (empty), got:\n{toml_str}"
            );
        }
        // Defaulted bools (disable/shared) should also be omitted.
        assert!(!toml_str.contains("disable"));
        assert!(!toml_str.contains("shared"));
    }

    #[test]
    fn storage_decl_emits_type_specific_fields_when_present() {
        // A `pbs` storage has server + datastore + fingerprint +
        // username; all four must survive serialisation. A `nfs`
        // storage has server + export; pbs-only fields must NOT
        // appear on it.
        let pbs = StorageDecl {
            storage: "backup-fra1".into(),
            storage_type: "pbs".into(),
            content: "backup".into(),
            server: "pbs.example.com".into(),
            datastore: "default".into(),
            fingerprint: "AA:BB:CC".into(),
            username: "backup@pbs!proxxx".into(),
            shared: true,
            ..Default::default()
        };
        let toml_str = toml::to_string(&pbs).expect("serialize");
        assert!(toml_str.contains("server = \"pbs.example.com\""));
        assert!(toml_str.contains("datastore = \"default\""));
        assert!(toml_str.contains("fingerprint"));
        assert!(toml_str.contains("username"));
        assert!(toml_str.contains("shared = true"));
        // No `pool`, `export`, `path` (those are for other types).
        assert!(!toml_str.contains("pool"));
        assert!(!toml_str.contains("export"));
        assert!(!toml_str.contains("path"));
    }

    #[test]
    fn storage_decl_round_trip_preserves_all_fields() {
        let entries = vec![
            StorageDecl {
                storage: "local".into(),
                storage_type: "dir".into(),
                content: "iso,backup,vztmpl".into(),
                path: "/var/lib/vz".into(),
                disable: false,
                shared: false,
                ..Default::default()
            },
            StorageDecl {
                storage: "ceph-rbd".into(),
                storage_type: "rbd".into(),
                content: "images,rootdir".into(),
                pool: "rbd".into(),
                shared: true,
                ..Default::default()
            },
            StorageDecl {
                storage: "shared-nfs".into(),
                storage_type: "nfs".into(),
                content: "backup".into(),
                server: "10.0.0.5".into(),
                export: "/exports/proxmox-backup".into(),
                shared: true,
                ..Default::default()
            },
        ];
        let s = ClusterState {
            meta: None,
            pools: vec![],
            acl: vec![],
            storage: entries.clone(),
        };
        let toml_str = toml::to_string(&s).expect("serialize");
        let parsed: ClusterState = toml::from_str(&toml_str).expect("deserialize");
        assert_eq!(parsed.storage, entries);
    }

    #[test]
    fn partial_state_with_only_pools_deserializes() {
        // Operators hand-authoring a declared state should not need
        // a `[meta]` header. Pins the "partial document is valid"
        // contract.
        let toml_str = r#"
[[pools]]
poolid = "team-platform"
comment = "engineering"
members = ["qemu/100", "storage/ceph-rbd"]
"#;
        let s: ClusterState = toml::from_str(toml_str).expect("deserialize");
        assert!(s.meta.is_none());
        assert_eq!(s.pools.len(), 1);
        assert_eq!(s.pools[0].poolid, "team-platform");
        assert_eq!(s.pools[0].members.len(), 2);
    }
}
