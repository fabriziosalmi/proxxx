//! Cluster state export + reconcile.
//!
//! This module is the foundation for `proxxx state {export,diff,apply}`
//! — the path toward declaratively-versioned Proxmox clusters tracked
//! in epic [#74](https://github.com/fabriziosalmi/proxxx/issues/74).
//!
//! v1 (this PR) ships **export only**, **pools only**. Subsequent PRs
//! add ACL, storage definitions, cluster firewall, backup jobs,
//! notifications, then the diff + apply layers.
//!
//! ## Layered design
//!
//! * [`model`] — serde structs per resource family, plus the top-level
//!   [`ClusterState`](model::ClusterState). Strict TOML / JSON
//!   serialisation; identity by PVE-side key (`poolid`, `(path,type,
//!   ugid,roleid)`, `storage`, …). All collections sorted on export so
//!   the output is diff-stable byte-for-byte across runs.
//! * [`export`] — read live state through `api::ProxmoxGateway`. Pure
//!   read; no mutation. Mockable for unit tests.
//! * `diff` (future) — structural diff between two
//!   `ClusterState` values; produces `Vec<Change>` (Create / Update /
//!   Delete).
//! * `apply` (future) — execute each `Change` via the api client;
//!   pre-flight gate + audit log per change; HITL on destructive ops.
//!
//! ## Why a separate module
//!
//! The reducer in `app/` is the read/render side of the Elm-style
//! state machine; that lives in-memory only and is recomputed every
//! frame from the latest API responses. `state/` is the disk-side
//! schema: declarative, versionable, externalised. They don't share
//! types because their concerns differ (reducer cares about render
//! ergonomics — sparkline buffers, selection cursors — `state/`
//! cares about wire-stable identity and TOML readability).

pub mod export;
pub mod model;
