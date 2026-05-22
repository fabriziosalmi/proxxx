//! Cluster state export + reconcile.
//!
//! This module is the foundation for `proxxx state {export,diff,apply}`
//! — the path toward declaratively-versioned Proxmox clusters tracked
//! in epic [#74](https://github.com/fabriziosalmi/proxxx/issues/74).
//!
//! Today this module covers **pools, ACL grants, storage definitions,
//! scheduled backup jobs, the cluster firewall (options + aliases + IP
//! sets + security groups), and notification matchers** across the full
//! export → diff → apply loop. HA groups are the one remaining family
//! from the epic, deferred while PVE 9's node-affinity `/cluster/ha/rules`
//! lacks a write gateway. Pre-flight risk gates + HITL approval per
//! destructive apply change (shipped v0.3.0) wrap the dispatch layer in
//! [`preflight`] without changing it.
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
//! * [`diff`] — structural diff between two `ClusterState` values;
//!   produces a `Vec<Change>` (Create / Update / Delete) ordered as
//!   Delete → Update → Create per family. Pure function; no I/O.
//! * [`apply`] — execute each `Change` via a narrow write-side trait
//!   ([`apply::StateWriteView`]) with blanket impl over
//!   `ProxmoxGateway`. Returns one [`apply::ApplyOutcome`] per change
//!   so callers can render or audit. Dry-run / prune / continue-on-
//!   error semantics live here.
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

pub mod apply;
pub mod diff;
pub mod export;
pub mod model;
pub mod preflight;
