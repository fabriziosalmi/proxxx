//! Cluster state export + reconcile.
//!
//! This module is the foundation for `proxxx state {export,diff,apply}`
//! — the path toward declaratively-versioned Proxmox clusters tracked
//! in epic [#74](https://github.com/fabriziosalmi/proxxx/issues/74).
//!
//! Today this module covers **pools, ACL, and storage definitions**
//! across the full export → diff → apply loop. Cluster firewall,
//! backup jobs, notifications, and HA groups land in follow-up PRs
//! tracked by the epic. Pre-flight risk gates + HITL approval per
//! destructive apply change are tracked separately and will wrap
//! the dispatch layer without changing it.
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
