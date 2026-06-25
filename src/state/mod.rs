//! Cluster state export + reconcile.
//!
//! This module is the foundation for `proxxx state {export,diff,apply}`
//! — the path toward declaratively-versioned Proxmox clusters tracked
//! in epic [#74](https://github.com/fabriziosalmi/proxxx/issues/74).
//!
//! Today this module covers **pools, ACL grants, storage definitions,
//! scheduled backup jobs, the cluster firewall (options + aliases + IP
//! sets + security groups), notification matchers, HA rules
//! (node-affinity + resource-affinity), and HA resources (which guests
//! are HA-managed + their per-resource CRM knobs)** across the full
//! export → diff → apply loop. **Epic #74 is now at 7/6 writable
//! families** — HA resources is the epilogue family that makes the
//! `GitOps` loop fully self-contained (declaring a rule no longer
//! requires the operator to register its referenced SIDs via raw curl
//! out-of-band). The `HaResources` family is intentionally ordered
//! BEFORE `HaRules` in [`export::Resource::all`] so creates flow
//! resources-then-rules; deletes ride on PVE's `purge=1` default
//! (resource-delete auto-purges referencing rules) with idempotent
//! 404-tolerance in the rule-delete apply path. (Legacy PVE-8
//! `/cluster/ha/groups` is intentionally not modelled — PVE 9 migrated
//! it to `/cluster/ha/rules`, and proxxx targets PVE 9.x.) Pre-flight
//! risk gates + HITL approval per destructive apply change (shipped
//! v0.3.0) wrap the dispatch layer in [`preflight`] without changing it.
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
pub mod converge;
pub mod diff;
pub mod export;
pub mod model;
pub mod preflight;

/// Shared `#[cfg(test)]` helpers (e.g. the `RecordingClient` mock) used by
/// multiple `state` submodules' tests.
#[cfg(test)]
pub(crate) mod test_support;
