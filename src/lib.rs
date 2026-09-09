//! proxxx as a library.
//!
//! # Compatibility (audit 2026-09-09, #284)
//!
//! This crate is consumed by the proxxx binary, by the integration tests
//! and — since v0.9.2 — by the **proxima** desktop UI, which links it
//! directly. The per-surface `SemVer` contract at the top of `CHANGELOG.md`
//! enumerated the CLI, exit codes, `--format json`, the config schema
//! and the MCP registry, and said nothing about this one; the header
//! here still described the crate as existing "for integration tests"
//! long after that stopped being the whole truth.
//!
//! The supported surface is:
//!
//! * [`api`] — `ProxmoxGateway`, `PxClient`, `ApiError` and the types in
//!   `api::types`. Additive within a minor; signature changes are major.
//! * [`config`] — `ProfileConfig` and its nested structs.
//! * [`app::preflight`] — the risk gate, so a consumer can run the same
//!   assessment before mutating.
//! * [`state::model`] — the declarative schema, versioned by
//!   `StateMeta::schema_version`.
//!
//! Everything else is an implementation detail and may change in any
//! release, including `tui`, `cli`, `state::test_support`, and the
//! internals of `app` outside `preflight`. If you depend on one of those,
//! open an issue and say why — it is easier to widen the contract than
//! to guess who is relying on what.
//
// The binary entry point is main.rs.

// Production code obeys the strict deny lints in Cargo.toml.
// Tests use `unwrap`/`expect`/`panic`/indexing for assertion ergonomics
// — relax those exclusively in `cfg(test)` so `cargo clippy --all-targets`
// stays clean without weakening the production surface.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
    )
)]

pub mod access;
pub mod alerts;
pub mod api;
pub mod app;
pub mod audit;
pub mod cli;
pub mod config;
pub mod console_record;
pub mod handoff;
pub mod hitl;
pub mod incident;
pub mod mcp;
pub mod metrics;
pub mod pbs;
pub mod ssh;
pub mod state;
pub mod tui;
pub mod util;
pub mod wsterm;
