// Library root — exposes modules for integration tests
// The binary entry point is main.rs

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
pub mod handoff;
pub mod hitl;
pub mod mcp;
pub mod metrics;
pub mod pbs;
pub mod ssh;
pub mod state;
pub mod tui;
pub mod util;
pub mod wsterm;
