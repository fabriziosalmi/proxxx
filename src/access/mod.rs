//! Access control inspector (feature #10).
//!
//! Per the architectural review, the **effective permission debugger
//! does NOT re-implement `pve-access-control`**. Instead we shell out
//! to `pveum user permissions --output-format json -- <userid>` via the
//! SSH layer. The Perl code on the node is the authority — proxxx wraps
//! and parses the JSON output into a deterministic structure.

pub mod pveum;

pub use pveum::{parse_user_permissions, EffectivePermissions, PathPerms};
