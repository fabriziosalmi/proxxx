//! Access control inspector (feature #10).
//!
//! Per the architectural review, the **effective permission debugger
//! does NOT re-implement `pve-access-control`**. Instead we shell out
//! to `pveum user permissions` via the SSH layer. The Perl
//! code on the node is the authority — proxxx wraps + parses, never
//! tries to be smarter.
//!
//! That's the whole reason this is `pub` and tested independently of
//! the API client: it's the highest-stakes flow in the feature, and
//! the parser must round-trip cleanly against `pveum`'s output formats
//! across PVE 7+ and 8+.

pub mod pveum;

pub use pveum::{parse_user_permissions, EffectivePermissions, PathPerms};
