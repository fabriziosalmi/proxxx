//! Proxmox Backup Server integration (feature #3).
//!
//! Two pieces, intentionally separate:
//! - `client`: REST browse (token auth, list datastores/snapshots/files).
//!   Pure HTTP, works on every platform proxxx runs on.
//! - `restore`: shell-out to `proxmox-backup-client` for actually
//!   pulling data. Linux-only in practice (the client binary isn't
//!   packaged for macOS / Windows upstream).
//!
//! Declared cuts: no FUSE mount, no single-file extraction (full
//! archive only), no agent re-injection.

pub mod client;
pub mod restore;
pub mod types;

pub use client::{PbsClient, PbsGateway};
pub use restore::{detect_client_binary, run_restore, RestoreRequest, RestoreResult};
pub use types::{ArchiveInfo, DatastoreInfo, SnapshotInfo};
