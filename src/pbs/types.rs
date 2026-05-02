//! Proxmox Backup Server REST types (feature #3).
//!
//! These mirror the relevant fields of the PBS API documented at
//! `https://pbs.proxmox.com/docs/api-viewer/`. We only model what the
//! browse + restore flows need; PBS returns many more fields per call
//! that we ignore via `#[serde(default)]` or by simply not declaring.

use serde::{Deserialize, Serialize};

/// One datastore on the PBS server. Matches `GET /admin/datastore`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatastoreInfo {
    pub store: String,
    #[serde(default)]
    pub comment: String,
}

/// One snapshot on a datastore. Matches `GET /admin/datastore/{store}/snapshots`.
///
/// `backup-time` is a Unix timestamp; combined with `backup-type` and
/// `backup-id` it forms a snapshot reference (e.g. `vm/100/2024-01-15T10:00:00Z`)
/// that the `proxmox-backup-client` binary accepts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotInfo {
    #[serde(rename = "backup-type")]
    pub backup_type: String,
    #[serde(rename = "backup-id")]
    pub backup_id: String,
    #[serde(rename = "backup-time", default)]
    pub backup_time: u64,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub owner: String,
    #[serde(default)]
    pub comment: String,
    /// PBS reports `protected: true/false`. Protected snapshots can't be
    /// pruned automatically — useful flag for the UI.
    #[serde(default)]
    pub protected: bool,
    /// Per-archive metadata when the API returns it expanded.
    #[serde(default)]
    pub files: Vec<ArchiveInfo>,
}

impl SnapshotInfo {
    /// Render the snapshot reference in the canonical form the
    /// `proxmox-backup-client` binary uses on its CLI:
    /// `<type>/<id>/<RFC3339-timestamp>`.
    #[must_use]
    pub fn snapshot_ref(&self) -> String {
        let ts = format_pbs_timestamp(self.backup_time);
        format!("{}/{}/{ts}", self.backup_type, self.backup_id)
    }
}

/// One file within a snapshot. PBS uses extensions to convey kind:
/// - `.pxar.didx` — directory archive (host filesystem dump)
/// - `.img.fidx` — fixed-size disk image (VM disks)
/// - `.blob` — small inline blob (e.g. config files)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveInfo {
    pub filename: String,
    #[serde(default)]
    pub size: u64,
    /// One of: `none`, `encrypt`, `sign-only` (PBS speak for whether
    /// the chunks are crypto-protected).
    #[serde(rename = "crypt-mode", default)]
    pub crypt_mode: String,
}

impl ArchiveInfo {
    /// True if this archive is encrypted at the chunk level. Restoring
    /// it requires the master key — surface in UI to set expectations.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.crypt_mode == "encrypt"
    }

    /// True for pxar (directory) archives. Useful for "browse files"
    /// affordances in the future — img.fidx archives need block-level
    /// tooling that isn't part of this MVP.
    #[must_use]
    pub fn is_pxar(&self) -> bool {
        self.filename.ends_with(".pxar.didx") || self.filename.ends_with(".pxar")
    }
}

/// Format a Unix timestamp as PBS expects: ISO-8601 UTC, second precision,
/// no fractional seconds. Avoids pulling chrono for one stringification.
#[must_use]
pub fn format_pbs_timestamp(epoch: u64) -> String {
    // PBS canonical form: 2024-01-15T10:00:00Z. We compute manually
    // because chrono would be a heavy dep just for this.
    let days = epoch / 86400;
    let secs_today = epoch % 86400;
    let h = secs_today / 3600;
    let m = (secs_today % 3600) / 60;
    let s = secs_today % 60;
    let (y, mo, d) = epoch_days_to_ymd(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Convert "days since 1970-01-01 UTC" to (year, month, day).
/// Standard civil-from-days algorithm (Hinnant 2012).
fn epoch_days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbs_timestamp_known_values() {
        // 2024-01-15 10:00:00 UTC = 1705_312_800
        assert_eq!(format_pbs_timestamp(1_705_312_800), "2024-01-15T10:00:00Z");
        // Epoch
        assert_eq!(format_pbs_timestamp(0), "1970-01-01T00:00:00Z");
        // 2026-05-01T00:00:00Z
        assert_eq!(format_pbs_timestamp(1_777_593_600), "2026-05-01T00:00:00Z");
    }

    #[test]
    fn snapshot_ref_format_matches_pbs_cli() {
        let s = SnapshotInfo {
            backup_type: "vm".into(),
            backup_id: "100".into(),
            backup_time: 1_705_312_800,
            size: 0,
            owner: String::new(),
            comment: String::new(),
            protected: false,
            files: vec![],
        };
        assert_eq!(s.snapshot_ref(), "vm/100/2024-01-15T10:00:00Z");
    }

    #[test]
    fn archive_kind_classification() {
        let pxar = ArchiveInfo {
            filename: "root.pxar.didx".into(),
            size: 0,
            crypt_mode: "none".into(),
        };
        assert!(pxar.is_pxar());
        assert!(!pxar.is_encrypted());

        let img = ArchiveInfo {
            filename: "drive-scsi0.img.fidx".into(),
            size: 0,
            crypt_mode: "encrypt".into(),
        };
        assert!(!img.is_pxar());
        assert!(img.is_encrypted());
    }
}
