use serde::{Deserialize, Serialize};

use super::deserialize_bool_from_int;

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StoragePool {
    pub storage: String,
    #[serde(rename = "type")]
    pub storage_type: String,
    pub used: u64,
    pub avail: u64,
    pub total: u64,
    #[serde(deserialize_with = "deserialize_bool_from_int")]
    pub active: bool,
    pub content: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageDefinition {
    /// Storage id (the operator-chosen name).
    pub storage: String,
    /// Storage type: `dir` | `lvm` | `lvmthin` | `zfspool` | `nfs` |
    /// `cifs` | `iscsi` | `glusterfs` | `cephfs` | `rbd` | `pbs` |
    /// `btrfs` | `esxi`.
    #[serde(rename = "type")]
    pub storage_type: String,
    /// CSV of allowed content kinds, e.g.
    /// `"vztmpl,iso,backup,images,rootdir,snippets"`.
    pub content: String,
    /// CSV of nodes this storage is restricted to. Empty = all nodes.
    pub nodes: String,
    /// 1 = config kept but storage is inactive.
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub disable: bool,
    /// 1 = visible to every node (e.g. NFS, PBS, `CephFS`).
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub shared: bool,
    pub digest: String,
    // ── Type-specific subset (most-common fields) ──
    /// `dir` / `btrfs`: filesystem path. Empty for non-fs types.
    pub path: String,
    /// `zfspool` / `rbd`: ZFS dataset / Ceph pool name.
    pub pool: String,
    /// `nfs` / `cifs` / `pbs` / `iscsi`: server hostname/IP.
    pub server: String,
    /// `nfs`: export path on the server.
    pub export: String,
    /// `pbs`: PBS datastore name.
    pub datastore: String,
    /// `pbs` / `cifs`: TLS fingerprint for verification.
    pub fingerprint: String,
    /// `cifs` / `pbs`: auth username (PBS uses `user@realm!tokenname`).
    pub username: String,
    /// `lvm` / `lvmthin`: volume group name.
    pub vgname: String,
    /// `lvmthin`: thin pool name within `vgname`.
    pub thinpool: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageContent {
    /// Volume identifier, e.g. `"local:iso/debian-12.iso"`.
    pub volid: String,
    /// Content type: `"iso"`, `"vztmpl"`, `"backup"`, `"images"`, `"import"`.
    #[serde(default)]
    pub content: String,
    /// Size in bytes.
    #[serde(default)]
    pub size: u64,
    /// File format for image entries (`"qcow2"`, `"raw"`, etc.); empty
    /// for ISOs.
    #[serde(default)]
    pub format: String,
    /// Owning guest VMID (populated for `backup` and `images` entries
    /// — empty for ISOs and templates which don't belong to a guest).
    /// Used by the pre-flight backup-recency check to find the most
    /// recent backup for a given VMID.
    #[serde(default)]
    pub vmid: Option<u32>,
    /// Creation time in Unix epoch seconds (populated for `backup`
    /// entries — PVE writes the vzdump timestamp here). Used by
    /// pre-flight backup-recency to compute "hours since last
    /// backup".
    #[serde(default)]
    pub ctime: u64,
    /// Backup subtype: `"qemu"` or `"lxc"` (only set for `content == "backup"`).
    #[serde(default)]
    pub subtype: String,
}

impl StorageContent {
    /// Last URL path component or filename — useful for matching against
    /// what proxxx is about to download.
    #[must_use]
    pub fn filename(&self) -> &str {
        self.volid.rsplit('/').next().unwrap_or(&self.volid)
    }
}
