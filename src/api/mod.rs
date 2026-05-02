// Proxmox API client — trait + types + implementation
// Zero knowledge of TUI. Pure domain layer.

mod auth;
mod client;
pub mod error;
pub mod types;

pub use client::PxClient;
pub use error::ApiError;

use anyhow::Result;
use async_trait::async_trait;
use types::{Guest, Node, StoragePool, TaskLog};

/// The core gateway trait. All Proxmox interactions go through this.
/// Implemented by `PxClient` (production) and `MockGateway` (tests).
#[async_trait]
pub trait ProxmoxGateway: Send + Sync {
    // ── Read Operations ─────────────────────────────────
    async fn get_nodes(&self) -> Result<Vec<Node>>;
    async fn get_guests(&self, node: &str) -> Result<Vec<Guest>>;
    async fn get_guest_status(&self, node: &str, vmid: u32) -> Result<Guest>;
    async fn get_storage_pools(&self, node: &str) -> Result<Vec<StoragePool>>;
    async fn get_task_log(
        &self,
        node: &str,
        upid: &str,
        start: usize,
        limit: usize,
    ) -> Result<TaskLog>;
    async fn get_guest_config(
        &self,
        node: &str,
        vmid: u32,
        guest_type: &crate::api::types::GuestType,
    ) -> Result<std::collections::HashMap<String, String>>;
    async fn get_cluster_tasks(&self) -> Result<Vec<crate::api::types::TaskInfo>>;

    // ── Write Operations (all go through HITL gate) ─────
    //
    // These all take a `GuestType` to dispatch between Proxmox's two
    // disjoint URL hierarchies: `/qemu/{vmid}/...` for VMs and
    // `/lxc/{vmid}/...` for containers. Forgetting the type produces
    // a 500/404 from the API, never silent corruption — but it means
    // the caller must always know the guest's type.
    async fn start_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<String>;
    /// Hard stop. For QEMU, `force=true` adds `forceStop=1` so PVE also
    /// SIGKILLs the qemu process if the soft stop hangs. For LXC the flag
    /// is ignored — the LXC stop endpoint rejects unknown params and stop
    /// is already a hard kill of the container init.
    /// For graceful shutdown (ACPI signal for VMs, init for LXC), use
    /// [`Self::shutdown_guest`] instead.
    async fn stop_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        force: bool,
    ) -> Result<String>;
    /// Graceful shutdown via ACPI/init. Falls back to hard stop after the
    /// guest's own timeout (Proxmox-side, not us).
    async fn shutdown_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<String>;
    async fn restart_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<String>;
    async fn migrate_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        target_node: &str,
    ) -> Result<String>;
    async fn delete_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<String>;
    async fn execute_guest_command(
        &self,
        node: &str,
        vmid: u32,
        guest_type: &crate::api::types::GuestType,
        command: &str,
    ) -> Result<String>;

    // ── Snapshot Operations ─────────────────────────────
    async fn create_snapshot(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        name: &str,
    ) -> Result<String>;
    async fn delete_snapshot(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        name: &str,
    ) -> Result<String>;

    // ── SPICE handoff ticket (feature #1c) ──────────────
    /// Issue a SPICE connection ticket. Returns a flat key/value map
    /// the caller renders into a `.vv` file for virt-viewer.
    /// QEMU-only — LXC has no SPICE display. Caller must check.
    async fn get_spiceproxy(&self, node: &str, vmid: u32)
        -> Result<crate::api::types::SpiceConfig>;

    // ── Termproxy ticket (feature #1b) ──────────────────
    /// Issue a termproxy ticket for the guest's serial console.
    /// Type-aware (qemu vs lxc). The ticket is one-shot — the caller
    /// MUST proceed to the WebSocket immediately.
    async fn get_termproxy(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<crate::api::types::TermproxyTicket>;

    // ── Access control (feature #10) ────────────────────
    //
    // Read-only first; the few mutating ops (token create/revoke, MFA
    // enroll) are gated by `--secure` / HITL policy at dispatch time.

    async fn list_acl(&self) -> Result<Vec<crate::api::types::AclEntry>>;
    async fn list_users(&self) -> Result<Vec<crate::api::types::User>>;
    async fn list_user_tokens(&self, userid: &str) -> Result<Vec<crate::api::types::ApiToken>>;
    async fn list_groups(&self) -> Result<Vec<crate::api::types::Group>>;
    async fn list_roles(&self) -> Result<Vec<crate::api::types::Role>>;
    async fn list_realms(&self) -> Result<Vec<crate::api::types::Realm>>;
    async fn list_tfa(&self, userid: &str) -> Result<Vec<crate::api::types::TfaEntry>>;

    /// Create an API token. Returns the token with the `value` field set
    /// — the only chance to capture the secret. Caller must persist it
    /// IMMEDIATELY because Proxmox can't show it again.
    async fn create_token(
        &self,
        userid: &str,
        tokenid: &str,
        privsep: bool,
        expire: Option<u64>,
        comment: Option<&str>,
    ) -> Result<crate::api::types::ApiToken>;

    /// Revoke an API token. Destructive — gate behind `--secure` /
    /// policy match in the caller.
    async fn revoke_token(&self, userid: &str, tokenid: &str) -> Result<()>;

    // ── Hardware inventory (feature #4) ─────────────────
    /// List PCI devices visible to a node, including IOMMU group ids.
    /// Read-only — `GET /nodes/{node}/hardware/pci`.
    async fn list_pci(&self, node: &str) -> Result<Vec<crate::api::types::PciDevice>>;

    /// List USB devices visible to a node. Read-only —
    /// `GET /nodes/{node}/hardware/usb`.
    async fn list_usb(&self, node: &str) -> Result<Vec<crate::api::types::UsbDevice>>;

    // ── HA + replication console (feature #5) ───────────

    /// List HA groups (configured failover priority sets).
    /// Read-only — `/cluster/ha/groups`.
    async fn list_ha_groups(&self) -> Result<Vec<crate::api::types::HaGroup>>;

    /// List HA resources (VMs/CTs under HA management).
    /// Read-only — `/cluster/ha/resources`.
    async fn list_ha_resources(&self) -> Result<Vec<crate::api::types::HaResource>>;

    /// HA manager runtime status (master, mode, per-node service state).
    /// Read-only — `/cluster/ha/status/manager_status`.
    async fn ha_manager_status(&self) -> Result<crate::api::types::HaManagerStatus>;

    /// Cluster status entries: one per node + one summary entry.
    /// Used for quorum visualisation. Read-only — `/cluster/status`.
    async fn cluster_status(&self) -> Result<Vec<crate::api::types::ClusterStatusEntry>>;

    /// Replication job definitions (cluster-wide). Read-only —
    /// `/cluster/replication`.
    async fn list_replication_jobs(&self) -> Result<Vec<crate::api::types::ReplicationJob>>;

    /// Per-node replication runtime status. Read-only —
    /// `/nodes/{node}/replication`.
    async fn list_replication_status(
        &self,
        node: &str,
    ) -> Result<Vec<crate::api::types::ReplicationStatus>>;

    // ── ISO / cloud-image lifecycle (feature #2) ────────
    //
    // Uses `POST /nodes/{node}/storage/{storage}/download-url` (PVE 7+).
    // Server-side download — Proxmox fetches from the URL directly,
    // verifies our supplied SHA-256, and writes to the storage. We do
    // NOT proxy bytes through proxxx.
    //
    // Listing existing content uses `GET /content` so the UI can show
    // "already on this storage" badges for library entries.

    /// Trigger a server-side download to a Proxmox storage.
    /// Returns a UPID; poll task progress for completion.
    /// `content` selects the Proxmox content category (e.g. `"iso"`,
    /// `"import"`, `"vztmpl"`) and must match the storage's allowed list.
    /// `checksum_algo` + `checksum_hex` are pinned together — both
    /// `Some` (e.g. `("sha256", "abc...")`) or both `None`. Proxmox's
    /// download-url endpoint accepts the algorithm separately so we
    /// pass them through unchanged. BLOCKER 1 schema: was a single
    /// `sha256: Option<&str>`; broadened to support Debian's
    /// SHA-512-only manifest without a downgrade.
    async fn download_to_storage(
        &self,
        node: &str,
        storage: &str,
        url: &str,
        filename: &str,
        checksum_algo: Option<&str>,
        checksum_hex: Option<&str>,
        content: &str,
    ) -> Result<String>;

    /// List items already on a storage, optionally filtered by content
    /// type. Returns volids + size/format metadata.
    async fn list_storage_content(
        &self,
        node: &str,
        storage: &str,
        content_filter: Option<&str>,
    ) -> Result<Vec<crate::api::types::StorageContent>>;

    // ── Disk operations (feature #6) ────────────────────
    //
    // The endpoint NAMES differ across guest types:
    //   QEMU:  POST /qemu/{vmid}/move_disk      (disk, storage, delete)
    //   LXC:   POST /lxc/{vmid}/move_volume     (volume, storage, delete)
    //
    // Resize uses the same name on both:
    //   POST /{type}/{vmid}/resize             (disk, size)
    //
    // Both ops are async on the Proxmox side: they return a UPID
    // immediately and the actual disk relocation/grow runs in the
    // background. The caller polls task progress as usual.
    //
    // *Destructive*: this is why these go through the Operation Queue
    // and HITL gate by default — see reducer + dispatch_side_effect.

    /// Move a disk/volume to a different storage backend.
    /// `disk` = e.g. `"scsi0"` for QEMU, `"rootfs"` or `"mp0"` for LXC.
    /// `delete_source` = if true, remove the source after copy
    /// (Proxmox default is to keep the source as `unused0:...`).
    async fn move_disk(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        disk: &str,
        target_storage: &str,
        delete_source: bool,
    ) -> Result<String>;

    /// Grow a disk (Proxmox forbids shrinking).
    /// `size` accepts the Proxmox forms: `"+10G"` (delta) or `"100G"`
    /// (absolute target). The caller is responsible for picking the
    /// form that matches user intent — we don't normalize it.
    async fn resize_disk(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        disk: &str,
        size: &str,
    ) -> Result<String>;

    // ── Snapshot listing (feature #7) ───────────────────
    /// List snapshots for a guest, including the synthetic `current`
    /// entry. Used by the snapshot tree view to assemble a parent-child
    /// graph for branching visualization.
    async fn list_snapshots(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<Vec<crate::api::types::Snapshot>>;

    // ── APT / Patching (feature #9) ─────────────────────
    /// Refresh the apt cache on a node. Returns a UPID; the caller can
    /// poll `/nodes/{node}/tasks/{upid}/status` for completion.
    async fn apt_update_refresh(&self, node: &str) -> Result<String>;

    /// List packages with available upgrades on a node. Reads the cached
    /// state from the most recent `apt_update_refresh` — no network call
    /// to apt mirrors happens at this stage.
    async fn apt_list_upgradable(
        &self,
        node: &str,
    ) -> Result<Vec<crate::api::types::AptUpgradable>>;

    /// Detailed node status (uptime, kernel, version). Used by the
    /// patching orchestrator to verify post-reboot liveness.
    async fn node_status_detail(&self, node: &str) -> Result<crate::api::types::NodeStatusDetail>;
}
