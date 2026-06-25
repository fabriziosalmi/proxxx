// Proxmox API client — trait + types + implementation
// Zero knowledge of TUI. Pure domain layer.

mod auth;
mod client;
pub mod error;
pub mod tls_pin;
mod transport;
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

    /// Every guest across the cluster. Only ONLINE nodes are queried (an
    /// offline node has no guests to report); a failed fetch on a reachable
    /// node PROPAGATES rather than silently truncating — a partial guest list
    /// looks exactly like guests vanishing. Use this instead of hand-rolling a
    /// `for node { if let Ok(..) }` loop (which swallows per-node errors).
    async fn get_all_guests(&self) -> Result<Vec<Guest>> {
        let mut out = Vec::new();
        for n in self.get_nodes().await? {
            if matches!(n.status, crate::api::types::NodeStatus::Online) {
                out.extend(self.get_guests(&n.node).await?);
            }
        }
        Ok(out)
    }

    /// Every storage pool across the cluster (online nodes only; a failed fetch
    /// on a reachable node propagates rather than silently dropping pools).
    async fn get_all_storage_pools(&self) -> Result<Vec<StoragePool>> {
        let mut out = Vec::new();
        for n in self.get_nodes().await? {
            if matches!(n.status, crate::api::types::NodeStatus::Online) {
                out.extend(self.get_storage_pools(&n.node).await?);
            }
        }
        Ok(out)
    }

    /// Resolve a vmid to its guest (carrying `.node` + `.guest_type`) by scanning
    /// the cluster. `Ok(None)` = genuinely not found; an Err means a node fetch
    /// failed — so callers don't mistake a transient failure for "not found"
    /// (which would mis-target or abort a mutation on the wrong/no node).
    async fn find_guest(&self, vmid: u32) -> Result<Option<Guest>> {
        Ok(self
            .get_all_guests()
            .await?
            .into_iter()
            .find(|g| g.vmid == vmid))
    }

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

    /// Read the status of a single task. Used by the `--wait` flag
    /// to poll a long-running async op until completion. Read-only —
    /// `GET /nodes/{node}/tasks/{upid}/status`.
    async fn get_task_status(
        &self,
        node: &str,
        upid: &str,
    ) -> Result<crate::api::types::TaskStatus>;

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
    /// Graceful shutdown via ACPI/init. PVE will hard-kill the guest if it
    /// has not stopped within `timeout_secs`. For QEMU, `forceStop=1` is
    /// also sent so PVE SIGKILLs the qemu process on timeout instead of
    /// leaving the task appended indefinitely (which saturates pvedaemon
    /// worker threads and can render the node unresponsive). LXC does not
    /// support `forceStop` — the LXC shutdown endpoint rejects unknown params.
    async fn shutdown_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        timeout_secs: u32,
    ) -> Result<String>;
    async fn restart_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<String>;

    /// Suspend a running guest. For QEMU, freezes vCPUs in RAM
    /// (no disk dump — `vmstate` stays in memory). For LXC, freezes
    /// the cgroup. The guest stops consuming CPU but holds its RAM.
    /// Pair with `resume_guest`.
    ///
    /// Note: QEMU's `/status/suspend` is the **freeze-to-RAM** call.
    /// The disk-suspend variant (`/status/suspend?todisk=1`) is a
    /// distinct flow we don't expose in this MVP.
    async fn suspend_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<String>;

    /// Resume a suspended guest — inverse of `suspend_guest`.
    async fn resume_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<String>;

    // ── Bulk node power (mountain hill) ─────────────────
    //
    // Operate on every guest on a node at once. PVE's `startall` /
    // `stopall` / `suspendall` walk the node's guest list and apply
    // the corresponding per-VM call, sequenced by `onboot`/`bootorder`
    // config. Returns one UPID for the whole batch.

    /// Start every auto-start guest on a node (respects `onboot=1`).
    /// `POST /nodes/{node}/startall`.
    async fn startall_node(&self, node: &str) -> Result<String>;

    /// Graceful shutdown for every running guest on a node.
    /// `POST /nodes/{node}/stopall`.
    async fn stopall_node(&self, node: &str) -> Result<String>;

    /// Suspend every running guest on a node (PVE 8+).
    /// `POST /nodes/{node}/suspendall`. Older PVE returns 404 — caller
    /// should be prepared for `ApiError::NotFound`.
    async fn suspendall_node(&self, node: &str) -> Result<String>;

    // ── apt extras (mountain hill) ──────────────────────
    //
    // `proxxx patch` already covers update + plan + apply. These add
    // VISIBILITY around what's installed and from where.

    /// List configured apt repositories on a node. PVE returns a
    /// nested `{errors, files: [{path, repositories, file-type, …}]}`
    /// structure with byte-array file digests — too noisy to model
    /// strictly, exposed as `serde_json::Value` so callers can pretty-
    /// print + drill in.
    async fn node_apt_repositories(&self, node: &str) -> Result<serde_json::Value>;

    /// Plain-text changelog for one installed apt package on a node.
    /// `GET /nodes/{node}/apt/changelog?name={package}`. Returns the
    /// `data` field unchanged (Debian changelog format, multi-line).
    async fn node_apt_changelog(&self, node: &str, package: &str) -> Result<String>;

    /// List every installed package on a node with version + state.
    /// Useful for kernel/manager-version drift detection across the
    /// cluster. `GET /nodes/{node}/apt/versions`.
    async fn node_apt_versions(
        &self,
        node: &str,
    ) -> Result<Vec<crate::api::types::AptInstalledPackage>>;

    // ── Time-series metrics (hill 3a) ───────────────────
    //
    // RRDtool-backed historical samples. The chosen `timeframe`
    // controls bucket resolution (hour → 60s buckets, year → ~1w);
    // the `cf` (consolidation function) controls AVERAGE vs MAX
    // aggregation within each bucket. Every endpoint returns a
    // typically-60-element `Vec<RrdPoint>` ordered oldest → newest.

    /// Per-guest historical metrics — cpu, mem, disk, net, PSI.
    /// `GET /nodes/{node}/{kind}/{vmid}/rrddata`.
    async fn get_guest_rrddata(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        timeframe: crate::api::types::RrdTimeframe,
        cf: crate::api::types::RrdCf,
    ) -> Result<Vec<crate::api::types::RrdPoint>>;

    /// Per-node historical metrics — adds loadavg, iowait, swap, root
    /// pool usage, ZFS arc size on top of the guest fields.
    /// `GET /nodes/{node}/rrddata`.
    async fn get_node_rrddata(
        &self,
        node: &str,
        timeframe: crate::api::types::RrdTimeframe,
        cf: crate::api::types::RrdCf,
    ) -> Result<Vec<crate::api::types::RrdPoint>>;

    /// Per-storage historical metrics — `used` + `total` only (the
    /// other fields are absent / None).
    /// `GET /nodes/{node}/storage/{storage}/rrddata`.
    async fn get_storage_rrddata(
        &self,
        node: &str,
        storage: &str,
        timeframe: crate::api::types::RrdTimeframe,
        cf: crate::api::types::RrdCf,
    ) -> Result<Vec<crate::api::types::RrdPoint>>;

    // ── Console handoff (hill 2a/2b) ────────────────────
    //
    // proxxx ships VNC/SPICE access as a HANDOFF to an external
    // viewer (browser noVNC, remote-viewer for SPICE) rather than
    // embedding pixel rendering in the terminal. These methods
    // mint the one-shot tickets the external client needs.

    /// Mint a VNC ticket for a guest. POST returns port + ticket
    /// + (optional) TLS cert; caller passes them to noVNC via URL
    /// or hands off to a viewer. QEMU + LXC both supported.
    async fn get_guest_vncproxy(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<crate::api::types::VncTicket>;

    /// Mint a SPICE config for an LXC container — mirror of the
    /// existing QEMU `get_spiceproxy`. Newer PVE LXC builds expose
    /// SPICE; older builds 404. `POST /nodes/{node}/lxc/{vmid}/spiceproxy`.
    async fn get_lxc_spiceproxy(
        &self,
        node: &str,
        vmid: u32,
    ) -> Result<crate::api::types::SpiceConfig>;

    /// Run a shell command inside an LXC container via the native
    /// LXC exec endpoint (NOT the guest agent — LXC has no QGA).
    /// `POST /nodes/{node}/lxc/{vmid}/exec`. Returns the spawned
    /// PID; full status polling (parity with `execute_guest_command`)
    /// is a follow-up.
    async fn lxc_exec_oneshot(
        &self,
        node: &str,
        vmid: u32,
        command: &str,
    ) -> Result<serde_json::Value>;

    /// Mint a termproxy ticket for the NODE shell (not a guest).
    /// Equivalent of `pveum xtermjs` — gives you a websocket-backed
    /// `bash` on the node itself. `POST /nodes/{node}/termproxy`.
    async fn get_node_termproxy(&self, node: &str) -> Result<crate::api::types::TermproxyTicket>;

    /// Mint a VNC ticket for the node shell. `POST /nodes/{node}/vncshell`.
    async fn get_node_vncshell(&self, node: &str) -> Result<crate::api::types::VncTicket>;

    /// Mint a SPICE config for the node shell.
    /// `POST /nodes/{node}/spiceshell`.
    async fn get_node_spiceshell(&self, node: &str) -> Result<crate::api::types::SpiceConfig>;

    // ── Scheduled backup jobs ─────────────────────────────
    //
    // CRUD over `/cluster/backup` (recurring jobs) plus
    // `/nodes/{node}/vzdump/extractconfig` for disaster-recovery
    // peek (read a guest's config out of an existing backup archive
    // without restoring).

    /// List all scheduled backup jobs cluster-wide.
    /// `GET /cluster/backup`.
    async fn list_backup_jobs(&self) -> Result<Vec<crate::api::types::BackupJob>>;

    /// Fetch one scheduled backup job by id.
    /// `GET /cluster/backup/{id}`.
    async fn get_backup_job(&self, id: &str) -> Result<crate::api::types::BackupJob>;

    /// Create a new scheduled backup job. PVE auto-assigns the id;
    /// caller doesn't choose it. Minimum required by PVE: `schedule`
    /// + `storage` + (`all=1` OR `vmid=CSV`). Optional: `mode`,
    /// `mailto`, `compress`, `prune-backups`, etc.
    async fn create_backup_job(&self, params: &[(&str, &str)]) -> Result<()>;

    /// Update fields on an existing backup job. Same param shape as
    /// create. `PUT /cluster/backup/{id}`.
    async fn update_backup_job(&self, id: &str, params: &[(&str, &str)]) -> Result<()>;

    /// Delete a scheduled backup job. `DELETE /cluster/backup/{id}`.
    /// Does NOT delete already-taken backup archives — only the
    /// future-runs schedule.
    async fn delete_backup_job(&self, id: &str) -> Result<()>;

    /// Cluster-wide backup volume runtime info.
    /// `GET /cluster/backup-info`. **PVE quirk**: this endpoint is
    /// restricted to the LITERAL `root@pam` USER — even
    /// `root@pam!<token>` is rejected with 403 ("user != root@pam"
    /// in the PVE source). Returns the raw JSON for callers that
    /// happen to authenticate via password as the actual root user.
    async fn cluster_backup_info(&self) -> Result<serde_json::Value>;

    /// Extract one guest's config from a backup archive — read-only
    /// peek without restoring. Useful for "what was this VM's NIC
    /// MAC back when this snapshot was taken". Returns plain text
    /// (the raw `qemu-server.conf` or `pct.conf`).
    /// `GET /nodes/{node}/vzdump/extractconfig?volume=<volid>`.
    async fn extract_backup_config(&self, node: &str, volume: &str) -> Result<String>;

    /// Migrate a guest to another cluster node.
    ///
    /// `online`: live-migrate a running VM (RAM transferred without
    /// downtime) when `true`. PVE rejects with
    /// `can't migrate running VM without --online` when `false` and
    /// the guest is running. Caller should set this from the guest's
    /// current status.
    ///
    /// `with_local_disks`: required `true` when migrating a guest
    /// whose disks live on a node-local storage (e.g. `local-lvm`).
    /// PVE will copy the disk content over the migration network
    /// (slow, watch the bandwidth). When `false`, PVE will refuse
    /// the migration if any disk isn't on shared storage.
    ///
    /// `restart`: LXC-only. PVE does not support live migration of
    /// containers (CRIU is experimental and disabled by default).
    /// Setting `restart=1` tells PVE to shut down the container on
    /// the source node, copy state, and restart on the target —
    /// short-downtime "restart migration". For QEMU this param is
    /// ignored by PVE (live migration handles the equivalent).
    async fn migrate_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        target_node: &str,
        online: bool,
        with_local_disks: bool,
        restart: bool,
    ) -> Result<String>;
    async fn delete_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<String>;
    /// Run a shell command inside a guest. For QEMU this submits via
    /// the Guest Agent's `/agent/exec` endpoint and polls
    /// `/agent/exec-status` until the command exits or `QGA_EXEC_TIMEOUT`
    /// is reached, capturing the real exit code, stdout, and stderr.
    ///
    /// For LXC this **bails** — PVE 9 does not expose a REST exec
    /// endpoint for containers (verified against pve-test cluster).
    /// Callers wanting one-shot commands inside an LXC must shell
    /// out via SSH, or open `proxxx serial <vmid>` for an interactive
    /// session.
    async fn execute_guest_command(
        &self,
        node: &str,
        vmid: u32,
        guest_type: &crate::api::types::GuestType,
        command: &str,
    ) -> Result<crate::api::types::GuestExecResult>;

    // ── QEMU Guest Agent file ops + network introspection ──
    //
    // QEMU-only — LXC has no QGA. Three day-to-day operator surfaces:
    // peek at a file inside a running guest, drop a marker/config in,
    // and ask the guest "what IPs do you actually have right now."

    /// Read a file inside a running QEMU guest via QGA.
    /// `GET /nodes/{node}/qemu/{vmid}/agent/file-read?file={path}`.
    /// Returns content + a `truncated` flag — files larger than the
    /// QGA buffer (default ~16 KiB) come back partial.
    async fn qemu_agent_file_read(
        &self,
        node: &str,
        vmid: u32,
        file: &str,
    ) -> Result<crate::api::types::GuestAgentFileContent>;

    /// Write a file inside a running QEMU guest via QGA.
    /// `POST /nodes/{node}/qemu/{vmid}/agent/file-write` with form
    /// body `file=…&content=…`. PVE base64-encodes the content
    /// internally before passing to QGA, so callers pass plain text.
    async fn qemu_agent_file_write(
        &self,
        node: &str,
        vmid: u32,
        file: &str,
        content: &str,
    ) -> Result<()>;

    /// Ask the guest for its current network interfaces (names, MACs,
    /// and live IP assignments). More authoritative than reading
    /// the cloud-init config — this is what the kernel actually has.
    /// `GET /nodes/{node}/qemu/{vmid}/agent/network-get-interfaces`.
    async fn qemu_agent_network_get_interfaces(
        &self,
        node: &str,
        vmid: u32,
    ) -> Result<Vec<crate::api::types::GuestAgentNetworkInterface>>;

    // ── Node system layer (nodes.system.*) ───────────────
    //
    // The whole "what does this node look like" surface beyond raw
    // metrics: resolver/hosts/clock for plumbing config; journal +
    // syslog for diagnostics; subscription + certs for licensing /
    // TLS hygiene; report for the support bundle; wakeonlan for
    // bringing a sleeping node back without a KVM cart.

    async fn get_node_dns(&self, node: &str) -> Result<crate::api::types::NodeDns>;
    async fn update_node_dns(&self, node: &str, params: &[(&str, &str)]) -> Result<()>;

    async fn get_node_hosts(&self, node: &str) -> Result<crate::api::types::NodeHosts>;
    async fn update_node_hosts(&self, node: &str, data: &str, digest: Option<&str>) -> Result<()>;

    /// Tail the systemd journal. `query` accepts PVE filters
    /// (`since`, `until`, `lastentries`, `startcursor`, `endcursor`,
    /// `service`). Returns one string per journal line, oldest first.
    async fn get_node_journal(&self, node: &str, query: &[(&str, &str)]) -> Result<Vec<String>>;

    /// Tail `/var/log/syslog`. `query` accepts `start`, `limit`,
    /// `since`, `until`, `service`. Each row carries its 1-indexed
    /// cursor so callers can paginate without losing position.
    async fn get_node_syslog(
        &self,
        node: &str,
        query: &[(&str, &str)],
    ) -> Result<Vec<crate::api::types::NodeSyslogLine>>;

    async fn get_node_time(&self, node: &str) -> Result<crate::api::types::NodeTime>;
    /// Update the node's timezone (e.g. `Europe/Rome`). The clock
    /// itself is set by NTP — only the zone is user-controllable.
    async fn update_node_timezone(&self, node: &str, timezone: &str) -> Result<()>;

    /// Send a magic packet to wake the named node from S5/standby.
    /// PVE-side: any live node with the cluster network can transmit;
    /// the target node's MAC comes from `/etc/pve/storage.cfg`-style
    /// config. Returns the MAC the packet was sent to.
    async fn wakeonlan_node(&self, node: &str) -> Result<String>;

    async fn get_node_subscription(
        &self,
        node: &str,
    ) -> Result<crate::api::types::NodeSubscription>;
    /// Set the subscription key. PVE validates against the licensing
    /// server; failure surfaces as `ApiError::Other { status: 400 }`.
    async fn set_node_subscription_key(&self, node: &str, key: &str) -> Result<()>;
    /// Force a re-validate of the existing key (PUT, no body) — used
    /// after a network blip or when the operator wants to confirm the
    /// license server still recognizes the key.
    async fn refresh_node_subscription(&self, node: &str) -> Result<()>;
    async fn delete_node_subscription(&self, node: &str) -> Result<()>;

    /// List the certificates currently served by pveproxy on this
    /// node — `pve-ssl.pem` (cluster CA), optionally a custom
    /// uploaded one, optionally an ACME-issued one.
    async fn get_node_certificates_info(
        &self,
        node: &str,
    ) -> Result<Vec<crate::api::types::NodeCertificateInfo>>;
    /// Upload an operator-managed certificate + key. PVE writes them
    /// to `/etc/pve/local/pveproxy-ssl.{pem,key}` and (when `restart=1`)
    /// reloads pveproxy to pick them up.
    async fn upload_node_custom_certificate(
        &self,
        node: &str,
        params: &[(&str, &str)],
    ) -> Result<()>;
    async fn delete_node_custom_certificate(&self, node: &str, restart: bool) -> Result<()>;
    /// Order or renew an ACME-issued certificate. Returns a UPID —
    /// this is a long task (DNS-01 or HTTP-01 round-trips with the CA).
    async fn order_node_acme_certificate(&self, node: &str, force: bool) -> Result<String>;

    /// Plain-text support bundle — `pvereport` output. Returns
    /// many KB of text; meant for piping into a file when filing a bug.
    async fn get_node_report(&self, node: &str) -> Result<String>;

    // ── Pools, cluster resources, version (foundationals) ──

    /// List every pool in the cluster.
    async fn list_pools(&self) -> Result<Vec<crate::api::types::Pool>>;
    /// Get one pool's full member list (mixed VMs/LXCs/storages).
    async fn get_pool(&self, poolid: &str) -> Result<crate::api::types::PoolDetails>;
    /// Create a new (empty) pool. Members are added separately via
    /// `update_pool` so the create surface stays atomic.
    async fn create_pool(&self, params: &[(&str, &str)]) -> Result<()>;
    /// Modify a pool — add/remove guests/storages, edit comment. PVE
    /// uses comma-separated `vms=`, `storage=` lists with a `delete=1`
    /// toggle to remove instead of add.
    async fn update_pool(&self, poolid: &str, params: &[(&str, &str)]) -> Result<()>;
    async fn delete_pool(&self, poolid: &str) -> Result<()>;

    /// Single-shot cluster-wide resource list — nodes, guests,
    /// storages, sdn, pools all in one flat array. The PVE web UI
    /// dashboard's primary query. `kind` filters to one type
    /// (`vm`, `storage`, `node`, `sdn`, `pool`); `None` returns all.
    async fn get_cluster_resources(
        &self,
        kind: Option<&str>,
    ) -> Result<Vec<crate::api::types::ClusterResource>>;

    /// `GET /version` — PVE API version + git rev. Use for compat
    /// gating before invoking PVE-version-dependent endpoints.
    async fn get_api_version(&self) -> Result<crate::api::types::ApiVersion>;

    // ── Cluster-wide config + log (cluster.core.{options,log}) ──

    async fn get_cluster_options(&self) -> Result<crate::api::types::ClusterOptions>;
    async fn update_cluster_options(&self, params: &[(&str, &str)]) -> Result<()>;

    /// Tail the cluster event log. `max` caps the number of entries
    /// (PVE default ≈ 50, max ≈ 500). Newest entries first.
    async fn get_cluster_log(
        &self,
        max: Option<u32>,
    ) -> Result<Vec<crate::api::types::ClusterLogEntry>>;

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

    async fn rollback_snapshot(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        name: &str,
    ) -> Result<String>;

    // ── Guest config mutation ───────────────────────────
    /// Update a guest's running config. Pass a flat list of
    /// `(key, value)` pairs — PVE applies them atomically. The CLI
    /// `vm set` / `ct set` subcommands serialize their typed flags
    /// into this shape; raw users go through `vm raw-set` / `ct
    /// raw-set` which forwards the user's strings directly.
    ///
    /// Hot-pluggable changes (memory in some configs, network adds
    /// to running VMs) take effect immediately. Everything else
    /// queues as **pending** (PVE marks the change with a leading
    /// `+`) and applies on the next reboot.
    ///
    /// Returns `Some(UPID)` when PVE spawns background work
    /// (e.g. live RAM resize task) and `None` when the change is
    /// instant. Most config edits return `None`.
    async fn update_guest_config(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        params: &[(String, String)],
    ) -> Result<Option<String>>;

    /// Regenerate a QEMU guest's cloud-init drive. Required after
    /// changing any `ci*` field via `update_guest_config` —
    /// without this, the next boot reads the stale image.
    /// QEMU only — LXC has no cloud-init pipeline.
    async fn regenerate_cloudinit(&self, node: &str, vmid: u32) -> Result<Option<String>>;

    /// List pending config changes for a guest. After
    /// `update_guest_config`, callers can use this to distinguish
    /// keys that took effect immediately (hot-plug) from keys that
    /// queued and apply only on reboot. Read-only — `GET /pending`.
    async fn list_pending_config(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<Vec<crate::api::types::PendingConfigEntry>>;

    // ── Templates & cloning (provisioning) ──────────────
    /// Convert a stopped guest into a template. Templates cannot be
    /// started — they exist only as a source for `clone_guest`. The
    /// operation is **irreversible**: there is no PVE endpoint to
    /// "un-template" a guest.
    ///
    /// QEMU template marks the disks as base disks (read-only,
    /// linked-clonable). LXC template marks the rootfs volume the
    /// same way. Both require the guest to be stopped — PVE rejects
    /// with a clear error otherwise.
    ///
    /// PVE returns `data: null` on success for both kinds (no UPID),
    /// so the returned String is empty on success — callers should
    /// treat the absence of an error as the success signal.
    async fn convert_to_template(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<String>;

    /// Clone a guest into a new VMID. For QEMU, `full = true` makes
    /// an independent copy; `full = false` makes a linked clone
    /// (backed by the source's base disk — much faster, requires
    /// source to be a template). For LXC, clones are always full —
    /// the `full` flag is accepted for symmetry but PVE ignores
    /// `full = false` for containers.
    ///
    /// Field names diverge between guest types: QEMU uses `name` for
    /// the clone's display name, LXC uses `hostname`. This method
    /// hides that — pass the desired name in `name` regardless.
    ///
    /// `target` defaults to the source node when None. `storage` is
    /// required for cross-storage full clones; defaults to source
    /// storage when None. `snapname` clones from a specific
    /// snapshot rather than the running state.
    ///
    /// Returns the task UPID.
    #[allow(clippy::too_many_arguments)]
    async fn clone_guest(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        newid: u32,
        name: Option<&str>,
        target: Option<&str>,
        storage: Option<&str>,
        full: bool,
        snapname: Option<&str>,
        description: Option<&str>,
    ) -> Result<String>;

    /// Fetch the next free cluster-wide VMID. PVE returns the
    /// smallest unused id ≥ 100. Used by `clone_guest` when the
    /// caller does not pin `newid`. Note: PVE wraps the value as a
    /// JSON string, this method parses it to u32.
    async fn next_free_vmid(&self) -> Result<u32>;

    // ── Backup creation (vzdump) ────────────────────────
    /// Trigger a vzdump backup of one or more guests on a node to a
    /// target storage. All `vmids` must live on the same `node` — PVE
    /// does not allow cross-node vzdump in a single call.
    ///
    /// `mode` accepts `"snapshot"` (default, no downtime), `"suspend"`
    /// (briefly pause), or `"stop"` (cold backup). `compress` is one
    /// of `"0"`, `"1"`, `"gzip"`, `"lzo"`, `"zstd"` — PVE rejects
    /// unknown values with a clear schema error.
    ///
    /// Returns the task UPID; track progress via `get_cluster_tasks`
    /// or the TUI Tasks view. Backup creation is a long-running
    /// task — this call returns as soon as the task is queued.
    async fn create_backup(
        &self,
        node: &str,
        vmids: &[u32],
        storage: &str,
        mode: &str,
        compress: Option<&str>,
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

    // ── Firewall (read-only — Phase 4) ──────────────────
    /// List datacenter-wide firewall rules. Read-only —
    /// `GET /cluster/firewall/rules`.
    async fn list_cluster_firewall_rules(&self) -> Result<Vec<crate::api::types::FirewallRule>>;

    /// List firewall rules attached to a node's iptables chains.
    /// Read-only — `GET /nodes/{node}/firewall/rules`.
    async fn list_node_firewall_rules(
        &self,
        node: &str,
    ) -> Result<Vec<crate::api::types::FirewallRule>>;

    /// List firewall rules attached to a guest's NIC chain.
    /// Read-only — `GET /nodes/{node}/{kind}/{vmid}/firewall/rules`.
    async fn list_guest_firewall_rules(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<Vec<crate::api::types::FirewallRule>>;

    // ── Cluster firewall CRUD (cluster.firewall.{aliases,groups,ipset,options}) ──
    //
    // Closes the CRUD half of the cluster firewall surface — list_rules
    // already covered the read side. These let operators build the
    // reusable primitives (aliases, security groups, ipsets) that rules
    // reference, plus toggle the global enable + default policies.

    async fn list_cluster_firewall_aliases(&self) -> Result<Vec<crate::api::types::FirewallAlias>>;
    async fn create_cluster_firewall_alias(&self, params: &[(&str, &str)]) -> Result<()>;
    async fn update_cluster_firewall_alias(
        &self,
        name: &str,
        params: &[(&str, &str)],
    ) -> Result<()>;
    async fn delete_cluster_firewall_alias(&self, name: &str) -> Result<()>;

    async fn list_cluster_firewall_groups(
        &self,
    ) -> Result<Vec<crate::api::types::FirewallSecurityGroup>>;
    async fn create_cluster_firewall_group(&self, params: &[(&str, &str)]) -> Result<()>;
    async fn delete_cluster_firewall_group(&self, group: &str) -> Result<()>;
    /// List the rules contained in a security group. Same `FirewallRule`
    /// shape as the rules surface — groups are essentially named rule
    /// bundles inlined at evaluation time by `direction=group` rules.
    async fn list_cluster_firewall_group_rules(
        &self,
        group: &str,
    ) -> Result<Vec<crate::api::types::FirewallRule>>;

    async fn list_cluster_firewall_ipsets(&self) -> Result<Vec<crate::api::types::FirewallIpset>>;
    async fn create_cluster_firewall_ipset(&self, params: &[(&str, &str)]) -> Result<()>;
    async fn delete_cluster_firewall_ipset(&self, name: &str) -> Result<()>;
    async fn list_cluster_firewall_ipset_cidrs(
        &self,
        name: &str,
    ) -> Result<Vec<crate::api::types::FirewallIpsetCidr>>;
    async fn add_cluster_firewall_ipset_cidr(
        &self,
        name: &str,
        params: &[(&str, &str)],
    ) -> Result<()>;
    async fn remove_cluster_firewall_ipset_cidr(&self, name: &str, cidr: &str) -> Result<()>;

    async fn get_cluster_firewall_options(&self) -> Result<crate::api::types::FirewallOptions>;
    async fn update_cluster_firewall_options(&self, params: &[(&str, &str)]) -> Result<()>;

    // ── Per-guest firewall CRUD (qemu/lxc.firewall.{aliases,options}) ──
    //
    // Symmetric closure of the cluster-firewall CRUD region: same
    // resources but at guest scope. The `guest_type` discriminator
    // routes between `/qemu/` and `/lxc/` URL hierarchies (same dispatch
    // pattern as `list_guest_firewall_rules`).

    async fn list_guest_firewall_aliases(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<Vec<crate::api::types::FirewallAlias>>;
    async fn create_guest_firewall_alias(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        params: &[(&str, &str)],
    ) -> Result<()>;
    async fn update_guest_firewall_alias(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        name: &str,
        params: &[(&str, &str)],
    ) -> Result<()>;
    async fn delete_guest_firewall_alias(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        name: &str,
    ) -> Result<()>;
    async fn get_guest_firewall_options(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
    ) -> Result<crate::api::types::GuestFirewallOptions>;
    async fn update_guest_firewall_options(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        params: &[(&str, &str)],
    ) -> Result<()>;

    // ── Cluster hardware mapping (cluster.mapping.{pci,usb}) ──
    //
    // Stable logical names for passthrough devices. Operators map an id
    // (e.g. `gpu-rtx`) to per-node hardware paths so a guest that
    // migrates between hosts keeps the same passthrough binding.

    async fn list_cluster_mapping_pci(&self) -> Result<Vec<crate::api::types::ClusterMappingPci>>;
    async fn create_cluster_mapping_pci(&self, params: &[(&str, &str)]) -> Result<()>;
    async fn update_cluster_mapping_pci(&self, id: &str, params: &[(&str, &str)]) -> Result<()>;
    async fn delete_cluster_mapping_pci(&self, id: &str) -> Result<()>;

    async fn list_cluster_mapping_usb(&self) -> Result<Vec<crate::api::types::ClusterMappingUsb>>;
    async fn create_cluster_mapping_usb(&self, params: &[(&str, &str)]) -> Result<()>;
    async fn update_cluster_mapping_usb(&self, id: &str, params: &[(&str, &str)]) -> Result<()>;
    async fn delete_cluster_mapping_usb(&self, id: &str) -> Result<()>;

    // ── Network interfaces (read-only — Phase 4) ────────
    /// List network interfaces (physical NICs, bridges, bonds,
    /// VLANs) on a node, with their current up/down state.
    /// Read-only — `GET /nodes/{node}/network`.
    async fn list_node_network(
        &self,
        node: &str,
    ) -> Result<Vec<crate::api::types::NetworkInterface>>;

    // ── Storage content management (Phase 5.7) ──────────
    /// Delete a single content item from a storage. `volid` has the
    /// PVE form `storage:type/file.ext` for files (ISOs, backups,
    /// CT templates) or `storage:vmid/disk-name.ext` for VM disks.
    /// Returns the task UPID for storages that perform deletion as
    /// a task (most do); returns `None` for instant deletes.
    async fn delete_storage_content(
        &self,
        node: &str,
        storage: &str,
        volid: &str,
    ) -> Result<Option<String>>;

    /// Upload a local file to a storage as multipart/form-data. The
    /// `content_type` MUST be one of PVE's recognised buckets:
    /// `"iso"` (bootable images), `"vztmpl"` (LXC templates),
    /// `"import"` (disk images for VM import). PVE refuses other
    /// values with a clear schema error.
    ///
    /// `remote_filename`: the destination filename on the storage.
    /// If `None`, derive from the local path's basename.
    ///
    /// Returns the upload task UPID — track via `get_task_status`
    /// to know when the upload finishes (for big files, this is
    /// minutes).
    async fn upload_to_storage(
        &self,
        node: &str,
        storage: &str,
        local_path: &std::path::Path,
        content_type: &str,
        remote_filename: Option<&str>,
    ) -> Result<String>;

    // ── Access control mutations (Phase 5.10) ───────────
    /// Create a PVE user. `userid` must include the realm
    /// (e.g. `alice@pve`, `svc@pam`). For PAM realm users PVE
    /// expects the OS account to already exist; for the built-in
    /// `pve` realm proxxx creates the account from scratch and
    /// `password` is required (others optional).
    #[allow(clippy::too_many_arguments)]
    async fn create_user(
        &self,
        userid: &str,
        password: Option<&str>,
        comment: Option<&str>,
        email: Option<&str>,
        firstname: Option<&str>,
        lastname: Option<&str>,
        enable: Option<bool>,
        expire: Option<u64>,
        groups: Option<&str>,
    ) -> Result<()>;

    /// Modify an existing user. All fields optional — only the ones
    /// passed are changed (PVE PUT semantics). Pass `groups` as a
    /// comma-separated list to replace the user's group membership.
    #[allow(clippy::too_many_arguments)]
    async fn update_user(
        &self,
        userid: &str,
        comment: Option<&str>,
        email: Option<&str>,
        firstname: Option<&str>,
        lastname: Option<&str>,
        enable: Option<bool>,
        expire: Option<u64>,
        groups: Option<&str>,
    ) -> Result<()>;

    /// Delete a user. PVE refuses if the user owns API tokens — the
    /// caller is expected to revoke those first via the existing
    /// `revoke_token` method.
    async fn delete_user(&self, userid: &str) -> Result<()>;

    /// Create a group. Members are set on the user side (per-user
    /// `groups` field), not here.
    async fn create_group(&self, groupid: &str, comment: Option<&str>) -> Result<()>;

    /// Delete a group. PVE refuses if any user is still a member —
    /// remove members first (via `update_user` with the new groups
    /// CSV).
    async fn delete_group(&self, groupid: &str) -> Result<()>;

    /// Modify an ACL entry. Single endpoint covers grant + revoke:
    /// `delete = true` means revoke. Exactly one of `users`/`groups`/
    /// `tokens` should be set per call (PVE accepts multiple, but
    /// the CLI keeps the model unambiguous).
    #[allow(clippy::too_many_arguments)]
    async fn modify_acl(
        &self,
        path: &str,
        roles: &str,
        users: Option<&str>,
        groups: Option<&str>,
        tokens: Option<&str>,
        propagate: bool,
        delete: bool,
    ) -> Result<()>;

    // ── Hardware inventory (feature #4) ─────────────────
    /// List PCI devices visible to a node, including IOMMU group ids.
    /// Read-only — `GET /nodes/{node}/hardware/pci`.
    async fn list_pci(&self, node: &str) -> Result<Vec<crate::api::types::PciDevice>>;

    /// List USB devices visible to a node. Read-only —
    /// `GET /nodes/{node}/hardware/usb`.
    async fn list_usb(&self, node: &str) -> Result<Vec<crate::api::types::UsbDevice>>;

    // ── Storage health (mountain #1) ────────────────────
    //
    // Block-layer inventory + SMART. proxxx previously stopped at the
    // logical storage layer; these methods expose what's UNDERNEATH so
    // operators can spot a failing physical disk before it cascades to
    // the VMs sitting on it.

    /// List physical disks on a node — model, serial, size, current
    /// usage, SMART health summary. Read-only —
    /// `GET /nodes/{node}/disks/list`.
    async fn list_node_disks(&self, node: &str) -> Result<Vec<crate::api::types::Disk>>;

    /// Full SMART output for one disk (per-attribute for ATA/SAS,
    /// `text` blob for NVME). Read-only —
    /// `GET /nodes/{node}/disks/smart?disk={path}`.
    async fn get_disk_smart(&self, node: &str, disk: &str) -> Result<crate::api::types::DiskSmart>;

    /// LVM volume groups on a node. Read-only —
    /// `GET /nodes/{node}/disks/lvm`. The PVE response is a tree
    /// (`children: [...]`) — we flatten to one entry per VG.
    async fn list_node_lvm(&self, node: &str) -> Result<Vec<crate::api::types::LvmVolumeGroup>>;

    /// LVM-thin pools on a node. Read-only —
    /// `GET /nodes/{node}/disks/lvmthin`.
    async fn list_node_lvmthin(&self, node: &str) -> Result<Vec<crate::api::types::LvmThinPool>>;

    /// ZFS pools on a node — health, capacity, fragmentation, dedup.
    /// Read-only — `GET /nodes/{node}/disks/zfs`.
    async fn list_node_zfs(&self, node: &str) -> Result<Vec<crate::api::types::ZfsPool>>;

    /// Per-pool ZFS detail — `GET /nodes/{node}/disks/zfs/{name}`. Reads the
    /// `scan` field (scrub progress / last-scrub epoch / error counters) and
    /// flattens PVE's nested vdev tree into a single `Vec<ZfsVdev>`.
    async fn get_node_zfs_detail(
        &self,
        node: &str,
        name: &str,
    ) -> Result<crate::api::types::ZfsPoolDetail>;

    /// Serial devices configured on a guest. QEMU: the `serial0..3` config
    /// keys; LXC: always empty (LXC uses `/dev/console` via `lxc-console`, not
    /// a serial device). Callers check `is_empty()` for console pre-flight.
    async fn guest_serial_devices(
        &self,
        node: &str,
        vmid: u32,
        guest_type: &crate::api::types::GuestType,
    ) -> Result<Vec<crate::api::types::SerialDevice>>;

    /// Best-effort instantaneous disk-IO rate for a guest, from the most recent
    /// RRD point (`rrddata?timeframe=hour`). PVE's RRD already stores
    /// `diskread`/`diskwrite` as bytes/second, so this is the latest sample.
    /// `None` when RRD has no point carrying IO data. Resolution ~60 s.
    async fn guest_disk_io_rate(
        &self,
        node: &str,
        vmid: u32,
        guest_type: &crate::api::types::GuestType,
    ) -> Result<Option<crate::api::types::DiskIoRate>>;

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

    /// User-facing HA live status — heterogeneous list mixing
    /// per-node, per-service, and master/quorum rows. Higher-level
    /// than `ha_manager_status` (which is the raw CRM internal state).
    /// Read-only — `/cluster/ha/status/current`.
    async fn get_ha_status_current(&self) -> Result<Vec<crate::api::types::HaStatusEntry>>;

    /// Hit the LITERAL `/cluster/ha/groups` path (PVE 8). On PVE 9
    /// this returns 500 (path migrated to `/cluster/ha/rules`); use
    /// `list_ha_groups` for the version-tolerant call.
    async fn list_ha_groups_legacy(&self) -> Result<Vec<crate::api::types::HaGroup>>;
    /// Create an HA group (PVE 8 only — PVE 9 uses rules instead).
    async fn create_ha_group(&self, params: &[(&str, &str)]) -> Result<()>;
    /// Update one HA group's nodes/restricted/nofailback/comment.
    async fn update_ha_group(&self, group: &str, params: &[(&str, &str)]) -> Result<()>;
    async fn delete_ha_group(&self, group: &str) -> Result<()>;

    // ── PVE 9 HA rules — node-affinity + resource-affinity (epic #74)

    /// List HA rules — node-affinity + resource-affinity, mixed in one
    /// array. PVE 9+ only; PVE 8 has no `/cluster/ha/rules` endpoint.
    /// Read-only — `/cluster/ha/rules`.
    async fn list_ha_rules(&self) -> Result<Vec<crate::api::types::HaRule>>;

    /// Create an HA rule. `params` must include `type` (one of
    /// `node-affinity` / `resource-affinity`) and `rule` (the id), plus
    /// the plugin-specific fields (`nodes`+`strict` for node-affinity,
    /// `affinity` for resource-affinity). Common fields (`resources`,
    /// `comment`, `disable`) are accepted by both plugins. Requires
    /// `Sys.Console` on `/`. POST `/cluster/ha/rules`.
    async fn create_ha_rule(&self, params: &[(&str, &str)]) -> Result<()>;

    /// Update one HA rule. The rule's `type` is immutable (PVE rejects
    /// changes); to switch types, delete + create. Plugin-specific
    /// fields apply per the existing rule's type. PVE keeps unspecified
    /// fields at their old values — pass them in `delete` (repeated keys
    /// per the matchers lesson) to clear them. PUT
    /// `/cluster/ha/rules/{rule}`. Sys.Console on `/`.
    async fn update_ha_rule(&self, rule: &str, params: &[(&str, &str)]) -> Result<()>;

    /// Delete an HA rule. Resources it constrained revert to the global
    /// HA defaults (no node preference, no affinity). DELETE
    /// `/cluster/ha/rules/{rule}`. Sys.Console on `/`.
    async fn delete_ha_rule(&self, rule: &str) -> Result<()>;

    // ── PVE 9 HA resources CRUD (epic #74 epilogue, 7/6) ─────

    /// Create an HA resource. `params` must include `sid` (the
    /// identity — e.g. `vm:100`, `ct:200`) and `type` (`vm` or `ct`,
    /// derivable from the SID prefix). Optional: `state`
    /// (`started`/`stopped`/`disabled`/`ignored`), `max_restart`,
    /// `max_relocate`, `failback`, `auto-rebalance`, `comment`.
    /// **Do not** pass `group` — PVE 9 rejects it ("ha groups have
    /// been migrated to rules"). Requires `Sys.Console` on `/`.
    /// POST `/cluster/ha/resources`.
    async fn create_ha_resource(&self, params: &[(&str, &str)]) -> Result<()>;

    /// Update one HA resource's mutable fields. SID and type are
    /// immutable; type must still be echoed in `params`. Unset
    /// fields are passed via repeated `delete=<key>` params (matcher
    /// lesson). PUT `/cluster/ha/resources/{sid}`. Sys.Console.
    async fn update_ha_resource(&self, sid: &str, params: &[(&str, &str)]) -> Result<()>;

    /// Delete an HA resource. PVE defaults `purge=1` which
    /// automatically removes the SID from any HA rules referencing
    /// it (and deletes a rule entirely if its only remaining resource
    /// was this one). DELETE `/cluster/ha/resources/{sid}`. Sys.Console.
    async fn delete_ha_resource(&self, sid: &str) -> Result<()>;

    // ── PVE 8+ notification system (cluster.notifications.*) ──

    async fn list_notification_endpoints(
        &self,
    ) -> Result<Vec<crate::api::types::NotificationEndpoint>>;
    /// Create an endpoint of the given type. PVE routes per-type:
    /// POST `/cluster/notifications/endpoints/{type}` (sendmail,
    /// smtp, gotify, webhook). Type-specific knobs go via `params`.
    async fn create_notification_endpoint(
        &self,
        endpoint_type: &str,
        params: &[(&str, &str)],
    ) -> Result<()>;
    async fn update_notification_endpoint(
        &self,
        endpoint_type: &str,
        name: &str,
        params: &[(&str, &str)],
    ) -> Result<()>;
    async fn delete_notification_endpoint(&self, endpoint_type: &str, name: &str) -> Result<()>;

    async fn list_notification_matchers(
        &self,
    ) -> Result<Vec<crate::api::types::NotificationMatcher>>;
    async fn create_notification_matcher(&self, params: &[(&str, &str)]) -> Result<()>;
    async fn update_notification_matcher(&self, name: &str, params: &[(&str, &str)]) -> Result<()>;
    async fn delete_notification_matcher(&self, name: &str) -> Result<()>;

    /// Read-only flat list of all valid delivery target names.
    /// Used by matcher `target` validation.
    async fn list_notification_targets(&self)
        -> Result<Vec<crate::api::types::NotificationTarget>>;

    // Top-tier 80/20 closure (4 endpoints).

    /// `GET /access/permissions[?userid=X&path=Y]` — effective
    /// permissions tree for a user on a path. Returns nested map
    /// `{path: {capability: 1, ...}, ...}`. Distinct from the existing
    /// `proxxx perms` SSH-shellout — this hits the API directly,
    /// removing the SSH dependency for RBAC debugging.
    async fn get_access_permissions(
        &self,
        userid: Option<&str>,
        api_path: Option<&str>,
    ) -> Result<serde_json::Value>;

    /// `PUT /access/password` — change a user's password. Requires
    /// the operator to be either the user themselves OR have
    /// `Realm.AllocateUser` on `/access/{realm}` (typically root@pam).
    async fn change_user_password(&self, userid: &str, password: &str) -> Result<()>;

    /// `GET /nodes/{node}/lxc/{vmid}/interfaces` — network interfaces
    /// inside an LXC container (PVE shells to `lxc-info` / `ip addr`
    /// in the container's netns). Mirrors QGA's `network-get-interfaces`
    /// but for LXC, where there's no agent.
    async fn list_lxc_interfaces(
        &self,
        node: &str,
        vmid: u32,
    ) -> Result<Vec<crate::api::types::LxcInterface>>;

    /// `GET /nodes/{node}/qemu/{vmid}/cloudinit/dump?type=X` —
    /// dump the generated cloud-init data PVE will serve to the guest
    /// on next boot. `kind` is `user` | `network` | `meta`. Useful for
    /// debugging cloud-init template inheritance and verifying that
    /// recent `qm set ... --cipassword/--ciuser/--ipconfig0` actually
    /// landed in the rendered output.
    async fn dump_qemu_cloudinit(&self, node: &str, vmid: u32, kind: &str) -> Result<String>;

    /// Build the WebSocket-upgrade URL for a guest's VNC console.
    /// Pure URL construction — no HTTP call. PVE's `vncwebsocket`
    /// endpoint expects a WebSocket upgrade handshake (with the
    /// `port` + `vncticket` from a prior `get_guest_vncproxy` call);
    /// the natural use is to hand the URL to a noVNC client or
    /// `tokio-tungstenite` for the actual upgrade. Returns
    /// `wss://host:8006/api2/json/nodes/{n}/{kind}/{vmid}/vncwebsocket?port=N&vncticket=T`.
    /// `GET /nodes/{node}/{kind}/{vmid}/vncwebsocket` (WebSocket).
    async fn build_guest_vncwebsocket_url(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        ticket: &crate::api::types::VncTicket,
    ) -> Result<String>;

    // ── RRD PNG graphs + cluster.metrics.server ──

    /// Pre-rendered RRD graph PNG for a guest. PVE writes the image
    /// to the node's filesystem and returns its path; caller fetches
    /// via separate transport. Distinct from `get_guest_rrddata`
    /// which returns numeric series — this is for UI / export
    /// pipelines wanting an existing image.
    /// `GET /nodes/{node}/{kind}/{vmid}/rrd?ds=…&timeframe=…&cf=…`.
    async fn get_guest_rrd_image(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        ds: &str,
        timeframe: crate::api::types::RrdTimeframe,
        cf: crate::api::types::RrdCf,
    ) -> Result<crate::api::types::RrdImage>;

    async fn list_metric_servers(&self) -> Result<Vec<crate::api::types::MetricServer>>;
    async fn get_metric_server(&self, id: &str) -> Result<crate::api::types::MetricServer>;
    /// Create a metrics exporter. Required: `id` (in path), `server`
    /// (host), `port`, plus protocol-specific knobs via `params`
    /// (`type` is REQUIRED in body too — `influxdb` or `graphite`).
    async fn create_metric_server(&self, id: &str, params: &[(&str, &str)]) -> Result<()>;
    async fn update_metric_server(&self, id: &str, params: &[(&str, &str)]) -> Result<()>;
    async fn delete_metric_server(&self, id: &str) -> Result<()>;

    // ── 80/20 grab-bag: tasks per-node, feature, sendkey/unlink, aplinfo ──

    /// Per-node task list (vs `get_cluster_tasks` which is cluster-wide).
    /// Use when one node is misbehaving and you need to filter by it.
    /// `GET /nodes/{node}/tasks?limit=N`.
    async fn list_node_tasks(
        &self,
        node: &str,
        limit: Option<u32>,
    ) -> Result<Vec<crate::api::types::TaskInfo>>;
    /// Cancel a running task. PVE first signals cleanly, then SIGKILLs
    /// after a grace period. Use when a vzdump/migration is wedged.
    /// `DELETE /nodes/{node}/tasks/{upid}`.
    async fn stop_node_task(&self, node: &str, upid: &str) -> Result<()>;

    /// Pre-flight capability check on a guest. Common features:
    /// `snapshot` | `clone` | `copy` | `migrate` | `replicate`.
    /// Returns `{has_feature, nodes}` — `nodes` is the list of nodes
    /// where the feature would still work after a migration.
    /// `GET /nodes/{node}/{kind}/{vmid}/feature?feature=X`.
    async fn get_guest_feature(
        &self,
        node: &str,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        feature: &str,
    ) -> Result<crate::api::types::GuestFeatureCheck>;

    /// Send a key sequence (NMI/sysrq) to a QEMU guest via QMP. Useful
    /// for kernel debugging — `sysrq+t` (task list), `sysrq+s` (sync),
    /// `sysrq+c` (crash). `key` syntax is QMP's: `ctrl-alt-delete`,
    /// `sysrq` (single literal), `0x42` (raw scancode), etc.
    /// `PUT /nodes/{node}/qemu/{vmid}/sendkey`. QEMU-only.
    async fn send_qemu_key(&self, node: &str, vmid: u32, key: &str) -> Result<()>;

    /// Detach a disk from a QEMU guest's config. Default leaves the
    /// underlying volume alone (operator can move/reattach later);
    /// `force=true` deletes the volume too. `idlist` is CSV
    /// (e.g. `scsi1,scsi2`). `PUT /nodes/{node}/qemu/{vmid}/unlink`.
    async fn unlink_qemu_disk(
        &self,
        node: &str,
        vmid: u32,
        idlist: &str,
        force: bool,
    ) -> Result<()>;

    /// List LXC templates from PVE's curated catalog (≈ `pveam available`).
    /// `GET /nodes/{node}/aplinfo`.
    async fn list_node_aplinfo(&self, node: &str) -> Result<Vec<crate::api::types::AplTemplate>>;
    /// Download one template to a node's storage (≈ `pveam download
    /// {storage} {template}`). Returns a UPID — long task (template
    /// fetch from PVE mirrors). `POST /nodes/{node}/aplinfo`.
    async fn download_node_aplinfo(
        &self,
        node: &str,
        storage: &str,
        template: &str,
    ) -> Result<String>;

    /// Pre-flight a URL for `download_to_storage` — returns size +
    /// filename + mime so the operator can size-check first.
    /// `GET /nodes/{node}/query-url-metadata?url=…`.
    async fn query_url_metadata(
        &self,
        node: &str,
        url: &str,
    ) -> Result<crate::api::types::UrlMetadata>;

    // ── Corosync cluster bootstrap (cluster.config.*) ──
    //
    // Cluster lifecycle: corosync node membership, join info for
    // bootstrapping a new node into an existing cluster, quorum-device
    // setup, totem transport inspection.

    async fn list_cluster_corosync_nodes(&self) -> Result<Vec<crate::api::types::CorosyncNode>>;
    /// Add a node to the corosync membership. PVE shape: POST to
    /// `/cluster/config/nodes/{node}` with optional `ring0_addr`/
    /// `ring1_addr`/`votes`/`nodeid`/`force`. Returns nothing useful.
    async fn add_cluster_corosync_node(&self, node: &str, params: &[(&str, &str)]) -> Result<()>;
    async fn remove_cluster_corosync_node(&self, node: &str) -> Result<()>;

    /// `GET /cluster/config/join` — fetch the join data + totem config
    /// + cert fingerprint a new node needs to join. `node` query param
    /// is the NEW node's intended name (PVE 8+ requires it).
    async fn get_cluster_join_info(&self, node: Option<&str>) -> Result<serde_json::Value>;
    /// `POST /cluster/config/join` — actually join an existing cluster
    /// from the new-node side. Required: `hostname` (target cluster
    /// node), `password` (root@pam password on target), `fingerprint`
    /// (cluster cert fingerprint). Returns a UPID.
    async fn join_cluster(&self, params: &[(&str, &str)]) -> Result<String>;

    /// `GET /cluster/config/qdevice` — quorum-device config (singleton
    /// per cluster). Heterogeneous shape — returned as raw Value.
    async fn get_cluster_qdevice(&self) -> Result<serde_json::Value>;
    /// `POST /cluster/config/qdevice` — set up a new quorum device.
    /// Required: `addr` (qdevice host), optional `algorithm`,
    /// `tie_breaker`, etc. Returns a UPID (corosync restart involved).
    async fn setup_cluster_qdevice(&self, params: &[(&str, &str)]) -> Result<String>;
    async fn update_cluster_qdevice(&self, params: &[(&str, &str)]) -> Result<String>;
    /// Remove the quorum device. Returns a UPID.
    async fn remove_cluster_qdevice(&self) -> Result<String>;

    /// `GET /cluster/config/totem` — corosync totem transport config
    /// (`cluster_name`, version, transport, interfaces, secauth, ...).
    /// Read-only — totem changes go through corosync.conf editing.
    async fn get_cluster_totem(&self) -> Result<serde_json::Value>;

    // ── ACME (cluster.acme.{accounts,plugins,tos,directories,challenge_schema}) ──

    async fn list_acme_accounts(&self) -> Result<Vec<crate::api::types::AcmeAccount>>;
    async fn get_acme_account(&self, name: &str) -> Result<crate::api::types::AcmeAccountDetails>;
    /// Register a new ACME account with the CA. Returns a UPID — the
    /// call is async because the CA round-trip can take seconds.
    /// Required params: `name`, `contact`. Optional: `tos_url`,
    /// `directory` (defaults to LE prod), `eab-kid`, `eab-hmac-key`.
    async fn create_acme_account(&self, params: &[(&str, &str)]) -> Result<String>;
    async fn update_acme_account(&self, name: &str, params: &[(&str, &str)]) -> Result<String>;
    async fn delete_acme_account(&self, name: &str) -> Result<String>;

    async fn list_acme_plugins(&self) -> Result<Vec<crate::api::types::AcmePlugin>>;
    async fn get_acme_plugin(&self, plugin_id: &str) -> Result<crate::api::types::AcmePlugin>;
    async fn create_acme_plugin(&self, params: &[(&str, &str)]) -> Result<()>;
    async fn update_acme_plugin(&self, plugin_id: &str, params: &[(&str, &str)]) -> Result<()>;
    async fn delete_acme_plugin(&self, plugin_id: &str) -> Result<()>;

    /// `GET /cluster/acme/tos` — Terms-of-Service URL for the chosen
    /// ACME directory. Caller must echo it back as `tos_url` on
    /// account create to confirm acceptance.
    async fn get_acme_tos(&self, directory: Option<&str>) -> Result<String>;

    /// `GET /cluster/acme/directories` — list of ACME-compatible CAs
    /// PVE knows about (Let's Encrypt prod/staging, custom).
    async fn list_acme_directories(&self) -> Result<Vec<crate::api::types::AcmeDirectory>>;

    /// `GET /cluster/acme/challenge-schema` — DNS-01 plugin schema
    /// list. Big nested object; surfaced as raw `serde_json::Value`
    /// because it's wizard-UI fodder, not operational API.
    async fn get_acme_challenge_schema(&self) -> Result<serde_json::Value>;

    // ── Cluster-wide storage definitions (storage.definitions) ──

    /// List every storage definition cluster-wide.
    async fn list_cluster_storages(&self) -> Result<Vec<crate::api::types::StorageDefinition>>;
    /// Get one storage definition by id.
    async fn get_cluster_storage(
        &self,
        storage: &str,
    ) -> Result<crate::api::types::StorageDefinition>;
    /// Create a storage. Required: `storage` (id) + `type`. Type-
    /// specific knobs (server/path/pool/datastore/...) via `params`.
    async fn create_cluster_storage(&self, params: &[(&str, &str)]) -> Result<()>;
    /// Modify an existing storage. Type cannot be changed; `type` must
    /// not appear in `params` (PVE 400s if it does).
    async fn update_cluster_storage(&self, storage: &str, params: &[(&str, &str)]) -> Result<()>;
    async fn delete_cluster_storage(&self, storage: &str) -> Result<()>;

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
    /// pass them through unchanged. schema: was a single
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

    /// Fetch the next available VMID from the cluster.
    /// `GET /cluster/nextid`.
    async fn get_next_vmid(&self) -> Result<u32>;

    /// Create a new QEMU VM. Returns the task UPID.
    /// `POST /nodes/{node}/qemu`.
    async fn create_qemu(&self, node: &str, params: &[(&str, &str)]) -> Result<String>;

    /// Create a new LXC container. Returns the task UPID.
    /// `POST /nodes/{node}/lxc`.
    async fn create_lxc(&self, node: &str, params: &[(&str, &str)]) -> Result<String>;
}
