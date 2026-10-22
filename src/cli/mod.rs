use anyhow::Result;
use clap::Subcommand;
use serde_json::Value;

mod access;
mod accounting;
mod anomaly;
pub mod args;
mod audit_cmd;
mod backup_verify;
mod cloudimg;
mod cluster;
pub mod common;
mod console;
mod ct;
mod daemon;
mod describe;
pub mod doctor;
mod events;
pub mod explain;
mod fanout;
mod firewall;
mod gpu_passthrough;
mod heatmap;
mod import_vm;
mod incident;
mod init;
mod init_wizard;
mod logs;
mod migrate_progress;
mod monitoring;
mod node;
mod patch;
// `pub(crate)` so the converge core in `state::converge` can reuse the shared
// drift helpers (`compute_drift_with_live`, `drift_summary`) without a second
// copy. The items themselves stay `pub(crate)`.
pub(crate) mod reconcile;
mod schedule;
mod state;
mod storage;
pub mod token_bootstrap;
mod upgrade_check;
pub mod vm;
mod watch;
#[cfg(test)]
mod cli_secret_scope_tests {
    #[test]
    fn the_cli_secret_is_refused_for_fanout_with_a_config_error() {
        let err = super::refuse_cli_secret_for_fanout(Some("s"), "fleet")
            .expect_err("a CLI secret must not be fanned out");
        assert!(err
            .chain()
            .any(|c| c.downcast_ref::<crate::config::ConfigError>().is_some()));
        assert!(format!("{err:#}").contains("`fleet`"));
        super::refuse_cli_secret_for_fanout(None, "fleet").expect("no flag, no refusal");
    }
}

#[cfg(test)]
mod help_text_tests;
#[cfg(test)]
mod yes_gate_net;

pub use audit_cmd::AuditAction;

use crate::util;
use common::{
    enforce_preflight, execute_batch_op_with_policy, find_guest, find_guest_full,
    wait_and_classify, BatchOp,
};

/// `proxxx feature --feature`: the values PVE's `/feature` endpoint takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum GuestFeature {
    Snapshot,
    Clone,
    Copy,
}

impl GuestFeature {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Clone => "clone",
            Self::Copy => "copy",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List resources (aliases: get)
    #[command(alias = "get")]
    Ls {
        /// Resource type: nodes, guests, storage
        resource: String,
        /// Fan out the query across every named profile in
        /// `config.toml` concurrently. Each output row gets a
        /// `profile` field. Per-profile failures (401 / unreachable)
        /// surface as `error` rows; the rest of the cluster keeps
        /// answering. Read-only — writes still require explicit
        /// `--profile <name>`.
        #[arg(long, short = 'A')]
        all_profiles: bool,
    },

    /// Find a guest by VMID across every cluster. Like `ls guests
    /// --all-profiles` but filtered to one VMID. Returns one row per
    /// profile that owns the VMID (typically 0 or 1). Useful for
    /// "which cluster owns VMID 100?" without manual profile-switching.
    #[command(alias = "where")]
    Find {
        /// VMID to find.
        vmid: u32,
    },
    /// Start a guest
    Start {
        /// Guest VMID(s)
        vmids: Vec<u32>,
        #[arg(long)]
        strict: bool,
        /// Execution policy: full (default), canary[=N%], rolling[=K]
        #[arg(long, default_value = "full")]
        policy: String,
    },
    /// Stop a guest
    Stop {
        /// Guest VMID(s)
        vmids: Vec<u32>,
        /// Force stop without graceful shutdown (PVE hard-kill — sends
        /// SIGKILL to the qemu process, container init).
        #[arg(long)]
        force: bool,
        #[arg(long)]
        strict: bool,
        /// Override proxxx pre-flight risk checks (lock, HA-managed,
        /// active network traffic, prod tag, …). Distinct from
        /// `--force`, which is PVE-level hard-kill semantics.
        #[arg(long)]
        allow_risk: bool,
        /// Seconds PVE waits for graceful shutdown before hard-killing
        /// the guest (QEMU: SIGKILL; LXC: init kill). Ignored when
        /// `--force` is set. [default: 60]
        #[arg(long, default_value_t = 60)]
        stop_timeout: u32,
        /// Execution policy: full (default), canary[=N%], rolling[=K]
        #[arg(long, default_value = "full")]
        policy: String,
    },
    /// Restart a guest
    Restart {
        /// Guest VMID(s)
        vmids: Vec<u32>,
        #[arg(long)]
        strict: bool,
        /// Override proxxx pre-flight risk checks.
        #[arg(long)]
        allow_risk: bool,
        /// Execution policy: full (default), canary[=N%], rolling[=K]
        #[arg(long, default_value = "full")]
        policy: String,
    },
    /// Suspend a running guest (freeze vCPUs to RAM). Pair with `resume`.
    /// QEMU + LXC. Non-destructive — the guest holds memory until you
    /// resume. To checkpoint to disk instead, use the QEMU monitor
    /// directly (out of MVP scope).
    Suspend {
        /// Guest VMID(s)
        vmids: Vec<u32>,
        #[arg(long)]
        strict: bool,
        /// Execution policy: full (default), canary[=N%], rolling[=K]
        #[arg(long, default_value = "full")]
        policy: String,
    },
    /// Resume a suspended guest — inverse of `suspend`.
    Resume {
        /// Guest VMID(s)
        vmids: Vec<u32>,
        #[arg(long)]
        strict: bool,
        /// Execution policy: full (default), canary[=N%], rolling[=K]
        #[arg(long, default_value = "full")]
        policy: String,
    },
    /// Delete a guest (VM or LXC)
    Delete {
        /// Guest VMID(s)
        vmids: Vec<u32>,
        /// Don't prompt; required for non-interactive use
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        strict: bool,
        /// Override proxxx pre-flight risk checks (lock, HA-managed,
        /// running with active traffic, prod tag, long uptime).
        /// PVE's own guards (e.g. refusing delete on a running VM)
        /// stay in force regardless.
        #[arg(long)]
        allow_risk: bool,
    },
    /// Migrate a guest to another node. proxxx auto-detects the
    /// right PVE semantics: `online=1` for running QEMU (live RAM
    /// transfer); `restart=1` for running LXC (PVE has no live
    /// container migration — it shuts down on source, copies, and
    /// restarts on target). Stopped guests get plain offline
    /// migration. Requires `--yes`.
    Migrate {
        /// Guest VMID
        vmid: u32,
        /// Target node name (must be in the same cluster)
        target: String,
        #[arg(long)]
        yes: bool,
        /// Required when any of the guest's disks live on a
        /// node-local storage (e.g. `local-lvm`). PVE will copy the
        /// disk content to the target over the migration network —
        /// expensive on multi-GB volumes. Without this flag, PVE
        /// refuses to migrate a guest with local disks.
        #[arg(long)]
        with_local_disks: bool,
        /// Override proxxx pre-flight risk checks.
        #[arg(long)]
        allow_risk: bool,
        /// Block until the migration task completes. Without this,
        /// returns the UPID immediately; the caller must poll. With
        /// it, exits 0 on PVE `exitstatus == OK` and 1 on anything
        /// else. Required for shell pipelines that chain ops.
        #[arg(long)]
        wait: bool,
        /// Stream per-disk transfer progress + RAM events live as
        /// PVE writes them to the migration task log. Implies `--wait`
        /// — streaming makes no sense without blocking on completion.
        ///
        /// Rendering picks itself based on `--format`:
        ///   * default / `--format table` → in-place ANSI progress bars
        ///     (one per disk) with a scrolling log above them.
        ///   * `--format json` → NDJSON, one JSON object per event,
        ///     terminated by `{"kind":"complete",…}`. Matches the
        ///     shape of `events stream --format json` so the same `jq`
        ///     filters work.
        ///
        /// On task completion proxxx emits a summary line + the final
        /// task status, then exits with the same code as `--wait`.
        #[arg(long)]
        stream: bool,
    },
    /// Run a command inside a guest via the QEMU Guest Agent.
    /// **QEMU only** — PVE 9 does not expose a REST exec endpoint for
    /// LXC; for containers use `proxxx serial <vmid>` (interactive)
    /// or shell out via SSH. The agent must be installed and
    /// running inside the QEMU guest.
    Exec {
        /// Guest VMID
        vmid: u32,
        /// Command and arguments. Use `--` to pass through flags
        /// that would otherwise be parsed by clap.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Show a guest's current Proxmox config (cores, memory, disks, net, …).
    /// Read-only.
    Config {
        /// Guest VMID
        vmid: u32,
    },
    /// List recent cluster-wide tasks, most recent first. Pass
    /// `--node X` to filter to a single node (uses the per-node
    /// task endpoint instead of the cluster-wide aggregator —
    /// faster + more detailed when one node is misbehaving).
    Tasks {
        /// Cap the number of tasks returned (default 50).
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// When set, fetch tasks from this node only (`/nodes/{n}/tasks`).
        #[arg(long)]
        node: Option<String>,
    },
    /// Real-time cluster event stream. Polls task queues across all nodes
    /// (or a single node with --node) and prints new task starts and
    /// completions as they happen. Press Ctrl-C to stop.
    Events {
        #[command(subcommand)]
        action: events::EventsCommand,
    },
    /// Cross-node `journalctl` tail with grep + time-range + unit
    /// filters. Fans `journalctl --follow` over every selected node
    /// via SSH; merges the streams locally and tags each line with
    /// its source node. Saves the daily "ssh to N nodes, run
    /// journalctl, eyeball-correlate" loop. Requires SSH configured
    /// in the profile.
    Logs {
        #[command(subcommand)]
        action: logs::LogsCommand,
    },
    /// Bundled error knowledge base — look up any typed error proxxx
    /// can emit and get cause / fixes / diagnostic commands /
    /// references. Ships with the binary; no network needed.
    /// Run `proxxx explain` (no args) for the catalog.
    Explain(explain::ExplainArgs),

    /// Incident-response primitives — cluster-wide write kill-switch.
    /// `freeze` halts every mutation entry point; `thaw` lifts it;
    /// `status` reports current state. Reads keep working.
    Incident {
        #[command(subcommand)]
        action: incident::IncidentCommand,
    },

    /// Structured cluster digest — one command, four formats. The
    /// `--output llm-context` variant is designed to paste at the
    /// top of an LLM chat: token-compact, prose+key:value mix, no
    /// markdown tables. Secrets are NEVER emitted regardless of
    /// flag.
    Describe(describe::DescribeArgs),

    /// Cloud-image provisioner — bundled SHA-256-pinned registry of
    /// cloud images, downloaded via PVE's `download-url` (server-side
    /// verified). Named `cloud-img` rather than `template` because
    /// the existing `proxxx template <vmid>` already covers marking a
    /// guest as a template (a different operation).
    CloudImg {
        #[command(subcommand)]
        action: cloudimg::CloudImgCommand,
    },

    /// Native scheduler for recurring proxxx operations. Each
    /// scheduled run flows through proxxx's existing dispatch path —
    /// audit log, pre-flight, HITL gate all apply. v1 uses
    /// interval-based scheduling (`--every 1d`); cron-syntax is
    /// tracked as a follow-up.
    Schedule {
        #[command(subcommand)]
        action: schedule::ScheduleCommand,
    },

    /// Unified background-task daemon — runs the alerts watcher,
    /// HITL Telegram listener, and schedule run-due tick under one
    /// process with a single SIGTERM handler. Each component can
    /// be opted out individually.
    Daemon {
        #[command(subcommand)]
        action: daemon::DaemonCommand,
    },

    /// Pre-flight scanner for PVE major-version upgrades (e.g.
    /// `--target 9.x`). Cluster + config scan; structured findings
    /// with severity (info/warn/block) for CI gating. Exit 0 on
    /// info+warn only, 1 on any block.
    UpgradeCheck(upgrade_check::UpgradeCheckArgs),

    /// Per-pool / per-node / per-tag resource accounting. Current
    /// state only — time-window aggregation deferred to a follow-up.
    Accounting(accounting::AccountingReportArgs),

    /// Per-node API latency probe. Colored table by RTT bucket
    /// (green/yellow/red), JSON for tooling.
    Heatmap(heatmap::HeatmapArgs),

    /// Rolling-baseline z-score anomaly detection across nodes for
    /// CPU + memory. Exit 0 = clean, 1 = anomalies found.
    Anomaly(anomaly::AnomalyArgs),

    /// Cross-cluster backup verification — metadata-level probe of
    /// each guest's most-recent backup. Exit 1 on any missing or
    /// corrupt manifest.
    BackupVerify(backup_verify::VerifyArgs),

    /// Unified VM image import — `qemu-img convert` wrapper for
    /// raw/qcow2/vmdk/vdi/vhdx/vhd → qcow2. Use `--dry-run` for
    /// inspect-only.
    Import(import_vm::ImportArgs),

    /// GPU / PCI passthrough inspection — IOMMU state, vfio
    /// readiness, lspci device map. Requires SSH configured.
    GpuInspect(gpu_passthrough::GpuInspectArgs),

    /// Cancel a running task. PVE first signals cleanly, then SIGKILLs
    /// after a grace period. Use when a vzdump/migration is wedged.
    TaskStop {
        /// Node hosting the task.
        #[arg(long)]
        node: String,
        /// Task UPID to cancel (full UPID:... string from `proxxx tasks`).
        #[arg(long)]
        upid: String,
        /// Required for non-interactive confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Pre-flight capability check on a guest: can it be snapshotted,
    /// cloned or copied with its current storage? Returns
    /// `{has_feature, nodes}`; for a QEMU VM, `nodes` lists the cluster
    /// nodes where the feature is available (PVE omits it for LXC).
    Feature {
        /// Guest VMID — auto-resolves to its node and guest type.
        vmid: u32,
        /// Feature to check. PVE 9 accepts only these three (measured:
        /// `migrate` and `replicate` are refused, audit #385).
        #[arg(long, value_enum)]
        feature: GuestFeature,
    },
    /// LXC template catalog (≈ `pveam`). `list` = available templates;
    /// `download` = pull one to a node's storage. Distinct from
    /// `proxxx storage` (content management) — this is the curated
    /// PVE upstream catalog.
    Aplinfo {
        #[command(subcommand)]
        action: storage::AplinfoCommand,
    },
    /// Pre-flight a URL for `download_to_storage`: returns size +
    /// filename + mimetype so the operator can size-check first.
    UrlInfo {
        #[arg(long)]
        node: String,
        #[arg(long)]
        url: String,
    },
    /// External metrics exporters (`InfluxDB` / Graphite). Cluster-wide
    /// CRUD on `/cluster/metrics/server`. Distinct from `proxxx metrics`
    /// which READS guest/node/storage RRD samples — this command
    /// configures the EXPORTERS that ship those samples elsewhere.
    MetricServers {
        #[command(subcommand)]
        action: monitoring::MetricServersCommand,
    },
    /// Trigger a vzdump backup of one or more guests to a target storage.
    /// All VMIDs must live on the same node (PVE limitation). Returns
    /// the task UPID — track via `proxxx tasks`.
    Backup {
        /// Guest VMID(s) to back up. Must all be on the same node.
        vmids: Vec<u32>,
        /// Target storage id (must support content type 'backup').
        #[arg(long)]
        storage: String,
        /// Backup mode: `snapshot` (default, no downtime),
        /// `suspend` (briefly pause), `stop` (cold backup).
        #[arg(long, default_value = "snapshot")]
        mode: String,
        /// Compression: `0` (none), `1` (lzo), `gzip`, `zstd`.
        #[arg(long)]
        compress: Option<String>,
        /// Block until the backup task completes. Without this, returns
        /// the UPID immediately and the caller must poll. With it,
        /// proxxx polls `/tasks/{upid}/status` and exits 0/1 based on
        /// task exitstatus — pipeline-friendly.
        #[arg(long)]
        wait: bool,
    },
    /// Convert a stopped guest into a template. **Irreversible** —
    /// PVE has no un-template endpoint. Templates cannot be started
    /// (PVE rejects); they exist only as a source for `proxxx clone`.
    /// QEMU and LXC both supported; guest must be stopped.
    Template {
        /// Guest VMID
        vmid: u32,
        /// Required for non-interactive use (irreversible action)
        #[arg(long)]
        yes: bool,
    },
    /// Clone a guest into a new VMID. The source can be a template
    /// (canonical IAC pattern) or a regular guest. For QEMU,
    /// `--full` produces an independent disk copy; without it, a
    /// linked clone backed by the source's base disk (fast, requires
    /// source to be a template). LXC clones are always full.
    Clone {
        /// Source guest VMID
        src_vmid: u32,
        /// Target VMID. If omitted, fetched from `GET /cluster/nextid`.
        #[arg(long)]
        newid: Option<u32>,
        /// Display name (QEMU) or hostname (LXC) of the new guest
        #[arg(long)]
        name: Option<String>,
        /// Target node. Defaults to the source node.
        #[arg(long)]
        target: Option<String>,
        /// Target storage. Required for cross-storage full clones.
        #[arg(long)]
        storage: Option<String>,
        /// Full clone (independent copy). Linked clone otherwise.
        /// LXC ignores this — clones are always full for containers.
        #[arg(long)]
        full: bool,
        /// Clone from a specific snapshot rather than running state.
        #[arg(long)]
        snapname: Option<String>,
        /// Description for the new guest.
        #[arg(long)]
        description: Option<String>,
        /// Cloud-init customization TOML file. Applied (and the
        /// cloud-init drive regenerated) after the clone task
        /// completes. QEMU-only. Supported keys: ciuser,
        /// cipassword, sshkey, `sshkey_file`, ipconfig0,
        /// searchdomain, nameserver.
        #[arg(long, value_name = "FILE")]
        cloud_init_user: Option<std::path::PathBuf>,
    },
    /// Manage snapshots
    Snapshot {
        #[command(subcommand)]
        action: vm::SnapshotCommand,
    },
    /// MCP server mode
    Mcp {
        #[command(subcommand)]
        action: McpCommand,
    },
    /// Watch for cluster changes or wait for a condition
    Watch {
        /// Show guest changes since a time ago, from the local state
        /// cache: a number with unit s, m, h, d or w (e.g. 30m, 6h, 1d).
        #[arg(long)]
        since: Option<String>,

        /// Target to watch: vm-<id> (or a bare <id>), storage-<id>, or
        /// storage-<id>@<node> for a node-local storage.
        #[arg(long, short)]
        target: Option<String>,

        /// Wait until condition is met: status=running|stopped|paused|suspended
        /// for a guest, usage=<70%, usage=>80% or usage=75% for storage.
        #[arg(long, short)]
        until: Option<String>,

        /// Abort watching after this many seconds (default 300)
        #[arg(long, default_value = "300")]
        timeout: u64,

        /// Channel to notify when condition is met (e.g. telegram)
        #[arg(long, short)]
        notify: Option<String>,
    },
    /// Replay the cluster state at a given timestamp
    Replay { timestamp: u64 },
    /// Cluster-wide fuzzy search across nodes, guests, and storage.
    /// Bug #4: was missing — caller would get clap "unknown subcommand".
    Search {
        /// Query string. Matches name, vmid, tags, status.
        query: String,
        /// Limit results (default 20).
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// HITL daemon management
    Hitl {
        #[command(subcommand)]
        action: HitlCommand,
    },
    /// Cluster patching orchestrator (apt update + dist-upgrade + rolling reboot)
    Patch {
        #[command(subcommand)]
        action: patch::PatchCommand,
    },
    /// Live disk operations (move between storage / grow). Destructive —
    /// requires `--yes`. Always routes through Proxmox API directly
    /// (CLI does not enqueue; the queue is a TUI concept).
    Disk {
        #[command(subcommand)]
        action: vm::DiskCommand,
    },
    /// ISO / cloud-image library (curated catalog + server-side download).
    Iso {
        #[command(subcommand)]
        action: storage::IsoCommand,
    },
    /// Proxmox Backup Server: list snapshots and restore archives.
    /// Read-only browse via REST API; restore shells out to
    /// `proxmox-backup-client` (Linux required).
    Pbs {
        #[command(subcommand)]
        action: storage::PbsCommand,
    },
    /// HA + replication console (read-only inspector).
    Ha {
        #[command(subcommand)]
        action: monitoring::HaCommand,
    },
    /// Storage replication jobs and per-node runtime status.
    Replication {
        #[command(subcommand)]
        action: monitoring::ReplicationCommand,
    },
    /// Hardware passthrough inventory + conflict detector (read-only).
    Hw {
        #[command(subcommand)]
        action: node::HwCommand,
    },
    /// Storage health (read-only): physical disks, SMART, LVM/LVM-thin/ZFS pools.
    /// Distinct from `proxxx disk` (singular, write-side disk operations on guest VMs).
    Disks {
        #[command(subcommand)]
        action: monitoring::DisksCommand,
    },
    /// Node-level operations: bulk power (start/stop/suspend ALL guests
    /// on a node at once). Distinct from per-VM `start/stop/suspend`
    /// commands which take VMIDs.
    Node {
        #[command(subcommand)]
        action: node::NodeCommand,
    },
    /// Time-series metrics (rrddata): historical CPU/mem/disk/net for
    /// guests, nodes, and storages. Default output is a Unicode block
    /// sparkline + min/max/avg summary; `--format json` emits raw
    /// rrddata for piping into jq / a charting tool.
    Metrics {
        #[command(subcommand)]
        action: monitoring::MetricsCommand,
    },
    /// Mint a one-shot VNC ticket for a guest (POST /vncproxy). Prints
    /// connection details (port, ticket, cert) as JSON. proxxx does
    /// NOT embed a VNC client — pipe to a noVNC URL builder, hand off
    /// to remote-viewer, or use `proxxx novnc` for the browser path.
    /// QEMU + LXC supported. Pass `--ws-url` to also emit the
    /// WebSocket-upgrade URL for hand-off to a noVNC client.
    Vnc {
        vmid: u32,
        /// Owning node — skip auto-discovery.
        #[arg(long)]
        node: Option<String>,
        /// Also emit the `wss://…/vncwebsocket?port=…&vncticket=…` URL.
        #[arg(long, default_value_t = false)]
        ws_url: bool,
    },
    /// Scheduled backup-job CRUD (recurring vzdump). Distinct from
    /// `proxxx backup` which triggers a one-shot. Common knobs are
    /// flagged; exotic params (exclude paths, hooks, etc.) accessible
    /// via the web UI or `proxxx backup-jobs raw-update`.
    BackupJobs {
        #[command(subcommand)]
        action: storage::BackupJobsCommand,
    },
    /// Cluster firewall CRUD — aliases, security groups, ipsets, and
    /// the global on/off + default policy. Read-only `proxxx firewall`
    /// covers rule listing across all three scopes; this command closes
    /// the CRUD half for the cluster-scope primitives.
    FirewallCluster {
        #[command(subcommand)]
        action: firewall::FirewallClusterCommand,
    },
    /// Per-guest firewall CRUD — aliases + per-guest options (enable,
    /// MAC filter, IP filter, DHCP/NDP auto-allow). VMID is auto-resolved
    /// to its node and guest type via the same scan `proxxx firewall
    /// --scope guest` uses.
    FirewallGuest {
        /// Guest VMID — node + guest type discovered automatically.
        vmid: u32,
        #[command(subcommand)]
        action: firewall::FirewallGuestCommand,
    },
    /// Cluster hardware mapping — stable logical names for PCI / USB
    /// passthrough devices. Lets a guest keep its passthrough binding
    /// across migrations between hosts where the device sits at a
    /// different bus address.
    ClusterMapping {
        #[command(subcommand)]
        action: firewall::ClusterMappingCommand,
    },
    /// QEMU Guest Agent file ops + network introspection. QEMU-only —
    /// LXC has no QGA. Bails clearly if pointed at an LXC. Common uses:
    /// peek at /etc/hostname inside a guest, drop a marker file, ask
    /// the guest "what IPs do you actually have."
    Qga {
        /// Guest VMID. Auto-resolved to its node; bails if not QEMU.
        vmid: u32,
        #[command(subcommand)]
        action: vm::QgaCommand,
    },
    /// Node system layer — DNS resolvers, /etc/hosts, NTP, journal,
    /// syslog, subscription, certificates, support report, wake-on-LAN.
    /// One command per node, sub-commands per resource.
    NodeSystem {
        /// Target node name (e.g. `pve1`).
        node: String,
        #[command(subcommand)]
        action: node::NodeSystemCommand,
    },
    /// Pool CRUD (multi-tenancy primitive). A pool is a named bag of
    /// guests + storages; ACL paths target it as `/pool/<name>`.
    Pool {
        #[command(subcommand)]
        action: cluster::PoolCommand,
    },
    /// Single-shot cluster-wide resource list — nodes, guests, storages,
    /// sdn objects, pools, networks — flattened. PVE web-UI's main
    /// dashboard query. Use `--kind` to keep one kind; omit for everything.
    ClusterResources {
        #[arg(long, value_enum)]
        kind: Option<cluster::ResourceKind>,
    },
    /// `GET /version` — PVE API version + git rev. Use for compat
    /// gating before invoking PVE-version-dependent endpoints.
    /// (Distinct from `proxxx version` which reports proxxx's own
    /// binary version.)
    PveVersion,
    /// Cluster-wide config: `mac_prefix`, default migration network,
    /// console viewer, `max_workers`, registered tags, etc. `get` shows
    /// the full config; `set` updates one or more fields.
    ClusterConfig {
        #[command(subcommand)]
        action: cluster::ClusterConfigCommand,
    },
    /// Cluster event log — login/lockout, task lifecycle, quorum
    /// changes. Newest entries first.
    ClusterLog {
        /// Cap on returned entries (PVE default ≈ 50, max ≈ 500).
        #[arg(long)]
        max: Option<u32>,
    },
    /// PVE 8+ native notification system — endpoints (delivery), matchers
    /// (routing rules), and targets (read-only valid-name list). Distinct
    /// from `proxxx alerts` which is the proxxx-side rule engine.
    Notifications {
        #[command(subcommand)]
        action: monitoring::NotificationsCommand,
    },
    /// Cluster-wide storage definitions CRUD — add/update/delete the
    /// storages PVE knows about (NFS, PBS, ZFS pool, dir, ...).
    /// Distinct from `proxxx storage` which manages CONTENT inside a
    /// storage (upload/delete files, ISOs, backups).
    StorageDefs {
        #[command(subcommand)]
        action: storage::StorageDefsCommand,
    },
    /// ACME (Let's Encrypt et al) cluster-wide config — accounts +
    /// challenge plugins + read-only `ToS` / directories / schema.
    /// Pairs with `proxxx node-system <node> cert acme-order` which
    /// triggers the actual cert order using these account/plugin configs.
    Acme {
        #[command(subcommand)]
        action: storage::AcmeCommand,
    },
    /// Corosync cluster bootstrap — node membership, join info,
    /// quorum-device, totem transport. Rare day-to-day but
    /// high-stakes (botched qdevice or node add can lose quorum and
    /// freeze HA).
    ClusterBootstrap {
        #[command(subcommand)]
        action: cluster::ClusterBootstrapCommand,
    },
    /// Alerting & notification routing (rule engine + Telegram/ntfy/webhook).
    Alerts {
        #[command(subcommand)]
        action: monitoring::AlertsCommand,
    },
    /// Access control: ACL, users, groups, roles, realms, TFA.
    Access {
        #[command(subcommand)]
        action: access::AccessCommand,
    },
    /// API token management (list / create / revoke).
    Token {
        #[command(subcommand)]
        action: access::TokenCommand,
    },
    /// Open the SPICE graphical console (QEMU only) by writing a `.vv`
    /// virt-viewer `ConfigFile` and launching `remote-viewer`. Falls back
    /// to the system default handler for `.vv` files when remote-viewer
    /// is not on PATH.
    Spice {
        /// Guest VMID (QEMU only).
        vmid: u32,
        #[arg(long)]
        node: String,
        /// Write the `.vv` to a fixed path instead of the temp dir.
        /// Useful for piping to a different launcher.
        #[arg(long)]
        write_vv: Option<std::path::PathBuf>,
        /// Don't auto-launch — print the `.vv` path and exit.
        #[arg(long)]
        no_launch: bool,
    },
    /// Open the noVNC console in the system browser. The user must
    /// already be logged into the Proxmox web UI (we do NOT inject
    /// auth tickets into the URL — that pattern leaks tokens via
    /// browser history). QEMU + LXC supported.
    Novnc {
        vmid: u32,
        #[arg(long)]
        node: String,
        /// Guest type. Auto-detected from cluster if omitted.
        #[arg(long, value_enum)]
        kind: Option<console::SerialKind>,
        /// Don't auto-launch — print the URL and exit.
        #[arg(long)]
        no_launch: bool,
    },
    /// Open a serial console to a guest via Proxmox termproxy (WebSocket).
    /// Useful for VM recovery when network/agent is dead. Puts the
    /// terminal in raw mode; press Ctrl+] then `q` to disconnect.
    Serial {
        /// Guest VMID.
        vmid: u32,
        /// Proxmox node hosting the guest.
        #[arg(long)]
        node: String,
        /// Guest type. Auto-detected from cluster if omitted.
        #[arg(long, value_enum)]
        kind: Option<console::SerialKind>,
        /// Record the session in asciinema cast v2 format. Pass a
        /// path to write there, or use `--record` alone to write to
        /// the default `<data_dir>/sessions/<ts>-<vmid>-serial.cast`.
        /// Operator keystrokes are recorded as `i` events; guest
        /// output as `o` events. Replay with `proxxx replay <path>`
        /// or any asciinema-compatible player.
        #[arg(long, num_args = 0..=1, default_missing_value = "")]
        record: Option<String>,
    },

    /// Console session recording — replay an asciinema cast v2
    /// file produced by `proxxx serial --record …`. Renders the
    /// recorded output with original timing; input events are
    /// skipped (only the operator's view is played back, not their
    /// keystrokes — same as `asciinema play`).
    PlayCast {
        /// Path to a `.cast` file.
        path: std::path::PathBuf,
        /// Playback speed multiplier. `1.0` is real-time; `2.0` is
        /// 2× faster; `0.5` is half speed. Negative / zero falls
        /// back to `1.0`.
        #[arg(long, default_value_t = 1.0)]
        speed: f64,
    },
    /// Open an interactive SSH session into a guest (NOT into the PVE
    /// node — for that, just `ssh root@<node>` directly). Per-guest
    /// connection details (host/IP, optional user/port/key override)
    /// are read from `[ssh.guests."<vmid>"]` in your config.toml.
    /// Spawns the system `ssh` so the operator's existing keys, agent,
    /// and `known_hosts` apply transparently. Press Ctrl+D or type `exit`
    /// to leave the session — return value is the remote shell's exit
    /// code (or `ssh`'s, if connection failed).
    Ssh {
        /// Guest VMID. Must have a `[ssh.guests."<vmid>"]` block in
        /// the config; without it, proxxx prints the exact TOML to
        /// paste in.
        vmid: u32,
        /// Optional remote command to run instead of an interactive
        /// shell (e.g. `--cmd "uptime"`). When present, ssh runs it
        /// non-interactively and exits.
        #[arg(long)]
        cmd: Option<String>,
    },
    /// Effective permissions for a user — shells out to `pveum user
    /// permissions` on a Proxmox node via SSH layer (SSH). Per the
    /// architectural review, we don't reimplement the algorithm; the
    /// Perl code on the node is the authority.
    Perms {
        /// User id (e.g. `oncall@pve`).
        userid: String,
        /// Optional path filter (e.g. `/vms/100`).
        #[arg(long)]
        path: Option<String>,
        /// Which Proxmox node to run `pveum` on (any one will do —
        /// they all share cluster ACL state).
        #[arg(long)]
        node: String,
    },
    /// Flight-recorder smoke test: trigger a controlled panic to verify the
    /// flight-recorder hook restores the terminal and writes the trace
    /// to the audit log. Use only as a manual smoke test.
    DevPanic {
        /// Panic message payload. Default `"manual smoke test"`.
        #[arg(long, default_value = "manual smoke test")]
        message: String,
    },
    /// Print build + capability metadata as JSON. The README links here
    /// instead of hardcoding test counts / subcommand counts / audit
    /// ignores — single source of truth, drift-proof. Use
    /// `proxxx version --json | jq` in scripts that need to assert
    /// "this binary has feature X" or "this binary's tests pass count
    /// is at least N".
    Version {
        /// Emit JSON (default true, the only mode currently). Reserved
        /// for a future `--text` short form.
        #[arg(long, default_value_t = true)]
        json: bool,
    },
    /// List named profiles defined in config.toml ([profiles.NAME] sections).
    /// Use `--profile NAME` to select one when starting the TUI or CLI.
    Profiles,
    /// Bootstrap a `config.toml` at the OS-default proxxx config
    /// directory (e.g. `~/.config/proxxx/config.toml` on Linux,
    /// `~/Library/Application Support/dev.proxxx.proxxx/config.toml`
    /// on macOS). Two flavours:
    ///
    ///   • `--interactive` — 5-step wizard prompting for URL, TLS,
    ///     auth, optional SSH (with `~/.ssh/` key auto-discovery
    ///     and per-guest overrides), optional Telegram. Each input
    ///     is probed live before write — wrong field caught at the
    ///     prompt, never lands in the TOML. Recommended for first-
    ///     time installs.
    ///   • Default (no flag) — write a commented starter template
    ///     for hand-editing. Fill in `url`, `user`, `token_id`,
    ///     `token_secret`, then `proxxx ls nodes` to validate.
    ///
    /// Both refuse to overwrite an existing config unless `--force`
    /// is passed (template-only path); the interactive flow offers
    /// backup-or-cancel instead.
    Init {
        /// Overwrite any existing config.toml at the target path.
        /// Without this flag, `init` refuses to clobber prior state.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Run an interactive wizard that prompts for URL, auth, TLS,
        /// optional SSH + Telegram, validates each input against the
        /// live cluster (anonymous version probe + token / password /
        /// ssh / telegram round-trips) and only writes the config if
        /// every probed field responded. First-mile UX: turns the
        /// 90 % of fresh-install failures ("config typo'd, error on
        /// first `ls nodes`") into "wrong field caught here, fix in
        /// place, never lands in TOML".
        #[arg(long, default_value_t = false)]
        interactive: bool,
    },
    /// Print shell completion script to stdout. Pipe to your shell's
    /// completion directory to enable tab-completion for proxxx.
    ///
    /// Examples:
    ///   proxxx completions bash >> ~/.bashrc
    ///   proxxx completions zsh > ~/.zfunc/_proxxx
    ///   proxxx completions fish > ~/.config/fish/completions/proxxx.fish
    ///   proxxx completions powershell >> $PROFILE
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },
    /// Read-only fleet view — a full-screen TUI that aggregates nodes,
    /// guests, and storage across EVERY configured `[profiles.NAME]`
    /// (clusters and standalone hosts, mixed) into one screen. Strictly
    /// read-only: no mutation path is reachable. Ignores `--profile`
    /// (it aggregates all of them). Launched as its own dedicated TUI
    /// runner; intercepted in `main.rs` before the CLI/stdout pipeline.
    Fleet,
    /// Self-diagnostic: validate config, cluster connectivity, auth,
    /// Telegram HITL, PBS, SSH key, and audit log in one pass. Prints
    /// a status table and exits 0 if all critical checks pass, 1 if
    /// any critical check fails.
    Doctor,
    /// Audit log management — view, export, and cryptographically verify
    /// the append-only mutation log.
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },
    /// Cluster state export + reconcile — the path toward declaratively
    /// versioned Proxmox clusters tracked in epic #74.
    ///
    /// v1 ships `state export` for the `pools` resource only. Future
    /// PRs add `state diff` / `state apply` plus the acl, storage,
    /// firewall-cluster, backup-jobs, and notifications families.
    State {
        #[command(subcommand)]
        action: state::StateCommand,
    },
    /// `GitOps` continuous reconciliation. `reconcile run` is a one-shot,
    /// CI-gateable drift check: diff a desired-state source (a local
    /// file, a directory, or a git repo) against live cluster state.
    /// Exit 0 = in sync, 2 = drift detected. Strictly read-only.
    Reconcile {
        #[command(subcommand)]
        action: reconcile::ReconcileCommand,
    },
    /// QEMU VM hardware/options/cloud-init management. The typed
    /// subcommands (`set`, `cloudinit`) cover the well-trodden config
    /// keys with parse-time validation; `raw-set` is the documented
    /// escape hatch for niche keys not yet typed (e.g. `smbios1`,
    /// NUMA topology). LXC is under `proxxx ct` instead.
    Vm {
        #[command(subcommand)]
        action: vm::VmCommand,
    },
    /// LXC container hardware/options management. Smaller surface
    /// than QEMU — no cloud-init, no VGA, etc. Same typed-vs-raw
    /// split as `proxxx vm`.
    Ct {
        #[command(subcommand)]
        action: ct::CtCommand,
    },
    /// Firewall management. PVE has three rule scopes (datacenter,
    /// node, guest); pick one. Read inspection plus full CRUD for
    /// aliases, IP sets, and security groups (cluster + guest scope).
    /// Individual allow/deny rule add/remove is not yet implemented —
    /// edit those via the PVE web UI or `pvesh` for now.
    Firewall {
        #[command(subcommand)]
        scope: firewall::FirewallScope,
    },
    /// Network interfaces on a node — physical NICs, bridges, bonds,
    /// VLANs — with up/down state and address config. Read-only.
    Network {
        /// Node name to inspect
        node: String,
    },
    /// Storage content management (upload local file to a storage,
    /// delete content item by volid). Read-side (`ls storage`) lives
    /// at the top-level `Ls`; this tree handles writes.
    Storage {
        #[command(subcommand)]
        action: storage::StorageCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum HitlCommand {
    /// Start the HITL Telegram daemon
    Serve,
}

#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Start MCP stdio server (JSON-RPC 2.0 over stdin/stdout)
    Serve,
    /// Start MCP HTTP server (Streamable HTTP transport, spec 2025-03-26)
    ServeHttp {
        /// Address to bind (default: 127.0.0.1)
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        /// Port to listen on (default: 3000)
        #[arg(long, default_value_t = 3000)]
        port: u16,
        /// Bearer token for auth (overrides `mcp_token` in config and survives SIGHUP reload).
        /// Visible in the process listing for as long as the server runs;
        /// prefer --token-file or `PROXXX_MCP_TOKEN`.
        #[arg(long)]
        token: Option<String>,
        /// Read the bearer token from a file; trailing whitespace is
        /// trimmed. Takes precedence over --token and `PROXXX_MCP_TOKEN`,
        /// which in turn win over `mcp_token` in config (#384).
        #[arg(long, value_name = "PATH")]
        token_file: Option<std::path::PathBuf>,
        /// DANGEROUS: allow binding to a non-loopback address WITHOUT auth.
        /// By default proxxx refuses to expose the MCP server on the network
        /// unless `mcp_token` (or --token) is set. Only pass this on a trusted
        /// network or behind an auth-enforcing reverse proxy.
        #[arg(long)]
        insecure_bind: bool,
        /// Additional Host/Origin authority (`<host[:port]>`) allowed on a
        /// non-loopback bind (repeatable).
        #[arg(long = "allowed-host", value_name = "HOST[:PORT]")]
        allowed_hosts: Vec<String>,
    },
    /// List available tools
    Tools {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        checksum: bool,
    },
}

/// Map a CLI [`Command`] to its canonical HITL action name (#338, #399).
///
/// Exhaustive over [`Command`] and every nested subcommand enum that contains a
/// mutation (no `_ =>` wildcard), so adding a new CLI subcommand fails to
/// compile until its destructive/non-destructive classification is explicitly
/// decided (#399). Read-only and non-destructive variants map to `None` (except
/// `start` and `snapshot` create, which retain their non-destructive HITL
/// names from #338).
#[must_use]
#[allow(clippy::too_many_lines)]
pub const fn cli_hitl_action(cmd: &Command) -> Option<&'static str> {
    match cmd {
        // Guest lifecycle — non-destructive:
        Command::Start { .. } => Some("start"),
        Command::Snapshot {
            action: vm::SnapshotCommand::Create { .. },
        } => Some("snapshot"),
        Command::Resume { .. } | Command::Clone { .. } => None,

        // Guest lifecycle & in-guest execution — destructive:
        Command::Stop { .. } => Some("stop"),
        Command::Restart { .. } => Some("restart"),
        Command::Delete { .. } => Some("delete"),
        Command::Suspend { .. } => Some("suspend"),
        Command::Migrate { .. } => Some("migrate"),
        Command::Exec { .. } => Some("exec"),
        Command::Template { .. } => Some("template"),
        Command::TaskStop { .. } => Some("task_stop"),
        Command::Backup { mode, .. } => {
            if matches!(mode.as_bytes(), b"stop" | b"suspend") {
                Some("backup_stop")
            } else {
                None
            }
        }
        Command::Snapshot {
            action: vm::SnapshotCommand::Delete { .. },
        } => Some("snapshot_delete"),
        Command::Disk {
            action: vm::DiskCommand::Move { .. },
        } => Some("move_disk"),
        Command::Disk {
            action: vm::DiskCommand::Resize { .. },
        } => Some("resize_disk"),
        Command::Qga { action, .. } => match action {
            vm::QgaCommand::Read { .. } | vm::QgaCommand::Net => None,
            vm::QgaCommand::Write { .. } => Some("qga_write"),
        },
        Command::Ssh { cmd, .. } => {
            if cmd.is_some() {
                Some("ssh_cmd")
            } else {
                None
            }
        }

        // VM / CT config & lifecycle subtrees:
        Command::Vm { action } => match action {
            vm::VmCommand::Set { .. }
            | vm::VmCommand::Cloudinit {
                action: vm::CloudinitCommand::Set { .. } | vm::CloudinitCommand::Regen { .. },
            }
            | vm::VmCommand::CloudinitDump { .. }
            | vm::VmCommand::Create { .. } => None,
            vm::VmCommand::RawSet { .. } => Some("vm_raw_set"),
            vm::VmCommand::Sendkey { .. } => Some("vm_sendkey"),
            vm::VmCommand::Unlink { .. } => Some("vm_unlink"),
        },
        Command::Ct { action } => match action {
            ct::CtCommand::Set { .. }
            | ct::CtCommand::Interfaces { .. }
            | ct::CtCommand::Create { .. } => None,
            ct::CtCommand::RawSet { .. } => Some("ct_raw_set"),
        },

        // Node operations & system configuration:
        Command::Node { action } => match action {
            node::NodeCommand::Startall { .. } | node::NodeCommand::Shell { .. } => None,
            node::NodeCommand::Stopall { .. } => Some("node_stopall"),
            node::NodeCommand::Suspendall { .. } => Some("node_suspendall"),
        },
        Command::NodeSystem { action, .. } => match action {
            node::NodeSystemCommand::Dns(
                node::NodeDnsCommand::Get | node::NodeDnsCommand::Set { .. },
            )
            | node::NodeSystemCommand::Hosts(
                node::NodeHostsCommand::Get | node::NodeHostsCommand::Set { .. },
            )
            | node::NodeSystemCommand::Journal { .. }
            | node::NodeSystemCommand::Syslog { .. }
            | node::NodeSystemCommand::Time(
                node::NodeTimeCommand::Get | node::NodeTimeCommand::Set { .. },
            )
            | node::NodeSystemCommand::Wol
            | node::NodeSystemCommand::Report => None,
            node::NodeSystemCommand::Subscription(sub) => match sub {
                node::NodeSubscriptionCommand::Get
                | node::NodeSubscriptionCommand::Set { .. }
                | node::NodeSubscriptionCommand::Refresh => None,
                node::NodeSubscriptionCommand::Delete { .. } => Some("node_subscription_delete"),
            },
            node::NodeSystemCommand::Cert(sub) => match sub {
                node::NodeCertCommand::Info
                | node::NodeCertCommand::Upload { .. }
                | node::NodeCertCommand::AcmeOrder { .. } => None,
                node::NodeCertCommand::Delete { .. } => Some("node_cert_delete"),
            },
        },
        Command::Patch { action } => match action {
            patch::PatchCommand::Plan { .. }
            | patch::PatchCommand::Repositories { .. }
            | patch::PatchCommand::Changelog { .. }
            | patch::PatchCommand::Versions { .. } => None,
            patch::PatchCommand::Apply { .. } => Some("patch_apply"),
        },
        Command::Hw { action } => match action {
            node::HwCommand::Pci { .. }
            | node::HwCommand::Usb { .. }
            | node::HwCommand::Conflicts { .. } => None,
        },

        // Cluster, HA, mappings, corosync bootstrap:
        Command::Ha { action } => match action {
            monitoring::HaCommand::Groups
            | monitoring::HaCommand::GroupsLegacy
            | monitoring::HaCommand::GroupCreate { .. }
            | monitoring::HaCommand::GroupUpdate { .. }
            | monitoring::HaCommand::Resources
            | monitoring::HaCommand::Status
            | monitoring::HaCommand::StatusCurrent
            | monitoring::HaCommand::Preview { .. } => None,
            monitoring::HaCommand::GroupDelete { .. } => Some("ha_group_delete"),
        },
        Command::ClusterMapping { action } => match action {
            firewall::ClusterMappingCommand::Pci(sub) => match sub {
                firewall::ClusterMappingPciCommand::List
                | firewall::ClusterMappingPciCommand::Create { .. }
                | firewall::ClusterMappingPciCommand::Update { .. } => None,
                firewall::ClusterMappingPciCommand::Delete { .. } => {
                    Some("cluster_mapping_pci_delete")
                }
            },
            firewall::ClusterMappingCommand::Usb(sub) => match sub {
                firewall::ClusterMappingUsbCommand::List
                | firewall::ClusterMappingUsbCommand::Create { .. }
                | firewall::ClusterMappingUsbCommand::Update { .. } => None,
                firewall::ClusterMappingUsbCommand::Delete { .. } => {
                    Some("cluster_mapping_usb_delete")
                }
            },
        },
        Command::ClusterConfig { action } => match action {
            cluster::ClusterConfigCommand::Get | cluster::ClusterConfigCommand::Set { .. } => None,
        },
        Command::ClusterBootstrap { action } => match action {
            cluster::ClusterBootstrapCommand::Totem => None,
            cluster::ClusterBootstrapCommand::Nodes(sub) => match sub {
                cluster::CorosyncNodesCommand::List => None,
                cluster::CorosyncNodesCommand::Add { .. } => Some("corosync_node_add"),
                cluster::CorosyncNodesCommand::Remove { .. } => Some("corosync_node_remove"),
            },
            cluster::ClusterBootstrapCommand::Join(sub) => match sub {
                cluster::ClusterJoinCommand::Info { .. } => None,
                cluster::ClusterJoinCommand::Join { .. } => Some("cluster_join"),
            },
            cluster::ClusterBootstrapCommand::Qdevice(sub) => match sub {
                cluster::ClusterQdeviceCommand::Get => None,
                cluster::ClusterQdeviceCommand::Setup { .. } => Some("qdevice_setup"),
                cluster::ClusterQdeviceCommand::Update { .. } => Some("qdevice_update"),
                cluster::ClusterQdeviceCommand::Delete { .. } => Some("qdevice_delete"),
            },
        },

        // Firewall:
        Command::FirewallCluster { action } => match action {
            firewall::FirewallClusterCommand::Alias(sub) => match sub {
                firewall::FirewallAliasCommand::List
                | firewall::FirewallAliasCommand::Create { .. } => None,
                firewall::FirewallAliasCommand::Update { .. } => Some("firewall_alias_update"),
                firewall::FirewallAliasCommand::Delete { .. } => Some("firewall_alias_delete"),
            },
            firewall::FirewallClusterCommand::Group(sub) => match sub {
                firewall::FirewallGroupCommand::List
                | firewall::FirewallGroupCommand::Create { .. }
                | firewall::FirewallGroupCommand::Rules { .. } => None,
                firewall::FirewallGroupCommand::Delete { .. } => Some("firewall_group_delete"),
            },
            firewall::FirewallClusterCommand::Ipset(sub) => match sub {
                firewall::FirewallIpsetCommand::List
                | firewall::FirewallIpsetCommand::Create { .. }
                | firewall::FirewallIpsetCommand::Cidrs { .. } => None,
                firewall::FirewallIpsetCommand::AddCidr { .. } => Some("firewall_ipset_add_cidr"),
                firewall::FirewallIpsetCommand::Delete { .. } => Some("firewall_ipset_delete"),
                firewall::FirewallIpsetCommand::RemoveCidr { .. } => {
                    Some("firewall_ipset_remove_cidr")
                }
            },
            firewall::FirewallClusterCommand::Options(sub) => match sub {
                firewall::FirewallOptionsCommand::Get => None,
                firewall::FirewallOptionsCommand::Set { .. } => Some("firewall_options_set"),
            },
        },
        Command::FirewallGuest { action, .. } => match action {
            firewall::FirewallGuestCommand::Alias(sub) => match sub {
                firewall::GuestFirewallAliasCommand::List
                | firewall::GuestFirewallAliasCommand::Create { .. } => None,
                firewall::GuestFirewallAliasCommand::Update { .. } => {
                    Some("guest_firewall_alias_update")
                }
                firewall::GuestFirewallAliasCommand::Delete { .. } => {
                    Some("guest_firewall_alias_delete")
                }
            },
            firewall::FirewallGuestCommand::Options(sub) => match sub {
                firewall::GuestFirewallOptionsCommand::Get => None,
                firewall::GuestFirewallOptionsCommand::Set { .. } => {
                    Some("guest_firewall_options_set")
                }
            },
        },
        Command::Firewall { .. } => None,

        // Access control, pools, API tokens:
        Command::Pool { action } => match action {
            cluster::PoolCommand::List
            | cluster::PoolCommand::Show { .. }
            | cluster::PoolCommand::Create { .. }
            | cluster::PoolCommand::AddMembers { .. }
            | cluster::PoolCommand::SetComment { .. } => None,
            cluster::PoolCommand::RemoveMembers { .. } => Some("pool_remove_members"),
            cluster::PoolCommand::Delete { .. } => Some("pool_delete"),
        },
        Command::Access { action } => match action {
            access::AccessCommand::Acl { .. }
            | access::AccessCommand::Users
            | access::AccessCommand::Groups
            | access::AccessCommand::Roles
            | access::AccessCommand::Realms
            | access::AccessCommand::Tfa { .. }
            | access::AccessCommand::UserCreate { .. }
            | access::AccessCommand::GroupCreate { .. }
            | access::AccessCommand::AclSet { .. }
            | access::AccessCommand::Permissions { .. } => None,
            access::AccessCommand::UserUpdate { .. } => Some("user_update"),
            access::AccessCommand::UserDelete { .. } => Some("user_delete"),
            access::AccessCommand::GroupDelete { .. } => Some("group_delete"),
            access::AccessCommand::AclUnset { .. } => Some("acl_unset"),
            access::AccessCommand::Password { .. } => Some("access_password"),
        },
        Command::Token { action } => match action {
            access::TokenCommand::List { .. } | access::TokenCommand::Create { .. } => None,
            access::TokenCommand::Revoke { .. } => Some("token_revoke"),
            access::TokenCommand::Bootstrap(args) => {
                if args.rotate {
                    Some("token_bootstrap_rotate")
                } else {
                    None
                }
            }
        },

        // Storage, backup jobs, ISO, templates, ACME, PBS, cloud-img:
        Command::Storage { action } => match action {
            storage::StorageCommand::Upload { .. } => None,
            storage::StorageCommand::Delete { .. } => Some("storage_delete"),
        },
        Command::StorageDefs { action } => match action {
            storage::StorageDefsCommand::List
            | storage::StorageDefsCommand::Show { .. }
            | storage::StorageDefsCommand::Create { .. } => None,
            storage::StorageDefsCommand::Update { .. } => Some("storage_def_update"),
            storage::StorageDefsCommand::Delete { .. } => Some("storage_def_delete"),
        },
        Command::BackupJobs { action } => match action {
            storage::BackupJobsCommand::List
            | storage::BackupJobsCommand::Show { .. }
            | storage::BackupJobsCommand::Create { .. }
            | storage::BackupJobsCommand::Update { .. }
            | storage::BackupJobsCommand::Info
            | storage::BackupJobsCommand::ExtractConfig { .. } => None,
            storage::BackupJobsCommand::Delete { .. } => Some("backup_job_delete"),
        },
        Command::Iso { action } => match action {
            storage::IsoCommand::List | storage::IsoCommand::Download { .. } => None,
        },
        Command::Aplinfo { action } => match action {
            storage::AplinfoCommand::List { .. } | storage::AplinfoCommand::Download { .. } => None,
        },
        Command::Acme { action } => match action {
            storage::AcmeCommand::Account(sub) => match sub {
                storage::AcmeAccountCommand::List
                | storage::AcmeAccountCommand::Show { .. }
                | storage::AcmeAccountCommand::Create { .. }
                | storage::AcmeAccountCommand::Update { .. } => None,
                storage::AcmeAccountCommand::Delete { .. } => Some("acme_account_delete"),
            },
            storage::AcmeCommand::Plugin(sub) => match sub {
                storage::AcmePluginCommand::List
                | storage::AcmePluginCommand::Show { .. }
                | storage::AcmePluginCommand::Create { .. }
                | storage::AcmePluginCommand::Update { .. } => None,
                storage::AcmePluginCommand::Delete { .. } => Some("acme_plugin_delete"),
            },
            storage::AcmeCommand::Directories
            | storage::AcmeCommand::Tos { .. }
            | storage::AcmeCommand::ChallengeSchema => None,
        },
        Command::Pbs { action } => match action {
            storage::PbsCommand::Ping
            | storage::PbsCommand::Datastores
            | storage::PbsCommand::Snapshots { .. }
            | storage::PbsCommand::Files { .. } => None,
            storage::PbsCommand::Restore { .. } => Some("pbs_restore"),
        },
        Command::CloudImg { action } => match action {
            cloudimg::CloudImgCommand::List { .. }
            | cloudimg::CloudImgCommand::Download { .. }
            | cloudimg::CloudImgCommand::Provision { .. } => None,
        },

        // Monitoring, alerts, notifications:
        Command::Alerts { action } => match action {
            monitoring::AlertsCommand::Eval
            | monitoring::AlertsCommand::Watch { .. }
            | monitoring::AlertsCommand::Test { .. } => None,
        },
        Command::MetricServers { action } => match action {
            monitoring::MetricServersCommand::List
            | monitoring::MetricServersCommand::Show { .. }
            | monitoring::MetricServersCommand::Create { .. }
            | monitoring::MetricServersCommand::Update { .. } => None,
            monitoring::MetricServersCommand::Delete { .. } => Some("metric_server_delete"),
        },
        Command::Notifications { action } => match action {
            monitoring::NotificationsCommand::Endpoint(sub) => match sub {
                monitoring::NotificationEndpointCommand::List
                | monitoring::NotificationEndpointCommand::Create { .. }
                | monitoring::NotificationEndpointCommand::Update { .. } => None,
                monitoring::NotificationEndpointCommand::Delete { .. } => {
                    Some("notification_endpoint_delete")
                }
            },
            monitoring::NotificationsCommand::Matcher(sub) => match sub {
                monitoring::NotificationMatcherCommand::List
                | monitoring::NotificationMatcherCommand::Create { .. }
                | monitoring::NotificationMatcherCommand::Update { .. } => None,
                monitoring::NotificationMatcherCommand::Delete { .. } => {
                    Some("notification_matcher_delete")
                }
            },
            monitoring::NotificationsCommand::Targets => None,
        },

        // Local schedules, incidents, audit, state, reconcile:
        Command::Schedule { action } => match action {
            schedule::ScheduleCommand::Add { .. }
            | schedule::ScheduleCommand::List { .. }
            | schedule::ScheduleCommand::Pause { .. }
            | schedule::ScheduleCommand::Resume { .. }
            | schedule::ScheduleCommand::RunDue { .. } => None,
            schedule::ScheduleCommand::Remove { .. } => Some("schedule_remove"),
        },
        Command::Incident { action } => match action {
            incident::IncidentCommand::Freeze { .. }
            | incident::IncidentCommand::Thaw { .. }
            | incident::IncidentCommand::Status => None,
        },
        Command::Audit { action } => match action {
            audit_cmd::AuditAction::Log { .. }
            | audit_cmd::AuditAction::Export { .. }
            | audit_cmd::AuditAction::Verify
            | audit_cmd::AuditAction::RotateKey => None,
        },
        Command::State { action } => match action {
            state::StateCommand::Export { .. } | state::StateCommand::Diff { .. } => None,
            state::StateCommand::Apply { .. } => Some("state_apply"),
        },
        Command::Reconcile { action } => match action {
            reconcile::ReconcileCommand::Run { .. } => None,
            reconcile::ReconcileCommand::Converge { .. } => Some("reconcile_converge"),
        },

        // Purely read-only, interactive console, or local daemon/utility commands:
        Command::Ls { .. }
        | Command::Find { .. }
        | Command::Config { .. }
        | Command::Tasks { .. }
        | Command::Events { .. }
        | Command::Logs { .. }
        | Command::Explain(..)
        | Command::Describe(..)
        | Command::Daemon { .. }
        | Command::UpgradeCheck(..)
        | Command::Accounting(..)
        | Command::Heatmap(..)
        | Command::Anomaly(..)
        | Command::BackupVerify(..)
        | Command::Import(..)
        | Command::GpuInspect(..)
        | Command::Feature { .. }
        | Command::UrlInfo { .. }
        | Command::Watch { .. }
        | Command::Replay { .. }
        | Command::Search { .. }
        | Command::Hitl { .. }
        | Command::Mcp { .. }
        | Command::Replication { .. }
        | Command::Disks { .. }
        | Command::Metrics { .. }
        | Command::Vnc { .. }
        | Command::ClusterResources { .. }
        | Command::PveVersion
        | Command::ClusterLog { .. }
        | Command::Spice { .. }
        | Command::Novnc { .. }
        | Command::Serial { .. }
        | Command::PlayCast { .. }
        | Command::Perms { .. }
        | Command::DevPanic { .. }
        | Command::Version { .. }
        | Command::Profiles
        | Command::Init { .. }
        | Command::Completions { .. }
        | Command::Fleet
        | Command::Doctor
        | Command::Network { .. } => None,
    }
}

/// The `mcp serve-http` bearer token from, in order, `--token-file`,
/// `--token` and `PROXXX_MCP_TOKEN` (#384: `--token` alone put it in the
/// process listing). An empty variable counts as unset; an empty file is
/// an error, since the operator plainly meant to set a token.
fn resolve_mcp_token(
    flag: Option<String>,
    file: Option<&std::path::Path>,
    env: Option<String>,
) -> Result<Option<String>> {
    if let Some(path) = file {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading --token-file {}: {e}", path.display()))?;
        let trimmed = raw.trim();
        anyhow::ensure!(
            !trimmed.is_empty(),
            "--token-file {} is empty",
            path.display()
        );
        return Ok(Some(trimmed.to_string()));
    }
    Ok(flag.or_else(|| env.filter(|t| !t.trim().is_empty())))
}

/// `--token-secret` / `--token-secret-file` hold ONE profile's secret
/// (#374). Fan-out commands talk to every configured profile, so passing
/// that secret on would send one cluster's credential to all of them.
/// Refuse instead of guessing which profile it was meant for.
pub fn refuse_cli_secret_for_fanout(cli_secret: Option<&str>, command: &str) -> Result<()> {
    if cli_secret.is_some() {
        return Err(crate::config::ConfigError::InvalidValue(format!(
            "--token-secret / --token-secret-file apply to a single profile, but `{command}` \
             contacts every configured profile; drop the flag so each profile resolves its \
             own secret (env var, token_secret_file or keychain)"
        ))
        .into());
    }
    Ok(())
}

/// Fail-closed `--secure` gate for the CLI (#338).
///
/// When `secure` is `true`, every destructive CLI command (as classified by
/// [`crate::hitl::is_destructive_action`]) refuses before any API call with a
/// typed [`crate::hitl::SecureModeRefusal`] (exit code 8). Non-destructive
/// commands pass through unchanged.
pub fn enforce_cli_secure_mode(cmd: &Command, secure: bool) -> Result<()> {
    if !secure {
        return Ok(());
    }
    if let Some(action) = cli_hitl_action(cmd) {
        if crate::hitl::is_destructive_action(action) {
            return Err(crate::hitl::SecureModeRefusal { action }.into());
        }
    }
    Ok(())
}

/// Argument ids of the per-command output flags that the global
/// `--format json` stands in for (#362).
pub const LOCAL_OUTPUT_FLAG_IDS: &[&str] = &["output", "print", "json"];

/// Make the global `--format json` (or `json-envelope`) select JSON for the
/// commands that have their own output flag, unless that flag was given
/// explicitly (#362). These commands print their own output, and the
/// global flag used to be ignored: `proxxx --format json describe` printed
/// text and exited 0, so `| jq` failed. Their JSON is printed as is, not
/// wrapped in the envelope.
pub const fn honour_global_json(
    cmd: &mut Command,
    format: crate::util::format::OutputFormat,
    local_flag_given: bool,
) {
    use crate::util::format::OutputFormat;
    if local_flag_given || !matches!(format, OutputFormat::Json | OutputFormat::JsonEnvelope) {
        return;
    }
    match cmd {
        Command::Explain(a) => a.output = explain::ExplainFormat::Json,
        Command::Describe(a) => a.output = describe::DescribeFormat::Json,
        Command::UpgradeCheck(a) => a.output = upgrade_check::UpgradeOutput::Json,
        Command::Accounting(a) => a.output = accounting::AccountingOutput::Json,
        Command::Heatmap(a) => a.output = heatmap::HeatmapOutput::Json,
        Command::Anomaly(a) => a.output = anomaly::AnomalyOutput::Json,
        Command::BackupVerify(a) => a.output = backup_verify::VerifyOutput::Json,
        Command::Import(a) => a.print = import_vm::ImportOutput::Json,
        Command::GpuInspect(a) => a.output = gpu_passthrough::GpuOutput::Json,
        Command::CloudImg { action } => match action {
            cloudimg::CloudImgCommand::List { output }
            | cloudimg::CloudImgCommand::Provision { output, .. } => {
                *output = cloudimg::CloudImgOutput::Json;
            }
            cloudimg::CloudImgCommand::Download { .. } => {}
        },
        Command::Schedule {
            action: schedule::ScheduleCommand::List { output },
        } => *output = schedule::ScheduleOutput::Json,
        Command::State { action } => match action {
            state::StateCommand::Export { output, .. } => *output = state::ExportFormat::Json,
            state::StateCommand::Diff { output, .. } => *output = state::DiffFormat::Json,
            state::StateCommand::Apply { output, .. } => {
                *output = state::ApplyOutputFormat::Json;
            }
        },
        Command::Reconcile { action } => match action {
            reconcile::ReconcileCommand::Run { json, .. }
            | reconcile::ReconcileCommand::Converge { json, .. } => *json = true,
        },
        Command::Mcp {
            action: McpCommand::Tools { json, .. },
        } => *json = true,
        _ => {}
    }
}

/// Execute a CLI command — returns JSON-serializable result and exit code.
#[allow(clippy::too_many_lines)] // audit #272: wide, flat dispatch — see Cargo.toml
pub async fn execute(
    cmd: Command,
    profile: Option<&str>,
    cli_secret: Option<&str>,
    secure: bool,
    format: crate::util::format::OutputFormat,
) -> Result<(Value, i32)> {
    enforce_cli_secure_mode(&cmd, secure)?;

    // MCP introspection commands don't need a Proxmox connection
    if let Command::Mcp {
        action: McpCommand::Tools { json, checksum },
    } = &cmd
    {
        let value = if *checksum {
            serde_json::json!({"checksum": crate::mcp::tools::registry_checksum()})
        } else {
            crate::mcp::tools::registry_json()
        };
        // `--json` (also set by the global `--format json`) prints the
        // document as is; it used to be ignored, so the output followed
        // `--format` and came wrapped in an array (audit #385).
        if *json {
            // raw-output: the registry is a JSON document; escaping it would change the data
            println!("{}", serde_json::to_string_pretty(&value)?);
            return Ok((Value::Null, 0));
        }
        return Ok((value, 0));
    }

    // `version` is the only command that doesn't need a live PVE
    // connection — it's pure self-introspection. Short-circuit BEFORE
    // building PxClient so users without a configured profile can still
    // run `proxxx version --json` (CI scripts, container health probes,
    // README badge generators).
    if let Command::Version { json } = &cmd {
        let payload = build_version_payload();
        // `version` is JSON only. Under `--format table` it relied on the
        // table renderer printing objects as pretty JSON; objects are now
        // key/value rows (#385), so it prints its JSON itself there. Every
        // other format goes through the usual pipeline, unchanged.
        if *json && matches!(format, crate::util::format::OutputFormat::Table) {
            // raw-output: the version document is JSON; escaping it would change the data
            println!("{}", serde_json::to_string_pretty(&payload)?);
            return Ok((Value::Null, 0));
        }
        return Ok((payload, 0));
    }

    // First-run UX: `proxxx init` MUST work on a fresh machine that
    // has no config.toml yet — that's the entire point. Short-circuit
    // before `load_config` so the "Config not found" error doesn't
    // catch the very command meant to fix it. (Audit-discovered
    // landmine: prior to this short-circuit the error message
    // recommended `proxxx init` but the command did not exist —
    // dismiss-after-five-seconds territory.)
    if let Command::Init { force, interactive } = &cmd {
        // The global `--profile <name>` doubles as "which profile to
        // create": `proxxx init --profile prod` APPENDS a [profiles.prod]
        // block (preserving any existing profiles); bare `proxxx init`
        // writes the flat starter template.
        if *interactive {
            return init_wizard::run(profile).await;
        }
        return init::execute(*force, profile);
    }

    // `proxxx profiles` lists named profiles without needing a valid config.
    if matches!(&cmd, Command::Profiles) {
        let names = crate::config::list_profiles()?;
        let val = if names.is_empty() {
            serde_json::json!({ "profiles": [], "hint": "Add [profiles.NAME] sections to config.toml to define named profiles." })
        } else {
            serde_json::json!({ "profiles": names })
        };
        return Ok((val, 0));
    }

    // Flight-recorder smoke: `dev-panic` is the panic-hook test fuel — it
    // intentionally panics regardless of cluster connectivity. The
    // integration test in `tests/panic_hook_test.rs` runs proxxx as a
    // subprocess on a clean CI runner with no config.toml; without
    // this short-circuit it would die with "Config not found" BEFORE
    // panicking, defeating the test.
    if let Command::DevPanic { message } = &cmd {
        #[allow(clippy::panic)]
        {
            panic!("[dev-panic] {message}");
        }
    }

    // `--all-profiles` short-circuits BEFORE load_config(profile) — the
    // fanout creates its own per-profile PxClient internally; a single
    // top-level profile selection would be ignored. Equally, `find`
    // is always cross-profile (no `--profile` makes sense for it).
    if let Command::Ls {
        resource,
        all_profiles: true,
    } = &cmd
    {
        let kind = fanout::FanoutKind::from_resource(resource).ok_or_else(|| {
            anyhow::anyhow!(
                "--all-profiles is supported on `ls nodes|guests|storage` (got `{resource}`)"
            )
        })?;
        refuse_cli_secret_for_fanout(cli_secret, "ls --all-profiles")?;
        let rows = fanout::fanout_ls(kind, None).await?;
        let exit = i32::from(rows.iter().any(fanout::ProfileRow::is_error));
        return Ok((serde_json::to_value(rows)?, exit));
    }
    if let Command::Find { vmid } = &cmd {
        refuse_cli_secret_for_fanout(cli_secret, "find")?;
        let rows = fanout::fanout_find_vmid(*vmid, None).await?;
        // #322: exit 5 (NotFound) ONLY when every profile answered without
        // error and none owns the VMID. If any profile errored, exit 1 and
        // still return `rows` so the operator sees which profile failed.
        let exit = if rows.is_empty() {
            5
        } else {
            i32::from(rows.iter().any(fanout::ProfileRow::is_error))
        };
        return Ok((serde_json::to_value(rows)?, exit));
    }

    if matches!(cmd, Command::Doctor) {
        return doctor::run_for_profile(profile).await;
    }

    if let Command::Audit { ref action } = cmd {
        return match action {
            AuditAction::Log { limit, since } => audit_cmd::execute_log(*limit, since.as_deref()),
            AuditAction::Export {
                export_format,
                limit,
                since,
            } => audit_cmd::execute_export(*export_format, *limit, since.as_deref()),
            AuditAction::Verify => audit_cmd::execute_verify(),
            AuditAction::RotateKey => audit_cmd::execute_rotate_key(),
        };
    }

    let config = crate::config::load_config(profile)?;
    if let Command::Pbs { action } = cmd {
        return storage::execute_pbs(&config, action, cli_secret).await;
    }
    if let Command::Token {
        action: access::TokenCommand::Bootstrap(ref args),
    } = cmd
    {
        return token_bootstrap::execute_token_bootstrap(&config, args).await;
    }
    let client = std::sync::Arc::new(crate::api::PxClient::new(config.clone(), cli_secret).await?);

    use crate::api::ProxmoxGateway;

    match cmd {
        Command::Ls {
            resource,
            all_profiles: _, // already handled in the short-circuit above when true
        } => match resource.as_str() {
            "nodes" => {
                let nodes = client.get_nodes().await?;
                Ok((serde_json::to_value(nodes)?, 0))
            }
            "guests" => Ok((serde_json::to_value(client.get_all_guests().await?)?, 0)),
            "storage" => {
                let (pools, skipped) = client.get_all_storage_pools_and_skipped().await?;
                // #352: an offline node's pools are not in the list; say so.
                if !skipped.is_empty() {
                    eprintln!(
                        "note: not listed, node not online: {}",
                        skipped
                            .iter()
                            .map(|n| crate::util::sanitize::sanitize_display(n).into_owned())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                }
                Ok((serde_json::to_value(pools)?, 0))
            }
            other => anyhow::bail!("Unknown resource: {other}. Use: nodes, guests, storage"),
        },
        Command::Start {
            vmids,
            strict,
            policy,
        } => {
            let bp = crate::cli::common::BatchPolicy::parse(&policy)?;
            execute_batch_op_with_policy(&client, BatchOp::Start, &vmids, &config, strict, bp).await
        }
        Command::Stop {
            vmids,
            force,
            strict,
            allow_risk,
            stop_timeout,
            policy,
        } => {
            for &vmid in &vmids {
                let g = find_guest_full(&client, vmid).await?;
                enforce_preflight(
                    &client,
                    None,
                    crate::app::preflight::Op::Stop,
                    &g,
                    allow_risk,
                )
                .await?;
            }
            let bp = crate::cli::common::BatchPolicy::parse(&policy)?;
            execute_batch_op_with_policy(
                &client,
                BatchOp::Stop {
                    force,
                    timeout_secs: stop_timeout,
                },
                &vmids,
                &config,
                strict,
                bp,
            )
            .await
        }
        Command::Restart {
            vmids,
            strict,
            allow_risk,
            policy,
        } => {
            for &vmid in &vmids {
                let g = find_guest_full(&client, vmid).await?;
                enforce_preflight(
                    &client,
                    None,
                    crate::app::preflight::Op::Restart,
                    &g,
                    allow_risk,
                )
                .await?;
            }
            let bp = crate::cli::common::BatchPolicy::parse(&policy)?;
            execute_batch_op_with_policy(&client, BatchOp::Restart, &vmids, &config, strict, bp)
                .await
        }
        Command::Suspend {
            vmids,
            strict,
            policy,
        } => {
            // No preflight: suspend is non-destructive (RAM frozen,
            // no state lost on resume). Mirror Restart's batch-op
            // dispatch shape.
            let bp = crate::cli::common::BatchPolicy::parse(&policy)?;
            execute_batch_op_with_policy(&client, BatchOp::Suspend, &vmids, &config, strict, bp)
                .await
        }
        Command::Resume {
            vmids,
            strict,
            policy,
        } => {
            let bp = crate::cli::common::BatchPolicy::parse(&policy)?;
            execute_batch_op_with_policy(&client, BatchOp::Resume, &vmids, &config, strict, bp)
                .await
        }
        Command::Delete {
            vmids,
            yes,
            strict,
            allow_risk,
        } => {
            crate::cli::common::require_yes(yes, "guest delete")?;
            for &vmid in &vmids {
                let g = find_guest_full(&client, vmid).await?;
                // Delete is the only op where backup-recency matters —
                // build a PBS client opportunistically (when configured)
                // so the preflight covers PBS-tracked snapshots too.
                // #374: the CLI secret belongs to the PVE profile, so the PBS
                // client resolves its own (PROXXX_PBS_TOKEN_SECRET, file,
                // keychain). If PBS is configured but its client cannot be
                // built, the backup-recency check is reported as skipped
                // instead of silently dropping PBS from it.
                let (pbs_for_preflight, pbs_unavailable) = match config.pbs.as_ref() {
                    Some(cfg) => match crate::pbs::PbsClient::new(cfg.clone(), None).await {
                        Ok(c) => (Some(c), None),
                        Err(e) => (None, Some(format!("{e:#}"))),
                    },
                    None => (None, None),
                };
                crate::cli::common::enforce_preflight_with_notes(
                    &client,
                    pbs_for_preflight.as_ref(),
                    crate::app::preflight::Op::Delete,
                    &g,
                    allow_risk,
                    pbs_unavailable.map(|e| {
                        format!(
                            "PBS is configured but its client could not be built, so PBS \
                             backups were not checked: {e}"
                        )
                    }),
                )
                .await?;
            }
            execute_delete(&client, &vmids, strict).await
        }
        Command::Migrate {
            vmid,
            target,
            yes,
            with_local_disks,
            allow_risk,
            wait,
            stream,
        } => {
            crate::cli::common::require_yes(yes, "guest migration")?;
            let g = find_guest_full(&client, vmid).await?;
            if g.node == target {
                anyhow::bail!("guest {vmid} is already on {target}");
            }
            enforce_preflight(
                &client,
                None,
                crate::app::preflight::Op::Migrate,
                &g,
                allow_risk,
            )
            .await?;
            // Auto-detect the right PVE migration semantics:
            //   QEMU running → online=1 (live RAM transfer)
            //   LXC running  → restart=1 (PVE has no live container
            //                  migration; shutdown+migrate+restart)
            //   Either stopped → no flag, plain offline migration
            // The user shouldn't have to remember which is which.
            let is_running = matches!(g.status, crate::api::types::GuestStatus::Running);
            let online = is_running && matches!(g.guest_type, crate::api::types::GuestType::Qemu);
            let restart = is_running && matches!(g.guest_type, crate::api::types::GuestType::Lxc);
            let upid = client
                .migrate_guest(
                    &g.node,
                    vmid,
                    g.guest_type,
                    &target,
                    online,
                    with_local_disks,
                    restart,
                )
                .await?;
            let envelope = serde_json::json!({
                "vmid": vmid,
                "from": g.node,
                "to": target,
                "online": online,
                "restart": restart,
                "with_local_disks": with_local_disks,
                "task": upid,
            });
            if stream {
                // `--stream` implies `--wait` — print a request
                // header so the user sees what we're about to do
                // (the streamer's output otherwise starts directly
                // with the first log line and feels disconnected
                // from the invocation).
                let json_mode = matches!(
                    format,
                    util::format::OutputFormat::Json | util::format::OutputFormat::JsonEnvelope
                );
                if !json_mode {
                    eprintln!(
                        "migrating vmid={vmid} {from} → {to} (task {upid})",
                        from = g.node,
                        to = target,
                    );
                }
                let status = if json_mode {
                    let mut renderer = migrate_progress::NdjsonRenderer {
                        writer: std::io::stdout(),
                    };
                    migrate_progress::stream_migration(
                        client.as_ref(),
                        &g.node,
                        &upid,
                        &mut renderer,
                        1500,
                        0,
                    )
                    .await?
                } else {
                    let mut renderer = migrate_progress::TtyRenderer::new();
                    migrate_progress::stream_migration(
                        client.as_ref(),
                        &g.node,
                        &upid,
                        &mut renderer,
                        1500,
                        0,
                    )
                    .await?
                };
                let exit = i32::from(!status.is_success());
                Ok((
                    serde_json::json!({
                        "request": envelope,
                        "task_status": serde_json::to_value(status)?,
                    }),
                    exit,
                ))
            } else if wait {
                let (status_json, exit) = wait_and_classify(&client, &g.node, &upid).await?;
                Ok((
                    serde_json::json!({
                        "request": envelope,
                        "task_status": status_json,
                    }),
                    exit,
                ))
            } else {
                Ok((envelope, 0))
            }
        }
        Command::Exec { vmid, command } => {
            let (node, gt) = find_guest(&client, vmid).await?;
            let cmd_str = command.join(" ");
            let result = client
                .execute_guest_command(&node, vmid, &gt, &cmd_str)
                .await?;
            // Propagate the guest's exit code so shell pipelines work
            // (`proxxx exec 100 -- false; echo $?` prints 1). LXC
            // bails earlier in the API layer with a path-forward
            // message — see `execute_guest_command` doc.
            Ok((
                serde_json::json!({
                    "vmid": vmid,
                    "node": node,
                    "command": cmd_str,
                    "exit_code": result.exit_code,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }),
                result.exit_code,
            ))
        }
        Command::Config { vmid } => {
            let (node, gt) = find_guest(&client, vmid).await?;
            let cfg = client.get_guest_config(&node, vmid, &gt).await?;
            Ok((serde_json::to_value(cfg)?, 0))
        }
        Command::Events { action } => events::execute_events(&client, action, format).await,
        Command::Logs { action } => {
            let render = if matches!(
                format,
                util::format::OutputFormat::Json | util::format::OutputFormat::JsonEnvelope
            ) {
                logs::LogsRenderMode::Json
            } else {
                logs::LogsRenderMode::Text
            };
            logs::execute_logs(&config, &client, action, render).await
        }
        Command::Explain(args) => explain::execute_explain(args),
        Command::Incident { action } => incident::execute_incident(action),
        Command::Describe(args) => describe::execute_describe(&client, args).await,
        Command::CloudImg { action } => cloudimg::execute_cloudimg(&client, action).await,
        Command::Schedule { action } => schedule::execute_schedule(action, secure),
        Command::Daemon { action } => {
            let handle = crate::config::watcher::new_handle(config.clone());
            client.attach_live_config(std::sync::Arc::clone(&handle));
            crate::config::watcher::spawn_reload_on_sighup(
                std::sync::Arc::clone(&handle),
                profile.map(str::to_owned),
            );
            daemon::execute_daemon(&client, handle, config.clone(), action, secure).await
        }
        Command::UpgradeCheck(args) => {
            upgrade_check::execute_upgrade_check(&client, &config, args).await
        }
        Command::Accounting(args) => accounting::execute_accounting(&client, args).await,
        Command::Heatmap(args) => heatmap::execute_heatmap(&client, args).await,
        Command::Anomaly(args) => anomaly::execute_anomaly(&client, args).await,
        Command::BackupVerify(args) => backup_verify::execute_verify(&client, args).await,
        Command::Import(args) => import_vm::execute_import(&args),
        Command::GpuInspect(args) => {
            gpu_passthrough::execute_gpu_inspect(&client, &config, args).await
        }
        Command::Tasks { limit, node } => {
            let tasks = if let Some(n) = node {
                client
                    .list_node_tasks(&n, Some(u32::try_from(limit).unwrap_or(50)))
                    .await?
            } else {
                let mut all = client.get_cluster_tasks().await?;
                // #354: `/cluster/tasks` holds only the recent tasks PVE
                // keeps cluster-wide (50 on PVE 9.1), so a larger
                // `--limit` used to return fewer rows without a word.
                if all.len() < limit {
                    eprintln!(
                        "note: the cluster-wide task list returned {} task(s), fewer than \
                         --limit {limit}; use --node <name> to list more of one node's tasks",
                        all.len()
                    );
                }
                all.truncate(limit);
                all
            };
            Ok((serde_json::to_value(tasks)?, 0))
        }
        Command::TaskStop { node, upid, yes } => {
            crate::cli::common::require_yes(yes, "task stop")?;
            client.stop_node_task(&node, &upid).await?;
            Ok((serde_json::json!({"stopped": upid, "node": node}), 0))
        }
        Command::Feature { vmid, feature } => {
            let feature = feature.as_str();
            let (node, gt) = find_guest(&client, vmid).await?;
            let res = client.get_guest_feature(&node, vmid, gt, feature).await?;
            Ok((
                serde_json::json!({
                    "vmid": vmid,
                    "node": node,
                    "feature": feature,
                    "has_feature": res.has_feature,
                    "nodes": res.nodes,
                }),
                0,
            ))
        }
        Command::Aplinfo { action } => storage::execute_aplinfo(&client, action).await,
        Command::UrlInfo { node, url } => {
            let meta = client.query_url_metadata(&node, &url).await?;
            Ok((serde_json::to_value(meta)?, 0))
        }
        Command::MetricServers { action } => {
            monitoring::execute_metric_servers(&client, action).await
        }
        Command::Backup {
            vmids,
            storage,
            mode,
            compress,
            wait,
        } => {
            let first_vmid = *vmids
                .first()
                .ok_or_else(|| anyhow::anyhow!("at least one VMID is required"))?;
            let (target_node, _) = find_guest(&client, first_vmid).await?;
            for &vmid in vmids.iter().skip(1) {
                let (n, _) = find_guest(&client, vmid).await?;
                if n != target_node {
                    anyhow::bail!(
                        "VMID {vmid} is on node {n}, but {first_vmid} is on {target_node}; \
                         vzdump cannot span nodes — split into one call per node"
                    );
                }
            }
            // Validate mode at the CLI boundary so the user gets a
            // friendly error instead of PVE's generic schema 400.
            let valid_modes = ["snapshot", "suspend", "stop"];
            if !valid_modes.contains(&mode.as_str()) {
                anyhow::bail!(
                    "invalid backup mode '{mode}'; valid values: {}",
                    valid_modes.join(", ")
                );
            }
            let upid = client
                .create_backup(&target_node, &vmids, &storage, &mode, compress.as_deref())
                .await?;
            let envelope = serde_json::json!({
                "node": target_node,
                "vmids": vmids,
                "storage": storage,
                "mode": mode,
                "compress": compress,
                "task": upid,
            });
            if wait {
                let (status_json, exit) = wait_and_classify(&client, &target_node, &upid).await?;
                Ok((
                    serde_json::json!({
                        "request": envelope,
                        "task_status": status_json,
                    }),
                    exit,
                ))
            } else {
                Ok((envelope, 0))
            }
        }
        Command::Template { vmid, yes } => {
            crate::cli::common::require_yes(yes, "template conversion")?;
            let (node, gt) = find_guest(&client, vmid).await?;
            let _ = client.convert_to_template(&node, vmid, gt).await?;
            Ok((
                serde_json::json!({
                    "vmid": vmid,
                    "node": node,
                    "guest_type": format!("{gt:?}").to_lowercase(),
                    "status": "templated",
                }),
                0,
            ))
        }
        Command::Clone {
            src_vmid,
            newid,
            name,
            target,
            storage,
            full,
            snapname,
            description,
            cloud_init_user,
        } => {
            let (src_node, gt) = find_guest(&client, src_vmid).await?;
            // Auto-fetch newid only when the user didn't pin one — saves
            // a round-trip on the common explicit case while keeping the
            // ergonomic `proxxx clone 9000` (no flags) workflow.
            let target_id = match newid {
                Some(n) => n,
                None => client.next_free_vmid().await?,
            };
            // Parse profile up-front so a malformed file fails before
            // we burn the clone task.
            let profile = match &cloud_init_user {
                Some(p) => Some(vm::CloudInitProfile::from_toml_file(p)?),
                None => None,
            };
            // The clone lands on the *target* node (or src node if not
            // pinned). Cloud-init mutations must hit the post-clone
            // location, not src.
            let landing_node = target.clone().unwrap_or_else(|| src_node.clone());
            let upid = client
                .clone_guest(
                    &src_node,
                    src_vmid,
                    gt,
                    target_id,
                    name.as_deref(),
                    target.as_deref(),
                    storage.as_deref(),
                    full,
                    snapname.as_deref(),
                    description.as_deref(),
                )
                .await?;
            let cloudinit_result = if let Some(profile) = profile {
                // Block until the clone task finishes — applying
                // cloudinit before the disk image lands races PVE's
                // own locking and returns a generic 500.
                let status =
                    crate::cli::common::poll_task_until_done(client.as_ref(), &src_node, &upid, 0)
                        .await?;
                if !status.is_success() {
                    anyhow::bail!(
                        "clone task did not succeed (status={:?}); skipping cloud-init apply",
                        status.exitstatus
                    );
                }
                Some(
                    vm::apply_cloudinit_and_regen(
                        client.as_ref(),
                        &landing_node,
                        target_id,
                        gt,
                        &profile,
                    )
                    .await?,
                )
            } else {
                None
            };
            Ok((
                serde_json::json!({
                    "src_vmid": src_vmid,
                    "src_node": src_node,
                    "newid": target_id,
                    "name": name,
                    "target": target,
                    "storage": storage,
                    "full": full,
                    "snapname": snapname,
                    "task": upid,
                    "cloudinit": cloudinit_result,
                }),
                0,
            ))
        }
        Command::Snapshot { action } => vm::execute_snapshot(&client, action).await,
        Command::Mcp { action } => match action {
            McpCommand::Serve => {
                let handle = crate::config::watcher::new_handle(config);
                client.attach_live_config(std::sync::Arc::clone(&handle));
                crate::config::watcher::spawn_reload_on_sighup(
                    std::sync::Arc::clone(&handle),
                    profile.map(str::to_owned),
                );
                crate::mcp::server::run_server(std::sync::Arc::clone(&client), handle).await?;
                Ok((serde_json::json!({"status": "MCP server stopped"}), 0))
            }
            McpCommand::ServeHttp {
                bind,
                port,
                token,
                token_file,
                insecure_bind,
                allowed_hosts,
            } => {
                // Keep CLI --token OUT of the reloadable config (#343) so a
                // SIGHUP reload can never drop a token given on the command line.
                let cli_token = resolve_mcp_token(
                    token,
                    token_file.as_deref(),
                    std::env::var("PROXXX_MCP_TOKEN").ok(),
                )?
                .map(crate::util::secret::SecretString::new);
                let handle = crate::config::watcher::new_handle(config);
                client.attach_live_config(std::sync::Arc::clone(&handle));
                crate::config::watcher::spawn_reload_on_sighup(
                    std::sync::Arc::clone(&handle),
                    profile.map(str::to_owned),
                );
                crate::mcp::http_server::run_http_server_with_options(
                    std::sync::Arc::clone(&client),
                    handle,
                    &bind,
                    port,
                    insecure_bind,
                    cli_token,
                    &allowed_hosts,
                )
                .await?;
                Ok((serde_json::json!({"status": "MCP HTTP server stopped"}), 0))
            }
            _ => unreachable!(),
        },
        Command::Replay { timestamp } => {
            let state = crate::app::cache::load_state_at(config.profile_label(), timestamp)?;
            Ok((serde_json::to_value(state)?, 0))
        }
        Command::Watch {
            since,
            target,
            until,
            timeout,
            notify,
        } => watch::execute_watch(&client, &config, since, target, until, timeout, notify).await,
        Command::Search { query, limit } => execute_search(&client, &query, limit).await,
        Command::Hitl { action } => match action {
            HitlCommand::Serve => {
                hitl_serve(client, config).await?;
                Ok((serde_json::json!({"status": "HITL daemon stopped"}), 0))
            }
        },
        Command::Patch { action } => patch::execute(client, &config, action).await,
        Command::Disk { action } => vm::execute_disk(&client, action).await,
        Command::Iso { action } => storage::execute_iso(&client, action).await,
        Command::Pbs { action } => storage::execute_pbs(&config, action, cli_secret).await,
        Command::Ha { action } => monitoring::execute_ha(&client, action).await,
        Command::Replication { action } => monitoring::execute_replication(&client, action).await,
        Command::Hw { action } => node::execute_hw(&client, action).await,
        Command::Disks { action } => monitoring::execute_disks(&client, action).await,
        Command::Node { action } => node::execute_node(&client, action).await,
        Command::Metrics { action } => monitoring::execute_metrics(&client, action).await,
        Command::Vnc { vmid, node, ws_url } => {
            console::execute_vnc(&client, vmid, node, ws_url).await
        }
        Command::BackupJobs { action } => storage::execute_backup_jobs(&client, action).await,
        Command::FirewallCluster { action } => {
            firewall::execute_firewall_cluster(&client, action).await
        }
        Command::FirewallGuest { vmid, action } => {
            firewall::execute_firewall_guest(&client, vmid, action).await
        }
        Command::ClusterMapping { action } => {
            firewall::execute_cluster_mapping(&client, action).await
        }
        Command::Qga { vmid, action } => vm::execute_qga(&client, vmid, action).await,
        Command::NodeSystem { node: n, action } => node::execute_system(&client, &n, action).await,
        Command::Pool { action } => cluster::execute_pool(&client, action).await,
        Command::ClusterResources { kind } => cluster::execute_resources(&client, kind).await,
        Command::PveVersion => cluster::execute_pve_version(&client).await,
        Command::ClusterConfig { action } => cluster::execute_config(&client, action).await,
        Command::ClusterLog { max } => cluster::execute_log(&client, max).await,
        Command::Notifications { action } => {
            monitoring::execute_notifications(&client, action).await
        }
        Command::StorageDefs { action } => storage::execute_storage_defs(&client, action).await,
        Command::Acme { action } => storage::execute_acme(&client, action).await,
        Command::ClusterBootstrap { action } => cluster::execute_bootstrap(&client, action).await,
        Command::Alerts { action } => {
            let handle = crate::config::watcher::new_handle(config.clone());
            client.attach_live_config(std::sync::Arc::clone(&handle));
            crate::config::watcher::spawn_reload_on_sighup(
                std::sync::Arc::clone(&handle),
                profile.map(str::to_owned),
            );
            monitoring::execute_alerts(&client, handle, action).await
        }
        Command::Access { action } => access::execute_access(&client, action).await,
        Command::Token { action } => access::execute_token(&client, action).await,
        Command::Perms { userid, path, node } => {
            access::execute_perms(&client, &config, &userid, path.as_deref(), &node).await
        }
        Command::Serial {
            vmid,
            node,
            kind,
            record,
        } => {
            // `--record` without a path → auto path under data dir.
            let record_path = record.map(|p| {
                if p.is_empty() {
                    crate::console_record::default_recording_path(vmid, "serial")
                } else {
                    std::path::PathBuf::from(p)
                }
            });
            console::execute_serial(&client, &config, vmid, &node, kind, record_path).await
        }
        Command::Ssh { vmid, cmd } => {
            console::execute_ssh(&client, &config, vmid, cmd.as_deref()).await
        }
        Command::PlayCast { path, speed } => {
            crate::console_record::replay_cast(&path, speed).await?;
            Ok((Value::Null, 0))
        }
        Command::Spice {
            vmid,
            node,
            write_vv,
            no_launch,
        } => console::execute_spice(&client, vmid, &node, write_vv, no_launch).await,
        Command::Novnc {
            vmid,
            node,
            kind,
            no_launch,
        } => console::execute_novnc(&client, &config, vmid, &node, kind, no_launch).await,
        Command::DevPanic { .. } => {
            // Unreachable: short-circuited before client construction
            // (so it works on CI runners without a config.toml). Kept
            // here for match exhaustiveness.
            unreachable!("DevPanic handled in early-exit block")
        }
        Command::Version { .. } => {
            // Unreachable: short-circuited before client construction.
            // Kept here so the match remains exhaustive without an
            // `_ =>` catch-all.
            Ok((build_version_payload(), 0))
        }
        Command::Profiles => {
            let names = crate::config::list_profiles()?;
            if names.is_empty() {
                Ok((
                    serde_json::json!({ "profiles": [], "hint": "Add [profiles.NAME] sections to config.toml to define named profiles." }),
                    0,
                ))
            } else {
                Ok((serde_json::json!({ "profiles": names }), 0))
            }
        }
        Command::Init {
            force: _,
            interactive: _,
        } => {
            // Unreachable: short-circuited before `load_config` so it
            // works on a fresh machine. Kept here for exhaustiveness.
            unreachable!("Init handled in early-exit block")
        }
        Command::Completions { .. } => Ok((serde_json::json!({}), 0)),
        // `Fleet` launches a TUI runner — intercepted in `main.rs`
        // before `execute` (like `Completions`), so it never reaches
        // the CLI/stdout pipeline. This arm exists only for match
        // exhaustiveness.
        Command::Fleet => Ok((serde_json::json!({}), 0)),
        Command::Doctor => Ok((serde_json::json!({}), 0)),
        Command::Audit { .. } => Ok((serde_json::json!({}), 0)),
        Command::State { action } => state::execute_state(&client, action).await,
        Command::Reconcile { action } => reconcile::execute_reconcile(&client, action).await,
        Command::Vm { action } => vm::execute_vm(&client, action).await,
        Command::Ct { action } => ct::execute(&client, action).await,
        Command::Firewall { scope } => firewall::execute_firewall(&client, scope).await,
        Command::Network { node } => {
            let interfaces = client.list_node_network(&node).await?;
            Ok((serde_json::to_value(interfaces)?, 0))
        }
        Command::Storage { action } => storage::execute_storage(&client, action).await,
        // `Find` is always cross-profile — short-circuited before
        // load_config. This arm is unreachable but the match must
        // be exhaustive.
        Command::Find { .. } => {
            unreachable!("Command::Find handled by --all-profiles short-circuit above")
        }
    }
}

fn build_version_payload() -> serde_json::Value {
    // Subcommand count: ask clap to augment a fresh Command with our
    // Subcommand enum, then count the variants. This is reflection-
    // free runtime introspection — the count moves automatically when
    // we add or remove a verb. CommandFactory would be cleaner but
    // it's only implemented for the top-level Parser (in main.rs);
    // the library (lib.rs) only sees the Subcommand enum.
    use clap::Subcommand as _;
    let cli = Command::augment_subcommands(clap::Command::new("proxxx"));
    let cli_subcommand_count = cli.get_subcommands().count();
    // Embed the audit policy as a static string so the JSON shows
    // exactly what `cargo audit` would skip. The file is short and
    // human-readable; we surface the count of ignored advisories.
    const AUDIT_POLICY: &str = include_str!("../../.cargo/audit.toml");
    let ignored_advisories: Vec<String> = AUDIT_POLICY
        .lines()
        .filter_map(|l| {
            let t = l.trim_start();
            // Lines look like `    "RUSTSEC-2023-0071",`
            if t.starts_with("\"RUSTSEC-") {
                Some(
                    t.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-')
                        .to_string(),
                )
            } else {
                None
            }
        })
        .collect();
    let kc = crate::config::keychain_store_info();
    let mut features: Vec<&'static str> = Vec::new();
    if cfg!(feature = "keychain") {
        features.push("keychain");
    }
    serde_json::json!({
        "name": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "cli_subcommand_count": cli_subcommand_count,
        "audit_ignores": ignored_advisories,
        "audit_ignores_count": ignored_advisories.len(),
        // Compile-time target triple — useful for "is this the macOS or
        // musl Linux binary?" checks. `target_os` / `target_arch` are
        // stable cfg names; we serialize what cargo decided at build.
        "target_os": std::env::consts::OS,
        "target_arch": std::env::consts::ARCH,
        // Build profile — `debug_assertions` is true only in debug.
        "build_profile": if cfg!(debug_assertions) { "debug" } else { "release" },
        // Pre-flight risk variants — counts how many distinct signals
        // the framework can surface. README references this number to
        // describe "rich preflight intelligence" without lying about
        // the depth.
        "preflight_risk_variants": 11_usize,
        // #332: active Cargo features and compiled OS keychain store.
        "features": features,
        "keychain": {
            "compiled": kc.compiled,
            "store": kc.store,
        },
    })
}

/// Bug #4 fix: cluster-wide fuzzy search via the existing in-memory
/// search engine. Reuses `app::search::SearchItem` + `nucleo_matcher`.
/// One-shot: fetches state, runs the matcher, prints JSON results.
async fn execute_search(
    client: &std::sync::Arc<crate::api::PxClient>,
    query: &str,
    limit: usize,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    // Errors propagate: a search that silently omits a transiently-failed
    // node's guests/pools yields false "not found" results.
    let nodes = client.get_nodes().await?;
    let all_guests = client.get_all_guests().await?;
    let all_storage = client.get_all_storage_pools().await?;
    let results = search_rows(&nodes, &all_guests, &all_storage, query, limit);
    Ok((serde_json::Value::Array(results), 0))
}

/// The `search` matches. Each row is matched on, and reports, the same
/// lowercase `status` and `type` strings `ls` prints; the haystack used
/// to hold `{:?}` names and the guest type as a number, so `search 0`
/// matched every QEMU VM (audit #385).
fn search_rows(
    nodes: &[crate::api::types::Node],
    guests: &[crate::api::types::Guest],
    storage: &[crate::api::types::StoragePool],
    query: &str,
    limit: usize,
) -> Vec<serde_json::Value> {
    fn label<T: serde::Serialize>(v: &T) -> String {
        serde_json::to_value(v)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default()
    }
    let q_lower = query.to_lowercase();
    let mut results: Vec<serde_json::Value> = Vec::new();
    for g in guests {
        let status = label(&g.status);
        let kind = g.guest_type.as_str();
        let hay = format!(
            "{} {} {} {} {} {}",
            g.vmid, g.name, g.tags, status, g.node, kind
        )
        .to_lowercase();
        if hay.contains(&q_lower) {
            results.push(serde_json::json!({
                "kind": "guest",
                "vmid": g.vmid,
                "name": g.name,
                "node": g.node,
                "status": status,
                "type": kind,
                "tags": g.tags,
            }));
        }
    }
    for n in nodes {
        let status = label(&n.status);
        let hay = format!("{} {}", n.node, status).to_lowercase();
        if hay.contains(&q_lower) {
            results.push(serde_json::json!({
                "kind": "node",
                "name": n.node,
                "status": status,
            }));
        }
    }
    for s in storage {
        let hay = format!("{} {} {}", s.storage, s.storage_type, s.content).to_lowercase();
        if hay.contains(&q_lower) {
            results.push(serde_json::json!({
                "kind": "storage",
                "name": s.storage,
                "type": s.storage_type,
            }));
        }
    }
    results.truncate(limit);
    results
}

/// Bug #6 fix: implement `proxxx delete <vmid>...` (was missing entirely).
/// Requires `--yes` from the caller; routes through `delete_guest` with
/// type-aware dispatch.
async fn execute_delete(
    client: &std::sync::Arc<crate::api::PxClient>,
    vmids: &[u32],
    strict: bool,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    use tracing::warn;

    // Build vmid → (node, type) map from a single cluster scan. Errors
    // propagate: a dropped node would make its guests look "not found".
    let mut guest_map: std::collections::HashMap<u32, (String, crate::api::types::GuestType)> =
        std::collections::HashMap::new();
    for g in client.get_all_guests().await? {
        guest_map.insert(g.vmid, (g.node, g.guest_type));
    }

    if strict {
        let missing: Vec<u32> = vmids
            .iter()
            .copied()
            .filter(|v| !guest_map.contains_key(v))
            .collect();
        if !missing.is_empty() {
            anyhow::bail!("Strict mode: guests not found: {missing:?}");
        }
    }

    let mut results = Vec::new();
    let mut has_failure = false;
    for vmid in vmids {
        let Some((node, gt)) = guest_map.get(vmid).cloned() else {
            warn!("guest {vmid} not found");
            results.push(serde_json::json!({
                "vmid": vmid,
                "status": "error",
                "message": "guest not found"
            }));
            has_failure = true;
            continue;
        };
        match client.delete_guest(&node, *vmid, gt).await {
            Ok(upid) => results.push(serde_json::json!({
                "vmid": vmid,
                "status": "success",
                "node": node,
                "upid": upid,
            })),
            Err(e) => {
                has_failure = true;
                results.push(serde_json::json!({
                    "vmid": vmid,
                    "status": "error",
                    "message": e.to_string()
                }));
                if strict {
                    anyhow::bail!("Strict mode: delete failed for {vmid}: {e}");
                }
            }
        }
    }

    let exit = i32::from(has_failure);
    Ok((serde_json::Value::Array(results), exit))
}

pub(crate) async fn hitl_serve(
    client: std::sync::Arc<crate::api::PxClient>,
    config: crate::config::ProfileConfig,
) -> Result<()> {
    use tracing::{error, info};

    let tg_config = config
        .telegram
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Telegram not configured"))?;
    let tg_gateway = crate::hitl::telegram::TelegramGateway::from_config(tg_config).await?;
    // #341 — persisted pending-approval store at `<config_dir>/hitl_pending.db`
    // (next to `telegram_hmac.key`), shared with CLI and MCP senders.
    let pending = std::sync::Arc::new(crate::hitl::pending::PendingStore::open_default()?);

    info!("Starting HITL daemon...");
    let mut offset = 0;
    // (Gemini audit) — exponential backoff on getUpdates
    // failure. Without this, sustained Telegram outage / DNS failure
    // would re-poll on a fixed cadence forever; with it we ramp from
    // 1 s to a 60 s ceiling so a multi-hour outage costs ~60 requests
    // per minute → ~1/min instead of 12/min.
    let mut backoff = std::time::Duration::from_secs(1);
    const BACKOFF_CAP: std::time::Duration = std::time::Duration::from_mins(1);

    loop {
        // (macro audit) — graceful shutdown.
        //
        // Race the next getUpdates against SIGTERM/SIGINT so systemd
        // stops the daemon cleanly instead of escalating to SIGKILL
        // after the grace period. Long-poll has a 30 s window; the
        // signal handler resolves immediately when fired.
        let poll_fut = tg_gateway.poll_updates(offset, 30);
        let updates = tokio::select! {
            biased;
            () = crate::util::shutdown::wait_for_shutdown_signal() => {
                info!("HITL daemon: shutdown signal received, exiting cleanly");
                return Ok(());
            }
            res = poll_fut => res,
        };
        match updates {
            Ok(updates) => {
                // Reset backoff on success — the next failure starts fresh
                // at 1 s rather than carrying over the previous outage's
                // cap.
                backoff = std::time::Duration::from_secs(1);
                for update in updates {
                    offset = offset.max(update.update_id + 1);
                    // The per-callback logic lives in hitl::daemon so it
                    // can be unit-tested without driving the long-poll
                    // loop. Outcomes are returned for diagnostics; the
                    // daemon ignores them after answering the callback
                    // (the user already saw the result on Telegram).
                    let _ = crate::hitl::daemon::handle_callback_update(
                        &update,
                        &pending,
                        client.as_ref(),
                        &tg_gateway,
                    )
                    .await;
                }
            }
            Err(e) => {
                error!("Polling error: {} — backing off {}s", e, backoff.as_secs());
                tokio::time::sleep(backoff).await;
                // Double until we hit the cap.
                backoff = (backoff * 2).min(BACKOFF_CAP);
            }
        }
    }
}
