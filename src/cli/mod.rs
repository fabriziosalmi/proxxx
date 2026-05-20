use anyhow::Result;
use clap::Subcommand;
use serde_json::Value;

mod access;
mod audit_cmd;
mod cluster;
pub mod common;
mod console;
mod ct;
mod doctor;
mod events;
pub mod explain;
mod firewall;
mod incident;
mod init;
mod init_wizard;
mod logs;
mod migrate_progress;
mod monitoring;
mod node;
mod patch;
mod state;
mod storage;
pub mod vm;

pub use audit_cmd::AuditAction;

use crate::util;
use common::{
    enforce_preflight, execute_batch_op_with_policy, find_guest, find_guest_full,
    wait_and_classify, BatchOp,
};

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List resources (aliases: get)
    #[command(alias = "get")]
    Ls {
        /// Resource type: nodes, guests, storage
        resource: String,
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
    /// Pre-flight capability check on a guest. PVE features:
    /// `snapshot`, `clone`, `copy`, `migrate`, `replicate`. Returns
    /// `{has_feature, nodes}` — `nodes` is the list of cluster nodes
    /// the guest could be migrated to without losing the feature.
    Feature {
        /// Guest VMID — auto-resolves to its node and guest type.
        vmid: u32,
        /// Feature to check (e.g. `snapshot`).
        #[arg(long)]
        feature: String,
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
        /// Watch changes since a given time (e.g. 1h, 30m)
        #[arg(long)]
        since: Option<String>,

        /// Target to watch (e.g., vm-100, task UPID, storage pool)
        #[arg(long, short)]
        target: Option<String>,

        /// Wait until condition is met (e.g. status=running, usage=<70%, usage=>80%)
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
    /// sdn objects, pools — flattened. PVE web-UI's main dashboard
    /// query. Use `--kind` to filter (vm | storage | node | sdn | pool);
    /// omit for everything.
    ClusterResources {
        #[arg(long)]
        kind: Option<String>,
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
    /// List named profiles defined in config.toml ([profiles.NAME] sections).
    /// Use `--profile NAME` to select one when starting the TUI or CLI.
    Profiles,
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
    /// Firewall rules — read-only inspection. PVE has three rule
    /// scopes (datacenter, node, guest); pick one. Write operations
    /// (add/remove rules, manage aliases/IPSets/groups) are not yet
    /// implemented.
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
        /// Bearer token for auth (overrides `mcp_token` in config)
        #[arg(long)]
        token: Option<String>,
    },
    /// List available tools
    Tools {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        checksum: bool,
    },
}

/// Execute a CLI command — returns JSON-serializable result and exit code.
///
/// `_secure` is reserved for future per-command HITL gating in pipelines;
/// it's currently honoured by the TUI only (see `state.secure_mode`).
pub async fn execute(
    cmd: Command,
    profile: Option<&str>,
    cli_secret: Option<&str>,
    _secure: bool,
    format: crate::util::format::OutputFormat,
) -> Result<(Value, i32)> {
    // MCP introspection commands don't need a Proxmox connection
    if let Command::Mcp {
        action: McpCommand::Tools { checksum, .. },
    } = &cmd
    {
        if *checksum {
            let hash = crate::mcp::tools::registry_checksum();
            return Ok((serde_json::json!({"checksum": hash}), 0));
        }
        return Ok((crate::mcp::tools::registry_json(), 0));
    }

    // `version` is the only command that doesn't need a live PVE
    // connection — it's pure self-introspection. Short-circuit BEFORE
    // building PxClient so users without a configured profile can still
    // run `proxxx version --json` (CI scripts, container health probes,
    // README badge generators).
    if matches!(cmd, Command::Version { .. }) {
        return Ok((build_version_payload(), 0));
    }

    // First-run UX: `proxxx init` MUST work on a fresh machine that
    // has no config.toml yet — that's the entire point. Short-circuit
    // before `load_config` so the "Config not found" error doesn't
    // catch the very command meant to fix it. (Audit-discovered
    // landmine: prior to this short-circuit the error message
    // recommended `proxxx init` but the command did not exist —
    // dismiss-after-five-seconds territory.)
    if let Command::Init { force, interactive } = &cmd {
        if *interactive {
            return init_wizard::run().await;
        }
        return init::execute(*force);
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

    if matches!(cmd, Command::Doctor) {
        return doctor::run().await;
    }

    if let Command::Audit { ref action } = cmd {
        return match action {
            AuditAction::Log { limit, since } => audit_cmd::execute_log(*limit, since.as_deref()),
            AuditAction::Export {
                format,
                limit,
                since,
            } => audit_cmd::execute_export(format, *limit, since.as_deref()),
            AuditAction::Verify => audit_cmd::execute_verify(),
        };
    }

    let config = crate::config::load_config(profile)?;
    let client = std::sync::Arc::new(crate::api::PxClient::new(config.clone(), cli_secret).await?);

    use crate::api::ProxmoxGateway;

    match cmd {
        Command::Ls { resource } => match resource.as_str() {
            "nodes" => {
                let nodes = client.get_nodes().await?;
                Ok((serde_json::to_value(nodes)?, 0))
            }
            "guests" => {
                let nodes = client.get_nodes().await?;
                let mut all_guests = Vec::new();
                for node in &nodes {
                    if let Ok(guests) = client.get_guests(&node.node).await {
                        all_guests.extend(guests);
                    }
                }
                Ok((serde_json::to_value(all_guests)?, 0))
            }
            "storage" => {
                let nodes = client.get_nodes().await?;
                let mut all_storage = Vec::new();
                for node in &nodes {
                    if let Ok(pools) = client.get_storage_pools(&node.node).await {
                        all_storage.extend(pools);
                    }
                }
                Ok((serde_json::to_value(all_storage)?, 0))
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
            if !yes {
                anyhow::bail!("`proxxx delete` is destructive — re-run with --yes to confirm");
            }
            for &vmid in &vmids {
                let g = find_guest_full(&client, vmid).await?;
                // Delete is the only op where backup-recency matters —
                // build a PBS client opportunistically (when configured)
                // so the preflight covers PBS-tracked snapshots too.
                let pbs_for_preflight = match config.pbs.as_ref() {
                    Some(cfg) => crate::pbs::PbsClient::new(cfg.clone(), cli_secret)
                        .await
                        .ok(),
                    None => None,
                };
                enforce_preflight(
                    &client,
                    pbs_for_preflight.as_ref(),
                    crate::app::preflight::Op::Delete,
                    &g,
                    allow_risk,
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
            if !yes {
                anyhow::bail!("`proxxx migrate` is potentially disruptive — re-run with --yes");
            }
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
                let json_mode = matches!(format, util::format::OutputFormat::Json);
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
        Command::Events { action } => events::execute_events(&client, action).await,
        Command::Logs { action } => {
            let render = if matches!(format, util::format::OutputFormat::Json) {
                logs::LogsRenderMode::Json
            } else {
                logs::LogsRenderMode::Text
            };
            logs::execute_logs(&config, &client, action, render).await
        }
        Command::Explain(args) => explain::execute_explain(args),
        Command::Incident { action } => incident::execute_incident(action),
        Command::Tasks { limit, node } => {
            let tasks = if let Some(n) = node {
                client
                    .list_node_tasks(&n, Some(u32::try_from(limit).unwrap_or(50)))
                    .await?
            } else {
                let mut all = client.get_cluster_tasks().await?;
                all.truncate(limit);
                all
            };
            Ok((serde_json::to_value(tasks)?, 0))
        }
        Command::TaskStop { node, upid, yes } => {
            if !yes {
                anyhow::bail!("destructive — pass --yes to confirm");
            }
            client.stop_node_task(&node, &upid).await?;
            Ok((serde_json::json!({"stopped": upid, "node": node}), 0))
        }
        Command::Feature { vmid, feature } => {
            let (node, gt) = find_guest(&client, vmid).await?;
            let res = client.get_guest_feature(&node, vmid, gt, &feature).await?;
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
            if !yes {
                anyhow::bail!("`proxxx template` is irreversible — re-run with --yes to confirm");
            }
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
                    crate::cli::common::poll_task_until_done(&client, &src_node, &upid, 0).await?;
                if !status.is_success() {
                    anyhow::bail!(
                        "clone task did not succeed (status={:?}); skipping cloud-init apply",
                        status.exitstatus
                    );
                }
                Some(
                    vm::apply_cloudinit_and_regen(&client, &landing_node, target_id, gt, &profile)
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
                crate::config::watcher::spawn_reload_on_sighup(
                    std::sync::Arc::clone(&handle),
                    profile.map(str::to_owned),
                );
                crate::mcp::server::run_server(std::sync::Arc::clone(&client), handle).await?;
                Ok((serde_json::json!({"status": "MCP server stopped"}), 0))
            }
            McpCommand::ServeHttp { bind, port, token } => {
                let mut cfg = config;
                // CLI --token overrides the profile's mcp_token.
                if token.is_some() {
                    cfg.mcp_token = token;
                }
                let handle = crate::config::watcher::new_handle(cfg);
                crate::config::watcher::spawn_reload_on_sighup(
                    std::sync::Arc::clone(&handle),
                    profile.map(str::to_owned),
                );
                crate::mcp::http_server::run_http_server(
                    std::sync::Arc::clone(&client),
                    handle,
                    &bind,
                    port,
                )
                .await?;
                Ok((serde_json::json!({"status": "MCP HTTP server stopped"}), 0))
            }
            _ => unreachable!(),
        },
        Command::Replay { timestamp } => {
            let state = crate::app::cache::load_state_at(profile, timestamp)?;
            Ok((serde_json::to_value(state)?, 0))
        }
        Command::Watch {
            since,
            target,
            until,
            timeout,
            notify,
        } => {
            if let Some(target) = target {
                let until = until.unwrap_or_else(|| "status=running".to_string());
                use crate::api::ProxmoxGateway;
                use tokio::time::{sleep, Duration, Instant};

                // Parse `key=<comparator><value>`, e.g. `usage=<70%` or `status=running`.
                let (key, raw_value) = if let Some((k, v)) = until.split_once('=') {
                    (k.trim().to_lowercase(), v.trim().to_lowercase())
                } else {
                    anyhow::bail!(
                        "Invalid condition format. Use key=value, key=<value or key=>value"
                    );
                };
                // Split leading comparator from the numeric/string value.
                let (comparator, value_str) = if raw_value.starts_with('<') {
                    ('<', raw_value.trim_start_matches('<'))
                } else if raw_value.starts_with('>') {
                    ('>', raw_value.trim_start_matches('>'))
                } else {
                    ('=', raw_value.as_str())
                };

                let mut met = false;
                tracing::info!("Watching {} until {}={}", target, key, raw_value);
                let deadline = Instant::now() + Duration::from_secs(timeout);

                while !met {
                    if Instant::now() >= deadline {
                        anyhow::bail!(
                            "watch timed out after {timeout}s — condition not met: {until}"
                        );
                    }
                    sleep(Duration::from_secs(2)).await;

                    if target.starts_with("vm-") || target.chars().all(char::is_numeric) {
                        let vmid_str = target.trim_start_matches("vm-");
                        if let Ok(vmid) = vmid_str.parse::<u32>() {
                            let mut found = false;
                            let nodes = client.get_nodes().await?;
                            for node in nodes {
                                if let Ok(guests) = client.get_guests(&node.node).await {
                                    if let Some(guest) = guests.into_iter().find(|g| g.vmid == vmid)
                                    {
                                        found = true;
                                        let current_val = match key.as_str() {
                                            "status" => {
                                                format!("{:?}", guest.status).to_lowercase()
                                            }
                                            _ => {
                                                anyhow::bail!("Unsupported condition key: {key}")
                                            }
                                        };

                                        if current_val == value_str {
                                            met = true;
                                        }
                                        break;
                                    }
                                }
                            }
                            if !found {
                                anyhow::bail!("Target guest {target} not found");
                            }
                        } else {
                            anyhow::bail!("Invalid VMID format: {target}");
                        }
                    } else if target.starts_with("storage-") {
                        let pool_id = target.trim_start_matches("storage-");
                        let mut found = false;
                        let nodes = client.get_nodes().await?;
                        for node in nodes {
                            if let Ok(pools) = client.get_storage_pools(&node.node).await {
                                if let Some(pool) = pools.into_iter().find(|p| p.storage == pool_id)
                                {
                                    found = true;
                                    if key == "usage" {
                                        let usage_pct =
                                            (pool.used as f64 / pool.total as f64) * 100.0;
                                        let threshold: f64 =
                                            value_str.trim_end_matches('%').parse()?;
                                        met = match comparator {
                                            '<' => usage_pct < threshold,
                                            '>' => usage_pct > threshold,
                                            _ => (usage_pct - threshold).abs() < 0.01,
                                        };
                                    } else {
                                        anyhow::bail!(
                                            "Unsupported condition key for storage: {key}"
                                        );
                                    }
                                    break;
                                }
                            }
                        }
                        if !found {
                            anyhow::bail!("Target storage {target} not found");
                        }
                    } else {
                        anyhow::bail!("Unsupported target format. Use vm-<id> or storage-<id>");
                    }
                }

                let msg = format!("Watch condition met: {target} is now {until}");

                if let Some(channel) = notify {
                    if channel == "telegram" {
                        if let Some(tg) = config.telegram.as_ref() {
                            let gateway =
                                crate::hitl::telegram::TelegramGateway::from_config(tg).await?;
                            gateway.send_message(&msg).await?;
                        }
                    }
                }

                Ok((
                    serde_json::json!({"status": "condition_met", "target": target, "condition": until}),
                    0,
                ))
            } else if let Some(since) = since {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let seconds = if since.ends_with('h') {
                    since.trim_end_matches('h').parse::<u64>().unwrap_or(1) * 3600
                } else if since.ends_with('m') {
                    since.trim_end_matches('m').parse::<u64>().unwrap_or(30) * 60
                } else {
                    since.parse::<u64>().unwrap_or(3600)
                };

                let past = now.saturating_sub(seconds);
                let state_past = crate::app::cache::load_state_at(profile, past)?;
                let state_now = crate::app::cache::load_state(profile)?;

                let mut diff = Vec::new();

                let past_map: std::collections::HashMap<_, _> =
                    state_past.guests.into_iter().map(|g| (g.vmid, g)).collect();
                let now_map: std::collections::HashMap<_, _> =
                    state_now.guests.into_iter().map(|g| (g.vmid, g)).collect();

                for (vmid, guest_now) in &now_map {
                    if let Some(guest_past) = past_map.get(vmid) {
                        if guest_past.status != guest_now.status {
                            diff.push(serde_json::json!({
                                "vmid": vmid,
                                "type": "status_change",
                                "from": format!("{:?}", guest_past.status),
                                "to": format!("{:?}", guest_now.status)
                            }));
                        }
                    } else {
                        diff.push(serde_json::json!({
                            "vmid": vmid,
                            "type": "created",
                            "status": format!("{:?}", guest_now.status)
                        }));
                    }
                }

                for vmid in past_map.keys() {
                    if !now_map.contains_key(vmid) {
                        diff.push(serde_json::json!({
                            "vmid": vmid,
                            "type": "deleted"
                        }));
                    }
                }

                Ok((
                    serde_json::json!({
                        "past_timestamp": state_past.timestamp,
                        "now_timestamp": state_now.timestamp,
                        "diff": diff
                    }),
                    0,
                ))
            } else {
                anyhow::bail!("Watch requires either --since or --target");
            }
        }
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
            crate::config::watcher::spawn_reload_on_sighup(
                std::sync::Arc::clone(&handle),
                profile.map(str::to_owned),
            );
            monitoring::execute_alerts(&client, handle, profile, action).await
        }
        Command::Access { action } => access::execute_access(&client, action).await,
        Command::Token { action } => access::execute_token(&client, action).await,
        Command::Perms { userid, path, node } => {
            access::execute_perms(&config, &userid, path.as_deref(), &node).await
        }
        Command::Serial { vmid, node, kind } => {
            console::execute_serial(&client, &config, vmid, &node, kind).await
        }
        Command::Ssh { vmid, cmd } => {
            console::execute_ssh(&client, &config, vmid, cmd.as_deref()).await
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
        Command::Doctor => Ok((serde_json::json!({}), 0)),
        Command::Audit { .. } => Ok((serde_json::json!({}), 0)),
        Command::State { action } => state::execute_state(&client, profile, action).await,
        Command::Vm { action } => vm::execute_vm(&client, action).await,
        Command::Ct { action } => ct::execute(&client, action).await,
        Command::Firewall { scope } => firewall::execute_firewall(&client, scope).await,
        Command::Network { node } => {
            let interfaces = client.list_node_network(&node).await?;
            Ok((serde_json::to_value(interfaces)?, 0))
        }
        Command::Storage { action } => storage::execute_storage(&client, action).await,
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
    let nodes = client.get_nodes().await?;
    let mut all_guests = Vec::new();
    let mut all_storage = Vec::new();
    for n in &nodes {
        if let Ok(guests) = client.get_guests(&n.node).await {
            all_guests.extend(guests);
        }
        if let Ok(pools) = client.get_storage_pools(&n.node).await {
            all_storage.extend(pools);
        }
    }
    let q_lower = query.to_lowercase();
    let mut results: Vec<serde_json::Value> = Vec::new();
    for g in &all_guests {
        let hay = format!(
            "{} {} {} {:?} {} {}",
            g.vmid, g.name, g.tags, g.status, g.node, g.guest_type as u8
        )
        .to_lowercase();
        if hay.contains(&q_lower) {
            results.push(serde_json::json!({
                "kind": "guest",
                "vmid": g.vmid,
                "name": g.name,
                "node": g.node,
                "status": format!("{:?}", g.status),
                "type": format!("{:?}", g.guest_type),
                "tags": g.tags,
            }));
        }
    }
    for n in &nodes {
        let hay = format!("{} {:?}", n.node, n.status).to_lowercase();
        if hay.contains(&q_lower) {
            results.push(serde_json::json!({
                "kind": "node",
                "name": n.node,
                "status": format!("{:?}", n.status),
            }));
        }
    }
    for s in &all_storage {
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
    Ok((serde_json::Value::Array(results), 0))
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

    // Build vmid → (node, type) map from a single cluster scan.
    let nodes = client.get_nodes().await?;
    let mut guest_map: std::collections::HashMap<u32, (String, crate::api::types::GuestType)> =
        std::collections::HashMap::new();
    for n in nodes {
        if let Ok(guests) = client.get_guests(&n.node).await {
            for g in guests {
                guest_map.insert(g.vmid, (n.node.clone(), g.guest_type));
            }
        }
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

async fn hitl_serve(
    client: std::sync::Arc<crate::api::PxClient>,
    config: crate::config::ProfileConfig,
) -> Result<()> {
    use tracing::{error, info};

    let tg_config = config
        .telegram
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Telegram not configured"))?;
    let tg_gateway = crate::hitl::telegram::TelegramGateway::from_config(tg_config).await?;
    // Phase 5.13 — replay protection for callbacks. Session-local; see
    // `hitl::pending` module docs for the full threat model + scope.
    let pending = std::sync::Arc::new(crate::hitl::pending::PendingApprovals::new());

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
