use anyhow::Result;
use clap::{Subcommand, ValueEnum};
use serde_json::Value;

mod init_wizard;

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
    },
    /// Resume a suspended guest — inverse of `suspend`.
    Resume {
        /// Guest VMID(s)
        vmids: Vec<u32>,
        #[arg(long)]
        strict: bool,
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
        action: AplinfoCommand,
    },
    /// Pre-flight a URL for `download_to_storage`: returns size +
    /// filename + mimetype so the operator can size-check first.
    UrlInfo {
        #[arg(long)]
        node: String,
        #[arg(long)]
        url: String,
    },
    /// External metrics exporters (InfluxDB / Graphite). Cluster-wide
    /// CRUD on `/cluster/metrics/server`. Distinct from `proxxx metrics`
    /// which READS guest/node/storage RRD samples — this command
    /// configures the EXPORTERS that ship those samples elsewhere.
    MetricServers {
        #[command(subcommand)]
        action: MetricServersCommand,
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
    },
    /// Manage snapshots
    Snapshot {
        #[command(subcommand)]
        action: SnapshotCommand,
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

        /// Wait until condition is met (e.g. status=running, usage<70%)
        #[arg(long, short)]
        until: Option<String>,

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
        action: PatchCommand,
    },
    /// Live disk operations (move between storage / grow). Destructive —
    /// requires `--yes`. Always routes through Proxmox API directly
    /// (CLI does not enqueue; the queue is a TUI concept).
    Disk {
        #[command(subcommand)]
        action: DiskCommand,
    },
    /// ISO / cloud-image library (curated catalog + server-side download).
    Iso {
        #[command(subcommand)]
        action: IsoCommand,
    },
    /// Proxmox Backup Server: list snapshots and restore archives.
    /// Read-only browse via REST API; restore shells out to
    /// `proxmox-backup-client` (Linux required).
    Pbs {
        #[command(subcommand)]
        action: PbsCommand,
    },
    /// HA + replication console (read-only inspector).
    Ha {
        #[command(subcommand)]
        action: HaCommand,
    },
    /// Storage replication jobs and per-node runtime status.
    Replication {
        #[command(subcommand)]
        action: ReplicationCommand,
    },
    /// Hardware passthrough inventory + conflict detector (read-only).
    Hw {
        #[command(subcommand)]
        action: HwCommand,
    },
    /// Storage health (read-only): physical disks, SMART, LVM/LVM-thin/ZFS pools.
    /// Distinct from `proxxx disk` (singular, write-side disk operations on guest VMs).
    Disks {
        #[command(subcommand)]
        action: DisksCommand,
    },
    /// Node-level operations: bulk power (start/stop/suspend ALL guests
    /// on a node at once). Distinct from per-VM `start/stop/suspend`
    /// commands which take VMIDs.
    Node {
        #[command(subcommand)]
        action: NodeCommand,
    },
    /// Time-series metrics (rrddata): historical CPU/mem/disk/net for
    /// guests, nodes, and storages. Default output is a Unicode block
    /// sparkline + min/max/avg summary; `--format json` emits raw
    /// rrddata for piping into jq / a charting tool.
    Metrics {
        #[command(subcommand)]
        action: MetricsCommand,
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
        action: BackupJobsCommand,
    },
    /// Cluster firewall CRUD — aliases, security groups, ipsets, and
    /// the global on/off + default policy. Read-only `proxxx firewall`
    /// covers rule listing across all three scopes; this command closes
    /// the CRUD half for the cluster-scope primitives.
    FirewallCluster {
        #[command(subcommand)]
        action: FirewallClusterCommand,
    },
    /// Per-guest firewall CRUD — aliases + per-guest options (enable,
    /// MAC filter, IP filter, DHCP/NDP auto-allow). VMID is auto-resolved
    /// to its node and guest type via the same scan `proxxx firewall
    /// --scope guest` uses.
    FirewallGuest {
        /// Guest VMID — node + guest type discovered automatically.
        vmid: u32,
        #[command(subcommand)]
        action: FirewallGuestCommand,
    },
    /// Cluster hardware mapping — stable logical names for PCI / USB
    /// passthrough devices. Lets a guest keep its passthrough binding
    /// across migrations between hosts where the device sits at a
    /// different bus address.
    ClusterMapping {
        #[command(subcommand)]
        action: ClusterMappingCommand,
    },
    /// QEMU Guest Agent file ops + network introspection. QEMU-only —
    /// LXC has no QGA. Bails clearly if pointed at an LXC. Common uses:
    /// peek at /etc/hostname inside a guest, drop a marker file, ask
    /// the guest "what IPs do you actually have."
    Qga {
        /// Guest VMID. Auto-resolved to its node; bails if not QEMU.
        vmid: u32,
        #[command(subcommand)]
        action: QgaCommand,
    },
    /// Node system layer — DNS resolvers, /etc/hosts, NTP, journal,
    /// syslog, subscription, certificates, support report, wake-on-LAN.
    /// One command per node, sub-commands per resource.
    NodeSystem {
        /// Target node name (e.g. `pve1`).
        node: String,
        #[command(subcommand)]
        action: NodeSystemCommand,
    },
    /// Pool CRUD (multi-tenancy primitive). A pool is a named bag of
    /// guests + storages; ACL paths target it as `/pool/<name>`.
    Pool {
        #[command(subcommand)]
        action: PoolCommand,
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
    /// Cluster-wide config: mac_prefix, default migration network,
    /// console viewer, max_workers, registered tags, etc. `get` shows
    /// the full config; `set` updates one or more fields.
    ClusterConfig {
        #[command(subcommand)]
        action: ClusterConfigCommand,
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
        action: NotificationsCommand,
    },
    /// Cluster-wide storage definitions CRUD — add/update/delete the
    /// storages PVE knows about (NFS, PBS, ZFS pool, dir, ...).
    /// Distinct from `proxxx storage` which manages CONTENT inside a
    /// storage (upload/delete files, ISOs, backups).
    StorageDefs {
        #[command(subcommand)]
        action: StorageDefsCommand,
    },
    /// ACME (Let's Encrypt et al) cluster-wide config — accounts +
    /// challenge plugins + read-only ToS / directories / schema.
    /// Pairs with `proxxx node-system <node> cert acme-order` which
    /// triggers the actual cert order using these account/plugin configs.
    Acme {
        #[command(subcommand)]
        action: AcmeCommand,
    },
    /// Corosync cluster bootstrap — node membership, join info,
    /// quorum-device, totem transport. Rare day-to-day but
    /// high-stakes (botched qdevice or node add can lose quorum and
    /// freeze HA).
    ClusterBootstrap {
        #[command(subcommand)]
        action: ClusterBootstrapCommand,
    },
    /// Alerting & notification routing (rule engine + Telegram/ntfy/webhook).
    Alerts {
        #[command(subcommand)]
        action: AlertsCommand,
    },
    /// Access control: ACL, users, groups, roles, realms, TFA.
    Access {
        #[command(subcommand)]
        action: AccessCommand,
    },
    /// API token management (list / create / revoke).
    Token {
        #[command(subcommand)]
        action: TokenCommand,
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
        kind: Option<SerialKind>,
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
        kind: Option<SerialKind>,
    },
    /// Open an interactive SSH session into a guest (NOT into the PVE
    /// node — for that, just `ssh root@<node>` directly). Per-guest
    /// connection details (host/IP, optional user/port/key override)
    /// are read from `[ssh.guests."<vmid>"]` in your config.toml.
    /// Spawns the system `ssh` so the operator's existing keys, agent,
    /// and known_hosts apply transparently. Press Ctrl+D or type `exit`
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
    /// Write a starter `config.toml` to the OS-default proxxx config
    /// directory (e.g. `~/.config/proxxx/config.toml` on Linux,
    /// `~/Library/Application Support/dev.proxxx.proxxx/config.toml`
    /// on macOS). Idempotent: refuses to overwrite an existing file
    /// unless `--force` is passed. The template carries the same
    /// fields as the in-tree example with all secrets commented out
    /// — fill in `url`, `user`, `token_id`, `token_secret`, then run
    /// `proxxx ls nodes` to validate the connection.
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
    /// QEMU VM hardware/options/cloud-init management. The typed
    /// subcommands (`set`, `cloudinit`) cover the well-trodden config
    /// keys with parse-time validation; `raw-set` is the documented
    /// escape hatch for niche keys not yet typed (e.g. `smbios1`,
    /// NUMA topology). LXC is under `proxxx ct` instead.
    Vm {
        #[command(subcommand)]
        action: VmCommand,
    },
    /// LXC container hardware/options management. Smaller surface
    /// than QEMU — no cloud-init, no VGA, etc. Same typed-vs-raw
    /// split as `proxxx vm`.
    Ct {
        #[command(subcommand)]
        action: CtCommand,
    },
    /// Firewall rules — read-only inspection. PVE has three rule
    /// scopes (datacenter, node, guest); pick one. Write operations
    /// (add/remove rules, manage aliases/IPSets/groups) are not yet
    /// implemented.
    Firewall {
        #[command(subcommand)]
        scope: FirewallScope,
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
        action: StorageCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum StorageCommand {
    /// Upload a local file (ISO, CT template, disk image for import)
    /// to a storage. Destination filename defaults to local basename.
    Upload {
        /// Node hosting the storage (must be reachable).
        node: String,
        /// Storage id (e.g. `local`, `storage`, `nfs-shared`).
        storage: String,
        /// Local file path to upload.
        local_path: std::path::PathBuf,
        /// PVE content bucket: `iso` | `vztmpl` | `import`.
        #[arg(long, default_value = "iso")]
        content: String,
        /// Override destination filename (default: local basename).
        #[arg(long = "as")]
        remote_filename: Option<String>,
        /// Block until the upload task completes.
        #[arg(long)]
        wait: bool,
    },
    /// Delete a content item by `volid`. Format:
    /// `<storage>:<type>/<file>` for files (e.g.
    /// `local:iso/ubuntu.iso`) or `<storage>:<vmid>/<disk>` for VM
    /// disks. Required: `--yes`.
    Delete {
        /// Node hosting the storage.
        node: String,
        /// Volid to delete (e.g. `local:iso/ubuntu-24.04.iso`).
        volid: String,
        /// Required: confirms this destructive op.
        #[arg(long)]
        yes: bool,
        /// Block until the delete task completes.
        #[arg(long)]
        wait: bool,
    },
}

/// Three firewall rule scopes, mirrored from PVE. Each scope is a
/// distinct iptables chain on the host; a packet may traverse rules
/// in all three depending on its path.
#[derive(Debug, Subcommand)]
pub enum FirewallScope {
    /// Datacenter-wide rules (apply to every node and guest).
    Cluster,
    /// Rules attached to a single node's host iptables.
    Node {
        /// Node name
        node: String,
    },
    /// Rules attached to a guest's NIC chain (resolved automatically
    /// from VMID — works for QEMU and LXC).
    Guest {
        /// Guest VMID
        vmid: u32,
    },
}

/// QEMU `vm` subcommand tree. Three branches:
///   - `set` — type-checked top-level config keys (cores, memory, …)
///   - `raw-set` — generic key=value escape hatch
///   - `cloudinit` — cloud-init lifecycle (set + regen)
#[derive(Debug, Subcommand)]
pub enum VmCommand {
    /// Update VM hardware/options. Each flag maps to one PVE config
    /// key; only flags actually passed are sent (no accidental
    /// "reset to default" if you pass `--cores 4` without
    /// `--memory`). For obscure keys, use `proxxx vm raw-set`.
    Set {
        /// Guest VMID
        vmid: u32,
        /// Number of CPU cores (sockets × cores = total vCPUs)
        #[arg(long)]
        cores: Option<u32>,
        /// CPU sockets (defaults to 1 in PVE)
        #[arg(long)]
        sockets: Option<u32>,
        /// Memory in MiB (e.g. `8192` for 8 GiB)
        #[arg(long)]
        memory: Option<u64>,
        /// Balloon target in MiB. Set ≤ `memory` for memory ballooning.
        /// `0` disables ballooning entirely.
        #[arg(long)]
        balloon: Option<u64>,
        /// CPU model (e.g. `host`, `kvm64`, `x86-64-v2-AES`)
        #[arg(long)]
        cpu: Option<String>,
        /// VM display name
        #[arg(long)]
        name: Option<String>,
        /// VM description (markdown supported in PVE web UI)
        #[arg(long)]
        description: Option<String>,
        /// Guest OS type (e.g. `l26` Linux 2.6+, `win11`, `other`)
        #[arg(long)]
        ostype: Option<String>,
    },
    /// Bypass typed flags and submit raw `key=value` pairs straight
    /// to PVE. Use for niche options not covered by `vm set`.
    /// Caller owns correctness — PVE will return a 400 schema error
    /// if a key is misspelled.
    #[command(name = "raw-set")]
    RawSet {
        /// Guest VMID
        vmid: u32,
        /// `key=value` pairs (one per positional arg)
        #[arg(required = true)]
        kvs: Vec<String>,
    },
    /// Cloud-init lifecycle for QEMU VMs.
    Cloudinit {
        #[command(subcommand)]
        action: CloudinitCommand,
    },
    /// Send a key sequence to a QEMU VM via QMP. Common uses: NMI/sysrq
    /// for kernel debugging (`sysrq` then send `t` for task list,
    /// `s` for sync, `c` for crash). `key` syntax follows QMP:
    /// `ctrl-alt-delete`, `sysrq`, single chars, raw scancodes
    /// (`0x42`).
    Sendkey {
        vmid: u32,
        /// Key sequence (e.g. `ctrl-alt-delete`, `sysrq`).
        #[arg(long)]
        key: String,
    },
    /// Detach a disk from a VM's config. Default leaves the underlying
    /// volume — operator can move/reattach later. `--force` ALSO
    /// deletes the volume (destructive — pair with `--yes`).
    Unlink {
        vmid: u32,
        /// CSV of disk ids to detach (e.g. `scsi1,scsi2`).
        #[arg(long)]
        idlist: String,
        /// Also delete the underlying volume(s). Destructive.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Required when `--force` is set.
        #[arg(long)]
        yes: bool,
    },
    /// Dump the cloud-init data PVE will serve to the guest on next
    /// boot. Useful for debugging template inheritance / verifying
    /// `qm set --cipassword/--ciuser/--ipconfig0` actually landed.
    /// `kind` selects which section: `user` | `network` | `meta`.
    CloudinitDump {
        vmid: u32,
        /// `user` (default) | `network` | `meta`.
        #[arg(long, default_value = "user")]
        kind: String,
    },
}

/// Cloud-init operations. After `set`, run `regen` to rebuild the
/// cloud-init drive — without it, the next boot reads stale data.
#[derive(Debug, Subcommand)]
pub enum CloudinitCommand {
    /// Set cloud-init parameters. Remember to run `proxxx vm
    /// cloudinit regen <vmid>` after — without that step the
    /// next boot reads the previous image.
    Set {
        /// Guest VMID
        vmid: u32,
        /// Cloud-init user (default account name)
        #[arg(long)]
        ciuser: Option<String>,
        /// Cloud-init password (sensitive — prefer SSH keys)
        #[arg(long)]
        cipassword: Option<String>,
        /// SSH public keys (concatenate multiple with `\n`)
        #[arg(long)]
        sshkey: Option<String>,
        /// First-NIC IP config (e.g. `ip=10.0.0.5/24,gw=10.0.0.1`
        /// or `ip=dhcp`)
        #[arg(long)]
        ipconfig0: Option<String>,
        /// DNS search domain
        #[arg(long)]
        searchdomain: Option<String>,
        /// DNS resolver IP
        #[arg(long)]
        nameserver: Option<String>,
    },
    /// Regenerate the cloud-init drive. Required after any `set`.
    Regen {
        /// Guest VMID
        vmid: u32,
    },
}

/// LXC `ct` subcommand tree. Smaller than VM — no cloud-init.
#[derive(Debug, Subcommand)]
pub enum CtCommand {
    /// Update container hardware/options.
    Set {
        /// Container VMID
        vmid: u32,
        /// CPU cores
        #[arg(long)]
        cores: Option<u32>,
        /// Memory in MiB
        #[arg(long)]
        memory: Option<u64>,
        /// Swap in MiB
        #[arg(long)]
        swap: Option<u64>,
        /// Container hostname
        #[arg(long)]
        hostname: Option<String>,
        /// Description
        #[arg(long)]
        description: Option<String>,
    },
    /// Bypass typed flags and submit raw `key=value` pairs.
    #[command(name = "raw-set")]
    RawSet {
        /// Container VMID
        vmid: u32,
        /// `key=value` pairs (one per positional arg)
        #[arg(required = true)]
        kvs: Vec<String>,
    },
    /// Container network interfaces (PVE shells to `lxc-info` /
    /// `ip addr` in the container's netns). LXC equivalent of QEMU's
    /// QGA `network-get-interfaces` — works without an agent in
    /// the container.
    Interfaces { vmid: u32 },
}

#[derive(Debug, Subcommand)]
pub enum AccessCommand {
    /// List ACL entries.
    Acl {
        /// Filter to a specific path (substring match).
        #[arg(long)]
        path: Option<String>,
    },
    /// List users.
    Users,
    /// List groups.
    Groups,
    /// List roles (with their privileges).
    Roles,
    /// List authentication realms (PAM/PVE/AD/LDAP/OIDC).
    Realms,
    /// List TFA entries for a user.
    Tfa { userid: String },
    /// Create a user. `userid` must include the realm
    /// (e.g. `alice@pve`, `svc@pam`).
    #[command(name = "user-create")]
    UserCreate {
        userid: String,
        /// Required for `@pve` realm; ignored for `@pam` (the OS owns that).
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        firstname: Option<String>,
        #[arg(long)]
        lastname: Option<String>,
        /// Comma-separated group ids the user joins on creation.
        #[arg(long)]
        groups: Option<String>,
        /// Disable on creation (default: enabled).
        #[arg(long)]
        disabled: bool,
        /// Account expiry as Unix timestamp; omit for never.
        #[arg(long)]
        expire: Option<u64>,
    },
    /// Modify an existing user. Only the fields you pass are changed.
    #[command(name = "user-update")]
    UserUpdate {
        userid: String,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        firstname: Option<String>,
        #[arg(long)]
        lastname: Option<String>,
        /// Comma-separated group ids to REPLACE the user's membership.
        #[arg(long)]
        groups: Option<String>,
        /// Enable the user.
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        /// Disable the user.
        #[arg(long, conflicts_with = "enable")]
        disable: bool,
        #[arg(long)]
        expire: Option<u64>,
    },
    /// Delete a user. PVE refuses if the user owns API tokens —
    /// revoke those first via `proxxx token revoke`.
    #[command(name = "user-delete")]
    UserDelete {
        userid: String,
        #[arg(long)]
        yes: bool,
    },
    /// Create a group.
    #[command(name = "group-create")]
    GroupCreate {
        groupid: String,
        #[arg(long)]
        comment: Option<String>,
    },
    /// Delete a group. PVE refuses if any user is still a member —
    /// remove members first via `proxxx access user-update --groups <new-csv>`.
    #[command(name = "group-delete")]
    GroupDelete {
        groupid: String,
        #[arg(long)]
        yes: bool,
    },
    /// Grant a role to a user/group/token on a path.
    #[command(name = "acl-set")]
    AclSet {
        /// PVE permission path (e.g. `/`, `/vms/100`, `/storage/local`).
        path: String,
        /// Role to grant (e.g. `PVEAuditor`, `PVEAdmin`, `Administrator`).
        #[arg(long)]
        role: String,
        /// Grant to this user (mutually exclusive with --group / --token).
        #[arg(long, conflicts_with_all = ["group", "token"])]
        user: Option<String>,
        /// Grant to this group.
        #[arg(long, conflicts_with_all = ["user", "token"])]
        group: Option<String>,
        /// Grant to this API token (`<userid>!<tokenid>`).
        #[arg(long, conflicts_with_all = ["user", "group"])]
        token: Option<String>,
        /// Disable propagation to child paths (default: propagate).
        #[arg(long)]
        no_propagate: bool,
    },
    /// Revoke a role from a user/group/token on a path.
    #[command(name = "acl-unset")]
    AclUnset {
        path: String,
        #[arg(long)]
        role: String,
        #[arg(long, conflicts_with_all = ["group", "token"])]
        user: Option<String>,
        #[arg(long, conflicts_with_all = ["user", "token"])]
        group: Option<String>,
        #[arg(long, conflicts_with_all = ["user", "group"])]
        token: Option<String>,
        /// Required: confirms this destructive op.
        #[arg(long)]
        yes: bool,
    },
    /// Effective permissions tree for a user (or self) on a path
    /// (or all paths). Hits `/access/permissions` directly — no SSH
    /// dependency, unlike the `proxxx perms` shellout.
    Permissions {
        /// User id (e.g. `alice@pve`). Default: current ticket's user.
        #[arg(long)]
        userid: Option<String>,
        /// ACL path (e.g. `/pool/dev`, `/storage/local`). Default: all.
        #[arg(long)]
        path: Option<String>,
    },
    /// Change a user's password. Requires either being the user
    /// themselves, or `Realm.AllocateUser` on `/access/{realm}`
    /// (typically root@pam).
    Password {
        userid: String,
        /// New password. Use shell history care — passes via `PUT` body.
        #[arg(long)]
        password: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// List tokens for a user.
    List { userid: String },
    /// Create a new token. The secret is printed ONCE — capture it,
    /// proxxx can't recover it later.
    Create {
        userid: String,
        tokenid: String,
        /// Privilege separation (recommended: leave default = true).
        #[arg(long, default_value_t = true)]
        privsep: bool,
        /// Expire timestamp (Unix seconds). Omit for never.
        #[arg(long)]
        expire: Option<u64>,
        #[arg(long)]
        comment: Option<String>,
    },
    /// Revoke a token. Required: `--yes`.
    Revoke {
        userid: String,
        tokenid: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AlertsCommand {
    /// One-shot evaluation of all configured rules. Prints events that
    /// would fire as JSON. Does NOT send. Use this in cron pipelines
    /// piped to your own notifier, or for `--dry-run`-style tests.
    Eval,
    /// Long-running daemon: poll cluster state every `--interval` and
    /// dispatch events through the configured channels. Dedup window
    /// per rule. Stop with Ctrl+C.
    Watch {
        /// Polling interval in seconds. Default 30.
        #[arg(long, default_value_t = 30)]
        interval: u64,
    },
    /// Send a synthetic test event to validate channel config end-to-end.
    Test {
        /// Route spec, e.g. `"telegram"`, `"ntfy:topic"`, `"webhook:URL"`.
        #[arg(long)]
        route: String,
        /// Severity for the test event. Default `info`.
        #[arg(long, default_value = "info")]
        severity: String,
    },
}

/// Selectable metric for `proxxx metrics …`. Each variant maps to a
/// `RrdPoint` field via the extractor in `execute_metrics`. Closed
/// enum (clap ValueEnum) so users can't typo their way into a silent
/// no-op.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum MetricField {
    /// CPU utilisation (0.0..1.0; multiply by 100 for percentage).
    Cpu,
    /// Memory used (bytes). For node, falls back to `memused` when
    /// `mem` is absent (PVE node responses use the verbose name).
    Mem,
    /// Bytes read from disk in this bucket.
    Diskread,
    /// Bytes written to disk in this bucket.
    Diskwrite,
    /// Bytes received on network.
    Netin,
    /// Bytes sent on network.
    Netout,
    /// Load average (node-only).
    Loadavg,
    /// IO-wait fraction (node-only).
    Iowait,
    /// Capacity used. Storage = `used`; guest = `disk`.
    Used,
    /// Total capacity. Storage = `total`; guest = `maxdisk`.
    Total,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TimeframeCli {
    Hour,
    Day,
    Week,
    Month,
    Year,
}

impl From<TimeframeCli> for crate::api::types::RrdTimeframe {
    fn from(t: TimeframeCli) -> Self {
        match t {
            TimeframeCli::Hour => Self::Hour,
            TimeframeCli::Day => Self::Day,
            TimeframeCli::Week => Self::Week,
            TimeframeCli::Month => Self::Month,
            TimeframeCli::Year => Self::Year,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CfCli {
    Average,
    Max,
}

impl From<CfCli> for crate::api::types::RrdCf {
    fn from(c: CfCli) -> Self {
        match c {
            CfCli::Average => Self::Average,
            CfCli::Max => Self::Max,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum MetricsCommand {
    /// Per-VM metrics. Auto-discovers which node owns the VMID unless
    /// `--node` is supplied (faster — skips the cluster-wide scan).
    Vm {
        vmid: u32,
        #[arg(long)]
        node: Option<String>,
        #[arg(long, value_enum, default_value_t = MetricField::Cpu)]
        field: MetricField,
        #[arg(long, value_enum, default_value_t = TimeframeCli::Hour)]
        timeframe: TimeframeCli,
        #[arg(long, value_enum, default_value_t = CfCli::Average)]
        cf: CfCli,
    },
    /// Per-LXC metrics.
    Ct {
        vmid: u32,
        #[arg(long)]
        node: Option<String>,
        #[arg(long, value_enum, default_value_t = MetricField::Cpu)]
        field: MetricField,
        #[arg(long, value_enum, default_value_t = TimeframeCli::Hour)]
        timeframe: TimeframeCli,
        #[arg(long, value_enum, default_value_t = CfCli::Average)]
        cf: CfCli,
    },
    /// Per-node metrics. Adds `loadavg`, `iowait`, root pool usage on
    /// top of the guest fields.
    Node {
        node: String,
        #[arg(long, value_enum, default_value_t = MetricField::Cpu)]
        field: MetricField,
        #[arg(long, value_enum, default_value_t = TimeframeCli::Hour)]
        timeframe: TimeframeCli,
        #[arg(long, value_enum, default_value_t = CfCli::Average)]
        cf: CfCli,
    },
    /// Per-storage capacity metrics (`used` / `total`).
    Storage {
        #[arg(long)]
        node: String,
        #[arg(long)]
        storage: String,
        #[arg(long, value_enum, default_value_t = MetricField::Used)]
        field: MetricField,
        #[arg(long, value_enum, default_value_t = TimeframeCli::Hour)]
        timeframe: TimeframeCli,
        #[arg(long, value_enum, default_value_t = CfCli::Average)]
        cf: CfCli,
    },
    /// Pre-rendered PNG graph reference (server-side path) for a guest.
    /// Distinct from `vm`/`ct` which return numeric series — this is
    /// for UI/export pipelines wanting an existing image.
    RrdPng {
        vmid: u32,
        /// `cpu`, `memory`, `netin`, `netout`, `diskread`, `diskwrite`.
        #[arg(long)]
        ds: String,
        #[arg(long, value_enum, default_value_t = TimeframeCli::Hour)]
        timeframe: TimeframeCli,
        #[arg(long, value_enum, default_value_t = CfCli::Average)]
        cf: CfCli,
    },
}

/// External metric exporter CRUD (`/cluster/metrics/server`).
/// Two protocols supported by PVE: `influxdb` and `graphite`. Each
/// has different mandatory + optional fields; less-common knobs go
/// via `--raw KEY=VAL`.
#[derive(Debug, Subcommand)]
pub enum MetricServersCommand {
    List,
    Show {
        id: String,
    },
    /// Create an exporter. PVE routes per-id: POST /cluster/metrics/
    /// server/{id} with `type` + protocol-specific knobs in the body.
    Create {
        /// Exporter id (operator-chosen name).
        #[arg(long)]
        id: String,
        /// `influxdb` | `graphite`.
        #[arg(long, value_name = "TYPE")]
        server_type: String,
        /// Server hostname or IP.
        #[arg(long)]
        server: String,
        /// Server port (e.g. 8086 for InfluxDB OSS, 2003 for Graphite).
        #[arg(long)]
        port: u16,
        #[arg(long)]
        comment: Option<String>,
        /// influxdb: `udp` | `http` | `https`.
        #[arg(long)]
        influxdbproto: Option<String>,
        /// graphite: `tcp` | `udp`.
        #[arg(long)]
        proto: Option<String>,
        /// influxdb cloud: org. influxdb OSS: ignored.
        #[arg(long)]
        organization: Option<String>,
        /// influxdb: target bucket / database name.
        #[arg(long)]
        bucket: Option<String>,
        /// graphite: top-level path prefix.
        #[arg(long)]
        path: Option<String>,
        /// influxdb 2.x: bearer token.
        #[arg(long)]
        token: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Update {
        id: String,
        #[arg(long)]
        server: Option<String>,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        disable: Option<bool>,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        id: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum NodeShellKind {
    /// Web-based xterm.js shell (POST /termproxy).
    Term,
    /// VNC framebuffer shell (POST /vncshell).
    Vnc,
    /// SPICE shell (POST /spiceshell).
    Spice,
}

#[derive(Debug, Subcommand)]
pub enum NodeCommand {
    /// Start every auto-start guest on the node (`onboot=1` config).
    /// Returns one UPID for the whole batch — track via
    /// `proxxx tasks`. Sequenced PVE-side by `bootorder`.
    Startall {
        /// Target node name (e.g. `pve1`).
        node: String,
    },
    /// Graceful shutdown of every running guest on the node.
    Stopall { node: String },
    /// Suspend every running guest (PVE 8+). On older PVE versions the
    /// endpoint 404s and the call surfaces `ApiError::NotFound`.
    Suspendall { node: String },
    /// Mint a one-shot ticket for shell access to the NODE itself
    /// (not a guest). Three flavours: term (xterm.js), vnc, spice.
    /// proxxx prints the ticket as JSON for handoff to a viewer; it
    /// does NOT embed a graphical client.
    Shell {
        node: String,
        #[arg(long, value_enum, default_value_t = NodeShellKind::Term)]
        kind: NodeShellKind,
    },
}

#[derive(Debug, Subcommand)]
pub enum BackupJobsCommand {
    /// List every scheduled backup job cluster-wide.
    List,
    /// Show one job by id (the autogenerated `backup-…` string from
    /// list output). Returns the same shape as one row of `list`.
    Show { id: String },
    /// Create a new scheduled job. PVE auto-assigns the id; minimum
    /// required is `--schedule` + `--storage` + (`--all` OR `--vmid`).
    /// Use the web UI or `--raw KEY=VAL` for less-common knobs.
    Create {
        /// systemd-time format, e.g. `"mon..fri 02:00"`.
        #[arg(long)]
        schedule: String,
        /// Target storage id.
        #[arg(long)]
        storage: String,
        /// Backup ALL guests (mutually exclusive with --vmid).
        #[arg(long, default_value_t = false)]
        all: bool,
        /// CSV of VMIDs to back up (mutually exclusive with --all).
        #[arg(long)]
        vmid: Option<String>,
        /// `snapshot` (default) | `stop` | `suspend`.
        #[arg(long, default_value = "snapshot")]
        mode: String,
        /// `none` | `lzo` | `gzip` | `zstd`. PVE 7+ default is zstd.
        #[arg(long)]
        compress: Option<String>,
        /// Email destination for run notifications.
        #[arg(long)]
        mailto: Option<String>,
        /// `always` | `failure` (default).
        #[arg(long)]
        mailnotification: Option<String>,
        /// Retention DSL — e.g. `keep-last=3,keep-daily=7`.
        #[arg(long)]
        prune_backups: Option<String>,
        /// Free-form comment shown in the web UI.
        #[arg(long)]
        comment: Option<String>,
        /// Restrict to one node (default: cluster-wide).
        #[arg(long)]
        node: Option<String>,
        /// Raw param escape hatch — repeatable `KEY=VAL`, forwarded
        /// to PVE verbatim. Example: `--raw exclude-path=/tmp/.*`.
        #[arg(long)]
        raw: Vec<String>,
    },
    /// Update one or more fields on an existing job.
    Update {
        id: String,
        #[arg(long)]
        schedule: Option<String>,
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long)]
        compress: Option<String>,
        #[arg(long)]
        prune_backups: Option<String>,
        #[arg(long)]
        comment: Option<String>,
        /// Same escape hatch as `create --raw`.
        #[arg(long)]
        raw: Vec<String>,
    },
    /// Delete a scheduled job. Does NOT delete already-taken backup
    /// archives — only the future-runs schedule.
    Delete {
        id: String,
        /// Required for non-interactive confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Cluster-wide backup volume runtime info. PVE quirk: only the
    /// LITERAL `root@pam` user can call this — token auth gets 403
    /// regardless of ACL ("user != root@pam" in the source).
    Info,
    /// Extract one guest's config from a backup archive — peek at
    /// what the VM looked like when the backup was taken, without
    /// restoring. Returns plain text.
    ExtractConfig {
        #[arg(long)]
        node: String,
        /// Volume id, e.g.
        /// `local:backup/vzdump-qemu-100-2026_05_03-12_00_00.vma.zst`.
        #[arg(long)]
        volume: String,
    },
}

/// Cluster firewall CRUD: aliases (named CIDRs), security groups
/// (rule bundles), ipsets (CIDR collections), and the global options.
/// Splits into four sub-trees so the help text stays grokable — each
/// resource has its own list/create/delete plus resource-specific
/// extras (e.g. `ipset add-cidr`).
#[derive(Debug, Subcommand)]
pub enum FirewallClusterCommand {
    #[command(subcommand)]
    Alias(FirewallAliasCommand),
    #[command(subcommand)]
    Group(FirewallGroupCommand),
    #[command(subcommand)]
    Ipset(FirewallIpsetCommand),
    #[command(subcommand)]
    Options(FirewallOptionsCommand),
}

#[derive(Debug, Subcommand)]
pub enum FirewallAliasCommand {
    List,
    Create {
        #[arg(long)]
        name: String,
        /// CIDR or single IP — e.g. `10.0.0.0/8` or `192.168.1.1`.
        #[arg(long)]
        cidr: String,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Update {
        name: String,
        #[arg(long)]
        cidr: Option<String>,
        #[arg(long)]
        comment: Option<String>,
        /// Rename the alias atomically (PVE PUT param `rename`).
        #[arg(long)]
        rename: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        name: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum FirewallGroupCommand {
    List,
    Create {
        /// Group name (operator-chosen, e.g. `web-allow`).
        #[arg(long)]
        group: String,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        group: String,
        #[arg(long)]
        yes: bool,
    },
    /// List the rules contained in a security group — same shape as
    /// `proxxx firewall --scope cluster`, but filtered to one group.
    Rules {
        group: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum FirewallIpsetCommand {
    List,
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        name: String,
        #[arg(long)]
        yes: bool,
    },
    /// List the CIDRs inside an ipset.
    Cidrs {
        name: String,
    },
    AddCidr {
        name: String,
        #[arg(long)]
        cidr: String,
        /// Invert membership for this CIDR (carves an exception out of
        /// a broader range — `nomatch=1` in PVE terms).
        #[arg(long, default_value_t = false)]
        nomatch: bool,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    RemoveCidr {
        name: String,
        cidr: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum FirewallOptionsCommand {
    /// Read the cluster-wide firewall options.
    Get,
    /// Update one or more cluster-wide firewall options. Refuses no-op
    /// calls (at least one field must change).
    Set {
        /// Master switch — `0` disables the entire cluster firewall.
        #[arg(long)]
        enable: Option<bool>,
        /// `ACCEPT` | `REJECT` | `DROP` (case-sensitive on PVE).
        #[arg(long)]
        policy_in: Option<String>,
        #[arg(long)]
        policy_out: Option<String>,
        #[arg(long)]
        ebtables: Option<bool>,
        /// e.g. `enable=1,burst=5,rate=1/second`.
        #[arg(long)]
        log_ratelimit: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
}

/// Per-guest firewall sub-tree. Same alias CRUD shape as cluster
/// firewall, plus the per-guest options surface (which adds NIC-level
/// knobs absent from the cluster scope: macfilter, ipfilter, dhcp/ndp
/// auto-allow, radv).
#[derive(Debug, Subcommand)]
pub enum FirewallGuestCommand {
    #[command(subcommand)]
    Alias(GuestFirewallAliasCommand),
    #[command(subcommand)]
    Options(GuestFirewallOptionsCommand),
}

#[derive(Debug, Subcommand)]
pub enum GuestFirewallAliasCommand {
    List,
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        cidr: String,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Update {
        name: String,
        #[arg(long)]
        cidr: Option<String>,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        rename: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        name: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum GuestFirewallOptionsCommand {
    Get,
    /// Update per-guest firewall options. Refuses no-op calls.
    Set {
        #[arg(long)]
        enable: Option<bool>,
        #[arg(long)]
        policy_in: Option<String>,
        #[arg(long)]
        policy_out: Option<String>,
        /// `emerg`..`debug` | `nolog`. Empty = inherit cluster default.
        #[arg(long)]
        log_level_in: Option<String>,
        #[arg(long)]
        log_level_out: Option<String>,
        /// Auto-allow DHCP request/reply.
        #[arg(long)]
        dhcp: Option<bool>,
        /// Auto-allow IPv6 NDP.
        #[arg(long)]
        ndp: Option<bool>,
        /// Drop frames whose source MAC ≠ NIC MAC.
        #[arg(long)]
        macfilter: Option<bool>,
        /// Drop frames whose source IP isn't in the per-VM ipset.
        #[arg(long)]
        ipfilter: Option<bool>,
        /// LXC-only: allow router advertisements.
        #[arg(long)]
        radv: Option<bool>,
        #[arg(long)]
        raw: Vec<String>,
    },
}

/// Cluster hardware mapping CRUD — split by device class because the
/// PCI shape carries the mediated-device flag (vGPU) that USB doesn't.
#[derive(Debug, Subcommand)]
pub enum ClusterMappingCommand {
    #[command(subcommand)]
    Pci(ClusterMappingPciCommand),
    #[command(subcommand)]
    Usb(ClusterMappingUsbCommand),
}

#[derive(Debug, Subcommand)]
pub enum ClusterMappingPciCommand {
    List,
    /// Create a new PCI mapping. The `--map` arg accepts the wire
    /// format PVE expects, e.g.
    /// `--map "node=pve1,path=0000:01:00.0,id=10de:2684,iommugroup=13"`.
    /// Repeat once per cluster node.
    Create {
        #[arg(long)]
        id: String,
        #[arg(long)]
        description: Option<String>,
        /// `1` if this is a mediated device (vGPU).
        #[arg(long)]
        mdev: Option<bool>,
        /// One or more `node=…,path=…,id=…[,iommugroup=…]` strings.
        #[arg(long, required = true)]
        map: Vec<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Update {
        id: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        mdev: Option<bool>,
        #[arg(long)]
        map: Vec<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        id: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ClusterMappingUsbCommand {
    List,
    Create {
        #[arg(long)]
        id: String,
        #[arg(long)]
        description: Option<String>,
        /// One or more `node=…,path=…,id=…` strings.
        #[arg(long, required = true)]
        map: Vec<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Update {
        id: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        map: Vec<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        id: String,
        #[arg(long)]
        yes: bool,
    },
}

/// QGA file ops + network introspection. Three commands, one per
/// underlying agent endpoint. `read` and `write` are file ops bounded
/// by QGA's buffer (~16 KiB by default — `read` surfaces a
/// `truncated` flag); `net` returns the per-interface IP table the
/// guest's kernel currently believes.
#[derive(Debug, Subcommand)]
pub enum QgaCommand {
    /// Read a file from inside the guest. Bounded by QGA's read buffer
    /// (~16 KiB default) — operator gets a warning when truncated.
    Read {
        /// Absolute path inside the guest, e.g. `/etc/hostname`.
        #[arg(long)]
        file: String,
    },
    /// Write content to a file inside the guest. PVE base64-encodes
    /// the content before passing to QGA, so plain text is fine.
    Write {
        #[arg(long)]
        file: String,
        /// File content (literal). Use shell quoting for newlines etc.
        #[arg(long)]
        content: String,
    },
    /// Ask the guest's kernel for current network interfaces (names,
    /// MACs, live IPs). Authoritative — beats reading cloud-init.
    Net,
}

/// Node system layer — nine resources rolled into one tree because
/// they share the same `<node>` first arg and the operator usually
/// reaches for several of them in the same maintenance window
/// (check NTP, peek the journal, reload pveproxy after cert upload).
#[derive(Debug, Subcommand)]
pub enum NodeSystemCommand {
    /// DNS resolver config (search domain + up to 3 nameservers).
    #[command(subcommand)]
    Dns(NodeDnsCommand),
    /// `/etc/hosts` content + digest-guarded atomic replace.
    #[command(subcommand)]
    Hosts(NodeHostsCommand),
    /// Tail systemd journal with PVE filters.
    Journal {
        /// ISO timestamp or relative (`-1h`, `yesterday`).
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        /// Cap on returned entries.
        #[arg(long)]
        lastentries: Option<u32>,
        /// Filter to one systemd unit (e.g. `ssh`, `corosync`).
        #[arg(long)]
        service: Option<String>,
    },
    /// Tail `/var/log/syslog` (line-numbered for paging).
    Syslog {
        /// 1-indexed start cursor — pass back the last `n` from the
        /// previous response to paginate forward.
        #[arg(long)]
        start: Option<u64>,
        #[arg(long)]
        limit: Option<u32>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
        #[arg(long)]
        service: Option<String>,
    },
    /// NTP / timezone — `get` reports clock + zone, `set` updates
    /// timezone (clock itself is NTP-driven).
    #[command(subcommand)]
    Time(NodeTimeCommand),
    /// Wake the node from S5/standby via cluster-network magic packet.
    Wol,
    /// Subscription state + key management.
    #[command(subcommand)]
    Subscription(NodeSubscriptionCommand),
    /// pveproxy TLS certificates — list, upload custom, delete custom,
    /// order ACME.
    #[command(subcommand)]
    Cert(NodeCertCommand),
    /// `pvereport` support bundle (plain text, many KB).
    Report,
}

#[derive(Debug, Subcommand)]
pub enum NodeDnsCommand {
    Get,
    Set {
        #[arg(long)]
        search: Option<String>,
        #[arg(long)]
        dns1: Option<String>,
        #[arg(long)]
        dns2: Option<String>,
        #[arg(long)]
        dns3: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum NodeHostsCommand {
    Get,
    /// Replace the entire `/etc/hosts` content. PVE rejects with 412
    /// if `--digest` doesn't match the current file (atomic update);
    /// pass `--no-check` to skip the digest guard.
    Set {
        /// Literal file content (use shell quoting for newlines).
        #[arg(long)]
        data: String,
        /// SHA-1 digest from a prior `get` — required unless
        /// `--no-check` is passed.
        #[arg(long)]
        digest: Option<String>,
        #[arg(long)]
        no_check: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum NodeTimeCommand {
    Get,
    Set {
        /// IANA timezone name (e.g. `Europe/Rome`, `UTC`).
        #[arg(long)]
        timezone: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum NodeSubscriptionCommand {
    /// Show current subscription state — status, level, due date.
    Get,
    /// Set the subscription key. PVE validates against the licensing
    /// server inline; failure surfaces as an API error.
    Set {
        #[arg(long)]
        key: String,
    },
    /// Force re-validate of the existing key (e.g. after a network blip).
    Refresh,
    /// Remove the subscription key. Destructive — requires `--yes`.
    Delete {
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum NodeCertCommand {
    /// List currently-served certs (filename, fingerprint, expiry, SAN).
    Info,
    /// Upload an operator-managed cert + key (writes to
    /// `pveproxy-ssl.{pem,key}`).
    Upload {
        /// PEM-encoded certificate (literal content).
        #[arg(long)]
        certificate: String,
        /// PEM-encoded private key (literal content).
        #[arg(long)]
        key: String,
        /// Reload pveproxy after writing.
        #[arg(long, default_value_t = false)]
        restart: bool,
    },
    /// Remove the operator-uploaded custom cert.
    Delete {
        #[arg(long, default_value_t = false)]
        restart: bool,
        #[arg(long)]
        yes: bool,
    },
    /// Trigger ACME order/renewal. Returns a UPID (long task —
    /// DNS-01 / HTTP-01 round-trips with the CA).
    AcmeOrder {
        /// Renew even if the existing cert isn't near expiry.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
}

/// Pool CRUD. Member changes (`add`/`remove`) split out so the operator
/// doesn't have to type `vms=` / `storage=` / `delete=1` form params
/// directly — typed flags compose into them.
#[derive(Debug, Subcommand)]
pub enum PoolCommand {
    /// List every pool in the cluster.
    List,
    /// Show one pool's full member list (mixed VMs/LXCs/storages).
    Show { poolid: String },
    /// Create a new (empty) pool.
    Create {
        #[arg(long)]
        poolid: String,
        #[arg(long)]
        comment: Option<String>,
    },
    /// Add members (VMIDs and/or storage ids) to an existing pool.
    AddMembers {
        poolid: String,
        /// CSV of VMIDs to add (e.g. `100,200,300`).
        #[arg(long)]
        vms: Option<String>,
        /// CSV of storage ids to add (e.g. `local,pbs-main`).
        #[arg(long)]
        storage: Option<String>,
    },
    /// Remove members from a pool. Same shape as `add-members` but
    /// PVE-side it's the same PUT with `delete=1`.
    RemoveMembers {
        poolid: String,
        #[arg(long)]
        vms: Option<String>,
        #[arg(long)]
        storage: Option<String>,
    },
    /// Edit just the comment.
    SetComment {
        poolid: String,
        #[arg(long)]
        comment: String,
    },
    /// Delete an empty pool. PVE rejects with 400 if there are still
    /// members — `remove-members` first.
    Delete {
        poolid: String,
        #[arg(long)]
        yes: bool,
    },
}

/// Cluster-wide config. Just `get` + `set` — most operators read once,
/// edit a few fields, walk away. `--raw KEY=VAL` covers the long tail
/// of less-common knobs (crs, fencing, u2f schema).
#[derive(Debug, Subcommand)]
pub enum ClusterConfigCommand {
    Get,
    /// Update one or more cluster-wide options. Refuses no-op calls.
    Set {
        /// MAC prefix for auto-generated guest NICs (e.g. `BC:24:11`).
        #[arg(long)]
        mac_prefix: Option<String>,
        /// Default migration network/type (e.g.
        /// `type=insecure,network=10.0.0.0/24`).
        #[arg(long)]
        migration: Option<String>,
        #[arg(long)]
        description: Option<String>,
        /// Console viewer choice: `applet` | `vv` | `html5` | `xtermjs`.
        #[arg(long)]
        console: Option<String>,
        /// Default keyboard layout for VNC/console.
        #[arg(long)]
        keyboard: Option<String>,
        #[arg(long)]
        max_workers: Option<u32>,
        #[arg(long)]
        email_from: Option<String>,
        /// Allowed tags (semicolon-separated).
        #[arg(long)]
        registered_tags: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
}

/// PVE 8+ notifications. Three sub-trees, one per resource:
/// `endpoint` (delivery mechanisms), `matcher` (routing rules),
/// `target` (read-only valid-name list).
#[derive(Debug, Subcommand)]
pub enum NotificationsCommand {
    #[command(subcommand)]
    Endpoint(NotificationEndpointCommand),
    #[command(subcommand)]
    Matcher(NotificationMatcherCommand),
    /// List all valid delivery target names (endpoints + groups).
    Targets,
}

#[derive(Debug, Subcommand)]
pub enum NotificationEndpointCommand {
    /// List all configured endpoints across all types.
    List,
    /// Create an endpoint. Type-specific knobs go via `--raw KEY=VAL`
    /// (e.g. for smtp: `--raw server=mail.example.com --raw from=…`;
    /// for gotify: `--raw server=https://gotify.example.com --raw token=…`).
    Create {
        /// Endpoint type: `sendmail` | `smtp` | `gotify` | `webhook`.
        #[arg(long)]
        endpoint_type: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Update {
        #[arg(long)]
        endpoint_type: String,
        name: String,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        disable: Option<bool>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        #[arg(long)]
        endpoint_type: String,
        name: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum NotificationMatcherCommand {
    List,
    /// Create a routing rule. `--target` is repeatable (each one is an
    /// endpoint or group name). Match clauses via `--match-field` /
    /// `--match-severity` (also repeatable).
    Create {
        #[arg(long)]
        name: String,
        /// Repeatable — endpoint/group names to deliver matched events to.
        #[arg(long, required = true)]
        target: Vec<String>,
        /// Repeatable — `field=pattern` clauses (e.g. `type=vzdump`).
        #[arg(long)]
        match_field: Vec<String>,
        /// Repeatable — severity filters (`error`, `warning`, etc.).
        #[arg(long)]
        match_severity: Vec<String>,
        /// `all` (default) | `any`.
        #[arg(long)]
        mode: Option<String>,
        #[arg(long)]
        invert_match: Option<bool>,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Update {
        name: String,
        #[arg(long)]
        target: Vec<String>,
        #[arg(long)]
        match_field: Vec<String>,
        #[arg(long)]
        match_severity: Vec<String>,
        #[arg(long)]
        mode: Option<String>,
        #[arg(long)]
        invert_match: Option<bool>,
        #[arg(long)]
        disable: Option<bool>,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        name: String,
        #[arg(long)]
        yes: bool,
    },
}

/// Cluster-wide storage definitions CRUD. Common knobs are flagged
/// (`--type`, `--content`, `--path`, `--server`, `--datastore`,
/// `--pool`, `--export`, `--username`, `--fingerprint`); type-specific
/// fields go via `--raw KEY=VAL`.
#[derive(Debug, Subcommand)]
pub enum StorageDefsCommand {
    List,
    Show {
        storage: String,
    },
    /// Create a new storage. PVE validates type-specific required fields
    /// inline (e.g. `nfs` requires `--server` + `--export`; `pbs`
    /// requires `--server` + `--datastore`).
    Create {
        /// Storage id (operator-chosen name).
        #[arg(long)]
        storage: String,
        /// Storage type: `dir` | `lvm` | `lvmthin` | `zfspool` | `nfs`
        /// | `cifs` | `iscsi` | `glusterfs` | `cephfs` | `rbd` | `pbs`
        /// | `btrfs` | `esxi`.
        #[arg(long, value_name = "TYPE")]
        storage_type: String,
        /// CSV: `vztmpl,iso,backup,images,rootdir,snippets`.
        #[arg(long)]
        content: Option<String>,
        /// CSV node-restriction. Empty = all nodes (default).
        #[arg(long)]
        nodes: Option<String>,
        /// 1 = visible to every node (NFS, PBS, CephFS, etc.).
        #[arg(long)]
        shared: Option<bool>,
        /// `dir` / `btrfs`: filesystem path.
        #[arg(long)]
        path: Option<String>,
        /// `nfs` / `cifs` / `pbs` / `iscsi`: server hostname/IP.
        #[arg(long)]
        server: Option<String>,
        /// `nfs`: export path on the server.
        #[arg(long)]
        export: Option<String>,
        /// `pbs`: datastore name.
        #[arg(long)]
        datastore: Option<String>,
        /// `pbs` / `cifs`: TLS fingerprint for verification.
        #[arg(long)]
        fingerprint: Option<String>,
        /// `cifs` / `pbs`: auth username.
        #[arg(long)]
        username: Option<String>,
        /// `zfspool` / `rbd`: ZFS dataset / Ceph pool name.
        #[arg(long)]
        pool: Option<String>,
        /// `lvm` / `lvmthin`: volume group name.
        #[arg(long)]
        vgname: Option<String>,
        /// `lvmthin`: thin pool name within `vgname`.
        #[arg(long)]
        thinpool: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    /// Update an existing storage. `type` cannot be changed (PVE rejects
    /// with 400). Refuses no-op calls.
    Update {
        storage: String,
        #[arg(long)]
        content: Option<String>,
        #[arg(long)]
        nodes: Option<String>,
        #[arg(long)]
        disable: Option<bool>,
        #[arg(long)]
        shared: Option<bool>,
        /// `pbs` / `cifs`: TLS fingerprint.
        #[arg(long)]
        fingerprint: Option<String>,
        /// Comma-separated list of fields to clear (PVE PUT param `delete`).
        #[arg(long)]
        delete: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        storage: String,
        #[arg(long)]
        yes: bool,
    },
}

/// ACME cluster-wide config. Five sub-trees mapping 1:1 to PVE
/// resources: `account` (CA registration), `plugin` (DNS-01/HTTP-01
/// challenge runners), `tos` / `directories` / `challenge-schema`
/// (read-only support endpoints).
#[derive(Debug, Subcommand)]
pub enum AcmeCommand {
    #[command(subcommand)]
    Account(AcmeAccountCommand),
    #[command(subcommand)]
    Plugin(AcmePluginCommand),
    /// Fetch the Terms-of-Service URL for the chosen ACME directory
    /// (defaults to PVE's default — usually Let's Encrypt prod).
    Tos {
        #[arg(long)]
        directory: Option<String>,
    },
    /// List ACME-compatible CAs PVE knows about.
    Directories,
    /// Dump the DNS-01 plugin schema list (raw JSON — wizard fodder).
    ChallengeSchema,
}

#[derive(Debug, Subcommand)]
pub enum AcmeAccountCommand {
    List,
    Show {
        name: String,
    },
    /// Register a new account with the ACME CA. Returns a UPID — the
    /// call is async (CA round-trip).
    Create {
        #[arg(long)]
        name: String,
        /// Contact email(s), CSV (`mailto:` prefix optional).
        #[arg(long)]
        contact: String,
        /// ToS URL to confirm acceptance — get it via `proxxx acme tos`.
        #[arg(long)]
        tos_url: Option<String>,
        /// ACME directory URL (defaults to LE prod).
        #[arg(long)]
        directory: Option<String>,
        /// External Account Binding key id (some CAs require it).
        #[arg(long)]
        eab_kid: Option<String>,
        #[arg(long)]
        eab_hmac_key: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    /// Update account contact / state. Returns a UPID.
    Update {
        name: String,
        #[arg(long)]
        contact: Option<String>,
        #[arg(long)]
        raw: Vec<String>,
    },
    /// Deactivate the account on the CA + remove local config.
    /// Returns a UPID.
    Delete {
        name: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum AcmePluginCommand {
    List,
    Show {
        plugin_id: String,
    },
    /// Create a challenge plugin. DNS-01 needs `--api` + `--data`;
    /// HTTP-01 (`--plugin-type standalone`) is config-free.
    Create {
        #[arg(long)]
        plugin_id: String,
        /// `dns` | `standalone` (HTTP-01).
        #[arg(long)]
        plugin_type: String,
        /// DNS plugin name (`cloudflare`, `route53`, `gandi_livedns`, ...).
        #[arg(long)]
        api: Option<String>,
        /// DNS API credentials (sub-spec, e.g. `CF_Token=…`).
        #[arg(long)]
        data: Option<String>,
        /// Seconds to wait for DNS propagation before validating.
        #[arg(long)]
        validation_delay: Option<u32>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Update {
        plugin_id: String,
        #[arg(long)]
        api: Option<String>,
        #[arg(long)]
        data: Option<String>,
        #[arg(long)]
        validation_delay: Option<u32>,
        #[arg(long)]
        disable: Option<bool>,
        #[arg(long)]
        raw: Vec<String>,
    },
    Delete {
        plugin_id: String,
        #[arg(long)]
        yes: bool,
    },
}

/// Corosync cluster bootstrap. Four sub-trees: `nodes` (membership),
/// `join` (bootstrap a new node into an existing cluster), `qdevice`
/// (3rd-party tiebreaker for even-node clusters), `totem` (read-only
/// transport inspection).
#[derive(Debug, Subcommand)]
pub enum ClusterBootstrapCommand {
    #[command(subcommand)]
    Nodes(CorosyncNodesCommand),
    #[command(subcommand)]
    Join(ClusterJoinCommand),
    #[command(subcommand)]
    Qdevice(ClusterQdeviceCommand),
    /// Inspect corosync totem transport config (read-only — totem
    /// changes go through `/etc/pve/corosync.conf` editing).
    Totem,
}

#[derive(Debug, Subcommand)]
pub enum CorosyncNodesCommand {
    List,
    /// Add a node to corosync membership. Optional knobs let you pin
    /// the nodeid + ring addresses + vote count instead of letting
    /// PVE auto-assign.
    Add {
        node: String,
        /// Primary corosync ring address (hostname or IP).
        #[arg(long)]
        ring0_addr: Option<String>,
        /// Secondary corosync ring address (knet redundancy).
        #[arg(long)]
        ring1_addr: Option<String>,
        /// Pin the corosync nodeid (default: PVE auto-assigns).
        #[arg(long)]
        nodeid: Option<u32>,
        /// Quorum votes for this node (default 1).
        #[arg(long)]
        votes: Option<u32>,
        /// Skip safety checks (dangerous — only for recovery).
        #[arg(long, default_value_t = false)]
        force: bool,
        #[arg(long)]
        raw: Vec<String>,
    },
    /// Remove a node from corosync membership. Destructive — requires `--yes`.
    Remove {
        node: String,
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ClusterJoinCommand {
    /// Fetch the join data + totem config + cert fingerprint a new
    /// node needs to join. PVE 8+ requires `--node` (the new node's
    /// intended name).
    Info {
        #[arg(long)]
        node: Option<String>,
    },
    /// Actually join an existing cluster from the new-node side.
    /// Needs the target cluster's hostname + a root password + the
    /// cert fingerprint (use `info` on the target side first).
    /// Returns a UPID — corosync restart involved.
    Join {
        /// Target cluster node hostname/IP.
        #[arg(long)]
        hostname: String,
        /// Root password on the target node.
        #[arg(long)]
        password: String,
        /// Cluster cert fingerprint (SHA-256, colon-separated).
        #[arg(long)]
        fingerprint: String,
        /// Override this new node's nodeid (default: auto-assigned).
        #[arg(long)]
        nodeid: Option<u32>,
        /// Override this node's vote count.
        #[arg(long)]
        votes: Option<u32>,
        /// Force-join despite safety check failures.
        #[arg(long, default_value_t = false)]
        force: bool,
        #[arg(long)]
        raw: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum ClusterQdeviceCommand {
    /// Read the current quorum-device config (singleton per cluster).
    Get,
    /// Set up a new quorum device. Required: `--addr` (qdevice host).
    /// Returns a UPID (corosync restart).
    Setup {
        /// Quorum device host address.
        #[arg(long)]
        addr: String,
        /// Voting algorithm: `ffsplit` | `lms` (last-man-standing).
        #[arg(long)]
        algorithm: Option<String>,
        /// Tie-breaker mode: `lowest` | `highest` | `valid_quorum_policy`.
        #[arg(long)]
        tie_breaker: Option<String>,
        /// Operator name on the qdevice host (default `root`).
        #[arg(long)]
        net_username: Option<String>,
        /// Force-setup despite safety check failures.
        #[arg(long, default_value_t = false)]
        force: bool,
        #[arg(long)]
        raw: Vec<String>,
    },
    /// Update an existing qdevice config (no-op refused).
    Update {
        #[arg(long)]
        algorithm: Option<String>,
        #[arg(long)]
        tie_breaker: Option<String>,
        #[arg(long)]
        force: Option<bool>,
        #[arg(long)]
        raw: Vec<String>,
    },
    /// Remove the quorum device. Destructive — requires `--yes`.
    /// Returns a UPID.
    Delete {
        #[arg(long)]
        yes: bool,
    },
}

/// LXC template catalog (PVE's curated upstream).
#[derive(Debug, Subcommand)]
pub enum AplinfoCommand {
    /// List available templates from the PVE catalog (≈ `pveam available`).
    List {
        /// Node from which to query the catalog (any cluster member works).
        #[arg(long)]
        node: String,
    },
    /// Download a template to a node's storage. Returns a UPID — long
    /// task (template fetch from PVE mirrors).
    Download {
        #[arg(long)]
        node: String,
        /// Target storage id (must support content type `vztmpl`).
        #[arg(long)]
        storage: String,
        /// Template name from `list` (e.g.
        /// `debian-12-standard_12.7-1_amd64.tar.zst`).
        #[arg(long)]
        template: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum DisksCommand {
    /// Physical disk inventory: model, serial, size, current usage,
    /// SMART verdict. One row per `/dev/sd*` / `/dev/nvme*`.
    List {
        #[arg(long)]
        node: String,
    },
    /// Full SMART output for one disk. Use the `devpath` from
    /// `disks list` (e.g. `/dev/sda`). For NVME the `attributes`
    /// table is empty — the smartctl `text` blob carries the
    /// data instead.
    Smart {
        #[arg(long)]
        node: String,
        /// Block device path, e.g. `/dev/sda` or `/dev/nvme0n1`.
        #[arg(long)]
        disk: String,
    },
    /// LVM volume groups on the node.
    Lvm {
        #[arg(long)]
        node: String,
    },
    /// LVM-thin pools on the node. The `metadata_used / metadata_size`
    /// ratio is the canary — at ~1.0 the thin pool stops accepting
    /// writes and every VM on top of it freezes.
    Lvmthin {
        #[arg(long)]
        node: String,
    },
    /// ZFS pools on the node. Watch `health != "ONLINE"` — anything
    /// else (DEGRADED, FAULTED, REMOVED, UNAVAIL) is operator-actionable.
    Zfs {
        #[arg(long)]
        node: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum HwCommand {
    /// List PCI devices on a node, including IOMMU group ids.
    Pci {
        #[arg(long)]
        node: String,
    },
    /// List USB devices on a node.
    Usb {
        #[arg(long)]
        node: String,
    },
    /// Detect passthrough conflicts (direct shared + IOMMU group split).
    /// Scans every guest's config and cross-references with the node's
    /// hardware list.
    Conflicts {
        #[arg(long)]
        node: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum HaCommand {
    /// List HA groups (PVE-version-tolerant: hits `/cluster/ha/rules`
    /// on PVE 9, falls back to `/cluster/ha/groups` semantics).
    Groups,
    /// Hit the LITERAL `/cluster/ha/groups` path (PVE 8 only — on
    /// PVE 9 this returns 500 because the path was migrated to
    /// `/cluster/ha/rules`).
    GroupsLegacy,
    /// Create an HA group (PVE 8). Nodes are CSV with optional
    /// `:priority` suffixes, e.g. `pve1:2,pve2:1,pve3`.
    GroupCreate {
        #[arg(long)]
        group: String,
        /// Member nodes, CSV with optional `:N` priorities.
        #[arg(long)]
        nodes: String,
        /// Restrict resources to nodes in the group only (no fallback
        /// to other nodes when all members are down).
        #[arg(long, default_value_t = false)]
        restricted: bool,
        /// Don't auto-fall-back when the preferred node returns.
        #[arg(long, default_value_t = false)]
        nofailback: bool,
        #[arg(long)]
        comment: Option<String>,
    },
    /// Update an HA group's nodes / restricted / nofailback / comment.
    GroupUpdate {
        group: String,
        #[arg(long)]
        nodes: Option<String>,
        #[arg(long)]
        restricted: Option<bool>,
        #[arg(long)]
        nofailback: Option<bool>,
        #[arg(long)]
        comment: Option<String>,
    },
    /// Delete an HA group. Refuses unless `--yes` is passed.
    GroupDelete {
        group: String,
        #[arg(long)]
        yes: bool,
    },
    /// List HA-managed resources (VMs/CTs).
    Resources,
    /// Show the HA manager runtime status (raw CRM internal state).
    Status,
    /// User-facing live HA status — heterogeneous list mixing per-node,
    /// per-service, and master/quorum rows. Higher-level than `status`.
    StatusCurrent,
    /// "What if?" preview: where does each resource land if a node fails?
    Preview {
        /// Node to simulate as failed.
        #[arg(long)]
        node: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum ReplicationCommand {
    /// List configured replication jobs (cluster-wide).
    Jobs,
    /// Show runtime status of replication jobs on one node.
    Status {
        #[arg(long)]
        node: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum PbsCommand {
    /// List datastores on the configured PBS server.
    Datastores,
    /// List snapshots in a datastore. Optional filters by guest type/id.
    Snapshots {
        #[arg(long)]
        store: String,
        /// Filter: backup type (`vm`, `ct`, `host`).
        #[arg(long)]
        backup_type: Option<String>,
        /// Filter: backup id (e.g. `100`).
        #[arg(long)]
        backup_id: Option<String>,
    },
    /// List archive files inside a specific snapshot.
    Files {
        #[arg(long)]
        store: String,
        #[arg(long = "type")]
        backup_type: String,
        #[arg(long)]
        backup_id: String,
        /// Snapshot timestamp (Unix seconds).
        #[arg(long = "time")]
        backup_time: u64,
    },
    /// Restore a full archive to a local target directory.
    /// Single-file extraction is NOT supported in this MVP — declared cut.
    Restore {
        #[arg(long)]
        store: String,
        /// Snapshot reference, e.g. `vm/100/2024-01-15T10:00:00Z`.
        #[arg(long)]
        snapshot: String,
        /// Archive name, e.g. `root.pxar.didx`.
        #[arg(long)]
        archive: String,
        /// Local directory to restore into.
        #[arg(long)]
        target: std::path::PathBuf,
        /// Required: confirms this writes to the local filesystem.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum IsoCommand {
    /// List the curated library entries (id, distro, version, sha256).
    List,
    /// Download a curated entry by id, or a custom URL.
    Download {
        /// Library entry id (see `iso list`). Mutually exclusive with `--url`.
        #[arg(long)]
        id: Option<String>,
        /// Custom URL (overrides `--id`). Pair with `--filename`.
        #[arg(long)]
        url: Option<String>,
        /// Filename to store as. Required with `--url`.
        #[arg(long)]
        filename: Option<String>,
        /// Optional SHA-256 to pin (Proxmox verifies).
        #[arg(long)]
        sha256: Option<String>,
        /// Content category: iso | import | vztmpl. Required with `--url`.
        #[arg(long)]
        content: Option<String>,
        /// Target node (which Proxmox node performs the download).
        #[arg(long)]
        node: String,
        /// Target storage name on that node.
        #[arg(long)]
        storage: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum DiskCommand {
    /// Move a disk to a different storage backend.
    Move {
        /// Guest VMID
        vmid: u32,
        /// Disk identifier (e.g. `scsi0` for QEMU, `rootfs` or `mp0` for LXC)
        #[arg(long)]
        disk: String,
        /// Target storage name (e.g. `ceph-rbd`, `local-lvm`)
        #[arg(long)]
        storage: String,
        /// Remove source disk after copy. Default: keep as `unused0:`
        /// (avoids storage leak on long-lived workflows; CLI default
        /// errs on the side of preserving user data).
        #[arg(long)]
        delete_source: bool,
        /// Required: confirms this destructive op
        #[arg(long)]
        yes: bool,
        /// Override proxxx pre-flight risk checks (e.g. PVE lock from
        /// concurrent op, HA-managed guest, active traffic).
        #[arg(long)]
        allow_risk: bool,
        /// Block until the move task completes. Without this, returns
        /// the UPID immediately and the caller must poll. With it,
        /// proxxx polls `/tasks/{upid}/status` and exits 0/1 based on
        /// task exitstatus.
        #[arg(long)]
        wait: bool,
    },
    /// Resize a disk. Proxmox forbids shrinking — `size` must be larger.
    Resize {
        /// Guest VMID
        vmid: u32,
        /// Disk identifier
        #[arg(long)]
        disk: String,
        /// New size — Proxmox accepts `+10G` (delta) or `100G` (absolute target)
        #[arg(long)]
        size: String,
        /// Required: confirms this destructive op
        #[arg(long)]
        yes: bool,
        /// Override proxxx pre-flight risk checks.
        #[arg(long)]
        allow_risk: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum PatchCommand {
    /// Show what would be upgraded across the cluster (apt update + list).
    /// No SSH required — pure API.
    Plan {
        /// Restrict to specific node(s). Repeatable.
        #[arg(long)]
        node: Vec<String>,
    },
    /// Execute the patch plan. Requires `[profiles.X.ssh]` configured.
    Apply {
        /// Restrict to specific node(s). Repeatable.
        #[arg(long)]
        node: Vec<String>,
        /// Reboot policy.
        #[arg(long, value_enum, default_value_t = RebootCli::Auto)]
        reboot: RebootCli,
        /// Plan and walk the state machine without running apt or rebooting.
        #[arg(long)]
        dry_run: bool,
        /// Hard timeout for apt upgrade per node (seconds).
        #[arg(long, default_value_t = 1800)]
        upgrade_timeout: u64,
        /// Hard timeout for post-reboot wait per node (seconds).
        #[arg(long, default_value_t = 600)]
        reboot_wait: u64,
    },
    /// Show configured apt repositories on a node (sources.list +
    /// sources.list.d). Helps diagnose "why isn't this update visible
    /// to me" — usually a missing or disabled repo.
    Repositories {
        #[arg(long)]
        node: String,
    },
    /// Plain-text changelog for one installed package on a node.
    /// Useful for "what's actually changed" before running `apply`.
    Changelog {
        #[arg(long)]
        node: String,
        /// Package name, e.g. `proxmox-ve`, `pve-manager`, `linux-image-amd64`.
        #[arg(long)]
        package: String,
    },
    /// List every installed package on a node with version + state.
    /// Useful for kernel/manager-version drift across the cluster
    /// (`proxxx patch versions --node X | jq '.[] | select(.package=="proxmox-ve")'`).
    Versions {
        #[arg(long)]
        node: String,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum RebootCli {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SerialKind {
    Qemu,
    Lxc,
}

impl From<SerialKind> for crate::api::types::GuestType {
    fn from(s: SerialKind) -> Self {
        match s {
            SerialKind::Qemu => Self::Qemu,
            SerialKind::Lxc => Self::Lxc,
        }
    }
}

impl From<RebootCli> for crate::app::patch::RebootPolicy {
    fn from(v: RebootCli) -> Self {
        match v {
            RebootCli::Auto => Self::Auto,
            RebootCli::Always => Self::Always,
            RebootCli::Never => Self::Never,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum HitlCommand {
    /// Start the HITL Telegram daemon
    Serve,
}

#[derive(Debug, Subcommand)]
pub enum SnapshotCommand {
    /// Create a snapshot
    Create {
        vmid: u32,
        #[arg(long)]
        name: String,
    },
    /// Delete a snapshot
    Delete {
        vmid: u32,
        #[arg(long)]
        name: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Start MCP server
    Serve,
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
        return execute_init(*force);
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
        Command::Start { vmids, strict } => {
            execute_batch_op(&client, BatchOp::Start, &vmids, &config, strict).await
        }
        Command::Stop {
            vmids,
            force,
            strict,
            allow_risk,
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
            execute_batch_op(&client, BatchOp::Stop { force }, &vmids, &config, strict).await
        }
        Command::Restart {
            vmids,
            strict,
            allow_risk,
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
            execute_batch_op(&client, BatchOp::Restart, &vmids, &config, strict).await
        }
        Command::Suspend { vmids, strict } => {
            // No preflight: suspend is non-destructive (RAM frozen,
            // no state lost on resume). Mirror Restart's batch-op
            // dispatch shape.
            execute_batch_op(&client, BatchOp::Suspend, &vmids, &config, strict).await
        }
        Command::Resume { vmids, strict } => {
            execute_batch_op(&client, BatchOp::Resume, &vmids, &config, strict).await
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
            if wait {
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
        Command::Aplinfo { action } => execute_aplinfo(&client, action).await,
        Command::UrlInfo { node, url } => {
            let meta = client.query_url_metadata(&node, &url).await?;
            Ok((serde_json::to_value(meta)?, 0))
        }
        Command::MetricServers { action } => execute_metric_servers(&client, action).await,
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
        } => {
            let (src_node, gt) = find_guest(&client, src_vmid).await?;
            // Auto-fetch newid only when the user didn't pin one — saves
            // a round-trip on the common explicit case while keeping the
            // ergonomic `proxxx clone 9000` (no flags) workflow.
            let target_id = match newid {
                Some(n) => n,
                None => client.next_free_vmid().await?,
            };
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
                }),
                0,
            ))
        }
        Command::Snapshot { action } => execute_snapshot(&client, action).await,
        Command::Mcp { action } => match action {
            McpCommand::Serve => {
                crate::mcp::server::run_server(
                    std::sync::Arc::clone(&client),
                    std::sync::Arc::new(config),
                )
                .await?;
                Ok((serde_json::json!({"status": "MCP server stopped"}), 0))
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
            notify,
        } => {
            if let Some(target) = target {
                let until = until.unwrap_or_else(|| "status=running".to_string());
                use crate::api::ProxmoxGateway;
                use tokio::time::{sleep, Duration};

                let (key, value) = if let Some((k, v)) = until.split_once('=') {
                    (k.trim().to_lowercase(), v.trim().to_lowercase())
                } else {
                    anyhow::bail!("Invalid condition format. Use key=value");
                };

                let mut met = false;
                tracing::info!("Watching {} until {}={}", target, key, value);

                while !met {
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

                                        if current_val == value {
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
                                        let threshold: f64 = value.trim_end_matches('%').parse()?;
                                        if value.starts_with('<') {
                                            if usage_pct < threshold {
                                                met = true;
                                            }
                                        } else if usage_pct > threshold {
                                            met = true;
                                        }
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
        Command::Patch { action } => execute_patch(client, &config, action).await,
        Command::Disk { action } => execute_disk(&client, action).await,
        Command::Iso { action } => execute_iso(&client, action).await,
        Command::Pbs { action } => execute_pbs(&config, action, cli_secret).await,
        Command::Ha { action } => execute_ha(&client, action).await,
        Command::Replication { action } => execute_replication(&client, action).await,
        Command::Hw { action } => execute_hw(&client, action).await,
        Command::Disks { action } => execute_disks(&client, action).await,
        Command::Node { action } => execute_node(&client, action).await,
        Command::Metrics { action } => execute_metrics(&client, action).await,
        Command::Vnc { vmid, node, ws_url } => execute_vnc(&client, vmid, node, ws_url).await,
        Command::BackupJobs { action } => execute_backup_jobs(&client, action).await,
        Command::FirewallCluster { action } => execute_firewall_cluster(&client, action).await,
        Command::FirewallGuest { vmid, action } => {
            execute_firewall_guest(&client, vmid, action).await
        }
        Command::ClusterMapping { action } => execute_cluster_mapping(&client, action).await,
        Command::Qga { vmid, action } => execute_qga(&client, vmid, action).await,
        Command::NodeSystem { node, action } => execute_node_system(&client, &node, action).await,
        Command::Pool { action } => execute_pool(&client, action).await,
        Command::ClusterResources { kind } => execute_cluster_resources(&client, kind).await,
        Command::PveVersion => execute_pve_version(&client).await,
        Command::ClusterConfig { action } => execute_cluster_config(&client, action).await,
        Command::ClusterLog { max } => execute_cluster_log(&client, max).await,
        Command::Notifications { action } => execute_notifications(&client, action).await,
        Command::StorageDefs { action } => execute_storage_defs(&client, action).await,
        Command::Acme { action } => execute_acme(&client, action).await,
        Command::ClusterBootstrap { action } => execute_cluster_bootstrap(&client, action).await,
        Command::Alerts { action } => execute_alerts(&client, &config, profile, action).await,
        Command::Access { action } => execute_access(&client, action).await,
        Command::Token { action } => execute_token(&client, action).await,
        Command::Perms { userid, path, node } => {
            execute_perms(&config, &userid, path.as_deref(), &node).await
        }
        Command::Serial { vmid, node, kind } => {
            execute_serial(&client, &config, vmid, &node, kind).await
        }
        Command::Ssh { vmid, cmd } => execute_ssh(&client, &config, vmid, cmd.as_deref()).await,
        Command::Spice {
            vmid,
            node,
            write_vv,
            no_launch,
        } => execute_spice(&client, vmid, &node, write_vv, no_launch).await,
        Command::Novnc {
            vmid,
            node,
            kind,
            no_launch,
        } => execute_novnc(&client, &config, vmid, &node, kind, no_launch).await,
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
        Command::Init {
            force: _,
            interactive: _,
        } => {
            // Unreachable: short-circuited before `load_config` so it
            // works on a fresh machine. Kept here for exhaustiveness.
            unreachable!("Init handled in early-exit block")
        }
        Command::Vm { action } => execute_vm(&client, action).await,
        Command::Ct { action } => execute_ct(&client, action).await,
        Command::Firewall { scope } => execute_firewall(&client, scope).await,
        Command::Network { node } => {
            let interfaces = client.list_node_network(&node).await?;
            Ok((serde_json::to_value(interfaces)?, 0))
        }
        Command::Storage { action } => execute_storage(&client, action).await,
    }
}

/// Feature #10 — read-only access browse.
async fn execute_access(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: AccessCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        AccessCommand::Acl { path } => {
            let mut acl = client.list_acl().await?;
            if let Some(p) = path {
                acl.retain(|e| e.path.contains(&p));
            }
            Ok((serde_json::to_value(acl)?, 0))
        }
        AccessCommand::Users => {
            let users = client.list_users().await?;
            Ok((serde_json::to_value(users)?, 0))
        }
        AccessCommand::Groups => {
            let groups = client.list_groups().await?;
            Ok((serde_json::to_value(groups)?, 0))
        }
        AccessCommand::Roles => {
            let roles = client.list_roles().await?;
            Ok((serde_json::to_value(roles)?, 0))
        }
        AccessCommand::Realms => {
            let realms = client.list_realms().await?;
            Ok((serde_json::to_value(realms)?, 0))
        }
        AccessCommand::Tfa { userid } => {
            let tfa = client.list_tfa(&userid).await?;
            Ok((serde_json::to_value(tfa)?, 0))
        }
        AccessCommand::UserCreate {
            userid,
            password,
            comment,
            email,
            firstname,
            lastname,
            groups,
            disabled,
            expire,
        } => {
            // `enable` semantic: PVE default is enabled. We pass
            // `enable=0` only when `--disabled` was set so the field
            // doesn't appear otherwise.
            let enable = if disabled { Some(false) } else { None };
            client
                .create_user(
                    &userid,
                    password.as_deref(),
                    comment.as_deref(),
                    email.as_deref(),
                    firstname.as_deref(),
                    lastname.as_deref(),
                    enable,
                    expire,
                    groups.as_deref(),
                )
                .await?;
            Ok((
                serde_json::json!({
                    "userid": userid,
                    "status": "created",
                    "groups": groups,
                    "enabled": !disabled,
                }),
                0,
            ))
        }
        AccessCommand::UserUpdate {
            userid,
            comment,
            email,
            firstname,
            lastname,
            groups,
            enable,
            disable,
            expire,
        } => {
            // `--enable` and `--disable` are clap-conflicting; if
            // neither is set, leave the field unchanged.
            let enable_param = if enable {
                Some(true)
            } else if disable {
                Some(false)
            } else {
                None
            };
            client
                .update_user(
                    &userid,
                    comment.as_deref(),
                    email.as_deref(),
                    firstname.as_deref(),
                    lastname.as_deref(),
                    enable_param,
                    expire,
                    groups.as_deref(),
                )
                .await?;
            Ok((
                serde_json::json!({
                    "userid": userid,
                    "status": "updated",
                }),
                0,
            ))
        }
        AccessCommand::UserDelete { userid, yes } => {
            if !yes {
                anyhow::bail!("`access user-delete` is destructive — re-run with --yes");
            }
            client.delete_user(&userid).await?;
            Ok((
                serde_json::json!({"userid": userid, "status": "deleted"}),
                0,
            ))
        }
        AccessCommand::GroupCreate { groupid, comment } => {
            client.create_group(&groupid, comment.as_deref()).await?;
            Ok((
                serde_json::json!({"groupid": groupid, "status": "created"}),
                0,
            ))
        }
        AccessCommand::GroupDelete { groupid, yes } => {
            if !yes {
                anyhow::bail!("`access group-delete` is destructive — re-run with --yes");
            }
            client.delete_group(&groupid).await?;
            Ok((
                serde_json::json!({"groupid": groupid, "status": "deleted"}),
                0,
            ))
        }
        AccessCommand::AclSet {
            path,
            role,
            user,
            group,
            token,
            no_propagate,
        } => {
            if user.is_none() && group.is_none() && token.is_none() {
                anyhow::bail!(
                    "`access acl-set` requires exactly one of --user, --group, or --token"
                );
            }
            client
                .modify_acl(
                    &path,
                    &role,
                    user.as_deref(),
                    group.as_deref(),
                    token.as_deref(),
                    !no_propagate,
                    false,
                )
                .await?;
            Ok((
                serde_json::json!({
                    "path": path,
                    "role": role,
                    "user": user,
                    "group": group,
                    "token": token,
                    "propagate": !no_propagate,
                    "status": "granted",
                }),
                0,
            ))
        }
        AccessCommand::AclUnset {
            path,
            role,
            user,
            group,
            token,
            yes,
        } => {
            if !yes {
                anyhow::bail!("`access acl-unset` is destructive — re-run with --yes");
            }
            if user.is_none() && group.is_none() && token.is_none() {
                anyhow::bail!(
                    "`access acl-unset` requires exactly one of --user, --group, or --token"
                );
            }
            client
                .modify_acl(
                    &path,
                    &role,
                    user.as_deref(),
                    group.as_deref(),
                    token.as_deref(),
                    true,
                    true,
                )
                .await?;
            Ok((
                serde_json::json!({
                    "path": path,
                    "role": role,
                    "user": user,
                    "group": group,
                    "token": token,
                    "status": "revoked",
                }),
                0,
            ))
        }
        AccessCommand::Permissions { userid, path } => {
            let perms = client
                .get_access_permissions(userid.as_deref(), path.as_deref())
                .await?;
            Ok((
                serde_json::json!({
                    "userid": userid, "path": path, "permissions": perms,
                }),
                0,
            ))
        }
        AccessCommand::Password { userid, password } => {
            client.change_user_password(&userid, &password).await?;
            Ok((serde_json::json!({"userid": userid, "changed": true}), 0))
        }
    }
}

/// Feature #10 — token CRUD.
async fn execute_token(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: TokenCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        TokenCommand::List { userid } => {
            let tokens = client.list_user_tokens(&userid).await?;
            Ok((serde_json::to_value(tokens)?, 0))
        }
        TokenCommand::Create {
            userid,
            tokenid,
            privsep,
            expire,
            comment,
        } => {
            let tok = client
                .create_token(&userid, &tokenid, privsep, expire, comment.as_deref())
                .await?;
            // The secret in `value` is shown ONCE. Highlight that fact
            // both in the JSON and in plain output via a banner.
            Ok((
                serde_json::json!({
                    "userid": userid,
                    "tokenid": tokenid,
                    "privsep": tok.privsep,
                    "expire": tok.expire,
                    "comment": tok.comment,
                    "value": tok.value,
                    "warning": "the token `value` is the secret and is shown ONCE — capture it now"
                }),
                0,
            ))
        }
        TokenCommand::Revoke {
            userid,
            tokenid,
            yes,
        } => {
            if !yes {
                anyhow::bail!("token revoke is destructive — re-run with --yes");
            }
            client.revoke_token(&userid, &tokenid).await?;
            Ok((
                serde_json::json!({
                    "userid": userid,
                    "tokenid": tokenid,
                    "status": "revoked"
                }),
                0,
            ))
        }
    }
}

/// Feature #10 — effective permissions via SSH shell-out (Option A).
async fn execute_perms(
    config: &crate::config::ProfileConfig,
    userid: &str,
    path_filter: Option<&str>,
    node: &str,
) -> Result<(Value, i32)> {
    use crate::ssh::{ExecOptions, SshPool};

    let ssh_cfg = config.ssh.clone().ok_or_else(|| {
        anyhow::anyhow!("[profiles.X.ssh] not configured — `proxxx perms` shells out via SSH")
    })?;
    let pool = SshPool::new(ssh_cfg, None)?;
    // Build the command. We pass userid through unchanged — pveum quotes
    // it server-side. We DO defend against shell-injection by refusing
    // any userid that contains shell metachars.
    // (Gemini audit) — defence in depth, three layers:
    //  1. Refuse-list of obvious shell metachars (early-out for the
    //     common attack patterns; produces a clearer error than a
    //     downstream pveum failure).
    //  2. `shell_quote`: wraps the value in single quotes and escapes
    //     internal `'` as `'\''`. Inside `'…'` bash does NOT interpret
    //     ANY metachar — backticks, $(), $VAR, `\` are all literal.
    //     The only escape is another `'`, which we handle. This is
    //     mathematically injection-proof at the shell layer.
    //  3. `--` separator before `{userid}`: even if pveum's argparser
    //     accepts flags after positionals, the `--` sentinel forces it
    //     to treat everything that follows as positional. This blocks
    //     argument-injection vectors like `--config-file=/etc/passwd`.
    if userid
        .chars()
        .any(|c| matches!(c, '`' | '$' | ';' | '&' | '|' | '\n' | '\r'))
    {
        anyhow::bail!("userid contains shell metacharacters — refusing");
    }
    let cmd = format!("pveum user permissions -- {}", shell_quote(userid));
    let res = pool.exec(node, &cmd, ExecOptions::default()).await?;
    if !res.ok() {
        anyhow::bail!(
            "pveum exited {:?}: {}",
            res.exit_code,
            res.stderr.trim().chars().take(500).collect::<String>()
        );
    }

    let mut perms = crate::access::parse_user_permissions(userid, &res.stdout);
    if let Some(p) = path_filter {
        perms.paths.retain(|x| x.path.contains(p));
    }
    // Render to JSON manually — `EffectivePermissions` isn't Serialize
    // (pure logic crate), so we shape it inline for the CLI.
    let json = serde_json::json!({
        "userid": perms.userid,
        "paths": perms.paths.iter().map(|pp| {
            serde_json::json!({
                "path": pp.path,
                "privileges": pp.privileges.iter().map(|(n, prop)| {
                    serde_json::json!({ "name": n, "propagate": prop })
                }).collect::<Vec<_>>()
            })
        }).collect::<Vec<_>>()
    });
    Ok((json, 0))
}

/// Feature #1c — SPICE handoff CLI. Issues spiceproxy ticket, writes
/// `.vv` `ConfigFile`, launches remote-viewer (or system default).
async fn execute_spice(
    client: &std::sync::Arc<crate::api::PxClient>,
    vmid: u32,
    node: &str,
    write_vv: Option<std::path::PathBuf>,
    no_launch: bool,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    let cfg = client.get_spiceproxy(node, vmid).await?;
    // audit: when the user passes `--write-vv <path>` we
    // honour it (they own the path). Without that flag we delegate to
    // the TOCTOU-safe `write_vv_file` which uses tempfile + O_EXCL +
    // 0600 atomically.
    let path = if let Some(p) = write_vv {
        crate::handoff::write_vv_at(&p, &cfg)?;
        p
    } else {
        crate::handoff::write_vv_file(vmid, &cfg)?
    };

    let mut launcher_used: Option<&'static str> = None;
    if !no_launch {
        match crate::handoff::open_spice_vv(&path) {
            Ok(name) => launcher_used = Some(name),
            Err(e) => {
                tracing::warn!("could not auto-launch SPICE viewer: {e:#}");
            }
        }
    }

    Ok((
        serde_json::json!({
            "vmid": vmid,
            "node": node,
            "vv_file": path.to_string_lossy(),
            "host": cfg.host(),
            "launcher": launcher_used,
            "launched": launcher_used.is_some(),
        }),
        0,
    ))
}

/// Feature #1c — noVNC handoff CLI. Builds the deep-link URL and opens
/// it via the system default handler. Authentication is left to the
/// browser's existing `PVEAuthCookie` session.
async fn execute_novnc(
    client: &std::sync::Arc<crate::api::PxClient>,
    config: &crate::config::ProfileConfig,
    vmid: u32,
    node: &str,
    kind_override: Option<SerialKind>,
    no_launch: bool,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    let guest_type = if let Some(k) = kind_override {
        k.into()
    } else {
        let guests = client.get_guests(node).await?;
        let g = guests
            .iter()
            .find(|g| g.vmid == vmid)
            .ok_or_else(|| anyhow::anyhow!("guest {vmid} not on node {node}"))?;
        g.guest_type
    };
    let url = crate::handoff::build_novnc_url(&config.url, node, vmid, guest_type);

    let mut launched = false;
    if !no_launch {
        if let Err(e) = crate::handoff::open_with_default(&url) {
            tracing::warn!("could not auto-launch browser: {e:#}");
        } else {
            launched = true;
        }
    }

    Ok((
        serde_json::json!({
            "vmid": vmid,
            "node": node,
            "type": format!("{guest_type:?}").to_lowercase(),
            "url": url,
            "launched": launched,
            "note": "user must be logged into the Proxmox web UI for the deep-link to work without re-auth"
        }),
        0,
    ))
}

/// Feature #1b — serial console CLI. Issues a termproxy ticket via REST,
/// connects WSS, puts the terminal in raw mode, copies bytes both ways
/// until Ctrl+] then `q`.
///
/// Honest limitations:
/// - Linux/macOS only (crossterm raw mode + signal handling assumes UNIX).
/// - No scrollback (raw passthrough — use `tmux` if you need it).
/// - Exit chord is hardcoded `Ctrl+] q` (telnet-style).
async fn execute_serial(
    client: &std::sync::Arc<crate::api::PxClient>,
    config: &crate::config::ProfileConfig,
    vmid: u32,
    node: &str,
    kind_override: Option<SerialKind>,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    // Auto-detect guest type from cluster state if not given.
    let guest_type = if let Some(k) = kind_override {
        k.into()
    } else {
        let guests = client.get_guests(node).await?;
        let g = guests
            .iter()
            .find(|g| g.vmid == vmid)
            .ok_or_else(|| anyhow::anyhow!("guest {vmid} not on node {node}"))?;
        g.guest_type
    };

    // Issue the termproxy ticket — short-lived, must connect immediately.
    let ticket = client.get_termproxy(node, vmid, guest_type).await?;
    let target = crate::wsterm::build_ws_target(
        &config.url,
        node,
        vmid,
        guest_type,
        ticket.port,
        &ticket.ticket,
        &ticket.user,
    );

    let mut ws = crate::wsterm::connect(&target, config.verify_tls).await?;

    // Put the local terminal in raw mode + alternate screen so the
    // remote shell controls every keystroke. The global panic hook
    // (flight recorder) already restores raw mode on crash; we also do an
    // explicit cleanup at function end.
    use anyhow::Context;
    use crossterm::{execute, terminal};
    use std::io::{stdout, Write};

    terminal::enable_raw_mode().context("enable raw mode")?;
    execute!(
        stdout(),
        terminal::EnterAlternateScreen,
        crossterm::cursor::Hide,
    )
    .context("enter alt screen")?;

    let _ = write!(
        stdout(),
        "\x1b[2J\x1b[H[serial console: vmid {vmid} on {node}]  Ctrl+] then 'q' to exit\r\n"
    );
    let _ = stdout().flush();

    // Initial size sync.
    if let Ok((cols, rows)) = terminal::size() {
        let _ = crate::wsterm::send_resize(&mut ws, cols, rows).await;
    }

    let exit_code = serial_loop(&mut ws).await;

    // Cleanup — best-effort. The panic hook is the safety net for the
    // unhappy path.
    let _ = execute!(
        stdout(),
        terminal::LeaveAlternateScreen,
        crossterm::cursor::Show,
    );
    let _ = terminal::disable_raw_mode();

    Ok((
        serde_json::json!({
            "vmid": vmid,
            "node": node,
            "type": format!("{guest_type:?}").to_lowercase(),
            "user": ticket.user,
            "exit_code": exit_code,
        }),
        exit_code,
    ))
}

/// `proxxx ssh <vmid>` — interactive SSH session into a guest VM/CT.
///
/// Why exec the system `ssh` rather than russh: the operator's
/// existing keys, known_hosts, ssh-agent, and SSH config (Host
/// stanzas, ProxyJump, ControlMaster) all apply transparently.
/// Re-implementing those features in russh would be incomplete and
/// invisible to muscle memory. The TUI's per-pane PTY uses russh
/// because it embeds the session in a TUI widget; here the operator
/// owns the terminal entirely and `ssh` is the right shape.
///
/// Resolution order:
///   1. `[ssh.guests."<vmid>"]` in config.toml — explicit override
///   2. Auto-discovery via QGA (QEMU) or `/lxc/N/interfaces` (LXC)
///      — uses [ssh].user / [ssh].key_path as defaults.
///   3. Friendly error with paste-able TOML if both fail.
async fn execute_ssh(
    client: &std::sync::Arc<crate::api::PxClient>,
    config: &crate::config::ProfileConfig,
    vmid: u32,
    cmd: Option<&str>,
) -> Result<(Value, i32)> {
    let ssh_cfg = config.ssh.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "no [ssh] block in config.toml — run `proxxx init --interactive`\n\
             and answer 'y' at the SSH layer step, OR add a minimal block:\n\
             \n\
             [ssh]\n\
             user = \"root\"\n\
             key_path = \"~/.ssh/id_ed25519\"\n\
             \n\
             then add a per-guest target as below."
        )
    })?;
    // 1. Explicit config wins. The operator may have set host:
    // "internal-name.lab" via DNS or pinned a non-default user/port —
    // auto-discovery must not override that.
    let (target, source) = if let Some(t) = ssh_cfg.resolve_guest(vmid) {
        (t, "config.toml")
    } else {
        // 2. Try auto-discovery. The error path collects WHY discovery
        // failed (no agent, link-local only, etc.) so the fallback
        // message is actionable rather than just "not found".
        match qga_resolve_guest(client, ssh_cfg, vmid).await {
            Ok(t) => (t, "QGA / lxc-interfaces auto-discovery"),
            Err(discovery_err) => {
                // 3. Both paths failed — surface paste-able TOML +
                // the discovery diagnostic so the operator knows
                // whether the agent is missing, the IP is link-local
                // only, or PVE rejected the lookup.
                anyhow::bail!(
                    "no [ssh.guests.\"{vmid}\"] entry in config.toml AND auto-\n\
                     discovery failed: {discovery_err}\n\
                     \n\
                     Add an explicit target:\n\
                     \n\
                     [ssh.guests.\"{vmid}\"]\n\
                     host = \"<guest-ip-or-hostname>\"   # e.g. 192.168.1.42\n\
                     # user = \"root\"                    # optional, falls back to [ssh].user\n\
                     # port = 22                          # optional, default 22\n\
                     # key_path = \"~/.ssh/...\"           # optional, falls back to [ssh].key_path\n\
                     \n\
                     You can confirm the guest's IP from PVE with:\n\
                     proxxx --format json ls guests | jq '.[] | select(.vmid == {vmid})'\n\
                     \n\
                     For QEMU guests with the agent installed but not running:\n\
                     proxxx qga {vmid} net   # exercises the same path"
                )
            }
        }
    };
    eprintln!(
        "\x1b[2m{}\x1b[0m",
        format!(
            "[ssh] resolved {}@{}:{} (source: {source})",
            target.user, target.host, target.port
        )
    );

    // Spawn the system `ssh`. Sharing stdin/stdout/stderr with the
    // parent gives a true terminal handoff — no extra PTY layer, no
    // double key forwarding. The child inherits TERM, LANG, etc.
    let mut cmd_builder = std::process::Command::new("ssh");
    cmd_builder
        .arg("-i")
        .arg(&target.key_path)
        .arg("-p")
        .arg(target.port.to_string())
        .arg(format!("{}@{}", target.user, target.host));
    if let Some(c) = cmd {
        cmd_builder.arg(c);
    }
    // stdio inherits by default for std::process::Command. Status
    // returns when the child exits — its exit code is what the
    // operator sees from `proxxx ssh ...`.
    let status = cmd_builder.status().map_err(|e| {
        anyhow::anyhow!(
            "spawning ssh failed: {e}\n\
             Verify `ssh` is on PATH (it usually is on macOS / Linux)."
        )
    })?;
    let exit_code = status.code().unwrap_or(1);

    Ok((
        serde_json::json!({
            "vmid": vmid,
            "host": target.host,
            "user": target.user,
            "port": target.port,
            "exit_code": exit_code,
        }),
        exit_code,
    ))
}

/// Resolve a guest's SSH target via auto-discovery — QGA for QEMU,
/// `/lxc/{vmid}/interfaces` for LXC. Used as a fallback by
/// `execute_ssh` when no explicit `[ssh.guests."<vmid>"]` block is
/// present in config.toml.
///
/// Selection: first IPv4 address that is NOT loopback (127.0.0.0/8)
/// AND NOT link-local (169.254.0.0/16). Picks IPv6 only if no IPv4
/// candidate exists — most operators want the v4 by default.
///
/// Diagnostic-rich error: tells the operator WHY discovery failed
/// (no node, agent off, only loopback) so the fallback message in
/// `execute_ssh` doesn't leave them guessing whether the agent
/// needs to be started or the IP just looks weird.
async fn qga_resolve_guest(
    client: &std::sync::Arc<crate::api::PxClient>,
    ssh_cfg: &crate::config::SshConfig,
    vmid: u32,
) -> Result<crate::config::ResolvedGuestSsh> {
    use crate::api::types::GuestType;
    use crate::api::ProxmoxGateway;

    let (node, gtype) = find_guest(client, vmid).await?;

    let host = match gtype {
        GuestType::Qemu => {
            let interfaces = client
                .qemu_agent_network_get_interfaces(&node, vmid)
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "QEMU guest-agent query failed (agent off or not installed?): {e:#}"
                    )
                })?;
            pick_first_routable_ipv4_qemu(&interfaces).ok_or_else(|| {
                anyhow::anyhow!(
                    "QGA returned no routable IPv4 for vmid {vmid} \
                     (only loopback / link-local / IPv6 found — guest may be on \
                     a private bridge with no usable address)"
                )
            })?
        }
        GuestType::Lxc => {
            let interfaces = client
                .list_lxc_interfaces(&node, vmid)
                .await
                .map_err(|e| anyhow::anyhow!("LXC interface query failed: {e:#}"))?;
            pick_first_routable_ipv4_lxc(&interfaces).ok_or_else(|| {
                anyhow::anyhow!(
                    "LXC vmid {vmid} has no routable IPv4 \
                     (interfaces query returned only empty / loopback / link-local entries)"
                )
            })?
        }
    };

    // Use [ssh] defaults — operator already accepted these in the
    // wizard / their config. This is the same fallback the explicit-
    // config path uses for missing per-guest user/key_path.
    let key_path = ssh_cfg.key_path_resolved().ok_or_else(|| {
        anyhow::anyhow!(
            "[ssh].key_path is not set in config.toml — auto-discovery found \
             host {host} for vmid {vmid} but cannot pick a private key"
        )
    })?;
    Ok(crate::config::ResolvedGuestSsh {
        host,
        port: 22,
        user: ssh_cfg.user.clone(),
        key_path,
    })
}

/// Pick the first routable IPv4 from a QGA interface list. Skips
/// loopback (127.0.0.0/8) and link-local (169.254.0.0/16); pure
/// function so we can pin invariants in unit tests without needing
/// a live cluster.
#[must_use]
pub fn pick_first_routable_ipv4_qemu(
    interfaces: &[crate::api::types::GuestAgentNetworkInterface],
) -> Option<String> {
    for iface in interfaces {
        for ip in &iface.ip_addresses {
            if ip.ip_address_type != "ipv4" {
                continue;
            }
            if is_routable_ipv4(&ip.ip_address) {
                return Some(ip.ip_address.clone());
            }
        }
    }
    None
}

/// Same as `pick_first_routable_ipv4_qemu` but for the LXC `inet`
/// shape (e.g. `"10.0.0.42/24"`) — strip the CIDR before predicate.
#[must_use]
pub fn pick_first_routable_ipv4_lxc(
    interfaces: &[crate::api::types::LxcInterface],
) -> Option<String> {
    for iface in interfaces {
        if iface.inet.is_empty() {
            continue;
        }
        let ip = iface
            .inet
            .split_once('/')
            .map_or(iface.inet.as_str(), |(addr, _cidr)| addr);
        if is_routable_ipv4(ip) {
            return Some(ip.to_string());
        }
    }
    None
}

/// True for IPv4 strings that aren't loopback or link-local. Pure;
/// rejects malformed input by returning false (caller filters with
/// the predicate, not asserts).
fn is_routable_ipv4(s: &str) -> bool {
    let octets: Vec<u8> = s.split('.').filter_map(|p| p.parse::<u8>().ok()).collect();
    if octets.len() != 4 {
        return false;
    }
    if octets[0] == 127 {
        return false; // loopback 127/8
    }
    if octets[0] == 169 && octets[1] == 254 {
        return false; // link-local 169.254/16
    }
    if octets[0] == 0 {
        return false; // 0.0.0.0/8 — never a destination
    }
    true
}

#[cfg(test)]
mod ssh_discovery_tests {
    use super::*;
    use crate::api::types::{GuestAgentIpAddress, GuestAgentNetworkInterface, LxcInterface};

    fn ipv4(addr: &str) -> GuestAgentIpAddress {
        GuestAgentIpAddress {
            ip_address_type: "ipv4".into(),
            ip_address: addr.into(),
            prefix: 24,
        }
    }
    fn ipv6(addr: &str) -> GuestAgentIpAddress {
        GuestAgentIpAddress {
            ip_address_type: "ipv6".into(),
            ip_address: addr.into(),
            prefix: 64,
        }
    }
    fn iface(name: &str, ips: Vec<GuestAgentIpAddress>) -> GuestAgentNetworkInterface {
        GuestAgentNetworkInterface {
            name: name.into(),
            hardware_address: "00:00:00:00:00:00".into(),
            ip_addresses: ips,
        }
    }

    #[test]
    fn qga_picks_first_routable_ipv4_skipping_loopback() {
        let ifaces = vec![
            iface("lo", vec![ipv4("127.0.0.1"), ipv6("::1")]),
            iface(
                "eth0",
                vec![ipv4("169.254.99.1"), ipv4("192.168.1.42"), ipv6("fe80::1")],
            ),
        ];
        assert_eq!(
            pick_first_routable_ipv4_qemu(&ifaces),
            Some("192.168.1.42".to_string())
        );
    }

    #[test]
    fn qga_returns_none_when_only_loopback_and_link_local() {
        // Pre-fix the wizard would have happily picked 127.0.0.1 and
        // tried to ssh into it — auto-discovery must reject and fall
        // back to the explicit-config error message.
        let ifaces = vec![iface("lo", vec![ipv4("127.0.0.1"), ipv4("169.254.99.1")])];
        assert!(pick_first_routable_ipv4_qemu(&ifaces).is_none());
    }

    #[test]
    fn qga_skips_ipv6_only_entries() {
        let ifaces = vec![iface("eth0", vec![ipv6("2001:db8::1")])];
        assert!(pick_first_routable_ipv4_qemu(&ifaces).is_none());
    }

    #[test]
    fn lxc_strips_cidr_and_picks_first_routable() {
        let ifaces = vec![
            LxcInterface {
                name: "lo".into(),
                hwaddr: String::new(),
                inet: "127.0.0.1/8".into(),
                inet6: "::1/128".into(),
            },
            LxcInterface {
                name: "eth0".into(),
                hwaddr: "00:01".into(),
                inet: "10.0.0.42/24".into(),
                inet6: String::new(),
            },
        ];
        assert_eq!(
            pick_first_routable_ipv4_lxc(&ifaces),
            Some("10.0.0.42".to_string())
        );
    }

    #[test]
    fn lxc_skips_empty_inet() {
        // PVE returns "" when the interface has no v4 — must be
        // skipped, not surfaced as a candidate, otherwise the SSH
        // command would be `ssh root@` and fail confusingly.
        let ifaces = vec![LxcInterface {
            name: "eth0".into(),
            hwaddr: "00:01".into(),
            inet: String::new(),
            inet6: "fe80::1/64".into(),
        }];
        assert!(pick_first_routable_ipv4_lxc(&ifaces).is_none());
    }

    #[test]
    fn is_routable_rejects_malformed_strings() {
        assert!(!is_routable_ipv4("not-an-ip"));
        assert!(!is_routable_ipv4("192.168.1"));
        assert!(!is_routable_ipv4(""));
        assert!(!is_routable_ipv4("999.999.999.999"));
        assert!(!is_routable_ipv4("0.0.0.0"));
        assert!(!is_routable_ipv4("127.0.0.1"));
        assert!(!is_routable_ipv4("169.254.0.1"));
        assert!(is_routable_ipv4("10.0.0.1"));
        assert!(is_routable_ipv4("192.168.1.42"));
        assert!(is_routable_ipv4("8.8.8.8"));
    }
}

/// Inner loop: keystrokes → WS, WS frames → stdout. Returns exit code.
async fn serial_loop<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>) -> i32
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use crossterm::event::{Event, EventStream, KeyCode, KeyModifiers};
    use futures_util::{SinkExt, StreamExt};
    use std::io::{stdout, Write};
    use tokio_tungstenite::tungstenite::protocol::Message;

    let mut events = EventStream::new();
    // State for the Ctrl+] q exit chord.
    let mut prefix_armed = false;

    loop {
        tokio::select! {
            // Local terminal events.
            evt = events.next() => {
                let Some(Ok(evt)) = evt else { break; };
                match evt {
                    Event::Key(key) => {
                        // Exit chord: Ctrl+] then 'q'.
                        if !prefix_armed
                            && key.modifiers.contains(KeyModifiers::CONTROL)
                            && matches!(key.code, KeyCode::Char(']'))
                        {
                            prefix_armed = true;
                            continue;
                        }
                        if prefix_armed {
                            prefix_armed = false;
                            if matches!(key.code, KeyCode::Char('q')) {
                                let _ = ws.send(Message::Close(None)).await;
                                return 0;
                            }
                            // Not the exit chord — forward Ctrl+] then this key.
                            let _ = crate::wsterm::send_input(ws, &[0x1D]).await;
                        }
                        // Encode + forward.
                        if let Some(bytes) = crate::ssh::pty::encode_key(&key) {
                            if crate::wsterm::send_input(ws, &bytes).await.is_err() {
                                return 1;
                            }
                        }
                    }
                    Event::Resize(cols, rows) => {
                        let _ = crate::wsterm::send_resize(ws, cols, rows).await;
                    }
                    _ => {}
                }
            }
            // Remote bytes.
            msg = ws.next() => {
                let Some(msg) = msg else { break; };
                match msg {
                    Ok(Message::Binary(payload)) => {
                        if let Some(bytes) = crate::wsterm::decode_data_frame(&payload) {
                            let _ = stdout().write_all(bytes);
                            let _ = stdout().flush();
                        }
                    }
                    Ok(Message::Text(t)) => {
                        let _ = stdout().write_all(t.as_bytes());
                        let _ = stdout().flush();
                    }
                    Ok(Message::Close(_)) => return 0,
                    Ok(_) => {}
                    Err(_) => return 1,
                }
            }
        }
    }
    0
}

/// Single-quote a string for safe inclusion in a shell command. Replaces
/// every `'` in the input with `'\''` (close, escape, open). Plain ASCII
/// userids skip the quoting cost.
/// Build the JSON payload for `proxxx version --json`. Single source of
/// truth for the README and any external probe (CI, container health
/// check, badge generator) — replaces hardcoded test counts and CLI
/// surface size that drift over time.
///
/// Counts that are knowable AT COMPILE TIME come from `clap` reflection
/// (subcommand variant count) and `Cargo.toml` (version, target via
/// `cfg!`). Audit ignores are loaded from `.cargo/audit.toml` at
/// build time via `include_str!` so the README link stays in sync
/// with the actual ignore policy.
/// Template content written by `proxxx init`. Mirrors the shape of
/// `ProfileConfig` (one profile per file in MVP). Required fields
/// are uncommented with placeholder values; optional sections (HITL
/// via Telegram, SSH layer, alerts, policies, PBS) are commented out
/// so an operator who only wants the API client doesn't have to
/// delete chunks. Inline comments document every secret-resolution
/// path so an operator who doesn't want plain-text secrets can pick
/// env / file / keychain at a glance.
const INIT_CONFIG_TEMPLATE: &str = r##"# proxxx — generated by `proxxx init`
#
# Edit the values below, then `proxxx ls nodes` to validate the
# connection. See `proxxx --help` for the full subcommand list and
# `proxxx version --json` for build + capability metadata.
#
# Secret resolution order (the same for every `*_secret` field):
#   1. CLI flag (`--token-secret`, `--pbs-token-secret`)
#   2. Env var (`PROXXX_TOKEN_SECRET`, `PROXXX_PBS_TOKEN_SECRET`)
#   3. `*_secret_file` path (must be 0600 on Unix or proxxx refuses)
#   4. OS keychain ("proxxx" / "token_secret" or "pbs_token_secret")
# Plain-text inline secrets are accepted but discouraged.

# ── Required: Proxmox VE REST connection ─────────────────────
url = "https://pve1.lan:8006"
user = "root@pam"
auth = "token"                   # "token" | "password"
verify_tls = true                # SET TO false ONLY for homelab clusters with self-
                                 # signed certs. Disabling TLS verification exposes the
                                 # full API + WebSocket traffic (incl. serial-console
                                 # tickets) to MITM. The flag is per-profile and also
                                 # propagates to the WebSocket termproxy client.
rate_limit = 10                  # API calls per second (default 10)

# Token auth (recommended over password for headless tools).
# Build it with: pveum user token add root@pam proxxx --privsep=1
token_id = "proxxx"
# token_secret = "00000000-0000-0000-0000-000000000000"
# token_secret_file = "/etc/proxxx/pve.secret"   # 0600 perms required

# Or password auth — proxxx logs in via /access/ticket and refreshes
# the cookie automatically. Useful for ad-hoc sessions, not pipelines.
# auth = "password"
# password = "..."

# ── Optional: HITL approval gate via Telegram ────────────────
# When `--secure` is set OR a [[policies]] entry matches a destructive
# action, proxxx sends an approval request to Telegram and blocks the
# operation until Approve/Deny is clicked. Deny-on-timeout (120 s).
# [telegram]
# bot_token = "0000000000:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
# chat_id = "-1001234567890"

# Per-action policies. `action` matches the dispatch identifier used
# internally (start, stop, restart, delete, migrate, exec, move_disk,
# resize_disk, …). `target` is "*" or "tag:<name>" or a vmid as string.
# [[policies]]
# action = "delete"
# target = "tag:prod"
# channel = "telegram"
# require = 1                    # Number of approvals needed

# ── Optional: SSH layer (SSH layer) ───────────────────────────
# Enables features that can't go through the Proxmox REST API:
#   - patch apply (apt-get on the node)
#   - `proxxx perms <user>` (pveum shell-out)
#   - per-guest SSH session (`proxxx ssh <vmid>`)
# [ssh]
# user = "root"
# key_path = "~/.ssh/id_ed25519"
# # known_hosts_path = "~/.ssh/known_hosts"  # default

# ── Optional: PBS (Proxmox Backup Server) connection ─────────
# Read-only browse via REST; restore shells out to proxmox-backup-client
# (Linux required for the restore subprocess).
# [pbs]
# url = "https://pbs.lan:8007"
# user = "root@pam"
# token_id = "proxxx"
# # token_secret = "..."
# fingerprint = "AB:CD:EF:..."   # PBS TLS fingerprint
# verify_tls = false

# ── Optional: alerts engine (rule-based notifier) ────────────
# Distinct from PVE 8+ native notifications — this is the proxxx-side
# rule engine for `proxxx alerts watch`. Channels: telegram, ntfy, webhook.
# [[alerts]]
# rule_id = "node-down"
# predicate = "node_offline"
# severity = "critical"
# route = "telegram:default"
"##;

/// `proxxx init` — write a starter config.toml to the OS-default
/// proxxx config directory. First-mile UX: the config-not-found
/// error message points here, so this command MUST work on a fresh
/// machine without an existing config.
fn execute_init(force: bool) -> Result<(serde_json::Value, i32)> {
    use anyhow::Context as _;
    use std::io::Write as _;

    let config_dir = directories::ProjectDirs::from("dev", "proxxx", "proxxx")
        .map(|d| d.config_dir().to_path_buf())
        .ok_or_else(|| anyhow::anyhow!("could not resolve OS config directory for proxxx"))?;

    let config_path = config_dir.join("config.toml");

    if config_path.exists() && !force {
        anyhow::bail!(
            "Config already exists at {}. Re-run with --force to overwrite.",
            config_path.display()
        );
    }

    std::fs::create_dir_all(&config_dir).with_context(|| {
        format!(
            "creating config directory {} (check filesystem perms)",
            config_dir.display()
        )
    })?;

    // Write atomically via a temp file in the same dir + rename — so a
    // partial write can't leave a half-template config.toml that the
    // next `load_config` call would parse-error on.
    let tmp_path = config_dir.join("config.toml.proxxx-init-tmp");
    {
        let mut f = std::fs::File::create(&tmp_path).with_context(|| {
            format!(
                "creating temp config at {} (check perms)",
                tmp_path.display()
            )
        })?;
        f.write_all(INIT_CONFIG_TEMPLATE.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp_path, &config_path).with_context(|| {
        format!(
            "renaming temp config into place at {}",
            config_path.display()
        )
    })?;

    Ok((
        serde_json::json!({
            "wrote": config_path.display().to_string(),
            "force": force,
            "next_step": "edit `url`, `user`, `token_id`, `token_secret`, then run `proxxx ls nodes`",
        }),
        0,
    ))
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

fn shell_quote(s: &str) -> String {
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '!' | '_' | '-' | '.'))
    {
        return s.to_string();
    }
    let escaped = s.replace('\'', "'\\''");
    format!("'{escaped}'")
}

#[cfg(test)]
mod parse_kv_pairs_tests {
    use super::parse_kv_pairs;

    #[test]
    fn simple_pairs() {
        let kvs = vec!["cores=4".to_string(), "memory=8192".to_string()];
        let out = parse_kv_pairs(&kvs).expect("parse");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], ("cores".to_string(), "4".to_string()));
        assert_eq!(out[1], ("memory".to_string(), "8192".to_string()));
    }

    #[test]
    fn value_containing_equals_signs_survives() {
        // PVE property strings often contain `=` inside values, e.g.
        //   net0=virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0
        // Splitting on the FIRST `=` only is the whole point of this
        // helper — pin the behaviour against future "clever" rewrites.
        let kvs = vec!["net0=virtio=AA:BB,bridge=vmbr0,firewall=1".to_string()];
        let out = parse_kv_pairs(&kvs).expect("parse");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, "net0");
        assert_eq!(out[0].1, "virtio=AA:BB,bridge=vmbr0,firewall=1");
    }

    #[test]
    fn empty_value_is_allowed() {
        // PVE accepts `delete` semantics via empty values on some keys.
        let kvs = vec!["description=".to_string()];
        let out = parse_kv_pairs(&kvs).expect("parse");
        assert_eq!(out[0], ("description".to_string(), String::new()));
    }

    #[test]
    fn missing_equals_separator_errors() {
        let kvs = vec!["cores4".to_string()];
        let err = parse_kv_pairs(&kvs).expect_err("must reject");
        assert!(err.to_string().contains("missing '=' separator"));
    }

    #[test]
    fn empty_key_errors() {
        let kvs = vec!["=4".to_string()];
        let err = parse_kv_pairs(&kvs).expect_err("must reject");
        assert!(err.to_string().contains("empty key"));
    }
}

#[cfg(test)]
mod shell_quote_tests {
    use super::shell_quote;

    /// (Gemini audit) — single-quote wrapping is mathematically
    /// injection-proof. Inside single quotes, bash interprets nothing
    /// except another single quote (which we escape via the
    /// close-escape-reopen idiom `'\''`).
    #[test]
    fn ascii_userid_passes_through_unquoted() {
        // Bare-ASCII userids are safe to pass through; the test pins
        // the optimisation so a refactor doesn't regress it.
        assert_eq!(shell_quote("root@pam"), "root@pam");
        assert_eq!(shell_quote("svc-readonly"), "svc-readonly");
    }

    #[test]
    fn embedded_single_quote_is_escaped() {
        // The textbook tricky input: a value containing a single quote.
        // Output must produce a literal `'` after shell parsing.
        assert_eq!(shell_quote("o'reilly"), "'o'\\''reilly'");
    }

    #[test]
    fn metachars_become_literal_inside_single_quotes() {
        // Inside `'…'` bash does NOT interpret $, `, \, ;, |, &, (, )
        // — they all become literal.
        assert_eq!(shell_quote("$(rm -rf /)"), "'$(rm -rf /)'");
        assert_eq!(shell_quote("`whoami`"), "'`whoami`'");
        assert_eq!(shell_quote("a;b|c&d"), "'a;b|c&d'");
        assert_eq!(shell_quote("a\\b\"c"), "'a\\b\"c'");
    }

    #[test]
    fn injection_attempt_from_audit_becomes_inert_literal() {
        // Gemini's exact attack string, re-shell-parsed:
        //   input: test'; touch /tmp/pwned; '
        //   shell_quote → 'test'\''; touch /tmp/pwned; '\'''
        // Bash parses that as a single concatenated literal:
        //   'test' + \' + '; touch /tmp/pwned; ' + \' + ''
        // = test'; touch /tmp/pwned; '
        // pveum then sees a single argument with the metachars inert.
        let q = shell_quote("test'; touch /tmp/pwned; '");
        // Closure invariants: starts with a single quote, ends with one,
        // and every embedded `'` is closed before being escaped.
        assert!(q.starts_with('\''));
        assert!(q.ends_with('\''));
        // The escaped form `'\''` must appear for each input `'`.
        assert_eq!(q.matches("'\\''").count(), 2);
        // No raw shell-active sequence outside of quotes survives.
        assert!(!q.contains(";'") || q.contains("'\\''"));
    }
}

/// Feature #8 — alerts CLI dispatch.
async fn execute_alerts(
    client: &std::sync::Arc<crate::api::PxClient>,
    config: &crate::config::ProfileConfig,
    profile: Option<&str>,
    action: AlertsCommand,
) -> Result<(Value, i32)> {
    use crate::alerts::engine::{evaluate, ClusterSnapshot, EngineState};
    use crate::alerts::{parse_route, send_event, AlertEvent, DedupCache, Severity};
    use crate::api::ProxmoxGateway;

    // Build a cluster snapshot once (used by Eval and Watch).
    async fn snapshot(client: &crate::api::PxClient) -> Result<ClusterSnapshot> {
        let nodes = client.get_nodes().await.unwrap_or_default();
        let mut storage = Vec::new();
        let mut replication = Vec::new();
        for n in &nodes {
            if n.status == crate::api::types::NodeStatus::Online {
                if let Ok(s) = client.get_storage_pools(&n.node).await {
                    storage.extend(s);
                }
                if let Ok(r) = client.list_replication_status(&n.node).await {
                    replication.extend(r);
                }
            }
        }
        Ok(ClusterSnapshot {
            nodes,
            storage,
            replication,
        })
    }

    match action {
        AlertsCommand::Eval => {
            let rules = config.alerts.clone().unwrap_or_default();
            if rules.is_empty() {
                return Ok((
                    serde_json::json!({"events": [], "warning": "no [[alerts]] rules configured"}),
                    0,
                ));
            }
            let snap = snapshot(client).await?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let (events, _state) = evaluate(&rules, &snap, EngineState::default(), now);
            Ok((
                serde_json::json!({
                    "evaluated_rules": rules.len(),
                    "events": events,
                }),
                0,
            ))
        }
        AlertsCommand::Watch { interval } => {
            let rules = config.alerts.clone().unwrap_or_default();
            if rules.is_empty() {
                anyhow::bail!("no [[alerts]] rules configured — nothing to watch");
            }
            let http = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?;
            let tg = match config.telegram.as_ref() {
                None => None,
                Some(cfg) => Some(crate::hitl::telegram::TelegramGateway::from_config(cfg).await?),
            };

            // Pre-parse routes once — invalid specs are reported then.
            let parsed_routes: Vec<(crate::config::AlertRuleConfig, Vec<crate::alerts::Channel>)> =
                rules
                    .iter()
                    .map(|r| {
                        let chans: Vec<crate::alerts::Channel> = r
                            .route
                            .iter()
                            .filter_map(|s| {
                                let p = parse_route(s);
                                if p.is_none() {
                                    tracing::warn!("rule {}: ignoring unknown route {s:?}", r.name);
                                }
                                p
                            })
                            .collect();
                        (r.clone(), chans)
                    })
                    .collect();

            let mut state = EngineState::default();
            // Cache schema v2 — persist the dedup window across daemon
            // restarts so a routine restart (config reload, kernel
            // update, accidental SIGHUP) does NOT re-fire every active
            // alert. Best-effort: a missing/corrupt cache yields an
            // empty DedupCache rather than failing the daemon.
            let mut dedup = match crate::app::cache::load_alert_dedup(profile) {
                Ok(rows) => {
                    if !rows.is_empty() {
                        tracing::info!(
                            "alert daemon: restored {} dedup entries from cache",
                            rows.len()
                        );
                    }
                    DedupCache::from_entries(rows)
                }
                Err(e) => {
                    tracing::warn!("alert daemon: dedup cache load failed: {e:#} — starting empty");
                    DedupCache::default()
                }
            };
            tracing::info!(
                "alert daemon starting: {} rules, interval {}s",
                rules.len(),
                interval
            );
            // (macro audit) — graceful shutdown on
            // SIGTERM/SIGINT. The select! races the daemon's tick
            // against the signal handler; whichever fires first wins.
            // On SIGTERM systemd waits up to 90 s before SIGKILL —
            // we comfortably exit within milliseconds.
            loop {
                tokio::select! {
                    biased; // signals are higher priority than the next tick
                    () = crate::util::shutdown::wait_for_shutdown_signal() => {
                        tracing::info!("alert daemon: shutdown signal received, exiting cleanly");
                        // Final flush so the dedup window survives the
                        // shutdown — operator restarts the daemon, the
                        // cache is current. Best-effort by design.
                        if let Err(e) =
                            crate::app::cache::save_alert_dedup(profile, &dedup.entries())
                        {
                            tracing::warn!(
                                "alert daemon: dedup cache flush at shutdown failed: {e:#}"
                            );
                        }
                        return Ok((
                            serde_json::json!({ "status": "shutdown" }),
                            0,
                        ));
                    }
                    snap_res = snapshot(client) => {
                        let snap = match snap_res {
                            Ok(s) => s,
                            Err(e) => {
                                tracing::warn!(
                                    "snapshot fetch failed: {e:#} — retrying next tick"
                                );
                                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                                continue;
                            }
                        };
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        let (events, new_state) = evaluate(&rules, &snap, state, now);
                        state = new_state;

                        for ev in &events {
                            let Some((rule, channels)) =
                                parsed_routes.iter().find(|(r, _)| r.name == ev.rule)
                            else {
                                continue;
                            };
                            if !dedup.allow(&ev.rule, &ev.target, rule.dedup_secs, now) {
                                continue;
                            }
                            for ch in channels {
                                if let Err(e) = send_event(ch, ev, &http, tg.as_ref()).await {
                                    tracing::warn!("alert {} → {ch:?} failed: {e:#}", ev.rule);
                                }
                            }
                        }

                        dedup.evict_older_than(86_400, now);
                        // Persist after each tick so a crash within
                        // `sleep` window costs at most one tick of
                        // dedup state. Best-effort — a transient I/O
                        // error must not kill the daemon.
                        if let Err(e) =
                            crate::app::cache::save_alert_dedup(profile, &dedup.entries())
                        {
                            tracing::warn!("alert daemon: dedup cache save failed: {e:#}");
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                    }
                }
            }
        }
        AlertsCommand::Test { route, severity } => {
            let ch = parse_route(&route)
                .ok_or_else(|| anyhow::anyhow!("invalid route spec: {route}"))?;
            let http = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()?;
            let tg = match config.telegram.as_ref() {
                None => None,
                Some(cfg) => Some(crate::hitl::telegram::TelegramGateway::from_config(cfg).await?),
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let event = AlertEvent {
                rule: "_test".into(),
                severity: Severity::parse(&severity),
                target: "_test".into(),
                summary: "synthetic test event from `proxxx alerts test`".into(),
                detail: serde_json::json!({"source": "proxxx alerts test"}),
                at: now,
            };
            send_event(&ch, &event, &http, tg.as_ref()).await?;
            Ok((
                serde_json::json!({
                    "route": route,
                    "channel": format!("{ch:?}"),
                    "status": "sent"
                }),
                0,
            ))
        }
    }
}

/// Feature #4 — hardware inventory CLI.
/// Hill 3b — time-series metrics CLI. Default emits a Unicode block
/// sparkline + min/max/avg over the chosen field; `--format json`
/// short-circuits and returns the raw rrddata. Auto-discovers the
/// owning node when the user omits `--node` for vm/ct.
async fn execute_metrics(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: MetricsCommand,
) -> Result<(Value, i32)> {
    use crate::api::types::{GuestType, RrdPoint};
    use crate::api::ProxmoxGateway;

    // RrdPng returns a server-side filename — different shape from the
    // numeric sparkline pipeline below, so handle it as an early return.
    if let MetricsCommand::RrdPng {
        vmid,
        ds,
        timeframe,
        cf,
    } = &action
    {
        let (node_name, gt) = find_guest(client, *vmid).await?;
        let img = client
            .get_guest_rrd_image(&node_name, *vmid, gt, ds, (*timeframe).into(), (*cf).into())
            .await?;
        return Ok((
            serde_json::json!({
                "vmid": vmid,
                "node": node_name,
                "ds": ds,
                "filename": img.filename,
            }),
            0,
        ));
    }

    // Helper: extract one optional metric from each point. Used for
    // both the sparkline render path AND the summary stats.
    fn extract(p: &RrdPoint, field: MetricField) -> Option<f64> {
        match field {
            MetricField::Cpu => p.cpu,
            // For node, `mem` is often absent; PVE returns memused
            // instead. Fall back so a `--field mem` request on a node
            // doesn't render an all-gap sparkline.
            MetricField::Mem => p.mem.or(p.memused),
            MetricField::Diskread => p.diskread,
            MetricField::Diskwrite => p.diskwrite,
            MetricField::Netin => p.netin,
            MetricField::Netout => p.netout,
            MetricField::Loadavg => p.loadavg,
            MetricField::Iowait => p.iowait,
            // Storage: `used`. Guest: `disk`. Try both.
            MetricField::Used => p.used.or(p.disk),
            MetricField::Total => p.total.or(p.maxdisk),
        }
    }

    // Auto-find owning node when caller omits --node for guests.
    async fn find_node_for_vmid(
        client: &std::sync::Arc<crate::api::PxClient>,
        vmid: u32,
    ) -> Result<(String, GuestType)> {
        let nodes = client.get_nodes().await?;
        for n in nodes {
            if let Ok(guests) = client.get_guests(&n.node).await {
                if let Some(g) = guests.iter().find(|g| g.vmid == vmid) {
                    return Ok((n.node.clone(), g.guest_type));
                }
            }
        }
        anyhow::bail!("vmid {vmid} not found on any node — pass --node X to skip discovery")
    }

    let (label, points, field) = match action {
        MetricsCommand::Vm {
            vmid,
            node,
            field,
            timeframe,
            cf,
        } => {
            let (node_name, _) = match node {
                Some(n) => (n, GuestType::Qemu),
                None => find_node_for_vmid(client, vmid).await?,
            };
            let pts = client
                .get_guest_rrddata(
                    &node_name,
                    vmid,
                    GuestType::Qemu,
                    timeframe.into(),
                    cf.into(),
                )
                .await?;
            (format!("VM {vmid} on {node_name}"), pts, field)
        }
        MetricsCommand::Ct {
            vmid,
            node,
            field,
            timeframe,
            cf,
        } => {
            let (node_name, _) = match node {
                Some(n) => (n, GuestType::Lxc),
                None => find_node_for_vmid(client, vmid).await?,
            };
            let pts = client
                .get_guest_rrddata(
                    &node_name,
                    vmid,
                    GuestType::Lxc,
                    timeframe.into(),
                    cf.into(),
                )
                .await?;
            (format!("LXC {vmid} on {node_name}"), pts, field)
        }
        MetricsCommand::Node {
            node,
            field,
            timeframe,
            cf,
        } => {
            let pts = client
                .get_node_rrddata(&node, timeframe.into(), cf.into())
                .await?;
            (format!("node {node}"), pts, field)
        }
        MetricsCommand::Storage {
            node,
            storage,
            field,
            timeframe,
            cf,
        } => {
            let pts = client
                .get_storage_rrddata(&node, &storage, timeframe.into(), cf.into())
                .await?;
            (format!("storage {storage} on {node}"), pts, field)
        }
        // Unreachable — short-circuited above.
        MetricsCommand::RrdPng { .. } => unreachable!("RrdPng handled by early return"),
    };

    // Pull the requested field from every point as Option<f64>.
    let series: Vec<Option<f64>> = points.iter().map(|p| extract(p, field)).collect();
    let summary = crate::util::sparkline::Summary::of(&series);
    let spark = crate::util::sparkline::render(&series);

    // The CLI table/plain renderer can't show a sparkline meaningfully;
    // emit a JSON envelope with the rendered sparkline + summary, and
    // additionally a `points` array carrying (time, value) pairs so
    // downstream tooling (jq / a charting script) can rebuild the
    // series without parsing the sparkline back.
    let pairs: Vec<Value> = points
        .iter()
        .zip(series.iter())
        .map(|(p, v)| serde_json::json!({"time": p.time, "value": v}))
        .collect();
    let summary_json = summary.map_or(Value::Null, |s| {
        serde_json::json!({
            "count": s.count,
            "min": s.min,
            "max": s.max,
            "avg": s.avg,
        })
    });
    Ok((
        serde_json::json!({
            "label": label,
            "field": format!("{field:?}").to_lowercase(),
            "sparkline": spark,
            "summary": summary_json,
            "points": pairs,
        }),
        0,
    ))
}

/// Cluster-wide metric exporter dispatch. PVE routes mutations
/// per-id (POST/PUT/DELETE on `/cluster/metrics/server/{id}`).
#[allow(clippy::too_many_lines)]
async fn execute_metric_servers(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: MetricServersCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    fn build_params<'a>(
        typed: Vec<(&'a str, String)>,
        raw: &'a [String],
    ) -> Result<Vec<(&'a str, String)>> {
        let mut out = typed;
        for spec in raw {
            let (k, v) = spec
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--raw expects KEY=VAL, got {spec:?}"))?;
            out.retain(|(ek, _)| *ek != k);
            let key_static: &'static str = Box::leak(k.to_string().into_boxed_str());
            out.push((key_static, v.to_string()));
        }
        Ok(out)
    }
    fn as_refs<'a>(v: &'a [(&'a str, String)]) -> Vec<(&'a str, &'a str)> {
        v.iter().map(|(k, s)| (*k, s.as_str())).collect()
    }

    match action {
        MetricServersCommand::List => {
            let servers = client.list_metric_servers().await?;
            Ok((serde_json::to_value(servers)?, 0))
        }
        MetricServersCommand::Show { id } => {
            let s = client.get_metric_server(&id).await?;
            Ok((serde_json::to_value(s)?, 0))
        }
        MetricServersCommand::Create {
            id,
            server_type,
            server,
            port,
            comment,
            influxdbproto,
            proto,
            organization,
            bucket,
            path,
            token,
            raw,
        } => {
            let mut typed: Vec<(&str, String)> = vec![
                ("type", server_type),
                ("server", server),
                ("port", port.to_string()),
            ];
            let push_opt =
                |t: &mut Vec<(&'static str, String)>, k: &'static str, v: Option<String>| {
                    if let Some(s) = v {
                        t.push((k, s));
                    }
                };
            push_opt(&mut typed, "comment", comment);
            push_opt(&mut typed, "influxdbproto", influxdbproto);
            push_opt(&mut typed, "proto", proto);
            push_opt(&mut typed, "organization", organization);
            push_opt(&mut typed, "bucket", bucket);
            push_opt(&mut typed, "path", path);
            push_opt(&mut typed, "token", token);
            let owned = build_params(typed, &raw)?;
            client.create_metric_server(&id, &as_refs(&owned)).await?;
            Ok((serde_json::json!({"created": id}), 0))
        }
        MetricServersCommand::Update {
            id,
            server,
            port,
            disable,
            comment,
            raw,
        } => {
            let mut typed: Vec<(&str, String)> = vec![];
            if let Some(s) = server {
                typed.push(("server", s));
            }
            if let Some(p) = port {
                typed.push(("port", p.to_string()));
            }
            if let Some(d) = disable {
                typed.push(("disable", if d { "1" } else { "0" }.to_string()));
            }
            if let Some(c) = comment {
                typed.push(("comment", c));
            }
            if typed.is_empty() && raw.is_empty() {
                anyhow::bail!("update needs at least one field");
            }
            let owned = build_params(typed, &raw)?;
            client.update_metric_server(&id, &as_refs(&owned)).await?;
            Ok((serde_json::json!({"updated": id}), 0))
        }
        MetricServersCommand::Delete { id, yes } => {
            if !yes {
                anyhow::bail!("destructive — pass --yes to confirm");
            }
            client.delete_metric_server(&id).await?;
            Ok((serde_json::json!({"deleted": id}), 0))
        }
    }
}

/// Hill B — bulk node power. Each subcommand is a single POST to PVE;
/// returns the batch UPID for `proxxx tasks` follow-up.
async fn execute_node(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: NodeCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        NodeCommand::Startall { node } => {
            let upid = client.startall_node(&node).await?;
            Ok((
                serde_json::json!({"action": "startall", "status": "submitted", "upid": upid}),
                0,
            ))
        }
        NodeCommand::Stopall { node } => {
            let upid = client.stopall_node(&node).await?;
            Ok((
                serde_json::json!({"action": "stopall", "status": "submitted", "upid": upid}),
                0,
            ))
        }
        NodeCommand::Suspendall { node } => {
            let upid = client.suspendall_node(&node).await?;
            Ok((
                serde_json::json!({"action": "suspendall", "status": "submitted", "upid": upid}),
                0,
            ))
        }
        NodeCommand::Shell { node, kind } => match kind {
            NodeShellKind::Term => {
                let t = client.get_node_termproxy(&node).await?;
                Ok((serde_json::to_value(t)?, 0))
            }
            NodeShellKind::Vnc => {
                let t = client.get_node_vncshell(&node).await?;
                Ok((serde_json::to_value(t)?, 0))
            }
            NodeShellKind::Spice => {
                let t = client.get_node_spiceshell(&node).await?;
                Ok((serde_json::to_value(t)?, 0))
            }
        },
    }
}

/// Backup-jobs CRUD CLI. proxxx already has `proxxx backup` for
/// one-shot vzdump; this surface manages the RECURRING jobs PVE
/// stores cluster-wide at `/cluster/backup`.
async fn execute_backup_jobs(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: BackupJobsCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    // Helper: fold typed flags + raw `KEY=VAL` overrides into the
    // flat (str, str) param list PVE expects. Raw entries win on
    // conflict — explicit operator override of a typed default.
    fn build_params<'a>(
        typed: Vec<(&'a str, String)>,
        raw: &'a [String],
    ) -> Result<Vec<(&'a str, String)>> {
        let mut out = typed;
        for spec in raw {
            let (k, v) = spec
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--raw expects KEY=VAL, got {spec:?}"))?;
            // Drop any typed entry under the same key.
            out.retain(|(ek, _)| *ek != k);
            // Lifetime hack: leak the key so it's 'static — fine for
            // CLI lifetime, this fn returns immediately into a one-
            // shot dispatch. Avoids threading another lifetime through
            // the entire CRUD signature.
            let key_static: &'static str = Box::leak(k.to_string().into_boxed_str());
            out.push((key_static, v.to_string()));
        }
        Ok(out)
    }

    match action {
        BackupJobsCommand::List => {
            let jobs = client.list_backup_jobs().await?;
            Ok((serde_json::to_value(jobs)?, 0))
        }
        BackupJobsCommand::Show { id } => {
            let job = client.get_backup_job(&id).await?;
            Ok((serde_json::to_value(job)?, 0))
        }
        BackupJobsCommand::Create {
            schedule,
            storage,
            all,
            vmid,
            mode,
            compress,
            mailto,
            mailnotification,
            prune_backups,
            comment,
            node,
            raw,
        } => {
            if all && vmid.is_some() {
                anyhow::bail!("--all and --vmid are mutually exclusive");
            }
            if !all && vmid.is_none() {
                anyhow::bail!("either --all or --vmid is required");
            }
            let mut typed: Vec<(&str, String)> =
                vec![("schedule", schedule), ("storage", storage), ("mode", mode)];
            if all {
                typed.push(("all", "1".to_string()));
            }
            if let Some(v) = vmid {
                typed.push(("vmid", v));
            }
            if let Some(c) = compress {
                typed.push(("compress", c));
            }
            if let Some(m) = mailto {
                typed.push(("mailto", m));
            }
            if let Some(mn) = mailnotification {
                typed.push(("mailnotification", mn));
            }
            if let Some(pb) = prune_backups {
                typed.push(("prune-backups", pb));
            }
            if let Some(c) = comment {
                typed.push(("comment", c));
            }
            if let Some(n) = node {
                typed.push(("node", n));
            }
            let merged = build_params(typed, &raw)?;
            let pairs: Vec<(&str, &str)> = merged.iter().map(|(k, v)| (*k, v.as_str())).collect();
            client.create_backup_job(&pairs).await?;
            Ok((serde_json::json!({"status": "created"}), 0))
        }
        BackupJobsCommand::Update {
            id,
            schedule,
            enabled,
            compress,
            prune_backups,
            comment,
            raw,
        } => {
            let mut typed: Vec<(&str, String)> = Vec::new();
            if let Some(s) = schedule {
                typed.push(("schedule", s));
            }
            if let Some(e) = enabled {
                typed.push(("enabled", if e { "1".into() } else { "0".into() }));
            }
            if let Some(c) = compress {
                typed.push(("compress", c));
            }
            if let Some(pb) = prune_backups {
                typed.push(("prune-backups", pb));
            }
            if let Some(c) = comment {
                typed.push(("comment", c));
            }
            let merged = build_params(typed, &raw)?;
            if merged.is_empty() {
                anyhow::bail!(
                    "update needs at least one --field or --raw KEY=VAL — \
                     no-op refused (would silently succeed)"
                );
            }
            let pairs: Vec<(&str, &str)> = merged.iter().map(|(k, v)| (*k, v.as_str())).collect();
            client.update_backup_job(&id, &pairs).await?;
            Ok((serde_json::json!({"status": "updated", "id": id}), 0))
        }
        BackupJobsCommand::Delete { id, yes } => {
            if !yes {
                anyhow::bail!(
                    "`backup-jobs delete {id}` is destructive — re-run with --yes to confirm"
                );
            }
            client.delete_backup_job(&id).await?;
            Ok((serde_json::json!({"status": "deleted", "id": id}), 0))
        }
        BackupJobsCommand::Info => {
            // Will return ApiError::Forbidden under token auth — let
            // the typed error bubble up through the standard CLI exit
            // mapping (Phase 7's write-path completion).
            let info = client.cluster_backup_info().await?;
            Ok((info, 0))
        }
        BackupJobsCommand::ExtractConfig { node, volume } => {
            let cfg = client.extract_backup_config(&node, &volume).await?;
            Ok((
                serde_json::json!({"node": node, "volume": volume, "config": cfg}),
                0,
            ))
        }
    }
}

/// Cluster firewall CRUD dispatch. Reuses the same `build_params`
/// pattern as backup-jobs: typed flags merged with `--raw KEY=VAL`
/// overrides, with `Box::leak` providing the static lifetime needed
/// for the `&[(&str, &str)]` shape PxClient takes. Acceptable here
/// because the process exits immediately after dispatching one CLI
/// invocation — the leak is bounded.
#[allow(clippy::too_many_lines)]
async fn execute_firewall_cluster(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: FirewallClusterCommand,
) -> Result<(serde_json::Value, i32)> {
    use crate::api::ProxmoxGateway;
    fn build_params<'a>(
        typed: Vec<(&'a str, String)>,
        raw: &'a [String],
    ) -> Result<Vec<(&'a str, String)>> {
        let mut out = typed;
        for spec in raw {
            let (k, v) = spec
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--raw expects KEY=VAL, got {spec:?}"))?;
            out.retain(|(ek, _)| *ek != k);
            let key_static: &'static str = Box::leak(k.to_string().into_boxed_str());
            out.push((key_static, v.to_string()));
        }
        Ok(out)
    }
    fn as_refs<'a>(v: &'a [(&'a str, String)]) -> Vec<(&'a str, &'a str)> {
        v.iter().map(|(k, v)| (*k, v.as_str())).collect()
    }

    match action {
        FirewallClusterCommand::Alias(cmd) => {
            match cmd {
                FirewallAliasCommand::List => {
                    let aliases = client.list_cluster_firewall_aliases().await?;
                    Ok((serde_json::to_value(aliases)?, 0))
                }
                FirewallAliasCommand::Create {
                    name,
                    cidr,
                    comment,
                    raw,
                } => {
                    let mut typed: Vec<(&str, String)> = vec![("name", name), ("cidr", cidr)];
                    if let Some(c) = comment {
                        typed.push(("comment", c));
                    }
                    let owned = build_params(typed, &raw)?;
                    client
                        .create_cluster_firewall_alias(&as_refs(&owned))
                        .await?;
                    Ok((serde_json::json!({"created": true}), 0))
                }
                FirewallAliasCommand::Update {
                    name,
                    cidr,
                    comment,
                    rename,
                    raw,
                } => {
                    let mut typed: Vec<(&str, String)> = vec![];
                    if let Some(c) = cidr {
                        typed.push(("cidr", c));
                    }
                    if let Some(c) = comment {
                        typed.push(("comment", c));
                    }
                    if let Some(r) = rename {
                        typed.push(("rename", r));
                    }
                    if typed.is_empty() && raw.is_empty() {
                        anyhow::bail!("update needs at least one field (--cidr, --comment, --rename, or --raw)");
                    }
                    let owned = build_params(typed, &raw)?;
                    client
                        .update_cluster_firewall_alias(&name, &as_refs(&owned))
                        .await?;
                    Ok((serde_json::json!({"updated": name}), 0))
                }
                FirewallAliasCommand::Delete { name, yes } => {
                    if !yes {
                        anyhow::bail!("destructive — pass --yes to confirm");
                    }
                    client.delete_cluster_firewall_alias(&name).await?;
                    Ok((serde_json::json!({"deleted": name}), 0))
                }
            }
        }
        FirewallClusterCommand::Group(cmd) => match cmd {
            FirewallGroupCommand::List => {
                let groups = client.list_cluster_firewall_groups().await?;
                Ok((serde_json::to_value(groups)?, 0))
            }
            FirewallGroupCommand::Create {
                group,
                comment,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("group", group)];
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                let owned = build_params(typed, &raw)?;
                client
                    .create_cluster_firewall_group(&as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"created": true}), 0))
            }
            FirewallGroupCommand::Delete { group, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client.delete_cluster_firewall_group(&group).await?;
                Ok((serde_json::json!({"deleted": group}), 0))
            }
            FirewallGroupCommand::Rules { group } => {
                let rules = client.list_cluster_firewall_group_rules(&group).await?;
                Ok((serde_json::to_value(rules)?, 0))
            }
        },
        FirewallClusterCommand::Ipset(cmd) => match cmd {
            FirewallIpsetCommand::List => {
                let ipsets = client.list_cluster_firewall_ipsets().await?;
                Ok((serde_json::to_value(ipsets)?, 0))
            }
            FirewallIpsetCommand::Create { name, comment, raw } => {
                let mut typed: Vec<(&str, String)> = vec![("name", name)];
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                let owned = build_params(typed, &raw)?;
                client
                    .create_cluster_firewall_ipset(&as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"created": true}), 0))
            }
            FirewallIpsetCommand::Delete { name, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client.delete_cluster_firewall_ipset(&name).await?;
                Ok((serde_json::json!({"deleted": name}), 0))
            }
            FirewallIpsetCommand::Cidrs { name } => {
                let cidrs = client.list_cluster_firewall_ipset_cidrs(&name).await?;
                Ok((serde_json::to_value(cidrs)?, 0))
            }
            FirewallIpsetCommand::AddCidr {
                name,
                cidr,
                nomatch,
                comment,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("cidr", cidr)];
                if nomatch {
                    typed.push(("nomatch", "1".to_string()));
                }
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                let owned = build_params(typed, &raw)?;
                client
                    .add_cluster_firewall_ipset_cidr(&name, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"added": true}), 0))
            }
            FirewallIpsetCommand::RemoveCidr { name, cidr, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client
                    .remove_cluster_firewall_ipset_cidr(&name, &cidr)
                    .await?;
                Ok((serde_json::json!({"removed": cidr}), 0))
            }
        },
        FirewallClusterCommand::Options(cmd) => match cmd {
            FirewallOptionsCommand::Get => {
                let opts = client.get_cluster_firewall_options().await?;
                Ok((serde_json::to_value(opts)?, 0))
            }
            FirewallOptionsCommand::Set {
                enable,
                policy_in,
                policy_out,
                ebtables,
                log_ratelimit,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                if let Some(e) = enable {
                    typed.push(("enable", if e { "1" } else { "0" }.to_string()));
                }
                if let Some(p) = policy_in {
                    typed.push(("policy_in", p));
                }
                if let Some(p) = policy_out {
                    typed.push(("policy_out", p));
                }
                if let Some(e) = ebtables {
                    typed.push(("ebtables", if e { "1" } else { "0" }.to_string()));
                }
                if let Some(l) = log_ratelimit {
                    typed.push(("log_ratelimit", l));
                }
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("set needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                client
                    .update_cluster_firewall_options(&as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"updated": true}), 0))
            }
        },
    }
}

/// Per-guest firewall CRUD dispatch. VMID is auto-resolved to its
/// owning node + guest type via the same scan the read-only firewall
/// command uses, so operators don't have to remember which node holds
/// which guest. Same `Box::leak` raw-param pattern as cluster firewall.
#[allow(clippy::too_many_lines)]
async fn execute_firewall_guest(
    client: &std::sync::Arc<crate::api::PxClient>,
    vmid: u32,
    action: FirewallGuestCommand,
) -> Result<(serde_json::Value, i32)> {
    use crate::api::ProxmoxGateway;

    fn build_params<'a>(
        typed: Vec<(&'a str, String)>,
        raw: &'a [String],
    ) -> Result<Vec<(&'a str, String)>> {
        let mut out = typed;
        for spec in raw {
            let (k, v) = spec
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--raw expects KEY=VAL, got {spec:?}"))?;
            out.retain(|(ek, _)| *ek != k);
            let key_static: &'static str = Box::leak(k.to_string().into_boxed_str());
            out.push((key_static, v.to_string()));
        }
        Ok(out)
    }
    fn as_refs<'a>(v: &'a [(&'a str, String)]) -> Vec<(&'a str, &'a str)> {
        v.iter().map(|(k, v)| (*k, v.as_str())).collect()
    }

    let (node, gt) = find_guest(client, vmid).await?;

    match action {
        FirewallGuestCommand::Alias(cmd) => match cmd {
            GuestFirewallAliasCommand::List => {
                let aliases = client.list_guest_firewall_aliases(&node, vmid, gt).await?;
                Ok((serde_json::to_value(aliases)?, 0))
            }
            GuestFirewallAliasCommand::Create {
                name,
                cidr,
                comment,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("name", name), ("cidr", cidr)];
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                let owned = build_params(typed, &raw)?;
                client
                    .create_guest_firewall_alias(&node, vmid, gt, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"created": true}), 0))
            }
            GuestFirewallAliasCommand::Update {
                name,
                cidr,
                comment,
                rename,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                if let Some(c) = cidr {
                    typed.push(("cidr", c));
                }
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                if let Some(r) = rename {
                    typed.push(("rename", r));
                }
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("update needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                client
                    .update_guest_firewall_alias(&node, vmid, gt, &name, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"updated": name}), 0))
            }
            GuestFirewallAliasCommand::Delete { name, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client
                    .delete_guest_firewall_alias(&node, vmid, gt, &name)
                    .await?;
                Ok((serde_json::json!({"deleted": name}), 0))
            }
        },
        FirewallGuestCommand::Options(cmd) => match cmd {
            GuestFirewallOptionsCommand::Get => {
                let opts = client.get_guest_firewall_options(&node, vmid, gt).await?;
                Ok((serde_json::to_value(opts)?, 0))
            }
            GuestFirewallOptionsCommand::Set {
                enable,
                policy_in,
                policy_out,
                log_level_in,
                log_level_out,
                dhcp,
                ndp,
                macfilter,
                ipfilter,
                radv,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                let push_bool = |t: &mut Vec<(&'static str, String)>, k: &'static str, v: bool| {
                    t.push((k, if v { "1" } else { "0" }.to_string()));
                };
                if let Some(e) = enable {
                    push_bool(&mut typed, "enable", e);
                }
                if let Some(p) = policy_in {
                    typed.push(("policy_in", p));
                }
                if let Some(p) = policy_out {
                    typed.push(("policy_out", p));
                }
                if let Some(l) = log_level_in {
                    typed.push(("log_level_in", l));
                }
                if let Some(l) = log_level_out {
                    typed.push(("log_level_out", l));
                }
                if let Some(b) = dhcp {
                    push_bool(&mut typed, "dhcp", b);
                }
                if let Some(b) = ndp {
                    push_bool(&mut typed, "ndp", b);
                }
                if let Some(b) = macfilter {
                    push_bool(&mut typed, "macfilter", b);
                }
                if let Some(b) = ipfilter {
                    push_bool(&mut typed, "ipfilter", b);
                }
                if let Some(b) = radv {
                    push_bool(&mut typed, "radv", b);
                }
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("set needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                client
                    .update_guest_firewall_options(&node, vmid, gt, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"updated": true, "vmid": vmid}), 0))
            }
        },
    }
}

/// Cluster hardware mapping dispatch (PCI + USB). Same operator
/// pattern as the firewall CRUD: typed flags + `--raw KEY=VAL`
/// escape hatch. The `--map` arg accepts repeats so multi-node
/// passthrough configs land in one CLI call.
#[allow(clippy::too_many_lines)]
async fn execute_cluster_mapping(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: ClusterMappingCommand,
) -> Result<(serde_json::Value, i32)> {
    use crate::api::ProxmoxGateway;

    fn build_params<'a>(
        typed: Vec<(&'a str, String)>,
        raw: &'a [String],
    ) -> Result<Vec<(&'a str, String)>> {
        let mut out = typed;
        for spec in raw {
            let (k, v) = spec
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--raw expects KEY=VAL, got {spec:?}"))?;
            out.retain(|(ek, _)| *ek != k);
            let key_static: &'static str = Box::leak(k.to_string().into_boxed_str());
            out.push((key_static, v.to_string()));
        }
        Ok(out)
    }
    fn as_refs<'a>(v: &'a [(&'a str, String)]) -> Vec<(&'a str, &'a str)> {
        v.iter().map(|(k, v)| (*k, v.as_str())).collect()
    }
    // PVE accepts the `map` field as a repeated form param — each
    // value is one `node=...,path=...,id=...` string. clap's Vec<String>
    // gives us each one separately; we re-emit them all under the same
    // key so the urlencoded body has `map=...&map=...&map=...`.
    fn push_map(typed: &mut Vec<(&'static str, String)>, items: Vec<String>) {
        for m in items {
            typed.push(("map", m));
        }
    }

    match action {
        ClusterMappingCommand::Pci(cmd) => match cmd {
            ClusterMappingPciCommand::List => {
                let mappings = client.list_cluster_mapping_pci().await?;
                Ok((serde_json::to_value(mappings)?, 0))
            }
            ClusterMappingPciCommand::Create {
                id,
                description,
                mdev,
                map,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("id", id)];
                if let Some(d) = description {
                    typed.push(("description", d));
                }
                if let Some(m) = mdev {
                    typed.push(("mdev", if m { "1" } else { "0" }.to_string()));
                }
                push_map(&mut typed, map);
                let owned = build_params(typed, &raw)?;
                client.create_cluster_mapping_pci(&as_refs(&owned)).await?;
                Ok((serde_json::json!({"created": true}), 0))
            }
            ClusterMappingPciCommand::Update {
                id,
                description,
                mdev,
                map,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                if let Some(d) = description {
                    typed.push(("description", d));
                }
                if let Some(m) = mdev {
                    typed.push(("mdev", if m { "1" } else { "0" }.to_string()));
                }
                push_map(&mut typed, map);
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("update needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                client
                    .update_cluster_mapping_pci(&id, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"updated": id}), 0))
            }
            ClusterMappingPciCommand::Delete { id, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client.delete_cluster_mapping_pci(&id).await?;
                Ok((serde_json::json!({"deleted": id}), 0))
            }
        },
        ClusterMappingCommand::Usb(cmd) => match cmd {
            ClusterMappingUsbCommand::List => {
                let mappings = client.list_cluster_mapping_usb().await?;
                Ok((serde_json::to_value(mappings)?, 0))
            }
            ClusterMappingUsbCommand::Create {
                id,
                description,
                map,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("id", id)];
                if let Some(d) = description {
                    typed.push(("description", d));
                }
                push_map(&mut typed, map);
                let owned = build_params(typed, &raw)?;
                client.create_cluster_mapping_usb(&as_refs(&owned)).await?;
                Ok((serde_json::json!({"created": true}), 0))
            }
            ClusterMappingUsbCommand::Update {
                id,
                description,
                map,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                if let Some(d) = description {
                    typed.push(("description", d));
                }
                push_map(&mut typed, map);
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("update needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                client
                    .update_cluster_mapping_usb(&id, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"updated": id}), 0))
            }
            ClusterMappingUsbCommand::Delete { id, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client.delete_cluster_mapping_usb(&id).await?;
                Ok((serde_json::json!({"deleted": id}), 0))
            }
        },
    }
}

/// QEMU Guest Agent file ops + network introspection. Auto-discovers
/// the VMID's node and guest type, then bails clearly if the guest is
/// LXC (no QGA on the container side). Emits a `truncated` warning on
/// the JSON output when a file read came back partial — operators
/// glancing at the result get a clear signal not to trust the content.
async fn execute_qga(
    client: &std::sync::Arc<crate::api::PxClient>,
    vmid: u32,
    action: QgaCommand,
) -> Result<(serde_json::Value, i32)> {
    use crate::api::types::GuestType;
    use crate::api::ProxmoxGateway;

    let (node, gt) = find_guest(client, vmid).await?;
    if !matches!(gt, GuestType::Qemu) {
        anyhow::bail!(
            "qga commands require QEMU — vmid {vmid} is an LXC \
             (no guest-agent surface; use `proxxx exec` or SSH instead)"
        );
    }

    match action {
        QgaCommand::Read { file } => {
            let res = client.qemu_agent_file_read(&node, vmid, &file).await?;
            Ok((
                serde_json::json!({
                    "file": file,
                    "content": res.content,
                    "truncated": res.truncated,
                }),
                0,
            ))
        }
        QgaCommand::Write { file, content } => {
            client
                .qemu_agent_file_write(&node, vmid, &file, &content)
                .await?;
            Ok((
                serde_json::json!({"file": file, "bytes": content.len(), "written": true}),
                0,
            ))
        }
        QgaCommand::Net => {
            let ifaces = client
                .qemu_agent_network_get_interfaces(&node, vmid)
                .await?;
            Ok((serde_json::json!({"vmid": vmid, "interfaces": ifaces}), 0))
        }
    }
}

/// Node system layer dispatch — nine resources sharing one `<node>`
/// arg. Atomic-update guard on hosts: GET first, hand the digest back
/// on PUT, unless the operator passes `--no-check` to bypass.
#[allow(clippy::too_many_lines)]
async fn execute_node_system(
    client: &std::sync::Arc<crate::api::PxClient>,
    node: &str,
    action: NodeSystemCommand,
) -> Result<(serde_json::Value, i32)> {
    use crate::api::ProxmoxGateway;

    fn push_opt<'a>(v: &mut Vec<(&'a str, String)>, key: &'a str, val: Option<String>) {
        if let Some(s) = val {
            v.push((key, s));
        }
    }
    fn as_refs<'a>(v: &'a [(&'a str, String)]) -> Vec<(&'a str, &'a str)> {
        v.iter().map(|(k, s)| (*k, s.as_str())).collect()
    }

    match action {
        NodeSystemCommand::Dns(cmd) => match cmd {
            NodeDnsCommand::Get => {
                let dns = client.get_node_dns(node).await?;
                Ok((serde_json::to_value(dns)?, 0))
            }
            NodeDnsCommand::Set {
                search,
                dns1,
                dns2,
                dns3,
            } => {
                let mut params: Vec<(&str, String)> = vec![];
                push_opt(&mut params, "search", search);
                push_opt(&mut params, "dns1", dns1);
                push_opt(&mut params, "dns2", dns2);
                push_opt(&mut params, "dns3", dns3);
                if params.is_empty() {
                    anyhow::bail!("set needs at least one field");
                }
                client.update_node_dns(node, &as_refs(&params)).await?;
                Ok((serde_json::json!({"updated": true}), 0))
            }
        },
        NodeSystemCommand::Hosts(cmd) => match cmd {
            NodeHostsCommand::Get => {
                let h = client.get_node_hosts(node).await?;
                Ok((serde_json::to_value(h)?, 0))
            }
            NodeHostsCommand::Set {
                data,
                digest,
                no_check,
            } => {
                let resolved_digest = if no_check {
                    None
                } else {
                    match digest {
                        Some(d) => Some(d),
                        None => Some(client.get_node_hosts(node).await?.digest),
                    }
                };
                client
                    .update_node_hosts(node, &data, resolved_digest.as_deref())
                    .await?;
                Ok((serde_json::json!({"updated": true}), 0))
            }
        },
        NodeSystemCommand::Journal {
            since,
            until,
            lastentries,
            service,
        } => {
            let mut q: Vec<(&str, String)> = vec![];
            push_opt(&mut q, "since", since);
            push_opt(&mut q, "until", until);
            if let Some(n) = lastentries {
                q.push(("lastentries", n.to_string()));
            }
            push_opt(&mut q, "service", service);
            let lines = client.get_node_journal(node, &as_refs(&q)).await?;
            Ok((
                serde_json::json!({"node": node, "count": lines.len(), "lines": lines}),
                0,
            ))
        }
        NodeSystemCommand::Syslog {
            start,
            limit,
            since,
            until,
            service,
        } => {
            let mut q: Vec<(&str, String)> = vec![];
            if let Some(s) = start {
                q.push(("start", s.to_string()));
            }
            if let Some(l) = limit {
                q.push(("limit", l.to_string()));
            }
            push_opt(&mut q, "since", since);
            push_opt(&mut q, "until", until);
            push_opt(&mut q, "service", service);
            let lines = client.get_node_syslog(node, &as_refs(&q)).await?;
            Ok((serde_json::to_value(lines)?, 0))
        }
        NodeSystemCommand::Time(cmd) => match cmd {
            NodeTimeCommand::Get => {
                let t = client.get_node_time(node).await?;
                Ok((serde_json::to_value(t)?, 0))
            }
            NodeTimeCommand::Set { timezone } => {
                client.update_node_timezone(node, &timezone).await?;
                Ok((serde_json::json!({"timezone": timezone}), 0))
            }
        },
        NodeSystemCommand::Wol => {
            let mac = client.wakeonlan_node(node).await?;
            Ok((serde_json::json!({"node": node, "mac": mac}), 0))
        }
        NodeSystemCommand::Subscription(cmd) => match cmd {
            NodeSubscriptionCommand::Get => {
                let s = client.get_node_subscription(node).await?;
                Ok((serde_json::to_value(s)?, 0))
            }
            NodeSubscriptionCommand::Set { key } => {
                client.set_node_subscription_key(node, &key).await?;
                Ok((serde_json::json!({"set": true}), 0))
            }
            NodeSubscriptionCommand::Refresh => {
                client.refresh_node_subscription(node).await?;
                Ok((serde_json::json!({"refreshed": true}), 0))
            }
            NodeSubscriptionCommand::Delete { yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client.delete_node_subscription(node).await?;
                Ok((serde_json::json!({"deleted": true}), 0))
            }
        },
        NodeSystemCommand::Cert(cmd) => match cmd {
            NodeCertCommand::Info => {
                let info = client.get_node_certificates_info(node).await?;
                Ok((serde_json::to_value(info)?, 0))
            }
            NodeCertCommand::Upload {
                certificate,
                key,
                restart,
            } => {
                let restart_str = if restart { "1" } else { "0" };
                let params: Vec<(&str, &str)> = vec![
                    ("certificates", certificate.as_str()),
                    ("key", key.as_str()),
                    ("restart", restart_str),
                ];
                client.upload_node_custom_certificate(node, &params).await?;
                Ok((
                    serde_json::json!({"uploaded": true, "restarted": restart}),
                    0,
                ))
            }
            NodeCertCommand::Delete { restart, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client.delete_node_custom_certificate(node, restart).await?;
                Ok((
                    serde_json::json!({"deleted": true, "restarted": restart}),
                    0,
                ))
            }
            NodeCertCommand::AcmeOrder { force } => {
                let upid = client.order_node_acme_certificate(node, force).await?;
                Ok((serde_json::json!({"upid": upid, "force": force}), 0))
            }
        },
        NodeSystemCommand::Report => {
            let txt = client.get_node_report(node).await?;
            Ok((
                serde_json::json!({"node": node, "bytes": txt.len(), "report": txt}),
                0,
            ))
        }
    }
}

/// Pool dispatch. `add-members` / `remove-members` both compose into
/// the same PVE PUT (PVE uses `delete=1` to flip the operation), so
/// we route them through a single helper.
async fn execute_pool(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: PoolCommand,
) -> Result<(serde_json::Value, i32)> {
    use crate::api::ProxmoxGateway;

    fn member_params<'a>(
        vms: &'a Option<String>,
        storage: &'a Option<String>,
    ) -> Vec<(&'a str, &'a str)> {
        let mut p = vec![];
        if let Some(v) = vms {
            p.push(("vms", v.as_str()));
        }
        if let Some(s) = storage {
            p.push(("storage", s.as_str()));
        }
        p
    }

    match action {
        PoolCommand::List => {
            let pools = client.list_pools().await?;
            Ok((serde_json::to_value(pools)?, 0))
        }
        PoolCommand::Show { poolid } => {
            let p = client.get_pool(&poolid).await?;
            Ok((serde_json::to_value(p)?, 0))
        }
        PoolCommand::Create { poolid, comment } => {
            let mut params: Vec<(&str, &str)> = vec![("poolid", poolid.as_str())];
            if let Some(c) = comment.as_deref() {
                params.push(("comment", c));
            }
            client.create_pool(&params).await?;
            Ok((serde_json::json!({"created": poolid}), 0))
        }
        PoolCommand::AddMembers {
            poolid,
            vms,
            storage,
        } => {
            let params = member_params(&vms, &storage);
            if params.is_empty() {
                anyhow::bail!("add-members needs at least one of --vms or --storage");
            }
            client.update_pool(&poolid, &params).await?;
            Ok((serde_json::json!({"added": true}), 0))
        }
        PoolCommand::RemoveMembers {
            poolid,
            vms,
            storage,
        } => {
            let mut params = member_params(&vms, &storage);
            if params.is_empty() {
                anyhow::bail!("remove-members needs at least one of --vms or --storage");
            }
            params.push(("delete", "1"));
            client.update_pool(&poolid, &params).await?;
            Ok((serde_json::json!({"removed": true}), 0))
        }
        PoolCommand::SetComment { poolid, comment } => {
            client
                .update_pool(&poolid, &[("comment", comment.as_str())])
                .await?;
            Ok((serde_json::json!({"updated": poolid}), 0))
        }
        PoolCommand::Delete { poolid, yes } => {
            if !yes {
                anyhow::bail!("destructive — pass --yes to confirm");
            }
            client.delete_pool(&poolid).await?;
            Ok((serde_json::json!({"deleted": poolid}), 0))
        }
    }
}

/// `proxxx cluster-resources [--kind ...]` — dump the single-shot
/// cluster-wide resource list. The PVE web UI's main dashboard query.
async fn execute_cluster_resources(
    client: &std::sync::Arc<crate::api::PxClient>,
    kind: Option<String>,
) -> Result<(serde_json::Value, i32)> {
    use crate::api::ProxmoxGateway;
    let resources = client.get_cluster_resources(kind.as_deref()).await?;
    Ok((
        serde_json::json!({"count": resources.len(), "resources": resources}),
        0,
    ))
}

/// `proxxx pve-version` — PVE API version + git rev. Output is the
/// typed shape so it's easy to grep with jq for compat-gating scripts.
/// (Distinct from `proxxx version` which reports proxxx's own binary
/// version + build metadata.)
async fn execute_pve_version(
    client: &std::sync::Arc<crate::api::PxClient>,
) -> Result<(serde_json::Value, i32)> {
    use crate::api::ProxmoxGateway;
    let v = client.get_api_version().await?;
    Ok((serde_json::to_value(v)?, 0))
}

/// `proxxx cluster-config {get|set}` — global cluster options.
async fn execute_cluster_config(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: ClusterConfigCommand,
) -> Result<(serde_json::Value, i32)> {
    use crate::api::ProxmoxGateway;

    fn build_params<'a>(
        typed: Vec<(&'a str, String)>,
        raw: &'a [String],
    ) -> Result<Vec<(&'a str, String)>> {
        let mut out = typed;
        for spec in raw {
            let (k, v) = spec
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--raw expects KEY=VAL, got {spec:?}"))?;
            out.retain(|(ek, _)| *ek != k);
            let key_static: &'static str = Box::leak(k.to_string().into_boxed_str());
            out.push((key_static, v.to_string()));
        }
        Ok(out)
    }
    fn as_refs<'a>(v: &'a [(&'a str, String)]) -> Vec<(&'a str, &'a str)> {
        v.iter().map(|(k, s)| (*k, s.as_str())).collect()
    }

    match action {
        ClusterConfigCommand::Get => {
            let opts = client.get_cluster_options().await?;
            Ok((serde_json::to_value(opts)?, 0))
        }
        ClusterConfigCommand::Set {
            mac_prefix,
            migration,
            description,
            console,
            keyboard,
            max_workers,
            email_from,
            registered_tags,
            raw,
        } => {
            let mut typed: Vec<(&str, String)> = vec![];
            let push_opt =
                |t: &mut Vec<(&'static str, String)>, k: &'static str, v: Option<String>| {
                    if let Some(s) = v {
                        t.push((k, s));
                    }
                };
            push_opt(&mut typed, "mac_prefix", mac_prefix);
            push_opt(&mut typed, "migration", migration);
            push_opt(&mut typed, "description", description);
            push_opt(&mut typed, "console", console);
            push_opt(&mut typed, "keyboard", keyboard);
            if let Some(n) = max_workers {
                typed.push(("max_workers", n.to_string()));
            }
            push_opt(&mut typed, "email_from", email_from);
            // Hyphenated wire field needs the literal hyphen, not the
            // snake_case CLI flag name.
            if let Some(t) = registered_tags {
                typed.push(("registered-tags", t));
            }
            if typed.is_empty() && raw.is_empty() {
                anyhow::bail!("set needs at least one field");
            }
            let owned = build_params(typed, &raw)?;
            client.update_cluster_options(&as_refs(&owned)).await?;
            Ok((serde_json::json!({"updated": true}), 0))
        }
    }
}

/// `proxxx cluster-log [--max N]` — recent cluster events. Newest
/// first. Useful for "what happened around 14:30 yesterday" diagnostics.
async fn execute_cluster_log(
    client: &std::sync::Arc<crate::api::PxClient>,
    max: Option<u32>,
) -> Result<(serde_json::Value, i32)> {
    use crate::api::ProxmoxGateway;
    let entries = client.get_cluster_log(max).await?;
    Ok((
        serde_json::json!({"count": entries.len(), "entries": entries}),
        0,
    ))
}

/// PVE 8+ notifications dispatch. Three sub-trees (endpoint/matcher/
/// targets). Repeated `--target` / `--match-field` / `--match-severity`
/// flags compose into PVE's repeated-form-param wire shape.
#[allow(clippy::too_many_lines)]
async fn execute_notifications(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: NotificationsCommand,
) -> Result<(serde_json::Value, i32)> {
    use crate::api::ProxmoxGateway;

    fn build_params<'a>(
        typed: Vec<(&'a str, String)>,
        raw: &'a [String],
    ) -> Result<Vec<(&'a str, String)>> {
        let mut out = typed;
        for spec in raw {
            let (k, v) = spec
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--raw expects KEY=VAL, got {spec:?}"))?;
            out.retain(|(ek, _)| *ek != k);
            let key_static: &'static str = Box::leak(k.to_string().into_boxed_str());
            out.push((key_static, v.to_string()));
        }
        Ok(out)
    }
    fn as_refs<'a>(v: &'a [(&'a str, String)]) -> Vec<(&'a str, &'a str)> {
        v.iter().map(|(k, s)| (*k, s.as_str())).collect()
    }
    fn push_repeated(
        typed: &mut Vec<(&'static str, String)>,
        key: &'static str,
        items: Vec<String>,
    ) {
        for v in items {
            typed.push((key, v));
        }
    }

    match action {
        NotificationsCommand::Endpoint(cmd) => match cmd {
            NotificationEndpointCommand::List => {
                let endpoints = client.list_notification_endpoints().await?;
                Ok((serde_json::to_value(endpoints)?, 0))
            }
            NotificationEndpointCommand::Create {
                endpoint_type,
                name,
                comment,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("name", name)];
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                let owned = build_params(typed, &raw)?;
                client
                    .create_notification_endpoint(&endpoint_type, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"created": true}), 0))
            }
            NotificationEndpointCommand::Update {
                endpoint_type,
                name,
                comment,
                disable,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                if let Some(d) = disable {
                    typed.push(("disable", if d { "1" } else { "0" }.to_string()));
                }
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("update needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                client
                    .update_notification_endpoint(&endpoint_type, &name, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"updated": name}), 0))
            }
            NotificationEndpointCommand::Delete {
                endpoint_type,
                name,
                yes,
            } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client
                    .delete_notification_endpoint(&endpoint_type, &name)
                    .await?;
                Ok((serde_json::json!({"deleted": name}), 0))
            }
        },
        NotificationsCommand::Matcher(cmd) => match cmd {
            NotificationMatcherCommand::List => {
                let matchers = client.list_notification_matchers().await?;
                Ok((serde_json::to_value(matchers)?, 0))
            }
            NotificationMatcherCommand::Create {
                name,
                target,
                match_field,
                match_severity,
                mode,
                invert_match,
                comment,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("name", name)];
                push_repeated(&mut typed, "target", target);
                push_repeated(&mut typed, "match-field", match_field);
                push_repeated(&mut typed, "match-severity", match_severity);
                if let Some(m) = mode {
                    typed.push(("mode", m));
                }
                if let Some(i) = invert_match {
                    typed.push(("invert-match", if i { "1" } else { "0" }.to_string()));
                }
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                let owned = build_params(typed, &raw)?;
                client.create_notification_matcher(&as_refs(&owned)).await?;
                Ok((serde_json::json!({"created": true}), 0))
            }
            NotificationMatcherCommand::Update {
                name,
                target,
                match_field,
                match_severity,
                mode,
                invert_match,
                disable,
                comment,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                push_repeated(&mut typed, "target", target);
                push_repeated(&mut typed, "match-field", match_field);
                push_repeated(&mut typed, "match-severity", match_severity);
                if let Some(m) = mode {
                    typed.push(("mode", m));
                }
                if let Some(i) = invert_match {
                    typed.push(("invert-match", if i { "1" } else { "0" }.to_string()));
                }
                if let Some(d) = disable {
                    typed.push(("disable", if d { "1" } else { "0" }.to_string()));
                }
                if let Some(c) = comment {
                    typed.push(("comment", c));
                }
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("update needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                client
                    .update_notification_matcher(&name, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"updated": name}), 0))
            }
            NotificationMatcherCommand::Delete { name, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client.delete_notification_matcher(&name).await?;
                Ok((serde_json::json!({"deleted": name}), 0))
            }
        },
        NotificationsCommand::Targets => {
            let targets = client.list_notification_targets().await?;
            Ok((serde_json::to_value(targets)?, 0))
        }
    }
}

/// Cluster-wide storage definitions dispatch.
#[allow(clippy::too_many_lines)]
async fn execute_storage_defs(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: StorageDefsCommand,
) -> Result<(serde_json::Value, i32)> {
    use crate::api::ProxmoxGateway;

    fn build_params<'a>(
        typed: Vec<(&'a str, String)>,
        raw: &'a [String],
    ) -> Result<Vec<(&'a str, String)>> {
        let mut out = typed;
        for spec in raw {
            let (k, v) = spec
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--raw expects KEY=VAL, got {spec:?}"))?;
            out.retain(|(ek, _)| *ek != k);
            let key_static: &'static str = Box::leak(k.to_string().into_boxed_str());
            out.push((key_static, v.to_string()));
        }
        Ok(out)
    }
    fn as_refs<'a>(v: &'a [(&'a str, String)]) -> Vec<(&'a str, &'a str)> {
        v.iter().map(|(k, s)| (*k, s.as_str())).collect()
    }

    match action {
        StorageDefsCommand::List => {
            let storages = client.list_cluster_storages().await?;
            Ok((serde_json::to_value(storages)?, 0))
        }
        StorageDefsCommand::Show { storage } => {
            let s = client.get_cluster_storage(&storage).await?;
            Ok((serde_json::to_value(s)?, 0))
        }
        StorageDefsCommand::Create {
            storage,
            storage_type,
            content,
            nodes,
            shared,
            path,
            server,
            export,
            datastore,
            fingerprint,
            username,
            pool,
            vgname,
            thinpool,
            raw,
        } => {
            let mut typed: Vec<(&str, String)> = vec![("storage", storage), ("type", storage_type)];
            let push_opt =
                |t: &mut Vec<(&'static str, String)>, k: &'static str, v: Option<String>| {
                    if let Some(s) = v {
                        t.push((k, s));
                    }
                };
            push_opt(&mut typed, "content", content);
            push_opt(&mut typed, "nodes", nodes);
            if let Some(s) = shared {
                typed.push(("shared", if s { "1" } else { "0" }.to_string()));
            }
            push_opt(&mut typed, "path", path);
            push_opt(&mut typed, "server", server);
            push_opt(&mut typed, "export", export);
            push_opt(&mut typed, "datastore", datastore);
            push_opt(&mut typed, "fingerprint", fingerprint);
            push_opt(&mut typed, "username", username);
            push_opt(&mut typed, "pool", pool);
            push_opt(&mut typed, "vgname", vgname);
            push_opt(&mut typed, "thinpool", thinpool);
            let owned = build_params(typed, &raw)?;
            client.create_cluster_storage(&as_refs(&owned)).await?;
            Ok((serde_json::json!({"created": true}), 0))
        }
        StorageDefsCommand::Update {
            storage,
            content,
            nodes,
            disable,
            shared,
            fingerprint,
            delete,
            raw,
        } => {
            let mut typed: Vec<(&str, String)> = vec![];
            let push_opt =
                |t: &mut Vec<(&'static str, String)>, k: &'static str, v: Option<String>| {
                    if let Some(s) = v {
                        t.push((k, s));
                    }
                };
            push_opt(&mut typed, "content", content);
            push_opt(&mut typed, "nodes", nodes);
            if let Some(d) = disable {
                typed.push(("disable", if d { "1" } else { "0" }.to_string()));
            }
            if let Some(s) = shared {
                typed.push(("shared", if s { "1" } else { "0" }.to_string()));
            }
            push_opt(&mut typed, "fingerprint", fingerprint);
            push_opt(&mut typed, "delete", delete);
            if typed.is_empty() && raw.is_empty() {
                anyhow::bail!("update needs at least one field");
            }
            let owned = build_params(typed, &raw)?;
            client
                .update_cluster_storage(&storage, &as_refs(&owned))
                .await?;
            Ok((serde_json::json!({"updated": storage}), 0))
        }
        StorageDefsCommand::Delete { storage, yes } => {
            if !yes {
                anyhow::bail!("destructive — pass --yes to confirm");
            }
            client.delete_cluster_storage(&storage).await?;
            Ok((serde_json::json!({"deleted": storage}), 0))
        }
    }
}

/// ACME cluster-wide config dispatch. Account create/update/delete
/// return UPIDs because the CA round-trip is async.
#[allow(clippy::too_many_lines)]
async fn execute_acme(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: AcmeCommand,
) -> Result<(serde_json::Value, i32)> {
    use crate::api::ProxmoxGateway;

    fn build_params<'a>(
        typed: Vec<(&'a str, String)>,
        raw: &'a [String],
    ) -> Result<Vec<(&'a str, String)>> {
        let mut out = typed;
        for spec in raw {
            let (k, v) = spec
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--raw expects KEY=VAL, got {spec:?}"))?;
            out.retain(|(ek, _)| *ek != k);
            let key_static: &'static str = Box::leak(k.to_string().into_boxed_str());
            out.push((key_static, v.to_string()));
        }
        Ok(out)
    }
    fn as_refs<'a>(v: &'a [(&'a str, String)]) -> Vec<(&'a str, &'a str)> {
        v.iter().map(|(k, s)| (*k, s.as_str())).collect()
    }

    match action {
        AcmeCommand::Account(cmd) => match cmd {
            AcmeAccountCommand::List => {
                let accounts = client.list_acme_accounts().await?;
                Ok((serde_json::to_value(accounts)?, 0))
            }
            AcmeAccountCommand::Show { name } => {
                let a = client.get_acme_account(&name).await?;
                Ok((serde_json::to_value(a)?, 0))
            }
            AcmeAccountCommand::Create {
                name,
                contact,
                tos_url,
                directory,
                eab_kid,
                eab_hmac_key,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("name", name), ("contact", contact)];
                let push_opt =
                    |t: &mut Vec<(&'static str, String)>, k: &'static str, v: Option<String>| {
                        if let Some(s) = v {
                            t.push((k, s));
                        }
                    };
                push_opt(&mut typed, "tos_url", tos_url);
                push_opt(&mut typed, "directory", directory);
                // PVE accepts both `eab_kid` and `eab-kid`; we pick the
                // hyphen variant since that's what the docs show.
                push_opt(&mut typed, "eab-kid", eab_kid);
                push_opt(&mut typed, "eab-hmac-key", eab_hmac_key);
                let owned = build_params(typed, &raw)?;
                let upid = client.create_acme_account(&as_refs(&owned)).await?;
                Ok((serde_json::json!({"upid": upid}), 0))
            }
            AcmeAccountCommand::Update { name, contact, raw } => {
                let mut typed: Vec<(&str, String)> = vec![];
                if let Some(c) = contact {
                    typed.push(("contact", c));
                }
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("update needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                let upid = client.update_acme_account(&name, &as_refs(&owned)).await?;
                Ok((serde_json::json!({"upid": upid, "updated": name}), 0))
            }
            AcmeAccountCommand::Delete { name, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                let upid = client.delete_acme_account(&name).await?;
                Ok((serde_json::json!({"upid": upid, "deleted": name}), 0))
            }
        },
        AcmeCommand::Plugin(cmd) => match cmd {
            AcmePluginCommand::List => {
                let plugins = client.list_acme_plugins().await?;
                Ok((serde_json::to_value(plugins)?, 0))
            }
            AcmePluginCommand::Show { plugin_id } => {
                let p = client.get_acme_plugin(&plugin_id).await?;
                Ok((serde_json::to_value(p)?, 0))
            }
            AcmePluginCommand::Create {
                plugin_id,
                plugin_type,
                api,
                data,
                validation_delay,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("id", plugin_id), ("type", plugin_type)];
                let push_opt =
                    |t: &mut Vec<(&'static str, String)>, k: &'static str, v: Option<String>| {
                        if let Some(s) = v {
                            t.push((k, s));
                        }
                    };
                push_opt(&mut typed, "api", api);
                push_opt(&mut typed, "data", data);
                if let Some(d) = validation_delay {
                    typed.push(("validation-delay", d.to_string()));
                }
                let owned = build_params(typed, &raw)?;
                client.create_acme_plugin(&as_refs(&owned)).await?;
                Ok((serde_json::json!({"created": true}), 0))
            }
            AcmePluginCommand::Update {
                plugin_id,
                api,
                data,
                validation_delay,
                disable,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                let push_opt =
                    |t: &mut Vec<(&'static str, String)>, k: &'static str, v: Option<String>| {
                        if let Some(s) = v {
                            t.push((k, s));
                        }
                    };
                push_opt(&mut typed, "api", api);
                push_opt(&mut typed, "data", data);
                if let Some(d) = validation_delay {
                    typed.push(("validation-delay", d.to_string()));
                }
                if let Some(d) = disable {
                    typed.push(("disable", if d { "1" } else { "0" }.to_string()));
                }
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("update needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                client
                    .update_acme_plugin(&plugin_id, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"updated": plugin_id}), 0))
            }
            AcmePluginCommand::Delete { plugin_id, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client.delete_acme_plugin(&plugin_id).await?;
                Ok((serde_json::json!({"deleted": plugin_id}), 0))
            }
        },
        AcmeCommand::Tos { directory } => {
            let tos = client.get_acme_tos(directory.as_deref()).await?;
            Ok((serde_json::json!({"tos_url": tos}), 0))
        }
        AcmeCommand::Directories => {
            let dirs = client.list_acme_directories().await?;
            Ok((serde_json::to_value(dirs)?, 0))
        }
        AcmeCommand::ChallengeSchema => {
            let schema = client.get_acme_challenge_schema().await?;
            Ok((schema, 0))
        }
    }
}

/// Corosync cluster bootstrap dispatch. Most mutations return UPIDs
/// (corosync restart on the cluster involves real reconfiguration).
#[allow(clippy::too_many_lines)]
async fn execute_cluster_bootstrap(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: ClusterBootstrapCommand,
) -> Result<(serde_json::Value, i32)> {
    use crate::api::ProxmoxGateway;

    fn build_params<'a>(
        typed: Vec<(&'a str, String)>,
        raw: &'a [String],
    ) -> Result<Vec<(&'a str, String)>> {
        let mut out = typed;
        for spec in raw {
            let (k, v) = spec
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("--raw expects KEY=VAL, got {spec:?}"))?;
            out.retain(|(ek, _)| *ek != k);
            let key_static: &'static str = Box::leak(k.to_string().into_boxed_str());
            out.push((key_static, v.to_string()));
        }
        Ok(out)
    }
    fn as_refs<'a>(v: &'a [(&'a str, String)]) -> Vec<(&'a str, &'a str)> {
        v.iter().map(|(k, s)| (*k, s.as_str())).collect()
    }

    match action {
        ClusterBootstrapCommand::Nodes(cmd) => match cmd {
            CorosyncNodesCommand::List => {
                let nodes = client.list_cluster_corosync_nodes().await?;
                Ok((serde_json::to_value(nodes)?, 0))
            }
            CorosyncNodesCommand::Add {
                node,
                ring0_addr,
                ring1_addr,
                nodeid,
                votes,
                force,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                let push_opt =
                    |t: &mut Vec<(&'static str, String)>, k: &'static str, v: Option<String>| {
                        if let Some(s) = v {
                            t.push((k, s));
                        }
                    };
                push_opt(&mut typed, "ring0_addr", ring0_addr);
                push_opt(&mut typed, "ring1_addr", ring1_addr);
                if let Some(n) = nodeid {
                    typed.push(("nodeid", n.to_string()));
                }
                if let Some(v) = votes {
                    typed.push(("votes", v.to_string()));
                }
                if force {
                    typed.push(("force", "1".to_string()));
                }
                let owned = build_params(typed, &raw)?;
                client
                    .add_cluster_corosync_node(&node, &as_refs(&owned))
                    .await?;
                Ok((serde_json::json!({"added": node}), 0))
            }
            CorosyncNodesCommand::Remove { node, yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                client.remove_cluster_corosync_node(&node).await?;
                Ok((serde_json::json!({"removed": node}), 0))
            }
        },
        ClusterBootstrapCommand::Join(cmd) => match cmd {
            ClusterJoinCommand::Info { node } => {
                let info = client.get_cluster_join_info(node.as_deref()).await?;
                Ok((info, 0))
            }
            ClusterJoinCommand::Join {
                hostname,
                password,
                fingerprint,
                nodeid,
                votes,
                force,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![
                    ("hostname", hostname),
                    ("password", password),
                    ("fingerprint", fingerprint),
                ];
                if let Some(n) = nodeid {
                    typed.push(("nodeid", n.to_string()));
                }
                if let Some(v) = votes {
                    typed.push(("votes", v.to_string()));
                }
                if force {
                    typed.push(("force", "1".to_string()));
                }
                let owned = build_params(typed, &raw)?;
                let upid = client.join_cluster(&as_refs(&owned)).await?;
                Ok((serde_json::json!({"upid": upid}), 0))
            }
        },
        ClusterBootstrapCommand::Qdevice(cmd) => match cmd {
            ClusterQdeviceCommand::Get => {
                let q = client.get_cluster_qdevice().await?;
                Ok((q, 0))
            }
            ClusterQdeviceCommand::Setup {
                addr,
                algorithm,
                tie_breaker,
                net_username,
                force,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![("addr", addr)];
                let push_opt =
                    |t: &mut Vec<(&'static str, String)>, k: &'static str, v: Option<String>| {
                        if let Some(s) = v {
                            t.push((k, s));
                        }
                    };
                push_opt(&mut typed, "algorithm", algorithm);
                push_opt(&mut typed, "tie_breaker", tie_breaker);
                push_opt(&mut typed, "net_username", net_username);
                if force {
                    typed.push(("force", "1".to_string()));
                }
                let owned = build_params(typed, &raw)?;
                let upid = client.setup_cluster_qdevice(&as_refs(&owned)).await?;
                Ok((serde_json::json!({"upid": upid}), 0))
            }
            ClusterQdeviceCommand::Update {
                algorithm,
                tie_breaker,
                force,
                raw,
            } => {
                let mut typed: Vec<(&str, String)> = vec![];
                let push_opt =
                    |t: &mut Vec<(&'static str, String)>, k: &'static str, v: Option<String>| {
                        if let Some(s) = v {
                            t.push((k, s));
                        }
                    };
                push_opt(&mut typed, "algorithm", algorithm);
                push_opt(&mut typed, "tie_breaker", tie_breaker);
                if let Some(f) = force {
                    typed.push(("force", if f { "1" } else { "0" }.to_string()));
                }
                if typed.is_empty() && raw.is_empty() {
                    anyhow::bail!("update needs at least one field");
                }
                let owned = build_params(typed, &raw)?;
                let upid = client.update_cluster_qdevice(&as_refs(&owned)).await?;
                Ok((serde_json::json!({"upid": upid}), 0))
            }
            ClusterQdeviceCommand::Delete { yes } => {
                if !yes {
                    anyhow::bail!("destructive — pass --yes to confirm");
                }
                let upid = client.remove_cluster_qdevice().await?;
                Ok((serde_json::json!({"upid": upid}), 0))
            }
        },
        ClusterBootstrapCommand::Totem => {
            let totem = client.get_cluster_totem().await?;
            Ok((totem, 0))
        }
    }
}

/// LXC template catalog dispatch. `download` returns a UPID — wrap
/// with `proxxx tasks --node X` to track completion.
async fn execute_aplinfo(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: AplinfoCommand,
) -> Result<(serde_json::Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        AplinfoCommand::List { node } => {
            let templates = client.list_node_aplinfo(&node).await?;
            Ok((
                serde_json::json!({"node": node, "count": templates.len(), "templates": templates}),
                0,
            ))
        }
        AplinfoCommand::Download {
            node,
            storage,
            template,
        } => {
            let upid = client
                .download_node_aplinfo(&node, &storage, &template)
                .await?;
            Ok((
                serde_json::json!({"upid": upid, "node": node, "storage": storage, "template": template}),
                0,
            ))
        }
    }
}

/// Hill 2a/2b — guest VNC handoff. Mints a one-shot vncproxy ticket
/// and emits it as JSON. Auto-discovers the owning node + guest_type
/// when caller omits `--node`.
async fn execute_vnc(
    client: &std::sync::Arc<crate::api::PxClient>,
    vmid: u32,
    node: Option<String>,
    ws_url: bool,
) -> Result<(Value, i32)> {
    use crate::api::types::GuestType;
    use crate::api::ProxmoxGateway;

    let (node_name, gt) = match node {
        Some(n) => {
            // Caller knows the node — but we still need guest_type to
            // route /qemu/ vs /lxc/. One get_guests call is the
            // cheapest way to determine it (filtering one node).
            let guests = client.get_guests(&n).await?;
            let g = guests
                .iter()
                .find(|g| g.vmid == vmid)
                .ok_or_else(|| anyhow::anyhow!("vmid {vmid} not on node {n}"))?;
            (n, g.guest_type)
        }
        None => {
            let nodes = client.get_nodes().await?;
            let mut found: Option<(String, GuestType)> = None;
            for n in &nodes {
                if let Ok(guests) = client.get_guests(&n.node).await {
                    if let Some(g) = guests.iter().find(|g| g.vmid == vmid) {
                        found = Some((n.node.clone(), g.guest_type));
                        break;
                    }
                }
            }
            found.ok_or_else(|| {
                anyhow::anyhow!(
                    "vmid {vmid} not found on any node — pass --node X to skip discovery"
                )
            })?
        }
    };

    let ticket = client.get_guest_vncproxy(&node_name, vmid, gt).await?;
    let mut out = serde_json::to_value(&ticket)?;
    if ws_url {
        let url = client
            .build_guest_vncwebsocket_url(&node_name, vmid, gt, &ticket)
            .await?;
        if let Some(obj) = out.as_object_mut() {
            obj.insert("ws_url".into(), serde_json::Value::String(url));
        }
    }
    Ok((out, 0))
}

/// Mountain #1 — storage health surface.
///
/// All five subcommands are pure read-through to the corresponding
/// PVE endpoint; the CLI emits the typed response as JSON. The TUI
/// integration (renderer + sparklines) is a separate iteration —
/// here we land the data layer + CLI access first.
///
/// Exit code is always 0 on a successful API call (even an empty
/// pool list). A non-success status from PVE bubbles up through
/// `ApiError`, which the top-level `main` maps to its standard
/// non-zero exit category (1 fatal, 4 forbidden, …).
async fn execute_disks(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: DisksCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        DisksCommand::List { node } => {
            let disks = client.list_node_disks(&node).await?;
            Ok((serde_json::to_value(disks)?, 0))
        }
        DisksCommand::Smart { node, disk } => {
            let smart = client.get_disk_smart(&node, &disk).await?;
            Ok((serde_json::to_value(smart)?, 0))
        }
        DisksCommand::Lvm { node } => {
            let vgs = client.list_node_lvm(&node).await?;
            Ok((serde_json::to_value(vgs)?, 0))
        }
        DisksCommand::Lvmthin { node } => {
            let pools = client.list_node_lvmthin(&node).await?;
            Ok((serde_json::to_value(pools)?, 0))
        }
        DisksCommand::Zfs { node } => {
            let pools = client.list_node_zfs(&node).await?;
            Ok((serde_json::to_value(pools)?, 0))
        }
    }
}

async fn execute_hw(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: HwCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        HwCommand::Pci { node } => {
            let pci = client.list_pci(&node).await?;
            Ok((serde_json::to_value(pci)?, 0))
        }
        HwCommand::Usb { node } => {
            let usb = client.list_usb(&node).await?;
            Ok((serde_json::to_value(usb)?, 0))
        }
        HwCommand::Conflicts { node } => {
            // Pull devices + every guest's config; run the pure-logic
            // detector. Exit code reflects "any conflicts found".
            let pci = client.list_pci(&node).await?;
            let nodes = client.get_nodes().await?;
            let mut configs: std::collections::HashMap<
                u32,
                std::collections::HashMap<String, String>,
            > = std::collections::HashMap::new();
            for n in &nodes {
                if let Ok(guests) = client.get_guests(&n.node).await {
                    for g in guests {
                        if let Ok(cfg) = client
                            .get_guest_config(&g.node, g.vmid, &g.guest_type)
                            .await
                        {
                            configs.insert(g.vmid, cfg);
                        }
                    }
                }
            }
            let (assignments, _) = crate::app::hw::scan_assignments(&configs);
            let conflicts = crate::app::hw::detect_pci_conflicts(&assignments, &pci);

            // Serialize to JSON: tag-distinguished variants.
            let serialized: Vec<serde_json::Value> = conflicts
                .iter()
                .map(|c| match c {
                    crate::app::hw::PciConflict::DirectShared { address, vmids } => {
                        serde_json::json!({
                            "kind": "direct_shared",
                            "address": address,
                            "vmids": vmids
                        })
                    }
                    crate::app::hw::PciConflict::IommuGroupSplit { group, members } => {
                        serde_json::json!({
                            "kind": "iommu_group_split",
                            "group": group,
                            "members": members
                                .iter()
                                .map(|(a, v)| serde_json::json!({ "address": a, "vmid": v }))
                                .collect::<Vec<_>>()
                        })
                    }
                })
                .collect();
            let exit = i32::from(!conflicts.is_empty());
            Ok((
                serde_json::json!({
                    "node": node,
                    "conflicts": serialized,
                    "count": conflicts.len()
                }),
                exit,
            ))
        }
    }
}

/// Feature #5 — HA console CLI.
async fn execute_ha(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: HaCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        HaCommand::Groups => {
            let groups = client.list_ha_groups().await?;
            Ok((serde_json::to_value(groups)?, 0))
        }
        HaCommand::GroupsLegacy => {
            let groups = client.list_ha_groups_legacy().await?;
            Ok((serde_json::to_value(groups)?, 0))
        }
        HaCommand::GroupCreate {
            group,
            nodes,
            restricted,
            nofailback,
            comment,
        } => {
            let restricted_str = if restricted { "1" } else { "0" };
            let nofailback_str = if nofailback { "1" } else { "0" };
            let mut params: Vec<(&str, &str)> = vec![
                ("group", group.as_str()),
                ("nodes", nodes.as_str()),
                ("restricted", restricted_str),
                ("nofailback", nofailback_str),
            ];
            if let Some(c) = comment.as_deref() {
                params.push(("comment", c));
            }
            client.create_ha_group(&params).await?;
            Ok((serde_json::json!({"created": group}), 0))
        }
        HaCommand::GroupUpdate {
            group,
            nodes,
            restricted,
            nofailback,
            comment,
        } => {
            let mut owned: Vec<(&str, String)> = vec![];
            if let Some(n) = nodes {
                owned.push(("nodes", n));
            }
            if let Some(r) = restricted {
                owned.push(("restricted", if r { "1" } else { "0" }.to_string()));
            }
            if let Some(n) = nofailback {
                owned.push(("nofailback", if n { "1" } else { "0" }.to_string()));
            }
            if let Some(c) = comment {
                owned.push(("comment", c));
            }
            if owned.is_empty() {
                anyhow::bail!("update needs at least one field");
            }
            let refs: Vec<(&str, &str)> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
            client.update_ha_group(&group, &refs).await?;
            Ok((serde_json::json!({"updated": group}), 0))
        }
        HaCommand::GroupDelete { group, yes } => {
            if !yes {
                anyhow::bail!("destructive — pass --yes to confirm");
            }
            client.delete_ha_group(&group).await?;
            Ok((serde_json::json!({"deleted": group}), 0))
        }
        HaCommand::Resources => {
            let resources = client.list_ha_resources().await?;
            Ok((serde_json::to_value(resources)?, 0))
        }
        HaCommand::Status => {
            let status = client.ha_manager_status().await?;
            Ok((serde_json::to_value(status)?, 0))
        }
        HaCommand::StatusCurrent => {
            let entries = client.get_ha_status_current().await?;
            Ok((
                serde_json::json!({"count": entries.len(), "entries": entries}),
                0,
            ))
        }
        HaCommand::Preview { node } => {
            // Bring everything we need locally and run the inspector.
            let groups = client.list_ha_groups().await?;
            let resources = client.list_ha_resources().await?;
            let cluster = client.cluster_status().await?;
            let online = crate::app::ha::online_nodes(&cluster);
            // To know each resource's CURRENT node, we look at all guests.
            let nodes = client.get_nodes().await?;
            let mut all_guests: std::collections::HashMap<u32, String> =
                std::collections::HashMap::new();
            for n in &nodes {
                if let Ok(guests) = client.get_guests(&n.node).await {
                    for g in guests {
                        all_guests.insert(g.vmid, g.node);
                    }
                }
            }
            let mut previews = Vec::new();
            for r in &resources {
                let cur = r
                    .vmid()
                    .and_then(|v| all_guests.get(&v).cloned())
                    .unwrap_or_default();
                let outcome = if cur.is_empty() {
                    serde_json::json!({ "kind": "unknown_current_node" })
                } else {
                    match crate::app::ha::preview_failover(r, &groups, &online, &cur, &node) {
                        crate::app::ha::FailoverPreview::Relocate { target, priority } => {
                            serde_json::json!({
                                "kind": "relocate",
                                "target": target,
                                "priority": priority
                            })
                        }
                        crate::app::ha::FailoverPreview::Stuck { restricted, chosen } => {
                            serde_json::json!({
                                "kind": "stuck",
                                "restricted": restricted,
                                "chosen": chosen
                            })
                        }
                        crate::app::ha::FailoverPreview::NotAffected => {
                            serde_json::json!({ "kind": "not_affected" })
                        }
                    }
                };
                previews.push(serde_json::json!({
                    "sid": r.sid,
                    "group": r.group,
                    "current_node": cur,
                    "outcome": outcome,
                }));
            }
            Ok((
                serde_json::json!({
                    "failed_node": node,
                    "previews": previews
                }),
                0,
            ))
        }
    }
}

async fn execute_replication(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: ReplicationCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        ReplicationCommand::Jobs => {
            let jobs = client.list_replication_jobs().await?;
            Ok((serde_json::to_value(jobs)?, 0))
        }
        ReplicationCommand::Status { node } => {
            let status = client.list_replication_status(&node).await?;
            Ok((serde_json::to_value(status)?, 0))
        }
    }
}

/// Feature #3 CLI dispatch. PBS lives in its own profile block; we don't
/// reuse the Proxmox API client. If `[profiles.X.pbs]` is missing, every
/// subcommand fails fast with a clear "configure PBS" message.
async fn execute_pbs(
    config: &crate::config::ProfileConfig,
    action: PbsCommand,
    cli_secret: Option<&str>,
) -> Result<(Value, i32)> {
    use crate::pbs::{PbsClient, PbsGateway};

    let pbs_cfg = config.pbs.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "no [profiles.X.pbs] block configured — add url, user, token_id, token_secret(_file)"
        )
    })?;

    match action {
        PbsCommand::Datastores => {
            let client = PbsClient::new(pbs_cfg, cli_secret).await?;
            let stores = client.list_datastores().await?;
            Ok((serde_json::to_value(stores)?, 0))
        }
        PbsCommand::Snapshots {
            store,
            backup_type,
            backup_id,
        } => {
            let client = PbsClient::new(pbs_cfg, cli_secret).await?;
            let snaps = client
                .list_snapshots(&store, backup_type.as_deref(), backup_id.as_deref())
                .await?;
            Ok((serde_json::to_value(snaps)?, 0))
        }
        PbsCommand::Files {
            store,
            backup_type,
            backup_id,
            backup_time,
        } => {
            let client = PbsClient::new(pbs_cfg, cli_secret).await?;
            let files = client
                .list_snapshot_files(&store, &backup_type, &backup_id, backup_time)
                .await?;
            Ok((serde_json::to_value(files)?, 0))
        }
        PbsCommand::Restore {
            store,
            snapshot,
            archive,
            target,
            yes,
        } => {
            if !yes {
                anyhow::bail!("`pbs restore` writes to the local filesystem — re-run with --yes");
            }
            crate::pbs::restore::validate_target(&target)?;
            // Pre-flight: surface a clean error if the binary is missing
            // before we start streaming.
            if crate::pbs::detect_client_binary().is_none() {
                anyhow::bail!(
                    "proxmox-backup-client not found. Install the PBS client \
                     (apt install proxmox-backup-client on Debian/Ubuntu/PVE). \
                     Note: macOS / Windows clients aren't available upstream."
                );
            }
            let req = crate::pbs::RestoreRequest {
                snapshot: snapshot.clone(),
                archive: archive.clone(),
                target: target.clone(),
                store: store.clone(),
            };
            let mut tail: Vec<String> = Vec::new();
            let result = crate::pbs::run_restore(&pbs_cfg, cli_secret, req, |line| {
                tail.push(line.to_string());
                if tail.len() > 50 {
                    tail.drain(..tail.len() - 50);
                }
            })
            .await?;

            let exit = i32::from(result.exit_code != Some(0));
            Ok((
                serde_json::json!({
                    "store": store,
                    "snapshot": snapshot,
                    "archive": archive,
                    "target": target,
                    "exit_code": result.exit_code,
                    "last_lines": result.last_lines,
                    "status": if exit == 0 { "ok" } else { "error" },
                }),
                exit,
            ))
        }
    }
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

/// Feature #2 CLI dispatch.
async fn execute_iso(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: IsoCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    use crate::app::iso_library;

    match action {
        IsoCommand::List => {
            let entries: Vec<serde_json::Value> = iso_library::LIBRARY
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "id": e.id,
                        "distro": e.distro,
                        "version": e.version,
                        "arch": e.arch,
                        "url": e.url,
                        // `checksum` is { "algo": "sha256"|"sha512", "digest": "..." }
                        // when pinned, or `null` when not (schema).
                        "checksum": e.checksum,
                        "content": e.content,
                        "size_mib": e.size_mib,
                        "notes": e.notes,
                    })
                })
                .collect();
            Ok((serde_json::Value::Array(entries), 0))
        }
        IsoCommand::Download {
            id,
            url,
            filename,
            sha256,
            content,
            node,
            storage,
        } => {
            // Resolve either a library entry or a custom URL+filename+content.
            // We refuse ambiguous combinations loudly — pipelines should
            // know exactly what they asked for.
            //
            // `final_checksum` is `(algo, hex)` so curated entries that
            // ship SHA-512 (Debian) flow through unchanged.
            let (final_url, final_filename, final_checksum, final_content): (
                String,
                String,
                Option<(String, String)>,
                String,
            ) = match (id, url) {
                (Some(_), Some(_)) => {
                    anyhow::bail!("specify either --id or --url, not both");
                }
                (Some(entry_id), None) => {
                    let entry = iso_library::by_id(&entry_id)
                        .ok_or_else(|| anyhow::anyhow!("library id '{entry_id}' not found"))?;
                    // refuse-on-unpinned-checksum gate: curated entry must be pinned.
                    let checksum = entry.checksum.ok_or_else(|| {
                        anyhow::anyhow!(
                            "library entry '{entry_id}' has no pinned checksum. \
                             Use --url <X> --sha256 <Y> to download with caller-supplied checksum."
                        )
                    })?;
                    let (algo, hex) = checksum.proxmox_pair();
                    let derived_filename = entry
                        .url
                        .rsplit('/')
                        .next()
                        .unwrap_or("download.img")
                        .to_string();
                    (
                        entry.url.to_string(),
                        derived_filename,
                        Some((algo.to_string(), hex.to_string())),
                        entry.content.to_string(),
                    )
                }
                (None, Some(custom_url)) => {
                    let fname =
                        filename.ok_or_else(|| anyhow::anyhow!("--url requires --filename"))?;
                    let cnt = content.ok_or_else(|| {
                        anyhow::anyhow!("--url requires --content (iso|import|vztmpl)")
                    })?;
                    let cs = sha256.map(|h| ("sha256".to_string(), h));
                    (custom_url, fname, cs, cnt)
                }
                (None, None) => {
                    anyhow::bail!("specify --id <entry> or --url <custom-url>");
                }
            };

            let (algo, hex): (Option<&str>, Option<&str>) = match final_checksum.as_ref() {
                Some((a, h)) => (Some(a.as_str()), Some(h.as_str())),
                None => (None, None),
            };
            let upid = client
                .download_to_storage(
                    &node,
                    &storage,
                    &final_url,
                    &final_filename,
                    algo,
                    hex,
                    &final_content,
                )
                .await?;

            Ok((
                serde_json::json!({
                    "node": node,
                    "storage": storage,
                    "url": final_url,
                    "filename": final_filename,
                    "checksum": final_checksum,
                    "content": final_content,
                    "upid": upid,
                    "status": "queued"
                }),
                0,
            ))
        }
    }
}

/// Feature #6 CLI dispatch.
///
/// Note: the CLI takes the direct API path (no queue), unlike the TUI.
/// We hard-require `--yes` per op so non-interactive scripts can't
/// accidentally trash storage by piping stale arguments.
/// Locate which node owns a given VMID and which guest type it is.
/// Walks `get_nodes()` then `get_guests(node)` per node — O(N nodes)
/// network calls. Used by every per-vmid command (migrate, exec, config,
/// disk, …) that the user invokes by VMID alone, without specifying
/// the node.
async fn find_guest(
    client: &crate::api::PxClient,
    vmid: u32,
) -> Result<(String, crate::api::types::GuestType)> {
    use crate::api::ProxmoxGateway;
    let nodes = client.get_nodes().await?;
    for n in nodes {
        if let Ok(guests) = client.get_guests(&n.node).await {
            if let Some(g) = guests.iter().find(|g| g.vmid == vmid) {
                return Ok((n.node.clone(), g.guest_type));
            }
        }
    }
    anyhow::bail!("Guest {vmid} not found")
}

/// Same scan as `find_guest`, but returns the full `Guest` so the
/// caller can run pre-flight risk assessment (lock, HA state, uptime,
/// tags, traffic) without a second round-trip.
async fn find_guest_full(
    client: &crate::api::PxClient,
    vmid: u32,
) -> Result<crate::api::types::Guest> {
    use crate::api::ProxmoxGateway;
    let nodes = client.get_nodes().await?;
    for n in nodes {
        if let Ok(guests) = client.get_guests(&n.node).await {
            if let Some(g) = guests.iter().find(|g| g.vmid == vmid) {
                return Ok(g.clone());
            }
        }
    }
    anyhow::bail!("Guest {vmid} not found")
}

/// Poll a long-running PVE task to completion. Used by `--wait` on
/// async ops (migrate, clone, disk move, backup, template). Returns
/// the final `TaskStatus` once `is_done()`, or bails on timeout.
///
/// `interval` defaults to 1.5s — fast enough that a 10-second backup
/// returns within ~12s, slow enough that a 5-minute disk migrate
/// only generates ~200 polls. `timeout_secs = 0` means "no timeout"
/// (poll forever).
async fn poll_task_until_done(
    client: &crate::api::PxClient,
    node: &str,
    upid: &str,
    timeout_secs: u64,
) -> Result<crate::api::types::TaskStatus> {
    use crate::api::ProxmoxGateway;
    use std::time::Duration;
    let interval = Duration::from_millis(1500);
    let deadline = if timeout_secs > 0 {
        Some(tokio::time::Instant::now() + Duration::from_secs(timeout_secs))
    } else {
        None
    };
    loop {
        let status = client.get_task_status(node, upid).await?;
        if status.is_done() {
            return Ok(status);
        }
        if let Some(d) = deadline {
            if tokio::time::Instant::now() >= d {
                anyhow::bail!(
                    "task {upid} did not complete within {timeout_secs}s (status: {})",
                    status.status
                );
            }
        }
        tokio::time::sleep(interval).await;
    }
}

/// Wait for a task and turn its outcome into a CLI exit code:
///   - PVE exitstatus == "OK" → exit 0, `task_status` field surfaces details.
///   - Anything else → exit 1, error message includes PVE's last log.
/// Returns the JSON envelope to embed in the response, the exit code,
/// and a flag indicating whether the wait was actually performed.
async fn wait_and_classify(
    client: &crate::api::PxClient,
    node: &str,
    upid: &str,
) -> Result<(serde_json::Value, i32)> {
    let status = poll_task_until_done(client, node, upid, 0).await?;
    let exit = i32::from(!status.is_success());
    Ok((serde_json::to_value(status)?, exit))
}

/// Run pre-flight risk assessment and either bail (on Severe risk
/// without `--force`) or print and proceed. Returns `Ok(())` if the
/// op should proceed, `Err` if we refuse.
///
/// Uses `assess_deep` to also include I/O-based risks (listening
/// ports via QGA). Falls back gracefully if QGA isn't available —
/// the caller still sees the cheap risks.
async fn enforce_preflight(
    client: &crate::api::PxClient,
    pbs: Option<&crate::pbs::PbsClient>,
    op: crate::app::preflight::Op,
    guest: &crate::api::types::Guest,
    force: bool,
) -> Result<()> {
    use crate::app::preflight::{assess_deep, max_level, RiskLevel};
    let risks = assess_deep(client, pbs, op, guest).await;
    if risks.is_empty() {
        return Ok(());
    }
    eprintln!(
        "PRE-FLIGHT for {} vmid={} ({}@{}):",
        op.as_str(),
        guest.vmid,
        guest.name,
        guest.node
    );
    for (risk, level) in &risks {
        eprintln!("  [{}] {}", level.as_str(), risk.describe());
    }
    let max = max_level(&risks);
    if max == RiskLevel::Severe && !force {
        anyhow::bail!(
            "refusing destructive op due to SEVERE pre-flight risk(s) above. \
             Re-run with --allow-risk to override (you own the consequence)."
        );
    }
    if max == RiskLevel::Severe && force {
        eprintln!("  --allow-risk passed; overriding SEVERE risk(s) and proceeding.");
    }
    Ok(())
}

/// Parse `key=value` positional args from `vm raw-set` / `ct raw-set`
/// into the `(String, String)` pairs `update_guest_config` expects.
/// Splits on the FIRST `=` so values like `bridge=vmbr0,firewall=1`
/// (which themselves contain `=`) survive intact.
fn parse_kv_pairs(kvs: &[String]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::with_capacity(kvs.len());
    for kv in kvs {
        let (k, v) = kv.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("raw-set arg '{kv}' missing '=' separator (use `key=value`)")
        })?;
        if k.is_empty() {
            anyhow::bail!("raw-set arg '{kv}' has empty key");
        }
        out.push((k.to_string(), v.to_string()));
    }
    Ok(out)
}

/// Refuse to issue a config-update with no parameters — PVE accepts
/// it as a no-op but the user almost certainly typed something wrong.
/// Catches `proxxx vm set 100` (no flags) at the boundary.
fn require_non_empty_params(params: &[(String, String)]) -> Result<()> {
    if params.is_empty() {
        anyhow::bail!("no config keys passed — pass at least one --flag or use `raw-set`")
    }
    Ok(())
}

/// After `update_guest_config`, classify which of the requested keys
/// took effect immediately (hot-plug or guest stopped) versus which
/// queued as pending until the next reboot. Calls `/pending` and
/// intersects with our submitted keys.
///
/// On error (endpoint unsupported, transient network), returns
/// (`requested.clone()`, []) and an `Option<Err>` the caller can
/// surface as a warning — degrading gracefully rather than failing
/// the whole operation after the update has already landed.
async fn classify_pending(
    client: &crate::api::PxClient,
    node: &str,
    vmid: u32,
    gt: crate::api::types::GuestType,
    requested: &[String],
) -> (Vec<String>, Vec<String>, Option<String>) {
    use crate::api::ProxmoxGateway;
    use std::collections::HashSet;
    let pending_resp = match client.list_pending_config(node, vmid, gt).await {
        Ok(p) => p,
        Err(e) => return (requested.to_vec(), Vec::new(), Some(e.to_string())),
    };
    let pending_keys: HashSet<&str> = pending_resp
        .iter()
        .filter(|e| e.pending.is_some() || e.delete.is_some())
        .map(|e| e.key.as_str())
        .collect();
    let mut applied_now = Vec::new();
    let mut pending_reboot = Vec::new();
    for k in requested {
        if pending_keys.contains(k.as_str()) {
            pending_reboot.push(k.clone());
        } else {
            applied_now.push(k.clone());
        }
    }
    (applied_now, pending_reboot, None)
}

async fn execute_vm(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: VmCommand,
) -> Result<(Value, i32)> {
    use crate::api::types::GuestType;
    use crate::api::ProxmoxGateway;
    match action {
        VmCommand::Set {
            vmid,
            cores,
            sockets,
            memory,
            balloon,
            cpu,
            name,
            description,
            ostype,
        } => {
            // Build params BEFORE the network round-trip so empty
            // invocations (`proxxx vm set 100`) fail fast with the
            // right diagnostic, not "Guest not found" after a useless
            // cluster scan.
            let mut params: Vec<(String, String)> = Vec::new();
            if let Some(v) = cores {
                params.push(("cores".into(), v.to_string()));
            }
            if let Some(v) = sockets {
                params.push(("sockets".into(), v.to_string()));
            }
            if let Some(v) = memory {
                params.push(("memory".into(), v.to_string()));
            }
            if let Some(v) = balloon {
                params.push(("balloon".into(), v.to_string()));
            }
            if let Some(v) = cpu {
                params.push(("cpu".into(), v));
            }
            if let Some(v) = name {
                params.push(("name".into(), v));
            }
            if let Some(v) = description {
                params.push(("description".into(), v));
            }
            if let Some(v) = ostype {
                params.push(("ostype".into(), v));
            }
            require_non_empty_params(&params)?;
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, GuestType::Qemu) {
                anyhow::bail!("VMID {vmid} is an LXC container — use `proxxx ct set` instead");
            }
            let task = client.update_guest_config(&node, vmid, gt, &params).await?;
            let requested: Vec<String> = params.iter().map(|(k, _)| k.clone()).collect();
            let (applied_now, pending_reboot, classify_warn) =
                classify_pending(client, &node, vmid, gt, &requested).await;
            Ok((
                serde_json::json!({
                    "vmid": vmid,
                    "node": node,
                    "requested": requested,
                    "applied_immediately": applied_now,
                    "pending_reboot": pending_reboot,
                    "classify_warning": classify_warn,
                    "task": task,
                }),
                0,
            ))
        }
        VmCommand::RawSet { vmid, kvs } => {
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, GuestType::Qemu) {
                anyhow::bail!("VMID {vmid} is an LXC container — use `proxxx ct raw-set` instead");
            }
            let params = parse_kv_pairs(&kvs)?;
            let task = client.update_guest_config(&node, vmid, gt, &params).await?;
            let requested: Vec<String> = params.iter().map(|(k, _)| k.clone()).collect();
            let (applied_now, pending_reboot, classify_warn) =
                classify_pending(client, &node, vmid, gt, &requested).await;
            Ok((
                serde_json::json!({
                    "vmid": vmid,
                    "node": node,
                    "requested": requested,
                    "applied_immediately": applied_now,
                    "pending_reboot": pending_reboot,
                    "classify_warning": classify_warn,
                    "raw": true,
                    "task": task,
                }),
                0,
            ))
        }
        VmCommand::Cloudinit { action } => execute_cloudinit(client, action).await,
        VmCommand::Sendkey { vmid, key } => {
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, crate::api::types::GuestType::Qemu) {
                anyhow::bail!("sendkey is QEMU-only — vmid {vmid} is an LXC");
            }
            client.send_qemu_key(&node, vmid, &key).await?;
            Ok((
                serde_json::json!({"vmid": vmid, "node": node, "key": key, "sent": true}),
                0,
            ))
        }
        VmCommand::Unlink {
            vmid,
            idlist,
            force,
            yes,
        } => {
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, crate::api::types::GuestType::Qemu) {
                anyhow::bail!("unlink is QEMU-only — vmid {vmid} is an LXC");
            }
            if force && !yes {
                anyhow::bail!("--force deletes the underlying volume — pass --yes to confirm");
            }
            client.unlink_qemu_disk(&node, vmid, &idlist, force).await?;
            Ok((
                serde_json::json!({
                    "vmid": vmid, "node": node, "idlist": idlist,
                    "deleted_volume": force,
                }),
                0,
            ))
        }
        VmCommand::CloudinitDump { vmid, kind } => {
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, crate::api::types::GuestType::Qemu) {
                anyhow::bail!("cloudinit-dump is QEMU-only — vmid {vmid} is an LXC");
            }
            let content = client.dump_qemu_cloudinit(&node, vmid, &kind).await?;
            Ok((
                serde_json::json!({
                    "vmid": vmid, "node": node, "kind": kind,
                    "bytes": content.len(), "content": content,
                }),
                0,
            ))
        }
    }
}

async fn execute_cloudinit(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: CloudinitCommand,
) -> Result<(Value, i32)> {
    use crate::api::types::GuestType;
    use crate::api::ProxmoxGateway;
    match action {
        CloudinitCommand::Set {
            vmid,
            ciuser,
            cipassword,
            sshkey,
            ipconfig0,
            searchdomain,
            nameserver,
        } => {
            // Build params first, fail fast on empty before the cluster scan.
            let mut params: Vec<(String, String)> = Vec::new();
            if let Some(v) = ciuser {
                params.push(("ciuser".into(), v));
            }
            if let Some(v) = cipassword {
                params.push(("cipassword".into(), v));
            }
            if let Some(v) = sshkey {
                // PVE expects URL-encoded SSH keys in `sshkeys`. The
                // raw newline-separated form must survive the form
                // serialization — reqwest handles URL-encoding for
                // form bodies, so we pass the raw key here.
                params.push(("sshkeys".into(), v));
            }
            if let Some(v) = ipconfig0 {
                // Parse-time validation via the typed `Ipconfig`
                // struct — a malformed value like
                //   --ipconfig0 "ip=10.0.0.5,brokenkeynoeq,gw=10.0.0.1"
                // is rejected here with a precise error instead of
                // surviving until PVE returns a generic 400.
                // Round-trip through Display normalises spacing.
                use std::str::FromStr;
                let parsed = crate::api::types::Ipconfig::from_str(&v)?;
                params.push(("ipconfig0".into(), parsed.to_string()));
            }
            if let Some(v) = searchdomain {
                params.push(("searchdomain".into(), v));
            }
            if let Some(v) = nameserver {
                params.push(("nameserver".into(), v));
            }
            require_non_empty_params(&params)?;
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, GuestType::Qemu) {
                anyhow::bail!("cloud-init is QEMU-only — VMID {vmid} is an LXC container");
            }
            let task = client.update_guest_config(&node, vmid, gt, &params).await?;
            let requested: Vec<String> = params.iter().map(|(k, _)| k.clone()).collect();
            let (applied_now, pending_reboot, classify_warn) =
                classify_pending(client, &node, vmid, gt, &requested).await;
            Ok((
                serde_json::json!({
                    "vmid": vmid,
                    "node": node,
                    "requested": requested,
                    "applied_immediately": applied_now,
                    "pending_reboot": pending_reboot,
                    "classify_warning": classify_warn,
                    "next_step": "run `proxxx vm cloudinit regen <vmid>` to rebuild the cloud-init drive",
                    "task": task,
                }),
                0,
            ))
        }
        CloudinitCommand::Regen { vmid } => {
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, GuestType::Qemu) {
                anyhow::bail!("cloud-init is QEMU-only — VMID {vmid} is an LXC container");
            }
            let task = client.regenerate_cloudinit(&node, vmid).await?;
            Ok((
                serde_json::json!({
                    "vmid": vmid,
                    "node": node,
                    "task": task,
                }),
                0,
            ))
        }
    }
}

async fn execute_storage(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: StorageCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        StorageCommand::Upload {
            node,
            storage,
            local_path,
            content,
            remote_filename,
            wait,
        } => {
            // Validate content bucket at the CLI boundary so the user
            // gets a clear error rather than PVE's generic schema 400.
            let valid = ["iso", "vztmpl", "import"];
            if !valid.contains(&content.as_str()) {
                anyhow::bail!(
                    "invalid content type '{content}'; valid: {}",
                    valid.join(", ")
                );
            }
            let upid = client
                .upload_to_storage(
                    &node,
                    &storage,
                    &local_path,
                    &content,
                    remote_filename.as_deref(),
                )
                .await?;
            let envelope = serde_json::json!({
                "node": node,
                "storage": storage,
                "filename": remote_filename
                    .clone()
                    .or_else(|| {
                        local_path.file_name()
                            .and_then(|s| s.to_str())
                            .map(std::string::ToString::to_string)
                    }),
                "content": content,
                "task": upid,
            });
            if wait {
                let (status_json, exit) = wait_and_classify(client, &node, &upid).await?;
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
        StorageCommand::Delete {
            node,
            volid,
            yes,
            wait,
        } => {
            if !yes {
                anyhow::bail!("storage delete is destructive — re-run with --yes");
            }
            // Volid form: `<storage>:<type>/<file>`. Extract the
            // storage portion to feed into the URL path. PVE wants
            // BOTH the storage name in the URL AND the full volid
            // (which redundantly includes the storage prefix).
            let storage = volid
                .split_once(':')
                .ok_or_else(|| {
                    anyhow::anyhow!("invalid volid '{volid}': expected '<storage>:<type>/<file>'")
                })?
                .0;
            let task = client
                .delete_storage_content(&node, storage, &volid)
                .await?;
            let envelope = serde_json::json!({
                "node": node,
                "storage": storage,
                "volid": volid,
                "task": task,
            });
            // Some storage backends return None (instant delete).
            // For those, --wait is a no-op (nothing to poll).
            if let (true, Some(upid)) = (wait, task.as_deref()) {
                let (status_json, exit) = wait_and_classify(client, &node, upid).await?;
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
    }
}

async fn execute_firewall(
    client: &std::sync::Arc<crate::api::PxClient>,
    scope: FirewallScope,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    let (rules, scope_label) = match scope {
        FirewallScope::Cluster => {
            let rules = client.list_cluster_firewall_rules().await?;
            (rules, serde_json::json!({"scope": "cluster"}))
        }
        FirewallScope::Node { node } => {
            let rules = client.list_node_firewall_rules(&node).await?;
            (rules, serde_json::json!({"scope": "node", "node": node}))
        }
        FirewallScope::Guest { vmid } => {
            let (node, gt) = find_guest(client, vmid).await?;
            let rules = client.list_guest_firewall_rules(&node, vmid, gt).await?;
            (
                rules,
                serde_json::json!({
                    "scope": "guest",
                    "node": node,
                    "vmid": vmid,
                    "guest_type": format!("{gt:?}").to_lowercase(),
                }),
            )
        }
    };
    Ok((
        serde_json::json!({
            "context": scope_label,
            "rules": rules,
            "count": rules.len(),
        }),
        0,
    ))
}

async fn execute_ct(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: CtCommand,
) -> Result<(Value, i32)> {
    use crate::api::types::GuestType;
    use crate::api::ProxmoxGateway;
    match action {
        CtCommand::Set {
            vmid,
            cores,
            memory,
            swap,
            hostname,
            description,
        } => {
            // Build params first, fail fast on empty before the cluster scan.
            let mut params: Vec<(String, String)> = Vec::new();
            if let Some(v) = cores {
                params.push(("cores".into(), v.to_string()));
            }
            if let Some(v) = memory {
                params.push(("memory".into(), v.to_string()));
            }
            if let Some(v) = swap {
                params.push(("swap".into(), v.to_string()));
            }
            if let Some(v) = hostname {
                params.push(("hostname".into(), v));
            }
            if let Some(v) = description {
                params.push(("description".into(), v));
            }
            require_non_empty_params(&params)?;
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, GuestType::Lxc) {
                anyhow::bail!("VMID {vmid} is a QEMU VM — use `proxxx vm set` instead");
            }
            let task = client.update_guest_config(&node, vmid, gt, &params).await?;
            let requested: Vec<String> = params.iter().map(|(k, _)| k.clone()).collect();
            let (applied_now, pending_reboot, classify_warn) =
                classify_pending(client, &node, vmid, gt, &requested).await;
            Ok((
                serde_json::json!({
                    "vmid": vmid,
                    "node": node,
                    "requested": requested,
                    "applied_immediately": applied_now,
                    "pending_reboot": pending_reboot,
                    "classify_warning": classify_warn,
                    "task": task,
                }),
                0,
            ))
        }
        CtCommand::RawSet { vmid, kvs } => {
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, GuestType::Lxc) {
                anyhow::bail!("VMID {vmid} is a QEMU VM — use `proxxx vm raw-set` instead");
            }
            let params = parse_kv_pairs(&kvs)?;
            let task = client.update_guest_config(&node, vmid, gt, &params).await?;
            let requested: Vec<String> = params.iter().map(|(k, _)| k.clone()).collect();
            let (applied_now, pending_reboot, classify_warn) =
                classify_pending(client, &node, vmid, gt, &requested).await;
            Ok((
                serde_json::json!({
                    "vmid": vmid,
                    "node": node,
                    "requested": requested,
                    "applied_immediately": applied_now,
                    "pending_reboot": pending_reboot,
                    "classify_warning": classify_warn,
                    "raw": true,
                    "task": task,
                }),
                0,
            ))
        }
        CtCommand::Interfaces { vmid } => {
            let (node, gt) = find_guest(client, vmid).await?;
            if !matches!(gt, GuestType::Lxc) {
                anyhow::bail!("interfaces is LXC-only — vmid {vmid} is a QEMU VM (use `proxxx qga {vmid} net` instead)");
            }
            let ifaces = client.list_lxc_interfaces(&node, vmid).await?;
            Ok((
                serde_json::json!({"vmid": vmid, "node": node, "interfaces": ifaces}),
                0,
            ))
        }
    }
}

async fn execute_disk(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: DiskCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    match action {
        DiskCommand::Move {
            vmid,
            disk,
            storage,
            delete_source,
            yes,
            allow_risk,
            wait,
        } => {
            if !yes {
                anyhow::bail!("disk move is destructive — re-run with --yes");
            }
            // GAP 1 fix: pre-flight read of `lock` (and other risks)
            // catches a concurrent move/clone/backup before we eat a
            // 30-second PVE timeout. The lock check is zero extra
            // I/O — `find_guest_full` already round-trips guest list.
            let g = find_guest_full(client, vmid).await?;
            enforce_preflight(
                client,
                None,
                crate::app::preflight::Op::MoveDisk,
                &g,
                allow_risk,
            )
            .await?;
            let upid = client
                .move_disk(&g.node, vmid, g.guest_type, &disk, &storage, delete_source)
                .await?;
            let envelope = serde_json::json!({
                "vmid": vmid,
                "disk": disk,
                "target_storage": storage,
                "delete_source": delete_source,
                "node": g.node,
                "upid": upid,
                "status": "queued"
            });
            if wait {
                let (status_json, exit) = wait_and_classify(client, &g.node, &upid).await?;
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
        DiskCommand::Resize {
            vmid,
            disk,
            size,
            yes,
            allow_risk,
        } => {
            if !yes {
                anyhow::bail!("disk resize is destructive — re-run with --yes");
            }
            let g = find_guest_full(client, vmid).await?;
            enforce_preflight(
                client,
                None,
                crate::app::preflight::Op::ResizeDisk,
                &g,
                allow_risk,
            )
            .await?;
            let upid = client
                .resize_disk(&g.node, vmid, g.guest_type, &disk, &size)
                .await?;
            Ok((
                serde_json::json!({
                    "vmid": vmid,
                    "disk": disk,
                    "size": size,
                    "node": g.node,
                    "upid": upid,
                    "status": "queued"
                }),
                0,
            ))
        }
    }
}

/// Bug #3 fix: implement `proxxx snapshot create/delete` (was stub).
async fn execute_snapshot(
    client: &std::sync::Arc<crate::api::PxClient>,
    action: SnapshotCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    let (vmid, name, is_create) = match action {
        SnapshotCommand::Create { vmid, name } => (vmid, name, true),
        SnapshotCommand::Delete { vmid, name } => (vmid, name, false),
    };

    // Locate the guest to get its node + type (bug #1 dispatch).
    let nodes = client.get_nodes().await?;
    let mut found: Option<(String, crate::api::types::GuestType)> = None;
    for n in nodes {
        if let Ok(guests) = client.get_guests(&n.node).await {
            if let Some(g) = guests.iter().find(|g| g.vmid == vmid) {
                found = Some((n.node.clone(), g.guest_type));
                break;
            }
        }
    }
    let (node, gt) = found.ok_or_else(|| anyhow::anyhow!("Guest {vmid} not found"))?;

    let upid = if is_create {
        client.create_snapshot(&node, vmid, gt, &name).await?
    } else {
        client.delete_snapshot(&node, vmid, gt, &name).await?
    };

    Ok((
        serde_json::json!({
            "vmid": vmid,
            "snapshot": name,
            "action": if is_create { "create" } else { "delete" },
            "node": node,
            "upid": upid,
            "status": "success"
        }),
        0,
    ))
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

async fn execute_patch(
    client: std::sync::Arc<crate::api::PxClient>,
    config: &crate::config::ProfileConfig,
    action: PatchCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    use crate::app::patch::{Orchestrator, PatchStrategy, Phase};
    use crate::ssh::{SshGateway, SshPool};
    use std::sync::Arc;

    // Clone the Arc so the new Repositories/Changelog/Versions arms
    // (which call methods on `client` after the orchestrator has
    // consumed `api`) keep their reference. Both Arcs point at the
    // same PxClient.
    let api: Arc<dyn ProxmoxGateway> = Arc::clone(&client) as Arc<dyn ProxmoxGateway>;

    match action {
        PatchCommand::Plan { node } => {
            // Plan only needs API. SSH not required at all.
            let strategy = PatchStrategy::default();
            // For plan-only we still need *some* SshGateway since the
            // Orchestrator type takes one — provide a trait object that
            // panics on use. Plan never calls .ssh.exec().
            let ssh: Arc<dyn SshGateway> = Arc::new(NoSsh);
            let orch = Orchestrator::new(api, ssh, strategy);
            let only = if node.is_empty() {
                None
            } else {
                Some(node.as_slice())
            };
            let plan = orch.plan(only).await?;
            Ok((serde_json::to_value(plan)?, 0))
        }
        PatchCommand::Apply {
            node,
            reboot,
            dry_run,
            upgrade_timeout,
            reboot_wait,
        } => {
            let ssh_cfg = config.ssh.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "patch apply requires `[profiles.X.ssh]` configured (key_path, etc.)"
                )
            })?;
            let pool = SshPool::new(ssh_cfg, None)?;
            let ssh: Arc<dyn SshGateway> = Arc::new(pool);

            let strategy = PatchStrategy {
                reboot_policy: reboot.into(),
                dry_run,
                upgrade_timeout: std::time::Duration::from_secs(upgrade_timeout),
                reboot_wait_timeout: std::time::Duration::from_secs(reboot_wait),
                ..Default::default()
            };
            let orch = Orchestrator::new(api, ssh, strategy);
            let only = if node.is_empty() {
                None
            } else {
                Some(node.as_slice())
            };
            let plan = orch.plan(only).await?;
            let progress = |node: &str, phase: &Phase| {
                tracing::info!("patch [{node}] → {phase:?}");
            };
            let applied = orch.apply(plan, progress).await?;

            // Exit non-zero if any node failed
            let exit = i32::from(
                applied
                    .nodes
                    .iter()
                    .any(|n| matches!(n.status, Phase::Failed { .. })),
            );
            Ok((serde_json::to_value(applied)?, exit))
        }
        PatchCommand::Repositories { node } => {
            use crate::api::ProxmoxGateway;
            let repos = client.node_apt_repositories(&node).await?;
            Ok((repos, 0))
        }
        PatchCommand::Changelog { node, package } => {
            use crate::api::ProxmoxGateway;
            let log = client.node_apt_changelog(&node, &package).await?;
            // Plain-text changelog wrapped in a `{"changelog": "..."}`
            // envelope so JSON consumers stay sane (vs returning a
            // bare string which `--format json` would emit unquoted).
            Ok((serde_json::json!({"package": package, "changelog": log}), 0))
        }
        PatchCommand::Versions { node } => {
            use crate::api::ProxmoxGateway;
            let pkgs = client.node_apt_versions(&node).await?;
            Ok((serde_json::to_value(pkgs)?, 0))
        }
    }
}

/// Trait object used by `patch plan` where SSH is never invoked. Panics
/// loudly if anyone tries to use it — that would be a programming error,
/// not a user-recoverable one.
struct NoSsh;

#[async_trait::async_trait]
impl crate::ssh::SshGateway for NoSsh {
    async fn exec(
        &self,
        _node: &str,
        _command: &str,
        _opts: crate::ssh::ExecOptions,
    ) -> Result<crate::ssh::ExecResult> {
        anyhow::bail!("internal: SSH should not be invoked during plan-only execution")
    }
}

enum BatchOp {
    Start,
    Stop { force: bool },
    Restart,
    Suspend,
    Resume,
}

async fn execute_batch_op(
    client: &std::sync::Arc<crate::api::PxClient>,
    op: BatchOp,
    vmids: &[u32],
    config: &crate::config::ProfileConfig,
    strict: bool,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    use tracing::{error, warn};

    let nodes = client.get_nodes().await?;
    let mut guest_map = std::collections::HashMap::new();

    let mut join_set = tokio::task::JoinSet::new();
    for node in nodes {
        let client_c = std::sync::Arc::clone(client);
        let node_name = node.node.clone();
        join_set.spawn(async move {
            let res = client_c.get_guests(&node_name).await;
            (node_name, res)
        });
    }

    while let Some(res) = join_set.join_next().await {
        if let Ok((_node_name, Ok(guests))) = res {
            for g in guests {
                guest_map.insert(g.vmid, g);
            }
        }
    }

    let mut results = Vec::new();
    let mut has_failure = false;
    let mut hitl_pending = false;
    let mut op_join_set = tokio::task::JoinSet::new();
    // (Gemini audit) — bound concurrent in-flight HTTPS
    // requests. Without this, `op_join_set.spawn(...)` per VMID with
    // 500+ selected guests would open 500 simultaneous TCP+TLS
    // connections, hitting `ulimit -n 1024` and cascading "Too many
    // open files" errors into the SQLite cache, log file, etc.
    //
    // 32 in-flight is a comfortable margin under any sensible ulimit
    // and well above what reqwest's per-host pool would dedupe to.
    const MAX_INFLIGHT_OPS: usize = 32;
    let inflight_sem = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_INFLIGHT_OPS));

    let action_str = match op {
        BatchOp::Start => "start",
        BatchOp::Stop { .. } => "stop",
        BatchOp::Restart => "restart",
        BatchOp::Suspend => "suspend",
        BatchOp::Resume => "resume",
    };

    let policies = config.policies.as_deref().unwrap_or_default();

    let tg_gateway = match config.telegram.as_ref() {
        None => None,
        Some(cfg) => Some(crate::hitl::telegram::TelegramGateway::from_config(cfg).await?),
    };

    if strict {
        let mut missing = Vec::new();
        for vmid in vmids {
            if !guest_map.contains_key(vmid) {
                missing.push(*vmid);
            }
        }
        if !missing.is_empty() {
            anyhow::bail!("Strict mode: Guests not found: {missing:?}");
        }
    }

    for vmid in vmids {
        if let Some(guest) = guest_map.get(vmid).cloned() {
            // Template guard — preventive. Templates cannot be
            // started or restarted; PVE would reject with a 500
            // message that doesn't tell the user how to proceed.
            // We catch it client-side and point them at `clone`.
            // Stop is allowed to fall through (templates are
            // always stopped, so PVE returns harmless no-op).
            if guest.is_template() && matches!(op, BatchOp::Start | BatchOp::Restart) {
                results.push(serde_json::json!({
                    "vmid": vmid,
                    "status": "rejected",
                    "reason": format!(
                        "guest {vmid} is a template — cannot {action_str}. \
                         Use `proxxx clone {vmid} --name <new>` to produce a \
                         startable copy."
                    ),
                }));
                has_failure = true;
                continue;
            }

            // Check HITL Policies
            let tags = guest.tag_list();
            if let Some(policy) =
                crate::hitl::policy::check_policies(policies, action_str, &vmid.to_string(), &tags)
            {
                warn!(
                    "HITL intercepted: {} on {} (Matched Policy: {} {})",
                    action_str, vmid, policy.action, policy.target
                );

                let txn_id = format!("{action_str}:{vmid}");

                if let Some(ref tg) = tg_gateway {
                    let reason = format!("CLI requested batch op: {action_str}");
                    if let Err(e) = tg
                        .request_approval(action_str, &vmid.to_string(), &reason, &txn_id)
                        .await
                    {
                        error!("Failed to send Telegram approval request: {}", e);
                    }
                }

                results.push(serde_json::json!({
                    "vmid": vmid,
                    "status": "pending_hitl",
                    "txn_id": txn_id,
                    "message": format!("Operation requires {} approval(s) via {}", policy.require, policy.channel)
                }));
                hitl_pending = true;
                continue; // Skip execution
            }

            let client_c = std::sync::Arc::clone(client);
            let v = *vmid;
            let node = guest.node;
            let gt = guest.guest_type;
            let operation = match op {
                BatchOp::Start => BatchOp::Start,
                BatchOp::Stop { force } => BatchOp::Stop { force },
                BatchOp::Restart => BatchOp::Restart,
                BatchOp::Suspend => BatchOp::Suspend,
                BatchOp::Resume => BatchOp::Resume,
            };

            if strict {
                // Bug #1+#2 fix: dispatch by guest_type, route force=false to shutdown.
                let res = match operation {
                    BatchOp::Start => client_c.start_guest(&node, v, gt).await,
                    BatchOp::Stop { force: true } => client_c.stop_guest(&node, v, gt, true).await,
                    BatchOp::Stop { force: false } => client_c.shutdown_guest(&node, v, gt).await,
                    BatchOp::Restart => client_c.restart_guest(&node, v, gt).await,
                    BatchOp::Suspend => client_c.suspend_guest(&node, v, gt).await,
                    BatchOp::Resume => client_c.resume_guest(&node, v, gt).await,
                };
                match res {
                    Ok(upid) => {
                        results.push(serde_json::json!({
                            "vmid": vmid,
                            "status": "success",
                            "upid": upid
                        }));
                    }
                    Err(e) => {
                        warn!("Operation failed for guest {}: {}", vmid, e);
                        results.push(serde_json::json!({
                            "vmid": vmid,
                            "status": "error",
                            "message": e.to_string()
                        }));
                        anyhow::bail!("Strict mode: Operation failed for guest {vmid}: {e}");
                    }
                }
            } else {
                let sem = std::sync::Arc::clone(&inflight_sem);
                op_join_set.spawn(async move {
                    // Acquire a permit before issuing the request. If
                    // 32 are already in flight, await here — the
                    // semaphore is the FD-exhaustion gate.
                    let _permit = sem.acquire_owned().await;
                    let res = match operation {
                        BatchOp::Start => client_c.start_guest(&node, v, gt).await,
                        BatchOp::Stop { force: true } => {
                            client_c.stop_guest(&node, v, gt, true).await
                        }
                        BatchOp::Stop { force: false } => {
                            client_c.shutdown_guest(&node, v, gt).await
                        }
                        BatchOp::Restart => client_c.restart_guest(&node, v, gt).await,
                        BatchOp::Suspend => client_c.suspend_guest(&node, v, gt).await,
                        BatchOp::Resume => client_c.resume_guest(&node, v, gt).await,
                    };
                    (v, res)
                });
            }
        } else {
            warn!("Guest {} not found across any node", vmid);
            results.push(serde_json::json!({
                "vmid": vmid,
                "status": "error",
                "message": "Guest not found"
            }));
            has_failure = true;
        }
    }

    if !strict {
        while let Some(res) = op_join_set.join_next().await {
            if let Ok((vmid, api_res)) = res {
                match api_res {
                    Ok(upid) => {
                        results.push(serde_json::json!({
                            "vmid": vmid,
                            "status": "success",
                            "upid": upid
                        }));
                    }
                    Err(e) => {
                        warn!("Operation failed for guest {}: {}", vmid, e);
                        results.push(serde_json::json!({
                            "vmid": vmid,
                            "status": "error",
                            "message": e.to_string()
                        }));
                        has_failure = true;
                    }
                }
            }
        }
    }

    let exit_code = if hitl_pending {
        3 // HITL Pending takes precedence in batch semantics
    } else if has_failure {
        2 // Partial Failure
    } else {
        0 // Full Success
    };

    Ok((serde_json::Value::Array(results), exit_code))
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
