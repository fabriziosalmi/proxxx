// App state machine — Elm Architecture (Unidirectional Data Flow)
// Model + Message + Reducer pattern. Zero I/O in update().

pub mod cache;
pub mod ha;
pub mod hw;
pub mod iso_library;
pub mod patch;
pub mod preflight;
pub mod queue;
pub mod search;
pub mod snaptree;

use crate::api::types::{Guest, Node, StoragePool};

/// The single source of truth for the entire application.
///
/// Note on the `bool` count (`clippy::struct_excessive_bools`): the
/// reducer is dispatched on every keystroke and benefits from cheap
/// scalar reads — packing flags into a bitset would force unpacking
/// on every match arm in `app::update`. Each flag is independent
/// (loading vs editing vs error vs `secure_mode` are not mutually
/// exclusive) so a single enum doesn't fit either. Keep flat.
#[allow(clippy::struct_excessive_bools)]
pub struct AppState {
    pub mode: AppMode,
    pub nav_stack: Vec<View>,
    pub nodes: Vec<Node>,
    pub guests: Vec<Guest>,
    pub storage: Vec<StoragePool>,
    pub selected_index: usize,
    pub is_loading: bool,
    pub error: Option<String>,
    pub search_query: String,
    pub command_input: String,
    pub pending_approvals: Vec<PendingApproval>,
    pub current_task_log: Vec<crate::api::types::TaskLogLine>,
    pub last_task_poll: Option<std::time::Instant>,
    pub error_time: Option<std::time::Instant>,
    pub last_sync: Option<std::time::Instant>,
    /// (macro audit): cluster quorum status from the most
    /// recent /cluster/status fetch. `Some(true)` = healthy quorum,
    /// `Some(false)` = QUORUM LOST (TUI shows banner; data is stale),
    /// `None` = not yet known (cold start, no fetch completed).
    pub cluster_quorate: Option<bool>,
    /// (audit) — names of nodes whose `uptime` did not
    /// advance between two consecutive `NodesLoaded` ticks. PVE
    /// marks a node `online` based on corosync membership, but the
    /// CPU/RAM/disk metrics come from `pvestatd`; when that daemon
    /// is wedged the metrics freeze while the node still looks up.
    /// Dashboard renders a "stale stats" badge for these.
    pub nodes_with_stale_stats: std::collections::HashSet<String>,
    pub active_tasks: std::collections::HashMap<u32, String>,
    pub op_queue: Vec<queue::QueuedOp>,
    pub selected_guests: std::collections::HashSet<u32>,
    pub storage_trend: std::collections::HashMap<String, (u64, u64)>, // pool -> (past_timestamp, past_used)
    pub cluster_tasks: Vec<crate::api::types::TaskInfo>,

    // Timeline state
    pub timeline_timestamps: Vec<u64>,
    pub timeline_index: usize,
    pub timeline_snapshot: Option<crate::app::cache::ClusterStateCache>,
    pub timeline_prev_snapshot: Option<crate::app::cache::ClusterStateCache>,

    // Security
    pub secure_mode: bool,
    /// Break-glass: single-shot flag set by `Action::ConfirmForce`
    /// before dispatching the inner action. Each destructive
    /// reducer (`StopGuest`, `DeleteGuest`, `RestartGuest`, `MigrateGuest`,
    /// `MoveDisk`, `ResizeDisk`) reads this flag to decide whether to
    /// honour `guest_block_reason` (the lock + HA gate). After the
    /// inner dispatch completes, `ConfirmForce` clears it again —
    /// the override never survives a single op.
    ///
    /// In-memory only: a TUI restart MUST re-prompt for break-glass.
    /// Persisting the flag would let a force survive across reboots
    /// and silently bypass safety. Audit-friendly default.
    pub force_next_destructive: bool,

    // Config Grep
    pub grep_query: String,
    pub grep_results: Vec<GrepMatch>,
    pub grep_searching: bool,

    // Snapshot tree (feature #7)
    /// Assembled tree for the current vmid in `View::SnapshotTree`.
    /// `None` while loading; `Some(empty_tree)` if no snapshots exist.
    pub snap_tree: Option<crate::app::snaptree::Tree>,
    /// Selected snapshot name in the tree view, for diff/cleanup actions.
    pub snap_tree_selected: Option<String>,
    /// Snapshot loading flag (mirrors API request state).
    pub snap_tree_loading: bool,

    /// Dirty flag for queue persistence (architectural review #2).
    /// Set whenever `op_queue` changes; cleared by the TUI loop after
    /// flushing to `SQLite`. Plain bool — the reducer is sync, no atomics.
    pub queue_dirty: bool,

    // HA + replication console (feature #5)
    pub ha_groups: Vec<crate::api::types::HaGroup>,
    pub ha_resources: Vec<crate::api::types::HaResource>,
    pub ha_manager: Option<crate::api::types::HaManagerStatus>,
    pub cluster_entries: Vec<crate::api::types::ClusterStatusEntry>,
    pub repl_status: Vec<crate::api::types::ReplicationStatus>,
    pub ha_loading: bool,

    // Hardware passthrough console (feature #4)
    pub hw_node: String,
    pub hw_pci: Vec<crate::api::types::PciDevice>,
    pub hw_usb: Vec<crate::api::types::UsbDevice>,
    /// Per-vmid raw configs (for the assignment scanner).
    pub hw_guest_configs: std::collections::HashMap<u32, std::collections::HashMap<String, String>>,
    pub hw_loading: bool,

    /// Per-node errors from the last guest fetch cycle. Non-empty when
    /// one or more nodes denied access (403) or were unreachable. Cleared
    /// on each new `GuestsLoaded` so stale errors don't linger after a
    /// token rotation.
    pub guests_fetch_errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GrepMatch {
    pub vmid: u32,
    pub name: String,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AppMode {
    Normal,
    Search,
    Command,
    InputTag,
    InputBroadcast,
    ConfigGrep,
    Confirm {
        description: String,
        action: Box<Action>,
    },
    /// Help overlay is open. Any key (or `?` again) returns to Normal.
    /// Reviewer P1: `?` used to be a TODO no-op; now it shows the
    /// keymap reference rendered from a static table.
    Help,
    /// User is inside an interactive SSH PTY session against a guest.
    /// While in this mode, the TUI loop bypasses normal key mapping and
    /// forwards every key (except the exit chord Ctrl+]) to the remote
    /// shell. The reducer never sees those keys.
    SshSession {
        vmid: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum View {
    Dashboard,
    NodeList,
    GuestList,
    GuestDetail {
        vmid: u32,
    },
    TaskLog {
        upid: String,
    },
    StorageList,
    ApprovalQueue,
    OperationQueue,
    GuestCompare {
        guests: Vec<u32>,
    },
    Heatmap,
    BackupBoard,
    AuditTimeline,
    ConfigGrep,
    /// Live SSH PTY session against a guest. Rendered by `views::ssh_session`.
    /// The actual `PtySession` lives in the TUI loop, not in `AppState` —
    /// `AppState` only knows the vmid for navigation purposes.
    GuestSshSession {
        vmid: u32,
    },
    /// Snapshot branching tree for a guest (feature #7). Tree assembly
    /// state lives on `AppState::snap_tree`; this view just binds to vmid.
    SnapshotTree {
        vmid: u32,
    },
    /// Curated ISO/cloud-image library (feature #2). The view renders
    /// the const `iso_library::LIBRARY` and lets the user trigger a
    /// server-side download to a chosen storage.
    IsoLibrary,
    /// HA + replication console (feature #5). Read-only inspector for
    /// HA groups, resources, manager status, and replication jobs.
    HaConsole,
    /// Hardware passthrough inventory + conflicts (feature #4).
    /// Read-only diagnostic. Per-node — `selected_node` drives data fetch.
    Hardware {
        node: String,
    },
}

#[derive(Debug, Clone)]
pub struct PendingApproval {
    pub txn_id: String,
    pub description: String,
    pub status: ApprovalStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Timeout,
}

/// Every possible event in the system.
/// Does NOT derive Eq — data payloads contain f64 fields.
#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    // Navigation & Selection
    Quit,
    Back,
    NavigateDown,
    NavigateUp,
    Select,
    SwitchView(View),
    ToggleSelection(u32),
    ClearSelection,
    SelectAll,
    SelectByTag(String),
    StartTagSelection,
    /// Toggle the help overlay (`?` keybind). Idempotent — pressing
    /// `?` again or any movement key returns to Normal.
    ToggleHelp,

    // Data
    Tick,
    NodesLoaded(Vec<Node>),
    GuestsLoaded(Vec<Guest>),
    StorageLoaded(Vec<StoragePool>),
    ClusterTasksLoaded(Vec<crate::api::types::TaskInfo>),
    /// live cluster quorum flag — drives the TUI banner.
    ClusterQuorateLoaded(bool),
    ErrorOccurred(String),
    /// Per-node errors from the guest fetch (403, unreachable, …).
    GuestsFetchErrorsLoaded(Vec<String>),

    // Guest operations
    StartGuest {
        vmid: u32,
    },
    StopGuest {
        vmid: u32,
        force: bool,
    },
    RestartGuest {
        vmid: u32,
    },
    DeleteGuest {
        vmid: u32,
    },
    MigrateGuest {
        vmid: u32,
        target_node: String,
    },
    CreateSnapshot {
        vmid: u32,
        name: String,
    },

    // Hardware passthrough console (feature #4)
    /// Open the hardware inventory for `node`. The TUI loop fetches the
    /// node's PCI/USB list AND every guest's config (so we can run the
    /// assignment scanner). Heavier than HA — N+1 calls — so we cache
    /// in `state.hw_*` until refresh.
    OpenHardware {
        node: String,
    },
    /// Aggregated HW data delivered.
    HwDataLoaded {
        node: String,
        pci: Vec<crate::api::types::PciDevice>,
        usb: Vec<crate::api::types::UsbDevice>,
        configs: std::collections::HashMap<u32, std::collections::HashMap<String, String>>,
    },

    // HA + replication console (feature #5)
    /// Open the HA console (read-only inspector). Triggers a refresh
    /// of `ha_groups`, `ha_resources`, `ha_status`, `cluster_status`,
    /// and per-node `replication_status`. (`replication_jobs` was
    /// fetched here too pre-cleanup but no view rendered it — the
    /// CLI `proxxx replication jobs` reads it directly from the
    /// gateway and bypasses `AppState`.)
    OpenHaConsole,
    /// Bulk data delivered by the controller after the multi-fetch.
    HaDataLoaded {
        groups: Vec<crate::api::types::HaGroup>,
        resources: Vec<crate::api::types::HaResource>,
        manager: crate::api::types::HaManagerStatus,
        cluster: Vec<crate::api::types::ClusterStatusEntry>,
        repl_status: Vec<crate::api::types::ReplicationStatus>,
    },

    // Snapshot tree (feature #7)
    /// Open the branching tree visualizer for `vmid`. The TUI loop fires
    /// the API call; the reducer pushes the view and marks loading.
    OpenSnapshotTree {
        vmid: u32,
    },
    /// API list returned: assemble the tree and stash on `AppState`.
    SnapshotsLoaded {
        vmid: u32,
        snaps: Vec<crate::api::types::Snapshot>,
    },

    // ISO / cloud-image lifecycle (feature #2)
    /// Open the curated library browser.
    OpenIsoLibrary,
    /// Trigger a server-side download of a library entry to a storage.
    /// `node` selects which Proxmox node performs the download (storages
    /// are typically attached to many nodes; pick one).
    DownloadIso {
        entry_id: String,
        node: String,
        storage: String,
    },
    /// Custom URL download — used by the CLI for things not in the curated
    /// library. No checksum pre-pin: the user is asserting they trust the URL.
    /// `checksum`, if present, is `(algo, hex)` — e.g. `("sha256", "...")`
    /// or `("sha512", "...")`. schema (was `sha256: Option<String>`).
    DownloadIsoCustom {
        url: String,
        filename: String,
        node: String,
        storage: String,
        checksum: Option<(String, String)>,
        content: String,
    },

    // Disk operations (feature #6)
    /// Request to move a disk to a different storage backend. The
    /// reducer ENQUEUES this (never emits a `SideEffect` directly) — the
    /// user must explicitly run the queue to commit. This is the
    /// "Operation Queue with HITL by default" guarantee for disk ops.
    MoveDisk {
        vmid: u32,
        disk: String,
        target_storage: String,
        delete_source: bool,
    },
    /// Request to grow a disk. Proxmox forbids shrinking — `size` must
    /// be larger than current. Same enqueue-only invariant as `MoveDisk`.
    ResizeDisk {
        vmid: u32,
        disk: String,
        size: String,
    },

    // SSH guest session (feature 1a)
    /// User asked to open an SSH PTY against a guest. The reducer pushes
    /// `View::GuestSshSession`, switches mode, and emits a side effect
    /// for the TUI loop to actually open the russh connection.
    OpenGuestSsh {
        vmid: u32,
    },
    /// Remote shell exited or user pressed the exit chord. The reducer
    /// pops the view back to whatever was beneath it.
    CloseSshSession,
    /// Out-of-band notification that the SSH session failed to open
    /// (auth denied, host key mismatch, network error). Restores the
    /// previous view and surfaces the message in `state.error`.
    SshSessionFailed {
        vmid: u32,
        error: String,
    },

    // Broadcast
    PromptBroadcastCommand,
    ExecuteBroadcast(String),
    ExecuteGuestCommand {
        vmid: u32,
        command: String,
    },

    // Timeline
    EnterTimeline,
    TimelineNext,
    TimelinePrev,

    // Node operations
    EvacuateNode {
        node: String,
    },

    // Compare
    CompareGuests,

    // Search & Command
    SearchInput(String),
    CommandInput(String),
    CommandSubmit,

    // Confirm Modal
    ConfirmRequest(String, Box<Self>),
    ConfirmAccept,
    /// Break-glass: same as `ConfirmAccept` but flags the resulting
    /// queue entry with `bypass_preflight = true`. Triggered by
    /// pressing `F` (capital, intentional friction) on the Confirm
    /// modal. The override is per-op (does NOT toggle a global
    /// mode) and never persists across TUI restarts.
    ConfirmForce,

    // HITL
    ApprovalRequested {
        txn_id: String,
        description: String,
    },
    ApprovalReceived {
        txn_id: String,
        approved: bool,
    },

    // Tasks
    TaskStarted(String),
    TaskLogUpdated {
        upid: String,
        lines: Vec<crate::api::types::TaskLogLine>,
    },
    GuestTaskFinished {
        vmid: u32,
    },

    /// Bug #2 enhancement: a graceful shutdown (`force=false`) was issued
    /// but the guest didn't reach the `stopped` state within the timeout.
    /// The reducer surfaces a Confirm modal asking the user to authorise
    /// a hard stop. If the user agrees, we re-dispatch with `force=true`.
    ShutdownTimedOut {
        vmid: u32,
        elapsed_secs: u64,
    },
    /// Per-poll progress event from the ACPI shutdown polling task.
    /// Fires every `poll_interval` (3s default) with the current observed
    /// status string and how long we've been waiting. The reducer uses
    /// this to update `state.active_tasks[vmid]` so the user sees a live
    /// countdown in the UI rather than a silent spinner.
    GuestStatusPolled {
        vmid: u32,
        status: String,
        elapsed_secs: u64,
    },

    // Config Grep
    StartConfigGrep,
    ConfigGrepInput(String),
    ConfigGrepSubmit,
    ConfigGrepResults {
        query: String,
        matches: Vec<GrepMatch>,
    },

    // Queue operations
    EnqueueOperation(Box<Self>),
    EnqueueBatchOperation(Vec<Box<Self>>),
    DequeueOperation(usize),
    ExecuteQueue,
    QueueOpStatusChanged(String, queue::OpStatus),
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            mode: AppMode::Normal,
            nav_stack: vec![View::Dashboard],
            nodes: Vec::new(),
            guests: Vec::new(),
            storage: Vec::new(),
            selected_index: 0,
            is_loading: true,
            error: None,
            search_query: String::new(),
            command_input: String::new(),
            pending_approvals: Vec::new(),
            current_task_log: Vec::new(),
            last_task_poll: None,
            error_time: None,
            last_sync: None,
            cluster_quorate: None,
            nodes_with_stale_stats: std::collections::HashSet::new(),
            active_tasks: std::collections::HashMap::new(),
            op_queue: Vec::new(),
            selected_guests: std::collections::HashSet::new(),
            storage_trend: std::collections::HashMap::new(),
            cluster_tasks: Vec::new(),
            timeline_timestamps: Vec::new(),
            timeline_index: 0,
            timeline_snapshot: None,
            timeline_prev_snapshot: None,
            secure_mode: false,
            force_next_destructive: false,
            grep_query: String::new(),
            grep_results: Vec::new(),
            grep_searching: false,
            snap_tree: None,
            snap_tree_selected: None,
            snap_tree_loading: false,
            queue_dirty: false,
            ha_groups: Vec::new(),
            ha_resources: Vec::new(),
            ha_manager: None,
            cluster_entries: Vec::new(),
            repl_status: Vec::new(),
            ha_loading: false,
            hw_node: String::new(),
            hw_pci: Vec::new(),
            hw_usb: Vec::new(),
            hw_guest_configs: std::collections::HashMap::new(),
            hw_loading: false,
            guests_fetch_errors: Vec::new(),
        }
    }
}

impl AppState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current view (top of navigation stack)
    #[must_use]
    pub fn current_view(&self) -> &View {
        self.nav_stack.last().unwrap_or(&View::Dashboard)
    }

    /// Push a view onto the navigation stack
    pub fn push_view(&mut self, view: View) {
        self.nav_stack.push(view);
        self.selected_index = 0;
    }

    /// Pop the navigation stack. Returns false if at root (should quit).
    ///
    /// (audit) — release view-scoped state when its owner view
    /// is popped, instead of waiting for the next entry to clear it.
    /// Bounded-by-1 was already true (clear-on-enter pattern), but
    /// holding the previous tree / hw inventory / grep results in
    /// memory until the next visit is wasteful when the user is
    /// navigating away. Drop them immediately at pop time.
    pub fn pop_view(&mut self) -> bool {
        if self.nav_stack.len() > 1 {
            // Inspect what we're leaving so we know which fields to free.
            if let Some(leaving) = self.nav_stack.last() {
                match leaving {
                    View::SnapshotTree { .. } => {
                        self.snap_tree = None;
                        self.snap_tree_selected = None;
                        self.snap_tree_loading = false;
                    }
                    View::Hardware { .. } => {
                        self.hw_pci.clear();
                        self.hw_pci.shrink_to_fit();
                        self.hw_usb.clear();
                        self.hw_usb.shrink_to_fit();
                        self.hw_guest_configs.clear();
                        self.hw_guest_configs.shrink_to_fit();
                        self.hw_loading = false;
                    }
                    View::ConfigGrep => {
                        self.grep_results.clear();
                        self.grep_results.shrink_to_fit();
                        self.grep_query.clear();
                    }
                    View::HaConsole => {
                        self.ha_groups.clear();
                        self.ha_resources.clear();
                        self.ha_manager = None;
                        self.cluster_entries.clear();
                        self.repl_status.clear();
                        self.ha_loading = false;
                    }
                    View::TaskLog { .. } => {
                        self.current_task_log.clear();
                        self.current_task_log.shrink_to_fit();
                    }
                    _ => {}
                }
            }
            self.nav_stack.pop();
            true
        } else {
            false
        }
    }

    /// Return guests filtered by `search_query`
    #[must_use]
    pub fn visible_guests(&self) -> Vec<&Guest> {
        if self.search_query.is_empty() {
            self.guests.iter().collect()
        } else {
            let q = self.search_query.to_lowercase();
            self.guests
                .iter()
                .filter(|g| {
                    g.name.to_lowercase().contains(&q)
                        || g.vmid.to_string().contains(&q)
                        || g.node.to_lowercase().contains(&q)
                        || g.tags.to_lowercase().contains(&q)
                })
                .collect()
        }
    }
}

/// SPOF 5.1 (Category 5 audit): log when a guest's tag set differs
/// between two consecutive snapshots. The tag string is PVE's raw
/// semicolon-separated form, so we compare the SET of tokens (order /
/// duplicates don't matter). Pure function — does not touch state and
/// does no I/O beyond `tracing::warn!`, which is file-only in proxxx.
pub fn audit_tag_changes(prev: &[Guest], next: &[Guest]) {
    use std::collections::{HashMap, HashSet};
    let prev_by_vmid: HashMap<u32, &str> = prev.iter().map(|g| (g.vmid, g.tags.as_str())).collect();
    for g in next {
        let Some(prev_tags) = prev_by_vmid.get(&g.vmid) else {
            continue; // newly observed guest — not a mutation
        };
        if *prev_tags == g.tags.as_str() {
            continue;
        }
        let prev_set: HashSet<&str> = prev_tags.split(';').filter(|t| !t.is_empty()).collect();
        let new_set: HashSet<&str> = g.tags.split(';').filter(|t| !t.is_empty()).collect();
        if prev_set == new_set {
            continue; // same tokens, just whitespace / order differences
        }
        let added: Vec<&&str> = new_set.difference(&prev_set).collect();
        let removed: Vec<&&str> = prev_set.difference(&new_set).collect();
        tracing::warn!(
            "tag mutation detected on guest {vmid} ({name}): added={added:?} removed={removed:?} \
             — out-of-band PVE mutation. Tag-based HITL policies may be evaded; \
             rely on --secure for tag-independent gating.",
            vmid = g.vmid,
            name = g.name,
        );
    }
}

/// PURE reducer — updates state based on action. Zero I/O, zero async.
/// Side effects (API calls) are returned as `Option<SideEffect>`.
/// + (audit) — return Some(reason) if `vmid` cannot
/// safely receive a destructive op named `op_label`. None means the
/// op is allowed to proceed. The reason string is user-visible.
///
/// Two failure modes:
///   - PVE has a sticky lock (`backup`, `clone`, `migrate`,
///     `rollback`, `snapshot*`, `suspending`). Issuing the call
///     would hit `500 VM is locked`; we'd rather show what's
///     blocking up-front.
///   - Guest is HA-managed (`hastate` non-empty). Raw `/status/*`
///     calls fight the CRM, which restarts the guest in 5 s or
///     fences the node. The user must change HA state via
///     `/cluster/ha/resources/<vmid>` first.
fn guest_block_reason(state: &AppState, vmid: u32, op_label: &str) -> Option<String> {
    let g = state.guests.iter().find(|g| g.vmid == vmid)?;
    if g.is_locked() {
        return Some(format!(
            "Cannot {op_label} guest {vmid} ({}): held by lock '{}' — wait for that operation to finish",
            g.name, g.lock
        ));
    }
    if g.is_ha_managed() {
        return Some(format!(
            "Cannot {op_label} guest {vmid} ({}) directly: HA-managed (state '{}'). Change HA state via `/cluster/ha/resources/{vmid}` first, or the CRM will undo this within seconds.",
            g.name, g.hastate
        ));
    }
    None
}

pub fn update(state: &mut AppState, action: Action) -> Option<SideEffect> {
    match action {
        Action::Quit => return Some(SideEffect::Quit),
        Action::Back => {
            if !matches!(state.mode, AppMode::Normal) {
                state.mode = AppMode::Normal;
                state.search_query.clear();
                state.command_input.clear();
            } else if !state.pop_view() {
                return Some(SideEffect::Quit);
            }
        }
        Action::NavigateDown => {
            let max = item_count(state);
            if max > 0 && state.selected_index < max - 1 {
                state.selected_index += 1;
            }
        }
        Action::NavigateUp => {
            if state.selected_index > 0 {
                state.selected_index -= 1;
            }
        }
        Action::Select => {
            return handle_select(state);
        }
        Action::SwitchView(view) => {
            state.push_view(view);
            state.selected_guests.clear();
        }
        Action::ToggleSelection(vmid) => {
            if !state.selected_guests.insert(vmid) {
                state.selected_guests.remove(&vmid);
            }
        }
        Action::ClearSelection => {
            state.selected_guests.clear();
        }
        Action::SelectAll => {
            if matches!(state.current_view(), View::GuestList) {
                for guest in &state.guests {
                    state.selected_guests.insert(guest.vmid);
                }
            }
        }
        Action::SelectByTag(tag) => {
            if matches!(state.current_view(), View::GuestList) {
                let tag_lower = tag.to_lowercase();
                for guest in &state.guests {
                    if guest
                        .tag_list()
                        .iter()
                        .any(|t| t.to_lowercase() == tag_lower)
                    {
                        state.selected_guests.insert(guest.vmid);
                    }
                }
            }
            state.mode = AppMode::Normal;
        }
        Action::ToggleHelp => {
            state.mode = if matches!(state.mode, AppMode::Help) {
                AppMode::Normal
            } else {
                AppMode::Help
            };
        }
        Action::StartTagSelection => {
            state.mode = AppMode::InputTag;
            state.command_input.clear();
        }
        Action::Tick => {
            let mut fetch_upid = None;
            if let View::TaskLog { upid } = state.current_view() {
                fetch_upid = Some(upid.clone());
            }

            let now = std::time::Instant::now();

            // Clear error after 5 seconds
            if let Some(err_time) = state.error_time {
                if now.duration_since(err_time).as_secs() >= 5 {
                    state.error = None;
                    state.error_time = None;
                }
            }

            // SPOF 5.2 (Category 5 audit): run queue garbage collection.
            // Bounded memory: drops stale Success ops after 5 min, caps
            // Error backlog at 50, hard-caps total at 200. Mark the
            // queue dirty if anything was evicted so the persisted DB
            // is brought back in sync before the next render.
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let dropped = queue::garbage_collect(&mut state.op_queue, now_unix);
            if dropped > 0 {
                state.queue_dirty = true;
            }

            if let Some(upid) = fetch_upid {
                let should_poll = match state.last_task_poll {
                    Some(last) => now.duration_since(last).as_secs() >= 1,
                    None => true,
                };

                if should_poll {
                    state.last_task_poll = Some(now);
                    let parts: Vec<&str> = upid.split(':').collect();
                    if parts.len() > 1 {
                        let node = parts[1].to_string();
                        return Some(SideEffect::FetchTaskLog { upid, node });
                    }
                }
            }
        }

        // Data updates
        Action::NodesLoaded(nodes) => {
            // (audit) — detect frozen pvestatd. PVE marks a
            // node "online" via corosync membership, but the per-
            // node CPU/RAM/disk metrics come from `pvestatd`. If
            // that daemon dies the metrics stay frozen at their
            // last value while the node still appears online —
            // exactly the silent-bad-data trap V17 (quorum) was
            // catching at the cluster level.
            //
            // Heuristic: the `uptime` field is monotonically
            // increasing on a healthy node. If the new fetch
            // reports the SAME uptime as the previous fetch (same
            // 5-second window), pvestatd hasn't ticked. Tag the
            // node so the dashboard renders a warning badge.
            for new_n in &nodes {
                if let Some(prev) = state.nodes.iter().find(|n| n.node == new_n.node) {
                    if prev.uptime > 0 && new_n.uptime == prev.uptime && new_n.status == prev.status
                    {
                        state.nodes_with_stale_stats.insert(new_n.node.clone());
                    } else {
                        state.nodes_with_stale_stats.remove(&new_n.node);
                    }
                }
            }
            // Drop stale-flags for nodes that disappeared from the
            // cluster (V15 replace-not-upsert at the set level).
            let known: std::collections::HashSet<&String> = nodes.iter().map(|n| &n.node).collect();
            state.nodes_with_stale_stats.retain(|n| known.contains(n));
            state.nodes = nodes;
            state.is_loading = false;
            state.last_sync = Some(std::time::Instant::now());
        }
        Action::GuestsLoaded(guests) => {
            // SPOF 5.1 (Category 5 audit): emit a forensic trail when
            // a guest's tag set changes between snapshots. proxxx can't
            // PREVENT out-of-band tag mutation (the attacker uses the
            // PVE API directly), but a WARN log gives ops a signal that
            // tag-based HITL policies may have been evaded.
            audit_tag_changes(&state.guests, &guests);
            state.guests = guests;
            state.is_loading = false;
            // Clear stale errors from the previous cycle — new data arrived.
            state.guests_fetch_errors.clear();
        }
        Action::GuestsFetchErrorsLoaded(errs) => {
            state.guests_fetch_errors = errs;
        }
        Action::StorageLoaded(storage) => {
            state.storage = storage;
        }
        Action::ClusterTasksLoaded(tasks) => {
            state.cluster_tasks = tasks;
        }
        Action::ClusterQuorateLoaded(quorate) => {
            state.cluster_quorate = Some(quorate);
        }
        Action::ErrorOccurred(err) => {
            state.error = Some(err);
            state.error_time = Some(std::time::Instant::now());
            state.is_loading = false;
        }

        // Search
        Action::SearchInput(query) => {
            state.mode = AppMode::Search;
            state.search_query = query;
        }

        // Command palette
        Action::CommandInput(input) => {
            state.mode = AppMode::Command;
            state.command_input = input;
        }
        Action::CommandSubmit => {
            let cmd = state.command_input.clone();
            state.mode = AppMode::Normal;
            state.command_input.clear();
            // Action-producing commands take precedence (they need a
            // reducer state transition before any side effect runs).
            if let Some(action) = parse_command_action(&cmd) {
                return update(state, action);
            }
            return parse_command(&cmd);
        }

        // Confirm Modal
        Action::ConfirmRequest(desc, action) => {
            state.mode = AppMode::Confirm {
                description: desc,
                action,
            };
        }
        Action::ConfirmAccept => {
            if let AppMode::Confirm { action, .. } = &state.mode {
                let action_to_dispatch = *action.clone();
                state.mode = AppMode::Normal;
                return update(state, action_to_dispatch);
            }
        }
        Action::ConfirmForce => {
            // Break-glass: bypass guest_block_reason for the next
            // single destructive op. We log loudly to the audit log
            // — every force-use must be traceable post-incident.
            if let AppMode::Confirm {
                action,
                description,
            } = &state.mode
            {
                let action_to_dispatch = *action.clone();
                tracing::error!(
                    "BREAK-GLASS: forcing op '{description}' — bypassing client-side guards"
                );
                state.mode = AppMode::Normal;
                state.force_next_destructive = true;
                let result = update(state, action_to_dispatch);
                // Always clear after the dispatch returns. The flag
                // MUST NOT outlast a single op — reading it twice
                // (e.g., a reducer recursively calling another
                // destructive op) would silently double-use the
                // break-glass intent.
                state.force_next_destructive = false;
                return result;
            }
        }

        // Guest operations — these produce side effects
        Action::StartGuest { vmid } => {
            state.active_tasks.insert(vmid, "Starting...".to_string());
            return Some(SideEffect::StartGuest { vmid });
        }
        Action::StopGuest { vmid, force } => {
            // + (audit) — refuse destructive ops when:
            //   (a) PVE has a sticky `lock` on the guest (a backup,
            //       clone, snapshot etc. is in flight). Issuing the
            //       call would surface PVE's confusing "500 VM is
            //       locked"; we'd rather show what's blocking.
            //   (b) the guest is HA-managed (`hastate` non-empty).
            //       A raw /status/stop on an HA-managed guest
            //       triggers the CRM to restart it within 5 s, or
            //       fence the node. The user must change HA state
            //       via /cluster/ha/resources first.
            //
            // BREAK-GLASS: when `force_next_destructive` is set
            // (user pressed `F` on the Confirm modal), skip this
            // gate. PVE's own server-side checks still apply — we
            // just stop pre-empting them client-side.
            if state.force_next_destructive {
                tracing::error!("BREAK-GLASS: bypassing client-side stop gate for vmid {vmid}");
            } else if let Some(reason) = guest_block_reason(state, vmid, "stop") {
                state.error = Some(reason);
                state.error_time = Some(std::time::Instant::now());
                return None;
            }
            let status = if force {
                "Force Stopping..."
            } else {
                "Stopping..."
            };
            state.active_tasks.insert(vmid, status.to_string());
            return Some(SideEffect::StopGuest { vmid, force });
        }
        Action::RestartGuest { vmid } => {
            // + same gate as StopGuest. Restart on a
            // locked / HA-managed guest is equally problematic.
            // BREAK-GLASS: see StopGuest comment for rationale.
            if state.force_next_destructive {
                tracing::error!("BREAK-GLASS: bypassing client-side restart gate for vmid {vmid}");
            } else if let Some(reason) = guest_block_reason(state, vmid, "restart") {
                state.error = Some(reason);
                state.error_time = Some(std::time::Instant::now());
                return None;
            }
            state.active_tasks.insert(vmid, "Restarting...".to_string());
            return Some(SideEffect::RestartGuest { vmid });
        }
        Action::MigrateGuest { vmid, target_node } => {
            // — only the lock check applies here. HA-managed
            // guests CAN be migrated (the CRM allows it), but a
            // backup/clone/snapshot lock conflicts with the move.
            // BREAK-GLASS: see StopGuest comment.
            if state.force_next_destructive {
                tracing::error!(
                    "BREAK-GLASS: bypassing client-side migrate lock gate for vmid {vmid}"
                );
            } else if let Some(g) = state.guests.iter().find(|g| g.vmid == vmid) {
                if g.is_locked() {
                    state.error = Some(format!(
                        "Cannot migrate guest {vmid} ({}): held by lock '{}' — wait for that operation to finish",
                        g.name, g.lock
                    ));
                    state.error_time = Some(std::time::Instant::now());
                    return None;
                }
            }
            // Bug #9 fix: emit a SideEffect so direct dispatch (not just via
            // queue) actually runs the migration. Source node is looked up
            // from current state. If we can't find the guest, surface an
            // error instead of silently no-op'ing.
            state
                .active_tasks
                .insert(vmid, format!("Migrating to {target_node}..."));
            if let Some(source_node) = state
                .guests
                .iter()
                .find(|g| g.vmid == vmid)
                .map(|g| g.node.clone())
            {
                return Some(SideEffect::MigrateGuest {
                    node: source_node,
                    vmid,
                    target_node,
                });
            }
            state.error = Some(format!("Migrate failed: guest {vmid} not in current state"));
            state.error_time = Some(std::time::Instant::now());
            state.active_tasks.remove(&vmid);
        }
        Action::DeleteGuest { vmid } => {
            // + HA-managed or locked → refuse loudly.
            // The API-level TOCTOU pre-flight  is the last
            // line of defence; this is the user-visible early gate.
            // BREAK-GLASS: see StopGuest comment.
            if state.force_next_destructive {
                tracing::error!("BREAK-GLASS: bypassing client-side delete gate for vmid {vmid}");
            } else if let Some(reason) = guest_block_reason(state, vmid, "delete") {
                state.error = Some(reason);
                state.error_time = Some(std::time::Instant::now());
                return None;
            }
            return Some(SideEffect::DeleteGuest { vmid });
        }
        Action::CreateSnapshot { vmid, name } => {
            // snapshot creation collides with backup/clone
            // locks — refuse early.
            if let Some(reason) = guest_block_reason(state, vmid, "snapshot") {
                state.error = Some(reason);
                state.error_time = Some(std::time::Instant::now());
                return None;
            }
            return Some(SideEffect::CreateSnapshot { vmid, name });
        }

        // ISO / cloud-image lifecycle (feature #2)
        Action::OpenIsoLibrary => {
            state.push_view(View::IsoLibrary);
        }
        Action::DownloadIso {
            entry_id,
            node,
            storage,
        } => {
            let Some(entry) = crate::app::iso_library::by_id(&entry_id) else {
                state.error = Some(format!("ISO library entry '{entry_id}' not found"));
                state.error_time = Some(std::time::Instant::now());
                return None;
            };
            // refuse-on-unpinned-checksum gate: refuse curated-library downloads when the
            // checksum has not been pinned against an upstream manifest.
            // The user can still use `proxxx iso download --url <X>` to
            // bring their own URL+checksum — the curated path is the one
            // that needs to ship trusted.
            let Some(checksum) = entry.checksum else {
                state.error = Some(format!(
                    "ISO library entry '{entry_id}' has no pinned checksum. \
                     Use --url <X> --sha256 <Y> via CLI instead, or wait for \
                     a proxxx release that pins this entry."
                ));
                state.error_time = Some(std::time::Instant::now());
                return None;
            };
            let (algo, hex) = checksum.proxmox_pair();
            // If the caller didn't specify a node, pick the first online
            // node from current cluster state — typical homelab single-node
            // case. CLI users always pass --node so they get deterministic
            // behaviour; TUI uses this fallback to avoid a whole picker UI
            // for the MVP.
            let resolved_node = if node.is_empty() {
                state
                    .nodes
                    .iter()
                    .find(|n| n.status == crate::api::types::NodeStatus::Online)
                    .map(|n| n.node.clone())
                    .unwrap_or_default()
            } else {
                node
            };
            if resolved_node.is_empty() {
                state.error = Some("No online node available for ISO download".to_string());
                state.error_time = Some(std::time::Instant::now());
                return None;
            }
            // Derive a sane filename from the URL — Proxmox accepts an
            // override and we want it predictable for users grepping
            // storage content later.
            let filename = entry
                .url
                .rsplit('/')
                .next()
                .unwrap_or("download.img")
                .to_string();
            return Some(SideEffect::DownloadIso {
                node: resolved_node,
                storage,
                url: entry.url.to_string(),
                filename,
                checksum: Some((algo.to_string(), hex.to_string())),
                content: entry.content.to_string(),
            });
        }
        Action::DownloadIsoCustom {
            url,
            filename,
            node,
            storage,
            checksum,
            content,
        } => {
            return Some(SideEffect::DownloadIso {
                node,
                storage,
                url,
                filename,
                checksum,
                content,
            });
        }

        // Disk operations (feature #6) — FORCE-ENQUEUE.
        // The reducer never returns Some(SideEffect::MoveDisk/ResizeDisk).
        // Queue execution is the only path that produces those side effects,
        // which gives us the user-confirmation step (`C` to execute queue)
        // for free, and routes through the same HITL gate as other
        // destructive ops at exec time.
        Action::MoveDisk {
            vmid,
            disk,
            target_storage,
            delete_source,
        } => {
            let a = Action::MoveDisk {
                vmid,
                disk,
                target_storage,
                delete_source,
            };
            // Honour break-glass: if ConfirmForce set the flag,
            // mark the op as bypass_preflight so the queue dispatcher
            // skips its preflight check too.
            let queued = if state.force_next_destructive {
                queue::QueuedOp::new_force(Box::new(a), state)
            } else {
                queue::QueuedOp::new(Box::new(a), state)
            };
            state.op_queue.push(queued);
            state.queue_dirty = true;
            state.push_view(View::OperationQueue);
        }
        Action::ResizeDisk { vmid, disk, size } => {
            let a = Action::ResizeDisk { vmid, disk, size };
            // Honour break-glass: if ConfirmForce set the flag,
            // mark the op as bypass_preflight so the queue dispatcher
            // skips its preflight check too.
            let queued = if state.force_next_destructive {
                queue::QueuedOp::new_force(Box::new(a), state)
            } else {
                queue::QueuedOp::new(Box::new(a), state)
            };
            state.op_queue.push(queued);
            state.queue_dirty = true;
            state.push_view(View::OperationQueue);
        }

        // Hardware passthrough console (feature #4)
        Action::OpenHardware { node } => {
            state.hw_node = node.clone();
            state.hw_loading = true;
            state.hw_pci.clear();
            state.hw_usb.clear();
            state.hw_guest_configs.clear();
            state.push_view(View::Hardware { node: node.clone() });
            return Some(SideEffect::FetchHardwareData { node });
        }
        Action::HwDataLoaded {
            node,
            pci,
            usb,
            configs,
        } => {
            // Only accept if it matches the currently-selected node —
            // a stale fetch result shouldn't overwrite what the user
            // navigated to in the meantime.
            if state.hw_node == node {
                state.hw_pci = pci;
                state.hw_usb = usb;
                state.hw_guest_configs = configs;
                state.hw_loading = false;
            }
        }

        // HA + replication console (feature #5)
        Action::OpenHaConsole => {
            state.ha_loading = true;
            state.push_view(View::HaConsole);
            return Some(SideEffect::FetchHaConsoleData);
        }
        Action::HaDataLoaded {
            groups,
            resources,
            manager,
            cluster,
            repl_status,
        } => {
            state.ha_groups = groups;
            state.ha_resources = resources;
            state.ha_manager = Some(manager);
            state.cluster_entries = cluster;
            state.repl_status = repl_status;
            state.ha_loading = false;
        }

        // Snapshot tree (feature #7)
        Action::OpenSnapshotTree { vmid } => {
            state.snap_tree = None;
            state.snap_tree_selected = None;
            state.snap_tree_loading = true;
            state.push_view(View::SnapshotTree { vmid });
            return Some(SideEffect::FetchSnapshotTree { vmid });
        }
        Action::SnapshotsLoaded { vmid, snaps } => {
            // Stale-fetch guard: a result for VMID-A must not overwrite the
            // tree of VMID-B if the user navigated to a different snapshot
            // tree before the fetch returned. Compare against the current
            // view; drop silently if it no longer matches.
            if !matches!(state.current_view(), View::SnapshotTree { vmid: v } if *v == vmid) {
                return None;
            }
            let tree = crate::app::snaptree::assemble(snaps);
            // Default selection: prefer "current" (where the user is now),
            // else first root, else nothing.
            let initial_selection = {
                let by_name = tree
                    .roots
                    .iter()
                    .flat_map(collect_names)
                    .collect::<Vec<_>>();
                by_name
                    .iter()
                    .find(|n| *n == "current")
                    .cloned()
                    .or_else(|| by_name.into_iter().next())
            };
            state.snap_tree_selected = initial_selection;
            state.snap_tree = Some(tree);
            state.snap_tree_loading = false;
        }

        // SSH guest session
        Action::OpenGuestSsh { vmid } => {
            // Push the view first so the renderer flips on the next tick,
            // even before the SSH connection completes. The view shows a
            // "connecting…" placeholder until the controller hands the
            // PTY parser to the renderer (via shared state outside AppState).
            state.push_view(View::GuestSshSession { vmid });
            state.mode = AppMode::SshSession { vmid };
            return Some(SideEffect::OpenSshSession { vmid });
        }
        Action::CloseSshSession => {
            // Only act if we're actually in an SSH session — defensive.
            if matches!(state.mode, AppMode::SshSession { .. })
                || matches!(state.current_view(), View::GuestSshSession { .. })
            {
                state.mode = AppMode::Normal;
                state.pop_view();
                return Some(SideEffect::CloseSshSession);
            }
        }
        Action::SshSessionFailed { vmid, error } => {
            state.mode = AppMode::Normal;
            // Pop only if we actually pushed the SSH view (we did, in OpenGuestSsh).
            if matches!(state.current_view(), View::GuestSshSession { vmid: v } if *v == vmid) {
                state.pop_view();
            }
            state.error = Some(format!("SSH to {vmid} failed: {error}"));
            state.error_time = Some(std::time::Instant::now());
        }

        // Compare
        Action::CompareGuests => {
            let guests: Vec<u32> = state.selected_guests.iter().copied().collect();
            state.selected_guests.clear();
            state.push_view(View::GuestCompare { guests });
        }

        // Node
        Action::EvacuateNode { node } => {
            let mut actions = Vec::new();

            // Get all other running nodes
            let available_nodes: Vec<_> = state
                .nodes
                .iter()
                .filter(|n| n.node != node && n.status == crate::api::types::NodeStatus::Online)
                .collect();

            if available_nodes.is_empty() {
                state.error = Some("No available nodes for evacuation".to_string());
                state.error_time = Some(std::time::Instant::now());
            } else {
                for guest in &state.guests {
                    if guest.node == node {
                        // Pick node with most free RAM. The if-else guard
                        // above (`available_nodes.is_empty()`) ensures
                        // there's always at least one element here, but
                        // we use `if let Some` instead of unwrap so a
                        // future refactor can't silently re-introduce
                        // the panic the lint forbids.
                        if let Some(target) = available_nodes
                            .iter()
                            .max_by_key(|n| n.maxmem.saturating_sub(n.mem))
                        {
                            actions.push(Box::new(Action::MigrateGuest {
                                vmid: guest.vmid,
                                target_node: target.node.clone(),
                            }));
                        }
                    }
                }

                if actions.is_empty() {
                    state.error = Some(format!("No guests on node {node}"));
                    state.error_time = Some(std::time::Instant::now());
                } else {
                    let force = state.force_next_destructive;
                    for action in actions {
                        // Same break-glass branch as MoveDisk/ResizeDisk.
                        let queued = if force {
                            queue::QueuedOp::new_force(action, state)
                        } else {
                            queue::QueuedOp::new(action, state)
                        };
                        state.op_queue.push(queued);
                        state.queue_dirty = true;
                    }
                    state.push_view(View::OperationQueue);
                }
            }
        }

        Action::PromptBroadcastCommand => {
            state.mode = AppMode::InputBroadcast;
            state.command_input.clear();
        }

        Action::ExecuteBroadcast(cmd) => {
            state.mode = AppMode::Normal;
            let mut actions = Vec::new();
            for vmid in &state.selected_guests {
                actions.push(Box::new(Action::ExecuteGuestCommand {
                    vmid: *vmid,
                    command: cmd.clone(),
                }));
            }
            state.selected_guests.clear();

            if actions.is_empty() {
                state.error = Some("No guests selected for broadcast".to_string());
                state.error_time = Some(std::time::Instant::now());
            } else {
                let force = state.force_next_destructive;
                for action in actions {
                    let queued = if force {
                        queue::QueuedOp::new_force(action, state)
                    } else {
                        queue::QueuedOp::new(action, state)
                    };
                    state.op_queue.push(queued);
                    state.queue_dirty = true;
                }
                state.push_view(View::OperationQueue);
            }
        }

        Action::ExecuteGuestCommand { vmid, command } => {
            if let Some(guest) = state.guests.iter().find(|g| g.vmid == vmid) {
                return Some(SideEffect::ExecuteGuestCommand {
                    node: guest.node.clone(),
                    vmid,
                    guest_type: guest.guest_type,
                    command,
                });
            }
            state.error = Some(format!("Guest {vmid} not found"));
            state.error_time = Some(std::time::Instant::now());
        }

        Action::EnterTimeline => {
            if let Ok(ts) = crate::app::cache::get_all_snapshots(None) {
                if ts.is_empty() {
                    state.error = Some("No historical snapshots found".to_string());
                    state.error_time = Some(std::time::Instant::now());
                } else {
                    state.timeline_timestamps = ts;
                    state.timeline_index = state.timeline_timestamps.len() - 1;
                    if let Ok(snap) = crate::app::cache::load_state_at(
                        None,
                        state.timeline_timestamps[state.timeline_index],
                    ) {
                        state.timeline_snapshot = Some(snap);
                    }
                    if state.timeline_index > 0 {
                        if let Ok(prev) = crate::app::cache::load_state_at(
                            None,
                            state.timeline_timestamps[state.timeline_index - 1],
                        ) {
                            state.timeline_prev_snapshot = Some(prev);
                        }
                    } else {
                        state.timeline_prev_snapshot = None;
                    }
                    state.push_view(View::AuditTimeline);
                }
            }
        }
        Action::TimelinePrev => {
            if state.timeline_index > 0 {
                state.timeline_index -= 1;
                if let Ok(snap) = crate::app::cache::load_state_at(
                    None,
                    state.timeline_timestamps[state.timeline_index],
                ) {
                    state.timeline_snapshot = Some(snap);
                }
                if state.timeline_index > 0 {
                    if let Ok(prev) = crate::app::cache::load_state_at(
                        None,
                        state.timeline_timestamps[state.timeline_index - 1],
                    ) {
                        state.timeline_prev_snapshot = Some(prev);
                    }
                } else {
                    state.timeline_prev_snapshot = None;
                }
            }
        }
        Action::TimelineNext => {
            if state.timeline_index + 1 < state.timeline_timestamps.len() {
                state.timeline_index += 1;
                if let Ok(snap) = crate::app::cache::load_state_at(
                    None,
                    state.timeline_timestamps[state.timeline_index],
                ) {
                    state.timeline_snapshot = Some(snap);
                }
                if state.timeline_index > 0 {
                    if let Ok(prev) = crate::app::cache::load_state_at(
                        None,
                        state.timeline_timestamps[state.timeline_index - 1],
                    ) {
                        state.timeline_prev_snapshot = Some(prev);
                    }
                } else {
                    state.timeline_prev_snapshot = None;
                }
            }
        }

        // HITL
        Action::ApprovalRequested {
            txn_id,
            description,
        } => {
            state.pending_approvals.push(PendingApproval {
                txn_id,
                description,
                status: ApprovalStatus::Pending,
            });
            // Auto switch to Approval Queue
            state.push_view(View::ApprovalQueue);
        }
        Action::ApprovalReceived { txn_id, approved } => {
            if let Some(approval) = state
                .pending_approvals
                .iter_mut()
                .find(|a| a.txn_id == txn_id)
            {
                approval.status = if approved {
                    ApprovalStatus::Approved
                } else {
                    ApprovalStatus::Denied
                };
            }
        }

        // Tasks
        Action::TaskStarted(upid) => {
            state.push_view(View::TaskLog { upid });
            state.current_task_log.clear();
        }
        Action::TaskLogUpdated { upid, lines } => {
            // Stale-fetch guard: an in-flight fetch for an old UPID must
            // not clobber the current task's log if the user navigated to
            // a different task in the interim.
            if !matches!(state.current_view(), View::TaskLog { upid: u } if u == &upid) {
                return None;
            }
            state.current_task_log = lines;
        }
        Action::GuestTaskFinished { vmid } => {
            state.active_tasks.remove(&vmid);
        }

        Action::GuestStatusPolled {
            vmid,
            status,
            elapsed_secs,
        } => {
            // Live progress: show "ACPI 27s/60s — running" in the spinner
            // column. The reducer is pure — it only writes to AppState.
            // The spawned poll task on the controller side decides when
            // to fire this Action.
            state
                .active_tasks
                .insert(vmid, format!("ACPI {elapsed_secs}s — {status}"));
        }

        Action::ShutdownTimedOut { vmid, elapsed_secs } => {
            // Wrap the hard-stop in the existing Confirm flow — the user
            // must explicitly press `y` before a destructive force-stop.
            // We deliberately do NOT auto-escalate: silent escalation
            // would defeat the entire purpose of "graceful means graceful".
            let name = state
                .guests
                .iter()
                .find(|g| g.vmid == vmid)
                .map(|g| g.name.clone())
                .unwrap_or_default();
            let label = if name.is_empty() {
                format!("vmid {vmid}")
            } else {
                format!("vmid {vmid} ({name})")
            };
            state.mode = AppMode::Confirm {
                description: format!(
                    "ACPI shutdown timed out for {label} after {elapsed_secs}s. Force hard stop?"
                ),
                action: Box::new(Action::StopGuest { vmid, force: true }),
            };
            state.active_tasks.insert(vmid, "ACPI timeout".to_string());
        }

        // Queue
        Action::EnqueueOperation(action) => {
            let queued = queue::QueuedOp::new(action, state);
            state.op_queue.push(queued);
            state.queue_dirty = true;
            state.push_view(View::OperationQueue);
        }
        Action::EnqueueBatchOperation(actions) => {
            for action in actions {
                let queued = queue::QueuedOp::new(action, state);
                state.op_queue.push(queued);
                state.queue_dirty = true;
            }
            state.push_view(View::OperationQueue);
        }
        Action::DequeueOperation(index) => {
            if index < state.op_queue.len() {
                state.op_queue.remove(index);
                state.queue_dirty = true;
            }
        }
        Action::ExecuteQueue => {
            let pending_ops: Vec<_> = state
                .op_queue
                .iter()
                .filter(|o| o.status == queue::OpStatus::Pending)
                .cloned()
                .collect();
            for op in &mut state.op_queue {
                if op.status == queue::OpStatus::Pending {
                    op.status = queue::OpStatus::Running;
                }
            }
            state.queue_dirty = true;
            return Some(SideEffect::ExecuteQueue(pending_ops));
        }
        Action::QueueOpStatusChanged(id, status) => {
            if let Some(op) = state.op_queue.iter_mut().find(|o| o.id == id) {
                op.status = status;
                state.queue_dirty = true;
            }
        }

        // Config Grep
        Action::StartConfigGrep => {
            state.mode = AppMode::ConfigGrep;
            state.push_view(View::ConfigGrep);
            state.grep_query.clear();
            state.grep_results.clear();
        }
        Action::ConfigGrepInput(q) => {
            state.grep_query = q;
        }
        Action::ConfigGrepSubmit => {
            if !state.grep_query.is_empty() {
                state.grep_searching = true;
                return Some(SideEffect::ConfigGrep {
                    query: state.grep_query.clone(),
                });
            }
        }
        Action::ConfigGrepResults { query, matches } => {
            // Stale-fetch guard: a result for a previous query string must
            // not overwrite the current grep_query's results if the user
            // edited the query before the worker returned.
            if state.grep_query != query {
                return None;
            }
            state.grep_results = matches;
            state.grep_searching = false;
        }
    }

    None
}

/// Side effects that the Controller must execute outside the reducer
#[derive(Debug)]
pub enum SideEffect {
    Quit,
    StartGuest {
        vmid: u32,
    },
    StopGuest {
        vmid: u32,
        force: bool,
    },
    RestartGuest {
        vmid: u32,
    },
    DeleteGuest {
        vmid: u32,
    },
    CreateSnapshot {
        vmid: u32,
        name: String,
    },
    MigrateGuest {
        node: String,
        vmid: u32,
        target_node: String,
    },
    ExecuteGuestCommand {
        node: String,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        command: String,
    },

    FetchTaskLog {
        upid: String,
        node: String,
    },
    ExecuteQueue(Vec<crate::app::queue::QueuedOp>),
    ConfigGrep {
        query: String,
    },

    /// Open a PTY-backed SSH session to a guest. The TUI loop owns the
    /// resulting `PtySession`; the reducer only flips the view/mode.
    OpenSshSession {
        vmid: u32,
    },
    /// Tell the TUI loop to drop the active `PtySession`.
    CloseSshSession,

    /// Fetch the snapshot list for `vmid` (feature #7). The TUI loop
    /// resolves the node + type from `state.guests`, calls the API,
    /// and dispatches `Action::SnapshotsLoaded` on completion.
    FetchSnapshotTree {
        vmid: u32,
    },

    /// Feature #5: refresh the HA console data. Multi-fetch — the
    /// controller fires all 6 endpoints in parallel and aggregates.
    FetchHaConsoleData,

    /// Feature #4: refresh PCI/USB inventory + all guest configs for
    /// the assignment scanner. Heavier than HA: O(node) HW + O(guests)
    /// config calls.
    FetchHardwareData {
        node: String,
    },

    /// Trigger a server-side ISO/image download (feature #2).
    DownloadIso {
        node: String,
        storage: String,
        url: String,
        filename: String,
        /// (algo, hex) pinned from the curated library. `None` means
        /// the entry was not pre-pinned (caller already gated, but
        /// kept Option to preserve the Custom-download path symmetry).
        checksum: Option<(String, String)>,
        content: String,
    },

    /// Disk move side effect, dispatched ONLY by queue execution
    /// (never by direct `Action::MoveDisk`) — force-enqueue invariant.
    MoveDisk {
        node: String,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        disk: String,
        target_storage: String,
        delete_source: bool,
    },
    /// Disk resize side effect, dispatched ONLY by queue execution.
    ResizeDisk {
        node: String,
        vmid: u32,
        guest_type: crate::api::types::GuestType,
        disk: String,
        size: String,
    },
}

fn item_count(state: &AppState) -> usize {
    if state.mode == AppMode::Search {
        return search::get_search_results(state).len();
    }
    match state.current_view() {
        View::Dashboard | View::NodeList => state.nodes.len(),
        View::GuestList => state.visible_guests().len(),
        View::StorageList => state.storage.len(),
        View::ApprovalQueue => state.pending_approvals.len(),
        View::OperationQueue => state.op_queue.len(),
        View::ConfigGrep => state.grep_results.len(),
        View::IsoLibrary => crate::app::iso_library::LIBRARY.len(),
        _ => 0,
    }
}

fn handle_select(state: &mut AppState) -> Option<SideEffect> {
    if state.mode == AppMode::Search {
        let results = search::get_search_results(state);
        if let Some((_, item)) = results.get(state.selected_index) {
            let mut pending_action = None;
            match item {
                search::SearchItem::Guest { vmid, .. } => {
                    state.push_view(View::GuestDetail { vmid: *vmid });
                }
                search::SearchItem::Node { .. } => {
                    state.push_view(View::NodeList);
                }
                search::SearchItem::Storage { .. } => {
                    state.push_view(View::StorageList);
                }
                search::SearchItem::Command { action, .. } => {
                    pending_action = Some(action.clone());
                }
            }
            state.mode = AppMode::Normal;
            state.search_query.clear();

            if let Some(act) = pending_action {
                return update(state, act);
            }
        }
        return None;
    }

    match state.current_view() {
        View::Dashboard | View::NodeList => {
            state.push_view(View::GuestList);
        }
        View::GuestList => {
            if let Some(guest) = state.visible_guests().get(state.selected_index) {
                state.push_view(View::GuestDetail { vmid: guest.vmid });
            }
        }
        View::IsoLibrary => {
            // Feature #2: Enter on a library entry → trigger download to
            // the first available storage on the first online node.
            // Pre-MVP UX — a storage picker modal comes later.
            if let Some(entry) = crate::app::iso_library::LIBRARY.get(state.selected_index) {
                if let Some(storage) = state.storage.first().map(|s| s.storage.clone()) {
                    return update(
                        state,
                        Action::DownloadIso {
                            entry_id: entry.id.to_string(),
                            // Empty node → reducer picks first online.
                            node: String::new(),
                            storage,
                        },
                    );
                }
                state.error = Some("No storage available — connect to a cluster first".to_string());
                state.error_time = Some(std::time::Instant::now());
            }
        }
        _ => {}
    }
    None
}

/// Walk a snapshot tree node depth-first, yielding all snapshot names in
/// order (used by the reducer to pick the initial selection).
fn collect_names(node: &crate::app::snaptree::TreeNode) -> Vec<String> {
    let mut out = vec![node.snap.name.clone()];
    for c in &node.children {
        out.extend(collect_names(c));
    }
    out
}

/// Parse a `:command` from the palette. Returns either a `SideEffect` to
/// execute directly, or None if the command isn't recognized.
///
/// The full reducer-level dispatch (e.g. `OpenGuestSsh` pushing a view)
/// happens via Actions rather than `SideEffects`, so commands that need
/// state transitions go through the alternate `parse_command_action`
/// path below.
const fn parse_command(_cmd: &str) -> Option<SideEffect> {
    // No SideEffect-only commands today. Action-producing commands live
    // in `parse_command_action` and are dispatched by the TUI before
    // the reducer's `CommandSubmit` arm runs.
    None
}

/// Parse a `:command` into an Action (used when the command needs a
/// reducer state transition rather than a direct side effect).
#[must_use]
pub fn parse_command_action(cmd: &str) -> Option<Action> {
    let cmd = cmd.trim();
    let mut parts = cmd.split_whitespace();
    let head = parts.next()?;
    match head {
        "ssh" => {
            let vmid_str = parts.next()?;
            let vmid: u32 = vmid_str.parse().ok()?;
            Some(Action::OpenGuestSsh { vmid })
        }
        "snaps" | "tree" | "snapshots" => {
            let vmid_str = parts.next()?;
            let vmid: u32 = vmid_str.parse().ok()?;
            Some(Action::OpenSnapshotTree { vmid })
        }
        "iso" | "images" | "library" => Some(Action::OpenIsoLibrary),
        "ha" | "replication" => Some(Action::OpenHaConsole),
        "hw" | "hardware" | "passthrough" => {
            let node = parts.next()?;
            Some(Action::OpenHardware {
                node: node.to_string(),
            })
        }
        _ => None,
    }
}
