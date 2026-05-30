//! Read-only fleet view — aggregate nodes / guests / storage across
//! EVERY configured profile into one screen.
//!
//! ## Why a separate runner
//!
//! The single-profile TUI (`tui::run`) is built around one
//! `Arc<PxClient>`, one `DataMsg` channel, an `AppState`, an SSH
//! handler, a HITL coordinator, and a keymap full of mutation actions.
//! The fleet view aggregates N clusters and is *strictly read-only*, so
//! it gets its OWN tiny runner instead of being bolted onto that loop.
//! Nothing here touches `AppState`, the `SQLite` cache, or any write
//! method on the gateway — the mutation machinery simply does not exist
//! in this module, which is the structural guarantee that fleet mode
//! cannot mutate a cluster.
//!
//! ## Attribution by containment
//!
//! Each cluster's `Node`/`Guest`/`StoragePool` live inside a
//! [`FleetCluster`] bucket that owns the `profile` name. The domain
//! structs are stored UNMODIFIED — we never add a `profile` field to
//! them (that would change the CLI JSON contract and the cache schema).
//! The `cluster` column in the guest table is synthesised from the
//! bucket, never read off the guest.

// `pub` so the snapshot test harness can call `fleet::view::draw`.
pub mod view;
mod worker;

pub use worker::{fetch_with_gateway, fleet_fetch_all, FleetDataMsg};

use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::mpsc;

use super::event::{self, AppEvent};
use super::terminal_guard::TerminalGuard;
use crate::api::types::{GuestStatus, Node, StoragePool};

/// Fleet poll cadence. Slower than the single-profile loop's 5s: a
/// fleet sweep fans out over N clusters, so 10s halves the aggregate
/// API load and is plenty for an at-a-glance overview.
const FLEET_POLL_SECS: u64 = 10;

/// One cluster/host's slice of the fleet. Attribution lives here: every
/// `Node`/`Guest`/`StoragePool` inside is owned by `profile`.
#[derive(Debug, Clone, Default)]
pub struct FleetCluster {
    pub profile: String,
    /// `false` => unreachable / errored this cycle. The last-known
    /// `nodes`/`guests`/`storage` are RETAINED (not blanked) so a
    /// transient blip doesn't flicker the row empty; `error` says why.
    pub reachable: bool,
    pub error: Option<String>,
    pub nodes: Vec<Node>,
    pub guests: Vec<crate::api::types::Guest>,
    pub storage: Vec<StoragePool>,
}

impl FleetCluster {
    fn empty(profile: &str) -> Self {
        Self {
            profile: profile.to_string(),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn running_guests(&self) -> usize {
        self.guests
            .iter()
            .filter(|g| g.status == GuestStatus::Running)
            .count()
    }

    #[must_use]
    pub fn stopped_guests(&self) -> usize {
        self.guests
            .iter()
            .filter(|g| g.status == GuestStatus::Stopped)
            .count()
    }

    #[must_use]
    pub fn total_cpu_cores(&self) -> u32 {
        self.nodes.iter().map(|n| n.maxcpu).sum()
    }

    #[must_use]
    pub fn mem_used(&self) -> u64 {
        self.nodes.iter().map(|n| n.mem).sum()
    }

    #[must_use]
    pub fn mem_total(&self) -> u64 {
        self.nodes.iter().map(|n| n.maxmem).sum()
    }

    /// Storage usage, de-duplicated by pool name. Shared storage (NFS,
    /// PBS, `CephFS`) is reported once per-node by PVE; summing raw would
    /// multiply a single 4 TB NAS by the node count. We fold by the
    /// `storage` id and count each pool once.
    #[must_use]
    pub fn storage_used(&self) -> u64 {
        self.dedup_storage(|p| p.used)
    }

    #[must_use]
    pub fn storage_total(&self) -> u64 {
        self.dedup_storage(|p| p.total)
    }

    fn dedup_storage(&self, field: impl Fn(&StoragePool) -> u64) -> u64 {
        let mut seen = std::collections::HashSet::new();
        let mut sum = 0u64;
        for p in &self.storage {
            if seen.insert(p.storage.as_str()) {
                sum = sum.saturating_add(field(p));
            }
        }
        sum
    }
}

/// Which content the bottom pane shows. `↑↓` always moves the cluster
/// selection in the summary table; `Tab` flips this.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FleetFocus {
    /// Guests of the currently-selected cluster only.
    #[default]
    SelectedCluster,
    /// Every guest across the whole fleet, with the `cluster` column.
    AllGuests,
}

/// Sort order for the guest pane. Cycled with `s`. `Cluster` is the
/// default and preserves the original stable `(profile, vmid)` order.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FleetSort {
    #[default]
    Cluster,
    Vmid,
    Name,
    Status,
    /// CPU usage, highest first (find the busy guests across the fleet).
    CpuDesc,
    /// Memory usage, highest first.
    MemDesc,
}

impl FleetSort {
    /// Next variant in the cycle (wraps).
    const fn next(self) -> Self {
        match self {
            Self::Cluster => Self::Vmid,
            Self::Vmid => Self::Name,
            Self::Name => Self::Status,
            Self::Status => Self::CpuDesc,
            Self::CpuDesc => Self::MemDesc,
            Self::MemDesc => Self::Cluster,
        }
    }

    /// Short label for the footer.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Cluster => "cluster",
            Self::Vmid => "vmid",
            Self::Name => "name",
            Self::Status => "status",
            Self::CpuDesc => "cpu↓",
            Self::MemDesc => "mem↓",
        }
    }
}

/// Single source of truth for fleet mode. Lives ONLY inside the fleet
/// runner — never inside `AppState` — so the single-profile contract
/// stays pristine. Fields are `pub` so the snapshot/integration tests
/// can build a deterministic state without a constructor.
#[derive(Debug, Clone, Default)]
pub struct FleetState {
    /// Stable, sorted by profile name (matches `fanout.rs` ordering).
    pub clusters: Vec<FleetCluster>,
    pub selected_index: usize,
    pub focus: FleetFocus,
    pub last_sync: Option<Instant>,
    /// Hard error: couldn't even enumerate profiles. Shown as a banner.
    pub fatal: Option<String>,
    /// Case-insensitive filter applied to the guest pane (name / vmid /
    /// node / cluster / tags). Empty = no filter.
    pub search_query: String,
    /// True while the user is typing into the search box (keystrokes
    /// edit `search_query` instead of navigating).
    pub search_active: bool,
    /// Sort order for the guest pane.
    pub sort: FleetSort,
}

impl FleetState {
    const fn select_next(&mut self) {
        if !self.clusters.is_empty() {
            self.selected_index = (self.selected_index + 1) % self.clusters.len();
        }
    }

    fn select_prev(&mut self) {
        if !self.clusters.is_empty() {
            self.selected_index = self
                .selected_index
                .checked_sub(1)
                .unwrap_or(self.clusters.len() - 1);
        }
    }

    const fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            FleetFocus::SelectedCluster => FleetFocus::AllGuests,
            FleetFocus::AllGuests => FleetFocus::SelectedCluster,
        };
    }

    fn cycle_sort(&mut self) {
        self.sort = self.sort.next();
    }

    /// True if a guest matches the active filter (case-insensitive across
    /// cluster / name / vmid / node / tags). Empty query matches all.
    fn matches(&self, profile: &str, g: &crate::api::types::Guest) -> bool {
        if self.search_query.is_empty() {
            return true;
        }
        let q = self.search_query.to_lowercase();
        profile.to_lowercase().contains(&q)
            || g.name.to_lowercase().contains(&q)
            || g.vmid.to_string().contains(&q)
            || g.node.to_lowercase().contains(&q)
            || g.tags.to_lowercase().contains(&q)
    }

    /// `(profile, &Guest)` pairs for the bottom pane, attribution by
    /// containment — filtered by `search_query`, then ordered by `sort`.
    /// Ties always break on `(profile, vmid)` so the order is stable
    /// (deterministic rendering + snapshot diffs).
    #[must_use]
    pub fn visible_guests(&self) -> Vec<(&str, &crate::api::types::Guest)> {
        use crate::api::types::Guest;
        let mut out: Vec<(&str, &Guest)> = match self.focus {
            FleetFocus::SelectedCluster => self
                .clusters
                .get(self.selected_index)
                .map(|c| c.guests.iter().map(|g| (c.profile.as_str(), g)).collect())
                .unwrap_or_default(),
            FleetFocus::AllGuests => self
                .clusters
                .iter()
                .flat_map(|c| c.guests.iter().map(move |g| (c.profile.as_str(), g)))
                .collect(),
        };
        out.retain(|(p, g)| self.matches(p, g));

        let tiebreak =
            |a: &(&str, &Guest), b: &(&str, &Guest)| a.0.cmp(b.0).then(a.1.vmid.cmp(&b.1.vmid));
        out.sort_by(|a, b| {
            let (ga, gb) = (a.1, b.1);
            let primary = match self.sort {
                FleetSort::Cluster => std::cmp::Ordering::Equal, // tiebreak handles it
                FleetSort::Vmid => ga.vmid.cmp(&gb.vmid),
                FleetSort::Name => ga.name.to_lowercase().cmp(&gb.name.to_lowercase()),
                FleetSort::Status => format!("{:?}", ga.status).cmp(&format!("{:?}", gb.status)),
                // Descending: bigger first. partial_cmp can't fail on
                // these finite PVE-sourced values; Equal on the rare NaN.
                FleetSort::CpuDesc => gb
                    .cpu
                    .partial_cmp(&ga.cpu)
                    .unwrap_or(std::cmp::Ordering::Equal),
                FleetSort::MemDesc => gb.mem.cmp(&ga.mem),
            };
            primary.then_with(|| tiebreak(a, b))
        });
        out
    }
}

/// Find the bucket for `profile`, inserting an empty (unreachable) one
/// when first seen. Returns its index in the sorted `clusters` vec.
fn idx_for(clusters: &mut Vec<FleetCluster>, profile: &str) -> usize {
    if let Some(i) = clusters.iter().position(|c| c.profile == profile) {
        return i;
    }
    clusters.push(FleetCluster::empty(profile));
    clusters.sort_by(|a, b| a.profile.cmp(&b.profile));
    clusters
        .iter()
        .position(|c| c.profile == profile)
        .unwrap_or(0)
}

/// Pure reducer: fold one [`FleetDataMsg`] into the [`FleetState`]. No
/// I/O, no clock reads — fully deterministic for unit tests.
pub fn apply(state: &mut FleetState, msg: FleetDataMsg) {
    match msg {
        FleetDataMsg::ClusterSnapshot {
            profile,
            nodes,
            guests,
            storage,
        } => {
            // A successful snapshot anywhere clears a prior fatal
            // (profiles became enumerable again).
            state.fatal = None;
            let i = idx_for(&mut state.clusters, &profile);
            if let Some(c) = state.clusters.get_mut(i) {
                c.nodes = nodes;
                c.guests = guests;
                c.storage = storage;
                c.reachable = true;
                c.error = None;
            }
        }
        FleetDataMsg::ClusterError { profile, error } => {
            let i = idx_for(&mut state.clusters, &profile);
            if let Some(c) = state.clusters.get_mut(i) {
                // Retain last-known data; just flag it stale.
                c.reachable = false;
                c.error = Some(error);
            }
        }
        FleetDataMsg::FatalError(e) => {
            state.fatal = Some(e);
        }
    }
    // Keep the selection in range as clusters appear.
    if state.selected_index >= state.clusters.len() {
        state.selected_index = state.clusters.len().saturating_sub(1);
    }
}

/// Top-level fleet runner. A stripped-down read-only mirror of
/// `tui::run`: terminal guard + a poll worker + a tiny event loop with
/// a navigation-only keymap. No `SideEffect`, no HITL, no SSH, no cache
/// writes — there is no code path from a keystroke to a mutation.
///
/// Returns `Ok(Some(profile))` when the user pressed Enter on a cluster
/// to drill in — the caller (`main.rs`) opens that profile's full
/// single-profile TUI and then re-enters the fleet view. `Ok(None)` on
/// quit. The terminal is torn down before returning either way so the
/// next runner can install its own.
pub async fn run_fleet(cli_secret: Option<&str>) -> Result<Option<String>> {
    let mut guard = TerminalGuard::install()?;
    guard.terminal_mut().clear()?;

    let mut state = FleetState::default();

    let (tx, mut rx) = mpsc::channel::<FleetDataMsg>(64);
    let secret = cli_secret.map(str::to_owned);
    // The worker is the only sender; it owns `tx` for its lifetime.
    let worker = tokio::spawn(async move {
        loop {
            fleet_fetch_all(secret.as_deref(), &tx).await;
            tokio::time::sleep(Duration::from_secs(FLEET_POLL_SECS)).await;
        }
    });

    // 250ms tick guarantees we drain data + redraw ~4×/s even with no
    // keyboard input.
    let mut events = event::spawn_event_loop(Duration::from_millis(250));

    loop {
        let mut dirty = false;
        while let Ok(msg) = rx.try_recv() {
            apply(&mut state, msg);
            dirty = true;
        }
        if dirty {
            state.last_sync = Some(Instant::now());
        }

        guard
            .terminal_mut()
            .draw(|f| view::draw(f, f.area(), &state))?;

        let mut open_profile: Option<String> = None;
        match events.recv().await {
            Some(AppEvent::Key(key)) => match handle_key(&mut state, key) {
                FleetAction::Continue => {}
                FleetAction::Quit => break,
                FleetAction::Open => {
                    open_profile = state
                        .clusters
                        .get(state.selected_index)
                        .map(|c| c.profile.clone());
                }
            },
            Some(AppEvent::Resize(..) | AppEvent::Tick) => {}
            None => break,
        }
        if let Some(profile) = open_profile {
            // Tear down the fleet terminal so the full single-profile TUI
            // can install its own; the caller re-enters the fleet after.
            worker.abort();
            guard.restore()?;
            return Ok(Some(profile));
        }
    }

    worker.abort();
    guard.restore()?;
    Ok(None)
}

/// What a keystroke means in fleet mode.
enum FleetAction {
    Continue,
    Quit,
    /// Enter on the selected cluster — drill into its full TUI.
    Open,
}

/// Navigation + read-only filter/sort keymap. Deliberately NOT
/// `event::map_key` — that maps `s`/`S`/`d` to destructive actions. Every
/// key here is read-only; `Enter` only hands off to the (separately-gated)
/// single-profile TUI. Has two modes: normal navigation, and a search
/// input sub-mode (`state.search_active`) where keystrokes edit the query.
fn handle_key(state: &mut FleetState, key: KeyEvent) -> FleetAction {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return FleetAction::Quit;
    }

    // ── Search input sub-mode: keystrokes edit the filter ──
    if state.search_active {
        match key.code {
            KeyCode::Esc => {
                // Cancel: drop the filter entirely.
                state.search_active = false;
                state.search_query.clear();
            }
            KeyCode::Enter => {
                // Confirm: keep the filter, leave input mode.
                state.search_active = false;
            }
            KeyCode::Backspace => {
                state.search_query.pop();
            }
            KeyCode::Char(c) => state.search_query.push(c),
            _ => {}
        }
        return FleetAction::Continue;
    }

    // ── Normal navigation mode ──
    match key.code {
        KeyCode::Char('q') => return FleetAction::Quit,
        // Esc clears an active filter first; only quits when there's none.
        KeyCode::Esc => {
            if state.search_query.is_empty() {
                return FleetAction::Quit;
            }
            state.search_query.clear();
        }
        KeyCode::Enter => return FleetAction::Open,
        KeyCode::Char('/') => state.search_active = true,
        KeyCode::Char('s') => state.cycle_sort(),
        KeyCode::Char('j') | KeyCode::Down => state.select_next(),
        KeyCode::Char('k') | KeyCode::Up => state.select_prev(),
        KeyCode::Tab | KeyCode::BackTab => state.toggle_focus(),
        _ => {}
    }
    FleetAction::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{Guest, GuestStatus, GuestType, Node, NodeStatus, StoragePool};

    fn node(name: &str, cores: u32, mem: u64, maxmem: u64) -> Node {
        Node {
            node: name.into(),
            status: NodeStatus::Online,
            maxcpu: cores,
            mem,
            maxmem,
            ..Node::default()
        }
    }

    fn guest(vmid: u32, name: &str, running: bool) -> Guest {
        Guest {
            vmid,
            name: name.into(),
            status: if running {
                GuestStatus::Running
            } else {
                GuestStatus::Stopped
            },
            guest_type: GuestType::Qemu,
            ..Guest::default()
        }
    }

    fn pool(name: &str, used: u64, total: u64) -> StoragePool {
        StoragePool {
            storage: name.into(),
            used,
            total,
            ..StoragePool::default()
        }
    }

    fn snapshot(profile: &str, nodes: Vec<Node>, guests: Vec<Guest>) -> FleetDataMsg {
        FleetDataMsg::ClusterSnapshot {
            profile: profile.into(),
            nodes,
            guests,
            storage: vec![],
        }
    }

    #[test]
    fn snapshot_merges_into_named_cluster() {
        let mut s = FleetState::default();
        apply(
            &mut s,
            snapshot(
                "dev",
                vec![node("pve1", 8, 0, 0)],
                vec![guest(100, "a", true)],
            ),
        );
        assert_eq!(s.clusters.len(), 1);
        let c = &s.clusters[0];
        assert_eq!(c.profile, "dev");
        assert!(c.reachable);
        assert!(c.error.is_none());
        assert_eq!(c.nodes.len(), 1);
        assert_eq!(c.guests.len(), 1);
    }

    #[test]
    fn error_marks_cluster_down_without_blanking_others_or_itself() {
        let mut s = FleetState::default();
        apply(
            &mut s,
            snapshot("dev", vec![node("d1", 4, 0, 0)], vec![guest(1, "x", true)]),
        );
        apply(
            &mut s,
            snapshot("prod", vec![node("p1", 4, 0, 0)], vec![guest(2, "y", true)]),
        );
        // prod goes down this cycle.
        apply(
            &mut s,
            FleetDataMsg::ClusterError {
                profile: "prod".into(),
                error: "connection refused".into(),
            },
        );
        let dev = s.clusters.iter().find(|c| c.profile == "dev").unwrap();
        let prod = s.clusters.iter().find(|c| c.profile == "prod").unwrap();
        // dev untouched.
        assert!(dev.reachable);
        assert_eq!(dev.guests.len(), 1);
        // prod flagged down but retains last-known data (no flicker).
        assert!(!prod.reachable);
        assert_eq!(prod.error.as_deref(), Some("connection refused"));
        assert_eq!(prod.guests.len(), 1, "down cluster keeps prior data");
    }

    #[test]
    fn first_cycle_error_inserts_empty_unreachable_bucket() {
        let mut s = FleetState::default();
        apply(
            &mut s,
            FleetDataMsg::ClusterError {
                profile: "lab".into(),
                error: "timeout".into(),
            },
        );
        assert_eq!(s.clusters.len(), 1);
        assert!(!s.clusters[0].reachable);
        assert!(s.clusters[0].guests.is_empty());
    }

    #[test]
    fn clusters_stay_sorted_by_profile_regardless_of_arrival_order() {
        let mut s = FleetState::default();
        apply(&mut s, snapshot("zeta", vec![], vec![]));
        apply(&mut s, snapshot("alpha", vec![], vec![]));
        apply(&mut s, snapshot("mike", vec![], vec![]));
        let names: Vec<&str> = s.clusters.iter().map(|c| c.profile.as_str()).collect();
        assert_eq!(names, ["alpha", "mike", "zeta"]);
    }

    #[test]
    fn repeated_snapshot_updates_in_place_not_duplicates() {
        let mut s = FleetState::default();
        apply(
            &mut s,
            snapshot("dev", vec![node("d1", 4, 0, 0)], vec![guest(1, "x", true)]),
        );
        apply(
            &mut s,
            snapshot("dev", vec![node("d1", 4, 0, 0)], vec![guest(1, "x", false)]),
        );
        assert_eq!(s.clusters.len(), 1);
        assert_eq!(s.clusters[0].stopped_guests(), 1);
    }

    #[test]
    fn fatal_sets_banner_without_panicking_or_dropping_clusters() {
        let mut s = FleetState::default();
        apply(&mut s, snapshot("dev", vec![], vec![]));
        apply(&mut s, FleetDataMsg::FatalError("config unreadable".into()));
        assert_eq!(s.fatal.as_deref(), Some("config unreadable"));
        assert_eq!(s.clusters.len(), 1);
        // A later good snapshot clears the banner.
        apply(&mut s, snapshot("dev", vec![], vec![]));
        assert!(s.fatal.is_none());
    }

    #[test]
    fn all_guests_pairs_each_guest_with_its_own_profile_even_on_shared_vmid() {
        let mut s = FleetState::default();
        // Same VMID 100 exists on both clusters — attribution must
        // come from the bucket, not the guest struct.
        apply(
            &mut s,
            snapshot("dev", vec![], vec![guest(100, "dev-vm", true)]),
        );
        apply(
            &mut s,
            snapshot("prod", vec![], vec![guest(100, "prod-vm", true)]),
        );
        s.focus = FleetFocus::AllGuests;
        let pairs = s.visible_guests();
        assert_eq!(pairs.len(), 2);
        // Sorted by (profile, vmid): dev first, prod second.
        assert_eq!(pairs[0].0, "dev");
        assert_eq!(pairs[0].1.name, "dev-vm");
        assert_eq!(pairs[1].0, "prod");
        assert_eq!(pairs[1].1.name, "prod-vm");
    }

    #[test]
    fn selected_cluster_focus_shows_only_that_cluster_guests() {
        let mut s = FleetState::default();
        apply(
            &mut s,
            snapshot(
                "alpha",
                vec![],
                vec![guest(1, "a1", true), guest(2, "a2", true)],
            ),
        );
        apply(&mut s, snapshot("beta", vec![], vec![guest(9, "b1", true)]));
        s.selected_index = 0; // alpha
        s.focus = FleetFocus::SelectedCluster;
        let pairs = s.visible_guests();
        assert_eq!(pairs.len(), 2);
        assert!(pairs.iter().all(|(p, _)| *p == "alpha"));
    }

    #[test]
    fn storage_usage_dedupes_shared_pools_across_nodes() {
        let c = FleetCluster {
            profile: "x".into(),
            reachable: true,
            error: None,
            nodes: vec![],
            guests: vec![],
            // "nfs" reported by 3 nodes; "local" distinct per node name.
            storage: vec![
                pool("nfs", 1000, 4000),
                pool("nfs", 1000, 4000),
                pool("nfs", 1000, 4000),
                pool("local", 50, 100),
            ],
        };
        // nfs counted once (1000/4000) + local (50/100).
        assert_eq!(c.storage_used(), 1050);
        assert_eq!(c.storage_total(), 4100);
    }

    #[test]
    fn aggregate_cpu_and_mem_sum_across_nodes() {
        let c = FleetCluster {
            profile: "x".into(),
            reachable: true,
            error: None,
            nodes: vec![node("n1", 8, 16, 64), node("n2", 16, 32, 128)],
            guests: vec![],
            storage: vec![],
        };
        assert_eq!(c.total_cpu_cores(), 24);
        assert_eq!(c.mem_used(), 48);
        assert_eq!(c.mem_total(), 192);
    }

    #[test]
    fn selection_wraps_and_stays_in_range() {
        let mut s = FleetState::default();
        apply(&mut s, snapshot("a", vec![], vec![]));
        apply(&mut s, snapshot("b", vec![], vec![]));
        assert_eq!(s.selected_index, 0);
        s.select_prev(); // wrap to last
        assert_eq!(s.selected_index, 1);
        s.select_next(); // wrap to first
        assert_eq!(s.selected_index, 0);
    }

    fn fleet_with_two() -> FleetState {
        let mut s = FleetState::default();
        apply(
            &mut s,
            snapshot(
                "alpha",
                vec![],
                vec![guest(100, "web-prod", true), guest(101, "db", false)],
            ),
        );
        apply(
            &mut s,
            snapshot("beta", vec![], vec![guest(200, "web-test", true)]),
        );
        s.focus = FleetFocus::AllGuests;
        s
    }

    #[test]
    fn search_filters_across_name_vmid_node_cluster_tags() {
        let mut s = fleet_with_two();
        // name match
        s.search_query = "web".into();
        let names: Vec<&str> = s
            .visible_guests()
            .iter()
            .map(|(_, g)| g.name.as_str())
            .collect();
        assert_eq!(names, ["web-prod", "web-test"]);
        // cluster match
        s.search_query = "beta".into();
        let v = s.visible_guests();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, "beta");
        // vmid substring match
        s.search_query = "101".into();
        let v = s.visible_guests();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].1.vmid, 101);
    }

    #[test]
    fn search_is_case_insensitive_and_empty_matches_all() {
        let mut s = fleet_with_two();
        s.search_query = "WEB-PROD".into();
        assert_eq!(s.visible_guests().len(), 1);
        s.search_query = String::new();
        assert_eq!(s.visible_guests().len(), 3);
    }

    #[test]
    fn no_match_yields_empty_not_panic() {
        let mut s = fleet_with_two();
        s.search_query = "zzz-nope".into();
        assert!(s.visible_guests().is_empty());
    }

    #[test]
    fn sort_cycle_visits_all_then_wraps() {
        let mut s = FleetState::default();
        assert_eq!(s.sort, FleetSort::Cluster);
        let seq = [
            FleetSort::Vmid,
            FleetSort::Name,
            FleetSort::Status,
            FleetSort::CpuDesc,
            FleetSort::MemDesc,
            FleetSort::Cluster, // wrap
        ];
        for expected in seq {
            s.cycle_sort();
            assert_eq!(s.sort, expected);
        }
    }

    #[test]
    fn sort_by_vmid_orders_ascending_across_clusters() {
        let mut s = fleet_with_two();
        s.sort = FleetSort::Vmid;
        let ids: Vec<u32> = s.visible_guests().iter().map(|(_, g)| g.vmid).collect();
        assert_eq!(ids, [100, 101, 200]);
    }

    #[test]
    fn sort_by_mem_desc_puts_biggest_first() {
        let mut s = FleetState::default();
        let big = Guest {
            vmid: 1,
            name: "big".into(),
            mem: 9_000,
            ..Guest::default()
        };
        let small = Guest {
            vmid: 2,
            name: "small".into(),
            mem: 10,
            ..Guest::default()
        };
        apply(
            &mut s,
            FleetDataMsg::ClusterSnapshot {
                profile: "x".into(),
                nodes: vec![],
                guests: vec![small, big],
                storage: vec![],
            },
        );
        s.focus = FleetFocus::AllGuests;
        s.sort = FleetSort::MemDesc;
        let order: Vec<&str> = s
            .visible_guests()
            .iter()
            .map(|(_, g)| g.name.as_str())
            .collect();
        assert_eq!(order, ["big", "small"]);
    }

    #[test]
    fn esc_in_search_input_cancels_and_clears() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut s = fleet_with_two();
        // enter search, type, then Esc cancels
        handle_key(&mut s, KeyEvent::from(KeyCode::Char('/')));
        assert!(s.search_active);
        handle_key(&mut s, KeyEvent::from(KeyCode::Char('w')));
        handle_key(&mut s, KeyEvent::from(KeyCode::Char('e')));
        assert_eq!(s.search_query, "we");
        handle_key(&mut s, KeyEvent::from(KeyCode::Esc));
        assert!(!s.search_active);
        assert!(s.search_query.is_empty());
    }

    #[test]
    fn enter_in_search_input_keeps_filter() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut s = fleet_with_two();
        handle_key(&mut s, KeyEvent::from(KeyCode::Char('/')));
        handle_key(&mut s, KeyEvent::from(KeyCode::Char('d')));
        handle_key(&mut s, KeyEvent::from(KeyCode::Char('b')));
        let act = handle_key(&mut s, KeyEvent::from(KeyCode::Enter));
        // Enter confirms the filter — must NOT be read as "drill in".
        assert!(matches!(act, FleetAction::Continue));
        assert!(!s.search_active);
        assert_eq!(s.search_query, "db");
    }

    #[test]
    fn esc_in_normal_mode_clears_filter_before_quitting() {
        use crossterm::event::{KeyCode, KeyEvent};
        let mut s = fleet_with_two();
        s.search_query = "web".into();
        // first Esc clears the filter (Continue), not quit
        let a1 = handle_key(&mut s, KeyEvent::from(KeyCode::Esc));
        assert!(matches!(a1, FleetAction::Continue));
        assert!(s.search_query.is_empty());
        // second Esc (no filter) quits
        let a2 = handle_key(&mut s, KeyEvent::from(KeyCode::Esc));
        assert!(matches!(a2, FleetAction::Quit));
    }
}
