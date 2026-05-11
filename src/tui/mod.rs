// TUI module — Terminal setup, event loop, render dispatch
// The Controller in our Actor model: receives events, updates state, triggers render.
// 3 actors: UI (crossterm), API Worker (tokio), Controller (this loop).

// `event` is `pub` so integration tests in `tests/console_test.rs`
// can import `map_key` and pin the keymap → action contract.
pub mod event;
mod ssh_handler;
mod terminal_guard;
mod theme;
// `views` + `widgets` are `pub` for the TUI snapshot test harness in
// `tests/tui_snapshot.rs`. They are NOT part of the proxxx public
// API and may change shape without a major version bump — the only
// stable contract here is the `(Frame, Rect, &AppState)` signature.
pub mod views;
pub mod widgets;

use terminal_guard::TerminalGuard;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    execute,
    terminal::{enable_raw_mode, EnterAlternateScreen},
};
use ratatui::Frame;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::api::types::{Guest, Node, StoragePool};
use crate::api::{ProxmoxGateway, PxClient};
use crate::app::{self, Action, AppState, SideEffect, View};
use crate::config;

// ── Data messages from the API worker back to the controller ──
enum DataMsg {
    Nodes(Vec<Node>),
    Guests(Vec<Guest>),
    Storage(Vec<StoragePool>),
    ClusterTasks(Vec<crate::api::types::TaskInfo>),
    /// live cluster-quorum status. `false` means proxxx is
    /// talking to a node that has lost quorum and any data we render
    /// from this point may be stale.
    ClusterQuorate(bool),
    Error(String),
    HitlRequested(String, String),               // txn_id, description
    HitlApproved(String, bool, Box<SideEffect>), // txn_id, approved, action
    TaskStarted(String),                         // upid
    TaskLogUpdated {
        upid: String,
        lines: Vec<crate::api::types::TaskLogLine>,
    },
    GuestTaskFinished(u32),
    QueueOpStatusChanged(String, crate::app::queue::OpStatus),
    ConfigGrepResults {
        query: String,
        matches: Vec<crate::app::GrepMatch>,
    },
    /// SSH PTY open task finished. `error` is None on success.
    SshSessionOpenResult {
        vmid: u32,
        error: Option<String>,
    },
    /// Bug #2 enhancement: a graceful shutdown didn't reach `stopped`
    /// state within the polling window. The polling task lives in the
    /// API worker pool — never on the render thread — so this message
    /// arrives asynchronously and unblocks the user with a Confirm modal.
    ShutdownTimeout {
        vmid: u32,
        elapsed_secs: u64,
    },
    /// Per-poll status update from the shutdown poller. Forwarded into
    /// `Action::GuestStatusPolled` so the reducer can surface a live
    /// countdown.
    GuestStatusPolled {
        vmid: u32,
        status: String,
        elapsed_secs: u64,
    },
    /// Feature #7: snapshot list fetched. Reducer assembles the tree.
    SnapshotsLoaded {
        vmid: u32,
        snaps: Vec<crate::api::types::Snapshot>,
    },
    /// Feature #4: hardware inventory + guest configs fetched.
    HwData {
        node: String,
        pci: Vec<crate::api::types::PciDevice>,
        usb: Vec<crate::api::types::UsbDevice>,
        configs: std::collections::HashMap<u32, std::collections::HashMap<String, String>>,
    },
    /// Feature #5: HA console aggregated data fetched.
    HaData {
        groups: Vec<crate::api::types::HaGroup>,
        resources: Vec<crate::api::types::HaResource>,
        manager: crate::api::types::HaManagerStatus,
        cluster: Vec<crate::api::types::ClusterStatusEntry>,
        repl_status: Vec<crate::api::types::ReplicationStatus>,
    },
}

/// Coordinator for in-flight HITL approval requests.
///
/// Solves two problems at once:
/// 1. Routing: when the Telegram callback arrives with `txn_id`, we
///    need to deliver `approved: bool` to the specific spawned task
///    that's awaiting it. Map `txn_id → oneshot::Sender<bool>`.
/// 2. Concurrency: only ONE long-poll on the bot at a time
///    (Telegram returns 409 Conflict if you call `getUpdates`
///    concurrently from the same bot). The coordinator owns the
///    single poller.
///
/// Pre-fix the TUI used a sleep+auto-approve simulation — the
/// reviewer caught it and we replaced it with this real path.
struct HitlCoordinator {
    pending:
        tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::oneshot::Sender<bool>>>,
}

impl HitlCoordinator {
    fn new() -> Self {
        Self {
            pending: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Register a pending approval and get back the receiver to await.
    async fn register(&self, txn_id: String) -> tokio::sync::oneshot::Receiver<bool> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending.lock().await.insert(txn_id, tx);
        rx
    }

    /// Drop a pending registration (used on Telegram-send failure).
    async fn unregister(&self, txn_id: &str) {
        self.pending.lock().await.remove(txn_id);
    }

    /// Resolve a pending approval with the user's decision. Called
    /// from the poller when a `callback_query` arrives.
    async fn resolve(&self, txn_id: &str, approved: bool) {
        // Drop the lock BEFORE sending on the oneshot. Holding it
        // across `sender.send(...)` is harmless today (send() is
        // non-blocking) but keeps the lock scope tighter than needed
        // and trips clippy's significant_drop_in_scrutinee.
        let sender = self.pending.lock().await.remove(txn_id);
        if let Some(s) = sender {
            let _ = s.send(approved);
        }
    }
}

/// Single poller task. Long-polls Telegram `getUpdates` and routes
/// callback queries to the coordinator. Runs until the TUI exits.
async fn run_hitl_poller(
    tg: Arc<crate::hitl::telegram::TelegramGateway>,
    coord: Arc<HitlCoordinator>,
) {
    let mut offset: i64 = 0;
    let mut backoff = Duration::from_secs(1);
    const BACKOFF_CAP: Duration = Duration::from_mins(1);
    loop {
        match tg.poll_updates(offset, 30).await {
            Ok(updates) => {
                backoff = Duration::from_secs(1);
                for u in updates {
                    offset = offset.max(u.update_id + 1);
                    let Some(cb) = u.callback_query else { continue };
                    let Some(data) = cb.data else { continue };
                    let Some((decision, txn_id)) = data.split_once(':') else {
                        continue;
                    };
                    let approved = decision == "approve";
                    let confirm_text = if approved {
                        "✅ Executed"
                    } else {
                        "🚫 Denied"
                    };
                    let _ = tg.answer_callback(&cb.id, confirm_text).await;
                    coord.resolve(txn_id, approved).await;
                }
            }
            Err(e) => {
                warn!("HITL Telegram poll error: {e:#} — backing off {backoff:?}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_CAP);
            }
        }
    }
}

/// Main TUI entry point — runs until user quits
pub async fn run(profile: Option<&str>, cli_secret: Option<&str>, secure: bool) -> Result<()> {
    // ── Connect to Proxmox ──────────────────────────────
    let config = match config::load_config(profile) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("⚠ Config error: {e}");
            eprintln!("  Run with `--profile <name>` or create ~/.config/proxxx/config.toml");
            eprintln!("  Starting with demo data...\n");
            // Fall back to demo mode
            return run_demo().await;
        }
    };

    let policies = config.policies.clone().unwrap_or_default();
    let config_for_ssh = config.clone();

    let client = match PxClient::new(config, cli_secret).await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("⚠ Connection failed: {e}");
            eprintln!("  Starting with demo data...\n");
            return run_demo().await;
        }
    };

    // ── SSH session handler (feature 1a) ──────────────────
    // Built unconditionally. If the profile has no [ssh] block (or has
    // a broken known_hosts), the handler still works as a no-op — opens
    // surface a clear error rather than crashing the TUI.
    let ssh_handler = Arc::new(ssh_handler::SshSessionHandler::new(config_for_ssh));

    // ── HITL coordinator (real Telegram round-trip) ───────
    //
    // P0 reviewer finding: the TUI used to "simulate" approval by
    // sleeping 3 s and auto-approving. Replaced with a real Telegram
    // request_approval + a single shared poller that dispatches
    // callback decisions to the matching pending oneshot.
    //
    // The coordinator is built only if `[telegram]` is configured.
    // Without it, secure_mode / policy gates on the TUI side become
    // hard refusals (better safe than secretly bypassing).
    let hitl_coord = Arc::new(HitlCoordinator::new());
    // Phase 5.13 — bot_token now resolves via env / file / inline /
    // keychain hierarchy. A plaintext token in TOML is the lowest
    // priority. If resolution fails (e.g. env var set but file 0644),
    // the gateway is None — secure_mode/policy gates then refuse
    // destructive ops loudly rather than silently bypassing.
    let tg_gateway: Option<Arc<crate::hitl::telegram::TelegramGateway>> =
        match client.profile_config().telegram.as_ref() {
            None => None,
            Some(cfg) => match crate::hitl::telegram::TelegramGateway::from_config(cfg).await {
                Ok(g) => Some(Arc::new(g)),
                Err(e) => {
                    tracing::warn!("Telegram gateway init failed: {e:#} — HITL gates will refuse");
                    None
                }
            },
        };
    // Phase 8 audit fix: capture the JoinHandle so we can abort the
    // poller cleanly on TUI quit AND log if it died on its own (e.g.
    // Telegram credential revoked, panic) before quit fired. Without
    // the handle the task was dropped silently when the runtime tore
    // down — operators saw "TUI exited cleanly" even when HITL had
    // died hours earlier.
    let hitl_handle: Option<tokio::task::JoinHandle<()>> = tg_gateway.as_ref().map(|tg| {
        let coord_clone = Arc::clone(&hitl_coord);
        let tg_clone = Arc::clone(tg);
        tokio::spawn(async move {
            run_hitl_poller(tg_clone, coord_clone).await;
        })
    });

    // flight recorder: panic hook is now installed in main() via
    // util::panic_hook::install() — it runs for both TUI and CLI
    // mode and is idempotent. The previous TUI-only hook is gone.

    // ── Terminal Setup ───────────────────────────────────
    //
    // route through TerminalGuard so an early `?` between here
    // and the explicit teardown at the bottom restores the terminal
    // via Drop instead of stranding the user in raw mode. The guard
    // OUTLIVES `terminal` (one re-borrow); on drop it disables raw
    // mode + leaves alt screen even if any `?` below short-circuits.
    let mut term_guard = TerminalGuard::install()?;
    let terminal = term_guard.terminal_mut();
    terminal.clear()?;

    info!("TUI started — connected to Proxmox");

    let profile_name = profile.map(std::string::ToString::to_string);

    // ── State ───────────────────────────────────────────
    let mut state = AppState::new();
    // Bug #7 fix: wire --secure CLI flag through to the reducer state.
    // Previously parsed but never applied → Self-HITL never triggered,
    // silently bypassing the gate the user thought they'd enabled.
    state.secure_mode = secure;
    if secure {
        info!("Self-HITL secure mode active: destructive ops require Telegram approval");
    }

    // Load state from cache for instant startup
    if let Ok(cached) = crate::app::cache::load_state(profile_name.as_deref()) {
        state.nodes = cached.nodes;
        state.guests = cached.guests;
        state.storage = cached.storage;
        state.is_loading = false;
        info!("Loaded state from cache. Timestamp: {}", cached.timestamp);
    }

    // Architectural review #2: restore the operation queue from SQLite.
    // If proxxx crashed or the user quit mid-disk-move, the in-flight
    // ops surface again with their last-known status (Running/Error/etc.)
    // so the user can inspect, retry, or dismiss.
    if let Ok(persisted) = crate::app::cache::load_queue(profile_name.as_deref()) {
        if !persisted.is_empty() {
            info!(
                "Restored {} queue entries from previous session",
                persisted.len()
            );
            state.op_queue = persisted
                .into_iter()
                .map(crate::app::queue::QueuedOp::from_persisted)
                .collect();
        }
    }

    // Load historical storage data (e.g. from 24h ago) to compute trend and ETA
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let past = now.saturating_sub(24 * 3600);
    if let Ok(past_cache) = crate::app::cache::load_state_at(profile_name.as_deref(), past) {
        for pool in past_cache.storage {
            state
                .storage_trend
                .insert(pool.storage.clone(), (past_cache.timestamp, pool.used));
        }
    }

    // ── Data channel (API worker → Controller) ──────────
    let (data_tx, mut data_rx) = mpsc::channel::<DataMsg>(32);

    // ── Spawn API worker ────────────────────────────────
    // Fetches data on startup and every 5 seconds.
    //
    // Phase 8 audit fix: capture the JoinHandle for the same reason as
    // the HITL poller above — graceful abort + post-mortem logging
    // instead of silently dropping the task on runtime teardown.
    let worker_client = Arc::clone(&client);
    let worker_tx = data_tx.clone();
    let api_worker_handle: tokio::task::JoinHandle<()> = tokio::spawn(async move {
        loop {
            fetch_all(&worker_client, &worker_tx).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });

    // ── Event Loop (UI events) ──────────────────────────
    let mut events = event::spawn_event_loop(Duration::from_millis(200));

    // Phase 8 audit fix: pin the shutdown future outside the loop so we
    // can poll it across iterations via `&mut`. SIGINT/SIGTERM during
    // the TUI cleanly triggers teardown (cache flush, terminal restore)
    // instead of dying on runtime drop. The `q` keypath still works as
    // before — both paths converge on `break` then teardown.
    let mut shutdown_signal = Box::pin(crate::util::shutdown::wait_for_shutdown_signal());

    // (Gemini audit) — resize debounce. While the user
    // drags the terminal corner, the OS fires Resize events at
    // ~60 Hz. Forwarding each one to the SSH PTY would flood the
    // remote sshd with window-change packets and risk
    // desynchronisation. Coalesce: keep only the most recent size
    // and forward it once the drag has been quiet for >= 50 ms,
    // checked on every loop iteration.
    let mut pending_pty_resize: Option<(u16, u16)> = None;
    let mut last_resize_event_at: Option<std::time::Instant> = None;
    const RESIZE_QUIET_MS: u128 = 50;

    loop {
        // flush a debounced PTY resize once the drag has
        // been quiet long enough. This runs every loop iteration; the
        // 200 ms Tick guarantees we re-check at least 5×/sec even
        // when no other event arrives.
        if let (Some((w, rows)), Some(last)) = (pending_pty_resize, last_resize_event_at) {
            if last.elapsed().as_millis() >= RESIZE_QUIET_MS
                && matches!(state.mode, app::AppMode::SshSession { .. })
            {
                ssh_handler.resize(w, rows);
                pending_pty_resize = None;
                last_resize_event_at = None;
            }
        }

        // Architectural review #2: flush queue to SQLite if it changed
        // since the last tick. Done before render so the on-disk state
        // is always at-least-as-fresh-as what's drawn. Best-effort —
        // a transient SQLite error is logged but doesn't kill the loop.
        //
        // Phase 12 audit fix: route through `save_queue_async` so the
        // SQLite write happens on `spawn_blocking` instead of pinning
        // this runtime worker for up to `busy_timeout` (5000 ms) under
        // WAL-checkpoint contention. Pre-fix, a contended write here
        // would stall every keypress and every API tick for the same
        // 5-second window.
        if state.queue_dirty {
            let entries: Vec<crate::app::cache::PersistedQueueEntry> = state
                .op_queue
                .iter()
                .filter_map(super::app::queue::QueuedOp::to_persisted)
                .collect();
            if let Err(e) = crate::app::cache::save_queue_async(profile_name.clone(), entries).await
            {
                warn!("queue persistence write failed: {e:#}");
            }
            state.queue_dirty = false;
        }

        // Render current state
        let render_ssh_handler = Arc::clone(&ssh_handler);
        terminal.draw(|f| draw(f, &state, &render_ssh_handler))?;

        // Auto-close on remote shell exit. Done before multiplex so the
        // very next render reflects the closed state.
        if matches!(state.mode, app::AppMode::SshSession { .. }) && ssh_handler.is_finished() {
            ssh_handler.close();
            app::update(&mut state, Action::CloseSshSession);
            continue;
        }

        // Multiplex: shutdown signal + UI events + data messages.
        //
        // Phase 8 audit fix: `biased;` orders the arms by priority so
        // SIGINT/SIGTERM and UI events (the user's `q`) cannot be
        // starved by a busy data channel. Without it, tokio's fair
        // (random) select policy could pick the data arm up to ~5 s
        // longer than the user's keypress — visible as quit latency
        // on a slow API tick. `biased` makes the policy deterministic.
        tokio::select! {
            biased;
            // External shutdown signal (SIGINT / SIGTERM) — top priority.
            () = &mut shutdown_signal => {
                info!("TUI: shutdown signal received, exiting cleanly");
                break;
            }
            // UI event (keyboard, tick, resize)
            evt = events.recv() => {
                if let Some(evt) = evt {
                    match evt {
                        event::AppEvent::Key(key) => {
                            // (Gemini wave-3 audit) — Ctrl+L force-redraw.
                            //
                            // crossterm doesn't auto-recover from SIGTSTP/SIGCONT
                            // (Ctrl+Z then `fg`). When the user resumes proxxx
                            // after backgrounding it, the terminal may have lost
                            // the alternate-screen / raw-mode state because the
                            // shell parent reset them. Pressing Ctrl+L re-applies
                            // both and clears the screen — pure terminal hygiene,
                            // no reducer involvement. Works everywhere (NORMAL,
                            // SearchSession, SshSession), so we intercept BEFORE
                            // the SSH/keymap dispatch.
                            {
                                use crossterm::event::{KeyCode, KeyModifiers};
                                if key.modifiers.contains(KeyModifiers::CONTROL)
                                    && matches!(key.code, KeyCode::Char('l'))
                                {
                                    let _ = enable_raw_mode();
                                    let _ = execute!(
                                        terminal.backend_mut(),
                                        EnterAlternateScreen
                                    );
                                    let _ = terminal.clear();
                                    continue;
                                }
                            }
                            // SSH PTY mode bypasses normal key mapping:
                            // Ctrl+] exits, every other key is forwarded
                            // to the remote shell as a byte sequence.
                            if matches!(state.mode, app::AppMode::SshSession { .. }) {
                                use crossterm::event::{KeyCode, KeyModifiers};
                                if key.modifiers.contains(KeyModifiers::CONTROL)
                                    && matches!(key.code, KeyCode::Char(']'))
                                {
                                    ssh_handler.close();
                                    app::update(&mut state, Action::CloseSshSession);
                                } else {
                                    ssh_handler.forward_key(&key);
                                }
                            } else if let Some(action) = event::map_key(key, &state) {
                                let effect = app::update(&mut state, action);
                                match effect {
                                    Some(SideEffect::Quit) => break,
                                    Some(SideEffect::OpenSshSession { vmid }) => {
                                        let h = Arc::clone(&ssh_handler);
                                        let tx_c = data_tx.clone();
                                        let area = terminal.size().unwrap_or_default();
                                        let cols = area.width.max(20);
                                        let rows = area.height.saturating_sub(2).max(5);
                                        tokio::spawn(async move {
                                            let res = h.open(vmid, cols, rows).await;
                                            let error = res.err().map(|e| format!("{e:#}"));
                                            let _ = tx_c
                                                .send(DataMsg::SshSessionOpenResult { vmid, error })
                                                .await;
                                        });
                                    }
                                    Some(SideEffect::CloseSshSession) => {
                                        ssh_handler.close();
                                    }
                                    Some(other) => {
                                        dispatch_side_effect(
                                            other,
                                            &state,
                                            &client,
                                            &data_tx,
                                            &policies,
                                            false,
                                            tg_gateway.as_ref(),
                                            &hitl_coord,
                                        ).await;
                                    }
                                    None => {}
                                }
                            }
                        }
                        event::AppEvent::Tick => {
                            let _ = app::update(&mut state, Action::Tick);
                        }
                        event::AppEvent::Resize(w, h) => {
                            // stage the latest dimensions and
                            // a quiet-period clock. The actual
                            // SSH window-change is sent below once the
                            // drag goes quiet for >= RESIZE_QUIET_MS.
                            if matches!(state.mode, app::AppMode::SshSession { .. }) {
                                let rows = h.saturating_sub(2).max(5);
                                pending_pty_resize = Some((w, rows));
                                last_resize_event_at = Some(std::time::Instant::now());
                            }
                        }
                    }
                }
            }
            // Data from API worker
            msg = data_rx.recv() => {
                if let Some(msg) = msg {
                    match msg {
                        DataMsg::Nodes(nodes) => {
                            app::update(&mut state, Action::NodesLoaded(nodes));
                        }
                        DataMsg::Guests(guests) => {
                            app::update(&mut state, Action::GuestsLoaded(guests));
                        }
                        DataMsg::Storage(storage) => {
                            app::update(&mut state, Action::StorageLoaded(storage));
                            // Save to cache once a full sync cycle is complete.
                            // Phase 12 audit fix: async wrapper so the SQLite
                            // write doesn't pin this runtime worker through
                            // the busy_timeout under WAL-checkpoint contention.
                            let _ = crate::app::cache::save_state_async(
                                profile_name.clone(),
                                state.nodes.clone(),
                                state.guests.clone(),
                                state.storage.clone(),
                            )
                            .await;
                        }
                        DataMsg::ClusterTasks(tasks) => {
                            app::update(&mut state, Action::ClusterTasksLoaded(tasks));
                        }
                        DataMsg::ClusterQuorate(q) => {
                            app::update(&mut state, Action::ClusterQuorateLoaded(q));
                        }
                        DataMsg::Error(err) => {
                            app::update(&mut state, Action::ErrorOccurred(err));
                        }
                        DataMsg::HitlRequested(txn_id, description) => {
                            app::update(&mut state, Action::ApprovalRequested { txn_id, description });
                        }
                        DataMsg::HitlApproved(txn_id, approved, effect) => {
                            app::update(&mut state, Action::ApprovalReceived { txn_id, approved });
                            if approved {
                                // Execute the original blocked side effect
                                dispatch_side_effect(
                                    *effect,
                                    &state,
                                    &client,
                                    &data_tx,
                                    &policies,
                                    true,
                                    tg_gateway.as_ref(),
                                    &hitl_coord,
                                ).await;
                            }
                        }
                        DataMsg::TaskStarted(upid) => {
                            app::update(&mut state, Action::TaskStarted(upid));
                        }
                        DataMsg::TaskLogUpdated { upid, lines } => {
                            app::update(&mut state, Action::TaskLogUpdated { upid, lines });
                        }
                        DataMsg::GuestTaskFinished(vmid) => {
                            app::update(&mut state, Action::GuestTaskFinished { vmid });
                        }
                        DataMsg::QueueOpStatusChanged(id, status) => {
                            app::update(&mut state, Action::QueueOpStatusChanged(id, status));
                        }
                        DataMsg::ConfigGrepResults { query, matches } => {
                            app::update(
                                &mut state,
                                Action::ConfigGrepResults { query, matches },
                            );
                        }
                        DataMsg::SshSessionOpenResult { vmid, error } => {
                            if let Some(err) = error {
                                app::update(
                                    &mut state,
                                    Action::SshSessionFailed { vmid, error: err },
                                );
                            }
                            // Success: the handler already holds the
                            // PtySession; the parser will surface in the
                            // next render frame. No reducer change needed.
                        }
                        DataMsg::ShutdownTimeout { vmid, elapsed_secs } => {
                            app::update(
                                &mut state,
                                Action::ShutdownTimedOut { vmid, elapsed_secs },
                            );
                        }
                        DataMsg::GuestStatusPolled { vmid, status, elapsed_secs } => {
                            app::update(
                                &mut state,
                                Action::GuestStatusPolled {
                                    vmid,
                                    status,
                                    elapsed_secs,
                                },
                            );
                        }
                        DataMsg::SnapshotsLoaded { vmid, snaps } => {
                            app::update(
                                &mut state,
                                Action::SnapshotsLoaded { vmid, snaps },
                            );
                        }
                        DataMsg::HwData { node, pci, usb, configs } => {
                            app::update(
                                &mut state,
                                Action::HwDataLoaded { node, pci, usb, configs },
                            );
                        }
                        DataMsg::HaData {
                            groups,
                            resources,
                            manager,
                            cluster,
                            repl_status,
                        } => {
                            app::update(
                                &mut state,
                                Action::HaDataLoaded {
                                    groups,
                                    resources,
                                    manager,
                                    cluster,
                                    repl_status,
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    // ── Background task teardown ─────────────────────────
    //
    // Phase 8 audit fix: abort + await the long-lived spawns so we
    // observe a final state instead of relying on runtime drop to GC
    // them. `is_cancelled()` is the expected outcome here; anything
    // else means the task ended on its own (panic, or — for HITL —
    // poll_updates returned successfully which today is unreachable).
    // Either way, log it so an operator who restarts the TUI knows.
    api_worker_handle.abort();
    match api_worker_handle.await {
        Ok(()) => warn!("API worker task ended unexpectedly without panic"),
        Err(e) if e.is_cancelled() => { /* expected */ }
        Err(e) => warn!("API worker task ended unexpectedly: {e:#}"),
    }
    if let Some(h) = hitl_handle {
        h.abort();
        match h.await {
            Ok(()) => warn!("HITL poller task ended unexpectedly without panic"),
            Err(e) if e.is_cancelled() => { /* expected */ }
            Err(e) => warn!("HITL poller task ended unexpectedly: {e:#}"),
        }
    }

    // ── Terminal Teardown ────────────────────────────────
    // explicit restore on the happy path so we surface IO
    // errors. Drop is the safety net for early-? returns above.
    // (NLL ends the `terminal` re-borrow at the last use above,
    // so the guard is free to be mutably borrowed here.)
    term_guard.restore()?;

    info!("TUI exited cleanly");
    Ok(())
}

/// Fetch all data from Proxmox and send to controller
async fn fetch_all(client: &Arc<PxClient>, tx: &mpsc::Sender<DataMsg>) {
    // Nodes
    match client.get_nodes().await {
        Ok(nodes) => {
            let node_names: Vec<String> = nodes.iter().map(|n| n.node.clone()).collect();
            let _ = tx.send(DataMsg::Nodes(nodes)).await;

            let mut join_set = tokio::task::JoinSet::new();

            for node_name in node_names {
                let client_cloned = Arc::clone(client);
                join_set.spawn(async move {
                    let guests = client_cloned.get_guests(&node_name).await;
                    let storage = client_cloned.get_storage_pools(&node_name).await;
                    (node_name, guests, storage)
                });
            }

            let mut all_guests = Vec::new();
            let mut all_storage = Vec::new();

            while let Some(res) = join_set.join_next().await {
                if let Ok((node_name, guests_res, storage_res)) = res {
                    match guests_res {
                        Ok(guests) => all_guests.extend(guests),
                        Err(e) => warn!("Failed to fetch guests from {node_name}: {e}"),
                    }
                    match storage_res {
                        Ok(pools) => all_storage.extend(pools),
                        Err(e) => warn!("Failed to fetch storage from {node_name}: {e}"),
                    }
                }
            }

            let _ = tx.send(DataMsg::Guests(all_guests)).await;
            let _ = tx.send(DataMsg::Storage(all_storage)).await;

            if let Ok(tasks) = client.get_cluster_tasks().await {
                let _ = tx.send(DataMsg::ClusterTasks(tasks)).await;
            }

            // (macro audit) — cluster quorum sanity check.
            //
            // PVE returns `200 OK` from a quorum-less node with a
            // partial / stale view of the cluster (some VMs flip to
            // "unknown", some go missing). We fetch /cluster/status
            // alongside the regular sweep and forward the quorate flag
            // so the TUI can render a red "QUORUM LOST" banner — and
            // the user knows not to act on the dashboard.
            if let Ok(entries) = client.cluster_status().await {
                let quorate = entries
                    .iter()
                    .find(|e| e.entry_type == "cluster")
                    .is_none_or(|e| e.quorate);
                let _ = tx.send(DataMsg::ClusterQuorate(quorate)).await;
            }
        }
        Err(e) => {
            error!("Failed to fetch nodes: {e}");
            let _ = tx.send(DataMsg::Error(format!("API error: {e}"))).await;
        }
    }
}

/// Outcome of polling for a guest to reach `stopped` state after a graceful
/// shutdown. Returned by [`wait_for_stopped`]. Public so the integration
/// tests can construct mock gateways and exercise the polling without the
/// full TUI loop attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    Stopped { elapsed_secs: u64 },
    Timeout { elapsed_secs: u64 },
}

/// Poll a guest's status until it reaches `Stopped` or the deadline elapses.
///
/// Implementation notes:
/// - The polling cadence is `poll_interval` and we sleep BEFORE the first
///   check — graceful shutdowns never finish in the first 100ms anyway.
/// - Status fetch errors are tolerated (logged, then keep polling). Many
///   "errors" during shutdown are transient (qemu-guest-agent vanishing as
///   the guest powers down).
/// - The function is `pub` for direct integration testing; it does NOT
///   send any `DataMsg` or touch reducer state directly. Per the
///   architectural invariant ("event-driven, never blocking the render
///   thread"), the caller passes a closure that's invoked for every poll
///   tick — the production caller forwards via the `DataMsg` mpsc channel.
pub async fn wait_for_stopped(
    client: &(dyn crate::api::ProxmoxGateway + Send + Sync),
    node: &str,
    vmid: u32,
    max_wait: Duration,
    poll_interval: Duration,
) -> WaitOutcome {
    wait_for_stopped_with_progress(client, node, vmid, max_wait, poll_interval, |_, _| {}).await
}

/// Same as `wait_for_stopped` but emits a callback on every poll tick
/// with the observed status string and elapsed seconds. Used by the
/// production controller to push `DataMsg::GuestStatusPolled` for the
/// live progress UI.
pub async fn wait_for_stopped_with_progress<F>(
    client: &(dyn crate::api::ProxmoxGateway + Send + Sync),
    node: &str,
    vmid: u32,
    max_wait: Duration,
    poll_interval: Duration,
    mut on_progress: F,
) -> WaitOutcome
where
    F: FnMut(&str, u64) + Send,
{
    let start = std::time::Instant::now();
    loop {
        tokio::time::sleep(poll_interval).await;
        let elapsed = start.elapsed();
        let observed_status: String = match client.get_guest_status(node, vmid).await {
            Ok(g) => {
                let status_str = format!("{:?}", g.status).to_lowercase();
                if g.status == crate::api::types::GuestStatus::Stopped {
                    on_progress(&status_str, elapsed.as_secs());
                    return WaitOutcome::Stopped {
                        elapsed_secs: elapsed.as_secs(),
                    };
                }
                status_str
            }
            Err(e) => {
                warn!("status poll failed for {vmid}: {e:#}");
                "unknown".to_string()
            }
        };
        on_progress(&observed_status, elapsed.as_secs());
        if elapsed >= max_wait {
            return WaitOutcome::Timeout {
                elapsed_secs: elapsed.as_secs(),
            };
        }
    }
}

/// Dispatch a side effect to the API. Async because most arms await
/// the API client; some early-return arms (e.g. `SshSession` lifecycle
/// passthroughs, MoveDisk/ResizeDisk warn-and-skip) don't, so clippy
/// flags the function as unused-async on a per-branch basis.
#[allow(clippy::unused_async)]
async fn dispatch_side_effect(
    effect: SideEffect,
    state: &AppState,
    client: &Arc<PxClient>,
    tx: &mpsc::Sender<DataMsg>,
    policies: &[crate::hitl::policy::Policy],
    skip_hitl: bool,
    tg_gateway: Option<&Arc<crate::hitl::telegram::TelegramGateway>>,
    hitl_coord: &Arc<HitlCoordinator>,
) {
    let get_node = |vmid: u32| -> Option<String> {
        state
            .guests
            .iter()
            .find(|g| g.vmid == vmid)
            .map(|g| g.node.clone())
    };

    let get_type = |vmid: u32| -> Option<crate::api::types::GuestType> {
        state
            .guests
            .iter()
            .find(|g| g.vmid == vmid)
            .map(|g| g.guest_type)
    };

    let check_hitl = |action: &str, vmid: u32, effect: SideEffect| -> bool {
        if skip_hitl {
            return false;
        }

        let tags = state
            .guests
            .iter()
            .find(|g| g.vmid == vmid)
            .map(|g| g.tag_list())
            .unwrap_or_default();
        let policy_match =
            crate::hitl::policy::check_policies(policies, action, &vmid.to_string(), &tags);

        // Feature #6: disk move/resize join the destructive list — they
        // touch storage state and are irreversible (move with delete=1
        // removes the source; resize is grow-only). HITL gate triggers
        // when secure_mode is on or a TOML policy matches.
        let is_destructive = matches!(
            action,
            "stop" | "delete" | "restart" | "migrate" | "exec" | "move_disk" | "resize_disk"
        );
        let secure_required = state.secure_mode && is_destructive;

        if policy_match.is_some() || secure_required {
            let channel = if secure_required {
                "telegram".to_string()
            } else if let Some(pm) = policy_match {
                pm.channel.clone()
            } else {
                "telegram".to_string()
            };
            warn!(
                "TUI HITL intercepted: {} on {} (via {})",
                action, vmid, channel
            );
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0);
            let txn_id = format!("{action}:{vmid}-{now_ms}");
            let desc = format!("Operation {action} on {vmid} requires approval via {channel}");
            let reason = format!("TUI requested {action} on guest {vmid}");
            let action_owned = action.to_string();
            let target_owned = vmid.to_string();

            let tx_cloned = tx.clone();
            let coord_clone = Arc::clone(hitl_coord);
            let tg_clone = tg_gateway.cloned();
            tokio::spawn(async move {
                let _ = tx_cloned
                    .send(DataMsg::HitlRequested(txn_id.clone(), desc))
                    .await;

                // P0 reviewer fix: real Telegram round-trip, no
                // simulation. Three terminal outcomes:
                //   1. Telegram not configured → DENY (secure_mode
                //      without a backing channel must not silently
                //      bypass).
                //   2. Telegram send fails → DENY + log (better safe
                //      than silently approving on a network blip).
                //   3. Telegram callback arrives within 120 s →
                //      forward the user's decision.
                //   4. Timeout → DENY (the user didn't decide; we
                //      err on safety).
                let Some(tg) = tg_clone else {
                    error!(
                        "TUI HITL on {action_owned}/{target_owned} requires Telegram, \
                         but [telegram] is not configured — denying"
                    );
                    let _ = tx_cloned
                        .send(DataMsg::HitlApproved(txn_id, false, Box::new(effect)))
                        .await;
                    return;
                };

                let receiver = coord_clone.register(txn_id.clone()).await;
                if let Err(e) = tg
                    .request_approval(&action_owned, &target_owned, &reason, &txn_id)
                    .await
                {
                    error!("Telegram request_approval failed: {e:#} — denying");
                    coord_clone.unregister(&txn_id).await;
                    let _ = tx_cloned
                        .send(DataMsg::HitlApproved(txn_id, false, Box::new(effect)))
                        .await;
                    return;
                }

                let approved = if let Ok(Ok(b)) =
                    tokio::time::timeout(Duration::from_mins(2), receiver).await
                {
                    b
                } else {
                    warn!("HITL approval timed out / channel dropped — denying");
                    coord_clone.unregister(&txn_id).await;
                    false
                };
                let _ = tx_cloned
                    .send(DataMsg::HitlApproved(txn_id, approved, Box::new(effect)))
                    .await;
            });
            true
        } else {
            false
        }
    };

    match effect {
        SideEffect::Quit => {} // handled in caller
        SideEffect::StartGuest { vmid } => {
            if check_hitl("start", vmid, SideEffect::StartGuest { vmid }) {
                return;
            }
            if let (Some(node), Some(gt)) = (get_node(vmid), get_type(vmid)) {
                info!("Starting guest {vmid} on {node}");
                let client_cloned = Arc::clone(client);
                let tx_cloned = tx.clone();
                tokio::spawn(async move {
                    match client_cloned.start_guest(&node, vmid, gt).await {
                        Ok(upid) => {
                            let _ = tx_cloned.send(DataMsg::TaskStarted(upid)).await;
                        }
                        Err(e) => {
                            error!("Failed to start guest {vmid}: {e}");
                        }
                    }
                    let _ = tx_cloned.send(DataMsg::GuestTaskFinished(vmid)).await;
                });
            }
        }
        SideEffect::StopGuest { vmid, force } => {
            if check_hitl("stop", vmid, SideEffect::StopGuest { vmid, force }) {
                return;
            }
            if let (Some(node), Some(gt)) = (get_node(vmid), get_type(vmid)) {
                info!("Stopping guest {vmid} on {node} (force={force})");
                let client_cloned = Arc::clone(client);
                let tx_cloned = tx.clone();
                // Bug #2 fix: force=false → graceful shutdown, force=true → hard stop.
                tokio::spawn(async move {
                    let res = if force {
                        client_cloned.stop_guest(&node, vmid, gt, true).await
                    } else {
                        client_cloned.shutdown_guest(&node, vmid, gt).await
                    };
                    let issued = res.is_ok();
                    match res {
                        Ok(upid) => {
                            let _ = tx_cloned.send(DataMsg::TaskStarted(upid)).await;
                        }
                        Err(e) => {
                            error!("Failed to stop guest {vmid}: {e}");
                        }
                    }

                    // Bug #2 enhancement: poll for actual stopped state on
                    // graceful shutdowns. ACPI signals are advisory — a
                    // pinned guest, a hung kernel, or a init waiting on
                    // open file handles will silently never stop.
                    //
                    // Polling lives in this spawned task, NOT on the render
                    // thread, so the TUI keeps drawing while we wait.
                    if issued && !force {
                        // Per the architectural review: every poll tick
                        // becomes a DataMsg::GuestStatusPolled so the UI
                        // shows live "ACPI 27s/60s — running" progress.
                        // Use try_send for the per-poll updates: if the
                        // channel is briefly full we drop the tick rather
                        // than block the polling loop.
                        let progress_tx = tx_cloned.clone();
                        let outcome = wait_for_stopped_with_progress(
                            client_cloned.as_ref(),
                            &node,
                            vmid,
                            Duration::from_mins(1),
                            Duration::from_secs(3),
                            |status: &str, elapsed: u64| {
                                let _ = progress_tx.try_send(DataMsg::GuestStatusPolled {
                                    vmid,
                                    status: status.to_string(),
                                    elapsed_secs: elapsed,
                                });
                            },
                        )
                        .await;
                        if let WaitOutcome::Timeout { elapsed_secs } = outcome {
                            let _ = tx_cloned
                                .send(DataMsg::ShutdownTimeout { vmid, elapsed_secs })
                                .await;
                        }
                    }

                    let _ = tx_cloned.send(DataMsg::GuestTaskFinished(vmid)).await;
                });
            }
        }
        SideEffect::RestartGuest { vmid } => {
            if check_hitl("restart", vmid, SideEffect::RestartGuest { vmid }) {
                return;
            }
            if let (Some(node), Some(gt)) = (get_node(vmid), get_type(vmid)) {
                info!("Restarting guest {vmid} on {node}");
                let client_cloned = Arc::clone(client);
                let tx_cloned = tx.clone();
                tokio::spawn(async move {
                    match client_cloned.restart_guest(&node, vmid, gt).await {
                        Ok(upid) => {
                            let _ = tx_cloned.send(DataMsg::TaskStarted(upid)).await;
                        }
                        Err(e) => {
                            error!("Failed to restart guest {vmid}: {e}");
                        }
                    }
                    let _ = tx_cloned.send(DataMsg::GuestTaskFinished(vmid)).await;
                });
            }
        }
        SideEffect::CreateSnapshot { vmid, name } => {
            if let (Some(node), Some(gt)) = (get_node(vmid), get_type(vmid)) {
                info!("Creating snapshot {name} for guest {vmid} on {node}");
                let client_cloned = Arc::clone(client);
                let tx_cloned = tx.clone();
                tokio::spawn(async move {
                    match client_cloned.create_snapshot(&node, vmid, gt, &name).await {
                        Ok(upid) => {
                            let _ = tx_cloned.send(DataMsg::TaskStarted(upid)).await;
                        }
                        Err(e) => {
                            error!("Failed to create snapshot for {vmid}: {e}");
                        }
                    }
                });
            }
        }
        SideEffect::DeleteGuest { vmid } => {
            if let (Some(node), Some(gt)) = (get_node(vmid), get_type(vmid)) {
                info!("Deleting guest {vmid} on {node}");
                let client_cloned = Arc::clone(client);
                let tx_cloned = tx.clone();
                tokio::spawn(async move {
                    match client_cloned.delete_guest(&node, vmid, gt).await {
                        Ok(upid) => {
                            let _ = tx_cloned.send(DataMsg::TaskStarted(upid)).await;
                        }
                        Err(e) => {
                            error!("Failed to delete guest {vmid}: {e}");
                        }
                    }
                });
            }
        }
        SideEffect::MigrateGuest {
            node,
            vmid,
            target_node,
        } => {
            // Look up type at dispatch time (we receive node here but not type).
            let gt = state
                .guests
                .iter()
                .find(|g| g.vmid == vmid)
                .map(|g| g.guest_type);
            if let Some(gt) = gt {
                let client_cloned = Arc::clone(client);
                let tx_cloned = tx.clone();
                tokio::spawn(async move {
                    // TUI migrate path: assume online (TUI typically operates
                    // on running guests) and accept local-disks for now —
                    // a future TUI dialog can let the user opt out. PVE
                    // will reject loudly if either assumption is wrong.
                    match client_cloned
                        // TUI assumes online=true; use restart=false for QEMU,
                        // restart=true for LXC (caller doesn't know which).
                        // We branch on gt to do the right thing.
                        .migrate_guest(
                            &node,
                            vmid,
                            gt,
                            &target_node,
                            matches!(gt, crate::api::types::GuestType::Qemu),
                            true,
                            matches!(gt, crate::api::types::GuestType::Lxc),
                        )
                        .await
                    {
                        Ok(upid) => {
                            let _ = tx_cloned.send(DataMsg::TaskStarted(upid)).await;
                        }
                        Err(e) => {
                            error!("Failed to migrate guest {vmid}: {e}");
                        }
                    }
                });
            } else {
                error!("Cannot migrate {vmid}: guest type unknown (not in state)");
            }
        }
        SideEffect::ExecuteGuestCommand {
            node,
            vmid,
            guest_type,
            command,
        } => {
            let client_cloned = Arc::clone(client);
            tokio::spawn(async move {
                match client_cloned
                    .execute_guest_command(&node, vmid, &guest_type, &command)
                    .await
                {
                    Ok(res) => {
                        info!(
                            "Guest {vmid} command exit={} stdout_bytes={} stderr_bytes={}",
                            res.exit_code,
                            res.stdout.len(),
                            res.stderr.len()
                        );
                    }
                    Err(e) => {
                        error!("Guest {vmid} command failed: {e}");
                    }
                }
            });
        }

        SideEffect::FetchTaskLog { upid, node } => {
            let client_cloned = Arc::clone(client);
            let tx_cloned = tx.clone();
            tokio::spawn(async move {
                match client_cloned.get_task_log(&node, &upid, 0, 500).await {
                    Ok(log) => {
                        let _ = tx_cloned
                            .send(DataMsg::TaskLogUpdated {
                                upid,
                                lines: log.data,
                            })
                            .await;
                    }
                    Err(e) => {
                        error!("Failed to fetch task log: {e}");
                    }
                }
            });
        }
        SideEffect::ExecuteQueue(ops) => {
            let client_cloned = Arc::clone(client);
            let tx_cloned = tx.clone();

            tokio::spawn(async move {
                for op in ops {
                    let id = op.id.clone();
                    let action = *op.action;
                    let target_vmid = match action {
                        app::Action::StartGuest { vmid } => Some(vmid),
                        app::Action::StopGuest { vmid, .. } => Some(vmid),
                        app::Action::RestartGuest { vmid } => Some(vmid),
                        app::Action::DeleteGuest { vmid } => Some(vmid),
                        app::Action::MigrateGuest { vmid, .. } => Some(vmid),
                        app::Action::ExecuteGuestCommand { vmid, .. } => Some(vmid),
                        app::Action::MoveDisk { vmid, .. } => Some(vmid),
                        app::Action::ResizeDisk { vmid, .. } => Some(vmid),
                        _ => None,
                    };

                    if let Some(vmid) = target_vmid {
                        // find node + capture the full Guest for pre-flight
                        // risk assessment (lock, HA, traffic, tags, ...).
                        // The cheap `assess` is called below; deep checks
                        // (snapshots, backup, listening ports) are skipped
                        // here because each adds 1+ extra round-trip and
                        // the TUI queue is async — we don't want a 6-op
                        // batch to take 30s of preflight before anything
                        // executes. CLI uses `assess_deep` for the full
                        // picture; TUI traded depth for snappy execution.
                        let mut target_node = None;
                        let mut g_type = crate::api::types::GuestType::Qemu;
                        let mut full_guest: Option<crate::api::types::Guest> = None;
                        if let Ok(nodes) = client_cloned.get_nodes().await {
                            for n in nodes {
                                if let Ok(guests) = client_cloned.get_guests(&n.node).await {
                                    if let Some(g) = guests.iter().find(|g| g.vmid == vmid) {
                                        target_node = Some(n.node.clone());
                                        g_type = g.guest_type;
                                        full_guest = Some(g.clone());
                                        break;
                                    }
                                }
                            }
                        }

                        // BREAK-GLASS: when the queued op carries
                        // bypass_preflight (set by ConfirmForce), skip
                        // the entire pre-flight check. Audit-log so
                        // the override is traceable post-incident.
                        let bypass = op.bypass_preflight;
                        if bypass {
                            tracing::error!(
                                "BREAK-GLASS: queue op {id} (vmid={vmid}) bypassing preflight"
                            );
                        }

                        // Pre-flight check: map the queued action onto a
                        // preflight Op, run cheap assess, abort with a
                        // descriptive error in OpStatus if any SEVERE
                        // risk fires. Warnings and notices are logged
                        // via tracing (visible in proxxx.log) but don't
                        // block — the user already chose to queue, so
                        // surface the soft signals without overruling.
                        if let (false, Some(g)) = (bypass, full_guest.as_ref()) {
                            let preflight_op = match action {
                                app::Action::DeleteGuest { .. } => {
                                    Some(crate::app::preflight::Op::Delete)
                                }
                                app::Action::StopGuest { .. } => {
                                    Some(crate::app::preflight::Op::Stop)
                                }
                                app::Action::RestartGuest { .. } => {
                                    Some(crate::app::preflight::Op::Restart)
                                }
                                app::Action::MigrateGuest { .. } => {
                                    Some(crate::app::preflight::Op::Migrate)
                                }
                                app::Action::MoveDisk { .. } => {
                                    Some(crate::app::preflight::Op::MoveDisk)
                                }
                                app::Action::ResizeDisk { .. } => {
                                    Some(crate::app::preflight::Op::ResizeDisk)
                                }
                                _ => None,
                            };
                            if let Some(op) = preflight_op {
                                let risks = crate::app::preflight::assess(op, g);
                                let max = crate::app::preflight::max_level(&risks);
                                for (r, l) in &risks {
                                    if *l == crate::app::preflight::RiskLevel::Severe {
                                        tracing::error!(
                                            "queue preflight {} vmid={}: SEVERE: {}",
                                            op.as_str(),
                                            vmid,
                                            r.describe()
                                        );
                                    } else {
                                        tracing::warn!(
                                            "queue preflight {} vmid={}: {}: {}",
                                            op.as_str(),
                                            vmid,
                                            l.as_str(),
                                            r.describe()
                                        );
                                    }
                                }
                                if max == crate::app::preflight::RiskLevel::Severe {
                                    let detail = risks
                                        .iter()
                                        .filter(|(_, l)| {
                                            *l == crate::app::preflight::RiskLevel::Severe
                                        })
                                        .map(|(r, _)| r.describe())
                                        .collect::<Vec<_>>()
                                        .join("; ");
                                    let _ = tx_cloned
                                        .send(DataMsg::QueueOpStatusChanged(
                                            id.clone(),
                                            crate::app::queue::OpStatus::Error(format!(
                                                "preflight refused: {detail}"
                                            )),
                                        ))
                                        .await;
                                    continue;
                                }
                            }
                        }

                        if let Some(node) = target_node {
                            // Bug #2 fix: queue StopGuest with force=false → graceful shutdown.
                            // Feature #6: MoveDisk / ResizeDisk dispatched here from the queue.
                            let res = match action {
                                app::Action::StartGuest { .. } => {
                                    client_cloned.start_guest(&node, vmid, g_type).await
                                }
                                app::Action::StopGuest { force: true, .. } => {
                                    client_cloned.stop_guest(&node, vmid, g_type, true).await
                                }
                                app::Action::StopGuest { force: false, .. } => {
                                    client_cloned.shutdown_guest(&node, vmid, g_type).await
                                }
                                app::Action::RestartGuest { .. } => {
                                    client_cloned.restart_guest(&node, vmid, g_type).await
                                }
                                app::Action::MigrateGuest { target_node, .. } => {
                                    // Queue dispatch — same as direct TUI
                                    // migrate (online for QEMU, restart for
                                    // LXC, with-local-disks accepted).
                                    client_cloned
                                        .migrate_guest(
                                            &node,
                                            vmid,
                                            g_type,
                                            &target_node,
                                            matches!(g_type, crate::api::types::GuestType::Qemu),
                                            true,
                                            matches!(g_type, crate::api::types::GuestType::Lxc),
                                        )
                                        .await
                                }
                                app::Action::ExecuteGuestCommand { command, .. } => {
                                    // Other queue arms return Result<String> (a UPID
                                    // or a status line); collapse the rich exec result
                                    // to the same shape so the queue's status reporting
                                    // can stay uniform.
                                    client_cloned
                                        .execute_guest_command(&node, vmid, &g_type, &command)
                                        .await
                                        .map(|r| {
                                            format!(
                                                "exit={} stdout={}B stderr={}B",
                                                r.exit_code,
                                                r.stdout.len(),
                                                r.stderr.len()
                                            )
                                        })
                                }
                                app::Action::MoveDisk {
                                    disk,
                                    target_storage,
                                    delete_source,
                                    ..
                                } => {
                                    client_cloned
                                        .move_disk(
                                            &node,
                                            vmid,
                                            g_type,
                                            &disk,
                                            &target_storage,
                                            delete_source,
                                        )
                                        .await
                                }
                                app::Action::ResizeDisk { disk, size, .. } => {
                                    client_cloned
                                        .resize_disk(&node, vmid, g_type, &disk, &size)
                                        .await
                                }
                                _ => Err(anyhow::anyhow!("Unsupported in queue yet")),
                            };

                            match res {
                                Ok(_) => {
                                    let _ = tx_cloned
                                        .send(DataMsg::QueueOpStatusChanged(
                                            id,
                                            crate::app::queue::OpStatus::Success,
                                        ))
                                        .await;
                                }
                                Err(e) => {
                                    let _ = tx_cloned
                                        .send(DataMsg::QueueOpStatusChanged(
                                            id,
                                            crate::app::queue::OpStatus::Error(e.to_string()),
                                        ))
                                        .await;
                                }
                            }
                        } else {
                            let _ = tx_cloned
                                .send(DataMsg::QueueOpStatusChanged(
                                    id,
                                    crate::app::queue::OpStatus::Error("Node not found".into()),
                                ))
                                .await;
                        }
                    } else {
                        let _ = tx_cloned
                            .send(DataMsg::QueueOpStatusChanged(
                                id,
                                crate::app::queue::OpStatus::Error("Invalid Action".into()),
                            ))
                            .await;
                    }
                }
            });
        }
        SideEffect::OpenSshSession { .. } | SideEffect::CloseSshSession => {
            // SSH session lifecycle is handled directly in the run loop
            // because it owns the SshSessionHandler. Reaching here means
            // the dispatch was invoked from a path that shouldn't —
            // log + ignore so we don't crash.
            warn!("SSH session SideEffect reached dispatch_side_effect — ignored");
        }
        // Feature #2: server-side ISO/cloud-image download.
        // Proxmox does the actual fetch — we just trigger it and surface
        // the UPID so the user can watch the task log if they want.
        SideEffect::DownloadIso {
            node,
            storage,
            url,
            filename,
            checksum,
            content,
        } => {
            let client_cloned = Arc::clone(client);
            let tx_cloned = tx.clone();
            tokio::spawn(async move {
                let (algo, hex): (Option<&str>, Option<&str>) = match checksum.as_ref() {
                    Some((a, h)) => (Some(a.as_str()), Some(h.as_str())),
                    None => (None, None),
                };
                match client_cloned
                    .download_to_storage(&node, &storage, &url, &filename, algo, hex, &content)
                    .await
                {
                    Ok(upid) => {
                        info!("ISO download started: {url} → {storage} (UPID {upid})");
                        let _ = tx_cloned.send(DataMsg::TaskStarted(upid)).await;
                    }
                    Err(e) => {
                        error!("ISO download failed for {url}: {e}");
                        let _ = tx_cloned
                            .send(DataMsg::Error(format!("ISO download: {e}")))
                            .await;
                    }
                }
            });
        }

        // Feature #6: disk ops are queue-dispatched. Reaching here means
        // a caller bypassed the reducer's force-enqueue invariant — log
        // and execute anyway (the API call is type-aware), but flag it.
        SideEffect::MoveDisk {
            node,
            vmid,
            guest_type,
            disk,
            target_storage,
            delete_source,
        } => {
            warn!("MoveDisk SideEffect bypassed queue — running directly for {vmid}");
            let client_cloned = Arc::clone(client);
            let tx_cloned = tx.clone();
            tokio::spawn(async move {
                match client_cloned
                    .move_disk(
                        &node,
                        vmid,
                        guest_type,
                        &disk,
                        &target_storage,
                        delete_source,
                    )
                    .await
                {
                    Ok(upid) => {
                        let _ = tx_cloned.send(DataMsg::TaskStarted(upid)).await;
                    }
                    Err(e) => error!("move_disk {vmid} failed: {e}"),
                }
            });
        }
        SideEffect::ResizeDisk {
            node,
            vmid,
            guest_type,
            disk,
            size,
        } => {
            warn!("ResizeDisk SideEffect bypassed queue — running directly for {vmid}");
            let client_cloned = Arc::clone(client);
            let tx_cloned = tx.clone();
            tokio::spawn(async move {
                match client_cloned
                    .resize_disk(&node, vmid, guest_type, &disk, &size)
                    .await
                {
                    Ok(upid) => {
                        let _ = tx_cloned.send(DataMsg::TaskStarted(upid)).await;
                    }
                    Err(e) => error!("resize_disk {vmid} failed: {e}"),
                }
            });
        }
        SideEffect::FetchHardwareData { node } => {
            // Feature #4: fetch PCI/USB inventory + every guest's config
            // (so the assignment scanner can run). N+1 calls — fanned out
            // in a JoinSet so total latency = max not sum.
            let client_cloned = Arc::clone(client);
            let tx_cloned = tx.clone();
            let guests_snapshot = state.guests.clone();
            tokio::spawn(async move {
                let (pci_res, usb_res) =
                    tokio::join!(client_cloned.list_pci(&node), client_cloned.list_usb(&node),);
                let mut config_set = tokio::task::JoinSet::new();
                for g in guests_snapshot {
                    let c = Arc::clone(&client_cloned);
                    config_set.spawn(async move {
                        let cfg = c.get_guest_config(&g.node, g.vmid, &g.guest_type).await;
                        (g.vmid, cfg)
                    });
                }
                let mut configs: std::collections::HashMap<
                    u32,
                    std::collections::HashMap<String, String>,
                > = std::collections::HashMap::new();
                while let Some(res) = config_set.join_next().await {
                    if let Ok((vmid, Ok(cfg))) = res {
                        configs.insert(vmid, cfg);
                    }
                }
                let payload = DataMsg::HwData {
                    node,
                    pci: pci_res.unwrap_or_default(),
                    usb: usb_res.unwrap_or_default(),
                    configs,
                };
                let _ = tx_cloned.send(payload).await;
            });
        }
        SideEffect::FetchHaConsoleData => {
            // Feature #5: parallel fetch of all 6 endpoints. Best-effort —
            // a single failed sub-call returns an empty list rather than
            // failing the whole console (the UI distinguishes "empty" from
            // "loading" via `state.ha_loading`).
            let client_cloned = Arc::clone(client);
            let tx_cloned = tx.clone();
            let nodes_snapshot: Vec<String> = state
                .nodes
                .iter()
                .filter(|n| n.status == crate::api::types::NodeStatus::Online)
                .map(|n| n.node.clone())
                .collect();
            tokio::spawn(async move {
                // (Gemini audit) — explicit per-call timeouts.
                //
                // reqwest already enforces a 30 s request-level timeout
                // ([api/client.rs]), but a partially fenced node can
                // accept TCP and never send HTTP body — pvedaemon
                // freezing on a corosync filesystem lock is the
                // canonical case. A 30 s wait is way above the 5 s
                // user-perceptual cliff. Explicit per-call timeouts at
                // the application layer:
                //   - cap the HA Console at FETCH_TIMEOUT seconds
                //     regardless of what reqwest does.
                //   - make the bound self-documenting in this code
                //     instead of action-at-a-distance via reqwest.
                //
                // Timed-out futures yield `Err(Elapsed)` which the
                // existing `unwrap_or_default()` arms already coalesce
                // into empty lists — the UI shows "no data" for the
                // stuck endpoint and the rest of the console works.
                const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

                let groups_fut =
                    tokio::time::timeout(FETCH_TIMEOUT, client_cloned.list_ha_groups());
                let resources_fut =
                    tokio::time::timeout(FETCH_TIMEOUT, client_cloned.list_ha_resources());
                let manager_fut =
                    tokio::time::timeout(FETCH_TIMEOUT, client_cloned.ha_manager_status());
                let cluster_fut =
                    tokio::time::timeout(FETCH_TIMEOUT, client_cloned.cluster_status());
                // (replication-jobs fetch removed — pre-cleanup we
                // pulled `list_replication_jobs` here too, but no
                // view rendered it. The CLI `proxxx replication
                // jobs` reads it directly via the gateway, bypassing
                // AppState — that path is unaffected.)
                // Per-node replication status: fan out across online nodes
                // and concatenate. Each per-node call gets the same
                // budget; one fenced node cannot stall the whole sweep.
                let mut status_set = tokio::task::JoinSet::new();
                for n in nodes_snapshot {
                    let c = Arc::clone(&client_cloned);
                    status_set.spawn(async move {
                        tokio::time::timeout(FETCH_TIMEOUT, c.list_replication_status(&n)).await
                    });
                }
                let (g, r, m, cl) =
                    tokio::join!(groups_fut, resources_fut, manager_fut, cluster_fut);
                // `timeout` returns Result<inner, Elapsed>. The inner is
                // itself anyhow::Result<T>. Coalesce timeout + transport
                // failure into "empty list" so a single fenced node
                // can't blank the whole console.
                macro_rules! flatten_or_default {
                    ($outer:expr, $label:literal) => {
                        match $outer {
                            Ok(Ok(v)) => v,
                            Ok(Err(e)) => {
                                warn!("HA fetch error ({}): {e:#}", $label);
                                Default::default()
                            }
                            Err(_) => {
                                warn!("HA fetch timed out ({}) after {FETCH_TIMEOUT:?}", $label);
                                Default::default()
                            }
                        }
                    };
                }
                let mut all_status = Vec::new();
                while let Some(res) = status_set.join_next().await {
                    if let Ok(Ok(Ok(list))) = res {
                        all_status.extend(list);
                    }
                }
                let payload = DataMsg::HaData {
                    groups: flatten_or_default!(g, "ha_groups"),
                    resources: flatten_or_default!(r, "ha_resources"),
                    manager: flatten_or_default!(m, "ha_manager"),
                    cluster: flatten_or_default!(cl, "cluster_status"),
                    repl_status: all_status,
                };
                let _ = tx_cloned.send(payload).await;
            });
        }
        SideEffect::FetchSnapshotTree { vmid } => {
            // Feature #7: fetch snapshots in a worker, hand back via DataMsg.
            // We deliberately read node + type from the live state at
            // fetch time — if the guest got migrated mid-flight we'd
            // rather see the stale node fail loudly than spoof success.
            if let (Some(node), Some(gt)) = (get_node(vmid), get_type(vmid)) {
                let client_cloned = Arc::clone(client);
                let tx_cloned = tx.clone();
                tokio::spawn(async move {
                    match client_cloned.list_snapshots(&node, vmid, gt).await {
                        Ok(snaps) => {
                            let _ = tx_cloned
                                .send(DataMsg::SnapshotsLoaded { vmid, snaps })
                                .await;
                        }
                        Err(e) => {
                            error!("Failed to fetch snapshots for {vmid}: {e}");
                            let _ = tx_cloned
                                .send(DataMsg::Error(format!("snapshots {vmid}: {e}")))
                                .await;
                            // Surface an empty list so loading flag clears.
                            let _ = tx_cloned
                                .send(DataMsg::SnapshotsLoaded {
                                    vmid,
                                    snaps: Vec::new(),
                                })
                                .await;
                        }
                    }
                });
            }
        }
        SideEffect::ConfigGrep { query } => {
            let client_cloned = Arc::clone(client);
            let tx_cloned = tx.clone();
            let guests = state.guests.clone();
            let query_lower = query.to_lowercase();

            tokio::spawn(async move {
                let mut matches = Vec::new();
                for guest in guests {
                    if let Ok(config) = client_cloned
                        .get_guest_config(&guest.node, guest.vmid, &guest.guest_type)
                        .await
                    {
                        for (k, v) in config {
                            if k.to_lowercase().contains(&query_lower)
                                || v.to_lowercase().contains(&query_lower)
                            {
                                matches.push(crate::app::GrepMatch {
                                    vmid: guest.vmid,
                                    name: guest.name.clone(),
                                    key: k,
                                    value: v,
                                });
                            }
                        }
                    }
                }
                let _ = tx_cloned
                    .send(DataMsg::ConfigGrepResults { query, matches })
                    .await;
            });
        }
    }
}

/// Fallback demo mode when no Proxmox connection is available
async fn run_demo() -> Result<()> {
    // — same TerminalGuard treatment as `run()`.
    let mut term_guard = TerminalGuard::install()?;
    let terminal = term_guard.terminal_mut();
    terminal.clear()?;

    let mut state = AppState::new();
    load_demo_data(&mut state);

    let mut events = event::spawn_event_loop(Duration::from_millis(200));

    // Demo mode has no live SSH — pass an inert handler.
    let demo_handler = ssh_handler::SshSessionHandler::new(crate::config::ProfileConfig {
        url: String::new(),
        user: String::new(),
        auth: "token".into(),
        token_id: None,
        token_secret: None,
        token_secret_file: None,
        password: None,
        verify_tls: false,
        tls_pin_mode: None,
        rate_limit: None,
        policies: None,
        telegram: None,
        ssh: None,
        pbs: None,
        alerts: None,
    });

    loop {
        terminal.draw(|f| draw(f, &state, &demo_handler))?;
        if let Some(evt) = events.recv().await {
            match evt {
                event::AppEvent::Key(key) => {
                    if let Some(action) = event::map_key(key, &state) {
                        if matches!(app::update(&mut state, action), Some(SideEffect::Quit)) {
                            break;
                        }
                    }
                }
                event::AppEvent::Tick => {
                    let _ = app::update(&mut state, Action::Tick);
                }
                event::AppEvent::Resize(_, _) => {}
            }
        }
    }

    term_guard.restore()?;
    Ok(())
}

/// Minimum frame dimensions — below this we refuse to dispatch to any
/// view and instead render a single "terminal too small" notice.
///
/// SPOF 3.1 (Category 3 audit): a sub-minimum terminal causes views to
/// hand zero/near-zero rects to widgets and slice indices, which can
/// underflow / panic deep inside the render path. Gating here gives us
/// a single mathematical proof site instead of N per-view branches.
const MIN_FRAME_WIDTH: u16 = 40;
const MIN_FRAME_HEIGHT: u16 = 8;

/// Top-level render dispatcher — routes to the correct view
fn draw(f: &mut Frame, state: &AppState, ssh: &ssh_handler::SshSessionHandler) {
    let area = f.area();

    // SPOF 3.1 — refuse to render below a sane minimum. Anything finer
    // would either crash on slice indexing in views or produce garbage.
    if area.width < MIN_FRAME_WIDTH || area.height < MIN_FRAME_HEIGHT {
        use ratatui::widgets::Paragraph;
        let msg = format!(
            " Terminal too small ({}×{}). Need at least {}×{}. ",
            area.width, area.height, MIN_FRAME_WIDTH, MIN_FRAME_HEIGHT
        );
        let p = Paragraph::new(msg)
            .style(
                ratatui::style::Style::default()
                    .fg(theme::Theme::DANGER)
                    .add_modifier(ratatui::style::Modifier::BOLD),
            )
            .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(p, area);
        return;
    }

    // Reserve the bottom row for the contextual keybindings footer.
    // The input-bar overlay (Command / InputTag / InputBroadcast) and
    // the help/confirm modals render on TOP of this layout, so they
    // naturally hide the footer when active without explicit gating.
    use ratatui::layout::{Constraint, Layout};
    let [view_area, footer_area] =
        Layout::vertical([Constraint::Min(1), Constraint::Length(1)]).areas(area);

    match state.current_view() {
        View::Dashboard => views::dashboard::draw(f, view_area, state),
        View::NodeList => views::nodes::draw(f, view_area, state),
        View::GuestList | View::GuestDetail { .. } => views::guests::draw(f, view_area, state),
        View::StorageList => views::storage::draw(f, view_area, state),
        View::TaskLog { upid } => views::tasks::draw(f, view_area, state, upid),
        View::ApprovalQueue => views::approval::draw(f, view_area, state),
        View::OperationQueue => views::queue::draw(f, view_area, state),
        View::GuestCompare { guests } => views::compare::draw(f, view_area, state, guests),
        View::Heatmap => views::heatmap::draw(f, view_area, state),
        View::BackupBoard => views::backup::draw(f, view_area, state),
        View::AuditTimeline => views::timeline::draw(f, view_area, state),
        View::ConfigGrep => views::grep::draw(f, view_area, state),
        View::SnapshotTree { vmid } => {
            views::snaptree::draw(f, view_area, state, *vmid);
        }
        View::IsoLibrary => views::iso_library::draw(f, view_area, state),
        View::HaConsole => views::ha_console::draw(f, view_area, state),
        View::Hardware { node } => views::hardware::draw(f, view_area, state, node),
        View::GuestSshSession { vmid } => {
            let parser = ssh.parser();
            let host = ssh.active_host();
            let user = ssh.active_user();
            let finished = ssh.is_finished();
            views::ssh_session::draw(
                f,
                view_area,
                &views::ssh_session::SessionFrameInput {
                    vmid: *vmid,
                    host: host.as_deref(),
                    user: user.as_deref(),
                    parser: parser.as_ref(),
                    finished,
                },
            );
        }
    }

    // Footer last, so it draws under any modal overlays the block
    // below adds for Confirm / Help / Search / InputBar.
    widgets::status_footer::draw_status_footer(f, footer_area, state);

    if let app::AppMode::Confirm { description, .. } = &state.mode {
        widgets::modal::draw_confirm_modal(f, area, description);
    } else if matches!(&state.mode, app::AppMode::Help) {
        widgets::modal::draw_help_overlay(f, area);
    } else if matches!(&state.mode, app::AppMode::Search) {
        views::search::draw(f, area, state);
    } else if let app::AppMode::Command | app::AppMode::InputTag | app::AppMode::InputBroadcast =
        &state.mode
    {
        widgets::input_bar::draw_input_bar(f, area, &state.mode, &state.command_input);
    }

    // ── Global Status Overlays ───────────────────────────
    let mut status_spans = Vec::new();

    if let Some(err) = &state.error {
        status_spans.push(ratatui::text::Span::styled(
            format!(" ⚠️ {err} "),
            ratatui::style::Style::default()
                .bg(theme::Theme::DANGER)
                .fg(ratatui::style::Color::White)
                .add_modifier(ratatui::style::Modifier::BOLD),
        ));
    }

    // — render the QUORUM LOST banner whenever the most
    // recent /cluster/status fetch reported quorate=false. Highest
    // visual priority (red, bold) because every other rendered field
    // could be silently stale at this point.
    if state.cluster_quorate == Some(false) {
        status_spans.push(ratatui::text::Span::styled(
            " 🚨 QUORUM LOST — STALE DATA ".to_string(),
            ratatui::style::Style::default()
                .bg(theme::Theme::DANGER)
                .fg(ratatui::style::Color::White)
                .add_modifier(ratatui::style::Modifier::BOLD),
        ));
    }

    if let Some(last) = state.last_sync {
        let age = std::time::Instant::now().duration_since(last).as_secs();
        if age > 10 {
            status_spans.push(ratatui::text::Span::styled(
                format!(" 📡 STALE DATA ({age}s) "),
                ratatui::style::Style::default()
                    .bg(theme::Theme::WARNING)
                    .fg(ratatui::style::Color::Black)
                    .add_modifier(ratatui::style::Modifier::BOLD),
            ));
        }
    }

    if !status_spans.is_empty() {
        use ratatui::widgets::Paragraph;
        let p = Paragraph::new(ratatui::text::Line::from(status_spans))
            .alignment(ratatui::layout::Alignment::Right);

        let overlay_area = ratatui::layout::Rect {
            x: 0,
            y: 0,
            width: area.width,
            height: 1,
        };
        f.render_widget(p, overlay_area);
    }
}

/// Demo data fallback for offline development
fn load_demo_data(state: &mut AppState) {
    use crate::api::types::{Guest, GuestStatus, GuestType, Node, NodeStatus};
    state.is_loading = false;
    state.nodes = vec![Node {
        node: "demo-node".into(),
        status: NodeStatus::Online,
        cpu: 2.4,
        maxcpu: 8,
        mem: 12_884_901_888,
        maxmem: 34_359_738_368,
        disk: 107_374_182_400,
        maxdisk: 536_870_912_000,
        uptime: 389520,
    }];
    state.guests = vec![Guest {
        vmid: 100,
        name: "demo-vm".into(),
        status: GuestStatus::Running,
        guest_type: GuestType::Qemu,
        node: "demo-node".into(),
        cpu: 0.45,
        cpus: 2,
        mem: 2_147_483_648,
        maxmem: 4_294_967_296,
        disk: 10_737_418_240,
        maxdisk: 34_359_738_368,
        uptime: 389520,
        tags: "demo".into(),
        lock: String::new(),
        hastate: String::new(),
        template: false,
        netin: 0,
        netout: 0,
    }];
}
