use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use std::time::Duration;
use tokio::sync::mpsc;

/// Terminal events — keyboard always has priority
#[derive(Debug)]
pub enum AppEvent {
    Key(KeyEvent),
    Tick,
    Resize(u16, u16),
}

/// (audit) — bounded channel capacity for terminal events.
///
/// `unbounded_channel` is a footgun for input streams: holding `j`
/// produces 50–200 events/sec, and if the renderer can't keep up,
/// the queue grows without bound — eventually paging from disk.
///
/// 256 is comfortably above any realistic burst (the user can't
/// physically generate 256 events before the next render iteration
/// in a TUI that draws on every event), but bounded enough that a
/// pathological key-mash stalls the producer thread (crossterm
/// reader) at the channel's `send` rather than ballooning RAM.
/// Stalling there is BENIGN — the OS keyboard buffer is also
/// bounded and naturally rate-limits the source.
const EVENT_CHANNEL_CAPACITY: usize = 256;

/// Spawn a background task that reads terminal events and sends them
/// over a bounded channel . Tick events fire every `tick_rate`.
#[must_use]
pub fn spawn_event_loop(tick_rate: Duration) -> mpsc::Receiver<AppEvent> {
    let (tx, rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);

    std::thread::spawn(move || {
        let mut last_tick = std::time::Instant::now();
        loop {
            let timeout = tick_rate
                .checked_sub(last_tick.elapsed())
                .unwrap_or(Duration::ZERO);

            if event::poll(timeout).unwrap_or(false) {
                match event::read() {
                    Ok(Event::Key(key))
                        // `blocking_send` is the right primitive here:
                        // we're on a std::thread (not a tokio task), so
                        // we can block. If the receiver is full, this
                        // applies backpressure to the crossterm reader,
                        // which is exactly what we want under key-mash.
                        if tx.blocking_send(AppEvent::Key(key)).is_err() => {
                            return; // channel closed, app is shutting down
                        }
                    Ok(Event::Resize(w, h)) => {
                        // Resize coalesces in the consumer; if the
                        // channel is full, drop rather than block —
                        // resize-storms (V8) shouldn't backpressure.
                        let _ = tx.try_send(AppEvent::Resize(w, h));
                    }
                    _ => {}
                }
            }

            if last_tick.elapsed() >= tick_rate {
                // Tick is best-effort: a slow consumer doesn't need
                // every tick, only the latest. `try_send` drops if
                // full — no tick storm RAM growth under heavy load.
                let _ = tx.try_send(AppEvent::Tick);
                last_tick = std::time::Instant::now();
            }
        }
    });

    rx
}

/// Map a key event to an app Action
#[must_use]
pub fn map_key(key: KeyEvent, state: &crate::app::AppState) -> Option<crate::app::Action> {
    use crate::app::{Action, AppMode, View};

    // Ctrl+C always quits
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Some(Action::Quit);
    }

    // Ctrl-K for command palette / search
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('k') {
        return Some(Action::SearchInput(String::new()));
    }

    // Help overlay swallows any key as "dismiss". Pressing `?` again
    // also closes via the toggle. This matches the user's expectation
    // from vim-style TUIs (`?` opens, anything closes).
    if matches!(state.mode, AppMode::Help) {
        return Some(Action::ToggleHelp);
    }

    match &state.mode {
        AppMode::Normal => match key.code {
            KeyCode::Char('q') => Some(Action::Quit),
            KeyCode::Char('j') | KeyCode::Down => Some(Action::NavigateDown),
            KeyCode::Char('k') | KeyCode::Up => Some(Action::NavigateUp),
            KeyCode::Enter | KeyCode::Char('l') | KeyCode::Right => {
                if *state.current_view() == View::AuditTimeline {
                    Some(Action::TimelineNext)
                } else {
                    Some(Action::Select)
                }
            }
            KeyCode::Esc | KeyCode::Char('h') | KeyCode::Left => {
                if *state.current_view() == View::AuditTimeline && key.code == KeyCode::Left {
                    Some(Action::TimelinePrev)
                } else {
                    Some(Action::Back)
                }
            }
            KeyCode::Char('/') => Some(Action::SearchInput(String::new())),
            KeyCode::Char(':') => Some(Action::CommandInput(String::new())),
            KeyCode::Char('1') => Some(Action::SwitchView(View::Dashboard)),
            KeyCode::Char('2') => Some(Action::SwitchView(View::NodeList)),
            KeyCode::Char('3') => Some(Action::SwitchView(View::GuestList)),
            KeyCode::Char('4') => Some(Action::SwitchView(View::StorageList)),
            KeyCode::Char('H') => Some(Action::SwitchView(View::Heatmap)),
            KeyCode::Char('B') => Some(Action::SwitchView(View::BackupBoard)),
            KeyCode::Char('G') => Some(Action::StartConfigGrep),

            KeyCode::Char(' ') => {
                if *state.current_view() == View::GuestList {
                    if let Some(guest) = state.visible_guests().get(state.selected_index) {
                        return Some(Action::ToggleSelection(guest.vmid));
                    }
                }
                None
            }
            KeyCode::Char('V') => Some(Action::SelectAll),
            KeyCode::Char('t') => {
                if *state.current_view() == View::GuestList {
                    return Some(Action::StartTagSelection);
                }
                None
            }

            KeyCode::Char('s') => {
                if *state.current_view() == View::GuestList {
                    let mut actions = Vec::new();
                    if !state.selected_guests.is_empty() {
                        for vmid in &state.selected_guests {
                            actions.push(Box::new(Action::StartGuest { vmid: *vmid }));
                        }
                    } else if let Some(guest) = state.visible_guests().get(state.selected_index) {
                        actions.push(Box::new(Action::StartGuest { vmid: guest.vmid }));
                    }
                    if !actions.is_empty() {
                        return Some(Action::EnqueueBatchOperation(actions));
                    }
                }
                None
            }
            KeyCode::Char('X') => {
                if *state.current_view() == View::GuestList && !state.selected_guests.is_empty() {
                    return Some(Action::PromptBroadcastCommand);
                }
                None
            }
            KeyCode::Char('S') => {
                if *state.current_view() == View::GuestList {
                    let mut actions = Vec::new();
                    if !state.selected_guests.is_empty() {
                        for vmid in &state.selected_guests {
                            actions.push(Box::new(Action::StopGuest {
                                vmid: *vmid,
                                force: false,
                            }));
                        }
                    } else if let Some(guest) = state.visible_guests().get(state.selected_index) {
                        actions.push(Box::new(Action::StopGuest {
                            vmid: guest.vmid,
                            force: false,
                        }));
                    }
                    if !actions.is_empty() {
                        return Some(Action::EnqueueBatchOperation(actions));
                    }
                }
                None
            }
            KeyCode::Char('r') => {
                if *state.current_view() == View::GuestList {
                    let mut actions = Vec::new();
                    if !state.selected_guests.is_empty() {
                        for vmid in &state.selected_guests {
                            actions.push(Box::new(Action::RestartGuest { vmid: *vmid }));
                        }
                    } else if let Some(guest) = state.visible_guests().get(state.selected_index) {
                        actions.push(Box::new(Action::RestartGuest { vmid: guest.vmid }));
                    }
                    if !actions.is_empty() {
                        return Some(Action::EnqueueBatchOperation(actions));
                    }
                }
                None
            }
            KeyCode::Char('d') => {
                // GuestList: enqueue delete for selected/highlighted.
                if *state.current_view() == View::GuestList {
                    let mut actions = Vec::new();
                    if !state.selected_guests.is_empty() {
                        for vmid in &state.selected_guests {
                            actions.push(Box::new(Action::DeleteGuest { vmid: *vmid }));
                        }
                    } else if let Some(guest) = state.visible_guests().get(state.selected_index) {
                        actions.push(Box::new(Action::DeleteGuest { vmid: guest.vmid }));
                    }
                    if !actions.is_empty() {
                        return Some(Action::EnqueueBatchOperation(actions));
                    }
                }
                // OperationQueue: remove the highlighted entry from the
                // queue. Pre-fix the view's instruction line advertised
                // "[D] Remove Selected" but no key was wired — Action::
                // DequeueOperation was reachable only from the reducer
                // side. Now `d` on the queue does what the legend says.
                if *state.current_view() == View::OperationQueue && !state.op_queue.is_empty() {
                    return Some(Action::DequeueOperation(state.selected_index));
                }
                None
            }
            KeyCode::Char('D') => {
                if *state.current_view() == View::GuestList && state.selected_guests.len() >= 2 {
                    Some(Action::CompareGuests)
                } else {
                    None
                }
            }
            KeyCode::Char('E') => {
                if *state.current_view() == View::NodeList {
                    if let Some(node) = state.nodes.get(state.selected_index) {
                        return Some(Action::EvacuateNode {
                            node: node.node.clone(),
                        });
                    }
                }
                None
            }
            KeyCode::Char('Q') => Some(Action::SwitchView(View::OperationQueue)),
            KeyCode::Char('C') => {
                if *state.current_view() == View::OperationQueue {
                    Some(Action::ExecuteQueue)
                } else {
                    None
                }
            }

            KeyCode::Char('R') => Some(Action::Tick), // force refresh
            KeyCode::Char('?') => Some(Action::ToggleHelp), // P1 fix: real overlay
            KeyCode::Char('c') => {
                // P0 fix: the Guest list action bar advertises
                // `c onsole` as a binding (views/guests.rs), but it
                // was never wired — pressing `c` did nothing while
                // the user thought it had triggered the unrelated
                // /nodes fetch error in the background. Open the SSH
                // session for the selected guest, equivalent to
                // typing `:ssh <vmid>`. If `[ssh.guests."<vmid>"]`
                // isn't configured the OpenGuestSsh dispatch surfaces
                // a clear error via SshSessionFailed.
                if *state.current_view() == View::GuestList {
                    if let Some(guest) = state.visible_guests().get(state.selected_index) {
                        return Some(Action::OpenGuestSsh { vmid: guest.vmid });
                    }
                }
                None
            }
            KeyCode::Char('T') => Some(Action::EnterTimeline),
            KeyCode::Char('Z') => {
                // Feature #7: open snapshot tree for the selected guest.
                if *state.current_view() == View::GuestList {
                    if let Some(guest) = state.visible_guests().get(state.selected_index) {
                        return Some(Action::OpenSnapshotTree { vmid: guest.vmid });
                    }
                }
                None
            }
            KeyCode::Char('W') => {
                // Feature #4: open hardware inventory for the selected node.
                if *state.current_view() == View::NodeList {
                    if let Some(node) = state.nodes.get(state.selected_index) {
                        return Some(Action::OpenHardware {
                            node: node.node.clone(),
                        });
                    }
                }
                None
            }
            _ => None,
        },
        AppMode::Search => match key.code {
            KeyCode::Esc => Some(Action::Back),
            KeyCode::Enter => Some(Action::Select),
            KeyCode::Up => Some(Action::NavigateUp),
            KeyCode::Down => Some(Action::NavigateDown),
            KeyCode::Char(c) => {
                let mut q = state.search_query.clone();
                q.push(c);
                Some(Action::SearchInput(q))
            }
            KeyCode::Backspace => {
                let mut q = state.search_query.clone();
                q.pop();
                Some(Action::SearchInput(q))
            }
            _ => None,
        },
        AppMode::InputTag => match key.code {
            KeyCode::Esc => Some(Action::Back),
            KeyCode::Enter => {
                let tag = state.command_input.clone();
                Some(Action::SelectByTag(tag))
            }
            KeyCode::Char(c) => {
                let mut q = state.command_input.clone();
                q.push(c);
                Some(Action::CommandInput(q))
            }
            KeyCode::Backspace => {
                let mut q = state.command_input.clone();
                q.pop();
                Some(Action::CommandInput(q))
            }
            _ => None,
        },
        AppMode::Command => match key.code {
            KeyCode::Esc => Some(Action::Back),
            KeyCode::Enter => Some(Action::CommandSubmit),
            KeyCode::Char(c) => {
                let mut q = state.command_input.clone();
                q.push(c);
                Some(Action::CommandInput(q))
            }
            KeyCode::Backspace => {
                let mut q = state.command_input.clone();
                q.pop();
                Some(Action::CommandInput(q))
            }
            _ => None,
        },
        AppMode::InputBroadcast => match key.code {
            KeyCode::Esc => Some(Action::Back),
            KeyCode::Enter => {
                let cmd = state.command_input.clone();
                Some(Action::ExecuteBroadcast(cmd))
            }
            KeyCode::Char(c) => {
                let mut q = state.command_input.clone();
                q.push(c);
                Some(Action::CommandInput(q))
            }
            KeyCode::Backspace => {
                let mut q = state.command_input.clone();
                q.pop();
                Some(Action::CommandInput(q))
            }
            _ => None,
        },
        AppMode::ConfigGrep => match key.code {
            KeyCode::Esc => Some(Action::Back),
            KeyCode::Enter => Some(Action::ConfigGrepSubmit),
            KeyCode::Up => Some(Action::NavigateUp),
            KeyCode::Down => Some(Action::NavigateDown),
            KeyCode::Char(c) => {
                let mut q = state.grep_query.clone();
                q.push(c);
                Some(Action::ConfigGrepInput(q))
            }
            KeyCode::Backspace => {
                let mut q = state.grep_query.clone();
                q.pop();
                Some(Action::ConfigGrepInput(q))
            }
            _ => None,
        },
        AppMode::Confirm { .. } => match key.code {
            KeyCode::Char('y') | KeyCode::Enter => Some(Action::ConfirmAccept),
            KeyCode::Char('n') | KeyCode::Esc => Some(Action::Back),
            // BREAK-GLASS: capital `F` (intentional friction — no
            // accidental press) bypasses the client-side guard for
            // this single op. Logged via tracing::error in the
            // reducer for post-incident audit.
            KeyCode::Char('F') => Some(Action::ConfirmForce),
            _ => None,
        },
        // SshSession is handled directly by the TUI run loop (it owns the
        // PtySession). map_key never sees these keys in practice — but
        // we cover it here so the match is exhaustive.
        AppMode::SshSession { .. } => None,
        // Help is handled by the early-return at the top of map_key so
        // any key dismisses the overlay; this arm is unreachable under
        // normal flow but the match must be exhaustive.
        AppMode::Help => Some(Action::ToggleHelp),
    }
}
