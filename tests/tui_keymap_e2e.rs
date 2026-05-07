#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc
)]
//! Headless TUI keymap → reducer → render smoke test.
//!
//! Closes the "TUI keystroke flow has no automated coverage" gap that
//! sat in the feature-coverage matrix across multiple cycles. Sister
//! to `tests/tui_snapshot.rs` (which covers static-render layout) —
//! this file drives the full input → reducer → render path that the
//! real TUI loop runs every keystroke.
//!
//! ## What it asserts
//!
//! Each test seeds a deterministic `AppState`, then drives a sequence
//! of synthetic `KeyEvent`s through the same code path the production
//! event loop uses:
//!
//!     KeyEvent  →  tui::event::map_key  →  Option<Action>
//!                                       →  app::update(&mut state)
//!                                       →  Option<SideEffect>
//!                                       →  render via TestBackend
//!
//! State transitions are checked at every step (mode, current view,
//! search query, etc.). The render call is a no-panic assertion: if
//! any view panics on the in-memory `Buffer`, the test fails with a
//! useful backtrace.
//!
//! Together with the existing `tui_snapshot.rs` static-render tests,
//! this gives the TUI layer the same kind of regression coverage the
//! reducer already has via `tests/app_test.rs`. Adding a new keymap
//! variant or breaking the reducer's quit semantics now fails the
//! gate before the demo cast can drift.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use proxxx::api::types::{Guest, GuestStatus, GuestType, Node, NodeStatus, StoragePool};
use proxxx::app::{self, AppMode, AppState, SideEffect, View};
use proxxx::tui::event::map_key;
use proxxx::tui::{views, widgets};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

// ── Key builders ──────────────────────────────────────────

const fn key_char(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

const fn key_ctrl(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
}

const fn key_code(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

// ── State seeding (deterministic) ─────────────────────────

fn online_node(name: &str) -> Node {
    Node {
        node: name.to_string(),
        status: NodeStatus::Online,
        cpu: 0.05,
        maxcpu: 4,
        mem: 2 * 1024 * 1024 * 1024,
        maxmem: 8 * 1024 * 1024 * 1024,
        disk: 10 * 1024 * 1024 * 1024,
        maxdisk: 100 * 1024 * 1024 * 1024,
        uptime: 86_400,
    }
}

fn alpine_qemu(vmid: u32, node: &str) -> Guest {
    Guest {
        vmid,
        name: format!("alpine-{vmid}"),
        guest_type: GuestType::Qemu,
        status: GuestStatus::Running,
        node: node.to_string(),
        cpus: 1,
        cpu: 0.01,
        mem: 256 * 1024 * 1024,
        maxmem: 1024 * 1024 * 1024,
        disk: 0,
        maxdisk: 16 * 1024 * 1024 * 1024,
        uptime: 3600,
        ..Default::default()
    }
}

fn debian_lxc(vmid: u32, node: &str) -> Guest {
    Guest {
        vmid,
        name: format!("debian-ct-{vmid}"),
        guest_type: GuestType::Lxc,
        status: GuestStatus::Stopped,
        node: node.to_string(),
        ..Default::default()
    }
}

fn local_storage() -> StoragePool {
    StoragePool {
        storage: "local".to_string(),
        used: 5 * 1024 * 1024 * 1024,
        total: 100 * 1024 * 1024 * 1024,
        avail: 95 * 1024 * 1024 * 1024,
        active: true,
        storage_type: "dir".to_string(),
        content: "iso,vztmpl,backup".to_string(),
    }
}

fn seed(state: &mut AppState) {
    state.nodes = vec![
        online_node("pve1"),
        online_node("pve2"),
        online_node("pve3"),
    ];
    state.guests = vec![
        alpine_qemu(101, "pve1"),
        alpine_qemu(102, "pve2"),
        debian_lxc(201, "pve3"),
    ];
    state.storage = vec![local_storage()];
}

// ── Driver: KeyEvent → state mutation + render ────────────

/// Run one keypress through the full pipeline.
///
/// Returns the `SideEffect` if any (so the caller can detect Quit),
/// AND renders the current view to a `TestBackend` to exercise the
/// view's render code on the resulting state. A panic in any view's
/// `draw` fails the test with a useful backtrace.
#[allow(clippy::needless_pass_by_value)]
fn step(state: &mut AppState, key: KeyEvent) -> Option<SideEffect> {
    let action = map_key(key, state)?;
    let effect = app::update(state, action);
    render_current_view(state);
    effect
}

/// Render whichever view the state is currently on, into a fixed-size
/// `TestBackend`. The exact dimensions match the snapshot suite (80×24)
/// so any layout assumption that breaks here also breaks `tui_snapshot.rs`.
///
/// Match arms cover only the views the tests in this file visit. New
/// views the tests touch get a new arm; an unmatched view triggers a
/// loud panic with the view name so the test author can wire it.
fn render_current_view(state: &AppState) {
    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).expect("test terminal builds");
    terminal
        .draw(|f| match state.current_view() {
            View::Dashboard => views::dashboard::draw(f, f.area(), state),
            View::NodeList => views::nodes::draw(f, f.area(), state),
            View::GuestList => views::guests::draw(f, f.area(), state),
            View::StorageList => views::storage::draw(f, f.area(), state),
            View::Heatmap => views::heatmap::draw(f, f.area(), state),
            other => panic!(
                "test seeded a sequence touching view {other:?} but the \
                 render dispatch in tui_keymap_e2e.rs has no arm for it; \
                 add the missing match arm or shorten the sequence"
            ),
        })
        .expect("draw succeeds");

    // Help is an overlay drawn ON TOP of whatever view is current —
    // verify it renders without panicking when the mode is Help.
    if matches!(state.mode, AppMode::Help) {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).expect("help-overlay terminal builds");
        terminal
            .draw(|f| widgets::modal::draw_help_overlay(f, f.area()))
            .expect("help overlay draw succeeds");
    }
}

// ── Tests ─────────────────────────────────────────────────

/// The canonical user session that the asciinema demo's Act 3
/// records: dashboard → guests → search → escape → help → quit.
/// If this drifts, the demo cast loses its ability to be re-recorded
/// deterministically.
#[test]
fn canonical_demo_act3_keymap_session_quits_cleanly() {
    let mut state = AppState::new();
    seed(&mut state);

    // Start: Normal mode, Dashboard implicit (nav_stack empty).
    assert!(matches!(state.mode, AppMode::Normal));
    assert_eq!(*state.current_view(), View::Dashboard);

    // 1 → Dashboard (explicit push so nav_stack has it).
    assert!(step(&mut state, key_char('1')).is_none());
    assert_eq!(*state.current_view(), View::Dashboard);

    // 3 → Guests.
    assert!(step(&mut state, key_char('3')).is_none());
    assert_eq!(*state.current_view(), View::GuestList);

    // / → enter search mode with empty query.
    assert!(step(&mut state, key_char('/')).is_none());
    assert!(matches!(state.mode, AppMode::Search));
    assert_eq!(state.search_query, "");

    // Type "alpine" character by character. Each keystroke rebuilds the
    // query through `Action::SearchInput`, mirroring how the live TUI
    // builds the query from typeahead.
    for c in "alpine".chars() {
        assert!(step(&mut state, key_char(c)).is_none());
    }
    assert!(matches!(state.mode, AppMode::Search));
    assert_eq!(state.search_query, "alpine");

    // Esc → leave search mode + clear query, stay on GuestList.
    assert!(step(&mut state, key_code(KeyCode::Esc)).is_none());
    assert!(matches!(state.mode, AppMode::Normal));
    assert_eq!(state.search_query, "");
    assert_eq!(*state.current_view(), View::GuestList);

    // ? → open Help overlay (only mapped in Normal).
    assert!(step(&mut state, key_char('?')).is_none());
    assert!(matches!(state.mode, AppMode::Help));

    // ? again → Help mode swallows ANY key as ToggleHelp, returns to Normal.
    assert!(step(&mut state, key_char('?')).is_none());
    assert!(matches!(state.mode, AppMode::Normal));

    // q → quit. Reducer must signal Quit cleanly.
    let effect = step(&mut state, key_char('q'));
    assert!(
        matches!(effect, Some(SideEffect::Quit)),
        "expected Quit, got {effect:?}"
    );
}

/// Help-overlay invariant: ANY key while in Help mode returns to Normal
/// via `ToggleHelp`. This is the user's expectation from vim-style TUIs.
#[test]
fn help_mode_dismisses_on_arbitrary_keypress() {
    // A grab-bag of keys that mean different things in Normal mode —
    // they should all collapse to "dismiss" while Help is open. Each
    // assertion runs against a fresh state because AppState isn't
    // `Clone` (intentionally — it owns SQLite handles in production).
    let pokes = [
        key_char('a'),
        key_char('q'),
        key_char(':'),
        key_char('?'),
        key_code(KeyCode::Esc),
        key_code(KeyCode::Enter),
        key_code(KeyCode::Down),
    ];
    for key in pokes {
        let mut state = AppState::new();
        seed(&mut state);
        state.mode = AppMode::Help;
        assert!(step(&mut state, key).is_none());
        assert!(
            matches!(state.mode, AppMode::Normal),
            "Help did not dismiss on key {key:?}"
        );
    }
}

/// Ctrl+C always quits — regardless of mode. Without this invariant,
/// a stuck Search-mode prompt with a long query would have no escape.
#[test]
fn ctrl_c_quits_from_any_mode() {
    for mode in [
        AppMode::Normal,
        AppMode::Search,
        AppMode::Command,
        AppMode::Help,
        AppMode::ConfigGrep,
    ] {
        let mut state = AppState::new();
        seed(&mut state);
        state.mode = mode.clone();
        let effect = step(&mut state, key_ctrl('c'));
        assert!(
            matches!(effect, Some(SideEffect::Quit)),
            "Ctrl+C did not quit from mode {mode:?}, got {effect:?}"
        );
    }
}

/// Search mode rebuilds `state.search_query` character-by-character.
/// Each keystroke reaches the reducer as a fresh `Action::SearchInput(q)`
/// where `q` is the cumulative string. Backspace shrinks it.
#[test]
fn search_mode_typeahead_and_backspace_round_trip() {
    let mut state = AppState::new();
    seed(&mut state);
    state.push_view(View::GuestList);

    // Open search.
    step(&mut state, key_char('/'));
    assert!(matches!(state.mode, AppMode::Search));
    assert_eq!(state.search_query, "");

    // Type "alpinx" — the user mistyped the last char.
    for c in "alpinx".chars() {
        step(&mut state, key_char(c));
    }
    assert_eq!(state.search_query, "alpinx");

    // Backspace, then correct char.
    step(&mut state, key_code(KeyCode::Backspace));
    assert_eq!(state.search_query, "alpin");

    step(&mut state, key_char('e'));
    assert_eq!(state.search_query, "alpine");
}

/// Pressing q from a deep view-stack should pop, not quit, until the
/// stack is empty. Verifies the existing `Action::Back` semantics are
/// not regressed by future keymap changes. Note: `q` in Normal mode
/// always emits `Action::Quit`, NOT `Action::Back` — so this test
/// drives Esc instead, which IS the back key.
#[test]
fn back_pops_view_stack_and_only_quits_when_empty() {
    let mut state = AppState::new();
    seed(&mut state);

    // Push two views.
    step(&mut state, key_char('3')); // GuestList
    step(&mut state, key_char('4')); // StorageList
    assert_eq!(*state.current_view(), View::StorageList);

    // Esc once → pop to GuestList.
    assert!(step(&mut state, key_code(KeyCode::Esc)).is_none());
    assert_eq!(*state.current_view(), View::GuestList);

    // Esc again → pop to Dashboard (the implicit root).
    assert!(step(&mut state, key_code(KeyCode::Esc)).is_none());
    assert_eq!(*state.current_view(), View::Dashboard);

    // Esc once more on the empty stack → Quit.
    let effect = step(&mut state, key_code(KeyCode::Esc));
    assert!(
        matches!(effect, Some(SideEffect::Quit)),
        "expected Quit on empty nav_stack, got {effect:?}"
    );
}
