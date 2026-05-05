#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::uninlined_format_args
)]
//! End-to-end contract test for the **`c` console** keybind path.
//!
//! User report: "pressing `c` (or Enter) on an LXC/VM doesn't open a
//! console". This test pins every link in the chain so any future
//! regression points at exactly which step broke:
//!
//! ```text
//!   crossterm::KeyEvent('c')
//!       │
//!       ▼   tui::event::map_key(state)
//!   Option<Action::OpenGuestSsh { vmid }>
//!       │
//!       ▼   app::update(state, action)
//!   Option<SideEffect::OpenSshSession { vmid }>
//!       │
//!       ▼   tui::run loop dispatches to ssh_handler.open()
//!   ssh_handler::SshSessionHandler::open(vmid, cols, rows)
//!       │
//!       ▼   on result, reducer dispatches:
//!   Action::SshSessionFailed { vmid, error: String }    (failure)
//!     OR  (success: PtySession surfaces silently)
//! ```
//!
//! Tests below cover the FIRST FOUR steps (the pure parts). The
//! `ssh_handler.open()` step depends on real network + valid SSH key
//! and is covered by E2E suite, NOT here.
//!
//! ## How to read failures
//!
//! - `keymap_c_in_guest_list_returns_open_ssh_for_qemu` failing →
//!   the `c` keybind regressed in `event.rs`.
//! - `keymap_c_in_other_views_is_inert` failing → `c` is firing
//!   outside the guest list (would interrupt other views).
//! - `reducer_open_guest_ssh_pushes_view_and_emits_side_effect`
//!   failing → reducer regression at `Action::OpenGuestSsh`.
//! - `reducer_ssh_session_failed_clears_view_and_surfaces_error`
//!   failing → the failure path no longer pops the view, leaving
//!   the user stuck on a "connecting…" screen forever.
//! - `command_ssh_vmid_parses_same_as_c_key` failing → the `:ssh
//!   <vmid>` command no longer mirrors the keybind, breaking the
//!   discoverability contract.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use proxxx::api::types::{Guest, GuestStatus, GuestType, Node, NodeStatus};
use proxxx::app::{parse_command_action, update, Action, AppMode, AppState, SideEffect, View};
use proxxx::tui::event::map_key;

/// Build a state with two guests (one QEMU VM, one LXC) on `pve1`,
/// pre-positioned on the `GuestList` view with selection on the QEMU.
fn state_with_qemu_and_lxc() -> AppState {
    let mut state = AppState::new();
    state.is_loading = false;
    state.nodes = vec![Node {
        node: "pve1".into(),
        status: NodeStatus::Online,
        ..Default::default()
    }];
    state.guests = vec![
        Guest {
            vmid: 100,
            name: "web-vm".into(),
            status: GuestStatus::Running,
            guest_type: GuestType::Qemu,
            node: "pve1".into(),
            cpus: 2,
            ..Default::default()
        },
        Guest {
            vmid: 200,
            name: "db-lxc".into(),
            status: GuestStatus::Running,
            guest_type: GuestType::Lxc,
            node: "pve1".into(),
            cpus: 1,
            ..Default::default()
        },
    ];
    state.push_view(View::GuestList);
    state.selected_index = 0; // points at the QEMU VM
    state
}

const fn key(c: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
}

// ── KEYMAP layer ────────────────────────────────────────

#[test]
fn keymap_c_in_guest_list_returns_open_ssh_for_qemu() {
    let state = state_with_qemu_and_lxc();
    // Selection is on vmid 100 (QEMU). `c` → OpenGuestSsh{vmid: 100}.
    let action = map_key(key('c'), &state);
    assert_eq!(
        action,
        Some(Action::OpenGuestSsh { vmid: 100 }),
        "pressing `c` on a QEMU guest must dispatch OpenGuestSsh"
    );
}

#[test]
fn keymap_c_in_guest_list_returns_open_ssh_for_lxc() {
    let mut state = state_with_qemu_and_lxc();
    state.selected_index = 1; // LXC
    let action = map_key(key('c'), &state);
    assert_eq!(
        action,
        Some(Action::OpenGuestSsh { vmid: 200 }),
        "pressing `c` on an LXC must dispatch OpenGuestSsh — same path as QEMU"
    );
}

#[test]
fn keymap_c_with_empty_guest_list_is_inert() {
    let mut state = AppState::new();
    state.is_loading = false;
    state.push_view(View::GuestList);
    // No guests in state → visible_guests().get(0) is None → no Action.
    assert!(
        map_key(key('c'), &state).is_none(),
        "pressing `c` with no guests must NOT dispatch a stale OpenGuestSsh"
    );
}

#[test]
fn keymap_c_in_other_views_is_inert() {
    // Outside the GuestList view, `c` must be a no-op so that pressing
    // it on the Dashboard / NodeList / TaskLog doesn't accidentally
    // open an SSH session against an unrelated vmid.
    let mut state = state_with_qemu_and_lxc();
    state.nav_stack.clear();
    state.push_view(View::Dashboard);
    assert!(
        map_key(key('c'), &state).is_none(),
        "`c` on Dashboard must NOT trigger OpenGuestSsh"
    );

    state.nav_stack.clear();
    state.push_view(View::StorageList);
    assert!(
        map_key(key('c'), &state).is_none(),
        "`c` on StorageList must NOT trigger OpenGuestSsh"
    );
}

#[test]
fn keymap_ctrl_c_still_quits_does_not_collide_with_console_binding() {
    // Ctrl+C must remain Quit even after we wired plain `c` to
    // OpenGuestSsh — the Ctrl modifier disambiguates.
    let state = state_with_qemu_and_lxc();
    let evt = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
    assert_eq!(
        map_key(evt, &state),
        Some(Action::Quit),
        "Ctrl+C must still Quit; `c` (no modifier) is the new console binding"
    );
}

// ── REDUCER layer ───────────────────────────────────────

#[test]
fn reducer_open_guest_ssh_pushes_view_and_emits_side_effect() {
    let mut state = state_with_qemu_and_lxc();
    let initial_stack_depth = state.nav_stack.len();

    let effect = update(&mut state, Action::OpenGuestSsh { vmid: 100 });

    assert!(
        matches!(effect, Some(SideEffect::OpenSshSession { vmid: 100 })),
        "reducer must emit OpenSshSession{{vmid: 100}}, got {effect:?}"
    );
    assert_eq!(
        state.nav_stack.len(),
        initial_stack_depth + 1,
        "view stack must grow by 1 (so Esc returns to GuestList)"
    );
    assert_eq!(
        *state.current_view(),
        View::GuestSshSession { vmid: 100 },
        "current view must be the SSH session view"
    );
    assert_eq!(
        state.mode,
        AppMode::SshSession { vmid: 100 },
        "mode must flip to SshSession so the TUI loop bypasses normal keymap"
    );
}

#[test]
fn reducer_ssh_session_failed_clears_view_and_surfaces_error() {
    // First open the session, then deliver a failure. The reducer
    // must pop the view AND set state.error so the user sees what
    // happened (the canonical case is "SSH key not configured for
    // this vmid" — the user must NOT be left on a blank screen).
    let mut state = state_with_qemu_and_lxc();
    update(&mut state, Action::OpenGuestSsh { vmid: 100 });
    assert!(matches!(state.current_view(), View::GuestSshSession { .. }));

    let _ = update(
        &mut state,
        Action::SshSessionFailed {
            vmid: 100,
            error: "no key configured for guest 100".into(),
        },
    );

    assert!(
        !matches!(state.current_view(), View::GuestSshSession { .. }),
        "failure must pop the SSH view"
    );
    assert_eq!(state.mode, AppMode::Normal, "mode must drop back to Normal");
    let err = state.error.as_deref().unwrap_or("");
    assert!(
        err.contains("100") && err.to_lowercase().contains("ssh"),
        "user-visible error must name the vmid + mention SSH; got: {err}"
    );
}

#[test]
fn reducer_close_ssh_session_pops_and_emits_close_side_effect() {
    let mut state = state_with_qemu_and_lxc();
    update(&mut state, Action::OpenGuestSsh { vmid: 200 });

    let effect = update(&mut state, Action::CloseSshSession);

    assert!(
        matches!(effect, Some(SideEffect::CloseSshSession)),
        "explicit close must emit CloseSshSession, got {effect:?}"
    );
    assert_eq!(state.mode, AppMode::Normal, "mode back to Normal");
    assert!(
        !matches!(state.current_view(), View::GuestSshSession { .. }),
        "view stack must no longer have the SSH view on top"
    );
}

// ── COMMAND-MODE parity (`:ssh <vmid>`) ──────────────────

#[test]
fn command_ssh_vmid_parses_same_as_c_key() {
    // The discoverability contract says `c` and `:ssh <vmid>` must
    // produce the SAME Action so muscle memory and command palette
    // converge on one underlying flow.
    let parsed = parse_command_action("ssh 100");
    assert_eq!(
        parsed,
        Some(Action::OpenGuestSsh { vmid: 100 }),
        ":ssh <vmid> must produce OpenGuestSsh"
    );
}

#[test]
fn command_ssh_invalid_vmid_returns_none() {
    assert!(
        parse_command_action("ssh notanumber").is_none(),
        ":ssh <non-numeric> must NOT produce a stale OpenGuestSsh"
    );
    assert!(
        parse_command_action("ssh").is_none(),
        ":ssh with no vmid must NOT produce an OpenGuestSsh"
    );
}

// ── INTEGRATION: full happy-path chain ──────────────────

#[test]
fn full_chain_keypress_to_side_effect_for_lxc() {
    // The single test that proves the whole stack: a user pressing
    // `c` while highlighting an LXC ends with a SideEffect ready to
    // dispatch to ssh_handler.open(200, ...). If THIS fails but the
    // unit tests above pass, the wiring between map_key and the
    // reducer regressed.
    let mut state = state_with_qemu_and_lxc();
    state.selected_index = 1; // LXC vmid 200

    let action = map_key(key('c'), &state).expect("`c` must produce an Action");
    let effect = update(&mut state, action).expect("Action must produce a SideEffect");

    assert!(
        matches!(effect, SideEffect::OpenSshSession { vmid: 200 }),
        "full chain must end at OpenSshSession{{vmid: 200}}, got {effect:?}"
    );
    assert_eq!(*state.current_view(), View::GuestSshSession { vmid: 200 });
    assert_eq!(state.mode, AppMode::SshSession { vmid: 200 });
}
