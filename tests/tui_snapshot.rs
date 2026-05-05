#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc
)]
//! TUI render snapshot harness — closes the "every TUI view is
//! unverified except by manual inspection" debt that the FASE 4
//! coverage analysis surfaced.
//!
//! ## How it works
//!
//! Each test:
//! 1. Builds an `AppState` via `AppState::new()` + targeted mutations
//!    (deterministic — no `Instant::now()`, no random vmids).
//! 2. Renders the chosen view into a `ratatui::backend::TestBackend`
//!    of fixed dimensions. Writing to the in-memory `Buffer` doesn't
//!    require a real terminal.
//! 3. Converts the `Buffer` to a stable text dump (cell symbols only,
//!    one line per row) and runs `insta::assert_snapshot!`.
//!
//! The dump deliberately DROPS styling (fg/bg/modifiers). A pure-text
//! snapshot survives ratatui Color enum changes + Theme tweaks; if we
//! ever need pixel-perfect colour assertions we add a separate dump
//! function. For now the goal is "did the LAYOUT or CONTENT change
//! unexpectedly", not "did the highlight color shift one shade".
//!
//! ## Adding a new view test
//!
//! ```rust,ignore
//! #[test]
//! fn my_view_typical_state() {
//!     let mut state = AppState::new();
//!     // ... mutate state ...
//!     let dump = render_to_string(80, 24, |f| {
//!         views::my_view::draw(f, f.area(), &state);
//!     });
//!     insta::assert_snapshot!(dump);
//! }
//! ```
//!
//! First run generates `tests/snapshots/tui_snapshot__my_view_…snap.new`.
//! Inspect with `cargo insta review` → accept → commit. Subsequent
//! runs diff against the accepted snap.

use proxxx::api::types::{Guest, GuestStatus, GuestType, Node, NodeStatus, StoragePool};
use proxxx::app::{AppState, View};
use proxxx::tui::{views, widgets};
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;

// ── Harness ─────────────────────────────────────────────────────

/// Render via `TestBackend` and return the text dump. Closure receives
/// `&mut Frame` exactly like the real TUI loop, so any view can be
/// driven without changing its signature.
fn render_to_string<F>(width: u16, height: u16, draw: F) -> String
where
    F: FnOnce(&mut ratatui::Frame),
{
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test terminal builds");
    terminal.draw(draw).expect("draw succeeds");
    buffer_to_string(terminal.backend().buffer())
}

/// Stable text dump of a Buffer: one line per row, cells joined by
/// their symbol, trailing whitespace trimmed. Drops styling.
///
/// Lines are joined with `\n` (no trailing `\n` on the last line) so
/// snapshot diffs read naturally.
fn buffer_to_string(buf: &Buffer) -> String {
    let mut lines: Vec<String> = Vec::with_capacity(buf.area.height as usize);
    for row in 0..buf.area.height {
        let mut line = String::with_capacity(buf.area.width as usize);
        for col in 0..buf.area.width {
            // Symbol() returns the rendered text for that cell —
            // multi-byte UTF-8 (emojis, box-drawing) appear as their
            // own glyph clusters, single-cell or zero-width.
            let cell = &buf[(col, row)];
            line.push_str(cell.symbol());
        }
        lines.push(line.trim_end().to_string());
    }
    lines.join("\n")
}

// ── State builders (deterministic) ─────────────────────────────

fn online_node(name: &str, cpu: f64, mem: u64, maxmem: u64) -> Node {
    Node {
        node: name.to_string(),
        status: NodeStatus::Online,
        cpu,
        maxcpu: 4,
        mem,
        maxmem,
        disk: maxmem / 4,
        maxdisk: maxmem * 8,
        uptime: 86_400, // 1 day, deterministic
    }
}

fn running_qemu(vmid: u32, name: &str, node: &str) -> Guest {
    Guest {
        vmid,
        name: name.to_string(),
        guest_type: GuestType::Qemu,
        status: GuestStatus::Running,
        node: node.to_string(),
        cpus: 2,
        cpu: 0.05,
        mem: 512 * 1024 * 1024,
        maxmem: 2 * 1024 * 1024 * 1024,
        disk: 0,
        maxdisk: 16 * 1024 * 1024 * 1024,
        uptime: 3600,
        ..Default::default()
    }
}

fn stopped_lxc(vmid: u32, name: &str, node: &str) -> Guest {
    Guest {
        vmid,
        name: name.to_string(),
        guest_type: GuestType::Lxc,
        status: GuestStatus::Stopped,
        node: node.to_string(),
        ..Default::default()
    }
}

fn storage_pool(name: &str, used: u64, total: u64) -> StoragePool {
    // Note: StoragePool intentionally has no `node` field; PVE returns
    // it without one (the route puts the node in the URL). proxxx
    // discards the URL context when modeling.
    StoragePool {
        storage: name.to_string(),
        used,
        total,
        avail: total.saturating_sub(used),
        active: true,
        storage_type: "lvm".to_string(),
        content: "images,rootdir".to_string(),
    }
}

// ── Tests ──────────────────────────────────────────────────────

#[test]
fn help_overlay_renders_keymap() {
    // Stateless view — perfect smoke for the harness itself.
    // If this snapshot drifts, the keymap docs in the modal changed.
    let dump = render_to_string(80, 30, |f| {
        widgets::modal::draw_help_overlay(f, f.area());
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn dashboard_empty_cluster_does_not_panic_and_shows_idle_state() {
    // Mountain coverage of line 89 (RBAC matrix): blind persona sees
    // an empty cluster — the dashboard MUST render without dividing
    // by zero on `total_maxcpu` / `total_maxmem`. Snapshot proves it.
    let state = AppState::new();
    assert!(state.nodes.is_empty(), "fixture pre-condition");

    let dump = render_to_string(80, 24, |f| {
        views::dashboard::draw(f, f.area(), &state);
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn dashboard_with_two_nodes_aggregates_correctly() {
    let mut state = AppState::new();
    state.nodes = vec![
        online_node("pve1", 0.5, 4 * 1024 * 1024 * 1024, 8 * 1024 * 1024 * 1024),
        online_node("pve2", 1.2, 2 * 1024 * 1024 * 1024, 8 * 1024 * 1024 * 1024),
    ];
    state.guests = vec![
        running_qemu(100, "vm-prod-01", "pve1"),
        stopped_lxc(200, "ct-test", "pve2"),
    ];
    state.storage = vec![storage_pool("local-lvm", 100_000_000_000, 500_000_000_000)];

    let dump = render_to_string(100, 30, |f| {
        views::dashboard::draw(f, f.area(), &state);
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn guests_table_with_mixed_status() {
    let mut state = AppState::new();
    state.nav_stack = vec![View::GuestList];
    state.guests = vec![
        running_qemu(100, "vm-prod-01", "pve1"),
        running_qemu(101, "vm-prod-02", "pve1"),
        stopped_lxc(200, "ct-staging", "pve2"),
        // ANSI-injection test from Phase 5.13 invariant — name with
        // ESC sequence must be sanitized at render time. If the
        // snapshot ever shows an ESC byte, the sanitize wiring broke.
        Guest {
            vmid: 999,
            name: "vm-\x1b[2J\x1b[Hattacker".to_string(),
            ..running_qemu(999, "", "pve1")
        },
    ];

    let dump = render_to_string(100, 20, |f| {
        views::guests::draw(f, f.area(), &state);
    });
    insta::assert_snapshot!(dump);
}

// ── Empty-state coverage for the remaining 13 views ─────────────
//
// First-batch goal: prove every view RENDERS without panicking on
// fresh AppState. This catches the most common regression class
// (renderer assuming non-empty Vec / Option). Populated states get
// added on-touch when behaviour changes.
//
// `ssh_session` is intentionally skipped — its draw signature takes
// a `SessionFrameInput` carrying a PTY parser instance, which needs
// a multi-step setup (vt100::Parser, term resize handshake) that's
// not worth replicating just for an empty snapshot.

#[test]
fn approval_view_empty_state() {
    let state = AppState::new();
    let dump = render_to_string(80, 20, |f| {
        views::approval::draw(f, f.area(), &state);
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn backup_view_empty_state() {
    let state = AppState::new();
    let dump = render_to_string(100, 20, |f| {
        views::backup::draw(f, f.area(), &state);
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn compare_view_with_two_selected_guests() {
    let mut state = AppState::new();
    state.guests = vec![
        running_qemu(100, "vm-prod", "pve1"),
        running_qemu(101, "vm-staging", "pve1"),
    ];
    let dump = render_to_string(100, 20, |f| {
        views::compare::draw(f, f.area(), &state, &[100, 101]);
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn grep_view_empty_state() {
    let state = AppState::new();
    let dump = render_to_string(100, 20, |f| {
        views::grep::draw(f, f.area(), &state);
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn ha_console_view_empty_state() {
    let state = AppState::new();
    let dump = render_to_string(100, 20, |f| {
        views::ha_console::draw(f, f.area(), &state);
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn hardware_view_empty_state() {
    let state = AppState::new();
    let dump = render_to_string(100, 20, |f| {
        views::hardware::draw(f, f.area(), &state, "pve1");
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn heatmap_view_empty_state() {
    let state = AppState::new();
    let dump = render_to_string(100, 20, |f| {
        views::heatmap::draw(f, f.area(), &state);
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn iso_library_view_empty_state() {
    let state = AppState::new();
    let dump = render_to_string(100, 20, |f| {
        views::iso_library::draw(f, f.area(), &state);
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn queue_view_empty_state() {
    let state = AppState::new();
    let dump = render_to_string(100, 20, |f| {
        views::queue::draw(f, f.area(), &state);
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn search_view_empty_state() {
    let state = AppState::new();
    let dump = render_to_string(100, 20, |f| {
        views::search::draw(f, f.area(), &state);
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn snaptree_view_empty_state() {
    let state = AppState::new();
    let dump = render_to_string(100, 20, |f| {
        views::snaptree::draw(f, f.area(), &state, 100);
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn storage_view_empty_state() {
    let state = AppState::new();
    let dump = render_to_string(100, 20, |f| {
        views::storage::draw(f, f.area(), &state);
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn tasks_view_empty_state() {
    let state = AppState::new();
    let dump = render_to_string(100, 20, |f| {
        views::tasks::draw(f, f.area(), &state, "UPID:test:0:0:0:0:0:0:0:");
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn timeline_view_empty_state() {
    let state = AppState::new();
    let dump = render_to_string(100, 20, |f| {
        views::timeline::draw(f, f.area(), &state);
    });
    insta::assert_snapshot!(dump);
}

// ── ssh_session view (the one that needed PTY parser setup) ────
//
// Earlier batches deferred this — the renderer takes a
// `SessionFrameInput` carrying a `SharedParser` (= `Arc<Mutex<vt100::Parser>>`).
// Turns out the parser API is trivially constructable: `vt100::Parser::new(rows,
// cols, scrollback)`. Snapshotting all three branches of the renderer's
// state machine (no parser + active, no parser + finished, parser
// populated) closes the last view in the matrix.

#[test]
fn ssh_session_connecting_placeholder() {
    let input = views::ssh_session::SessionFrameInput {
        vmid: 100,
        host: Some("10.0.0.5"),
        user: Some("root"),
        parser: None,
        finished: false,
    };
    let dump = render_to_string(80, 12, |f| {
        views::ssh_session::draw(f, f.area(), &input);
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn ssh_session_finished_placeholder() {
    let input = views::ssh_session::SessionFrameInput {
        vmid: 100,
        host: None,
        user: None,
        parser: None,
        finished: true,
    };
    let dump = render_to_string(80, 12, |f| {
        views::ssh_session::draw(f, f.area(), &input);
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn ssh_session_with_pty_content() {
    use std::sync::{Arc, Mutex};
    // Construct a parser sized to the inner area (renderer carves
    // 1 row of border on each side, so 80×10 = 78×10 inner). Feed
    // some deterministic ASCII; PtyView snapshots cell-by-cell.
    let parser = Arc::new(Mutex::new(vt100::Parser::new(10, 78, 0)));
    parser
        .lock()
        .expect("parser lock")
        .process(b"alpine:~# uname -a\r\nLinux alpine 6.12.0-pve #1 SMP\r\nalpine:~# ");

    let input = views::ssh_session::SessionFrameInput {
        vmid: 100,
        host: Some("10.0.0.5"),
        user: Some("root"),
        parser: Some(&parser),
        finished: false,
    };
    let dump = render_to_string(80, 12, |f| {
        views::ssh_session::draw(f, f.area(), &input);
    });
    insta::assert_snapshot!(dump);
}

#[test]
fn nodes_view_with_quorum_and_stale_stats_badges() {
    let mut state = AppState::new();
    state.nav_stack = vec![View::NodeList];
    state.nodes = vec![
        online_node("pve1", 0.5, 4 * 1024 * 1024 * 1024, 8 * 1024 * 1024 * 1024),
        online_node("pve2", 0.0, 0, 8 * 1024 * 1024 * 1024),
    ];
    state.cluster_quorate = Some(true);
    state.nodes_with_stale_stats.insert("pve2".to_string());

    let dump = render_to_string(100, 15, |f| {
        views::nodes::draw(f, f.area(), &state);
    });
    insta::assert_snapshot!(dump);
}
