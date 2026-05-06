//! Always-visible 1-row footer with contextual keybindings.
//!
//! Why this exists: the only navigation help today is the `?` modal.
//! New users have no on-screen reminder of what keys do what — they
//! hit a wrong key, see no feedback, exit, look up the cheat sheet,
//! come back. Always-visible footer follows the htop / lazygit / k9s
//! convention: cheap, non-blocking, gets out of the way the moment
//! the operator types a command.
//!
//! Suppression: the input bar (Command / InputTag / InputBroadcast
//! modes) renders a 3-row overlay at the bottom — it covers the
//! footer naturally without explicit gating. Confirm + Help modals
//! cover the whole screen. Search renders its own overlay.
//!
//! Pure-function `bindings_for` returns the (key, label) list per
//! (View, AppMode). Pinned by unit tests so a future refactor that
//! drops the `q`-back invariant on a view fails loudly.

use crate::app::{AppMode, AppState, View};
use crate::tui::theme::Theme;
use ratatui::{
    layout::{Alignment, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};

pub fn draw_status_footer(f: &mut Frame, area: Rect, state: &AppState) {
    let bindings = bindings_for(&state.current_view(), &state.mode);
    let mut spans: Vec<Span<'static>> = Vec::with_capacity(bindings.len() * 4 + 3);

    // Mode indicator pill — promoted from the per-view status bars
    // (dashboard.rs / nodes.rs each had their own copy) into the
    // single global footer. Same look as the legacy dashboard pill
    // (accent bg, bg fg, bold) so the visual continuity is preserved.
    let mode_label = mode_label_for(&state.mode);
    spans.push(Span::styled(
        format!(" {mode_label} "),
        Style::default()
            .fg(Theme::BG)
            .bg(Theme::ACCENT)
            .add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::styled(" │ ", Style::default().fg(Theme::TEXT_MUTED)));

    for (i, (key, label)) in bindings.iter().enumerate() {
        if i > 0 {
            spans.push(Span::styled(" · ", Style::default().fg(Theme::TEXT_MUTED)));
        }
        spans.push(Span::styled(
            format!(" {key} "),
            Style::default()
                .fg(Theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            (*label).to_string(),
            Style::default().fg(Theme::TEXT_DIM),
        ));
    }
    let p = Paragraph::new(Line::from(spans))
        .alignment(Alignment::Left)
        .style(Style::default().bg(Theme::BG_ELEVATED));
    f.render_widget(p, area);
}

/// Pure mapping of `AppMode` → label rendered in the footer's mode
/// pill. Pre-fix this lived in `dashboard.rs::draw_status_bar` only
/// — `nodes.rs` re-rendered the dashboard chrome (a copy-paste bug
/// from when it was forked) and other views had no mode indicator
/// at all. Centralised here so every view shows the same.
const fn mode_label_for(mode: &AppMode) -> &'static str {
    match mode {
        AppMode::Normal => "NORMAL",
        AppMode::Search => "SEARCH",
        AppMode::Command => "COMMAND",
        AppMode::InputTag => "INPUT TAG",
        AppMode::InputBroadcast => "BROADCAST",
        AppMode::ConfigGrep => "CONFIG GREP",
        AppMode::Confirm { .. } => "CONFIRM",
        AppMode::SshSession { .. } => "SSH",
        AppMode::Help => "HELP",
    }
}

/// Returns the `(key, label)` pairs to surface for the current
/// (view, mode). Pure — testable without rendering.
fn bindings_for(view: &View, mode: &AppMode) -> Vec<(&'static str, &'static str)> {
    if matches!(mode, AppMode::Help) {
        return vec![("any key", "dismiss help")];
    }
    if matches!(mode, AppMode::SshSession { .. }) {
        return vec![("Ctrl+]", "exit SSH")];
    }
    if matches!(
        mode,
        AppMode::Search | AppMode::Command | AppMode::InputTag | AppMode::InputBroadcast
    ) {
        // Input bar overlays the footer in these modes; we still
        // return a useful set so the visible-row order doesn't shift
        // if the overlay ever shrinks.
        return vec![("Esc", "cancel"), ("↵", "submit")];
    }

    // Truth-in-binds: `q` is hardcoded to Action::Quit (always exits the
    // app). `Esc` / `h` / `←` are the back-out chord (Action::Back —
    // pops the nav stack, falls through to Quit only when the stack is
    // empty / Dashboard is the root). Pre-fix the footer claimed
    // "q back" on internal views, which lied: an operator who typed
    // `q` from GuestList expecting to return to Dashboard got dumped
    // back to the shell instead. Now the footer surfaces both chords
    // separately so the legend matches the keymap.
    match view {
        View::Dashboard => vec![
            ("↵", "open"),
            ("/", "search"),
            ("g", "guests"),
            ("n", "nodes"),
            ("s", "storage"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::NodeList => vec![
            ("j/k", "nav"),
            ("↵", "detail"),
            ("/", "search"),
            ("Esc", "back"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::GuestList => vec![
            ("j/k", "nav"),
            ("↵", "detail"),
            ("s", "start"),
            ("S", "stop"),
            ("r", "restart"),
            ("c", "console"),
            ("/", "search"),
            ("Esc", "back"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::GuestDetail { .. } => vec![
            ("s", "start"),
            ("S", "stop"),
            ("r", "restart"),
            ("c", "console"),
            ("Esc", "back"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::StorageList => vec![
            ("j/k", "nav"),
            ("↵", "detail"),
            ("Esc", "back"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::TaskLog { .. } => vec![
            ("j/k", "scroll"),
            ("Esc", "back"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::ApprovalQueue => vec![
            ("a", "approve"),
            ("d", "deny"),
            ("Esc", "back"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::OperationQueue => vec![
            ("j/k", "nav"),
            ("d", "remove"),
            ("C", "commit"),
            ("R", "refresh"),
            ("Esc", "back"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::Heatmap => vec![("Esc", "back"), ("?", "help"), ("q", "quit")],
        View::BackupBoard => vec![
            ("j/k", "nav"),
            ("Esc", "back"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::AuditTimeline => vec![
            ("j/k", "scroll"),
            ("Esc", "back"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::ConfigGrep => vec![
            ("/", "search"),
            ("Esc", "back"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::SnapshotTree { .. } => vec![
            ("j/k", "nav"),
            ("Esc", "back"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::IsoLibrary => vec![
            ("j/k", "nav"),
            ("↵", "download"),
            ("Esc", "back"),
            ("?", "help"),
            ("q", "quit"),
        ],
        View::HaConsole => vec![("Esc", "back"), ("?", "help"), ("q", "quit")],
        View::Hardware { .. } => vec![("Esc", "back"), ("?", "help"), ("q", "quit")],
        View::GuestCompare { .. } => vec![("Esc", "back"), ("?", "help"), ("q", "quit")],
        View::GuestSshSession { .. } => vec![("Ctrl+]", "exit SSH")],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_has_navigation_keys() {
        let b = bindings_for(&View::Dashboard, &AppMode::Normal);
        assert!(b.iter().any(|(k, _)| *k == "↵"));
        assert!(b.iter().any(|(k, _)| *k == "/"));
        assert!(b.iter().any(|(k, _)| *k == "?"));
        assert!(b.iter().any(|(k, _)| *k == "q"));
    }

    #[test]
    fn guest_list_has_lifecycle_keys() {
        // Pre-fix, the only way to discover s/S/r was the `?` modal.
        // The footer must surface the lifecycle keys directly so a new
        // user sees "I can stop this VM" without leaving the view.
        let b = bindings_for(&View::GuestList, &AppMode::Normal);
        for k in &["s", "S", "r", "c"] {
            assert!(b.iter().any(|(key, _)| key == k), "missing key {k}");
        }
    }

    #[test]
    fn help_mode_overrides_view_bindings() {
        // In Help mode, the only useful binding is "any key dismisses".
        // The view-specific list would be misleading — those keys are
        // not active while help is up.
        let b = bindings_for(&View::Dashboard, &AppMode::Help);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].0, "any key");
    }

    #[test]
    fn ssh_session_mode_shows_exit_chord() {
        // Inside an SSH PTY, every key (except Ctrl+]) goes to the
        // remote shell. Footer pins the exit chord so the operator
        // doesn't get trapped.
        let b = bindings_for(&View::Dashboard, &AppMode::SshSession { vmid: 100 });
        assert_eq!(b, vec![("Ctrl+]", "exit SSH")]);
    }

    #[test]
    fn input_bar_modes_show_minimal_universal_bindings() {
        for mode in &[
            AppMode::Search,
            AppMode::Command,
            AppMode::InputTag,
            AppMode::InputBroadcast,
        ] {
            let b = bindings_for(&View::GuestList, mode);
            assert!(b.iter().any(|(k, _)| *k == "Esc"));
            assert!(b.iter().any(|(k, _)| *k == "↵"));
        }
    }

    #[test]
    fn every_view_has_a_quit_chord() {
        // Every view in Normal mode must surface SOME way to leave —
        // `q:quit` (every regular view), `Ctrl+]` (SSH session, where
        // every key forwards to the remote shell). Pre-fix the
        // assertion was conflated with "back" — the guarantee here is
        // narrower: there's always an exit-the-app path visible.
        let views: Vec<View> = vec![
            View::Dashboard,
            View::NodeList,
            View::GuestList,
            View::GuestDetail { vmid: 100 },
            View::StorageList,
            View::TaskLog {
                upid: String::new(),
            },
            View::ApprovalQueue,
            View::OperationQueue,
            View::Heatmap,
            View::BackupBoard,
            View::AuditTimeline,
            View::ConfigGrep,
            View::SnapshotTree { vmid: 100 },
            View::IsoLibrary,
            View::HaConsole,
            View::Hardware {
                node: String::new(),
            },
            View::GuestCompare { guests: vec![] },
            View::GuestSshSession { vmid: 100 },
        ];
        for v in &views {
            let b = bindings_for(v, &AppMode::Normal);
            let has_exit = b.iter().any(|(k, _)| *k == "q" || *k == "Ctrl+]");
            assert!(has_exit, "{v:?} surfaces no quit binding");
        }
    }

    #[test]
    fn footer_truth_q_quits_esc_goes_back_on_internal_views() {
        // Pre-fix the footer claimed "q back" on internal views — a
        // lie: event::map_key wires `q` to Action::Quit unconditionally,
        // while Action::Back is bound to Esc / h / ←. An operator who
        // typed `q` from GuestList expecting to return to Dashboard
        // got dumped back to the shell. This test pins the truth: every
        // internal view must surface BOTH chords as separate bindings,
        // with the correct labels.
        let internal_views: Vec<View> = vec![
            View::NodeList,
            View::GuestList,
            View::GuestDetail { vmid: 100 },
            View::StorageList,
            View::TaskLog {
                upid: String::new(),
            },
            View::ApprovalQueue,
            View::OperationQueue,
            View::Heatmap,
            View::BackupBoard,
            View::AuditTimeline,
            View::ConfigGrep,
            View::SnapshotTree { vmid: 100 },
            View::IsoLibrary,
            View::HaConsole,
            View::Hardware {
                node: String::new(),
            },
            View::GuestCompare { guests: vec![] },
        ];
        for v in &internal_views {
            let b = bindings_for(v, &AppMode::Normal);
            let q_label = b.iter().find(|(k, _)| *k == "q").map(|(_, l)| *l);
            let esc_label = b.iter().find(|(k, _)| *k == "Esc").map(|(_, l)| *l);
            assert_eq!(
                q_label,
                Some("quit"),
                "{v:?}: q must say 'quit' (it triggers Action::Quit unconditionally)"
            );
            assert_eq!(
                esc_label,
                Some("back"),
                "{v:?}: Esc must say 'back' (it triggers Action::Back which pops the stack)"
            );
        }
    }

    #[test]
    fn dashboard_omits_back_chord_at_root() {
        // Dashboard is the bottom of the nav stack — Action::Back from
        // here also exits (pop_view returns false → SideEffect::Quit),
        // so showing "Esc back" would be misleading. Pin: dashboard
        // surfaces `q quit` and nothing labelled "back".
        let b = bindings_for(&View::Dashboard, &AppMode::Normal);
        assert_eq!(
            b.iter().find(|(k, _)| *k == "q").map(|(_, l)| *l),
            Some("quit")
        );
        assert!(
            !b.iter().any(|(_, l)| *l == "back"),
            "Dashboard should not surface 'back' (it's the nav root)"
        );
    }

    #[test]
    fn help_binding_appears_on_every_top_level_view() {
        // Discoverability invariant: the operator should see "?: help"
        // surface on every view they can navigate to from the dashboard,
        // so the path to the keymap reference is one keypress away.
        // SSH-session is the deliberate exception (key forwarded to
        // remote shell) — covered by ssh_session_mode_shows_exit_chord.
        for v in &[
            View::Dashboard,
            View::NodeList,
            View::GuestList,
            View::StorageList,
            View::Heatmap,
            View::BackupBoard,
            View::HaConsole,
        ] {
            let b = bindings_for(v, &AppMode::Normal);
            assert!(
                b.iter().any(|(k, _)| *k == "?"),
                "view {v:?} missing ?:help"
            );
        }
    }
}
