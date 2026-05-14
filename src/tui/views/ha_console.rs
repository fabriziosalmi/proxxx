//! HA + replication console (feature #5).
//!
//! Read-only inspector. Three vertical sections:
//!   ┌── HA manager + cluster quorum ──┐
//!   ├── HA groups + resources ────────┤
//!   └── Replication jobs + status ────┘
//!
//! No editing affordances. Per the draconian review's honest cuts, we
//! don't reimplement pve-ha-manager scoring — but we do show a "what if
//! this node fails?" preview alongside each resource using the
//! deterministic priority-list inspector in `app::ha`.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::prelude::Frame;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, Wrap};

use crate::api::types::{ReplicationHealth, ReplicationStatus};
use crate::app::ha::{
    online_nodes, preview_failover, summarise_replication_health, FailoverPreview,
};
use crate::app::AppState;
use crate::tui::theme::Theme;

pub fn draw(f: &mut Frame, area: Rect, state: &AppState) {
    if state.ha_loading {
        let p = Paragraph::new(Line::from(Span::styled(
            "Loading HA console…",
            Style::default().fg(Theme::TEXT_DIM),
        )))
        .alignment(ratatui::layout::Alignment::Center);
        f.render_widget(p, area);
        return;
    }

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(7),  // header (manager + quorum)
            Constraint::Min(8),     // groups + resources
            Constraint::Length(10), // replication
        ])
        .split(area);

    draw_header(f, layout[0], state);
    draw_ha(f, layout[1], state);
    draw_replication(f, layout[2], state);
}

fn draw_header(f: &mut Frame, area: Rect, state: &AppState) {
    let mut lines: Vec<Line> = Vec::new();

    // Cluster quorum summary.
    let online = online_nodes(&state.cluster_entries);
    let total = state
        .cluster_entries
        .iter()
        .filter(|e| e.entry_type == "node")
        .count();
    let quorate = state.cluster_entries.iter().any(|e| e.quorate);
    let quorate_span = if quorate {
        Span::styled(
            "QUORATE",
            Style::default()
                .fg(Theme::SUCCESS)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            "NO QUORUM",
            Style::default()
                .fg(Theme::DANGER)
                .add_modifier(Modifier::BOLD),
        )
    };

    lines.push(Line::from(vec![
        Span::styled("Cluster:    ", Style::default().fg(Theme::TEXT_DIM)),
        quorate_span,
        Span::raw(format!("  ·  {}/{} nodes online", online.len(), total)),
    ]));

    // HA manager state.
    let (master, mode) = state
        .ha_manager
        .as_ref()
        .map_or(("(unknown)", "(unknown)"), |m| {
            (m.master.as_str(), m.mode.as_str())
        });
    let mode_style = if mode == "active" {
        Style::default().fg(Theme::SUCCESS)
    } else {
        Style::default().fg(Theme::WARNING)
    };
    lines.push(Line::from(vec![
        Span::styled("HA master:  ", Style::default().fg(Theme::TEXT_DIM)),
        Span::raw(master.to_string()),
        Span::styled("   mode: ", Style::default().fg(Theme::TEXT_DIM)),
        Span::styled(mode.to_string(), mode_style),
    ]));

    // Online node list with local marker.
    let mut node_spans: Vec<Span> = vec![Span::styled(
        "Nodes:      ",
        Style::default().fg(Theme::TEXT_DIM),
    )];
    for entry in state
        .cluster_entries
        .iter()
        .filter(|e| e.entry_type == "node")
    {
        let style = if entry.online {
            Style::default().fg(Theme::SUCCESS)
        } else {
            Style::default().fg(Theme::DANGER)
        };
        let marker = if entry.local { "*" } else { "" };
        node_spans.push(Span::styled(
            format!("{}{}  ", entry.name, marker),
            style.add_modifier(Modifier::BOLD),
        ));
    }
    lines.push(Line::from(node_spans));
    lines.push(Line::from(Span::styled(
        " (* = local node — the one proxxx is connected to)",
        Style::default().fg(Theme::TEXT_DIM),
    )));

    let block = Block::default()
        .borders(Borders::ALL)
        .title(" cluster status ");
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_ha(f: &mut Frame, area: Rect, state: &AppState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    // ── HA groups ─────────────────────────────────────────
    let group_rows: Vec<Row> = state
        .ha_groups
        .iter()
        .map(|g| {
            let priority = g.parse_priority_list();
            let summary = if priority.is_empty() {
                "(empty)".to_string()
            } else {
                priority
                    .iter()
                    .map(|(n, p)| format!("{n}:{p}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let flags = match (g.restricted, g.nofailback) {
                (true, true) => "restricted+nofallback",
                (true, false) => "restricted",
                (false, true) => "nofallback",
                (false, false) => "—",
            };
            Row::new(vec![g.name.clone(), summary, flags.to_string()])
        })
        .collect();
    let groups_table = Table::new(
        group_rows,
        [
            Constraint::Length(20),
            Constraint::Min(20),
            Constraint::Length(22),
        ],
    )
    .header(
        Row::new(vec!["group", "priority", "flags"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" HA groups ({}) ", state.ha_groups.len())),
    );
    f.render_widget(groups_table, cols[0]);

    // ── HA resources + failover preview ───────────────────
    let online = online_nodes(&state.cluster_entries);
    // Find current node for each HA-managed VM by cross-referencing state.guests.
    let current_node = |sid: &str| -> Option<String> {
        let resource = state.ha_resources.iter().find(|r| r.sid == sid)?;
        let vmid = resource.vmid()?;
        state
            .guests
            .iter()
            .find(|g| g.vmid == vmid)
            .map(|g| g.node.clone())
    };

    let res_rows: Vec<Row> = state
        .ha_resources
        .iter()
        .map(|r| {
            let cur = current_node(&r.sid).unwrap_or_default();
            // What if `cur` fails right now?
            let preview = if cur.is_empty() {
                "?".to_string()
            } else {
                match preview_failover(r, &state.ha_groups, &online, &cur, &cur) {
                    FailoverPreview::Relocate { target, priority } => {
                        format!("-> {target} (prio {priority})")
                    }
                    FailoverPreview::Stuck {
                        restricted: true, ..
                    } => "STUCK (restricted)".to_string(),
                    FailoverPreview::Stuck {
                        restricted: false,
                        chosen: Some(n),
                    } => format!("-> {n} (fallback)"),
                    FailoverPreview::Stuck {
                        restricted: false,
                        chosen: None,
                    } => "STUCK (cluster down)".to_string(),
                    FailoverPreview::NotAffected => "—".to_string(),
                }
            };
            Row::new(vec![
                r.sid.clone(),
                r.group.clone(),
                cur,
                r.state.clone(),
                preview,
            ])
        })
        .collect();
    let resources_table = Table::new(
        res_rows,
        [
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(10),
            Constraint::Min(20),
        ],
    )
    .header(
        Row::new(vec!["sid", "group", "node", "state", "if-fails ->"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" HA resources ({}) ", state.ha_resources.len())),
    );
    f.render_widget(resources_table, cols[1]);
}

fn draw_replication(f: &mut Frame, area: Rect, state: &AppState) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Default expected period: 15 minutes (Proxmox default schedule).
    // Future enhancement: parse the schedule field per-job.
    let period_secs = 900;

    let summary_health = summarise_replication_health(&state.repl_status, now, period_secs);
    let summary_label = match summary_health {
        ReplicationHealth::Healthy => Span::styled(
            "HEALTHY",
            Style::default()
                .fg(Theme::SUCCESS)
                .add_modifier(Modifier::BOLD),
        ),
        ReplicationHealth::Stale => Span::styled(
            "STALE",
            Style::default()
                .fg(Theme::WARNING)
                .add_modifier(Modifier::BOLD),
        ),
        ReplicationHealth::Failing => Span::styled(
            "FAILING",
            Style::default()
                .fg(Theme::DANGER)
                .add_modifier(Modifier::BOLD),
        ),
    };

    let rows: Vec<Row> = state
        .repl_status
        .iter()
        .map(|s| row_for_status(s, now, period_secs))
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(14),
            Constraint::Length(10),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(vec!["job", "src", "dst", "RPO", "fails", "last-error"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(Line::from(vec![
                Span::raw(" replication jobs ("),
                Span::raw(format!("{} ", state.repl_status.len())),
                summary_label,
                Span::raw(") "),
            ])),
    );
    f.render_widget(table, area);
}

fn row_for_status(s: &ReplicationStatus, now: u64, period: u64) -> Row<'static> {
    let rpo = s.rpo_secs(now);
    let rpo_str = if rpo == u64::MAX {
        "never".to_string()
    } else {
        format_duration(rpo)
    };
    let health = s.health(now, period);
    let style = match health {
        ReplicationHealth::Healthy => Style::default().fg(Theme::SUCCESS),
        ReplicationHealth::Stale => Style::default().fg(Theme::WARNING),
        ReplicationHealth::Failing => Style::default().fg(Theme::DANGER),
    };
    Row::new(vec![
        s.id.clone(),
        s.source.clone(),
        s.target.clone(),
        rpo_str,
        s.fail_count.to_string(),
        truncate(s.error.as_str(), 40),
    ])
    .style(style)
}

fn format_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else if secs < 86400 {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d{}h", secs / 86400, (secs % 86400) / 3600)
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let cutoff: String = s.chars().take(n).collect();
        format!("{cutoff}…")
    }
}
