use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table},
    Frame,
};

use crate::app::AppState;
use crate::tui::theme::Theme;

pub fn draw(f: &mut Frame, area: Rect, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(area);

    let title = Paragraph::new(Line::from(vec![
        Span::styled(" 🛡️ ", Style::default().fg(Theme::INFO)),
        Span::styled("Backup Health Board", Theme::title()),
        Span::styled(" (Cluster-wide VZDump Audit)", Theme::dim()),
    ]))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Theme::border()),
    );
    f.render_widget(title, chunks[0]);

    if state.guests.is_empty() {
        f.render_widget(
            Paragraph::new(" No guests to monitor.").style(Theme::dim()),
            chunks[1],
        );
        return;
    }

    let header = Row::new(vec![
        "VMID",
        "NAME",
        "NODE",
        "LAST OK",
        "DURATION",
        "FAILURES (30D)",
        "HEALTH",
    ])
    .style(Theme::header())
    .height(1);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut rows = Vec::new();

    for guest in &state.guests {
        let vmid_str = guest.vmid.to_string();
        let mut guest_tasks: Vec<_> = state
            .cluster_tasks
            .iter()
            .filter(|t| t.task_type == "vzdump" && t.id == vmid_str)
            .collect();

        guest_tasks.sort_by_key(|t| t.starttime);
        guest_tasks.reverse();

        let mut last_ok_time = 0;
        let mut last_ok_duration = 0;
        let mut failures = 0;

        let thirty_days_ago = now.saturating_sub(30 * 24 * 3600);

        for task in &guest_tasks {
            if task.starttime < thirty_days_ago {
                continue;
            }

            let is_ok = task.status.as_deref().unwrap_or("").starts_with("OK");

            if is_ok && last_ok_time == 0 {
                last_ok_time = task.starttime;
                if let Some(end) = task.endtime {
                    last_ok_duration = end.saturating_sub(task.starttime);
                }
            }

            if !is_ok && task.endtime.is_some() {
                failures += 1;
            }
        }

        let days_since_ok = if last_ok_time > 0 {
            (now.saturating_sub(last_ok_time)) / 86400
        } else {
            999
        };

        let (health_str, health_style) = if last_ok_time == 0 {
            (
                "UNPROTECTED".to_string(),
                Style::default()
                    .fg(Theme::DANGER)
                    .add_modifier(Modifier::BOLD),
            )
        } else if days_since_ok > 7 {
            (
                format!("STALE ({}d)", days_since_ok),
                Style::default().fg(Theme::WARNING),
            )
        } else if failures > 0 {
            ("DEGRADED".to_string(), Style::default().fg(Theme::WARNING))
        } else {
            ("HEALTHY".to_string(), Style::default().fg(Theme::SUCCESS))
        };

        let last_ok_str = if last_ok_time > 0 {
            let elapsed = now.saturating_sub(last_ok_time);
            if elapsed < 3600 {
                format!("{}m ago", elapsed / 60)
            } else if elapsed < 86400 {
                format!("{}h {}m ago", elapsed / 3600, (elapsed % 3600) / 60)
            } else {
                format!("{}d {}h ago", elapsed / 86400, (elapsed % 86400) / 3600)
            }
        } else {
            "-".to_string()
        };

        let duration_str = if last_ok_duration > 0 {
            let m = last_ok_duration / 60;
            let s = last_ok_duration % 60;
            format!("{}m {}s", m, s)
        } else {
            "-".to_string()
        };

        rows.push(
            Row::new(vec![
                guest.vmid.to_string(),
                guest.name.clone(),
                guest.node.clone(),
                last_ok_str,
                duration_str,
                if failures > 0 {
                    failures.to_string()
                } else {
                    "-".to_string()
                },
                health_str,
            ])
            .style(health_style),
        );
    }

    let widths = [
        Constraint::Length(6),  // vmid
        Constraint::Length(20), // name
        Constraint::Length(12), // node
        Constraint::Length(18), // last ok
        Constraint::Length(10), // duration
        Constraint::Length(14), // failures
        Constraint::Length(15), // health
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Theme::border()),
    );

    f.render_widget(table, chunks[1]);
}
