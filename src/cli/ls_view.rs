//! `ls nodes|guests|storage` for a person at a terminal.
//!
//! `--format table` is a TSV built from every field of the API objects:
//! eighteen columns for a guest, in alphabetical order, with sizes in
//! bytes and the vmid last. That is the right shape for a script and the
//! wrong one for a reader. When stdout is a terminal and the format is
//! `table`, these renderers print a chosen set of columns instead,
//! aligned, with readable sizes and the `util::color` colours. A pipe, a
//! file and every other format still get the TSV or JSON, unchanged.

use std::io::IsTerminal as _;

use crate::api::types::{Guest, GuestStatus, GuestType, Node, NodeStatus, StoragePool};
use crate::tui::theme::UsageMetric;
use crate::util::color::{self, Line, Paint};
use crate::util::format::{human_bytes, human_uptime, OutputFormat};

/// Whether `ls` prints the reader's table: `--format table` (the default)
/// to a terminal.
#[must_use]
pub fn wanted(format: OutputFormat) -> bool {
    matches!(format, OutputFormat::Table) && std::io::stdout().is_terminal()
}

#[derive(Clone, Copy)]
enum Align {
    Left,
    Right,
}

/// One cell: its text (sanitized when printed) and its colour.
struct Cell {
    text: String,
    paint: Option<Paint>,
}

fn cell(text: impl Into<String>) -> Cell {
    Cell {
        text: text.into(),
        paint: None,
    }
}

fn painted(text: impl Into<String>, paint: Option<Paint>) -> Cell {
    Cell {
        text: text.into(),
        paint,
    }
}

/// Lay the rows out in aligned columns, two spaces apart. Widths are
/// measured on the sanitized text, so a control character removed on
/// output does not shift a column.
fn render(columns: &[(&str, Align)], rows: &[Vec<Cell>], color: bool) -> Vec<String> {
    let safe = |s: &str| crate::util::format::safe_text(s);
    let mut widths: Vec<usize> = columns.iter().map(|(h, _)| h.chars().count()).collect();
    for row in rows {
        for (w, c) in widths.iter_mut().zip(row) {
            *w = (*w).max(safe(&c.text).chars().count());
        }
    }
    let pad = |text: &str, width: usize, align: Align| match align {
        Align::Left => format!("{text:<width$}"),
        Align::Right => format!("{text:>width$}"),
    };
    let mut out = Vec::with_capacity(rows.len() + 1);
    let mut header = Line::new();
    for (i, ((h, align), w)) in columns.iter().zip(&widths).enumerate() {
        let sep = if i == 0 { "" } else { "  " };
        header = header.paint(format!("{sep}{}", pad(h, *w, *align)), Some(Paint::Dim));
    }
    out.push(header.render(color).trim_end().to_string());
    for row in rows {
        let mut line = Line::new();
        for (i, ((c, (_, align)), w)) in row.iter().zip(columns).zip(&widths).enumerate() {
            if i > 0 {
                line = line.plain("  ");
            }
            line = line.paint(pad(&safe(&c.text), *w, *align), c.paint);
        }
        out.push(line.render(color).trim_end().to_string());
    }
    out
}

fn print(lines: &[String]) {
    // Every cell was sanitized in `render` (#437); the only control
    // sequences left are the SGR codes `util::color` added.
    for l in lines {
        // raw-output: cells sanitized in `render`, only SGR codes remain.
        println!("{l}");
    }
}

#[allow(clippy::cast_precision_loss)]
fn pct(used: u64, total: u64) -> Option<f64> {
    (total > 0).then(|| used as f64 / total as f64 * 100.0)
}

fn usage_cell(text: String, metric: UsageMetric, percent: Option<f64>) -> Cell {
    match percent {
        Some(p) => {
            let (paint, mark) = color::usage(metric, p);
            painted(format!("{text}{mark}"), paint)
        }
        None => cell(text),
    }
}

/// Rows for `ls guests`, by vmid. A guest that is not running shows `-`
/// for CPU, memory and uptime: PVE reports its configured maximum, not a
/// use.
fn guest_rows(guests: &[Guest]) -> Vec<Vec<Cell>> {
    let mut sorted: Vec<&Guest> = guests.iter().collect();
    sorted.sort_by_key(|g| g.vmid);
    sorted
        .into_iter()
        .map(|g| {
            let status = format!("{:?}", g.status).to_lowercase();
            let running = g.status == GuestStatus::Running;
            let kind = match g.guest_type {
                GuestType::Qemu => "vm",
                GuestType::Lxc => "lxc",
            };
            let (cpu, mem, up) = if running {
                let cpu_pct = (g.cpu * 100.0).clamp(0.0, 100.0);
                (
                    usage_cell(format!("{cpu_pct:.0}%"), UsageMetric::Cpu, Some(cpu_pct)),
                    usage_cell(
                        format!("{}/{}", human_bytes(g.mem), human_bytes(g.maxmem)),
                        UsageMetric::Memory,
                        pct(g.mem, g.maxmem),
                    ),
                    cell(human_uptime(g.uptime)),
                )
            } else {
                (
                    cell("-"),
                    cell(format!("-/{}", human_bytes(g.maxmem))),
                    cell("-"),
                )
            };
            vec![
                cell(g.vmid.to_string()),
                cell(g.name.clone()),
                cell(kind),
                painted(status.clone(), Some(color::guest_status(&status))),
                cell(g.node.clone()),
                cpu,
                mem,
                up,
                cell(g.tags.replace(';', ",")),
            ]
        })
        .collect()
}

const GUEST_COLUMNS: &[(&str, Align)] = &[
    ("VMID", Align::Right),
    ("NAME", Align::Left),
    ("TYPE", Align::Left),
    ("STATUS", Align::Left),
    ("NODE", Align::Left),
    ("CPU", Align::Right),
    ("MEM", Align::Right),
    ("UPTIME", Align::Right),
    ("TAGS", Align::Left),
];

/// Rows for `ls nodes`, by name. A node that is not online has no
/// metrics (#535).
fn node_rows(nodes: &[Node]) -> Vec<Vec<Cell>> {
    let mut sorted: Vec<&Node> = nodes.iter().collect();
    sorted.sort_by(|a, b| a.node.cmp(&b.node));
    sorted
        .into_iter()
        .map(|n| {
            let status = format!("{:?}", n.status).to_lowercase();
            let online = n.status == NodeStatus::Online;
            let (cpu, mem, up) = if online {
                let cpu_pct = (n.cpu * 100.0).clamp(0.0, 100.0);
                (
                    usage_cell(format!("{cpu_pct:.0}%"), UsageMetric::Cpu, Some(cpu_pct)),
                    usage_cell(
                        format!("{}/{}", human_bytes(n.mem), human_bytes(n.maxmem)),
                        UsageMetric::Memory,
                        pct(n.mem, n.maxmem),
                    ),
                    cell(human_uptime(n.uptime)),
                )
            } else {
                (cell("-"), cell("-"), cell("-"))
            };
            vec![
                cell(n.node.clone()),
                painted(status.clone(), Some(color::node_status(&status))),
                cell(if online {
                    n.maxcpu.to_string()
                } else {
                    "-".into()
                }),
                cpu,
                mem,
                up,
            ]
        })
        .collect()
}

const NODE_COLUMNS: &[(&str, Align)] = &[
    ("NODE", Align::Left),
    ("STATUS", Align::Left),
    ("CORES", Align::Right),
    ("CPU", Align::Right),
    ("MEM", Align::Right),
    ("UPTIME", Align::Right),
];

/// Rows for `ls storage`, by node then name.
fn storage_rows(pools: &[StoragePool]) -> Vec<Vec<Cell>> {
    let mut sorted: Vec<&StoragePool> = pools.iter().collect();
    sorted.sort_by(|a, b| (&a.node, &a.storage).cmp(&(&b.node, &b.storage)));
    sorted
        .into_iter()
        .map(|p| {
            let used = pct(p.used, p.total);
            vec![
                cell(p.node.clone()),
                cell(p.storage.clone()),
                cell(p.storage_type.clone()),
                usage_cell(
                    used.map_or_else(|| "-".into(), |u| format!("{u:.0}%")),
                    UsageMetric::Disk,
                    used,
                ),
                cell(format!("{}/{}", human_bytes(p.used), human_bytes(p.total))),
                cell(if p.shared { "shared" } else { "local" }),
                painted(
                    if p.active { "yes" } else { "no" },
                    (!p.active).then_some(Paint::Warn),
                ),
            ]
        })
        .collect()
}

const STORAGE_COLUMNS: &[(&str, Align)] = &[
    ("NODE", Align::Left),
    ("STORAGE", Align::Left),
    ("TYPE", Align::Left),
    ("USE", Align::Right),
    ("USED/TOTAL", Align::Right),
    ("SCOPE", Align::Left),
    ("ACTIVE", Align::Left),
];

pub fn print_guests(guests: &[Guest]) {
    print(&render(
        GUEST_COLUMNS,
        &guest_rows(guests),
        color::enabled(),
    ));
}

pub fn print_nodes(nodes: &[Node]) {
    print(&render(NODE_COLUMNS, &node_rows(nodes), color::enabled()));
}

pub fn print_storage(pools: &[StoragePool]) {
    print(&render(
        STORAGE_COLUMNS,
        &storage_rows(pools),
        color::enabled(),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1_073_741_824;

    fn guest(vmid: u32, name: &str, status: GuestStatus) -> Guest {
        Guest {
            vmid,
            name: name.into(),
            status,
            node: "pve1".into(),
            cpu: 0.5,
            mem: GIB,
            maxmem: 4 * GIB,
            uptime: 90_000,
            ..Guest::default()
        }
    }

    #[test]
    fn guests_are_sorted_aligned_and_readable() {
        let rows = guest_rows(&[
            guest(8004, "backup-srv", GuestStatus::Stopped),
            guest(101, "dns", GuestStatus::Running),
        ]);
        let lines = render(GUEST_COLUMNS, &rows, false);
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("VMID  NAME"), "{lines:?}");
        assert!(lines[1].starts_with(" 101  dns"), "{lines:?}");
        assert!(lines[2].starts_with("8004  backup-srv"), "{lines:?}");
        assert!(
            lines[1].contains("50%") && lines[1].contains("1.0G/4.0G"),
            "{lines:?}"
        );
        assert!(lines[1].contains("1d1h"), "{lines:?}");
        // A stopped guest has no CPU, memory use or uptime to show.
        assert!(
            !lines[2].contains('%') && lines[2].contains("-/4.0G"),
            "{lines:?}"
        );
        // Columns line up: STATUS starts at the same offset on every line.
        let at = |l: &str, w: &str| l.find(w).unwrap_or(usize::MAX);
        assert_eq!(at(&lines[0], "STATUS"), at(&lines[1], "running"));
        assert_eq!(at(&lines[0], "STATUS"), at(&lines[2], "stopped"));
    }

    #[test]
    fn an_offline_node_has_no_metrics() {
        let nodes = [
            Node {
                node: "pve2".into(),
                status: NodeStatus::Offline,
                ..Node::default()
            },
            Node {
                node: "pve1".into(),
                status: NodeStatus::Online,
                cpu: 0.97,
                maxcpu: 8,
                mem: 8 * GIB,
                maxmem: 32 * GIB,
                uptime: 3600,
                ..Node::default()
            },
        ];
        let lines = render(NODE_COLUMNS, &node_rows(&nodes), false);
        assert!(
            lines[1].starts_with("pve1") && lines[1].contains("97%!"),
            "{lines:?}"
        );
        assert!(lines[2].starts_with("pve2"), "{lines:?}");
        assert!(
            !lines[2].contains('%') && !lines[2].contains("0.0"),
            "{lines:?}"
        );
    }

    #[test]
    fn colour_wraps_status_and_high_usage_only() {
        let rows = guest_rows(&[guest(101, "dns", GuestStatus::Running)]);
        let lines = render(GUEST_COLUMNS, &rows, true);
        assert!(lines[1].contains("\u{1b}[32mrunning"), "{lines:?}");
        // 50% CPU and 25% memory are below the elevated thresholds.
        assert!(!lines[1].contains("\u{1b}[33m"), "{lines:?}");
    }

    /// #437: a guest name cannot bring its own escape sequence.
    #[test]
    fn a_hostile_name_loses_its_control_sequence() {
        let rows = guest_rows(&[guest(1, "evil\u{1b}]52;c;eA==\u{7}", GuestStatus::Stopped)]);
        for color in [false, true] {
            let joined = render(GUEST_COLUMNS, &rows, color).join("\n");
            assert!(!joined.contains("\u{1b}]"), "{joined:?}");
            assert!(!joined.contains('\u{7}'), "{joined:?}");
        }
    }
}
