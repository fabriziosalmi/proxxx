//! `proxxx logs tail` — cross-node journalctl streaming.
//!
//! Fans `journalctl --follow --output short-iso …` over every selected
//! cluster node in parallel via the existing SSH pool. Lines stream
//! back through one shared mpsc channel — interleaved by arrival
//! order, tagged with the node they came from. Client-side filters
//! (`--grep`, `--service`, `--since`) apply *after* the stream merges
//! so the regex doesn't have to be journalctl-compatible.
//!
//! Output shapes:
//!   --format table (default) → `<ts>  <node>  <message>`
//!   --format json            → NDJSON, one object per line with
//!                              `{timestamp, node, text}`
//!
//! Graceful per-node failures: an SSH error on node X surfaces as a
//! stderr-tagged log line; the rest of the cluster keeps streaming.
//! Ctrl-C / SIGTERM stops every per-node task cleanly via the shared
//! cancellation token.

use anyhow::{Context, Result};
use clap::Subcommand;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

use crate::api::ProxmoxGateway;
use crate::ssh::exec::{ExecOptions, StreamLine};
use crate::ssh::SshPool;
use crate::util::sanitize::sanitize_display;

#[derive(Debug, Subcommand)]
pub enum LogsCommand {
    /// Tail systemd journals from one or more cluster nodes.
    ///
    /// Spawns `journalctl --follow --output short-iso …` over SSH
    /// to each selected node and merges the streams locally. Each
    /// line is tagged with the node it came from so cross-node
    /// correlation works out of the box.
    ///
    /// Examples:
    ///   proxxx logs tail                                    # every node, every unit
    ///   proxxx logs tail --service pveproxy                 # one unit, all nodes
    ///   proxxx logs tail --node pve-test-1 --node pve-test-2
    ///   proxxx logs tail --since "1 hour ago" --grep "OOM"  # cross-cluster OOM scan
    ///   proxxx logs tail --since "1 hour ago" --no-follow   # finite window, then exit
    Tail {
        /// Node(s) to tail. May be repeated. Empty = every cluster node.
        #[arg(long)]
        node: Vec<String>,

        /// Filter lines containing this substring. Applied client-side
        /// after the per-node streams merge, so any string works —
        /// no journalctl regex escaping needed.
        #[arg(long)]
        grep: Option<String>,

        /// `systemd` unit name. Passed verbatim to `journalctl --unit`.
        /// Common: `pveproxy`, `pvedaemon`, `corosync`, `pve-ha-lrm`.
        #[arg(long)]
        service: Option<String>,

        /// Time window. Anything `journalctl --since` accepts:
        /// `"1 hour ago"`, `"2026-05-20 01:00:00"`, `"yesterday"`.
        /// Without this, follow starts from "now" — no history.
        #[arg(long)]
        since: Option<String>,

        /// Don't follow; emit lines up to "now" then exit. Useful for
        /// a finite window scan: `--since "1 hour ago" --no-follow`.
        #[arg(long)]
        no_follow: bool,
    },
}

/// One parsed journal line, ready for filter + render.
#[derive(Debug, Clone, Serialize)]
pub struct LogLine {
    /// RFC 3339 timestamp from `journalctl --output short-iso` (the
    /// first space-separated token of each line). Empty for lines we
    /// can't parse a timestamp out of (banner lines, stderr from the
    /// remote process, etc.) — operators still see the text.
    pub timestamp: String,
    /// Cluster node the line originated from. Always set — comes
    /// from which SSH session emitted the line, not from the line.
    pub node: String,
    /// The post-timestamp portion of the line (hostname + unit +
    /// message). For lines without a timestamp this is the full
    /// line as received.
    pub text: String,
}

/// Why a node's stream counts as failed, or `None` when journalctl ran
/// and exited 0 (#364). An SSH error, a non-zero exit (e.g. `--since
/// banana`) or a missing exit status is a failure.
fn node_failure(outcome: &Result<Option<u32>>) -> Option<String> {
    match outcome {
        Ok(Some(0)) => None,
        Ok(Some(code)) => Some(format!("journalctl exited with status {code}")),
        Ok(None) => Some("the remote command ended without an exit status".into()),
        Err(e) => Some(format!("ssh: {e:#}")),
    }
}

/// Exit 1 when any node failed (#364), as `ls --all-profiles` does for a
/// failed profile; the lines of the nodes that answered are still printed.
fn exit_code(failed_nodes: &[String]) -> i32 {
    if failed_nodes.is_empty() {
        return 0;
    }
    eprintln!(
        "logs tail: {} node(s) failed: {}",
        failed_nodes.len(),
        failed_nodes
            .iter()
            .map(|n| sanitize_display(n).into_owned())
            .collect::<Vec<_>>()
            .join(", ")
    );
    1
}

/// Print a non-journal message on stderr; return the node when it failed.
fn report_on_stderr(msg: NodeMsg) -> Option<String> {
    match msg {
        NodeMsg::Line(_) => None,
        NodeMsg::Stderr { node, text } => {
            eprintln!(
                "[{}] [stderr] {}",
                sanitize_display(&node),
                sanitize_display(&text)
            );
            None
        }
        NodeMsg::Failed { node, error } => {
            eprintln!(
                "logs tail: node {} failed: {}",
                sanitize_display(&node),
                sanitize_display(&error)
            );
            Some(node)
        }
    }
}

/// What a per-node task sends to the consumer.
enum NodeMsg {
    /// One journal line, for stdout.
    Line(LogLine),
    /// A line the remote command wrote on stderr.
    Stderr { node: String, text: String },
    /// The node's stream failed: SSH error or a non-zero journalctl exit.
    Failed { node: String, error: String },
}

/// Render mode picked by the caller from the global `--format` flag.
#[derive(Debug, Clone, Copy)]
pub enum LogsRenderMode {
    Text,
    Json,
}

pub async fn execute_logs(
    config: &crate::config::ProfileConfig,
    client: &Arc<crate::api::PxClient>,
    action: LogsCommand,
    render: LogsRenderMode,
) -> Result<(Value, i32)> {
    match action {
        LogsCommand::Tail {
            node,
            grep,
            service,
            since,
            no_follow,
        } => {
            let ssh_cfg = config.ssh.clone().context(
                "`proxxx logs tail` requires `[profiles.X.ssh]` configured (key_path, etc.)",
            )?;
            let api: Arc<dyn crate::api::ProxmoxGateway> =
                Arc::clone(client) as Arc<dyn crate::api::ProxmoxGateway>;
            let pool = Arc::new(SshPool::new(ssh_cfg, None)?.with_api(&config.url, api));

            // Resolve target nodes. Empty `--node` = fanout to every
            // cluster member. We still tag each line with the node
            // name so the operator sees where it came from.
            let nodes: Vec<String> = if node.is_empty() {
                let n = client.get_nodes().await?;
                n.into_iter().map(|x| x.node).collect()
            } else {
                node
            };
            if nodes.is_empty() {
                anyhow::bail!("no cluster nodes found — is the API reachable?");
            }

            let cmd = build_journalctl_command(service.as_deref(), since.as_deref(), !no_follow);

            // Fan out: one tokio task per node, all feeding a single
            // mpsc. Bounded channel sized to 4 × node count so a slow
            // consumer applies backpressure but bursts don't stall.
            let (tx, mut rx) = tokio::sync::mpsc::channel::<NodeMsg>(nodes.len().max(8) * 4);
            let mut handles = Vec::with_capacity(nodes.len());

            for n in nodes {
                let pool = Arc::clone(&pool);
                let cmd = cmd.clone();
                let tx = tx.clone();
                let node_name = n.clone();
                let tx_end = tx.clone();
                let handle = tokio::spawn(async move {
                    let on_line = move |line: StreamLine| {
                        let msg = match line {
                            StreamLine::Stdout(s) => {
                                NodeMsg::Line(parse_journalctl_line(&s, &node_name))
                            }
                            // Remote stderr is not journal content (#364).
                            StreamLine::Stderr(s) => NodeMsg::Stderr {
                                node: node_name.clone(),
                                text: s,
                            },
                        };
                        // try_send: drop the line if the consumer is
                        // catatonic. Better than blocking the SSH
                        // event loop indefinitely.
                        let _ = tx.try_send(msg);
                    };
                    let opts = ExecOptions {
                        // No timeout — follow streams are long-lived.
                        timeout: None,
                        // Cap individual line capture; the merge channel
                        // bounds overall memory.
                        max_capture_bytes: 16 * 1024 * 1024,
                    };
                    // #364: an SSH failure or a non-zero journalctl exit is
                    // a node failure, reported apart from the log lines.
                    let outcome = pool.exec_stream(&n, &cmd, opts, on_line).await;
                    if let Some(error) = node_failure(&outcome) {
                        let _ = tx_end.send(NodeMsg::Failed { node: n, error }).await;
                    }
                });
                handles.push(handle);
            }
            // Important: drop our own sender so the channel closes
            // when every per-node task ends. Otherwise `rx.recv()`
            // hangs forever after --no-follow's commands all exit.
            drop(tx);

            // Consumer loop — filter + render. Log lines go to stdout;
            // remote stderr and node failures go to stderr, so a JSON
            // stream holds only journal records.
            let grep_filter = grep.as_deref();
            let mut failed_nodes: Vec<String> = Vec::new();
            let mut stopped = false;
            loop {
                tokio::select! {
                    biased;
                    () = crate::util::shutdown::wait_for_shutdown_signal() => {
                        eprintln!("\nlogs tail stopped");
                        stopped = true;
                        break;
                    }
                    maybe_msg = rx.recv() => {
                        match maybe_msg {
                            Some(NodeMsg::Line(line)) => emit(&line, grep_filter, render),
                            Some(other) => failed_nodes.extend(report_on_stderr(other)),
                            None => break, // every per-node task exited
                        }
                    }
                }
            }

            if stopped {
                // A follow stream never ends on its own; stop the tasks
                // instead of waiting for them.
                for h in &handles {
                    h.abort();
                }
            }
            for h in handles {
                let _ = h.await;
            }

            Ok((Value::Null, exit_code(&failed_nodes)))
        }
    }
}

/// Build the remote `journalctl` command line from the parsed CLI
/// flags. `follow=true` adds `--follow`; otherwise the command runs
/// to completion over the requested window. `--output short-iso` is
/// always set so timestamps are parseable. Single-quoted args are
/// shell-safe because we control every input (no user-supplied raw
/// command fragments).
fn build_journalctl_command(service: Option<&str>, since: Option<&str>, follow: bool) -> String {
    let mut parts: Vec<String> = vec![
        "journalctl".to_string(),
        "--no-pager".to_string(),
        "--output".to_string(),
        "short-iso".to_string(),
    ];
    if follow {
        parts.push("--follow".to_string());
    }
    if let Some(unit) = service {
        parts.push("--unit".to_string());
        parts.push(shell_single_quote(unit));
    }
    if let Some(window) = since {
        parts.push("--since".to_string());
        parts.push(shell_single_quote(window));
    }
    parts.join(" ")
}

/// Single-quote a value for `sh -c`. Wraps in `'…'` and escapes
/// embedded single quotes via the standard `'\''` trick. Used for
/// the `--unit` and `--since` values because they may contain spaces
/// or other shell metacharacters from user input.
fn shell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Parse one `journalctl --output short-iso` line. The first
/// whitespace-separated token is the RFC 3339 timestamp; the rest
/// is `<hostname> <unit>[<pid>]: <message>`. Banner lines like
/// `-- Logs begin at … --` have no leading timestamp; we still
/// pass them through with an empty timestamp so the operator can
/// see them.
pub fn parse_journalctl_line(line: &str, node: &str) -> LogLine {
    let trimmed = line.trim_end_matches('\r');
    let Some((first, rest)) = trimmed.split_once(' ') else {
        return LogLine {
            timestamp: String::new(),
            node: node.to_string(),
            text: trimmed.to_string(),
        };
    };
    // Sanity-check: a short-iso timestamp starts with a digit and
    // contains a `T` (e.g. `2026-05-20T01:23:45+0200`). Otherwise
    // it's banner / informational and we keep the whole line.
    if first.starts_with(|c: char| c.is_ascii_digit()) && first.contains('T') {
        LogLine {
            timestamp: first.to_string(),
            node: node.to_string(),
            text: rest.to_string(),
        }
    } else {
        LogLine {
            timestamp: String::new(),
            node: node.to_string(),
            text: trimmed.to_string(),
        }
    }
}

/// Apply the optional substring filter and write one rendered line
/// to stdout. Filter check happens before formatting to skip the
/// allocation for lines that won't be printed.
fn emit(line: &LogLine, grep: Option<&str>, render: LogsRenderMode) {
    if let Some(needle) = grep {
        if !line.text.contains(needle) {
            return;
        }
    }
    match render {
        LogsRenderMode::Json => match serde_json::to_string(line) {
            // raw-output: JSON for machines; removing characters would change the data
            Ok(s) => println!("{s}"),
            Err(e) => tracing::warn!("logs tail: serialise failure: {e}"),
        },
        LogsRenderMode::Text => {
            // Time first because it sorts; node next so columns
            // align visually across lines from the same host.
            if line.timestamp.is_empty() {
                crate::outln!("(no-ts)               [{}] {}", line.node, line.text);
            } else {
                crate::outln!("{}  [{}] {}", line.timestamp, line.node, line.text);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// #364: only a journalctl that ran and exited 0 is a success. An
    /// unknown or offline node (SSH error) and a bad `--since` (non-zero
    /// exit) used to end with exit 0.
    #[test]
    fn node_failure_classifies_the_outcome() {
        assert_eq!(node_failure(&Ok(Some(0))), None);
        assert!(node_failure(&Ok(Some(1))).unwrap().contains("status 1"));
        assert!(node_failure(&Ok(None)).is_some());
        let err = node_failure(&Err(anyhow::anyhow!("failed to lookup address"))).unwrap();
        assert!(err.contains("ssh") && err.contains("lookup"), "{err}");
    }

    #[test]
    fn parses_short_iso_journal_line() {
        let line = parse_journalctl_line(
            "2026-05-20T01:23:45+0200 pve-test-1 pveproxy[1234]: starting 4 worker(s)",
            "pve-test-1",
        );
        assert_eq!(line.timestamp, "2026-05-20T01:23:45+0200");
        assert_eq!(line.node, "pve-test-1");
        assert!(line.text.contains("pveproxy[1234]"));
        assert!(line.text.contains("starting 4 worker"));
    }

    #[test]
    fn keeps_banner_lines_with_empty_timestamp() {
        let line = parse_journalctl_line(
            "-- Logs begin at Thu 2026-05-20 01:00:00 CEST, end at Thu 2026-05-20 02:00:00 CEST. --",
            "pve-test-1",
        );
        assert_eq!(line.timestamp, "");
        assert!(line.text.starts_with("-- Logs begin"));
    }

    #[test]
    fn parses_empty_remainder_line() {
        let line = parse_journalctl_line("2026-05-20T01:23:45+0200", "pve-test-1");
        // No space → whole token is the line, no timestamp split.
        assert_eq!(line.timestamp, "");
        assert!(line.text.starts_with("2026-"));
    }

    #[test]
    fn strips_trailing_cr_for_windows_journals() {
        let line = parse_journalctl_line(
            "2026-05-20T01:23:45+0200 pve-test-1 sshd: accepted publickey\r",
            "pve-test-1",
        );
        assert!(!line.text.ends_with('\r'));
    }

    #[test]
    fn build_journalctl_command_minimal() {
        let cmd = build_journalctl_command(None, None, true);
        assert!(cmd.contains("--follow"));
        assert!(cmd.contains("--output short-iso"));
        assert!(!cmd.contains("--unit"));
        assert!(!cmd.contains("--since"));
    }

    #[test]
    fn build_journalctl_command_with_unit_and_since() {
        let cmd = build_journalctl_command(Some("pveproxy"), Some("1 hour ago"), true);
        assert!(cmd.contains("--unit 'pveproxy'"));
        assert!(cmd.contains("--since '1 hour ago'"));
    }

    #[test]
    fn build_journalctl_command_no_follow_finite_window() {
        let cmd = build_journalctl_command(None, Some("yesterday"), false);
        assert!(!cmd.contains("--follow"));
        assert!(cmd.contains("--since 'yesterday'"));
    }

    #[test]
    fn shell_single_quote_escapes_embedded_quote() {
        assert_eq!(shell_single_quote("plain"), "'plain'");
        assert_eq!(shell_single_quote("with 'apos"), r"'with '\''apos'");
        assert_eq!(shell_single_quote(""), "''");
    }
}
