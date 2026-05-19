// Real-time cluster event stream.
//
// Polls `/cluster/tasks` (or `/nodes/{node}/tasks` when --node is set) at a
// configurable interval and emits events for:
//   - RUNNING  — tasks already in progress when the stream starts (shown once
//                at startup unless --no-existing is passed)
//   - START    — a new task appeared since the last poll
//   - DONE     — a previously running task completed with exitstatus "OK"
//   - FAIL     — a previously running task completed with a non-OK status
//   - FINISH   — same as DONE/FAIL when the task appeared already completed
//                (started + finished between two polls)
//
// PVE has no native server-sent-events or WebSocket task feed, so this is
// a pull-poll stream.  2 s default interval gives sub-4 s visibility on
// fast task completions without hammering the API.

use anyhow::Result;
use clap::Subcommand;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::api::types::TaskInfo;
use crate::api::{ProxmoxGateway, PxClient};

#[derive(Debug, Subcommand)]
pub enum EventsCommand {
    /// Stream cluster task events in real-time.
    ///
    /// Shows a live feed of task starts and completions across all nodes
    /// (or one node with --node). Press Ctrl-C or send SIGTERM to stop.
    ///
    /// Examples:
    ///   proxxx events stream
    ///   proxxx events stream --node pve1 --type qmmigrate
    ///   proxxx events stream --format json | jq 'select(.event=="FAIL")'
    Stream {
        /// Poll interval in seconds (default 2, minimum 1)
        #[arg(long, default_value_t = 2)]
        interval: u64,
        /// Watch only this node (default: all nodes)
        #[arg(long)]
        node: Option<String>,
        /// Filter by task type substring (e.g. qmstart, qmstop, qmmigrate,
        /// vzdump, qmclone). Case-insensitive.
        #[arg(long, value_name = "TYPE")]
        r#type: Option<String>,
        /// Filter by guest VMID
        #[arg(long)]
        vmid: Option<u32>,
        /// Do not print currently-running tasks at startup
        #[arg(long)]
        no_existing: bool,
        /// Output format: text (default) or json (NDJSON, one object per line)
        #[arg(long, default_value = "text")]
        format: String,
    },
}

pub async fn execute_events(client: &Arc<PxClient>, action: EventsCommand) -> Result<(Value, i32)> {
    match action {
        EventsCommand::Stream {
            interval,
            node,
            r#type,
            vmid,
            no_existing,
            format,
        } => {
            let interval = interval.max(1);
            let is_json = format.trim().eq_ignore_ascii_case("json");

            // Initial poll — build the "seen" baseline without emitting
            // events for tasks that were already completed.
            let initial = fetch_tasks(client, node.as_deref(), vmid, r#type.as_deref()).await?;
            let mut seen: HashMap<String, TaskInfo> = HashMap::new();

            if !is_json {
                eprintln!(
                    "Streaming cluster events (Ctrl-C to stop, interval {}s)...",
                    interval
                );
            }

            // Show currently-running tasks as the initial snapshot.
            if !no_existing {
                let running: Vec<&TaskInfo> =
                    initial.iter().filter(|t| t.endtime.is_none()).collect();
                if !running.is_empty() {
                    if !is_json {
                        let sep = "─".repeat(72);
                        eprintln!("{sep}");
                    }
                    for task in &running {
                        emit_event("RUNNING", task, None, is_json);
                    }
                    if !is_json {
                        let sep = "─".repeat(72);
                        eprintln!("{sep}");
                    }
                }
            }

            for task in initial {
                seen.insert(task.upid.clone(), task);
            }

            // Stream loop — emit deltas on each poll.
            loop {
                tokio::select! {
                    biased;
                    () = crate::util::shutdown::wait_for_shutdown_signal() => {
                        if !is_json {
                            eprintln!("\nstream stopped");
                        }
                        break;
                    }
                    () = tokio::time::sleep(std::time::Duration::from_secs(interval)) => {}
                }

                let current =
                    match fetch_tasks(client, node.as_deref(), vmid, r#type.as_deref()).await {
                        Ok(t) => t,
                        Err(e) => {
                            tracing::warn!("events stream: poll failed: {e:#}");
                            continue;
                        }
                    };

                for task in &current {
                    match seen.get(&task.upid) {
                        None => {
                            // Task wasn't in the last snapshot.
                            let elapsed = elapsed_secs(task);
                            if task.endtime.is_none() {
                                emit_event("START", task, None, is_json);
                            } else {
                                // Fast task: started and finished between polls.
                                let label = outcome_label(task);
                                emit_event(label, task, elapsed, is_json);
                            }
                        }
                        Some(old) => {
                            // Known task: emit if it just completed.
                            if old.endtime.is_none() && task.endtime.is_some() {
                                let elapsed =
                                    task.endtime.map(|e| e.saturating_sub(task.starttime));
                                let label = outcome_label(task);
                                emit_event(label, task, elapsed, is_json);
                            }
                        }
                    }
                    seen.insert(task.upid.clone(), task.clone());
                }
            }

            Ok((serde_json::json!({"status": "stream stopped"}), 0))
        }
    }
}

/// Fetch tasks, applying node/vmid/type filters.
async fn fetch_tasks(
    client: &PxClient,
    node: Option<&str>,
    vmid_filter: Option<u32>,
    type_filter: Option<&str>,
) -> Result<Vec<TaskInfo>> {
    let mut tasks = if let Some(n) = node {
        client.list_node_tasks(n, Some(200)).await?
    } else {
        client.get_cluster_tasks().await?
    };

    if let Some(v) = vmid_filter {
        let id_str = v.to_string();
        tasks.retain(|t| t.id == id_str);
    }
    if let Some(tp) = type_filter {
        let tp_lower = tp.to_ascii_lowercase();
        tasks.retain(|t| t.task_type.to_ascii_lowercase().contains(&tp_lower));
    }
    Ok(tasks)
}

/// Elapsed seconds for a completed task.
fn elapsed_secs(task: &TaskInfo) -> Option<u64> {
    task.endtime
        .map(|e| e.saturating_sub(task.starttime))
        .filter(|_| task.starttime > 0)
}

/// "DONE" for OK, "FAIL" for anything else.
fn outcome_label(task: &TaskInfo) -> &'static str {
    match task.status.as_deref() {
        None | Some("OK") => "DONE",
        _ => "FAIL",
    }
}

fn emit_event(kind: &str, task: &TaskInfo, elapsed: Option<u64>, json: bool) {
    if json {
        let obj = serde_json::json!({
            "event":    kind,
            "upid":     task.upid,
            "node":     task.node,
            "type":     task.task_type,
            "id":       task.id,
            "user":     task.user,
            "status":   task.status,
            "starttime":task.starttime,
            "endtime":  task.endtime,
            "elapsed_secs": elapsed,
        });
        println!("{obj}");
    } else {
        let ts = fmt_ts(task.starttime);
        let elapsed_str = elapsed.map(|s| format!("  [{s}s]")).unwrap_or_default();
        let status_str = match task.status.as_deref() {
            None | Some("OK") => String::new(),
            Some(s) => format!("  {s}"),
        };
        let id_part = if task.id.is_empty() {
            String::new()
        } else {
            format!("  vmid={}", task.id)
        };
        println!(
            "{ts}  {kind:<8}  {node:<14}  {ty:<22}{id}{status}{elapsed}",
            node = task.node,
            ty = task.task_type,
            id = id_part,
            status = status_str,
            elapsed = elapsed_str,
        );
    }
}

fn fmt_ts(unix: u64) -> String {
    // Format as ISO-8601 without pulling in chrono — good enough for a log line.
    // Days since epoch via Euclidean division, then hour/min/sec.
    if unix == 0 {
        return "                   ".to_string(); // placeholder width
    }
    let secs = unix % 60;
    let mins = (unix / 60) % 60;
    let hours = (unix / 3600) % 24;
    let days = unix / 86400; // days since 1970-01-01

    // Compute calendar date from days-since-epoch (no leap-second handling).
    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{mins:02}:{secs:02}Z")
}

const fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Algorithm from Henry Warren "Hacker's Delight" §12-3, adjusted for u64.
    days += 719468; // shift epoch to 0000-03-01
    let era = days / 146097;
    let doe = days % 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
