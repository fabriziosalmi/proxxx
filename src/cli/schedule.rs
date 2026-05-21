//! `proxxx schedule …` — interval-based scheduler for recurring
//! proxxx operations.
//!
//! Why this exists: wrapping `cron` around proxxx today drops the
//! audit trail. Native scheduling means every recurring op flows
//! through proxxx's existing dispatch path (audit, pre-flight,
//! HITL gate), and the audit log is the canonical record of what
//! ran when.
//!
//! ## Design choice: interval, not cron
//!
//! v1 uses `--every <duration>` instead of a full cron expression.
//! Reasons:
//!
//!   1. The 80% case (daily snapshots, hourly backups, weekly
//!      patches) is interval-shaped — "every 24 h" is what
//!      operators write in their heads.
//!   2. A cron parser is a 300-line minefield (DST jumps, leap
//!      seconds, `*/N` vs `N-M/K` syntax, locale-dependent
//!      day-name parsing). MVP-out.
//!   3. The deferral leaves cron-syntax behind an explicit follow-up
//!      issue rather than a half-baked subset.
//!
//! ## What lands here
//!
//! - `proxxx schedule add --name X --every Y --cmd "..."` — write
//!   a schedule entry to `<data_dir>/schedules.toml`.
//! - `proxxx schedule list` — display all schedules + last/next run.
//! - `proxxx schedule remove --name X` — delete a schedule.
//! - `proxxx schedule run-due` — execute any schedule whose
//!   `next_run` is past. Designed to be invoked by the host's
//!   `cron`/`systemd-timer` once a minute: `* * * * * proxxx schedule run-due`.
//!   This way the host scheduler is just the trigger; the LOGIC,
//!   audit, and dispatch live in proxxx.
//!
//! ## Out of scope (deferred per #63)
//!
//! - **`SQLite` migration v3** + a `schedule_runs` table for full
//!   per-run stdout/stderr capture. v1 stores schedules in TOML
//!   (simpler, append-only) and the actual execution writes to the
//!   existing audit log + tracing.
//! - **Long-running daemon mode** (`schedule serve`) — for v1 the
//!   host's cron is the daemon. Once we add a unified daemon
//!   (alerts + HITL + schedule), folding `run-due` into a tokio
//!   tick is one PR.
//! - **Distributed scheduling / HA failover** — single-instance.
//! - **Complex DAGs** — flat list of schedules; no dependencies.

use anyhow::{Context, Result};
use clap::Subcommand;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// One persisted schedule entry. Written to `schedules.toml` as a
/// `[[schedule]]` array entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScheduleEntry {
    /// Human-readable identifier the operator types (e.g.
    /// `nightly-snapshot`, `weekly-patch`).
    pub name: String,
    /// Interval in seconds between runs. Internal representation;
    /// the CLI accepts `--every 1d`/`1h`/`30m`/`1w` and converts.
    pub interval_secs: u64,
    /// The proxxx CLI command to run (split on shell whitespace).
    /// Example: `vm snapshot 100 --name nightly --yes`.
    pub cmd: String,
    /// Unix epoch seconds of the last completed run. `0` = never.
    pub last_run: u64,
    /// Unix epoch seconds when the next run is due. Set on `add`
    /// and on every successful execution.
    pub next_run: u64,
    /// Whether the schedule is currently enabled. Disabled
    /// schedules survive in the file but are skipped by `run-due`.
    pub enabled: bool,
}

/// Top-level schedule store — the on-disk shape of
/// `schedules.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScheduleStore {
    #[serde(default, rename = "schedule")]
    pub schedules: Vec<ScheduleEntry>,
}

/// Default path: `<data_local_dir>/schedules.toml`. Overridable
/// via `PROXXX_SCHEDULES_PATH` for tests.
#[must_use]
pub fn schedules_path() -> PathBuf {
    if let Ok(p) = std::env::var("PROXXX_SCHEDULES_PATH") {
        return PathBuf::from(p);
    }
    directories::ProjectDirs::from("dev", "proxxx", "proxxx")
        .map_or_else(
            || PathBuf::from("/tmp/proxxx"),
            |d| d.data_local_dir().to_path_buf(),
        )
        .join("schedules.toml")
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Load the store from disk, or return an empty default if the
/// file doesn't exist. Hard error only on read/parse failure.
pub fn load_store() -> Result<ScheduleStore> {
    load_store_at(&schedules_path())
}

/// `load_store` with an explicit path. Tests use this form.
pub fn load_store_at(path: &std::path::Path) -> Result<ScheduleStore> {
    if !path.exists() {
        return Ok(ScheduleStore::default());
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("read schedules at {}", path.display()))?;
    let store: ScheduleStore = toml::from_str(&content)
        .with_context(|| format!("parse schedules at {}", path.display()))?;
    Ok(store)
}

/// Save the store atomically (tempfile + rename).
pub fn save_store(store: &ScheduleStore) -> Result<()> {
    save_store_at(&schedules_path(), store)
}

/// `save_store` with an explicit path. Tests use this form.
pub fn save_store_at(path: &std::path::Path, store: &ScheduleStore) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create dir {}", parent.display()))?;
    }
    let content = toml::to_string_pretty(store)?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, content)
        .with_context(|| format!("write temp schedules at {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("rename {} → {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Parse a duration suffix: `30s`, `5m`, `2h`, `1d`, `1w`.
/// Bare numbers = seconds. Returns the value in seconds.
pub fn parse_interval(s: &str) -> Result<u64> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty interval");
    }
    // Match on the trailing CHAR, not a byte split. `split_at(len-1)`
    // panics when the last char is multi-byte (e.g. `5µ`); the suffix
    // units are all ASCII, so byte-slicing `len-1` is only safe inside
    // the matched branches where the last char is provably 1 byte.
    let last = s.chars().next_back().unwrap_or('\0');
    let (n_str, mult): (&str, u64) = match last {
        's' => (&s[..s.len() - 1], 1),
        'm' => (&s[..s.len() - 1], 60),
        'h' => (&s[..s.len() - 1], 3600),
        'd' => (&s[..s.len() - 1], 86400),
        'w' => (&s[..s.len() - 1], 86400 * 7),
        _ => (s, 1),
    };
    let n: u64 = n_str.parse().map_err(|_| {
        anyhow::anyhow!("invalid interval `{s}` — try `30s`, `5m`, `2h`, `1d`, `1w`")
    })?;
    Ok(n.saturating_mul(mult))
}

#[derive(Debug, Subcommand)]
pub enum ScheduleCommand {
    /// Register a recurring proxxx operation. The schedule fires on
    /// the next `proxxx schedule run-due` invocation that occurs at
    /// or after `now + interval`.
    ///
    /// Example: snapshot guest 100 every night at the next
    /// `run-due` after a 24 h interval has elapsed:
    ///
    ///   proxxx schedule add \
    ///     --name nightly-100 \
    ///     --every 1d \
    ///     --cmd "vm snapshot 100 --name nightly --yes"
    Add {
        /// Unique kebab-case name.
        #[arg(long)]
        name: String,
        /// Interval between runs. Accepts `30s`, `5m`, `2h`, `1d`, `1w`.
        #[arg(long)]
        every: String,
        /// The proxxx CLI command to run, as you'd type it (without
        /// the `proxxx` prefix). Example: `"vm snapshot 100 --yes"`.
        #[arg(long)]
        cmd: String,
    },

    /// List every registered schedule with status (enabled / next
    /// run / last run).
    List {
        #[arg(long, value_enum, default_value_t = ScheduleOutput::Text)]
        output: ScheduleOutput,
    },

    /// Remove a schedule by name. Idempotent — removing a
    /// non-existent name is a no-op.
    Remove {
        #[arg(long)]
        name: String,
    },

    /// Pause a schedule (sets `enabled = false`). Idempotent.
    Pause {
        #[arg(long)]
        name: String,
    },

    /// Resume a paused schedule (sets `enabled = true`). Idempotent.
    Resume {
        #[arg(long)]
        name: String,
    },

    /// Execute every schedule whose `next_run` is past. Designed to
    /// be invoked by the host's `cron`/`systemd-timer` once a
    /// minute: `* * * * * proxxx schedule run-due`. The host
    /// scheduler is the trigger; the LOGIC, audit trail, and
    /// dispatch live in proxxx.
    ///
    /// For v1, "execute" means re-exec the proxxx binary as a
    /// subprocess with the saved `cmd`. The dispatch + audit +
    /// HITL gate of the spawned process all apply. Once we add a
    /// long-running daemon, this becomes an in-process call.
    RunDue {
        /// Path to the proxxx binary to spawn. Defaults to the
        /// current executable path. Override for tests / unusual
        /// install layouts.
        #[arg(long)]
        proxxx_binary: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, Default)]
pub enum ScheduleOutput {
    #[default]
    Text,
    Json,
}

pub fn execute_schedule(action: ScheduleCommand) -> Result<(Value, i32)> {
    match action {
        ScheduleCommand::Add { name, every, cmd } => {
            if name.is_empty() {
                anyhow::bail!("--name is required");
            }
            if cmd.is_empty() {
                anyhow::bail!("--cmd is required");
            }
            let interval_secs = parse_interval(&every)?;
            let mut store = load_store()?;
            if store.schedules.iter().any(|s| s.name == name) {
                anyhow::bail!("schedule `{name}` already exists — remove it first to redefine");
            }
            let now = now_secs();
            let entry = ScheduleEntry {
                name,
                interval_secs,
                cmd,
                last_run: 0,
                next_run: now.saturating_add(interval_secs),
                enabled: true,
            };
            store.schedules.push(entry.clone());
            save_store(&store)?;
            Ok((serde_json::to_value(entry)?, 0))
        }
        ScheduleCommand::List { output } => {
            let store = load_store()?;
            if matches!(output, ScheduleOutput::Json) {
                let s = serde_json::to_string_pretty(&store.schedules)?;
                println!("{s}");
                return Ok((Value::Null, 0));
            }
            if store.schedules.is_empty() {
                println!("(no schedules — add one with `proxxx schedule add`)");
                return Ok((Value::Null, 0));
            }
            let now = now_secs();
            println!(
                "{name:<24}  {enabled:<7}  {every:<8}  {next:<8}  cmd",
                name = "name",
                enabled = "enabled",
                every = "every",
                next = "next"
            );
            let sep = "─".repeat(72);
            println!("{sep}");
            for s in &store.schedules {
                let every = fmt_interval(s.interval_secs);
                let next = if s.next_run <= now {
                    "now".to_string()
                } else {
                    format!("{}s", s.next_run.saturating_sub(now))
                };
                println!(
                    "{name:<24}  {enabled:<7}  {every:<8}  {next:<8}  {cmd}",
                    name = s.name,
                    enabled = s.enabled,
                    every = every,
                    next = next,
                    cmd = s.cmd
                );
            }
            Ok((Value::Null, 0))
        }
        ScheduleCommand::Remove { name } => {
            let mut store = load_store()?;
            let before = store.schedules.len();
            store.schedules.retain(|s| s.name != name);
            let after = store.schedules.len();
            save_store(&store)?;
            Ok((
                serde_json::json!({"name": name, "removed": before != after}),
                0,
            ))
        }
        ScheduleCommand::Pause { name } => set_enabled(&name, false),
        ScheduleCommand::Resume { name } => set_enabled(&name, true),
        ScheduleCommand::RunDue { proxxx_binary } => run_due(proxxx_binary.as_deref()),
    }
}

fn set_enabled(name: &str, enabled: bool) -> Result<(Value, i32)> {
    let mut store = load_store()?;
    let mut changed = false;
    for s in &mut store.schedules {
        if s.name == name {
            s.enabled = enabled;
            changed = true;
        }
    }
    save_store(&store)?;
    Ok((
        serde_json::json!({"name": name, "enabled": enabled, "changed": changed}),
        0,
    ))
}

/// Format a duration in seconds back to the human form used by
/// `parse_interval`. Greedy match — picks the largest unit that
/// divides evenly.
fn fmt_interval(secs: u64) -> String {
    if secs.is_multiple_of(86400 * 7) && secs >= 86400 * 7 {
        format!("{}w", secs / (86400 * 7))
    } else if secs.is_multiple_of(86400) && secs >= 86400 {
        format!("{}d", secs / 86400)
    } else if secs.is_multiple_of(3600) && secs >= 3600 {
        format!("{}h", secs / 3600)
    } else if secs.is_multiple_of(60) && secs >= 60 {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// Run every enabled schedule whose `next_run <= now`. For each:
/// spawn proxxx as a subprocess, wait, capture exit code, update
/// `last_run` + `next_run`, persist.
///
/// Failures don't halt the loop — each schedule independent.
///
/// Public so the unified daemon (`cli::daemon::execute_daemon`)
/// can tick it directly without going through the CLI dispatch.
/// The `schedule` module itself is private; this is reachable
/// only from sibling modules in `cli/`.
pub fn run_due(proxxx_binary: Option<&std::path::Path>) -> Result<(Value, i32)> {
    use std::process::Command;

    let mut store = load_store()?;
    let now = now_secs();
    let binary = match proxxx_binary {
        Some(p) => p.to_path_buf(),
        None => std::env::current_exe().context("resolve current proxxx binary path")?,
    };

    let mut outcomes: Vec<Value> = Vec::new();
    for s in &mut store.schedules {
        if !s.enabled || s.next_run > now {
            continue;
        }
        // Hand-rolled whitespace split — adequate for the MVP
        // scheduler. Quoted arguments would need `shlex`, but the
        // expected use case (`vm snapshot 100 --yes`) has no
        // embedded whitespace anyway. Document as a limitation:
        // operators with whitespace inside arg values can pass them
        // via a wrapper script.
        let argv: Vec<String> = s.cmd.split_whitespace().map(str::to_owned).collect();
        let started = now_secs();
        let result = Command::new(&binary).args(&argv).output();
        let finished = now_secs();
        let outcome = match result {
            Ok(out) => serde_json::json!({
                "name": s.name,
                "started": started,
                "finished": finished,
                "exit_code": out.status.code(),
                "stdout_len": out.stdout.len(),
                "stderr_len": out.stderr.len(),
            }),
            Err(e) => serde_json::json!({
                "name": s.name,
                "started": started,
                "finished": finished,
                "error": format!("{e:#}"),
            }),
        };
        outcomes.push(outcome);
        s.last_run = finished;
        s.next_run = finished.saturating_add(s.interval_secs);
    }
    save_store(&store)?;
    Ok((serde_json::json!({"runs": outcomes}), 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("schedules.toml");
        (dir, p)
    }

    #[test]
    fn parse_interval_handles_all_suffixes() {
        assert_eq!(parse_interval("30s").unwrap(), 30);
        assert_eq!(parse_interval("5m").unwrap(), 300);
        assert_eq!(parse_interval("2h").unwrap(), 7200);
        assert_eq!(parse_interval("1d").unwrap(), 86400);
        assert_eq!(parse_interval("1w").unwrap(), 86400 * 7);
        assert_eq!(parse_interval("42").unwrap(), 42); // bare seconds
    }

    #[test]
    fn parse_interval_rejects_garbage() {
        assert!(parse_interval("").is_err());
        assert!(parse_interval("forever").is_err());
        assert!(parse_interval("abc-def").is_err());
    }

    #[test]
    fn parse_interval_does_not_panic_on_multibyte_suffix() {
        // Regression: `split_at(len-1)` panicked when the trailing char
        // was multi-byte. These must return Err cleanly, never panic.
        assert!(parse_interval("5µ").is_err());
        assert!(parse_interval("10€").is_err());
        assert!(parse_interval("3🔥").is_err());
        assert!(parse_interval("неделя").is_err());
    }

    #[test]
    fn fmt_interval_picks_largest_unit() {
        assert_eq!(fmt_interval(30), "30s");
        assert_eq!(fmt_interval(60), "1m");
        assert_eq!(fmt_interval(3600), "1h");
        assert_eq!(fmt_interval(86400), "1d");
        assert_eq!(fmt_interval(86400 * 7), "1w");
        assert_eq!(fmt_interval(86400 * 14), "2w");
    }

    #[test]
    fn round_trip_save_load_preserves_entries() {
        let (_d, p) = temp_path();
        let store = ScheduleStore {
            schedules: vec![
                ScheduleEntry {
                    name: "nightly".into(),
                    interval_secs: 86400,
                    cmd: "vm snapshot 100 --yes".into(),
                    last_run: 0,
                    next_run: 1_700_000_000,
                    enabled: true,
                },
                ScheduleEntry {
                    name: "hourly".into(),
                    interval_secs: 3600,
                    cmd: "events stream --no-existing".into(),
                    last_run: 100,
                    next_run: 1_700_000_100,
                    enabled: false,
                },
            ],
        };
        save_store_at(&p, &store).unwrap();
        let loaded = load_store_at(&p).unwrap();
        assert_eq!(loaded.schedules, store.schedules);
    }

    #[test]
    fn load_store_empty_when_file_missing() {
        let (_d, p) = temp_path();
        let s = load_store_at(&p).unwrap();
        assert!(s.schedules.is_empty());
    }
}
