//! Live migration progress streaming for `proxxx migrate --stream`.
//!
//! PVE emits per-disk transfer progress + RAM / phase events into the
//! migration task log. This module:
//!
//! 1. Parses the log lines into [`MigrationEvent`] values (hand-rolled
//!    — no regex dep). The parser is total: lines that aren't
//!    recognised become [`MigrationEvent::Info`] so we don't drop
//!    anything operators might need.
//! 2. Drives the streaming loop: poll `/log` incrementally (start=
//!    last-seen+1), poll `/status`, emit one event per new line, exit
//!    when the task is done.
//! 3. Renders to a [`Renderer`] — `Tty` (in-place per-disk progress
//!    bars via crossterm) or `Ndjson` (one JSON object per event,
//!    matching the `events stream` format on stdout).
//!
//! Why hand-rolled vs `regex`: keeps the dependency surface unchanged
//! (no `regex` / `once_cell` added). The PVE format is regular enough
//! that a forward-scan with prefix matching is cleaner and faster.

use anyhow::Result;
use serde::Serialize;

use crate::api::types::TaskStatus;

/// One semantic event extracted from a migration task log line.
///
/// `Info` is the catch-all for log lines we don't have a structured
/// shape for — they still flow through so operators see them in TTY
/// scrollback and JSON consumers can match on them by raw text.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MigrationEvent {
    /// `drive-scsi0: transferred 256.0 MiB of 32.0 GiB (0.78%) in 3s, read: 85.3 MiB/s, write: 85.3 MiB/s`
    ///
    /// One of these per disk per progress tick. Multiple disks
    /// interleave — the renderer keys by `drive`.
    DiskProgress {
        drive: String,
        transferred_bytes: u64,
        total_bytes: u64,
        percent: f32,
        /// Seconds since transfer for this disk started (PVE's `in Ns`).
        /// `None` for the initial 0% line which usually omits it.
        elapsed_secs: Option<u64>,
        /// PVE reports `read:` and `write:` separately; we keep both
        /// for JSON consumers and surface the average to TTY.
        read_rate_bps: Option<u64>,
        write_rate_bps: Option<u64>,
    },
    /// `migration status: active (transferred X MiB, remaining Y MiB), …`
    /// or `migration speed: 123 MiB/s - downtime 42 ms`. Live-RAM
    /// progress for QEMU online migration. Whichever fields PVE
    /// emitted survive — the rest are `None`.
    RamProgress {
        transferred_bytes: Option<u64>,
        remaining_bytes: Option<u64>,
        speed_bps: Option<u64>,
        downtime_ms: Option<u64>,
    },
    /// `migration finished successfully (duration 00:01:23)` or its
    /// error sibling. Wall-clock duration in seconds when PVE included it.
    Finished {
        success: bool,
        duration_secs: Option<u64>,
        raw: String,
    },
    /// Anything else — timestamp lines, `starting migration`, `found
    /// local disk`, etc. Operators care about these but they have no
    /// stable shape.
    Info { text: String },
}

/// Parse one log line into a structured event.
///
/// Always returns something — unrecognised input becomes `Info`. The
/// parser strips a leading PVE timestamp (`2026-05-20 01:23:45 `) if
/// present so the prefix-matching below works against either form.
pub fn parse_line(raw: &str) -> MigrationEvent {
    let line = strip_pve_timestamp(raw.trim_end());

    if let Some(ev) = parse_disk_progress(line) {
        return ev;
    }
    if let Some(ev) = parse_ram_progress(line) {
        return ev;
    }
    if let Some(ev) = parse_finished(line) {
        return ev;
    }
    MigrationEvent::Info {
        text: line.to_string(),
    }
}

/// PVE prefixes most task log lines with `YYYY-MM-DD HH:MM:SS `. Strip
/// it so downstream prefix matching doesn't have to know about it.
/// Conservative: only strip when the prefix matches the exact shape,
/// otherwise return the line untouched (the per-disk lines from
/// `qemu_drive_mirror_monitor` skip the timestamp entirely).
fn strip_pve_timestamp(line: &str) -> &str {
    // `YYYY-MM-DD HH:MM:SS ` is exactly 20 chars then a space.
    if line.len() < 20 {
        return line;
    }
    let b = line.as_bytes();
    if b[4] == b'-' && b[7] == b'-' && b[10] == b' ' && b[13] == b':' && b[16] == b':' {
        // Strip the date+time+single-space prefix.
        // After the seconds (chars 17-18) we expect a space at 19.
        if b.get(19) == Some(&b' ') {
            return &line[20..];
        }
    }
    line
}

/// `drive-scsi0: transferred 256.0 MiB of 32.0 GiB (0.78%) in 3s, read: 85.3 MiB/s, write: 85.3 MiB/s`
fn parse_disk_progress(line: &str) -> Option<MigrationEvent> {
    // Drive name is anything before `: transferred`. PVE has used both
    // `drive-scsi0:` and `drive-virtio0:`; we don't care which, just
    // capture the token.
    let (drive, rest) = line.split_once(": transferred")?;
    if !drive.starts_with("drive-") {
        return None;
    }
    // Optional `:` (some PVE versions emit `transferred:` with a colon).
    let rest = rest.trim_start().trim_start_matches(':').trim_start();

    // `256.0 MiB of 32.0 GiB (0.78%) in 3s, read: 85.3 MiB/s, write: 85.3 MiB/s`
    let (transferred_str, after_transferred) = rest.split_once(" of ")?;
    let (total_str, after_total) = after_transferred.split_once(" (")?;
    let (percent_str, after_percent) = after_total.split_once("%)")?;

    let transferred_bytes = parse_size(transferred_str.trim())?;
    let total_bytes = parse_size(total_str.trim())?;
    let percent: f32 = percent_str.trim().parse().ok()?;

    let elapsed_secs = after_percent
        .split_once("in ")
        .and_then(|(_, rest)| rest.split_once('s').map(|(num, _)| num))
        .and_then(|s| s.trim().parse::<u64>().ok());

    let read_rate_bps = extract_rate(after_percent, "read:");
    let write_rate_bps = extract_rate(after_percent, "write:");

    Some(MigrationEvent::DiskProgress {
        drive: drive.to_string(),
        transferred_bytes,
        total_bytes,
        percent,
        elapsed_secs,
        read_rate_bps,
        write_rate_bps,
    })
}

/// `migration status: active (transferred X MiB, remaining Y MiB)` /
/// `migration speed: 123 MiB/s - downtime 42 ms`.
fn parse_ram_progress(line: &str) -> Option<MigrationEvent> {
    if !line.starts_with("migration status: ") && !line.starts_with("migration speed:") {
        return None;
    }
    let transferred_bytes = find_after(line, "transferred ")
        .and_then(parse_size_prefix)
        .map(|(n, _)| n);
    let remaining_bytes = find_after(line, "remaining ")
        .and_then(parse_size_prefix)
        .map(|(n, _)| n);
    let speed_bps = if let Some(after) = find_after(line, "migration speed:") {
        // " 123 MiB/s - downtime …"
        let trimmed = after.trim_start();
        let (n, rest) = parse_size_prefix(trimmed)?;
        // Speed is followed by "/s" — accept either presence or absence.
        let _ = rest;
        Some(n)
    } else {
        None
    };
    let downtime_ms = find_after(line, "downtime ").and_then(|after| {
        let after = after.trim_start();
        let (num, _) = after.split_once(' ').unwrap_or((after, ""));
        num.parse::<u64>().ok()
    });

    Some(MigrationEvent::RamProgress {
        transferred_bytes,
        remaining_bytes,
        speed_bps,
        downtime_ms,
    })
}

/// `migration finished successfully (duration 00:01:23)` or `migration
/// failed: …` / `TASK ERROR: …` — the closing line PVE writes when
/// the task is about to exit.
fn parse_finished(line: &str) -> Option<MigrationEvent> {
    let lower = line.to_ascii_lowercase();
    let success = lower.contains("migration finished") || lower.contains("migration completed");
    let failed = lower.contains("migration failed")
        || lower.contains("task error:")
        || lower.contains("migration aborted");
    if !success && !failed {
        return None;
    }
    let duration_secs = find_after(line, "duration ").and_then(|after| {
        let dur = after.split_whitespace().next()?.trim_end_matches(')');
        parse_hms_or_secs(dur)
    });
    Some(MigrationEvent::Finished {
        success: success && !failed,
        duration_secs,
        raw: line.to_string(),
    })
}

/// Find the substring after the first occurrence of `marker`. None if
/// the marker doesn't appear.
fn find_after<'a>(haystack: &'a str, marker: &str) -> Option<&'a str> {
    haystack.find(marker).map(|i| &haystack[i + marker.len()..])
}

/// Parse a size string like `256.0 MiB`, `32.0 GiB`, `0.0 B` into bytes.
/// Accepts: B, KiB, MiB, GiB, TiB, KB, MB, GB, TB (PVE uses IEC, but
/// some older versions used SI — we accept both). Returns `None` on
/// unrecognised units.
pub fn parse_size(s: &str) -> Option<u64> {
    let (n, _) = parse_size_prefix(s.trim())?;
    Some(n)
}

/// Like [`parse_size`] but also returns the remainder after the unit
/// so the caller can continue parsing (used by RAM progress where
/// multiple sizes appear on one line).
fn parse_size_prefix(s: &str) -> Option<(u64, &str)> {
    let s = s.trim_start();
    let split_idx = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    if split_idx == 0 {
        return None;
    }
    let num: f64 = s[..split_idx].parse().ok()?;
    let rest = s[split_idx..].trim_start();
    let (unit, after) = rest
        .split_once(|c: char| !c.is_ascii_alphabetic())
        .unwrap_or((rest, ""));
    let multiplier = match unit {
        "B" | "" => 1_f64,
        "KiB" => 1024_f64,
        "MiB" => 1024_f64 * 1024_f64,
        "GiB" => 1024_f64 * 1024_f64 * 1024_f64,
        "TiB" => 1024_f64 * 1024_f64 * 1024_f64 * 1024_f64,
        "KB" => 1000_f64,
        "MB" => 1_000_000_f64,
        "GB" => 1_000_000_000_f64,
        "TB" => 1_000_000_000_000_f64,
        _ => return None,
    };
    // `as u64` is intentional — clamps NaN/negative to 0 (which we
    // discard via `?` upstream when relevant). Sub-byte precision in
    // a size string is meaningless anyway.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let bytes = (num * multiplier) as u64;
    Some((bytes, after))
}

/// Extract the byte-rate after `marker` in a tail like `…, read: 85.3
/// MiB/s, write: …`. Returns bytes-per-second. `None` if the marker
/// isn't present.
fn extract_rate(line: &str, marker: &str) -> Option<u64> {
    let after = find_after(line, marker)?;
    let trimmed = after.trim_start();
    // Stop at `,` so we don't run past one rate into the next.
    let token = trimmed.split(',').next()?.trim_end_matches("/s").trim();
    parse_size(token)
}

/// Parse a duration string. Accepts `HH:MM:SS`, `MM:SS`, or a bare
/// number of seconds. Returns `None` on unrecognised input.
fn parse_hms_or_secs(s: &str) -> Option<u64> {
    let s = s.trim_end_matches(')').trim_end_matches('s');
    if !s.contains(':') {
        return s.parse::<u64>().ok();
    }
    let parts: Vec<&str> = s.split(':').collect();
    let nums: Option<Vec<u64>> = parts.iter().map(|p| p.parse::<u64>().ok()).collect();
    let nums = nums?;
    match nums.len() {
        3 => Some(nums[0] * 3600 + nums[1] * 60 + nums[2]),
        2 => Some(nums[0] * 60 + nums[1]),
        1 => Some(nums[0]),
        _ => None,
    }
}

// ────────────────────────────────────────────────────────────
// Streaming driver
// ────────────────────────────────────────────────────────────

/// Output sink for streaming events. The driver feeds parsed events
/// into one of these implementations.
pub trait Renderer {
    /// Called once per parsed log line.
    fn emit(&mut self, event: &MigrationEvent);
    /// Called once when the task completes, after the last event.
    /// `status` is the final [`TaskStatus`] from PVE.
    fn finish(&mut self, status: &TaskStatus);
}

/// NDJSON renderer — one JSON object per event, plus a final summary
/// object with `event: "complete"` + the PVE task status. Matches the
/// shape of `events stream --format json` so consumers can use the
/// same `jq` filters.
pub struct NdjsonRenderer<W: std::io::Write> {
    pub writer: W,
}

impl<W: std::io::Write> Renderer for NdjsonRenderer<W> {
    fn emit(&mut self, event: &MigrationEvent) {
        // serde_json failures here would mean we constructed
        // unserialisable data — that's a programmer error, not a
        // runtime condition; we log and skip rather than panicking
        // mid-stream.
        match serde_json::to_string(event) {
            Ok(s) => {
                let _ = writeln!(self.writer, "{s}");
            }
            Err(e) => tracing::warn!("migrate stream: failed to serialise event: {e}"),
        }
    }
    fn finish(&mut self, status: &TaskStatus) {
        let summary = serde_json::json!({
            "kind": "complete",
            "exitstatus": status.exitstatus,
            "status": status.status,
        });
        let _ = writeln!(self.writer, "{summary}");
    }
}

/// TTY renderer — per-disk progress bars, one stable line per drive,
/// rewritten in place on each tick. Info / RAM / Finished events are
/// printed above the disk-bar block as a scrolling log.
///
/// The bar block lives below a "log scrollback" region. After each
/// emit we:
///   1. Move cursor up `bars_drawn` lines so the next print starts
///      where the bars are.
///   2. Print the (re-ordered, sorted by drive name) bar block.
///   3. The terminal cursor naturally ends below the last bar — the
///      next log line then prints below the bars, pushing them
///      visually upward only on log events (not on bar-only ticks).
///
/// Falls back gracefully if the terminal can't be reached — every
/// crossterm command's Result is swallowed (a dead PTY mid-stream
/// shouldn't crash the migration).
pub struct TtyRenderer {
    /// Number of disk-progress bar lines drawn last tick. Used to
    /// know how far up to move the cursor before redrawing.
    bars_drawn: u16,
    /// Per-drive latest state, sorted by drive name when rendered so
    /// ordering is stable across ticks regardless of which disk PVE
    /// emitted into the log first.
    disks: std::collections::BTreeMap<String, DiskState>,
}

#[derive(Clone, Copy)]
struct DiskState {
    transferred_bytes: u64,
    total_bytes: u64,
    percent: f32,
    elapsed_secs: Option<u64>,
    write_rate_bps: Option<u64>,
}

impl Default for TtyRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl TtyRenderer {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bars_drawn: 0,
            disks: std::collections::BTreeMap::new(),
        }
    }

    fn redraw_bars(&mut self) {
        use std::io::Write;
        let mut out = std::io::stdout();
        // Move cursor up to the start of the bar block from last tick.
        for _ in 0..self.bars_drawn {
            let _ = write!(out, "\x1b[1A\x1b[2K");
        }
        for (drive, state) in &self.disks {
            let bar = render_bar(state.percent, 30);
            let transferred = format_bytes(state.transferred_bytes);
            let total = format_bytes(state.total_bytes);
            let rate = state
                .write_rate_bps
                .map_or_else(String::new, |r| format!("  {}/s", format_bytes(r)));
            let elapsed = state
                .elapsed_secs
                .map_or_else(String::new, |s| format!("  {s}s"));
            let _ = writeln!(
                out,
                "  {drive:<16} {bar} {pct:>5.1}%  {transferred} / {total}{rate}{elapsed}",
                pct = state.percent,
            );
        }
        let _ = out.flush();
        // `as u16` is safe — operators don't migrate VMs with >65k
        // disks. `try_into().unwrap_or(u16::MAX)` would just clamp
        // unnecessarily.
        #[allow(clippy::cast_possible_truncation)]
        {
            self.bars_drawn = self.disks.len() as u16;
        }
    }
}

impl Renderer for TtyRenderer {
    fn emit(&mut self, event: &MigrationEvent) {
        match event {
            MigrationEvent::DiskProgress {
                drive,
                transferred_bytes,
                total_bytes,
                percent,
                elapsed_secs,
                write_rate_bps,
                ..
            } => {
                self.disks.insert(
                    drive.clone(),
                    DiskState {
                        transferred_bytes: *transferred_bytes,
                        total_bytes: *total_bytes,
                        percent: *percent,
                        elapsed_secs: *elapsed_secs,
                        write_rate_bps: *write_rate_bps,
                    },
                );
                self.redraw_bars();
            }
            MigrationEvent::RamProgress {
                transferred_bytes,
                remaining_bytes,
                speed_bps,
                downtime_ms,
            } => {
                self.print_log_line(&format_ram(
                    *transferred_bytes,
                    *remaining_bytes,
                    *speed_bps,
                    *downtime_ms,
                ));
            }
            MigrationEvent::Finished { raw, .. } | MigrationEvent::Info { text: raw } => {
                self.print_log_line(raw);
            }
        }
    }

    fn finish(&mut self, status: &TaskStatus) {
        let outcome = status.exitstatus.as_deref().unwrap_or("(no exitstatus)");
        let line = if status.is_success() {
            format!("migration complete — {outcome}")
        } else {
            format!("migration failed — {outcome}")
        };
        self.print_log_line(&line);
    }
}

impl TtyRenderer {
    /// Print one log line *above* the bar block, then redraw the bars
    /// so the order on screen reads: scrolling log → current bars at
    /// the bottom.
    fn print_log_line(&mut self, text: &str) {
        use std::io::Write;
        let mut out = std::io::stdout();
        // Move up past the bars, clear those lines, print the new log
        // line, then re-emit the bars below it.
        for _ in 0..self.bars_drawn {
            let _ = write!(out, "\x1b[1A\x1b[2K");
        }
        let _ = writeln!(out, "{text}");
        // bars_drawn is now stale (we cleared them); reset and
        // redraw_bars will repaint.
        self.bars_drawn = 0;
        let _ = out.flush();
        self.redraw_bars();
    }
}

fn render_bar(percent: f32, width: usize) -> String {
    let pct = percent.clamp(0.0, 100.0) / 100.0;
    // Truncation is the intended behaviour — sub-cell precision in a
    // 30-cell bar is meaningless.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let filled = (pct * width as f32) as usize;
    let empty = width - filled;
    format!("[{}{}]", "█".repeat(filled), " ".repeat(empty))
}

fn format_bytes(n: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let f = n as f64;
    if n >= 1 << 40 {
        format!("{:.1} TiB", f / (1_u64 << 40) as f64)
    } else if n >= 1 << 30 {
        format!("{:.1} GiB", f / (1_u64 << 30) as f64)
    } else if n >= 1 << 20 {
        format!("{:.1} MiB", f / (1_u64 << 20) as f64)
    } else if n >= 1 << 10 {
        format!("{:.1} KiB", f / (1_u64 << 10) as f64)
    } else {
        format!("{n} B")
    }
}

fn format_ram(
    transferred: Option<u64>,
    remaining: Option<u64>,
    speed: Option<u64>,
    downtime: Option<u64>,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(t) = transferred {
        parts.push(format!("ram transferred {}", format_bytes(t)));
    }
    if let Some(r) = remaining {
        parts.push(format!("remaining {}", format_bytes(r)));
    }
    if let Some(s) = speed {
        parts.push(format!("speed {}/s", format_bytes(s)));
    }
    if let Some(d) = downtime {
        parts.push(format!("downtime {d} ms"));
    }
    if parts.is_empty() {
        "(ram event with no fields)".to_string()
    } else {
        parts.join("  ")
    }
}

// ────────────────────────────────────────────────────────────
// Driver — polls the task log and feeds the renderer until done.
// ────────────────────────────────────────────────────────────

/// Narrow read-side trait over `ProxmoxGateway`, covering only the
/// two endpoints the streamer needs. Blanket impl below means the
/// production `PxClient` works directly; tests implement this trait
/// against a scripted in-memory state machine without stubbing the
/// full gateway.
#[async_trait::async_trait]
pub trait TaskLogView: Send + Sync {
    async fn get_task_log_view(
        &self,
        node: &str,
        upid: &str,
        start: usize,
        limit: usize,
    ) -> Result<crate::api::types::TaskLog>;
    async fn get_task_status_view(&self, node: &str, upid: &str) -> Result<TaskStatus>;
}

#[async_trait::async_trait]
impl<T> TaskLogView for T
where
    T: crate::api::ProxmoxGateway + Send + Sync + ?Sized,
{
    async fn get_task_log_view(
        &self,
        node: &str,
        upid: &str,
        start: usize,
        limit: usize,
    ) -> Result<crate::api::types::TaskLog> {
        crate::api::ProxmoxGateway::get_task_log(self, node, upid, start, limit).await
    }
    async fn get_task_status_view(&self, node: &str, upid: &str) -> Result<TaskStatus> {
        crate::api::ProxmoxGateway::get_task_status(self, node, upid).await
    }
}

/// Stream a running migration task to the supplied renderer until
/// PVE reports it complete (or `timeout_secs` elapses, defaulting to
/// 3600 s — same as [`crate::cli::common::poll_task_until_done`]).
///
/// Returns the final [`TaskStatus`] so the caller can build the JSON
/// envelope + classify the exit code.
///
/// `poll_interval_ms` controls how aggressively we poll. 1500 ms
/// matches `poll_task_until_done`'s default — fast enough to feel
/// live for sub-minute migrations, slow enough that a multi-hour
/// transfer doesn't hammer the API.
pub async fn stream_migration<C: TaskLogView + ?Sized, R: Renderer>(
    client: &C,
    node: &str,
    upid: &str,
    renderer: &mut R,
    poll_interval_ms: u64,
    timeout_secs: u64,
) -> Result<TaskStatus> {
    let deadline = if timeout_secs > 0 {
        Some(tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs))
    } else {
        None
    };
    let interval = std::time::Duration::from_millis(poll_interval_ms.max(250));

    // PVE's task-log `start` parameter is 0-based — we track the next
    // line we haven't yet fetched. Fetching with start=cursor will
    // either return [] (no new lines) or [lines from cursor onwards].
    let mut cursor: usize = 0;
    // The fetch limit per poll. PVE clamps internally — 1000 is
    // generous and avoids re-fetching the same lines repeatedly.
    let fetch_limit: usize = 1000;

    loop {
        // Fetch any new log lines first so the renderer sees what's
        // already happened before we check status (avoids missing
        // the last lines emitted right before status flips to done).
        match client
            .get_task_log_view(node, upid, cursor, fetch_limit)
            .await
        {
            Ok(log) => {
                for line in &log.data {
                    // PVE returns the line number `n` 1-based. We
                    // bump the cursor to one past the highest n seen
                    // so the next fetch picks up from there.
                    if line.n > cursor {
                        cursor = line.n;
                    }
                    let event = parse_line(&line.t);
                    renderer.emit(&event);
                }
            }
            Err(e) => {
                tracing::warn!("migrate stream: log fetch failed (will retry): {e:#}");
            }
        }

        let status = client.get_task_status_view(node, upid).await?;
        if status.is_done() {
            // One last log sweep in case PVE wrote the final lines
            // between the previous fetch and the status flip.
            if let Ok(log) = client
                .get_task_log_view(node, upid, cursor, fetch_limit)
                .await
            {
                for line in &log.data {
                    if line.n > cursor {
                        cursor = line.n;
                    }
                    let event = parse_line(&line.t);
                    renderer.emit(&event);
                }
            }
            renderer.finish(&status);
            return Ok(status);
        }

        if let Some(d) = deadline {
            if tokio::time::Instant::now() >= d {
                anyhow::bail!(
                    "migration task {upid} did not complete within {timeout_secs}s (status: {})",
                    status.status
                );
            }
        }
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unwrap_disk(ev: MigrationEvent) -> (String, u64, u64, f32, Option<u64>, Option<u64>) {
        match ev {
            MigrationEvent::DiskProgress {
                drive,
                transferred_bytes,
                total_bytes,
                percent,
                read_rate_bps,
                write_rate_bps,
                ..
            } => (
                drive,
                transferred_bytes,
                total_bytes,
                percent,
                read_rate_bps,
                write_rate_bps,
            ),
            other => panic!("expected DiskProgress, got {other:?}"),
        }
    }

    #[test]
    fn parses_iec_disk_progress_line() {
        let ev = parse_line(
            "drive-scsi0: transferred 256.0 MiB of 32.0 GiB (0.78%) in 3s, read: 85.3 MiB/s, write: 85.3 MiB/s",
        );
        let (drive, t, total, pct, r, w) = unwrap_disk(ev);
        assert_eq!(drive, "drive-scsi0");
        assert_eq!(t, 256 * 1024 * 1024);
        assert_eq!(total, 32_u64 * 1024 * 1024 * 1024);
        assert!((pct - 0.78).abs() < 0.001);
        // 85.3 MiB ≈ 89_443_532 bytes
        assert!(r.is_some() && r.unwrap() > 89_000_000 && r.unwrap() < 90_000_000);
        assert!(w.is_some());
    }

    #[test]
    fn parses_disk_progress_with_pve_timestamp_prefix() {
        let ev = parse_line(
            "2026-05-20 01:23:45 drive-virtio0: transferred 1.0 GiB of 32.0 GiB (3.12%) in 12s, read: 85.3 MiB/s, write: 85.3 MiB/s",
        );
        let (drive, t, _, _, _, _) = unwrap_disk(ev);
        assert_eq!(drive, "drive-virtio0");
        assert_eq!(t, 1024 * 1024 * 1024);
    }

    #[test]
    fn parses_disk_progress_with_colon_after_transferred() {
        // Some PVE versions emit `transferred:` with a colon.
        let ev = parse_line("drive-scsi0: transferred: 0.0 B of 32.0 GiB (0.00%) in 0s");
        let (_, t, total, pct, r, _) = unwrap_disk(ev);
        assert_eq!(t, 0);
        assert_eq!(total, 32_u64 * 1024 * 1024 * 1024);
        assert!((pct - 0.0).abs() < 0.001);
        // No rate fields on the initial line.
        assert!(r.is_none());
    }

    #[test]
    fn parses_disk_progress_without_rate_fields() {
        let ev = parse_line("drive-scsi0: transferred 512.0 MiB of 32.0 GiB (1.56%) in 6s");
        let (_, t, _, _, r, w) = unwrap_disk(ev);
        assert_eq!(t, 512 * 1024 * 1024);
        assert!(r.is_none());
        assert!(w.is_none());
    }

    #[test]
    fn parses_ram_progress_active_status() {
        let ev =
            parse_line("migration status: active (transferred 1024 MiB, remaining 512 MiB), …");
        match ev {
            MigrationEvent::RamProgress {
                transferred_bytes: Some(t),
                remaining_bytes: Some(r),
                ..
            } => {
                assert_eq!(t, 1024 * 1024 * 1024);
                assert_eq!(r, 512 * 1024 * 1024);
            }
            other => panic!("expected RamProgress with transferred+remaining, got {other:?}"),
        }
    }

    #[test]
    fn parses_ram_progress_speed_and_downtime() {
        let ev = parse_line("migration speed: 123 MiB/s - downtime 42 ms");
        match ev {
            MigrationEvent::RamProgress {
                speed_bps: Some(s),
                downtime_ms: Some(d),
                ..
            } => {
                assert!(s > 128_000_000 && s < 130_000_000);
                assert_eq!(d, 42);
            }
            other => panic!("expected RamProgress with speed+downtime, got {other:?}"),
        }
    }

    #[test]
    fn parses_finished_successful_with_duration() {
        let ev = parse_line("migration finished successfully (duration 00:01:23)");
        match ev {
            MigrationEvent::Finished {
                success: true,
                duration_secs: Some(d),
                ..
            } => assert_eq!(d, 83),
            other => panic!("expected successful Finished, got {other:?}"),
        }
    }

    #[test]
    fn parses_finished_failure() {
        let ev = parse_line("TASK ERROR: migration aborted: target host unreachable");
        match ev {
            MigrationEvent::Finished { success: false, .. } => (),
            other => panic!("expected failed Finished, got {other:?}"),
        }
    }

    #[test]
    fn falls_back_to_info_for_unknown_lines() {
        let ev =
            parse_line("2026-05-20 01:23:45 starting migration of VM 100 to node 'pve-test-2'");
        match ev {
            MigrationEvent::Info { text } => {
                assert!(text.contains("starting migration"));
                // Timestamp stripped.
                assert!(!text.starts_with("2026"));
            }
            other => panic!("expected Info, got {other:?}"),
        }
    }

    #[test]
    fn parse_size_handles_iec_and_si_units() {
        assert_eq!(parse_size("1.0 B"), Some(1));
        assert_eq!(parse_size("1.0 KiB"), Some(1024));
        assert_eq!(parse_size("1.0 MiB"), Some(1024 * 1024));
        assert_eq!(parse_size("1.0 GiB"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_size("1.0 MB"), Some(1_000_000));
        assert_eq!(parse_size("0.5 GiB"), Some(512 * 1024 * 1024));
        assert_eq!(parse_size("not a size"), None);
    }

    #[test]
    fn parse_hms_or_secs_handles_all_shapes() {
        assert_eq!(parse_hms_or_secs("00:01:23"), Some(83));
        assert_eq!(parse_hms_or_secs("01:23"), Some(83));
        assert_eq!(parse_hms_or_secs("83"), Some(83));
        assert_eq!(parse_hms_or_secs("83s"), Some(83));
        assert_eq!(parse_hms_or_secs("not"), None);
    }

    // ── Driver tests with a scripted mock client ──────────────────

    /// Mock `TaskLogView` that returns scripted log batches per poll
    /// and a final `TaskStatus`. `script` is consumed front-to-back —
    /// each call to `get_task_log_view` returns the next entry's
    /// lines, then status flips to "stopped" so the loop exits.
    struct ScriptedClient {
        /// Log batches, one per poll iteration. The driver fetches
        /// each call so the batches simulate "new lines since last
        /// fetch" — each batch is what PVE would return starting
        /// from `cursor`.
        log_script: tokio::sync::Mutex<Vec<Vec<crate::api::types::TaskLogLine>>>,
        /// Status to return until the script is empty, then flip to
        /// the final terminal status.
        final_status: TaskStatus,
    }

    impl ScriptedClient {
        fn new(batches: Vec<Vec<&str>>, final_exitstatus: &str) -> Self {
            let scripted = batches
                .into_iter()
                .enumerate()
                .map(|(i, batch)| {
                    batch
                        .into_iter()
                        .enumerate()
                        .map(|(j, t)| crate::api::types::TaskLogLine {
                            n: i * 100 + j + 1,
                            t: t.to_string(),
                        })
                        .collect()
                })
                .collect();
            Self {
                log_script: tokio::sync::Mutex::new(scripted),
                final_status: TaskStatus {
                    status: "stopped".to_string(),
                    exitstatus: Some(final_exitstatus.to_string()),
                    ..Default::default()
                },
            }
        }
    }

    #[async_trait::async_trait]
    impl TaskLogView for ScriptedClient {
        async fn get_task_log_view(
            &self,
            _: &str,
            _: &str,
            _: usize,
            _: usize,
        ) -> Result<crate::api::types::TaskLog> {
            let mut guard = self.log_script.lock().await;
            let batch = if guard.is_empty() {
                Vec::new()
            } else {
                guard.remove(0)
            };
            Ok(crate::api::types::TaskLog {
                total: batch.len(),
                data: batch,
            })
        }
        async fn get_task_status_view(&self, _: &str, _: &str) -> Result<TaskStatus> {
            // While there's still scripted log batches, return
            // "running" to keep the loop alive. Once exhausted,
            // return the terminal status.
            if self.log_script.lock().await.is_empty() {
                Ok(self.final_status.clone())
            } else {
                Ok(TaskStatus {
                    status: "running".to_string(),
                    exitstatus: None,
                    ..Default::default()
                })
            }
        }
    }

    /// Capture renderer — records every event in order so tests can
    /// assert on the dispatch decisions of the driver.
    #[derive(Default)]
    struct CaptureRenderer {
        events: Vec<MigrationEvent>,
        finished: Option<TaskStatus>,
    }
    impl Renderer for CaptureRenderer {
        fn emit(&mut self, event: &MigrationEvent) {
            self.events.push(event.clone());
        }
        fn finish(&mut self, status: &TaskStatus) {
            self.finished = Some(status.clone());
        }
    }

    #[tokio::test]
    async fn streamer_runs_to_completion_and_emits_parsed_events() {
        let client = ScriptedClient::new(
            vec![
                vec!["2026-05-20 01:23:45 starting migration of VM 100"],
                vec![
                    "drive-scsi0: transferred 256.0 MiB of 32.0 GiB (0.78%) in 3s",
                    "drive-scsi0: transferred 512.0 MiB of 32.0 GiB (1.56%) in 6s",
                ],
                vec!["migration finished successfully (duration 00:01:23)"],
            ],
            "OK",
        );
        let mut renderer = CaptureRenderer::default();
        let status = stream_migration(
            &client,
            "pve-test-1",
            "UPID:pve-test-1:0:0:0:qmigrate:100:test:",
            &mut renderer,
            250, // clamps to min interval
            60,
        )
        .await
        .unwrap();
        assert!(status.is_success());
        // Each scripted log line should have produced one event.
        assert_eq!(renderer.events.len(), 4);
        // First is the Info ("starting migration").
        assert!(matches!(renderer.events[0], MigrationEvent::Info { .. }));
        // Two disk-progress events.
        assert!(matches!(
            renderer.events[1],
            MigrationEvent::DiskProgress { .. }
        ));
        assert!(matches!(
            renderer.events[2],
            MigrationEvent::DiskProgress { .. }
        ));
        // Finished marker.
        assert!(matches!(
            renderer.events[3],
            MigrationEvent::Finished { success: true, .. }
        ));
        assert!(renderer.finished.is_some());
    }

    #[tokio::test]
    async fn streamer_propagates_failure_status() {
        let client = ScriptedClient::new(
            vec![vec![
                "TASK ERROR: migration aborted: target host unreachable",
            ]],
            "migration aborted: target host unreachable",
        );
        let mut renderer = CaptureRenderer::default();
        let status = stream_migration(
            &client,
            "pve-test-1",
            "UPID:pve-test-1:0:0:0:qmigrate:100:test:",
            &mut renderer,
            250,
            10,
        )
        .await
        .unwrap();
        assert!(!status.is_success());
        assert!(matches!(
            renderer.events[0],
            MigrationEvent::Finished { success: false, .. }
        ));
    }

    #[test]
    fn ndjson_renderer_emits_one_object_per_event_plus_summary() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut r = NdjsonRenderer { writer: &mut buf };
            r.emit(&MigrationEvent::Info {
                text: "starting".to_string(),
            });
            r.emit(&MigrationEvent::DiskProgress {
                drive: "drive-scsi0".to_string(),
                transferred_bytes: 256 * 1024 * 1024,
                total_bytes: 32 * 1024_u64.pow(3),
                percent: 0.78,
                elapsed_secs: Some(3),
                read_rate_bps: None,
                write_rate_bps: None,
            });
            let status = TaskStatus {
                status: "stopped".to_string(),
                exitstatus: Some("OK".to_string()),
                ..Default::default()
            };
            r.finish(&status);
        }
        let text = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 3);
        // Each line is valid JSON.
        for l in &lines {
            let _: serde_json::Value = serde_json::from_str(l).unwrap();
        }
        // Last line is the summary.
        let summary: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(summary["kind"], "complete");
        assert_eq!(summary["exitstatus"], "OK");
    }

    #[test]
    fn render_bar_clamps_extremes() {
        assert!(render_bar(0.0, 10).starts_with('['));
        assert_eq!(render_bar(0.0, 10).chars().filter(|c| *c == '█').count(), 0);
        assert_eq!(
            render_bar(100.0, 10).chars().filter(|c| *c == '█').count(),
            10
        );
        // Clamps out-of-range values rather than panicking.
        let bar = render_bar(150.0, 10);
        assert_eq!(bar.chars().filter(|c| *c == '█').count(), 10);
    }

    #[test]
    fn format_bytes_handles_unit_breakpoints() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
        assert_eq!(format_bytes(1024_u64.pow(4)), "1.0 TiB");
    }
}
