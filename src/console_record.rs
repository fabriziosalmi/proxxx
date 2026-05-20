//! asciinema cast v2 recording + replay.
//!
//! [Asciicast v2 spec](https://docs.asciinema.org/manual/asciicast/v2/).
//! The format is one JSON object per line:
//!
//! ```text
//! {"version": 2, "width": 80, "height": 24, "timestamp": 1700000000, "title": "..."}
//! [0.123, "o", "hello\r\n"]
//! [0.234, "i", "q"]
//! ```
//!
//! Events use:
//!   * `"o"` — output (host → terminal, what the operator sees)
//!   * `"i"` — input (terminal → host, what the operator typed)
//!
//! The text payload is a JSON string containing the raw UTF-8 bytes
//! (asciinema treats it as a string, with the standard JSON
//! `\uXXXX` / backslash / quote escapes for non-ASCII or control bytes).
//! Our writer takes `&[u8]` and emits the string form via
//! `String::from_utf8_lossy` — invalid sequences become the
//! Unicode replacement character (U+FFFD), which the replayer
//! renders verbatim.
//! Lossy is acceptable for this use case (terminal control bytes
//! are valid ASCII; UTF-8 substring corruption is rare).
//!
//! ## Replay
//!
//! [`replay_cast`] reads the file, parses each line, sleeps to
//! re-create the timing, and writes the output bytes to stdout.
//! Input events are SKIPPED on replay (we render only what the
//! operator saw; their keystrokes are forensic data, not playback).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::time::Instant;

/// Asciicast v2 header (first line of every cast file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CastHeader {
    /// Always 2 for the v2 format.
    pub version: u32,
    pub width: u16,
    pub height: u16,
    /// Unix epoch seconds when recording started.
    pub timestamp: u64,
    pub title: String,
}

/// Streaming writer for an asciicast v2 file. One per session;
/// dropping the writer closes the file (the writer is `BufWriter`-
/// wrapped so the final flush happens on drop).
///
/// Failures are downgraded to `tracing::warn` on the recording
/// side: we DO NOT want a failing recorder to bring down a live
/// SSH/serial session. The session keeps running; the cast may
/// just be missing the last few events.
pub struct CastWriter {
    file: BufWriter<std::fs::File>,
    start: Instant,
}

impl CastWriter {
    /// Open `path` and write the header line. The parent directory
    /// is created if missing. File permissions 0600 on Unix.
    pub fn create(path: &Path, width: u16, height: u16, title: &str) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create dir {}", parent.display()))?;
        }
        let file = std::fs::File::create(path)
            .with_context(|| format!("open cast file {} for write", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 0600 {}", path.display()))?;
        }
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let header = CastHeader {
            version: 2,
            width,
            height,
            timestamp,
            title: title.to_string(),
        };
        let mut bw = BufWriter::new(file);
        let header_line = serde_json::to_string(&header)?;
        writeln!(bw, "{header_line}").context("write cast header")?;
        Ok(Self {
            file: bw,
            start: Instant::now(),
        })
    }

    /// Record a chunk of output bytes (host → terminal).
    pub fn record_output(&mut self, bytes: &[u8]) {
        self.record_event("o", bytes);
    }

    /// Record a chunk of input bytes (terminal → host).
    pub fn record_input(&mut self, bytes: &[u8]) {
        self.record_event("i", bytes);
    }

    /// Format one event line and append. I/O failures are logged
    /// but not propagated — see the struct rustdoc.
    fn record_event(&mut self, kind: &str, bytes: &[u8]) {
        let elapsed = self.start.elapsed().as_secs_f64();
        // Lossy is the right call for terminal data: the alternative
        // (skipping invalid UTF-8) loses the operator's view. Lone
        // replacement chars in a recording are diagnostic, not fatal.
        let payload = String::from_utf8_lossy(bytes);
        // Use serde_json to escape — its escape rules match asciinema's
        // (RFC 8259 JSON string), guaranteeing the cast parses.
        let payload_json = match serde_json::to_string(&payload) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("cast: payload serialise failed: {e}");
                return;
            }
        };
        // The asciinema format is a JSON array literal — emit it by
        // hand to keep the timestamp formatting consistent (3 decimal
        // digits is standard).
        let line = format!("[{elapsed:.6}, \"{kind}\", {payload_json}]");
        if let Err(e) = writeln!(self.file, "{line}") {
            tracing::warn!("cast: write failed: {e}");
        }
    }

    /// Force-flush. The Drop impl below also flushes; callers can
    /// call this explicitly before exit if they need a guarantee.
    pub fn flush(&mut self) {
        if let Err(e) = self.file.flush() {
            tracing::warn!("cast: flush failed: {e}");
        }
    }
}

impl Drop for CastWriter {
    fn drop(&mut self) {
        self.flush();
    }
}

/// Replay a cast file to stdout. Reads the header line + every
/// event, sleeps the per-event delay, writes the output bytes.
/// Input events are skipped (we render only what the operator saw).
///
/// `speed` is a multiplier — `1.0` plays at the recording rate;
/// `2.0` plays 2× faster; `0.5` plays at half speed.
pub async fn replay_cast(path: &Path, speed: f64) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("open cast {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();

    // Header first.
    let n = reader
        .read_line(&mut line)
        .await
        .with_context(|| format!("read cast header {}", path.display()))?;
    if n == 0 {
        anyhow::bail!("empty cast file: {}", path.display());
    }
    let header: CastHeader = serde_json::from_str(line.trim())
        .with_context(|| format!("parse cast header in {}", path.display()))?;
    if header.version != 2 {
        anyhow::bail!(
            "unsupported cast version {} (expected 2) in {}",
            header.version,
            path.display(),
        );
    }
    eprintln!(
        "▶ replaying {} ({}×{}, recorded {} epoch s)",
        header.title, header.width, header.height, header.timestamp
    );

    let mut stdout = tokio::io::stdout();
    let mut prev_t = 0_f64;
    let speed = if speed <= 0.0 { 1.0 } else { speed };

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // `[<seconds>, "<kind>", "<payload>"]` parses as a 3-tuple.
        let event: (f64, String, String) = match serde_json::from_str(trimmed) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("cast: skipping malformed event line: {e}");
                continue;
            }
        };
        let (t, kind, payload) = event;
        // Skip input events on replay (operator keystrokes are
        // forensic data, not playback).
        if kind != "o" {
            prev_t = t;
            continue;
        }
        let delay = (t - prev_t).max(0.0) / speed;
        if delay > 0.0 {
            tokio::time::sleep(std::time::Duration::from_secs_f64(delay)).await;
        }
        prev_t = t;
        stdout.write_all(payload.as_bytes()).await?;
        stdout.flush().await?;
    }
    Ok(())
}

/// Default path for a recording: `<data_local_dir>/sessions/
/// <ts>-<vmid>-<kind>.cast`. Overridable via the CLI flag — this
/// is just the auto-generated fallback.
#[must_use]
pub fn default_recording_path(vmid: u32, kind: &str) -> std::path::PathBuf {
    let dir = directories::ProjectDirs::from("dev", "proxxx", "proxxx")
        .map_or_else(
            || std::path::PathBuf::from("/tmp/proxxx"),
            |d| d.data_local_dir().to_path_buf(),
        )
        .join("sessions");
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    dir.join(format!("{ts}-{vmid}-{kind}.cast"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cast_writer_emits_header_then_events() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.cast");
        {
            let mut w = CastWriter::create(&path, 120, 30, "test session").unwrap();
            w.record_output(b"hello\r\n");
            w.record_input(b"q");
            w.flush();
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 3);

        // Header.
        let header: CastHeader = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(header.version, 2);
        assert_eq!(header.width, 120);
        assert_eq!(header.height, 30);
        assert_eq!(header.title, "test session");

        // Output event.
        let (_, kind, payload): (f64, String, String) = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(kind, "o");
        assert_eq!(payload, "hello\r\n");

        // Input event.
        let (_, kind2, payload2): (f64, String, String) = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(kind2, "i");
        assert_eq!(payload2, "q");
    }

    #[test]
    fn cast_writer_handles_invalid_utf8_gracefully() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.cast");
        {
            let mut w = CastWriter::create(&path, 80, 24, "binary").unwrap();
            // Invalid UTF-8 in terminal output — `from_utf8_lossy`
            // should replace it with U+FFFD and the line should
            // still serialise as valid JSON.
            w.record_output(&[0xFF, b'a', 0xFE]);
            w.flush();
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        // Header + one event; both must be valid JSON.
        assert_eq!(lines.len(), 2);
        let _: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let _: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    }

    #[test]
    fn default_recording_path_has_session_dir_and_extension() {
        let p = default_recording_path(100, "serial");
        let s = p.to_string_lossy();
        assert!(s.contains("sessions"));
        assert!(s.ends_with(".cast"));
        assert!(s.contains("-100-serial"));
    }
}
