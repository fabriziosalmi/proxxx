//! Colour for human-readable CLI output.
//!
//! The rule is the TUI's: colour means "look here". A running guest's
//! status is green, a stopped one is dim (a normal state, not an alarm),
//! usage is coloured only from the elevated threshold up, and red is kept
//! for what is wrong (a node offline, usage past the critical threshold,
//! which also gets a `!` marker for monochrome terminals and colour-blind
//! readers).
//!
//! Colour is written only when the stream it goes to (stdout, or stderr
//! for a [`Line::eprint`]) is a terminal, `NO_COLOR` is unset or empty
//! (<https://no-color.org>) and `TERM` is not `dumb`. A pipe, a file or
//! `--format json` never sees an escape sequence.
//!
//! #437: human-readable output goes through `outln!`, which removes every
//! control sequence, colour included. A [`Line`] therefore sanitizes each
//! segment on its own and adds the colour codes after, so a cluster string
//! still cannot carry its own escape sequence to the terminal.

use std::sync::OnceLock;

use crate::tui::theme::{usage_level, UsageLevel, UsageMetric};

/// A colour with a meaning, mapped to the basic ANSI palette so it follows
/// the user's terminal theme (light or dark) instead of fixed RGB values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Paint {
    /// Running, online.
    Ok,
    /// Stopped: present but not active. Also a side note on stderr.
    Dim,
    /// Paused or suspended: an intentional state.
    Info,
    /// Unknown state, usage at the elevated threshold.
    Warn,
    /// Usage at the high threshold.
    High,
    /// Offline, usage at the critical threshold.
    Critical,
}

impl Paint {
    const fn sgr(self) -> &'static str {
        match self {
            Self::Ok => "32",
            Self::Dim => "2",
            Self::Info => "34",
            Self::Warn => "33",
            Self::High => "38;5;208",
            Self::Critical => "31",
        }
    }
}

/// Whether CLI output on stdout is coloured, decided once per process.
#[must_use]
pub fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        decide(
            std::io::IsTerminal::is_terminal(&std::io::stdout()),
            std::env::var_os("NO_COLOR").as_deref(),
            std::env::var_os("TERM").as_deref(),
        )
    })
}

/// Whether CLI output on stderr is coloured, decided once per process.
/// stderr is checked on its own: one of the two streams is often redirected
/// (`2>log`, `| less`) while the other stays on the terminal.
#[must_use]
pub fn stderr_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        decide(
            std::io::IsTerminal::is_terminal(&std::io::stderr()),
            std::env::var_os("NO_COLOR").as_deref(),
            std::env::var_os("TERM").as_deref(),
        )
    })
}

/// Pure form of [`enabled`] and [`stderr_enabled`].
#[must_use]
pub fn decide(
    stream_is_terminal: bool,
    no_color: Option<&std::ffi::OsStr>,
    term: Option<&std::ffi::OsStr>,
) -> bool {
    stream_is_terminal
        && no_color.is_none_or(std::ffi::OsStr::is_empty)
        && term.is_none_or(|t| t != "dumb")
}

/// Colour of a guest status word as PVE reports it.
#[must_use]
pub fn guest_status(status: &str) -> Paint {
    match status {
        "running" => Paint::Ok,
        "stopped" => Paint::Dim,
        "paused" | "suspended" => Paint::Info,
        _ => Paint::Warn,
    }
}

/// Colour of a node status word as PVE reports it.
#[must_use]
pub fn node_status(status: &str) -> Paint {
    match status {
        "online" => Paint::Ok,
        "offline" => Paint::Critical,
        _ => Paint::Warn,
    }
}

/// Colour of a `STATUS` cell in `--format table` output, for the words a
/// guest or a node can report. Any other word (a storage or task status)
/// stays uncoloured.
#[must_use]
pub fn status_word(status: &str) -> Option<Paint> {
    match status {
        "running" | "online" => Some(Paint::Ok),
        "stopped" => Some(Paint::Dim),
        "paused" | "suspended" => Some(Paint::Info),
        "offline" => Some(Paint::Critical),
        _ => None,
    }
}

/// Colour and marker of a usage percentage, from the TUI thresholds
/// (`#334`). An ok level has no colour and no marker.
#[must_use]
pub fn usage(metric: UsageMetric, percent: f64) -> (Option<Paint>, &'static str) {
    let level = usage_level(metric, percent);
    let paint = match level {
        UsageLevel::Ok => None,
        UsageLevel::Elevated => Some(Paint::Warn),
        UsageLevel::High => Some(Paint::High),
        UsageLevel::Critical => Some(Paint::Critical),
    };
    (paint, level.marker())
}

/// One line of human-readable output, built from segments. Pad a segment
/// before adding it: escape codes have no width, but `{:<8}` counts them.
#[derive(Debug, Default)]
pub struct Line {
    segments: Vec<(String, Option<Paint>)>,
}

impl Line {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add uncoloured text.
    #[must_use]
    pub fn plain(mut self, text: impl Into<String>) -> Self {
        self.segments.push((text.into(), None));
        self
    }

    /// Add text in `paint` (uncoloured when `paint` is `None`).
    #[must_use]
    pub fn paint(mut self, text: impl Into<String>, paint: Option<Paint>) -> Self {
        self.segments.push((text.into(), paint));
        self
    }

    /// The line as text: every segment sanitized (#437), coloured segments
    /// wrapped in their SGR code when `color` is true.
    #[must_use]
    pub fn render(&self, color: bool) -> String {
        let mut out = String::new();
        for (text, paint) in &self.segments {
            let safe = crate::util::format::safe_text(text);
            match paint {
                Some(p) if color => {
                    out.push_str("\x1b[");
                    out.push_str(p.sgr());
                    out.push('m');
                    out.push_str(&safe);
                    out.push_str("\x1b[0m");
                }
                _ => out.push_str(&safe),
            }
        }
        out
    }

    /// Print the line to stdout, coloured when [`enabled`].
    pub fn print(&self) {
        // raw-output: every segment is sanitized in `render`; the only
        // control sequences left are the SGR codes added there.
        println!("{}", self.render(enabled()));
    }

    /// Print the line to stderr, coloured when [`stderr_enabled`].
    pub fn eprint(&self) {
        eprintln!("{}", self.render(stderr_enabled()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn colour_only_on_a_terminal_without_no_color_or_dumb_term() {
        assert!(decide(true, None, Some(OsStr::new("xterm-256color"))));
        assert!(decide(true, Some(OsStr::new("")), None));
        assert!(
            !decide(false, None, None),
            "a pipe or a file gets no colour"
        );
        assert!(!decide(true, Some(OsStr::new("1")), None), "NO_COLOR set");
        assert!(!decide(true, None, Some(OsStr::new("dumb"))));
    }

    #[test]
    fn render_without_colour_is_the_plain_text() {
        let line = Line::new()
            .plain("  101 ")
            .paint("stopped ", Some(guest_status("stopped")));
        assert_eq!(line.render(false), "  101 stopped ");
    }

    #[test]
    fn render_with_colour_wraps_only_painted_segments() {
        let line = Line::new()
            .plain("a ")
            .paint("running", Some(guest_status("running")))
            .paint(" n/a", None);
        assert_eq!(line.render(true), "a \x1b[32mrunning\x1b[0m n/a");
    }

    /// #437: a cluster string cannot bring its own escape sequence, with or
    /// without colour.
    #[test]
    fn a_segment_cannot_carry_its_own_control_sequence() {
        let hostile = "evil\x1b]52;c;cHduZWQ=\x07name";
        for color in [false, true] {
            let out = Line::new()
                .plain(hostile)
                .paint(hostile, Some(Paint::Ok))
                .render(color);
            assert!(!out.contains("\x1b]"), "OSC survived: {out:?}");
            assert!(!out.contains('\x07'), "BEL survived: {out:?}");
        }
    }

    #[test]
    fn stopped_is_dim_and_red_is_kept_for_problems() {
        assert_eq!(guest_status("running"), Paint::Ok);
        assert_eq!(guest_status("stopped"), Paint::Dim);
        assert_eq!(guest_status("paused"), Paint::Info);
        assert_eq!(node_status("online"), Paint::Ok);
        assert_eq!(node_status("offline"), Paint::Critical);
    }

    #[test]
    fn a_table_status_cell_is_coloured_only_for_guest_and_node_words() {
        assert_eq!(status_word("running"), Some(Paint::Ok));
        assert_eq!(status_word("offline"), Some(Paint::Critical));
        assert_eq!(status_word("OK"), None);
        assert_eq!(status_word("-"), None);
    }

    #[test]
    fn usage_is_coloured_from_the_elevated_threshold_up() {
        assert_eq!(usage(UsageMetric::Cpu, 6.2), (None, ""));
        assert_eq!(usage(UsageMetric::Memory, 75.0), (Some(Paint::Warn), ""));
        assert_eq!(usage(UsageMetric::Disk, 85.0), (Some(Paint::High), ""));
        assert_eq!(usage(UsageMetric::Disk, 95.0), (Some(Paint::Critical), "!"));
    }
}
