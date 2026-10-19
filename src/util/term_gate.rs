//! Process-wide runtime gate suppressing `stderr` `tracing` output while a
//! full-screen terminal view owns the alternate screen (`#333`).
//!
//! ## Why a runtime gate instead of a command list
//!
//! `src/main.rs` previously checked `let is_tui = cli.command.is_none();` at
//! startup and installed the `stderr` tracing layer for every CLI subcommand.
//! Full-screen subcommands (`proxxx fleet` and its drill-in `tui::run`, plus
//! `proxxx serial` in `src/cli/console.rs` which enters the alternate screen
//! mid-command after connecting) therefore kept the `stderr` layer active while
//! the alternate screen was open, drawing `INFO proxxx::api::client: Connected
//! to …` lines directly on top of the TUI frame.
//!
//! A static command list in `main.rs` would miss future full-screen subcommands
//! and cannot handle `proxxx serial`, which needs `stderr` logging during its
//! pre-connect phase and silence once `EnterAlternateScreen` is active.
//!
//! Instead, [`TermGate`] maintains an `AtomicUsize` nesting counter:
//! - [`TerminalGuard::install`](crate::tui::terminal_guard::TerminalGuard::install)
//!   and `proxxx serial` (`src/cli/console.rs`) acquire a [`TermGateGuard`]
//!   before entering raw mode / the alternate screen and release it on
//!   teardown or `Drop` (covering early `?` returns and unwinding panics).
//! - Because the counter is depth-counted (`AtomicUsize`), nested full-screen
//!   views (`proxxx fleet` -> drill-in `tui::run`) keep the gate held until
//!   every active guard is dropped.
//! - [`GatedMakeWriter`] inspects the gate on each event: while `depth > 0`, it
//!   returns [`io::Sink`] so nothing is written to `stderr`; when `depth == 0`,
//!   it delegates to the underlying writer (`std::io::stderr`). The rotating
//!   file layer is never gated and always receives every log event.
//! - Unit tests construct isolated [`TermGate::new`] instances and pass them to
//!   [`GatedMakeWriter::new`] so parallel test threads never touch or race on
//!   the process-global [`GLOBAL_DEPTH`] counter.

use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tracing_subscriber::fmt::MakeWriter;

static GLOBAL_DEPTH: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug)]
enum GateBacking {
    Global(&'static AtomicUsize),
    Isolated(Arc<AtomicUsize>),
}

impl GateBacking {
    #[inline]
    fn counter(&self) -> &AtomicUsize {
        match self {
            Self::Global(c) => c,
            Self::Isolated(c) => c.as_ref(),
        }
    }
}

/// Depth-counted terminal ownership gate (`#333`).
///
/// Use [`TermGate::global`] (or the module-level [`acquire`] / [`is_active`]
/// helpers) in production code, and [`TermGate::new`] in unit tests to avoid
/// sharing process-global state across parallel test threads.
#[derive(Clone, Debug)]
pub struct TermGate {
    backing: GateBacking,
}

impl Default for TermGate {
    fn default() -> Self {
        Self::new()
    }
}

impl TermGate {
    /// Create an isolated gate with depth `0` for hermetic unit testing.
    #[must_use]
    pub fn new() -> Self {
        Self {
            backing: GateBacking::Isolated(Arc::new(AtomicUsize::new(0))),
        }
    }

    /// Handle to the process-global terminal gate.
    #[must_use]
    pub const fn global() -> Self {
        Self {
            backing: GateBacking::Global(&GLOBAL_DEPTH),
        }
    }

    /// Increment the gate depth and return an RAII [`TermGateGuard`] that
    /// decrements it when dropped.
    #[must_use = "dropping the guard immediately releases the terminal log gate"]
    pub fn acquire(&self) -> TermGateGuard {
        self.backing.counter().fetch_add(1, Ordering::AcqRel);
        TermGateGuard { gate: self.clone() }
    }

    /// Returns `true` when at least one [`TermGateGuard`] is currently alive.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.depth() > 0
    }

    /// Current nesting depth (`0` when no full-screen view owns the terminal).
    #[must_use]
    pub fn depth(&self) -> usize {
        self.backing.counter().load(Ordering::Acquire)
    }
}

/// Acquire a guard on the process-global terminal gate (`#333`).
#[must_use = "dropping the guard immediately releases the terminal log gate"]
pub fn acquire() -> TermGateGuard {
    TermGate::global().acquire()
}

/// Returns `true` when the process-global terminal gate is currently held.
#[must_use]
pub fn is_active() -> bool {
    TermGate::global().is_active()
}

/// RAII guard for one nesting level of a [`TermGate`].
///
/// Decrements the gate depth on [`Drop`], including on early `?` returns and
/// unwinding panics.
#[derive(Debug)]
pub struct TermGateGuard {
    gate: TermGate,
}

impl Drop for TermGateGuard {
    fn drop(&mut self) {
        self.gate.backing.counter().fetch_sub(1, Ordering::AcqRel);
    }
}

/// Writer returned by [`GatedMakeWriter::make_writer`].
pub enum GatedWriter<W> {
    /// Full-screen view is active: discard all bytes destined for the terminal.
    Sink(io::Sink),
    /// Normal CLI mode: forward all bytes to the underlying writer.
    Active(W),
}

impl<W: Write> Write for GatedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Sink(s) => s.write(buf),
            Self::Active(w) => w.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Sink(s) => s.flush(),
            Self::Active(w) => w.flush(),
        }
    }
}

/// `tracing_subscriber` [`MakeWriter`] wrapper that routes to [`io::Sink`]
/// while its [`TermGate`] is held and to the inner `M` otherwise (`#333`).
#[derive(Clone, Debug)]
pub struct GatedMakeWriter<M> {
    gate: TermGate,
    inner: M,
}

/// Type alias for the production `stderr` [`GatedMakeWriter`].
pub type GatedStderrMakeWriter = GatedMakeWriter<fn() -> io::Stderr>;

impl GatedMakeWriter<fn() -> io::Stderr> {
    /// Construct the production `stderr` writer gated by [`TermGate::global`].
    #[must_use]
    pub const fn stderr() -> Self {
        Self {
            gate: TermGate::global(),
            inner: io::stderr,
        }
    }
}

impl<M> GatedMakeWriter<M> {
    /// Construct a [`GatedMakeWriter`] with an explicit [`TermGate`] and inner
    /// [`MakeWriter`] (used by unit tests to inject an isolated gate and an
    /// in-memory buffer).
    #[must_use]
    pub const fn new(gate: TermGate, inner: M) -> Self {
        Self { gate, inner }
    }
}

impl<'a, M> MakeWriter<'a> for GatedMakeWriter<M>
where
    M: MakeWriter<'a>,
{
    type Writer = GatedWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        if self.gate.is_active() {
            GatedWriter::Sink(io::sink())
        } else {
            GatedWriter::Active(self.inner.make_writer())
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    #[derive(Clone, Default)]
    struct SharedBuffer(Arc<Mutex<Vec<u8>>>);

    impl SharedBuffer {
        fn take_string(&self) -> String {
            let mut guard = self.0.lock().expect("buffer mutex");
            let s = String::from_utf8_lossy(&guard).into_owned();
            guard.clear();
            s
        }
    }

    struct SharedBufferWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedBufferWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("buffer mutex").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for SharedBuffer {
        type Writer = SharedBufferWriter;

        fn make_writer(&'a self) -> Self::Writer {
            SharedBufferWriter(Arc::clone(&self.0))
        }
    }

    /// Test 1 (#333):
    /// On the gating `MakeWriter` with an injected buffer and isolated
    /// `TermGate`:
    /// - Gate held -> a `tracing` event writes nothing to the buffer.
    /// - Gate released -> a `tracing` event writes to the buffer.
    /// - Nested: two guards held, drop one -> still suppressed; drop both ->
    ///   writes again.
    #[test]
    fn gated_make_writer_suppresses_while_held_and_handles_nested_guards() {
        let gate = TermGate::new();
        let buf = SharedBuffer::default();
        let make_writer = GatedMakeWriter::new(gate.clone(), buf.clone());

        let subscriber = tracing_subscriber::fmt()
            .with_writer(make_writer)
            .with_ansi(false)
            .without_time()
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            assert_eq!(gate.depth(), 0);
            assert!(!gate.is_active());

            // 1. Gate held -> writes nothing.
            let g1 = gate.acquire();
            assert_eq!(gate.depth(), 1);
            assert!(gate.is_active());
            tracing::info!("suppressed-while-single-guard-held");
            assert_eq!(
                buf.take_string(),
                "",
                "buffer must remain empty while the gate is held"
            );

            // 2. Gate released -> writes normally.
            drop(g1);
            assert_eq!(gate.depth(), 0);
            assert!(!gate.is_active());
            tracing::info!("visible-after-single-guard-dropped");
            let out = buf.take_string();
            assert!(
                out.contains("visible-after-single-guard-dropped"),
                "expected event to reach buffer when gate is released, got: {out:?}"
            );

            // 3. Nested guards (e.g. `proxxx fleet` -> drill-in `tui::run`):
            //    two guards held -> suppressed; drop one -> still suppressed;
            //    drop second -> writes again.
            let outer = gate.acquire();
            let inner = gate.acquire();
            assert_eq!(gate.depth(), 2);
            tracing::info!("suppressed-with-two-guards");
            assert_eq!(buf.take_string(), "");

            drop(inner);
            assert_eq!(gate.depth(), 1);
            assert!(gate.is_active());
            tracing::info!("suppressed-with-one-guard-remaining");
            assert_eq!(
                buf.take_string(),
                "",
                "dropping only the inner guard must keep stderr suppressed"
            );

            drop(outer);
            assert_eq!(gate.depth(), 0);
            assert!(!gate.is_active());
            tracing::info!("visible-after-both-guards-dropped");
            let out_nested = buf.take_string();
            assert!(
                out_nested.contains("visible-after-both-guards-dropped"),
                "expected event to reach buffer after both guards drop, got: {out_nested:?}"
            );
        });
    }

    /// Test 2 (#333):
    /// `TermGateGuard` releases on an early `?` return and on an unwinding
    /// panic (`std::panic::catch_unwind`).
    #[test]
    fn guard_releases_on_early_return_and_on_panic() {
        let gate = TermGate::new();

        // 1. Early `?` return
        let early_return = || -> Result<(), &'static str> {
            let _guard = gate.acquire();
            assert_eq!(gate.depth(), 1);
            Err("simulated early error")?;
            Ok(())
        };
        assert!(early_return().is_err());
        assert_eq!(
            gate.depth(),
            0,
            "gate depth must return to 0 after early `?` return"
        );
        assert!(!gate.is_active());

        // 2. Unwinding panic via `catch_unwind`
        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = gate.acquire();
            assert_eq!(gate.depth(), 1);
            panic!("simulated full-screen panic");
        }));
        assert!(panicked.is_err());
        assert_eq!(
            gate.depth(),
            0,
            "gate depth must return to 0 after unwinding panic"
        );
        assert!(!gate.is_active());
    }

    /// Replace comments and string literals with spaces (preserving newlines
    /// and line numbers) so source scans only match real code tokens.
    fn strip_comments_and_strings(src: &str) -> String {
        let bytes = src.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            // Line comment `//...`
            if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'/' {
                while i < bytes.len() && bytes[i] != b'\n' {
                    out.push(b' ');
                    i += 1;
                }
                continue;
            }
            // Block comment `/* ... */`
            if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
                out.push(b' ');
                out.push(b' ');
                i += 2;
                while i < bytes.len() {
                    if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                        out.push(b' ');
                        out.push(b' ');
                        i += 2;
                        break;
                    }
                    out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                }
                continue;
            }
            // Raw string literal `r#"..."#` / `r"..."`
            if bytes[i] == b'r'
                && i + 1 < bytes.len()
                && (bytes[i + 1] == b'"' || bytes[i + 1] == b'#')
            {
                let mut hashes = 0usize;
                let mut j = i + 1;
                while j < bytes.len() && bytes[j] == b'#' {
                    hashes += 1;
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b'"' {
                    out.extend(std::iter::repeat_n(b' ', j - i + 1));
                    i = j + 1;
                    while i < bytes.len() {
                        if bytes[i] == b'"'
                            && i + hashes < bytes.len()
                            && bytes[i + 1..=i + hashes].iter().all(|&b| b == b'#')
                        {
                            out.extend(std::iter::repeat_n(b' ', hashes + 1));
                            i += hashes + 1;
                            break;
                        }
                        out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                        i += 1;
                    }
                    continue;
                }
            }
            // Normal string literal `"..."`
            if bytes[i] == b'"' {
                out.push(b' ');
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        out.push(b' ');
                        out.push(if bytes[i + 1] == b'\n' { b'\n' } else { b' ' });
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b'"' {
                        out.push(b' ');
                        i += 1;
                        break;
                    }
                    out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                }
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8(out).expect("valid utf-8 after stripping ASCII comments/strings")
    }

    fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir).expect("read_dir");
        for entry in entries {
            let entry = entry.expect("dir entry");
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().and_then(|s| s.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }

    /// Extract `(fn_name, start_byte, end_byte)` for every top-level or impl
    /// function in `clean_src` (which has comments and string literals replaced
    /// by spaces).
    fn extract_function_spans(clean_src: &str) -> Vec<(String, usize, usize)> {
        let bytes = clean_src.as_bytes();
        let mut spans = Vec::new();
        let mut i = 0;
        while i + 3 < bytes.len() {
            let prev_ok = i == 0 || !(bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            if prev_ok
                && bytes[i] == b'f'
                && bytes[i + 1] == b'n'
                && bytes[i + 2].is_ascii_whitespace()
            {
                let fn_start = i;
                let mut j = i + 3;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                let name_start = j;
                while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                    j += 1;
                }
                let fn_name = clean_src[name_start..j].to_string();
                // Advance to the opening `{` of the function body (or `;` for
                // trait method declarations without a body).
                let mut paren_depth = 0usize;
                while j < bytes.len() {
                    match bytes[j] {
                        b'(' => paren_depth += 1,
                        b')' => paren_depth = paren_depth.saturating_sub(1),
                        b';' if paren_depth == 0 => break,
                        b'{' if paren_depth == 0 => {
                            let mut brace_depth = 1usize;
                            let mut k = j + 1;
                            while k < bytes.len() && brace_depth > 0 {
                                if bytes[k] == b'{' {
                                    brace_depth += 1;
                                } else if bytes[k] == b'}' {
                                    brace_depth -= 1;
                                }
                                k += 1;
                            }
                            spans.push((fn_name, fn_start, k));
                            break;
                        }
                        _ => {}
                    }
                    j += 1;
                }
            }
            i += 1;
        }
        spans
    }

    /// Check whether `raw_src` (at relative path `rel_path`) has any
    /// `EnterAlternateScreen` usage outside a function that acquires the
    /// terminal gate. Returns a list of human-readable violation descriptions.
    fn find_unguarded_alt_screen_sites(rel_path: &str, raw_src: &str) -> (usize, Vec<String>) {
        // Ignore unit test modules at the tail of source files (`#[cfg(test)]`)
        // so test fixtures inside `term_gate.rs` don't self-match.
        let prod_src = raw_src.split("#[cfg(test)]").next().unwrap_or(raw_src);
        let clean = strip_comments_and_strings(prod_src);
        let fn_spans = extract_function_spans(&clean);

        let mut checked_sites = 0usize;
        let mut violations = Vec::new();
        let needle = "EnterAlternateScreen";
        let mut search_from = 0usize;

        while let Some(rel_idx) = clean[search_from..].find(needle) {
            let idx = search_from + rel_idx;
            search_from = idx + needle.len();

            // Check if this occurrence is part of a `use ...;` statement by
            // scanning backwards to the previous `;`, `{`, or `}` (ignoring
            // brace-grouped `use foo::{bar, EnterAlternateScreen};`).
            let prefix = &clean[..idx];
            let stmt_start = prefix.rfind(';').map_or(0, |p| p + 1);
            let stmt_slice = clean[stmt_start..idx].trim_start();
            if stmt_slice.starts_with("use ") || stmt_slice.contains("\nuse ") {
                continue;
            }

            checked_sites += 1;
            let line_no = clean[..idx].bytes().filter(|&b| b == b'\n').count() + 1;

            // Find the innermost enclosing function span.
            let enclosing = fn_spans
                .iter()
                .filter(|(_, start, end)| *start <= idx && idx < *end)
                .max_by_key(|(_, start, _)| *start);

            let Some((fn_name, start, end)) = enclosing else {
                violations.push(format!(
                    "{rel_path}:{line_no}: `EnterAlternateScreen` is not inside any function"
                ));
                continue;
            };

            let fn_body = &clean[*start..*end];
            let is_terminal_guard_file = rel_path.ends_with("terminal_guard.rs");
            let has_gate = if is_terminal_guard_file {
                fn_body.contains("term_gate::acquire(")
            } else {
                fn_body.contains("term_gate::acquire(")
                    || fn_body.contains("TerminalGuard::install(")
            };

            if !has_gate {
                violations.push(format!(
                    "{rel_path}:{line_no}: `EnterAlternateScreen` in `fn {fn_name}` does not acquire `term_gate::acquire()` or `TerminalGuard::install()`"
                ));
            }
        }

        (checked_sites, violations)
    }

    /// Test 3 (#333):
    /// Source-scan guard test: every `EnterAlternateScreen` in `src/` sits in
    /// a function that also takes the terminal gate (`term_gate::acquire()` or
    /// `TerminalGuard::install()`, with `terminal_guard.rs` itself required to
    /// call `term_gate::acquire()`).
    #[test]
    fn every_enter_alternate_screen_in_src_is_guarded_by_term_gate() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let src_dir = manifest_dir.join("src");
        let mut files = Vec::new();
        collect_rs_files(&src_dir, &mut files);
        files.sort();

        let mut total_sites = 0usize;
        let mut all_violations = Vec::new();

        for file in files {
            let rel = file
                .strip_prefix(&manifest_dir)
                .unwrap_or(&file)
                .to_string_lossy()
                .replace('\\', "/");
            let content = std::fs::read_to_string(&file).expect("read source file");
            let (sites, violations) = find_unguarded_alt_screen_sites(&rel, &content);
            total_sites += sites;
            all_violations.extend(violations);
        }

        assert!(
            total_sites >= 3,
            "expected at least 3 EnterAlternateScreen call sites in src/ (terminal_guard.rs, tui/mod.rs, cli/console.rs), found {total_sites}"
        );
        assert!(
            all_violations.is_empty(),
            "found unguarded `EnterAlternateScreen` call site(s) in `src/`:\n  {}",
            all_violations.join("\n  ")
        );
    }

    #[test]
    fn source_scanner_rejects_unguarded_enter_alternate_screen() {
        let bad = r"
            use crossterm::terminal::EnterAlternateScreen;
            pub fn new_fullscreen_cmd() {
                execute!(std::io::stdout(), EnterAlternateScreen).unwrap();
            }
        ";
        let (sites, violations) = find_unguarded_alt_screen_sites("src/cli/fake.rs", bad);
        assert_eq!(sites, 1);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("fn new_fullscreen_cmd"));

        let good = r"
            use crossterm::terminal::EnterAlternateScreen;
            pub fn new_fullscreen_cmd() {
                let _gate = crate::util::term_gate::acquire();
                execute!(std::io::stdout(), EnterAlternateScreen).unwrap();
            }
        ";
        let (sites_ok, violations_ok) = find_unguarded_alt_screen_sites("src/cli/fake.rs", good);
        assert_eq!(sites_ok, 1);
        assert!(violations_ok.is_empty());
    }

    /// Inspect `src/main.rs` (after stripping comments, string literals, and
    /// any `#[cfg(test)]` tail) and return every violation of the #333 rule:
    /// the `stderr` `tracing_subscriber::fmt::layer()` in `src/main.rs` must be
    /// built with `GatedStderrMakeWriter::stderr()`, and no `.with_writer(...)`
    /// call in `src/main.rs` may wire an un-gated `std::io::stderr` / `io::stderr`
    /// (or any writer other than `non_blocking` or `GatedStderrMakeWriter::stderr()`).
    fn find_main_rs_stderr_wiring_violations(raw_src: &str) -> Vec<String> {
        let prod_src = raw_src.split("#[cfg(test)]").next().unwrap_or(raw_src);
        let clean = strip_comments_and_strings(prod_src);
        let compact: String = clean.chars().filter(|c| !c.is_whitespace()).collect();

        let mut violations = Vec::new();

        if !compact.contains("GatedStderrMakeWriter::stderr()") {
            violations.push(
                "src/main.rs does not reference `GatedStderrMakeWriter::stderr()`".to_string(),
            );
        }

        // Every `fmt::layer()` must immediately specify `.with_writer(...)`.
        let mut layer_from = 0usize;
        let layer_needle = "fmt::layer()";
        let mut layer_count = 0usize;
        while let Some(rel) = compact[layer_from..].find(layer_needle) {
            let idx = layer_from + rel;
            layer_from = idx + layer_needle.len();
            layer_count += 1;
            let after = &compact[layer_from..];
            if !after.starts_with(".with_writer(") {
                violations.push(
                    "src/main.rs has a `fmt::layer()` not immediately followed by `.with_writer(...)`"
                        .to_string(),
                );
            }
        }
        if layer_count < 2 {
            violations.push(format!(
                "src/main.rs expected at least 2 `fmt::layer()` calls (file + gated stderr), found {layer_count}"
            ));
        }

        // Inspect every `.with_writer(...)` argument in `src/main.rs`.
        let writer_needle = ".with_writer(";
        let mut search_from = 0usize;
        let mut saw_gated_stderr_writer = false;

        while let Some(rel) = clean[search_from..].find(writer_needle) {
            let call_start = search_from + rel;
            let arg_start = call_start + writer_needle.len();
            let line_no = clean[..call_start].bytes().filter(|&b| b == b'\n').count() + 1;

            let bytes = clean.as_bytes();
            let mut depth = 1usize;
            let mut k = arg_start;
            while k < bytes.len() && depth > 0 {
                if bytes[k] == b'(' {
                    depth += 1;
                } else if bytes[k] == b')' {
                    depth -= 1;
                }
                k += 1;
            }
            search_from = k;

            if depth != 0 {
                violations.push(format!(
                    "src/main.rs:{line_no}: unclosed `.with_writer(` call"
                ));
                continue;
            }

            let arg: String = clean[arg_start..k - 1]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();

            if arg == "non_blocking" {
                continue;
            }
            if arg == "GatedStderrMakeWriter::stderr()"
                || arg.ends_with("::GatedStderrMakeWriter::stderr()")
            {
                saw_gated_stderr_writer = true;
                continue;
            }

            violations.push(format!(
                "src/main.rs:{line_no}: `.with_writer({arg})` is not allowed; stderr tracing layer must use `GatedStderrMakeWriter::stderr()`"
            ));
        }

        if !saw_gated_stderr_writer {
            violations.push(
                "src/main.rs has no `.with_writer(...GatedStderrMakeWriter::stderr())` call"
                    .to_string(),
            );
        }

        violations
    }

    /// Test 4 (#333, Rev. 28 F1):
    /// Guard test ensuring `src/main.rs` builds its `stderr` `fmt::layer()`
    /// with `GatedStderrMakeWriter::stderr()` and never with raw
    /// `std::io::stderr` / `io::stderr`.
    #[test]
    fn main_rs_wires_stderr_tracing_layer_through_gated_make_writer() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let main_rs = manifest_dir.join("src").join("main.rs");
        let content = std::fs::read_to_string(&main_rs).expect("read src/main.rs");
        let violations = find_main_rs_stderr_wiring_violations(&content);
        assert!(
            violations.is_empty(),
            "src/main.rs stderr tracing layer wiring violation(s):\n  {}",
            violations.join("\n  ")
        );
    }

    #[test]
    fn main_rs_wiring_scanner_rejects_raw_stderr_writer() {
        let b1_std_io_stderr = r"
            fn main() {
                tracing_subscriber::registry()
                    .with(tracing_subscriber::fmt::layer().with_writer(non_blocking))
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_writer(std::io::stderr)
                            .with_ansi(true),
                    )
                    .init();
            }
        ";
        let v1 = find_main_rs_stderr_wiring_violations(b1_std_io_stderr);
        assert!(
            !v1.is_empty(),
            "scanner must reject `.with_writer(std::io::stderr)`"
        );

        let b1_io_stderr_with_dead_reference = r"
            fn main() {
                let _unused = util::term_gate::GatedStderrMakeWriter::stderr();
                tracing_subscriber::registry()
                    .with(tracing_subscriber::fmt::layer().with_writer(non_blocking))
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_writer(io::stderr)
                            .with_ansi(true),
                    )
                    .init();
            }
        ";
        let v2 = find_main_rs_stderr_wiring_violations(b1_io_stderr_with_dead_reference);
        assert!(
            !v2.is_empty(),
            "scanner must reject `.with_writer(io::stderr)` even if GatedStderrMakeWriter is referenced elsewhere"
        );

        let good_main = r"
            fn main() {
                tracing_subscriber::fmt()
                    .with_writer(non_blocking)
                    .init();
                tracing_subscriber::registry()
                    .with(tracing_subscriber::fmt::layer().with_writer(non_blocking))
                    .with(
                        tracing_subscriber::fmt::layer()
                            .with_writer(util::term_gate::GatedStderrMakeWriter::stderr())
                            .with_ansi(true),
                    )
                    .init();
            }
        ";
        let v_ok = find_main_rs_stderr_wiring_violations(good_main);
        assert!(v_ok.is_empty(), "unexpected violations: {v_ok:?}");
    }
}
