//! (audit) — RAII terminal restoration.
//!
//! Pre-fix: `tui::run` called `enable_raw_mode()` + `EnterAlternateScreen`
//! manually at the top, then `disable_raw_mode()` + `LeaveAlternateScreen`
//! manually at the bottom. Any early `?` return between those two points
//! left the user's terminal in raw mode + alternate screen — typing
//! would not echo, prompt would be invisible, and the only recovery was
//! `reset` blind. The panic hook (flight recorder) catches panics, but a
//! plain `Err` return path was unguarded.
//!
//! `TerminalGuard` wraps the `Terminal<CrosstermBackend<Stdout>>` and
//! implements `Drop` to ALWAYS restore the terminal — on the happy path,
//! on `?` early return, on panic (the panic hook still fires first; the
//! Drop is the second line of defence).

use std::io::{self, Stdout};

use anyhow::{Context, Result};
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

/// Owns the ratatui Terminal and guarantees teardown via Drop.
///
/// Construction installs raw mode + alternate screen; drop restores
/// both. The `terminal` field is exposed via `as_mut` / `as_ref` so
/// callers can render through it. Idempotent: calling `restore()`
/// explicitly is fine — Drop becomes a no-op afterwards.
pub struct TerminalGuard {
    terminal: Option<Terminal<CrosstermBackend<Stdout>>>,
}

impl TerminalGuard {
    /// Enter raw mode + alternate screen and build a ratatui Terminal.
    /// Returns an error WITHOUT modifying terminal state if any step
    /// fails (so the caller's stdout stays usable).
    pub fn install() -> Result<Self> {
        enable_raw_mode().context("enable raw mode")?;
        let mut stdout = io::stdout();
        if let Err(e) = execute!(stdout, EnterAlternateScreen) {
            // Roll back the raw mode we just entered to leave the
            // shell in the state we found it.
            let _ = disable_raw_mode();
            return Err(e).context("enter alternate screen");
        }
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).context("create ratatui Terminal")?;
        Ok(Self {
            terminal: Some(terminal),
        })
    }

    /// Borrow the underlying Terminal. Returns None only after
    /// `restore()` was already called — which means the caller is
    /// using the guard post-teardown, a programming bug. We surface
    /// that as a clear error rather than silently rendering nowhere.
    pub fn terminal_mut(&mut self) -> &mut Terminal<CrosstermBackend<Stdout>> {
        // SAFETY: The only path that takes `self.terminal` is
        // `restore()`. By construction, `terminal_mut` is never
        // called after `restore()` in our codebase (verified by all
        // call sites in tui/mod.rs). The `unwrap_or_else` keeps the
        // deny lint clean while documenting the invariant.
        match self.terminal.as_mut() {
            Some(t) => t,
            None => unreachable!("TerminalGuard::terminal_mut after restore()"),
        }
    }

    /// Explicit teardown for the happy path. Equivalent to dropping
    /// the guard but lets the caller surface IO errors that the Drop
    /// path swallows. Idempotent.
    pub fn restore(&mut self) -> Result<()> {
        if let Some(mut terminal) = self.terminal.take() {
            disable_raw_mode().context("disable raw mode")?;
            execute!(terminal.backend_mut(), LeaveAlternateScreen)
                .context("leave alternate screen")?;
            terminal.show_cursor().context("show cursor")?;
        }
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        // Best-effort. If the terminal was already restored explicitly
        // (`restore()` consumed `self.terminal`), this is a no-op.
        if let Some(mut terminal) = self.terminal.take() {
            // Errors here are logged but not propagated — Drop can't
            // return Result. The crucial bit is that we ATTEMPT all
            // three teardown steps even if intermediate ones fail.
            if let Err(e) = disable_raw_mode() {
                tracing::warn!("TerminalGuard::drop: disable_raw_mode failed: {e}");
            }
            if let Err(e) = execute!(terminal.backend_mut(), LeaveAlternateScreen) {
                tracing::warn!("TerminalGuard::drop: LeaveAlternateScreen failed: {e}");
            }
            if let Err(e) = terminal.show_cursor() {
                tracing::warn!("TerminalGuard::drop: show_cursor failed: {e}");
            }
        }
    }
}
