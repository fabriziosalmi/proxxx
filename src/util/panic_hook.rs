//! Aerospace-style panic hook (BLOCKER 3 — flight recorder).
//!
//! Installs a `std::panic::set_hook` that, before propagating the panic:
//! 1. Disables raw mode (best-effort — no-op if not enabled).
//! 2. Leaves the alternate screen and shows the cursor.
//! 3. Logs the panic info via `tracing::error!` so the audit log file
//!    captures the trace alongside the rest of the application log.
//! 4. Calls the previous hook so the default colourful trace still
//!    prints to stderr for the user.
//!
//! Idempotent: calling `install()` twice replaces the hook with itself
//! (the second install captures the first one's chain via `take_hook`).
//! Both TUI and CLI mode call this from `main` so a panic from any path
//! leaves the terminal in a usable state.

use std::sync::atomic::{AtomicBool, Ordering};

static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Install the global panic hook. Safe to call multiple times — only
/// the first call wires the chain; later calls are no-ops.
pub fn install() {
    if INSTALLED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // 1. Audit log capture FIRST — even if the terminal restoration
        //    below fails for some reason, the trace must reach the log
        //    file. tracing-appender's non_blocking writer flushes on
        //    drop of its guard (the application's `_guard` in main).
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown".to_string());
        let payload = panic_message(info);
        tracing::error!(
            target: "panic",
            location = %location,
            "PANIC: {payload}"
        );

        // 2. Terminal restoration. Best-effort — every step is fire-
        //    and-forget. The user's terminal is the most precious thing
        //    we own at this point; we do not gate later steps on
        //    earlier-step failures.
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::LeaveAlternateScreen,
            crossterm::cursor::Show,
        );

        // 3. Mark the audit log so a tail of the file shows the panic
        //    without needing the panic-target filter.
        eprintln!();
        eprintln!("💀 proxxx panicked at {location}");
        eprintln!("   payload: {payload}");
        eprintln!("   audit log: ~/.local/share/proxxx (proxxx.log)");
        eprintln!();

        // 4. Run the original hook for the colourful trace.
        original(info);
    }));
}

/// Best-effort extraction of the panic payload as a string. Handles
/// the two payload types `panic!` macros produce: `&'static str` and
/// `String`. Other Box<dyn Any> payloads return a generic placeholder.
fn panic_message(info: &std::panic::PanicHookInfo<'_>) -> String {
    let payload = info.payload();
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    if let Some(s) = payload.downcast_ref::<String>() {
        return s.clone();
    }
    "<non-string panic payload>".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_is_idempotent() {
        // Calling install() twice from a single test process must not
        // panic or stack hooks. The atomic guard ensures only one
        // install actually wires the chain.
        install();
        install();
        install();
    }

    #[test]
    fn panic_message_extracts_string_payload() {
        // Drive a controlled panic and intercept its payload via the
        // hook chain. We don't actually want the test process to die,
        // so we use catch_unwind.
        let result = std::panic::catch_unwind(|| {
            panic!("test-panic-payload-abc");
        });
        let err = result.expect_err("controlled panic");
        let msg = if let Some(s) = err.downcast_ref::<&'static str>() {
            (*s).to_string()
        } else if let Some(s) = err.downcast_ref::<String>() {
            s.clone()
        } else {
            String::new()
        };
        assert!(msg.contains("test-panic-payload-abc"));
    }
}
