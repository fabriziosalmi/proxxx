#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! BLOCKER 3 verification: integration smoke test for the flight-recorder
//! panic hook. Spawns `proxxx dev-panic` and asserts:
//!
//! 1. The process exits non-zero (panic propagated, not swallowed).
//! 2. stderr contains the flight-recorder signature line.
//! 3. stderr contains the panic location/payload (verifies hook ran
//!    BEFORE the default trace, not just alongside it).
//!
//! We can't directly observe the terminal-restoration steps in a unit
//! test (no real TTY), but the same hook code path that panics here
//! also runs the `disable_raw_mode` + `LeaveAlternateScreen` sequence in a
//! real TTY. The unit tests in `util::panic_hook` cover the install
//! idempotency + payload extraction.

#[cfg(test)]
mod tests {
    use std::process::Command;

    fn cargo_bin() -> std::path::PathBuf {
        // CARGO_BIN_EXE_proxxx is set by Cargo when integration tests run.
        std::path::PathBuf::from(env!("CARGO_BIN_EXE_proxxx"))
    }

    #[test]
    fn dev_panic_triggers_flight_recorder_hook() {
        let out = Command::new(cargo_bin())
            .args(["dev-panic", "--message", "smoke-payload-xyz"])
            .output()
            .expect("spawn proxxx");

        assert!(
            !out.status.success(),
            "panic must propagate as non-zero exit, got: {:?}",
            out.status
        );

        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("proxxx panicked at"),
            "flight-recorder signature missing from stderr:\n{stderr}"
        );
        assert!(
            stderr.contains("smoke-payload-xyz"),
            "panic payload missing from stderr:\n{stderr}"
        );
        assert!(
            stderr.contains("audit log:"),
            "audit log pointer missing from stderr:\n{stderr}"
        );
    }
}
