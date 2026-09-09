//! #270 — where log records actually go, asserted by running the binary.
//!
//! The defect this guards against is structural and easy to reintroduce:
//! the subscriber was wired to a rotating file appender and nothing else,
//! so a daemon under the recommended systemd unit produced a journald
//! stream with its start and stop lines and nothing in between. Every
//! diagnostic that mattered — the write kill-switch disengaging, TLS
//! pinning silently off — went to a file the operator had not been told
//! about.
//!
//! These run the real binary rather than inspecting source, because what
//! matters is the observable stream, not how it is constructed.

#![allow(clippy::expect_used)]

use std::process::Command;

fn run(args: &[&str], rust_log: Option<&str>) -> (String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_proxxx"));
    cmd.args(args);
    match rust_log {
        Some(v) => {
            cmd.env("RUST_LOG", v);
        }
        None => {
            cmd.env_remove("RUST_LOG");
        }
    }
    // Point the config somewhere empty so the run fails fast and
    // deterministically instead of touching a developer's real cluster.
    cmd.env("PROXXX_CONFIG", "/nonexistent/proxxx-logging-test.toml");
    let out = cmd.output().expect("binary runs");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// A CLI invocation must put its log records on stderr, where journald
/// and a log shipper can see them.
#[test]
fn cli_mode_logs_to_stderr() {
    let (_out, err) = run(&["ls", "nodes"], None);
    assert!(
        err.contains("proxxx v") && err.contains("starting"),
        "the startup record must reach stderr, got: {err:?}"
    );
}

/// …and must not put them on stdout, which carries `--format json` and
/// `state export` output that pipelines parse.
#[test]
fn log_records_never_contaminate_stdout() {
    let (out, _err) = run(&["--format", "json", "ls", "nodes"], None);
    assert!(
        !out.contains("INFO") && !out.contains("proxxx v"),
        "stdout must stay machine-readable, got: {out:?}"
    );
}

/// `RUST_LOG` must be honoured. It was previously ignored in favour of a
/// compile-time literal, so an operator who set it believed they had
/// changed something and had not.
#[test]
fn rust_log_controls_the_level() {
    let (_out, default_err) = run(&["ls", "nodes"], None);
    assert!(
        default_err.contains("INFO"),
        "the default filter must emit info records, got: {default_err:?}"
    );

    let (_out, quiet_err) = run(&["ls", "nodes"], Some("error"));
    assert!(
        !quiet_err.contains("INFO"),
        "RUST_LOG=error must suppress info records, got: {quiet_err:?}"
    );
}

/// The operator is told where the file copy lives, so the rotating log
/// is discoverable rather than a path they have to know already.
#[test]
fn startup_names_the_log_file_location() {
    let (_out, err) = run(&["ls", "nodes"], None);
    assert!(
        err.contains("log file:"),
        "startup must name the log file path, got: {err:?}"
    );
}
