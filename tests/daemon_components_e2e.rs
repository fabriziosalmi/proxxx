#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #372: `daemon serve` starts alerts and HITL only when they are
//! configured. Each refuses to run without its section, and the supervisor
//! treats a component that exits as a fault, so a config without
//! `[[alerts]]` or `[telegram]` used to make the daemon exit 1 at startup
//! and take schedule and reconcile down with it.

use std::io::{BufRead as _, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

const STARTUP: Duration = Duration::from_secs(20);
const EXIT_DEADLINE: Duration = Duration::from_secs(8);

/// A mock PVE that answers every GET with an empty list.
async fn mock_pve() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
        .mount(&server)
        .await;
    server
}

fn write_config(dir: &std::path::Path, url: &str, extra: &str) -> std::path::PathBuf {
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        format!(
            "default = \"lab\"\n\n[profiles.lab]\nurl = \"{url}\"\nuser = \"root@pam\"\n\
             token_id = \"proxxx\"\n\
             token_secret = \"00000000-0000-0000-0000-000000000000\"\n\
             verify_tls = false\n{extra}"
        ),
    )
    .unwrap();
    path
}

/// One rule. The mock has no nodes, so it never fires and nothing is sent.
const ONE_RULE: &str =
    "\n[[profiles.lab.alerts]]\nname = \"node_down\"\ntrigger = \"node_offline\"\n\
                        for_secs = 60\nroute = [\"ntfy:proxxx-372-test\"]\n";

/// Spawn `proxxx daemon serve <args>`; every stderr line goes to the receiver.
fn spawn_daemon(
    dir: &std::path::Path,
    cfg: &std::path::Path,
    args: &[&str],
) -> (Child, Receiver<String>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .args(["daemon", "serve"])
        .args(args)
        .env("PROXXX_CONFIG", cfg)
        .env("PROXXX_AUDIT_DIR", dir.join("audit"))
        .env("PROXXX_SCHEDULES_PATH", dir.join("schedules.toml"))
        .env("RUST_LOG", "proxxx=info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    (child, rx)
}

/// Lines read until every needle has appeared in some line, in any order.
fn lines_until(rx: &Receiver<String>, needles: &[&str]) -> Vec<String> {
    let start = Instant::now();
    let mut seen: Vec<String> = Vec::new();
    while let Some(left) = STARTUP.checked_sub(start.elapsed()) {
        if needles.iter().all(|n| seen.iter().any(|l| l.contains(n))) {
            return seen;
        }
        match rx.recv_timeout(left) {
            Ok(line) => seen.push(line),
            Err(_) => break,
        }
    }
    if needles.iter().all(|n| seen.iter().any(|l| l.contains(n))) {
        return seen;
    }
    panic!(
        "not all of {needles:?} seen; stderr so far:\n{}",
        seen.join("\n")
    );
}

/// The line that contains `needle`.
fn line<'a>(seen: &'a [String], needle: &str) -> &'a str {
    seen.iter().find(|l| l.contains(needle)).unwrap()
}

/// Every remaining stderr line, until the child closes stderr.
fn drain(rx: &Receiver<String>) -> Vec<String> {
    let mut out = Vec::new();
    while let Ok(l) = rx.recv_timeout(STARTUP) {
        out.push(l);
    }
    out
}

fn exit_code_within(child: &mut Child, deadline: Duration) -> i32 {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status.code().unwrap_or(-1);
        }
        if start.elapsed() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("daemon still running {deadline:?} later");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn sigterm(child: &Child) {
    let pid = i32::try_from(child.id()).unwrap();
    // SAFETY: kill(2) on a child we spawned and still own.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGTERM) }, 0, "kill failed");
}

/// No `[[alerts]]`, no `[telegram]`, no `[reconcile]`: schedule runs, the
/// rest are named as not started, and the daemon stays up.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_optional_sections_schedule_runs_and_the_daemon_stays_up() {
    let server = mock_pve().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri(), "");
    let (mut child, rx) = spawn_daemon(dir.path(), &cfg, &["--schedule-interval-secs", "5"]);

    let seen = lines_until(
        &rx,
        &["proxxx daemon: started", "proxxx daemon: not started"],
    );
    let started = line(&seen, "proxxx daemon: started");
    assert!(
        started.contains("started 1 component(s)") && started.contains("schedule"),
        "{started}"
    );
    let not_started = line(&seen, "proxxx daemon: not started");
    for part in [
        "alerts (no [[alerts]] rules)",
        "hitl (no [telegram] section)",
        "reconcile (no [reconcile] section)",
    ] {
        assert!(
            not_started.contains(part),
            "missing {part:?} in {not_started}"
        );
    }

    // The old daemon exited 1 here, as soon as alerts and HITL returned.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        child.try_wait().unwrap().is_none(),
        "daemon exited without a signal"
    );

    sigterm(&child);
    assert_eq!(exit_code_within(&mut child, EXIT_DEADLINE), 0);
}

/// With `[[alerts]]` rules the alerts component runs next to schedule.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alerts_runs_when_rules_are_configured() {
    let server = mock_pve().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri(), ONE_RULE);
    let (mut child, rx) = spawn_daemon(dir.path(), &cfg, &["--schedule-interval-secs", "5"]);

    let seen = lines_until(
        &rx,
        &[
            "proxxx daemon: started",
            "proxxx daemon: not started",
            "alert daemon starting",
        ],
    );
    let started = line(&seen, "proxxx daemon: started");
    assert!(
        started.contains("started 2 component(s)") && started.contains("schedule + alerts"),
        "{started}"
    );
    let not_started = line(&seen, "proxxx daemon: not started");
    assert!(!not_started.contains("alerts ("), "{not_started}");

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        child.try_wait().unwrap().is_none(),
        "daemon exited without a signal"
    );

    sigterm(&child);
    assert_eq!(exit_code_within(&mut child, EXIT_DEADLINE), 0);
}

/// Nothing to run: the daemon refuses to start and says why.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_nothing_to_run_the_daemon_refuses_and_names_the_reasons() {
    let server = mock_pve().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri(), "");
    let (mut child, rx) = spawn_daemon(dir.path(), &cfg, &["--no-schedule"]);

    let code = exit_code_within(&mut child, EXIT_DEADLINE);
    let stderr = drain(&rx);
    assert_ne!(code, 0, "stderr:\n{}", stderr.join("\n"));
    let text = stderr.join("\n");
    assert!(
        text.contains("no daemon component to run")
            && text.contains("alerts (no [[alerts]] rules)")
            && text.contains("hitl (no [telegram] section)"),
        "stderr:\n{text}"
    );
}
