#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #366: long-running commands stop on SIGTERM / SIGINT whenever it arrives,
//! not only while they happen to be waiting on the signal future. Each test
//! runs the real binary against a mock PVE, sends the signal at a moment the
//! old code did not listen (during a tick's sleep, with an SSE client
//! connected, under the daemon supervisor), and requires a clean exit within
//! a few seconds.

use std::io::{BufRead as _, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

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

/// One rule, so `alerts watch` has something to watch. The mock has no
/// nodes, so it never fires and nothing is sent.
const ONE_RULE: &str =
    "\n[[profiles.lab.alerts]]\nname = \"node_down\"\ntrigger = \"node_offline\"\n\
                        for_secs = 60\nroute = [\"ntfy:proxxx-366-test\"]\n";

fn spawn(dir: &std::path::Path, cfg: &std::path::Path, args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .args(args)
        .env("PROXXX_CONFIG", cfg)
        .env("PROXXX_AUDIT_DIR", dir.join("audit"))
        .env("PROXXX_SCHEDULES_PATH", dir.join("schedules.toml"))
        .env("RUST_LOG", "proxxx=info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Read stderr on a thread; resolve once a line contains `needle`.
fn wait_for_line(child: &mut Child, needle: &'static str) -> std::sync::mpsc::Receiver<()> {
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut sent = false;
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            if !sent && line.contains(needle) {
                let _ = tx.send(());
                sent = true;
            }
        }
    });
    rx
}

fn signal(child: &Child, sig: i32) {
    let pid = i32::try_from(child.id()).unwrap();
    // SAFETY: kill(2) on a child we spawned and still own.
    let rc = unsafe { libc::kill(pid, sig) };
    assert_eq!(rc, 0, "kill failed");
}

/// Wait for exit up to `EXIT_DEADLINE`; on timeout kill the child and fail.
fn exit_code_within_deadline(child: &mut Child, what: &str) -> i32 {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status.code().unwrap_or(-1);
        }
        if start.elapsed() > EXIT_DEADLINE {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{what}: still running {EXIT_DEADLINE:?} after the signal");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// `alerts watch` sleeps between ticks; a SIGTERM during that sleep used to
/// be swallowed (the signal listener only existed while the snapshot was
/// in flight).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alerts_watch_stops_on_sigterm_during_the_tick_sleep() {
    let server = mock_pve().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri(), ONE_RULE);
    let mut child = spawn(dir.path(), &cfg, &["alerts", "watch", "--interval", "60"]);
    let ready = wait_for_line(&mut child, "alert daemon starting");
    ready
        .recv_timeout(Duration::from_secs(20))
        .expect("alerts watch did not start");
    // Let the first tick finish so the loop is in its 60 s sleep.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    signal(&child, libc::SIGTERM);
    let code = exit_code_within_deadline(&mut child, "alerts watch");
    assert_eq!(code, 0, "a SIGTERM stop is a clean exit");
}

/// Same, for Ctrl-C (SIGINT) from an interactive terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn alerts_watch_stops_on_sigint_during_the_tick_sleep() {
    let server = mock_pve().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri(), ONE_RULE);
    let mut child = spawn(dir.path(), &cfg, &["alerts", "watch", "--interval", "60"]);
    let ready = wait_for_line(&mut child, "alert daemon starting");
    ready
        .recv_timeout(Duration::from_secs(20))
        .expect("alerts watch did not start");
    tokio::time::sleep(Duration::from_millis(1500)).await;
    signal(&child, libc::SIGINT);
    let code = exit_code_within_deadline(&mut child, "alerts watch");
    assert_eq!(code, 0, "a SIGINT stop is a clean exit");
}

/// `daemon serve`: a component that stops because of the shutdown signal is
/// not a component failure. The old supervisor raced its own signal arm
/// against the component's exit report and could exit 1 on a clean stop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_serve_exits_zero_on_sigterm() {
    let server = mock_pve().await;
    for round in 0..5 {
        let dir = tempfile::tempdir().unwrap();
        let cfg = write_config(dir.path(), &server.uri(), "");
        let mut child = spawn(
            dir.path(),
            &cfg,
            &[
                "daemon",
                "serve",
                "--no-alerts",
                "--no-hitl",
                "--no-reconcile",
                "--schedule-interval-secs",
                "5",
            ],
        );
        let ready = wait_for_line(&mut child, "proxxx daemon");
        ready
            .recv_timeout(Duration::from_secs(20))
            .expect("daemon did not start");
        tokio::time::sleep(Duration::from_millis(500)).await;
        signal(&child, libc::SIGTERM);
        let code = exit_code_within_deadline(&mut child, "daemon serve");
        assert_eq!(code, 0, "round {round}: a SIGTERM stop is a clean exit");
    }
}

/// `mcp serve-http`: an open SSE stream (`GET /mcp`) used to keep graceful
/// shutdown waiting forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mcp_serve_http_stops_on_sigterm_with_an_sse_client_connected() {
    let server = mock_pve().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri(), "");
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let port_s = port.to_string();
    let mut child = spawn(
        dir.path(),
        &cfg,
        &[
            "mcp",
            "serve-http",
            "--port",
            &port_s,
            "--token",
            "test-token-366",
        ],
    );
    let ready = wait_for_line(&mut child, "MCP HTTP server listening");
    ready
        .recv_timeout(Duration::from_secs(20))
        .expect("serve-http did not start");

    // Open an SSE stream and keep it open.
    let http = reqwest::Client::new();
    let resp = http
        .get(format!("http://127.0.0.1:{port}/mcp"))
        .header("Host", format!("127.0.0.1:{port}"))
        .header("Authorization", "Bearer test-token-366")
        .header("Accept", "text/event-stream")
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "SSE status {}", resp.status());
    let body = tokio::spawn(async move {
        let mut resp = resp;
        while let Ok(Some(_)) = resp.chunk().await {}
    });

    tokio::time::sleep(Duration::from_millis(300)).await;
    signal(&child, libc::SIGTERM);
    let code = exit_code_within_deadline(&mut child, "mcp serve-http");
    assert_eq!(code, 0, "a SIGTERM stop is a clean exit");
    body.abort();
}
