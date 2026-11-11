#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `describe` text output: guests by vmid, and no colour codes when stdout
//! is not a terminal (a pipe, a file, a CI log).

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn cluster() -> MockServer {
    let s = MockServer::start().await;
    let get = |p: &str, body: Value| {
        Mock::given(method("GET"))
            .and(path(format!("/api2/json{p}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": body })))
    };
    get("/nodes", json!([{"node": "pve1", "status": "online"}]))
        .mount(&s)
        .await;
    // PVE answers per node, VMs then containers, in its own order.
    get(
        "/nodes/pve1/qemu",
        json!([
            {"vmid": 8004, "name": "vm-b", "status": "stopped"},
            {"vmid": 103, "name": "vm-a", "status": "running"}
        ]),
    )
    .mount(&s)
    .await;
    get(
        "/nodes/pve1/lxc",
        json!([
            {"vmid": 200, "name": "ct-b", "status": "stopped"},
            {"vmid": 101, "name": "ct-a", "status": "running"}
        ]),
    )
    .mount(&s)
    .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&s)
        .await;
    s
}

fn run(s: &MockServer, args: &[&str], extra_env: &[(&str, &str)]) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "url = \"{}\"\nuser = \"root@pam\"\ntoken_id = \"x\"\n\
             token_secret = \"00000000-0000-0000-0000-000000000000\"\nverify_tls = false\n",
            s.uri()
        ),
    )
    .unwrap();
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_proxxx"));
    cmd.args(args)
        .env("PROXXX_CONFIG", &cfg)
        .env("PROXXX_AUDIT_DIR", dir.path().join("audit"))
        .env_remove("NO_COLOR");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

#[tokio::test]
async fn describe_lists_guests_by_vmid() {
    let s = cluster().await;
    let out = run(&s, &["describe"], &[]);
    let text = String::from_utf8_lossy(&out.stdout);
    let order: Vec<&str> = text
        .lines()
        .skip_while(|l| !l.starts_with("## Guests"))
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| l.split_whitespace().next())
        .collect();
    assert_eq!(order, ["101", "103", "200", "8004"], "{text}");
}

/// stdout here is a pipe: no escape sequence may reach it, even with a
/// colour-capable `TERM`.
#[tokio::test]
async fn describe_on_a_pipe_has_no_colour_codes() {
    let s = cluster().await;
    let out = run(&s, &["describe"], &[("TERM", "xterm-256color")]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("running"), "{text}");
    assert!(!text.contains('\u{1b}'), "{text:?}");
}

/// `ls` prints the generic TSV table; on a pipe its STATUS column stays
/// plain text, so a script reading it gets the word, not escape codes.
#[tokio::test]
async fn ls_table_on_a_pipe_has_no_colour_codes() {
    let s = cluster().await;
    let out = run(&s, &["ls", "guests"], &[("TERM", "xterm-256color")]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("\trunning\t") || text.contains("\trunning\n"),
        "{text:?}"
    );
    assert!(!text.contains('\u{1b}'), "{text:?}");
}
