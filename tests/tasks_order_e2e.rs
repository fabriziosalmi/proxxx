#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #354: `tasks --limit N` returns the N newest tasks. `/cluster/tasks`
//! comes grouped by node, and the list was truncated as received.

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn task(node: &str, start: u64) -> Value {
    json!({"upid": format!("UPID:{node}:{start}"), "node": node, "user": "root@pam",
           "id": "", "type": "qmstart", "starttime": start})
}

#[tokio::test]
async fn the_limit_keeps_the_newest_tasks_across_nodes() {
    let s = MockServer::start().await;
    // Grouped by node, as PVE sends it: all of pve2, then all of pve1.
    let data = json!([
        task("pve2", 300),
        task("pve2", 100),
        task("pve1", 400),
        task("pve1", 200)
    ]);
    Mock::given(method("GET"))
        .and(path("/api2/json/cluster/tasks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": data})))
        .mount(&s)
        .await;
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
    let run = |limit: &str| {
        std::process::Command::new(env!("CARGO_BIN_EXE_proxxx"))
            .args(["--format", "json", "tasks", "--limit", limit])
            .env("PROXXX_CONFIG", &cfg)
            .env("PROXXX_AUDIT_DIR", dir.path().join("audit"))
            .output()
            .unwrap()
    };
    let out = run("2");
    let rows: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    let starts: Vec<u64> = rows
        .iter()
        .map(|r| r["starttime"].as_u64().unwrap())
        .collect();
    assert_eq!(starts, [400, 300], "the two newest, across nodes");
    assert!(!String::from_utf8_lossy(&out.stderr).contains("fewer than"));

    // More than the server returns: all four, newest first, and a note.
    let out = run("10");
    let rows: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    let starts: Vec<u64> = rows
        .iter()
        .map(|r| r["starttime"].as_u64().unwrap())
        .collect();
    assert_eq!(starts, [400, 300, 200, 100]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("fewer than --limit 10"));
}
