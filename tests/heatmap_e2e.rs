#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #353: `heatmap` times each node, not the API node. It called
//! `/version` for every row, which the configured node answers, so a node
//! that is down showed a green latency.

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn a_down_node_is_reported_down_not_green() {
    let s = MockServer::start().await;
    let mount = |p: &'static str, status: u16, body: Value| {
        Mock::given(method("GET"))
            .and(path(format!("/api2/json{p}")))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
    };
    mount("/nodes", 200, json!({"data": [{"node": "pve1", "status": "online"}, {"node": "pve2", "status": "offline"}]})).mount(&s).await;
    mount(
        "/version",
        200,
        json!({"data": {"version": "9.1.1", "release": "9.1", "repoid": "x"}}),
    )
    .mount(&s)
    .await;
    mount(
        "/nodes/pve1/time",
        200,
        json!({"data": {"time": 1, "localtime": 1, "timezone": "UTC"}}),
    )
    .mount(&s)
    .await;
    mount(
        "/nodes/pve2/time",
        500,
        json!({"data": null, "message": "hostname lookup 'pve2' failed"}),
    )
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
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .args(["heatmap", "--output", "json"])
        .env("PROXXX_CONFIG", &cfg)
        .env("PROXXX_AUDIT_DIR", dir.path().join("audit"))
        .output()
        .unwrap();
    let rows: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    let row = |n: &str| rows.iter().find(|r| r["node"] == n).unwrap().clone();
    assert_eq!(row("pve1")["status"], "Ok");
    assert_eq!(row("pve2")["bucket"], "down", "{rows:?}");
    assert!(row("pve2")["status"].as_str().unwrap().contains("500"));
    assert_eq!(out.status.code(), Some(1));
}
