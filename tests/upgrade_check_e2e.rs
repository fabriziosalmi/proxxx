#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #355: `upgrade-check` checks the version of every node and does not
//! pass when it could not check. It read `/version` once, which answers
//! for the API node only, so a cluster with that node on 9.x and another
//! on 8.x passed `--target 9`; a target with no rules passed as well.

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn get(server: &MockServer, p: &str, status: u16, body: Value) {
    Mock::given(method("GET"))
        .and(path(format!("/api2/json{p}")))
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(server)
        .await;
}

fn version(v: &str) -> Value {
    json!({"data": {"version": v, "release": "x", "repoid": "x"}})
}

/// The API node (`/version`) is on 9.1; pve2 is still on 8.4; pve3 cannot
/// be reached when `with_down_node`.
async fn cluster(with_down_node: bool) -> MockServer {
    let s = MockServer::start().await;
    let mut nodes = vec![
        json!({"node": "pve1", "status": "online"}),
        json!({"node": "pve2", "status": "online"}),
    ];
    if with_down_node {
        nodes.push(json!({"node": "pve3", "status": "offline"}));
        get(
            &s,
            "/nodes/pve3/version",
            595,
            json!({"data": null, "message": "no route to host"}),
        )
        .await;
    }
    get(&s, "/nodes", 200, json!({"data": nodes})).await;
    get(&s, "/version", 200, version("9.1.1")).await;
    get(&s, "/nodes/pve1/version", 200, version("9.1.1")).await;
    get(&s, "/nodes/pve2/version", 200, version("8.4.1")).await;
    s
}

fn run(server: &MockServer, target: &str) -> (Option<i32>, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "url = \"{}\"\nuser = \"root@pam\"\ntoken_id = \"x\"\n\
             token_secret = \"00000000-0000-0000-0000-000000000000\"\nverify_tls = true\n",
            server.uri()
        ),
    )
    .unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .args(["upgrade-check", "--target", target, "--output", "json"])
        .env("PROXXX_CONFIG", &cfg)
        .env("PROXXX_AUDIT_DIR", dir.path().join("audit"))
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[tokio::test]
async fn a_node_behind_the_api_node_blocks() {
    let server = cluster(false).await;
    let (code, stdout, _) = run(&server, "9");
    let v: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(code, Some(1), "{v}");
    assert_eq!(v["result"], "block");
    let blocked: Vec<&str> = v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["severity"] == "block")
        .map(|f| f["node"].as_str().unwrap())
        .collect();
    assert_eq!(blocked, ["pve2"], "{v}");
}

#[tokio::test]
async fn a_node_that_cannot_be_read_makes_the_result_indeterminate() {
    let server = cluster(true).await;
    let (code, stdout, _) = run(&server, "9");
    let v: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(code, Some(1));
    assert_eq!(v["indeterminate"][0]["node"], "pve3", "{v}");
}

#[tokio::test]
async fn a_target_without_rules_is_a_usage_error() {
    let server = cluster(false).await;
    for t in ["banana", "10"] {
        let (code, stdout, stderr) = run(&server, t);
        assert_eq!(code, Some(2), "{t}: {stderr}");
        assert!(stdout.is_empty(), "{t}");
        assert!(stderr.contains("supported targets: 9"), "{t}: {stderr}");
    }
}
