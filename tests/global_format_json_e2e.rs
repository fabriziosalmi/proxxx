#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #362: the global `--format json` gives JSON for the commands that have
//! their own output flag. It used to be ignored: they printed text with
//! exit 0, so `| jq` failed. An explicit local flag still wins.

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn cluster() -> MockServer {
    let s = MockServer::start().await;
    let get = |p: &'static str, body: serde_json::Value| {
        Mock::given(method("GET"))
            .and(path(format!("/api2/json{p}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": body })))
    };
    get(
        "/nodes",
        json!([{"node": "pve1", "status": "online", "cpu": 0.1, "mem": 1, "maxmem": 2}]),
    )
    .mount(&s)
    .await;
    get(
        "/version",
        json!({"version": "9.1.1", "release": "9.1", "repoid": "x"}),
    )
    .mount(&s)
    .await;
    get(
        "/nodes/pve1/version",
        json!({"version": "9.1.1", "release": "9.1", "repoid": "x"}),
    )
    .mount(&s)
    .await;
    get(
        "/nodes/pve1/time",
        json!({"time": 1, "localtime": 1, "timezone": "UTC"}),
    )
    .mount(&s)
    .await;
    get("/cluster/firewall/options", json!({})).mount(&s).await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&s)
        .await;
    s
}

#[tokio::test]
async fn global_format_json_gives_json_for_commands_with_their_own_output_flag() {
    let s = cluster().await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "url = \"{}\"\nuser = \"root@pam\"\ntoken_id = \"x\"\n\
             token_secret = \"00000000-0000-0000-0000-000000000000\"\nverify_tls = true\n",
            s.uri()
        ),
    )
    .unwrap();
    let state = dir.path().join("state.toml");
    std::fs::write(&state, "pools = []\n").unwrap();
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_proxxx"))
            .args(args)
            .env("PROXXX_CONFIG", &cfg)
            .env("PROXXX_AUDIT_DIR", dir.path().join("audit"))
            .env("PROXXX_SCHEDULES_PATH", dir.path().join("schedules.toml"))
            .output()
            .unwrap()
    };
    let state_s = state.to_str().unwrap();
    for args in [
        vec!["explain", "unauthorized"],
        vec!["explain"],
        vec!["describe"],
        vec!["cloud-img", "list"],
        vec!["schedule", "list"],
        vec!["backup-verify"],
        vec!["heatmap"],
        vec!["anomaly"],
        vec!["upgrade-check", "--target", "9"],
        vec!["accounting", "--group-by", "node"],
        vec!["state", "diff", state_s],
        vec!["state", "export", "--resource", "pools"],
        vec!["mcp", "tools"],
    ] {
        let mut full = vec!["--format", "json"];
        full.extend(&args);
        let out = run(&full);
        let text = String::from_utf8_lossy(&out.stdout);
        serde_json::from_str::<serde_json::Value>(&text).unwrap_or_else(|e| {
            panic!(
                "{args:?}: stdout is not JSON ({e}):\n{text}\nstderr: {}",
                String::from_utf8_lossy(&out.stderr)
            )
        });
    }
    // An explicit local flag wins over the global one.
    let out = run(&["--format", "json", "cloud-img", "list", "--output", "text"]);
    assert!(serde_json::from_slice::<serde_json::Value>(&out.stdout).is_err());
}
