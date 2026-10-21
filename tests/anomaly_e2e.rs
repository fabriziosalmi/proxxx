#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #356: `anomaly` judges each node against its own RRD history. The
//! cross-node z-score it used could not exceed sqrt(n-1), so on a small
//! cluster the default threshold never fired, and an offline node joined
//! the population as cpu 0 / mem 0.

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn a_node_far_above_its_history_fires_and_an_offline_node_is_skipped() {
    let s = MockServer::start().await;
    let get = |p: &'static str, body: Value| {
        Mock::given(method("GET"))
            .and(path(format!("/api2/json{p}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": body })))
    };
    // pve1 runs at 95 % CPU now; pve2 is at its usual level; pve3 is down.
    get(
        "/nodes",
        json!([
            {"node": "pve1", "status": "online", "cpu": 0.95, "mem": 40, "maxmem": 100},
            {"node": "pve2", "status": "online", "cpu": 0.11, "mem": 40, "maxmem": 100},
            {"node": "pve3", "status": "offline"}
        ]),
    )
    .mount(&s)
    .await;
    let history: Vec<Value> = (0..60)
        .map(|i| {
            json!({"time": 1000 + i * 1200, "cpu": 0.10 + f64::from(i % 5) * 0.01,
                         "memused": 40.0 + f64::from(i % 3), "memtotal": 100.0})
        })
        .collect();
    get("/nodes/pve1/rrddata", json!(history.clone()))
        .mount(&s)
        .await;
    get("/nodes/pve2/rrddata", json!(history)).mount(&s).await;

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
        .args(["anomaly", "--output", "json"])
        .env("PROXXX_CONFIG", &cfg)
        .env("PROXXX_AUDIT_DIR", dir.path().join("audit"))
        .output()
        .unwrap();
    let v: Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stderr)));
    let flagged: Vec<(String, String)> = v["anomalies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["node"].as_str().unwrap().into(),
                a["metric"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert_eq!(flagged, [("pve1".to_string(), "cpu".to_string())], "{v}");
    assert_eq!(v["skipped"][0]["node"], "pve3", "{v}");
    assert_eq!(out.status.code(), Some(1));
}
