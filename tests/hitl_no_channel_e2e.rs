#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #360: when a policy requires approval and no `[telegram]` is configured,
//! no approval request can exist. The batch used to report `pending_hitl`
//! with a made-up id and exit 3 (the configuration-error code); it now
//! reports the operation as not run and exits 2, sending nothing to PVE.

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn approval_required_without_a_channel_is_an_error_not_pending() {
    let s = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": [{"node": "pve1", "status": "online"}]})),
        )
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/qemu"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": [{"vmid": 100, "name": "vm", "status": "stopped"}]})),
        )
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/lxc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&s)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "url = \"{}\"\nuser = \"root@pam\"\ntoken_id = \"x\"\n\
             token_secret = \"00000000-0000-0000-0000-000000000000\"\nverify_tls = false\n\n\
             [[policies]]\naction = \"start\"\ntarget = \"*\"\nrequire = 1\nchannel = \"telegram\"\n",
            s.uri()
        ),
    )
    .unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .args(["--format", "json", "start", "100"])
        .env("PROXXX_CONFIG", &cfg)
        .env("PROXXX_AUDIT_DIR", dir.path().join("audit"))
        .env("PROXXX_CACHE_DIR", dir.path().join("cache"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let rows: Vec<Value> = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{e}: {stdout}\n{}", String::from_utf8_lossy(&out.stderr)));
    assert_eq!(rows[0]["status"], "error", "{rows:?}");
    assert!(
        rows[0]["message"]
            .as_str()
            .unwrap()
            .contains("no [telegram]"),
        "{rows:?}"
    );
    assert_eq!(out.status.code(), Some(2));
    let posts = s
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() != "GET")
        .count();
    assert_eq!(posts, 0, "the operation must not run");
}
