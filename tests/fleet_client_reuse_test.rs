#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #379: the fleet view keeps one client per profile across poll cycles.
//! It built a new one each 10 s cycle, so a password profile logged in
//! again every cycle, and `/nodes` was read three times per cycle.
//!
//! Own test binary: it sets `PROXXX_CONFIG` for the process.

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn requests_to(s: &MockServer, m: &str, p: &str) -> usize {
    s.received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == m && r.url.path() == p)
        .count()
}

#[tokio::test]
async fn one_login_per_session_and_one_nodes_read_per_cycle() {
    let s = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api2/json/access/ticket"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"ticket": "PVE:root@pam:X", "CSRFPreventionToken": "c", "username": "root@pam"}
        })))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": [{"node": "pve1", "status": "online"}]})),
        )
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
            "[profiles.lab]\nurl = \"{}\"\nuser = \"root@pam\"\nauth = \"password\"\n\
             password = \"x\"\nverify_tls = false\n",
            s.uri()
        ),
    )
    .unwrap();
    std::env::set_var("PROXXX_CONFIG", &cfg);

    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    let mut clients = proxxx::tui::fleet::FleetClients::default();
    for _ in 0..3 {
        proxxx::tui::fleet::fleet_fetch_all(None, &tx, &mut clients).await;
        match rx.recv().await.unwrap() {
            proxxx::tui::fleet::FleetDataMsg::ClusterSnapshot { profile, .. } => {
                assert_eq!(profile, "lab");
            }
            other => panic!("expected a snapshot, got {other:?}"),
        }
    }
    assert_eq!(
        requests_to(&s, "POST", "/api2/json/access/ticket").await,
        1,
        "one login for three cycles"
    );
    assert_eq!(
        requests_to(&s, "GET", "/api2/json/nodes").await,
        3,
        "one /nodes read per cycle"
    );
    assert_eq!(clients.len(), 1);

    // A failing cycle drops the client; the next cycle builds a new one.
    s.reset().await;
    proxxx::tui::fleet::fleet_fetch_all(None, &tx, &mut clients).await;
    assert!(matches!(
        rx.recv().await.unwrap(),
        proxxx::tui::fleet::FleetDataMsg::ClusterError { .. }
    ));
    assert!(clients.is_empty(), "a failed cycle drops the cached client");
    Mock::given(method("POST"))
        .and(path("/api2/json/access/ticket"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"ticket": "PVE:root@pam:Y", "CSRFPreventionToken": "c", "username": "root@pam"}
        })))
        .mount(&s)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&s)
        .await;
    proxxx::tui::fleet::fleet_fetch_all(None, &tx, &mut clients).await;
    assert!(matches!(
        rx.recv().await.unwrap(),
        proxxx::tui::fleet::FleetDataMsg::ClusterSnapshot { .. }
    ));
    assert_eq!(
        requests_to(&s, "POST", "/api2/json/access/ticket").await,
        1,
        "logged in again"
    );
    assert_eq!(clients.len(), 1);
}
