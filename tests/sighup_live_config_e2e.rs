#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #373: `read_only` follows a config reload in long-running processes.
//! Setting `read_only = true` and sending SIGHUP is the obvious emergency
//! brake; the client must refuse the next write without a restart.

use proxxx::api::types::GuestType;
use proxxx::api::{ProxmoxGateway, PxClient};
use proxxx::config::{watcher, ProfileConfig};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn cfg(url: &str, read_only: bool) -> ProfileConfig {
    toml::from_str(&format!(
        "url = \"{url}\"\nuser = \"root@pam\"\ntoken_id = \"t\"\nverify_tls = false\nread_only = {read_only}\n"
    ))
    .unwrap()
}

#[tokio::test]
async fn a_reloaded_read_only_stops_writes_and_a_reloaded_false_allows_them_again() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api2/json/nodes/pve1/qemu/100/status/start"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": "UPID:pve1:00000001:00000001:00000001:qmstart:100:root@pam:"
        })))
        .mount(&server)
        .await;
    let audit = tempfile::tempdir().unwrap();
    let client = PxClient::new(
        cfg(&server.uri(), false),
        Some("00000000-0000-0000-0000-000000000001"),
    )
    .await
    .unwrap()
    .with_audit_dir(audit.path());
    let handle = watcher::new_handle(cfg(&server.uri(), false));
    client.attach_live_config(std::sync::Arc::clone(&handle));

    client
        .start_guest("pve1", 100, GuestType::Qemu)
        .await
        .expect("writable");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);

    // SIGHUP with read_only = true.
    assert!(watcher::reload_once(&handle, || Ok(cfg(&server.uri(), true))).await);
    let err = client
        .start_guest("pve1", 100, GuestType::Qemu)
        .await
        .expect_err("read_only from the reload must refuse the write");
    assert!(
        err.chain().any(|c| c
            .downcast_ref::<proxxx::config::ReadOnlyRefusal>()
            .is_some()),
        "{err:#}"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "the refused write must not reach PVE"
    );

    // SIGHUP back to read_only = false.
    assert!(watcher::reload_once(&handle, || Ok(cfg(&server.uri(), false))).await);
    client
        .start_guest("pve1", 100, GuestType::Qemu)
        .await
        .expect("writable again");
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn without_a_live_config_the_startup_value_applies() {
    let client = PxClient::new(
        cfg("https://127.0.0.1:1", true),
        Some("00000000-0000-0000-0000-000000000001"),
    )
    .await
    .unwrap();
    assert!(client.effective_read_only().await);
}

/// Every long-running command that creates a reloadable config handle must
/// attach it to its client, or `read_only` would not follow the reload.
#[test]
fn every_reloadable_handle_is_attached_to_the_client() {
    let src =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cli/mod.rs")).unwrap();
    let lines: Vec<&str> = src.lines().collect();
    let mut sites = 0;
    for (i, line) in lines.iter().enumerate() {
        if line.contains("let handle = crate::config::watcher::new_handle(") {
            sites += 1;
            let next = lines.get(i + 1).copied().unwrap_or("");
            assert!(
                next.contains("client.attach_live_config(std::sync::Arc::clone(&handle))"),
                "src/cli/mod.rs:{}: handle created without attach_live_config",
                i + 1
            );
        }
    }
    assert!(
        sites >= 4,
        "expected the daemon, mcp serve, mcp serve-http and alerts sites, found {sites}"
    );
}
