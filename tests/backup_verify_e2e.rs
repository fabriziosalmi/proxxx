#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #357: `backup-verify` tells "no backup" from "could not check".
//! A backup storage that cannot be read used to be skipped, and the guests
//! whose backups live there were reported `missing` with age 0.

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

/// pve1 holds VM 100; `local` (backup-capable) is readable and empty,
/// `pbs` (backup-capable) answers 500, `local-lvm` holds no backups.
/// pve2's guest list fails.
async fn cluster(pbs_ok: bool) -> MockServer {
    let s = MockServer::start().await;
    get(
        &s,
        "/nodes",
        200,
        json!({"data": [
            {"node": "pve1", "status": "online"}, {"node": "pve2", "status": "online"}
        ]}),
    )
    .await;
    get(
        &s,
        "/nodes/pve1/qemu",
        200,
        json!({"data": [{"vmid": 100, "name": "vm", "status": "running"}]}),
    )
    .await;
    get(&s, "/nodes/pve1/lxc", 200, json!({"data": []})).await;
    get(
        &s,
        "/nodes/pve2/qemu",
        500,
        json!({"data": null, "message": "node down"}),
    )
    .await;
    get(&s, "/nodes/pve2/lxc", 200, json!({"data": []})).await;
    get(
        &s,
        "/nodes/pve1/storage",
        200,
        json!({"data": [
            {"storage": "local", "type": "dir", "content": "iso,backup"},
            {"storage": "pbs", "type": "pbs", "content": "backup"},
            {"storage": "local-lvm", "type": "lvmthin", "content": "images,rootdir"}
        ]}),
    )
    .await;
    get(
        &s,
        "/nodes/pve1/storage/local/content",
        200,
        json!({"data": []}),
    )
    .await;
    if pbs_ok {
        get(
            &s,
            "/nodes/pve1/storage/pbs/content",
            200,
            json!({"data": []}),
        )
        .await;
    } else {
        get(
            &s,
            "/nodes/pve1/storage/pbs/content",
            500,
            json!({"data": null, "message": "Can't connect to pbs:8007"}),
        )
        .await;
    }
    s
}

fn verify(server: &MockServer) -> (Option<i32>, Vec<Value>) {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "default = \"lab\"\n\n[profiles.lab]\nurl = \"{}\"\nuser = \"root@pam\"\n\
             token_id = \"x\"\ntoken_secret = \"00000000-0000-0000-0000-000000000000\"\n\
             verify_tls = false\n",
            server.uri()
        ),
    )
    .unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .args(["backup-verify", "--output", "json"])
        .env("PROXXX_CONFIG", &cfg)
        .env("PROXXX_AUDIT_DIR", dir.path().join("audit"))
        .output()
        .unwrap();
    let rows: Vec<Value> = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stderr)));
    (out.status.code(), rows)
}

#[tokio::test]
async fn an_unreadable_backup_storage_is_unknown_not_missing() {
    let server = cluster(false).await;
    let (code, rows) = verify(&server);
    assert_eq!(code, Some(1));
    let vm = rows
        .iter()
        .find(|r| r["vmid"] == 100)
        .expect("row for VM 100");
    assert_eq!(vm["status"], "unknown", "{vm}");
    assert!(vm["reason"].as_str().unwrap().contains("pbs"), "{vm}");
    assert!(
        vm.get("age_days").is_none(),
        "no age without a backup: {vm}"
    );
    // A node whose guests cannot be listed is reported, not skipped.
    let node = rows
        .iter()
        .find(|r| r["node"] == "pve2")
        .expect("row for pve2");
    assert_eq!(node["status"], "unknown", "{node}");
    assert!(node.get("vmid").is_none(), "{node}");
    // local-lvm cannot hold backups and is not read.
    let reqs = server.received_requests().await.unwrap();
    assert!(!reqs.iter().any(|r| r.url.path().contains("local-lvm")));
}

#[tokio::test]
async fn with_every_storage_readable_no_backup_is_missing() {
    let server = cluster(true).await;
    let (code, rows) = verify(&server);
    assert_eq!(code, Some(1));
    let vm = rows
        .iter()
        .find(|r| r["vmid"] == 100)
        .expect("row for VM 100");
    assert_eq!(vm["status"], "missing", "{vm}");
    assert!(vm.get("age_days").is_none(), "{vm}");
}
