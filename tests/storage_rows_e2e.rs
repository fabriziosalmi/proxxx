#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #352: storage rows carry their node, `describe` uses PVE's `shared`
//! flag, and an offline node's missing pools are mentioned.

use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn cluster() -> MockServer {
    let s = MockServer::start().await;
    let get = |p: String, body: Value| {
        Mock::given(method("GET"))
            .and(path(format!("/api2/json{p}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": body })))
    };
    get(
        "/nodes".into(),
        json!([
            {"node": "pve1", "status": "online"}, {"node": "pve2", "status": "online"},
            {"node": "pve3", "status": "offline"}
        ]),
    )
    .mount(&s)
    .await;
    // local-lvm: 26 % used on pve1, 0 % on pve2; nfs is shared.
    for (n, used) in [("pve1", 26_u64), ("pve2", 0)] {
        get(format!("/nodes/{n}/storage"), json!([
            {"storage": "local-lvm", "type": "lvmthin", "used": used, "total": 100, "avail": 100 - used, "active": 1, "shared": 0},
            {"storage": "nfs", "type": "nfs", "used": 25, "total": 100, "avail": 75, "active": 1, "shared": 1}
        ])).mount(&s).await;
    }
    // describe reads more than storage; answer the rest with empty lists.
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&s)
        .await;
    s
}

fn run(s: &MockServer, args: &[&str]) -> std::process::Output {
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
    std::process::Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .args(args)
        .env("PROXXX_CONFIG", &cfg)
        .env("PROXXX_AUDIT_DIR", dir.path().join("audit"))
        .output()
        .unwrap()
}

#[tokio::test]
async fn ls_storage_rows_name_their_node_and_the_skipped_node() {
    let s = cluster().await;
    let out = run(&s, &["--format", "json", "ls", "storage"]);
    let rows: Vec<Value> = serde_json::from_slice(&out.stdout).unwrap();
    let pairs: Vec<(String, String)> = rows
        .iter()
        .map(|r| {
            (
                r["node"].as_str().unwrap().into(),
                r["storage"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert!(
        pairs.contains(&("pve1".into(), "local-lvm".into())),
        "{pairs:?}"
    );
    assert!(
        pairs.contains(&("pve2".into(), "local-lvm".into())),
        "{pairs:?}"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("not online: pve3"), "{err}");
}

#[tokio::test]
async fn describe_uses_the_shared_flag_and_sums_node_local_storage() {
    let s = cluster().await;
    let out = run(&s, &["describe"]);
    let text = String::from_utf8_lossy(&out.stdout);
    let line = |id: &str| {
        text.lines()
            .find(|l| l.trim_start().starts_with(id))
            .unwrap_or_else(|| panic!("no {id} line in:\n{text}"))
            .to_string()
    };
    let lvm = line("local-lvm");
    assert!(lvm.contains("13.0%") && !lvm.contains("shared"), "{lvm}");
    let nfs = line("nfs");
    assert!(nfs.contains("25.0%") && nfs.contains("shared"), "{nfs}");
}
