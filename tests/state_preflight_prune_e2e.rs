#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #369: the `state apply` pre-flight gate assesses what the run would send.
//!
//! Live has a non-empty pool the declared file does not list; deleting it is
//! Severe. Without `--prune` apply skips the delete, so the gate must not
//! refuse (it used to exit 6, pushing operators to `--allow-risk`). With
//! `--prune --dry-run` the rehearsal must refuse like the real run (it used
//! to skip the gate and exit 0).

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A mock PVE with one pool, `prod`, holding VM 100. Every other family is
/// empty.
async fn mock_pve() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "version": "9.1.1", "release": "9.1", "repoid": "deadbeef" }
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api2/json/cluster/firewall/options"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": {} })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api2/json/pools"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "data": [{ "poolid": "prod" }] })),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api2/json/pools/prod"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "poolid": "prod", "comment": "", "members": [
                { "id": "qemu/100", "type": "qemu", "vmid": 100, "node": "pve1" }
            ] }
        })))
        .mount(&server)
        .await;
    for endpoint in [
        "/api2/json/access/acl",
        "/api2/json/storage",
        "/api2/json/cluster/backup",
        "/api2/json/cluster/firewall/aliases",
        "/api2/json/cluster/firewall/ipset",
        "/api2/json/cluster/firewall/groups",
        "/api2/json/cluster/notifications/matchers",
        "/api2/json/cluster/ha/resources",
        "/api2/json/cluster/ha/rules",
        "/api2/json/cluster/mapping/pci",
        "/api2/json/cluster/mapping/usb",
    ] {
        Mock::given(method("GET"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": [] })))
            .mount(&server)
            .await;
    }
    server
}

fn setup(dir: &Path, url: &str) -> (PathBuf, PathBuf) {
    let cfg = dir.join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "default = \"lab\"\n\n[profiles.lab]\nurl = \"{url}\"\nuser = \"root@pam\"\n\
             token_id = \"proxxx\"\n\
             token_secret = \"00000000-0000-0000-0000-000000000000\"\n\
             verify_tls = false\n"
        ),
    )
    .unwrap();
    // Declares no pools: the live `prod` pool diffs to a Severe delete.
    let declared = dir.join("state.toml");
    std::fs::write(&declared, "pools = []\n").unwrap();
    (cfg, declared)
}

fn apply(dir: &Path, cfg: &Path, declared: &Path, flags: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .args(["state", "apply", declared.to_str().unwrap()])
        .args(flags)
        .env("PROXXX_CONFIG", cfg)
        .env("PROXXX_AUDIT_DIR", dir.join("audit"))
        .output()
        .unwrap()
}

fn text(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

async fn writes(server: &MockServer) -> Vec<String> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() != "GET")
        .map(|r| format!("{} {}", r.method, r.url.path()))
        .collect()
}

/// Without `--prune` the delete is skipped, so it neither refuses the run
/// nor needs `--allow-risk`.
#[tokio::test]
async fn without_prune_a_severe_delete_does_not_refuse_the_run() {
    let server = mock_pve().await;
    let dir = tempfile::tempdir().unwrap();
    let (cfg, declared) = setup(dir.path(), &server.uri());

    let out = apply(dir.path(), &cfg, &declared, &[]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("prod"), "{}", text(&out));
    assert!(writes(&server).await.is_empty(), "no write without --prune");
}

/// With `--prune --dry-run` the rehearsal refuses like the real run.
#[tokio::test]
async fn a_dry_run_with_prune_refuses_like_the_real_run() {
    let server = mock_pve().await;
    let dir = tempfile::tempdir().unwrap();
    let (cfg, declared) = setup(dir.path(), &server.uri());

    let real = apply(dir.path(), &cfg, &declared, &["--prune"]);
    assert_eq!(real.status.code(), Some(6), "{}", text(&real));
    let dry = apply(dir.path(), &cfg, &declared, &["--prune", "--dry-run"]);
    assert_eq!(dry.status.code(), Some(6), "{}", text(&dry));
    let dry_forced = apply(
        dir.path(),
        &cfg,
        &declared,
        &["--prune", "--dry-run", "--allow-risk"],
    );
    assert_eq!(dry_forced.status.code(), Some(0), "{}", text(&dry_forced));
    assert!(writes(&server).await.is_empty(), "nothing is written");
}
