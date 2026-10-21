#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #371: a state document that declares no resource family is refused,
//! and `state export` declares every family it exported, empty or not.
//!
//! Before: `state diff` of an empty file printed "no changes" and exited 0,
//! and `state export --resource pools` on a cluster without pools wrote a
//! file with only `[meta]`, so a pool created afterwards never showed up as
//! drift.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A mock PVE for `state export` / `state diff`. `pools` is the pool list;
/// each pool has no members.
async fn mock_pve(pools: &[&str]) -> MockServer {
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
    let list: Vec<_> = pools.iter().map(|p| json!({ "poolid": p })).collect();
    Mock::given(method("GET"))
        .and(path("/api2/json/pools"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": list })))
        .mount(&server)
        .await;
    for p in pools {
        Mock::given(method("GET"))
            .and(path(format!("/api2/json/pools/{p}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    json!({ "data": { "poolid": p, "comment": "", "members": [] } }),
                ),
            )
            .mount(&server)
            .await;
    }
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

fn write_config(dir: &Path, url: &str) -> PathBuf {
    let p = dir.join("config.toml");
    std::fs::write(
        &p,
        format!(
            "default = \"lab\"\n\n[profiles.lab]\nurl = \"{url}\"\nuser = \"root@pam\"\n\
             token_id = \"proxxx\"\n\
             token_secret = \"00000000-0000-0000-0000-000000000000\"\n\
             verify_tls = false\n"
        ),
    )
    .unwrap();
    p
}

fn proxxx(dir: &Path, cfg: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .args(args)
        .env("PROXXX_CONFIG", cfg)
        .env("PROXXX_AUDIT_DIR", dir.join("audit"))
        .output()
        .unwrap()
}

/// An empty file, a comment-only file and a `[meta]`-only file are refused
/// before any request reaches PVE.
#[tokio::test]
async fn state_diff_refuses_a_document_without_a_family() {
    let server = mock_pve(&[]).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = write_config(dir.path(), &server.uri());
    for (name, body) in [
        ("empty", ""),
        ("comments", "# prod cluster\n"),
        (
            "meta-only",
            "[meta]\nschema_version = 1\nprofile = \"lab\"\nexported_at = \"2026-10-21T00:00:00Z\"\n",
        ),
    ] {
        let file = dir.path().join(format!("{name}.toml"));
        std::fs::write(&file, body).unwrap();
        let out = proxxx(dir.path(), &cfg, &["state", "diff", file.to_str().unwrap()]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_ne!(out.status.code(), Some(0), "{name}: must not pass, stderr: {stderr}");
        assert_ne!(out.status.code(), Some(2), "{name}: not a drift result: {stderr}");
        assert!(stderr.contains("declares no resource family"), "{name}: {stderr}");
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "a refused document must not reach PVE"
    );
}

/// Export a cluster without pools, then create a pool: the diff reports it.
#[tokio::test]
async fn an_export_of_an_empty_family_still_detects_a_new_member() {
    let dir = tempfile::tempdir().unwrap();

    let empty = mock_pve(&[]).await;
    let cfg = write_config(dir.path(), &empty.uri());
    let out = proxxx(
        dir.path(),
        &cfg,
        &["state", "export", "--resource", "pools"],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let exported = String::from_utf8(out.stdout).unwrap();
    assert!(
        exported.lines().any(|l| l == "pools = []"),
        "export:\n{exported}"
    );
    let file = dir.path().join("state.toml");
    std::fs::write(&file, &exported).unwrap();

    // Same cluster, unchanged: in sync.
    let out = proxxx(dir.path(), &cfg, &["state", "diff", file.to_str().unwrap()]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A pool appears on the cluster: drift, exit 2, naming the pool.
    let with_pool = mock_pve(&["stray"]).await;
    let cfg = write_config(dir.path(), &with_pool.uri());
    let out = proxxx(dir.path(), &cfg, &["state", "diff", file.to_str().unwrap()]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(2),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("stray"), "{stdout}");
}
