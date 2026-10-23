#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! `proxxx incident {freeze, status, thaw}` end to end (#297).
//!
//! The unit tests in `src/incident` exercise the path-taking forms. These
//! run the binary, so the lock is found the way production finds it
//! (`PROXXX_FREEZE_PATH`, per-profile siblings) and the refusal is the one
//! `PxClient` raises before a mutation leaves the process. Every path is a
//! temp dir and the "cluster" is a wiremock server.

use std::path::Path;
use std::process::{Command, Output};

use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

const fn proxxx_bin() -> &'static str {
    env!("CARGO_BIN_EXE_proxxx")
}

/// Run the binary against `dir`'s config, lock and audit paths.
fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(proxxx_bin())
        .args(["--token-secret", "fake-secret", "--format", "json"])
        .args(args)
        .env("PROXXX_CONFIG", dir.join("config.toml"))
        .env("PROXXX_FREEZE_PATH", dir.join("locks").join("freeze.lock"))
        .env("PROXXX_AUDIT_DIR", dir.join("audit"))
        .env_remove("PROXXX_AUDIT_KEY")
        .output()
        .expect("run proxxx")
}

fn json(out: &Output) -> serde_json::Value {
    assert!(
        out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    v[0].clone()
}

async fn delete_count(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == "DELETE")
        .count()
}

async fn mock_cluster() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path_regex(r"^/api2/json/access/users/alice(@|%40)pve$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": null})))
        .mount(&server)
        .await;
    server
}

fn delete_user(dir: &Path, profile: Option<&str>) -> Output {
    let mut args = Vec::new();
    if let Some(p) = profile {
        args.extend(["--profile", p]);
    }
    args.extend(["access", "user-delete", "alice@pve", "--yes"]);
    run(dir, &args)
}

fn assert_frozen_refusal(out: &Output, reason: &str) {
    assert_eq!(
        out.status.code(),
        Some(8),
        "a frozen mutation exits 8: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(all.contains(reason), "the refusal names the reason: {all}");
}

#[tokio::test]
async fn a_global_freeze_refuses_mutations_until_thawed() {
    let server = mock_cluster().await;
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "url = \"{}\"\nuser = \"root@pam\"\nauth = \"token\"\ntoken_id = \"test\"\nverify_tls = false\n",
            server.uri()
        ),
    )
    .unwrap();

    // No lock directory yet: nothing is frozen.
    let status = json(&run(dir.path(), &["incident", "status"]));
    assert_eq!(status["active"], false);

    let frozen = json(&run(
        dir.path(),
        &["incident", "freeze", "--reason", "token leaked"],
    ));
    assert_eq!(frozen["reason"], "token leaked");

    let status = json(&run(dir.path(), &["incident", "status"]));
    assert_eq!(status["active"], true);
    assert_eq!(status["state"]["reason"], "token leaked");

    assert_frozen_refusal(&delete_user(dir.path(), None), "token leaked");
    assert_eq!(delete_count(&server).await, 0, "no request may leave");

    let thawed = json(&run(
        dir.path(),
        &["incident", "thaw", "--reason", "token rotated"],
    ));
    assert_eq!(thawed["thawed"], true);
    assert_eq!(thawed["prior_state"]["reason"], "token leaked");
    assert_eq!(
        json(&run(dir.path(), &["incident", "status"]))["active"],
        false
    );

    let out = delete_user(dir.path(), None);
    assert!(
        out.status.success(),
        "after thaw the mutation runs: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(delete_count(&server).await, 1);
}

#[tokio::test]
async fn a_profile_freeze_refuses_only_that_profile() {
    let server = mock_cluster().await;
    let dir = tempfile::tempdir().expect("temp dir");
    let profile = |name: &str| {
        format!(
            "[profiles.{name}]\nurl = \"{}\"\nuser = \"root@pam\"\nauth = \"token\"\ntoken_id = \"test\"\nverify_tls = false\n",
            server.uri()
        )
    };
    std::fs::write(
        dir.path().join("config.toml"),
        format!(
            "default = \"lab\"\n\n{}\n{}",
            profile("prod"),
            profile("lab")
        ),
    )
    .unwrap();

    json(&run(
        dir.path(),
        &[
            "incident",
            "freeze",
            "--profile",
            "prod",
            "--reason",
            "prod drill",
        ],
    ));

    let locks = dir.path().join("locks");
    // Files the status scan must skip: an atomic-write temp file holding a
    // valid lock, and a `.lock` file that is not a freeze lock.
    let prod_lock = std::fs::read_dir(&locks)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "lock"))
        .expect("the prod lock file");
    std::fs::copy(&prod_lock, locks.join("freeze.lock.tmp.1.2")).unwrap();
    std::fs::copy(&prod_lock, locks.join("other.lock")).unwrap();

    let status = json(&run(dir.path(), &["incident", "status"]));
    assert_eq!(status["active"], true);
    assert!(status["state"].is_null(), "no global freeze: {status}");
    let freezes = status["freezes"].as_array().expect("freezes");
    assert_eq!(freezes.len(), 1, "only the prod lock is a freeze: {status}");
    assert_eq!(freezes[0]["profile"], "prod");

    assert_frozen_refusal(&delete_user(dir.path(), Some("prod")), "prod drill");
    assert_eq!(delete_count(&server).await, 0);

    let out = delete_user(dir.path(), Some("lab"));
    assert!(
        out.status.success(),
        "another profile stays writable: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(delete_count(&server).await, 1);

    let thawed = json(&run(
        dir.path(),
        &[
            "incident",
            "thaw",
            "--profile",
            "prod",
            "--reason",
            "drill over",
        ],
    ));
    assert_eq!(thawed["thawed"], true);
    assert_eq!(thawed["prior_state"]["profile"], "prod");
}

#[test]
fn an_unreadable_lock_directory_is_an_error_not_an_empty_list() {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        dir.path().join("config.toml"),
        "url = \"https://127.0.0.1:9\"\nuser = \"root@pam\"\nauth = \"token\"\ntoken_id = \"test\"\nverify_tls = false\n",
    )
    .unwrap();
    // The lock "directory" is a regular file, so listing it fails with an
    // error other than NotFound.
    std::fs::write(dir.path().join("locks"), "not a directory").unwrap();

    let out = run(dir.path(), &["incident", "status"]);
    assert!(
        !out.status.success(),
        "status must not report an unreadable lock directory as no freeze: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}
