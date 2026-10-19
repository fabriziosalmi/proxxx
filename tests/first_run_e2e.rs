//! End-to-end and unit tests for Step 14 (`#322`, `#324`, `#325`):
//! - `#322`: `ls <kind> --all-profiles` and `find <vmid>` exit `1` when any
//!   profile fails (while still printing error + data rows), and `find <vmid>`
//!   exits `5` only when every profile answered without error and none owns the VMID.
//! - `#324`: `token_secret_file` (PVE and PBS) expands `~` and `~/...` via the
//!   single shared helper in `proxxx::util::path`.
//! - `#325`: `proxxx doctor`'s `ssh_key` check expands `~` and `~/...` via the
//!   same shared helper.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]

use std::path::{Path, PathBuf};
use std::process::Command;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const fn proxxx_bin() -> &'static str {
    env!("CARGO_BIN_EXE_proxxx")
}

fn write_secret_0600(file_path: &Path, content: &str) {
    if let Some(parent) = file_path.parent() {
        std::fs::create_dir_all(parent).expect("create secret parent dir");
    }
    std::fs::write(file_path, content).expect("write secret file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600 secret file");
    }
}

async fn mount_pve_node_with_guest(server: &MockServer, node_name: &str, vmid: Option<u32>) {
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [{
                "node": node_name,
                "status": "online",
                "cpu": 0.05,
                "maxcpu": 8,
                "mem": 1_073_741_824_u64,
                "maxmem": 17_179_869_184_u64,
                "uptime": 3600
            }]
        })))
        .mount(server)
        .await;

    let qemu_data = vmid.map_or_else(
        || serde_json::json!([]),
        |id| {
            serde_json::json!([{
                "vmid": id,
                "name": format!("vm-{id}"),
                "status": "running",
                "cpus": 2,
                "mem": 536_870_912_u64,
                "maxmem": 2_147_483_648_u64,
                "disk": 0,
                "maxdisk": 10_737_418_240_u64,
                "uptime": 120
            }])
        },
    );
    Mock::given(method("GET"))
        .and(path(format!("/api2/json/nodes/{node_name}/qemu")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": qemu_data
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/api2/json/nodes/{node_name}/lxc")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": []
        })))
        .mount(server)
        .await;
}

/// Test 1 (#322):
/// - Two profiles pointing at closed ports: `ls nodes --all-profiles` exits 1
///   and still prints both error rows (in JSON and table output).
/// - One good (wiremock) + one dead profile: exits 1, and both the good row
///   and the error row are present.
/// - Both good (wiremock): exits 0 and prints both good rows.
#[tokio::test]
async fn test_1_ls_all_profiles_exits_1_when_any_profile_fails_and_0_when_all_succeed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let audit_dir = tmp.path().join("audit");
    std::fs::create_dir_all(&audit_dir).expect("create audit dir");

    // 1a. Both profiles pointing at closed ports.
    let cfg_both_dead = tmp.path().join("both_dead.toml");
    std::fs::write(
        &cfg_both_dead,
        r#"
default = "alpha"

[profiles.alpha]
url = "https://127.0.0.1:1"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000001"
verify_tls = false

[profiles.beta]
url = "https://127.0.0.1:2"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000002"
verify_tls = false
"#,
    )
    .expect("write both_dead.toml");

    let out_json = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_both_dead)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["--format", "json", "ls", "nodes", "--all-profiles"])
        .output()
        .expect("run proxxx ls nodes --all-profiles (both dead, json)");
    assert_eq!(
        out_json.status.code(),
        Some(1),
        "ls nodes --all-profiles with all profiles dead must exit 1, stdout: {}, stderr: {}",
        String::from_utf8_lossy(&out_json.stdout),
        String::from_utf8_lossy(&out_json.stderr)
    );
    let rows: serde_json::Value =
        serde_json::from_slice(&out_json.stdout).expect("parse json output");
    let arr = rows.as_array().expect("rows array");
    assert_eq!(arr.len(), 2, "both error rows must be printed: {arr:?}");
    assert_eq!(arr[0]["profile"], "alpha");
    assert!(arr[0]["error"].is_string(), "alpha must be an error row");
    assert_eq!(arr[1]["profile"], "beta");
    assert!(arr[1]["error"].is_string(), "beta must be an error row");

    let out_table = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_both_dead)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["ls", "nodes", "--all-profiles"])
        .output()
        .expect("run proxxx ls nodes --all-profiles (both dead, table)");
    assert_eq!(out_table.status.code(), Some(1));
    let table_stdout = String::from_utf8_lossy(&out_table.stdout);
    assert!(
        table_stdout.contains("alpha") && table_stdout.contains("beta"),
        "table output must still include both profiles: {table_stdout}"
    );

    // 1b. One good (wiremock) + one dead profile.
    let good_server = MockServer::start().await;
    mount_pve_node_with_guest(&good_server, "pve-good-1", None).await;

    let cfg_mixed = tmp.path().join("mixed.toml");
    std::fs::write(
        &cfg_mixed,
        format!(
            r#"
default = "good"

[profiles.dead]
url = "https://127.0.0.1:1"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000001"
verify_tls = false

[profiles.good]
url = "{}"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000002"
verify_tls = false
"#,
            good_server.uri()
        ),
    )
    .expect("write mixed.toml");

    let out_mixed = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_mixed)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["--format", "json", "ls", "nodes", "--all-profiles"])
        .output()
        .expect("run proxxx ls nodes --all-profiles (mixed)");
    assert_eq!(
        out_mixed.status.code(),
        Some(1),
        "ls nodes --all-profiles with one dead profile must exit 1"
    );
    let mixed_rows: serde_json::Value =
        serde_json::from_slice(&out_mixed.stdout).expect("parse mixed json");
    let mixed_arr = mixed_rows.as_array().expect("mixed rows array");
    assert_eq!(mixed_arr.len(), 2, "must contain both dead and good rows");
    assert_eq!(mixed_arr[0]["profile"], "dead");
    assert!(mixed_arr[0]["error"].is_string());
    assert_eq!(mixed_arr[1]["profile"], "good");
    assert_eq!(mixed_arr[1]["data"]["node"], "pve-good-1");

    // 1c. Both profiles good.
    let second_server = MockServer::start().await;
    mount_pve_node_with_guest(&second_server, "pve-good-2", None).await;

    let cfg_both_good = tmp.path().join("both_good.toml");
    std::fs::write(
        &cfg_both_good,
        format!(
            r#"
default = "first"

[profiles.first]
url = "{}"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000001"
verify_tls = false

[profiles.second]
url = "{}"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000002"
verify_tls = false
"#,
            good_server.uri(),
            second_server.uri()
        ),
    )
    .expect("write both_good.toml");

    let out_good = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_both_good)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["--format", "json", "ls", "nodes", "--all-profiles"])
        .output()
        .expect("run proxxx ls nodes --all-profiles (both good)");
    assert_eq!(
        out_good.status.code(),
        Some(0),
        "ls nodes --all-profiles with all profiles ok must exit 0"
    );
    let good_rows: serde_json::Value =
        serde_json::from_slice(&out_good.stdout).expect("parse good json");
    let good_arr = good_rows.as_array().expect("good rows array");
    assert_eq!(good_arr.len(), 2);
    assert_eq!(good_arr[0]["profile"], "first");
    assert_eq!(good_arr[0]["data"]["node"], "pve-good-1");
    assert_eq!(good_arr[1]["profile"], "second");
    assert_eq!(good_arr[1]["data"]["node"], "pve-good-2");
}

/// Test 2 (#322):
/// - `find <vmid>` with all profiles dead -> exit 1 (not 5, not 0), and prints
///   error rows attributed to their profile names.
/// - `find <vmid>` with one profile answering (not owning the VMID) and one
///   profile dead -> exit 1 (not 5), and prints the error row.
/// - `find <vmid>` with all profiles answering and none owning it -> exit 5.
/// - `find <vmid>` with all profiles answering and one owning it -> exit 0.
#[tokio::test]
async fn test_2_find_exits_1_when_any_profile_errors_and_5_only_when_all_answer_and_none_owns_vmid()
{
    let tmp = tempfile::tempdir().expect("tempdir");
    let audit_dir = tmp.path().join("audit");
    std::fs::create_dir_all(&audit_dir).expect("create audit dir");

    // 2a. All profiles dead -> exit 1, not 5.
    let cfg_dead = tmp.path().join("find_dead.toml");
    std::fs::write(
        &cfg_dead,
        r#"
default = "alpha"

[profiles.alpha]
url = "https://127.0.0.1:1"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000001"
verify_tls = false

[profiles.beta]
url = "https://127.0.0.1:2"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000002"
verify_tls = false
"#,
    )
    .expect("write find_dead.toml");

    let out_dead = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_dead)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["--format", "json", "find", "100"])
        .output()
        .expect("run proxxx find 100 (all dead)");
    assert_eq!(
        out_dead.status.code(),
        Some(1),
        "find 100 with all profiles dead must exit 1 (not 5 or 0)"
    );
    let dead_rows: serde_json::Value =
        serde_json::from_slice(&out_dead.stdout).expect("parse find dead json");
    let dead_arr = dead_rows.as_array().expect("dead rows array");
    assert_eq!(
        dead_arr.len(),
        2,
        "must include error rows for both profiles"
    );
    assert_eq!(dead_arr[0]["profile"], "alpha");
    assert!(dead_arr[0]["error"].is_string());
    assert_eq!(dead_arr[1]["profile"], "beta");
    assert!(dead_arr[1]["error"].is_string());

    // 2b. One profile answers (owns 100, not 999) + one profile dead -> `find 999` exits 1, not 5.
    let srv_a = MockServer::start().await;
    mount_pve_node_with_guest(&srv_a, "pve-a", Some(100)).await;

    let cfg_partial = tmp.path().join("find_partial.toml");
    std::fs::write(
        &cfg_partial,
        format!(
            r#"
default = "alive"

[profiles.alive]
url = "{}"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000001"
verify_tls = false

[profiles.dead]
url = "https://127.0.0.1:1"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000002"
verify_tls = false
"#,
            srv_a.uri()
        ),
    )
    .expect("write find_partial.toml");

    let out_partial = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_partial)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["--format", "json", "find", "999"])
        .output()
        .expect("run proxxx find 999 (one alive without 999, one dead)");
    assert_eq!(
        out_partial.status.code(),
        Some(1),
        "find 999 with one profile dead and no owner must exit 1 (not 5)"
    );
    let partial_rows: serde_json::Value =
        serde_json::from_slice(&out_partial.stdout).expect("parse partial json");
    let partial_arr = partial_rows.as_array().expect("partial rows array");
    assert_eq!(partial_arr.len(), 1);
    assert_eq!(partial_arr[0]["profile"], "dead");
    assert!(partial_arr[0]["error"].is_string());

    // 2c. All profiles answer and none owns 999 -> exit 5.
    let srv_b = MockServer::start().await;
    mount_pve_node_with_guest(&srv_b, "pve-b", Some(200)).await;

    let cfg_all_ok = tmp.path().join("find_all_ok.toml");
    std::fs::write(
        &cfg_all_ok,
        format!(
            r#"
default = "first"

[profiles.first]
url = "{}"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000001"
verify_tls = false

[profiles.second]
url = "{}"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000002"
verify_tls = false
"#,
            srv_a.uri(),
            srv_b.uri()
        ),
    )
    .expect("write find_all_ok.toml");

    let out_not_found = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_all_ok)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["--format", "json", "find", "999"])
        .output()
        .expect("run proxxx find 999 (all ok, none owns)");
    assert_eq!(
        out_not_found.status.code(),
        Some(5),
        "find 999 when all profiles answer and none owns it must exit 5"
    );

    // 2d. All profiles answer and `first` owns 100 -> exit 0.
    let out_found = Command::new(proxxx_bin())
        .env("PROXXX_CONFIG", &cfg_all_ok)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["--format", "json", "find", "100"])
        .output()
        .expect("run proxxx find 100 (all ok, first owns)");
    assert_eq!(out_found.status.code(), Some(0));
    let found_rows: serde_json::Value =
        serde_json::from_slice(&out_found.stdout).expect("parse found json");
    let found_arr = found_rows.as_array().expect("found rows array");
    assert_eq!(found_arr.len(), 1);
    assert_eq!(found_arr[0]["profile"], "first");
    assert_eq!(found_arr[0]["data"]["vmid"], 100);
}

/// Test 3 (#324):
/// `token_secret_file = "~/<relative path>"` resolves under a temporary `HOME`
/// (without touching the real `HOME` or mutating process-wide env vars):
/// - Against a closed port, `ls nodes` gets past secret resolution and fails on
///   transport (`Connection refused` / `connect`), not with `"not found"`.
/// - Against a wiremock server expecting the secret from `~/...`, `ls nodes`
///   authenticates and exits 0.
/// - Same for `pbs.token_secret_file = "~/<relative path>"` with `pbs ping`.
/// - When the file does not exist, the error message shows both the user-written
///   `~/...` path and the expanded path.
#[tokio::test]
async fn test_3_token_secret_file_expands_tilde_for_pve_and_pbs() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tmp.path().join("fake-home");
    std::fs::create_dir_all(&fake_home).expect("create fake home");
    let audit_dir = tmp.path().join("audit");
    std::fs::create_dir_all(&audit_dir).expect("create audit dir");

    let pve_secret_path = fake_home.join(".proxxx-secrets/pve.token");
    write_secret_0600(&pve_secret_path, "tilde-pve-secret-value\n");

    let pbs_secret_path = fake_home.join(".proxxx-secrets/pbs.token");
    write_secret_0600(&pbs_secret_path, "tilde-pbs-secret-value\n");

    // 3a. Closed port: gets past secret resolution and fails on transport.
    let cfg_closed = tmp.path().join("tilde_closed.toml");
    std::fs::write(
        &cfg_closed,
        r#"
default = "lab"

[profiles.lab]
url = "https://127.0.0.1:1"
user = "root@pam"
token_id = "test"
token_secret_file = "~/.proxxx-secrets/pve.token"
verify_tls = false

[profiles.lab.pbs]
url = "https://127.0.0.1:2"
user = "backup@pbs"
token_id = "reader"
token_secret_file = "~/.proxxx-secrets/pbs.token"
verify_tls = false
"#,
    )
    .expect("write tilde_closed.toml");

    let out_closed = Command::new(proxxx_bin())
        .env("HOME", &fake_home)
        .env("PROXXX_CONFIG", &cfg_closed)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .env_remove("PROXXX_TOKEN_SECRET")
        .args(["ls", "nodes"])
        .output()
        .expect("run proxxx ls nodes with ~/ token_secret_file");
    assert_eq!(out_closed.status.code(), Some(1));
    let stderr_closed = String::from_utf8_lossy(&out_closed.stderr);
    assert!(
        !stderr_closed.contains("token_secret_file")
            && !stderr_closed.contains("Token secret not found"),
        "must get past secret resolution, got stderr: {stderr_closed}"
    );
    let stderr_lower = stderr_closed.to_ascii_lowercase();
    assert!(
        stderr_lower.contains("connection refused") || stderr_lower.contains("connect"),
        "must fail on transport, got stderr: {stderr_closed}"
    );

    // 3b. Wiremock PVE + PBS verifying that the resolved secret from `~/...` is sent.
    let pve_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes"))
        .and(header(
            "Authorization",
            "PVEAPIToken=root@pam!test=tilde-pve-secret-value",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [{
                "node": "pve-tilde",
                "status": "online",
                "cpu": 0.01,
                "maxcpu": 4,
                "mem": 1024,
                "maxmem": 4096,
                "uptime": 100
            }]
        })))
        .mount(&pve_server)
        .await;

    let pbs_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/version"))
        .and(header(
            "Authorization",
            "PBSAPIToken=backup@pbs!reader:tilde-pbs-secret-value",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "version": "3.2", "release": "1" }
        })))
        .mount(&pbs_server)
        .await;

    let cfg_live = tmp.path().join("tilde_live.toml");
    std::fs::write(
        &cfg_live,
        format!(
            r#"
default = "lab"

[profiles.lab]
url = "{}"
user = "root@pam"
token_id = "test"
token_secret_file = "~/.proxxx-secrets/pve.token"
verify_tls = false

[profiles.lab.pbs]
url = "{}"
user = "backup@pbs"
token_id = "reader"
token_secret_file = "~/.proxxx-secrets/pbs.token"
verify_tls = false
"#,
            pve_server.uri(),
            pbs_server.uri()
        ),
    )
    .expect("write tilde_live.toml");

    let out_pve_ok = Command::new(proxxx_bin())
        .env("HOME", &fake_home)
        .env("PROXXX_CONFIG", &cfg_live)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .env_remove("PROXXX_TOKEN_SECRET")
        .args(["--format", "json", "ls", "nodes"])
        .output()
        .expect("run proxxx ls nodes against wiremock");
    assert_eq!(
        out_pve_ok.status.code(),
        Some(0),
        "ls nodes with ~/ token_secret_file must succeed, stderr: {}",
        String::from_utf8_lossy(&out_pve_ok.stderr)
    );

    let out_pbs_ok = Command::new(proxxx_bin())
        .env("HOME", &fake_home)
        .env("PROXXX_CONFIG", &cfg_live)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .env_remove("PROXXX_PBS_TOKEN_SECRET")
        .args(["--format", "json", "pbs", "ping"])
        .output()
        .expect("run proxxx pbs ping against wiremock");
    assert_eq!(
        out_pbs_ok.status.code(),
        Some(0),
        "pbs ping with ~/ pbs.token_secret_file must succeed, stderr: {}",
        String::from_utf8_lossy(&out_pbs_ok.stderr)
    );

    // 3c. Missing `~/...` file shows both the user-written path and the expanded path.
    let cfg_missing = tmp.path().join("tilde_missing.toml");
    std::fs::write(
        &cfg_missing,
        r#"
default = "lab"

[profiles.lab]
url = "https://127.0.0.1:1"
user = "root@pam"
token_id = "test"
token_secret_file = "~/.proxxx-secrets/does-not-exist.token"
verify_tls = false
"#,
    )
    .expect("write tilde_missing.toml");

    let out_missing = Command::new(proxxx_bin())
        .env("HOME", &fake_home)
        .env("PROXXX_CONFIG", &cfg_missing)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .env_remove("PROXXX_TOKEN_SECRET")
        .args(["ls", "nodes"])
        .output()
        .expect("run proxxx ls nodes with missing ~/ token_secret_file");
    assert_ne!(out_missing.status.code(), Some(0));
    let stderr_missing = String::from_utf8_lossy(&out_missing.stderr);
    let expected_expanded = fake_home.join(".proxxx-secrets/does-not-exist.token");
    assert!(
        stderr_missing.contains("~/.proxxx-secrets/does-not-exist.token")
            && stderr_missing.contains(&expected_expanded.display().to_string()),
        "error message must show both user-written and expanded path, got: {stderr_missing}"
    );
}

/// Test 4 (#325):
/// `proxxx doctor` expands `~` on `[ssh] key_path = "~/<file>"`:
/// - When the file exists under the temporary `HOME`, `ssh_key` check reports `ok`
///   and includes both the user-written `~/...` path and the expanded path.
/// - When the file does not exist under the temporary `HOME`, `ssh_key` check
///   reports `fail` and includes both the user-written `~/...` path and the expanded path.
#[tokio::test]
async fn test_4_doctor_ssh_key_check_expands_tilde() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fake_home = tmp.path().join("fake-home");
    let audit_dir = tmp.path().join("audit");
    std::fs::create_dir_all(&audit_dir).expect("create audit dir");

    let ssh_key = fake_home.join(".ssh/id_rsa");
    write_secret_0600(&ssh_key, "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n");

    let pve_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/version"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "version": "8.2.4", "release": "8.2" }
        })))
        .mount(&pve_server)
        .await;

    let cfg_path = tmp.path().join("doctor_tilde.toml");
    std::fs::write(
        &cfg_path,
        format!(
            r#"
default = "lab"

[profiles.lab]
url = "{}"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000001"
verify_tls = false

[profiles.lab.ssh]
user = "root"
key_path = "~/.ssh/id_rsa"
"#,
            pve_server.uri()
        ),
    )
    .expect("write doctor_tilde.toml");

    let out = Command::new(proxxx_bin())
        .env("HOME", &fake_home)
        .env("PROXXX_CONFIG", &cfg_path)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["--format", "json", "doctor"])
        .output()
        .expect("run proxxx doctor");

    let stdout_json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("parse doctor json");
    let checks = stdout_json
        .as_array()
        .expect("doctor top-level checks array");
    let ssh_check = checks
        .iter()
        .find(|c| c["check"] == "ssh_key")
        .expect("ssh_key check must be present");
    assert_eq!(
        ssh_check["status"], "ok",
        "doctor ssh_key check must report ok when ~/.ssh/id_rsa exists under HOME, got: {ssh_check:?}"
    );
    let msg = ssh_check["message"].as_str().expect("ssh_key message");
    assert!(
        msg.contains("~/.ssh/id_rsa") && msg.contains(&ssh_key.display().to_string()),
        "ssh_key message must show both user-written and expanded path, got: {msg}"
    );

    // Also verify missing `~/...` key reports `fail` with both paths.
    let cfg_missing = tmp.path().join("doctor_tilde_missing.toml");
    std::fs::write(
        &cfg_missing,
        format!(
            r#"
default = "lab"

[profiles.lab]
url = "{}"
user = "root@pam"
token_id = "test"
token_secret = "00000000-0000-0000-0000-000000000001"
verify_tls = false

[profiles.lab.ssh]
user = "root"
key_path = "~/.ssh/missing_ed25519"
"#,
            pve_server.uri()
        ),
    )
    .expect("write doctor_tilde_missing.toml");

    let out_missing = Command::new(proxxx_bin())
        .env("HOME", &fake_home)
        .env("PROXXX_CONFIG", &cfg_missing)
        .env("PROXXX_AUDIT_DIR", &audit_dir)
        .args(["--format", "json", "doctor"])
        .output()
        .expect("run proxxx doctor with missing key");
    assert_eq!(out_missing.status.code(), Some(1));
    let missing_json: serde_json::Value =
        serde_json::from_slice(&out_missing.stdout).expect("parse doctor missing json");
    let missing_checks = missing_json.as_array().expect("doctor checks array");
    let missing_ssh = missing_checks
        .iter()
        .find(|c| c["check"] == "ssh_key")
        .expect("ssh_key check must be present");
    assert_eq!(missing_ssh["status"], "fail");
    let missing_msg = missing_ssh["message"]
        .as_str()
        .expect("ssh_key fail message");
    let expected_missing = fake_home.join(".ssh/missing_ed25519");
    assert!(
        missing_msg.contains("~/.ssh/missing_ed25519")
            && missing_msg.contains(&expected_missing.display().to_string()),
        "ssh_key fail message must show both user-written and expanded path, got: {missing_msg}"
    );
}

/// Test 5 (#324, #325):
/// - Exercises the single shared tilde helper (`~`, `~/x`, `/abs`, `rel`, `~user` left as-is).
/// - Verifies that `fn expand_tilde` exists only in `src/util/path.rs` and
///   `fn expand_tilde_str` is gone from `src/`.
#[test]
fn test_5_single_shared_tilde_helper_unit_and_no_duplicate_helpers_guard() {
    use proxxx::util::path::{expand_tilde, expand_tilde_with_home};

    let home = Path::new("/tmp/proxxx-test-home");
    assert_eq!(
        expand_tilde_with_home("~", Some(home)),
        PathBuf::from("/tmp/proxxx-test-home")
    );
    assert_eq!(
        expand_tilde_with_home("~/x", Some(home)),
        PathBuf::from("/tmp/proxxx-test-home/x")
    );
    assert_eq!(
        expand_tilde_with_home("/abs", Some(home)),
        PathBuf::from("/abs")
    );
    assert_eq!(
        expand_tilde_with_home("rel", Some(home)),
        PathBuf::from("rel")
    );
    assert_eq!(
        expand_tilde_with_home("~user", Some(home)),
        PathBuf::from("~user")
    );

    if let Some(real_home) = std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|h| !h.as_os_str().is_empty())
    {
        assert_eq!(expand_tilde("~"), real_home);
        assert_eq!(expand_tilde("~/x"), real_home.join("x"));
    }
    assert_eq!(expand_tilde("/abs"), PathBuf::from("/abs"));
    assert_eq!(expand_tilde("rel"), PathBuf::from("rel"));
    assert_eq!(expand_tilde("~user"), PathBuf::from("~user"));

    // Guard: `fn expand_tilde` may only be defined in `src/util/path.rs`,
    // and `fn expand_tilde_str` must not exist anywhere in `src/`.
    let src_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut rs_files = Vec::new();
    collect_rs_files(&src_root, &mut rs_files);
    let allowed = src_root.join("util/path.rs");

    for file in rs_files {
        let content = std::fs::read_to_string(&file).expect("read source file");
        assert!(
            !content.contains("fn expand_tilde_str"),
            "duplicate helper `fn expand_tilde_str` found in {}",
            file.display()
        );
        if file != allowed {
            assert!(
                !content.contains("fn expand_tilde("),
                "duplicate helper `fn expand_tilde` found in {} (must live only in src/util/path.rs)",
                file.display()
            );
        }
    }
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).expect("read_dir");
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_rs_files(&p, out);
        } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(p);
        }
    }
}
