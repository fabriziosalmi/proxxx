#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::uninlined_format_args,
    clippy::branches_sharing_code
)]
//! Mission 2 — Scenario Alpha: full CRUD lifecycle of a test LXC.
//!
//! Steps (all polled, no `sleep`-based waits):
//!   1. **Create** an LXC at the configured `PROXXX_E2E_VMID`.
//!      Registers the guest with the RAII guard *before* the create
//!      call returns, so even a panic mid-create triggers cleanup.
//!   2. Poll until the guest is observable AND `status == stopped`.
//!   3. Run `proxxx start <vmid>` (CLI binary contract). Poll until
//!      `status == running`.
//!   4. Create a snapshot via the API. Poll until the task UPID
//!      reports stopped (i.e., snapshot finished).
//!   5. Run `proxxx stop <vmid> --force`. Poll until `status == stopped`.
//!   6. Run `proxxx delete <vmid> --yes` (destructive — only if
//!      `PROXXX_E2E_ALLOW_DELETE=1`). Poll until the guest 404s.
//!
//! Concurrency: `#[serial_test::serial]` forces sequential execution
//! across all mutation tests so two of them never race the same VMID.
//!
//! Teardown: `TestResourceGuard` registers the guest at step 1. If
//! the test panics anywhere from step 2 onward, the guard's `Drop`
//! force-stops and deletes the guest in a fresh runtime — the
//! cluster ends in the same shape it started.

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use proxxx::api::types::{GuestStatus, GuestType};
use proxxx::api::ProxmoxGateway;
use serial_test::serial;

use common::{poll_until, E2eEnv, Resource, TestResourceGuard};

/// Minimum-viable LXC creation. `PxClient` doesn't expose `create_lxc`
/// in its trait surface (the rest of proxxx never creates guests),
/// so we POST directly via reqwest with the env's token. Returns the
/// UPID of the create task.
async fn create_test_lxc(env: &E2eEnv) -> Result<String> {
    let template = env
        .template
        .clone()
        .context("PROXXX_E2E_TEMPLATE not set; cannot create test LXC")?;
    let storage = env
        .storage
        .clone()
        .context("PROXXX_E2E_STORAGE not set; cannot create test LXC")?;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_mins(1))
        .build()?;
    let url = format!(
        "{}/api2/json/nodes/{}/lxc",
        env.api_url.trim_end_matches('/'),
        env.node
    );
    let auth = format!(
        "PVEAPIToken={}!{}={}",
        env.user, env.token_id, env.token_secret
    );
    // Minimal viable payload: rootfs, ostemplate, hostname, memory,
    // swap=0, unprivileged=1. Network is intentionally omitted to keep
    // the test contained; the LXC starts without networking.
    let params = [
        ("vmid", env.vmid.to_string()),
        ("ostemplate", template),
        ("hostname", format!("proxxx-e2e-{}", env.vmid)),
        ("memory", "256".to_string()),
        ("swap", "0".to_string()),
        ("rootfs", format!("{storage}:1")),
        ("unprivileged", "1".to_string()),
        ("start", "0".to_string()),
    ];
    let resp = client
        .post(&url)
        .header("Authorization", &auth)
        .form(&params)
        .send()
        .await
        .context("POST /lxc")?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("create LXC {}: HTTP {status}: {body}", env.vmid);
    }
    // Body shape: { "data": "UPID:..." }
    let parsed: serde_json::Value =
        serde_json::from_str(&body).with_context(|| format!("parse create response: {body}"))?;
    let upid = parsed
        .get("data")
        .and_then(|v| v.as_str())
        .context("create response missing data UPID")?
        .to_string();
    Ok(upid)
}

#[tokio::test]
#[serial]
#[ignore = "requires PROXXX_E2E_ENABLE=1 and a real Proxmox cluster (see tests/common/mod.rs)"]
async fn alpha_full_crud_lifecycle() {
    let Some(env) = E2eEnv::load() else {
        // Env-gated skip — `cargo test --ignored` on a dev machine
        // without PROXXX_E2E_* exits cleanly here.
        return;
    };

    let client = env
        .build_client()
        .await
        .expect("build PxClient from E2E env");

    // ── RAII guard registered FIRST so a panic during create still
    //    cleans up. The cleanup is best-effort — if create itself
    //    fails (e.g., template missing), there's nothing to delete
    //    and the guard's poll-until in cleanup will surface a 404
    //    which we treat as already-gone.
    let guard = TestResourceGuard::new(Arc::clone(&client));
    guard.register(Resource::Guest {
        node: env.node.clone(),
        vmid: env.vmid,
        guest_type: GuestType::Lxc,
    });

    // Step 1 — create. PVE returns an UPID; we don't poll the task,
    // we poll the guest's existence + stopped state in step 2.
    eprintln!("[alpha] step 1: create LXC {}", env.vmid);
    let create_upid = create_test_lxc(&env).await.expect("create LXC");
    eprintln!("[alpha] create UPID: {create_upid}");

    // Step 2 — poll until visible AND stopped.
    eprintln!("[alpha] step 2: poll until visible + stopped");
    poll_until(
        "guest visible and stopped after create",
        Duration::from_mins(2),
        Duration::from_millis(500),
        || async {
            match client.get_guest_status(&env.node, env.vmid).await {
                Ok(g) if g.status == GuestStatus::Stopped => Ok(Some(())),
                Ok(_) => Ok(None),
                Err(e) => {
                    let msg = format!("{e:#}");
                    if msg.contains("404") {
                        // Not yet provisioned; keep polling.
                        Ok(None)
                    } else {
                        Err(e)
                    }
                }
            }
        },
    )
    .await
    .expect("guest reaches stopped");

    // Step 3 — `proxxx start <vmid>` via the CLI binary.
    //          Verifies the binary contract (Mission 2 rule on E2E
    //          testing the COMPILED ARTIFACT, not just the library).
    eprintln!("[alpha] step 3: proxxx start {}", env.vmid);
    let (stdout, stderr, code) = common::run_proxxx_capture(&["start", &env.vmid.to_string()]);
    assert_eq!(
        code, 0,
        "proxxx start exit={code}\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Poll until running.
    poll_until(
        "guest reaches running after CLI start",
        Duration::from_mins(1),
        Duration::from_millis(500),
        || async {
            let g = client.get_guest_status(&env.node, env.vmid).await?;
            if g.status == GuestStatus::Running {
                Ok(Some(()))
            } else {
                Ok(None)
            }
        },
    )
    .await
    .expect("guest reaches running");

    // Step 4 — snapshot via the API. Register with the guard so that
    // teardown deletes the snapshot before deleting the guest (PVE
    // refuses to delete a guest with snapshots in some configs).
    let snap_name = format!("proxxx-e2e-{}", env.vmid);
    eprintln!("[alpha] step 4: snapshot {}", snap_name);
    guard.register(Resource::Snapshot {
        node: env.node.clone(),
        vmid: env.vmid,
        guest_type: GuestType::Lxc,
        name: snap_name.clone(),
    });
    let snap_upid = client
        .create_snapshot(&env.node, env.vmid, GuestType::Lxc, &snap_name)
        .await
        .expect("create_snapshot");
    eprintln!("[alpha] snapshot UPID: {snap_upid}");
    // Poll until the snapshot shows up in the list.
    poll_until(
        "snapshot listed after create",
        Duration::from_mins(1),
        Duration::from_millis(500),
        || async {
            let snaps = client
                .list_snapshots(&env.node, env.vmid, GuestType::Lxc)
                .await?;
            if snaps.iter().any(|s| s.name == snap_name) {
                Ok(Some(()))
            } else {
                Ok(None)
            }
        },
    )
    .await
    .expect("snapshot listed");

    // Step 5 — `proxxx stop <vmid> --force` via the CLI.
    eprintln!("[alpha] step 5: proxxx stop --force {}", env.vmid);
    let (stdout, stderr, code) =
        common::run_proxxx_capture(&["stop", "--force", &env.vmid.to_string()]);
    assert_eq!(
        code, 0,
        "proxxx stop exit={code}\nstdout: {stdout}\nstderr: {stderr}"
    );
    poll_until(
        "guest reaches stopped after CLI stop",
        Duration::from_mins(1),
        Duration::from_millis(500),
        || async {
            let g = client.get_guest_status(&env.node, env.vmid).await?;
            if g.status == GuestStatus::Stopped {
                Ok(Some(()))
            } else {
                Ok(None)
            }
        },
    )
    .await
    .expect("guest reaches stopped");

    // Step 6 — destructive delete. Gated behind PROXXX_E2E_ALLOW_DELETE
    // because deleting the test VM means re-provisioning it before the
    // next run. Default-off; users opt in explicitly.
    if env.allow_delete {
        eprintln!("[alpha] step 6: proxxx delete --yes {}", env.vmid);
        let (stdout, stderr, code) =
            common::run_proxxx_capture(&["delete", "--yes", &env.vmid.to_string()]);
        assert_eq!(
            code, 0,
            "proxxx delete exit={code}\nstdout: {stdout}\nstderr: {stderr}"
        );
        poll_until(
            "guest 404s after CLI delete",
            Duration::from_mins(1),
            Duration::from_millis(500),
            || async {
                match client.get_guest_status(&env.node, env.vmid).await {
                    Ok(_) => Ok(None),
                    Err(e) => {
                        let msg = format!("{e:#}");
                        if msg.contains("404") {
                            Ok(Some(()))
                        } else {
                            Err(e)
                        }
                    }
                }
            },
        )
        .await
        .expect("guest 404s");
        // Resources successfully removed by the test itself —
        // explicit cleanup marks the guard consumed so Drop is a
        // no-op. Otherwise the guard would try to stop+delete a
        // 404'd vmid, which is harmless but logs noise.
        guard.cleanup().await;
    } else {
        eprintln!(
            "[alpha] step 6 skipped: PROXXX_E2E_ALLOW_DELETE != 1 \
             (RAII guard will stop+delete on Drop)"
        );
        guard.cleanup().await;
    }
}
