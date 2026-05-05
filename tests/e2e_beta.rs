#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::uninlined_format_args,
    clippy::branches_sharing_code
)]
//! Mission 2 — Scenario Beta: HITL bypass + token verification.
//!
//! Two unrelated assertions, both gating v1.0.0:
//!
//! ## Beta-1: destructive without `--yes` MUST refuse, MUST NOT call API
//!
//! `proxxx delete <vmid>` (no `--yes`) is supposed to bail before any
//! API call. We assert:
//!   - Exit code is non-zero (the CLI refused to proceed).
//!   - The guest at `PROXXX_E2E_VMID` is unaffected — we read its
//!     status before AND after; states must match exactly. (If the
//!     CLI had called the API and the call succeeded, we'd see a
//!     mid-flight task; if it failed, we'd see a 500 / lock error.)
//!
//! ## Beta-2: bad token surfaces 401 cleanly
//!
//! Validates Vector 11's mitigation. We invoke `proxxx ls guests`
//! with a deliberately wrong token. The binary must:
//!   - Exit non-zero.
//!   - Mention "401" or "Unauthorized" in stderr.
//!   - Return within a few seconds (NO infinite retry, NO panic).
//!
//! Concurrency: `#[serial]` because Beta-1 reads guest state and
//! must not race with Alpha mid-mutation.
//!
//! Teardown: Beta does NOT mutate cluster state, so the guard is
//! unused — we still construct one as documentation that no zombie
//! is possible from this test.

#[path = "common/mod.rs"]
mod common;

use std::time::{Duration, Instant};

use proxxx::api::ProxmoxGateway;
use serial_test::serial;

use common::E2eEnv;

#[tokio::test]
#[serial]
#[ignore = "requires PROXXX_E2E_ENABLE=1 and a real Proxmox cluster"]
async fn beta_destructive_without_yes_refuses() {
    let Some(env) = E2eEnv::load() else {
        return;
    };
    let client = env.build_client().await.expect("PxClient");

    // Snapshot status BEFORE — we'll compare after the CLI invocation
    // to prove no mutation happened.
    let before = client
        .get_guest_status(&env.node, env.vmid)
        .await
        .expect("guest must exist for Beta-1");

    // Run `proxxx delete <vmid>` WITHOUT --yes. The CLI's hard-coded
    // refusal at `cli/mod.rs:610` should bail with a non-zero exit
    // code BEFORE any HTTP request lands at PVE.
    let (stdout, stderr, code) = common::run_proxxx_capture(&["delete", &env.vmid.to_string()]);
    assert_ne!(
        code, 0,
        "destructive delete WITHOUT --yes must exit non-zero \
         (got 0; stdout={stdout}; stderr={stderr})"
    );
    assert!(
        stderr.contains("--yes") || stdout.contains("--yes"),
        "the refusal must mention `--yes` so the user knows how to retry; \
         stdout={stdout}; stderr={stderr}"
    );

    // Verify state is unchanged. status == before.status, vmid is
    // still observable, no mid-flight lock error.
    let after = client
        .get_guest_status(&env.node, env.vmid)
        .await
        .expect("guest must still be observable");
    assert_eq!(
        before.status, after.status,
        "guest status changed after a refused destructive op — \
         CLI bypassed its own --yes guard"
    );
}

#[tokio::test]
#[serial]
#[ignore = "requires PROXXX_E2E_ENABLE=1 and a real Proxmox cluster"]
async fn beta_bad_token_surfaces_401_cleanly() {
    let Some(_env) = E2eEnv::load() else {
        return;
    };

    // Override the token in the subprocess env. The parent test
    // process keeps its real token; only the spawned `proxxx`
    // sees the bad one.
    //
    // Mission 2 rule: validates Vector 11's mitigation. The binary
    // must surface the auth error within a small budget (no
    // infinite retry, no panic, no hang).
    let bin = env!("CARGO_BIN_EXE_proxxx");
    let started = Instant::now();
    let out = std::process::Command::new(bin)
        .args(["ls", "guests", "--format", "json"])
        .env("PROXXX_TOKEN_SECRET", "this-is-deliberately-wrong-xxxxxxxx")
        .output()
        .expect("spawn proxxx with bad token");
    let elapsed = started.elapsed();

    let code = out.status.code().unwrap_or(-1);
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();

    // Bound 1: must NOT exit cleanly with bad creds.
    assert_ne!(
        code, 0,
        "proxxx must exit non-zero on bad token; stdout={stdout}; stderr={stderr}"
    );

    // Bound 2: must surface 401 / Unauthorized in user-visible output.
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        combined.contains("401")
            || combined.to_lowercase().contains("unauthorized")
            || combined.to_lowercase().contains("authentication"),
        "expected 401/Unauthorized signal; stdout={stdout}; stderr={stderr}"
    );

    // Bound 3: must return within a small time budget (NO infinite
    // retry — the V11 reactive re-auth is one shot for token auth,
    // and the V11 retry budget caps total time at <30s under any
    // circumstance). 60 s is a generous ceiling that still catches
    // a regression to the old "retry forever" code path.
    assert!(
        elapsed < Duration::from_mins(1),
        "proxxx took {:?} on bad token — V11 mitigation regressed; \
         must return promptly",
        elapsed
    );
}

#[tokio::test]
#[serial]
#[ignore = "requires PROXXX_E2E_ENABLE=1"]
async fn beta_cli_contract_ls_guests_emits_valid_json() {
    let Some(_env) = E2eEnv::load() else {
        return;
    };

    // CLI binary contract: `proxxx ls guests --format json` must
    // produce parseable JSON on stdout. The shape is a list of
    // guest objects (or a single error object on failure).
    let (stdout, stderr, code) = common::run_proxxx_capture(&["ls", "guests", "--format", "json"]);
    assert_eq!(code, 0, "ls guests --format json failed; stderr={stderr}");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!("ls guests output is not valid JSON: {e}\n--- stdout ---\n{stdout}")
    });
    // The top-level shape is an array (proxxx wraps non-array
    // results into one in main.rs for the JSON format).
    assert!(
        parsed.is_array(),
        "expected top-level JSON array, got: {parsed}"
    );
}
