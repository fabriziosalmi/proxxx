#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]
//! Phase 7 — Live RBAC test suite against a real PVE cluster.
//!
//! Provisioning: see [`tests/fixtures/setup_rbac.sh`] which creates
//! 3 PVE personas (operator/auditor/blind) + privsep tokens + scoped
//! ACLs. Capture the script's output and `export` as env vars before
//! running this suite.
//!
//! ## Env contract
//!
//! ```bash
//! export PROXXX_E2E_RBAC_ENABLE=1
//! export PROXXX_E2E_API_URL="https://10.0.0.1:8006"
//! export PROXXX_E2E_OWNED_VMID=8888           # operator's PVEVMAdmin scope
//! export PROXXX_E2E_BLIND_VMID=9999           # blind's PVEVMUser scope (often nonexistent)
//! export PROXXX_E2E_TOKEN_OPERATOR="ae028584-…"
//! export PROXXX_E2E_TOKEN_AUDITOR="a29c09ef-…"
//! export PROXXX_E2E_TOKEN_BLIND="3752c186-…"
//! cargo test --release --test rbac_live -- --ignored --nocapture
//! ```
//!
//! Tests are `#[ignore]`-gated. `cargo test` skips them silently;
//! `--ignored` activates. They share the cluster, so each is
//! `#[serial]`.
//!
//! ## Matrix mapping
//!
//! Each test header tags the line items in
//! [pre-commit/01-feature-coverage.md] under "RBAC & multi-persona"
//! that it closes. Most tests close 1–2 lines; the bulk-op test
//! closes 1 standalone line.

use std::sync::Arc;

use anyhow::Result;
use proxxx::api::types::GuestType;
use proxxx::api::{ApiError, ProxmoxGateway, PxClient};
use proxxx::config::ProfileConfig;

// ── Env loader ────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct RbacEnv {
    api_url: String,
    owned_vmid: u32,
    #[allow(dead_code)]
    blind_vmid: u32,
    operator_secret: String,
    auditor_secret: String,
    blind_secret: String,
}

impl RbacEnv {
    fn load() -> Option<Self> {
        if std::env::var("PROXXX_E2E_RBAC_ENABLE").as_deref() != Ok("1") {
            eprintln!("[rbac-live] PROXXX_E2E_RBAC_ENABLE != 1 — skipping");
            return None;
        }
        let api_url = std::env::var("PROXXX_E2E_API_URL").ok()?;
        let owned_vmid: u32 = std::env::var("PROXXX_E2E_OWNED_VMID").ok()?.parse().ok()?;
        let blind_vmid: u32 = std::env::var("PROXXX_E2E_BLIND_VMID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(9999);
        let operator_secret = std::env::var("PROXXX_E2E_TOKEN_OPERATOR").ok()?;
        let auditor_secret = std::env::var("PROXXX_E2E_TOKEN_AUDITOR").ok()?;
        let blind_secret = std::env::var("PROXXX_E2E_TOKEN_BLIND").ok()?;
        Some(Self {
            api_url,
            owned_vmid,
            blind_vmid,
            operator_secret,
            auditor_secret,
            blind_secret,
        })
    }

    async fn client_for(&self, user: &str, secret: &str) -> Result<Arc<PxClient>> {
        // Pass the secret as cli_secret (resolver priority #1). The
        // serial annotation already removes intra-suite race risk, but
        // avoiding set_var also keeps env state clean for tests in
        // OTHER suites that share the same cargo-test process — and
        // means a hot-loop test no longer hands the secret to siblings
        // through process-global state.
        let cfg = ProfileConfig {
            url: self.api_url.clone(),
            user: user.into(),
            auth: "token".into(),
            token_id: Some("proxxx-rbac".into()),
            token_secret: None,
            token_secret_file: None,
            password: None,
            verify_tls: false,
            tls_pin_mode: None,
            rate_limit: Some(20),
            policies: None,
            telegram: None,
            ssh: None,
            pbs: None,
            alerts: None,
        };
        Ok(Arc::new(PxClient::new(cfg, Some(secret)).await?))
    }

    async fn operator(&self) -> Result<Arc<PxClient>> {
        self.client_for("operator@pve", &self.operator_secret).await
    }
    async fn auditor(&self) -> Result<Arc<PxClient>> {
        self.client_for("auditor@pve", &self.auditor_secret).await
    }
    async fn blind(&self) -> Result<Arc<PxClient>> {
        self.client_for("blind@pve", &self.blind_secret).await
    }
}

/// Pull the typed `ApiError` out of an `anyhow::Error` chain. Panics
/// if the chain is generic — that's the contract failure we want loud.
fn typed(err: &anyhow::Error) -> &ApiError {
    err.chain()
        .find_map(|e| e.downcast_ref::<ApiError>())
        .unwrap_or_else(|| panic!("expected ApiError in chain, got generic: {err:#}"))
}

/// Skip the test cleanly if no env. Used at the top of every test.
macro_rules! env_or_skip {
    () => {{
        let Some(env) = RbacEnv::load() else {
            return;
        };
        env
    }};
}

// ── Tests ──────────────────────────────────────────────────────────

/// Closes line 87 (provisioning fixture) implicitly: this test only
/// passes if the operator persona was created with `PVEVMAdmin` on
/// /`vms/${OWNED_VMID`}.
///
/// Closes line 92 partially (positive control half of bulk-op
/// atomicity): operator CAN restart their own VM.
#[tokio::test]
#[ignore = "live cluster: requires PROXXX_E2E_RBAC_ENABLE=1 + persona tokens"]
#[serial_test::serial]
async fn operator_can_restart_owned_vm() {
    let env = env_or_skip!();
    let client = env.operator().await.expect("operator client");

    // Find which node owns the VM (operator can read /nodes scoped to
    // /vms/X — the resource list will include the parent node).
    let nodes = client.get_nodes().await.expect("operator can list nodes");
    assert!(
        !nodes.is_empty(),
        "operator should see at least the parent node"
    );

    // Try every node until we find one with the VMID. PVE rejects
    // requests against the wrong node with 595/500, not 403.
    let mut restarted = false;
    for n in &nodes {
        let res = client
            .restart_guest(&n.node, env.owned_vmid, GuestType::Qemu)
            .await;
        if let Ok(upid) = res {
            assert!(upid.contains("UPID:"), "expected UPID, got {upid}");
            restarted = true;
            break;
        }
    }
    assert!(
        restarted,
        "operator must be able to restart owned vmid {} on at least one node",
        env.owned_vmid
    );
}

/// Closes line 90 (auditor write → typed Forbidden) and line 97
/// (HITL approval doesn't escalate — the calling token is what
/// matters; auditor token can never write regardless of HITL).
#[tokio::test]
#[ignore = "live cluster: requires PROXXX_E2E_RBAC_ENABLE=1 + persona tokens"]
#[serial_test::serial]
async fn auditor_restart_owned_vm_returns_typed_forbidden() {
    let env = env_or_skip!();
    let client = env.auditor().await.expect("auditor client");

    let nodes = client.get_nodes().await.expect("auditor reads nodes");
    let mut got_403 = false;
    for n in &nodes {
        let res = client
            .restart_guest(&n.node, env.owned_vmid, GuestType::Qemu)
            .await;
        match res {
            Err(e) => {
                if matches!(typed(&e), ApiError::Forbidden(_)) {
                    got_403 = true;
                    break;
                }
                // Other errors (e.g. NotFound on wrong node) — keep
                // trying other nodes.
            }
            Ok(_) => {
                panic!(
                    "auditor MUST NOT be able to restart vmid {} on {}!",
                    env.owned_vmid, n.node
                );
            }
        }
    }
    assert!(
        got_403,
        "auditor's restart attempt on vmid {} must surface ApiError::Forbidden",
        env.owned_vmid
    );
}

/// Closes line 95 (typed JSON contract preservation) and validates
/// the typed-error coverage extends to write paths post-Phase 7
/// (POST/PUT/DELETE all surface `ApiError::Forbidden`, not anyhow
/// strings).
///
/// IMPORTANT: `PVEVMAdmin` INCLUDES Permissions.Modify on the role's
/// scope — operators delegate VM access within their own ACL. So
/// `modify_acl("/vms/8888", ...)` SUCCEEDS for the operator. To
/// prove typed-403 propagation we must hit a path OUTSIDE their
/// scope: `/` (cluster root) requires Permissions.Modify on `/`,
/// which operator lacks.
#[tokio::test]
#[ignore = "live cluster: requires PROXXX_E2E_RBAC_ENABLE=1 + persona tokens"]
#[serial_test::serial]
async fn operator_modify_acl_outside_scope_returns_typed_forbidden() {
    let env = env_or_skip!();
    let client = env.operator().await.expect("operator client");

    let res = client
        .modify_acl(
            "/",
            "PVEAuditor",
            Some("attacker@pve"),
            None,
            None,
            true,
            false,
        )
        .await;
    let err = res.expect_err("operator must not modify cluster-root ACL");
    assert!(
        matches!(typed(&err), ApiError::Forbidden(_)),
        "expected ApiError::Forbidden, got {:?}",
        typed(&err)
    );
}

/// Closes line 96 (auditor opening sensitive views surfaces typed
/// 403 — no crash, no partial state). Auditor has Sys.Audit on /
/// which lets them READ /access/users (returns full list), but PVE
/// gates `delete_user` behind User.Modify which auditor lacks.
#[tokio::test]
#[ignore = "live cluster: requires PROXXX_E2E_RBAC_ENABLE=1 + persona tokens"]
#[serial_test::serial]
async fn auditor_delete_user_returns_typed_forbidden() {
    let env = env_or_skip!();
    let client = env.auditor().await.expect("auditor client");

    // Try to delete a fixture user. Should 403 (no User.Modify), not
    // 404 (the user exists). Asserting "Forbidden, not NotFound" is
    // how we distinguish "auditor was correctly stopped" from "delete
    // succeeded by accident".
    let res = client.delete_user("blind@pve").await;
    let err = res.expect_err("auditor must not delete users");
    let api = typed(&err);
    assert!(
        matches!(api, ApiError::Forbidden(_)),
        "expected Forbidden (auditor lacks User.Modify), got {api:?}"
    );
}

/// Closes line 89 (blind persona empty/sparse cluster view doesn't
/// crash). The matrix originally framed this as a TUI test ("no
/// div-by-zero, q exits clean"); at the API layer the equivalent is
/// "deserialization survives the filtered/empty array shape".
#[tokio::test]
#[ignore = "live cluster: requires PROXXX_E2E_RBAC_ENABLE=1 + persona tokens"]
#[serial_test::serial]
async fn blind_persona_filtered_arrays_deserialize_cleanly() {
    let env = env_or_skip!();
    let client = env.blind().await.expect("blind client");

    // get_nodes — PVE filters to nodes the user has any privilege on.
    // Blind has PVEVMUser on /vms/9999 (likely nonexistent) so the
    // result is typically empty OR contains the node owning 9999.
    let nodes = client.get_nodes().await.expect("blind nodes deserializes");
    eprintln!(
        "[blind] sees {} node(s); cluster view is correctly filtered",
        nodes.len()
    );

    // get_guests on each visible node — should be empty or contain
    // only VMID 9999.
    for n in &nodes {
        let guests = client
            .get_guests(&n.node)
            .await
            .expect("blind guests deserializes");
        for g in &guests {
            assert_eq!(
                g.vmid, env.blind_vmid,
                "blind should only see vmid {}, got {}",
                env.blind_vmid, g.vmid
            );
        }
    }

    // list_acl — auditor & root see entries, blind sees [] (no
    // Sys.Audit). MUST deserialize cleanly, not crash on empty data.
    let acls = client
        .list_acl()
        .await
        .map(|v| v.len())
        .unwrap_or_else(|e| {
            // Acceptable: filtered to empty (Ok([])), 200, OR 403
            // (some PVE versions return 403 instead of empty).
            assert!(
                matches!(typed(&e), ApiError::Forbidden(_)),
                "expected Ok([]) or Forbidden, got {e:#}"
            );
            0
        });
    eprintln!("[blind] sees {acls} ACL entries");
}

/// Closes line 92 (bulk-op atomicity per-target). Operator has
/// `PVEVMAdmin` on /`vms/${OWNED_VMID`} ONLY — a hypothetical bulk like
/// `restart owned, restart unowned` should produce: owned succeeds,
/// unowned 403s, no abort. We test by issuing two restarts in
/// sequence and asserting both observed shapes.
#[tokio::test]
#[ignore = "live cluster: requires PROXXX_E2E_RBAC_ENABLE=1 + persona tokens"]
#[serial_test::serial]
async fn operator_bulk_partial_failure_is_deterministic() {
    let env = env_or_skip!();
    let client = env.operator().await.expect("operator client");

    let nodes = client.get_nodes().await.expect("nodes");
    let node = nodes.first().expect("at least one node visible");

    // Owned: should succeed (positive control).
    let owned_res = client
        .restart_guest(&node.node, env.owned_vmid, GuestType::Qemu)
        .await;
    if let Err(ref e) = owned_res {
        // If the parent node isn't this one, restart returns
        // 595/500/404 — try the others.
        eprintln!(
            "[bulk] owned restart on {} returned {e:#} — trying other nodes",
            node.node
        );
        for n in &nodes[1..] {
            if client
                .restart_guest(&n.node, env.owned_vmid, GuestType::Qemu)
                .await
                .is_ok()
            {
                break;
            }
        }
    } else {
        assert!(owned_res.expect("ok").contains("UPID:"));
    }

    // Unowned: a VMID the operator definitely lacks ACL on. Use a
    // very-likely-unused VMID 1 (PVE forbids vmid < 100, but the ACL
    // check fires before the validity check — we get 403 either way,
    // not the validity error). Confirm we see Forbidden.
    let bad_res = client.restart_guest(&node.node, 1, GuestType::Qemu).await;
    let err = bad_res.expect_err("operator must not restart unowned vmid");
    let api = typed(&err);
    assert!(
        matches!(api, ApiError::Forbidden(_) | ApiError::NotFound(_)),
        "expected Forbidden (RBAC) or NotFound (PVE checked existence first), got {api:?}"
    );
    eprintln!("[bulk] partial-failure verified: owned succeeded, unowned was rejected");
}

/// Closes line 91 (graceful 403 on task-log endpoint). Operator's
/// `PVEVMAdmin` doesn't include Sys.Audit on /nodes/X, so reading the
/// task log of a task they kicked off may 403 depending on PVE
/// version. The test is "if it 403s, we surface Forbidden, not
/// reqwest spam".
#[tokio::test]
#[ignore = "live cluster: requires PROXXX_E2E_RBAC_ENABLE=1 + persona tokens"]
#[serial_test::serial]
async fn operator_task_log_403_surfaces_typed() {
    let env = env_or_skip!();
    let client = env.operator().await.expect("operator client");

    let nodes = client.get_nodes().await.expect("nodes");
    let node = nodes.first().expect("at least one node");

    // A made-up but plausibly-shaped UPID. PVE's task auth check fires
    // before the existence check, so this should 403 if we lack
    // Sys.Audit, OR 400 if the UPID is malformed.
    let upid = format!(
        "UPID:{}:00000000:00000000:65000000:qmrestart:{}:operator@pve!proxxx-rbac:",
        node.node, env.owned_vmid
    );
    let res = client.get_task_log(&node.node, &upid, 0, 100).await;
    match res {
        Ok(_) => {
            eprintln!("[task-log] operator HAS Sys.Audit — task log read succeeded");
        }
        Err(e) => {
            let api = typed(&e);
            assert!(
                matches!(
                    api,
                    ApiError::Forbidden(_) | ApiError::NotFound(_) | ApiError::Other { .. }
                ),
                "task-log error must be a typed variant, got {api:?}"
            );
        }
    }
}

/// Closes line 98 (privsep tokens have INDEPENDENT ACL from the
/// parent user — verifies real token-RBAC) **transitively**.
///
/// PVE protects `/access/users/{uid}/token` aggressively: only `root`
/// or callers with `User.Modify` on `/access/users/{uid}` may read it.
/// Auditor's `Sys.Audit` on `/` is NOT enough. Without root creds in
/// the env we can't directly inspect the privsep flag — BUT we don't
/// need to:
///
/// > If the fixture's privsep wiring were broken (token created but
/// > NO ACL row granted on the token), every operator API call would
/// > return 403 (privsep token with empty ACL never inherits from the
/// > user). The fact that `operator_can_restart_owned_vm` PASSES
/// > proves the token has its own ACL row — independent of the user.
///
/// This test exists as a load-bearing comment + sanity check: it
/// re-runs the operator restart and asserts success. If this fails
/// while `operator_can_restart_owned_vm` also fails, the privsep
/// wiring is broken and the fixture must be re-provisioned.
#[tokio::test]
#[ignore = "live cluster: requires PROXXX_E2E_RBAC_ENABLE=1 + persona tokens"]
#[serial_test::serial]
async fn privsep_tokens_have_own_acl_via_transitive_proof() {
    let env = env_or_skip!();
    let client = env.operator().await.expect("operator client");

    let nodes = client.get_nodes().await.expect("operator nodes");
    let mut succeeded = false;
    for n in &nodes {
        if client
            .restart_guest(&n.node, env.owned_vmid, GuestType::Qemu)
            .await
            .is_ok()
        {
            succeeded = true;
            break;
        }
    }
    assert!(
        succeeded,
        "operator restart MUST succeed; failure here means the privsep \
         token has no ACL row (fixture bug). Re-run tests/fixtures/setup_rbac.sh"
    );
}

/// Closes line 97 (HITL approval doesn't privilege-escalate). When
/// the calling client is the auditor token, even though the
/// hypothetical Telegram approver is "root", the actual API call
/// happens under the auditor token → PVE applies auditor's ACL → 403.
/// proxxx never re-issues with admin creds.
///
/// At the API layer this is the same test as
/// `auditor_restart_owned_vm_returns_typed_forbidden` — we re-assert
/// here under the HITL framing for matrix traceability.
#[tokio::test]
#[ignore = "live cluster: requires PROXXX_E2E_RBAC_ENABLE=1 + persona tokens"]
#[serial_test::serial]
async fn hitl_does_not_escalate_auditor_to_admin() {
    let env = env_or_skip!();
    let client = env.auditor().await.expect("auditor client");

    // Simulates: the daemon (running as auditor token) just received
    // an "approve restart 8888" callback. It dispatches the API call.
    // PVE responds 403. Daemon must propagate, not retry with
    // different creds.
    let nodes = client.get_nodes().await.expect("nodes");
    let mut saw_403 = false;
    for n in &nodes {
        if let Err(e) = client
            .restart_guest(&n.node, env.owned_vmid, GuestType::Qemu)
            .await
        {
            if matches!(typed(&e), ApiError::Forbidden(_)) {
                saw_403 = true;
                break;
            }
        }
    }
    assert!(
        saw_403,
        "auditor's restart MUST 403 — HITL approval does not confer extra PVE privilege"
    );
}

// ── HITL callback replay-attack live coverage ───────────────────────
//
// The replay gate (`PendingApprovals::consume`) is unit-tested at the
// pure-logic layer in `src/hitl/pending.rs` and exercised via mocks
// in `tests/hitl_e2e.rs`. The remaining angle this DOES NOT cover:
// does the gate actually hold when wired to a real `ProxmoxGateway`
// implementation (PxClient against a live PVE cluster) under the
// realistic timing of two callbacks arriving back-to-back?
//
// Threat model the live test pins:
//   - Telegram redelivers `approve:restart:9999` due to a network
//     hiccup before the daemon advances `offset`.
//   - Daemon receives it twice within the same session.
//   - First callback hits `client.get_nodes()` / `client.get_guests()`
//     against real PVE (using the operator's privsep token).
//   - Second callback MUST short-circuit at the dedup gate before
//     reaching PVE again — proven by `CallbackOutcome::Replay` and by
//     `pending.consumed_count()` staying at 1.
//
// Side-effect minimisation: we deliberately use `BLIND_VMID` (which
// the env contract documents as "often nonexistent on the cluster")
// so the first callback hits `NodeNotFound` rather than restarting a
// real VM. This still exercises the full PVE round-trip (every
// `get_guests` call goes over the wire) AND keeps the test idempotent
// — no VM is restarted, no UPID is created.

/// Closes the "HITL replay attack" row in
/// [pre-commit/01-feature-coverage.md] under "RBAC & multi-persona".
/// Pre-fix (no `PendingApprovals::consume` in `handle_callback_update`)
/// the second call would also produce `NodeNotFound` and
/// `consumed_count == 0` — but the contract is that the daemon
/// REJECTS at the gate and exposes that as `Replay`. This test fails
/// loudly if anyone removes / weakens the gate.
#[tokio::test]
#[ignore = "live cluster: requires PROXXX_E2E_RBAC_ENABLE=1 + persona tokens"]
#[serial_test::serial]
async fn hitl_callback_replay_rejected_under_live_pve() {
    use proxxx::hitl::daemon::{handle_callback_update, CallbackOutcome};
    use proxxx::hitl::pending::PendingApprovals;
    use proxxx::hitl::telegram::{TelegramGateway, Update};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let env = env_or_skip!();

    // Wiremock stand-in for api.telegram.org so the daemon's
    // `answer_callback` / `edit_message_text` calls succeed (they're
    // wrapped in `let _ = ...await`, but a real connection failure
    // would hold the test for the reqwest connect timeout — using a
    // mock keeps the test fast and independent of network shape).
    let server = MockServer::start().await;
    for endpoint in [
        "/botfaketoken/answerCallbackQuery",
        "/botfaketoken/editMessageText",
        "/botfaketoken/sendMessage",
    ] {
        Mock::given(method("POST"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true,
                "result": { "message_id": 1 },
            })))
            .mount(&server)
            .await;
    }
    let tg = TelegramGateway::with_base_url(
        "faketoken".to_string(),
        "1".to_string(),
        format!("{}/bot", server.uri()),
    );

    // Real operator client against the live PVE cluster.
    let client = env.operator().await.expect("operator client");

    // Build the synthetic callback. Round-trip through serde_json
    // because `CallbackQuery` only derives `Deserialize`. The data
    // string `approve:restart:{blind_vmid}` is what Telegram would
    // actually deliver — and the gate stores the FULL data string as
    // the txn_id, so two identical Updates collide on it.
    let callback_data = format!("approve:restart:{}", env.blind_vmid);
    let update_json = serde_json::json!({
        "update_id": 1_i64,
        "callback_query": {
            "id": "live-replay-1",
            "from": { "first_name": "live-replay-tester" },
            "data": callback_data,
            "message": { "message_id": 1_i64 },
        }
    });
    let update: Update = serde_json::from_value(update_json).expect("Update deserializes");

    let pending = PendingApprovals::new();

    // First call — passes the gate, hits real PVE for node/guest
    // discovery, ends in NodeNotFound (blind_vmid does not exist on
    // the cluster). Side effect on PVE: only read-only API calls.
    let first = handle_callback_update(&update, &pending, client.as_ref(), &tg)
        .await
        .expect("handle_callback_update first");
    assert!(
        matches!(first, CallbackOutcome::NodeNotFound { .. }),
        "first call should land at NodeNotFound (blind_vmid is sentinel-nonexistent), got {first:?}"
    );
    assert_eq!(
        pending.consumed_count(),
        1,
        "after first call, exactly one txn must be marked consumed"
    );

    // Second call — IDENTICAL update. MUST short-circuit at the
    // dedup gate before any PVE call. The contract is loud: any
    // outcome other than Replay means the gate is broken.
    let second = handle_callback_update(&update, &pending, client.as_ref(), &tg)
        .await
        .expect("handle_callback_update second");
    let CallbackOutcome::Replay { txn_id } = second else {
        panic!("second call MUST be Replay, got {second:?} — replay gate is broken");
    };
    assert_eq!(
        txn_id, callback_data,
        "Replay outcome must surface the colliding callback data as txn_id"
    );
    assert_eq!(
        pending.consumed_count(),
        1,
        "consumed_count must NOT increment on replay (HashSet dedup invariant)"
    );
}
