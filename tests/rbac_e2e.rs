#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]
//! Phase 7 — RBAC fixture closing the 3 deferred RBAC invariants in
//! [pre-commit/03-security-invariants.md]:
//!
//! 1. **Destructive op by `operator` on unowned VM returns HTTP 403** —
//!    asserts proxxx surfaces `ApiError::Forbidden` (typed, not generic
//!    anyhow), so callers can match on it.
//! 2. **`operator` cannot view global ACLs/Tokens (returns HTTP 403 /
//!    empty)** — asserts that 403 propagates as typed error AND that
//!    PVE's "filtered 200 with empty array" response shape (returned
//!    when the user can see *some* but not all entries) deserializes
//!    cleanly to an empty Vec, not a panic or parse error.
//! 3. **Token without Privilege Separation maps to user rights
//!    accurately** — asserts proxxx's wire format for `privsep` is
//!    correct in both directions: `create_token(privsep=false)`
//!    sends `privsep=0`, and `list_user_tokens` deserializes
//!    `privsep=0` as `false`. The actual ACL inheritance is
//!    PVE-side; proxxx must not silently rewrite the flag.
//!
//! ## Persona model
//!
//! The 4-persona convention from
//! `memory/project_rbac_e2e.md` —
//!
//! - `root@pam`     — full rights (covered by the Alpha/Beta scenarios)
//! - `operator@pve` — `PVEVMAdmin` on `/vms`; no `/nodes`, no `/access`
//! - `auditor@pve` — `PVEAuditor` global; read-only
//! - `blind@pve`   — `PVEVMUser` scoped to a single VMID; sees one VM,
//!   nothing else
//!
//! Each test names the persona it simulates so the matrix-to-test map
//! is searchable: `grep operator_` finds every operator-scoped case.
//!
//! ## Fixture layering
//!
//! Wiremock represents PVE's *response*, not its decision logic. Each
//! test sets up the response shape PVE would return for a given persona
//! and asserts proxxx's reaction:
//!
//! - 403 → `ApiError::Forbidden`
//! - 200 with filtered array → `Ok(Vec)` (possibly empty)
//! - 200 with privsep=0 → `ApiToken { privsep: false, … }`

use proxxx::api::{ApiError, ProxmoxGateway, PxClient};
use proxxx::config::ProfileConfig;
use wiremock::matchers::{body_string_contains, header_exists, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

// ── Shared scaffolding ─────────────────────────────────────────────────

/// Build a `PxClient` pointed at the wiremock server. The `user` arg
/// flows into the configured profile so the client picks the right auth
/// header shape (token-auth uses the user as the principal).
async fn persona_client(server: &MockServer, user: &str) -> PxClient {
    // Pass the secret as cli_secret (resolver priority #1) instead of
    // mutating PROXXX_TOKEN_SECRET. Env state is process-global and
    // cargo runs integration tests in parallel — set_var would race
    // with any test that observes the env var.
    let cfg = ProfileConfig {
        url: server.uri(),
        user: user.into(),
        auth: "token".into(),
        token_id: Some("rbac-test".into()),
        token_secret: None,
        token_secret_file: None,
        password: None,
        verify_tls: false,
        tls_pin_mode: None,
        rate_limit: Some(100),
        policies: None,
        telegram: None,
        ssh: None,
        pbs: None,
        alerts: None,
        mcp_token: None,
        profile_name: None,
    };
    PxClient::new(cfg, Some("fake-secret"))
        .await
        .expect("client builds")
}

/// Stock 403 response in PVE's standard envelope.
fn pve_403(message: &str) -> ResponseTemplate {
    ResponseTemplate::new(403).set_body_json(serde_json::json!({
        "data": null,
        "errors": { "permission": message },
    }))
}

/// Extract the typed `ApiError` from an `anyhow::Error`. Panics if the
/// chain doesn't carry one — that's the contract failure we want loud.
fn typed(err: &anyhow::Error) -> &ApiError {
    err.chain()
        .find_map(|e| e.downcast_ref::<ApiError>())
        .unwrap_or_else(|| panic!("expected ApiError in chain, got generic: {err:#}"))
}

// ── Invariant 1 — operator destructive on unowned VM → typed 403 ───────

/// Set-up: operator persona attempts to DELETE vmid 100. PVE returns
/// 403 (no VM.Allocate on /vms/100).
/// Expected: proxxx surfaces `ApiError::Forbidden`, callers can match.
#[tokio::test]
async fn operator_delete_unowned_vm_returns_typed_forbidden() {
    let server = MockServer::start().await;

    // delete_guest does a pre-flight status check; mock that as
    // "stopped" so the dispatch reaches the actual DELETE call.
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/qemu/100/status/current"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "vmid": 100,
                "name": "vm-prod-100",
                "status": "stopped",
                "type": "qemu",
                "node": "pve1"
            }
        })))
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path("/api2/json/nodes/pve1/qemu/100"))
        .respond_with(pve_403("Permission check failed (/vms/100, VM.Allocate)"))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "operator@pve").await;
    let err = c
        .delete_guest("pve1", 100, proxxx::api::types::GuestType::Qemu)
        .await
        .expect_err("operator cannot delete unowned VM");

    let api_err = typed(&err);
    assert!(
        matches!(api_err, ApiError::Forbidden(_)),
        "expected Forbidden, got {api_err:?}"
    );
    let msg = format!("{api_err}");
    assert!(
        msg.contains("VM.Allocate"),
        "PVE's permission detail must surface in the error: {msg}"
    );
}

/// Set-up: operator attempts a stop on vmid 100. PVE returns 403.
/// Expected: typed Forbidden.
#[tokio::test]
async fn operator_stop_unowned_vm_returns_typed_forbidden() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api2/json/nodes/pve1/qemu/100/status/stop"))
        .respond_with(pve_403("Permission check failed (/vms/100, VM.PowerMgmt)"))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "operator@pve").await;
    let err = c
        .stop_guest("pve1", 100, proxxx::api::types::GuestType::Qemu, false)
        .await
        .expect_err("operator cannot stop unowned VM");

    assert!(matches!(typed(&err), ApiError::Forbidden(_)));
}

/// Positive-path control: the same operator stopping a VM they DO own
/// gets 200 OK. Without this, the "403 on unowned" assertion above
/// could just be "always 403", which is not the invariant.
#[tokio::test]
async fn operator_can_stop_owned_vm() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api2/json/nodes/pve1/qemu/200/status/stop"))
        // Verify the client actually sends the Authorization header so this
        // test catches RBAC regressions, not just mock-level wiring.
        .and(header_exists("authorization"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": "UPID:pve1:00000001:00000001:test:qmstop:200:operator@pve!rbac-test:"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "operator@pve").await;
    let upid = c
        .stop_guest("pve1", 200, proxxx::api::types::GuestType::Qemu, false)
        .await
        .expect("operator can stop owned VM");
    assert!(upid.contains("UPID:"));
}

// ── Invariant 2 — global ACL/Token views: 403 / filtered-empty ────────

/// 403 propagates as typed Forbidden — caller can match and surface a
/// "you lack global access" hint instead of an opaque error.
#[tokio::test]
async fn operator_list_acl_403_propagates_as_typed_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/access/acl"))
        .respond_with(pve_403("Permission check failed (/access/acl, Sys.Audit)"))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "operator@pve").await;
    let err = c.list_acl().await.expect_err("operator cannot read ACL");

    assert!(matches!(typed(&err), ApiError::Forbidden(_)));
}

#[tokio::test]
async fn operator_list_users_403_propagates_as_typed_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/access/users"))
        .respond_with(pve_403("Permission check failed (/access, User.Modify)"))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "operator@pve").await;
    let err = c
        .list_users()
        .await
        .expect_err("operator cannot read users");
    assert!(matches!(typed(&err), ApiError::Forbidden(_)));
}

/// PVE often returns 200 with a *filtered* array (entries the caller
/// CAN see, others omitted). For a persona with no global Sys.Audit
/// the filter strips everything — the response is `{"data": []}`. This
/// MUST deserialize as an empty Vec, never as a parse error or `null`
/// panic. Auditor scenario.
#[tokio::test]
async fn auditor_list_acl_filtered_to_empty_deserializes_cleanly() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/access/acl"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "auditor@pve").await;
    let acls = c.list_acl().await.expect("empty array deserializes");
    assert!(acls.is_empty(), "expected empty Vec, got {acls:?}");
}

/// Auditor sees a *partial* ACL — only entries on paths they can audit.
/// Proxxx must not assume the response is exhaustive; this just
/// asserts deserialization survives.
#[tokio::test]
async fn auditor_list_acl_filtered_partial_subset_deserializes() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/access/acl"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {
                    "path": "/vms/200",
                    "type": "user",
                    "ugid": "operator@pve",
                    "roleid": "PVEVMAdmin",
                    "propagate": 1
                }
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "auditor@pve").await;
    let acls = c.list_acl().await.expect("partial array deserializes");
    assert_eq!(acls.len(), 1);
    assert_eq!(acls[0].roleid, "PVEVMAdmin");
    assert!(acls[0].propagate);
}

// ── Invariant 3 — token privsep wire-format contract ───────────────────

/// `create_token(privsep=false)` MUST send `privsep=0` in the form body.
/// The opposite (always sending `privsep=1`, defensively) would
/// silently isolate every token from its parent user's ACL — operators
/// would create tokens believing they inherit user rights and find
/// every call returns 403.
#[tokio::test]
async fn create_token_no_privsep_sends_privsep_zero() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api2/json/access/users/operator%40pve/token/inherit"))
        .and(body_string_contains("privsep=0"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "info": {
                    "tokenid": "inherit",
                    "privsep": 0,
                    "comment": "",
                    "expire": 0
                },
                "value": "00000000-1111-2222-3333-444444444444"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "root@pam").await;
    let tok = c
        .create_token("operator@pve", "inherit", false, None, None)
        .await
        .expect("create_token succeeds");
    assert!(!tok.privsep, "round-tripped privsep must be false");
    assert_eq!(
        tok.value.as_deref(),
        Some("00000000-1111-2222-3333-444444444444")
    );
}

/// Mirror image: `create_token(privsep=true)` MUST send `privsep=1`.
#[tokio::test]
async fn create_token_with_privsep_sends_privsep_one() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(
            "/api2/json/access/users/operator%40pve/token/isolated",
        ))
        .and(body_string_contains("privsep=1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "info": {
                    "tokenid": "isolated",
                    "privsep": 1,
                    "comment": "",
                    "expire": 0
                },
                "value": "ffffffff-1111-2222-3333-444444444444"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "root@pam").await;
    let tok = c
        .create_token("operator@pve", "isolated", true, None, None)
        .await
        .expect("create_token succeeds");
    assert!(tok.privsep, "round-tripped privsep must be true");
}

/// `list_user_tokens` deserializes a mixed-privsep list correctly.
/// PVE returns `privsep` as `0` or `1` (int), not `false`/`true`; the
/// `deserialize_bool_from_int` shim in `types.rs` is what we're
/// asserting actually fires.
#[tokio::test]
async fn list_user_tokens_deserializes_mixed_privsep() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/access/users/operator%40pve/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                { "tokenid": "inherit",  "privsep": 0, "comment": "", "expire": 0 },
                { "tokenid": "isolated", "privsep": 1, "comment": "", "expire": 0 }
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "root@pam").await;
    let tokens = c
        .list_user_tokens("operator@pve")
        .await
        .expect("list deserializes");
    assert_eq!(tokens.len(), 2);
    let inherit = tokens
        .iter()
        .find(|t| t.tokenid == "inherit")
        .expect("inherit");
    let isolated = tokens
        .iter()
        .find(|t| t.tokenid == "isolated")
        .expect("isolated");
    assert!(!inherit.privsep, "privsep=0 → false");
    assert!(isolated.privsep, "privsep=1 → true");
    // List response NEVER carries the secret value — a regression here
    // means proxxx would log/cache long-lived secrets.
    assert!(inherit.value.is_none(), "list must not expose secret");
    assert!(isolated.value.is_none());
}

/// Behavioural assertion of the privsep contract: a token with
/// `privsep=0` whose parent user lacks privilege still receives a 403
/// from PVE — proxxx must not paper over it. (PVE applies the user's
/// effective ACL; we just verify proxxx doesn't add extra logic on
/// top of the wire response.)
///
/// Without this, a `privsep=0` token might be assumed by callers to
/// "always succeed" — when in reality it inherits the user's
/// limitations.
#[tokio::test]
async fn privsep_zero_token_still_403s_when_user_lacks_privilege() {
    let server = MockServer::start().await;
    // Wiremock plays the part of PVE's RBAC: even though the token has
    // privsep=0 (would inherit user ACL), the user `operator@pve` lacks
    // /access privileges, so the call returns 403.
    Mock::given(method("GET"))
        .and(path("/api2/json/access/users"))
        .respond_with(pve_403("Permission check failed (/access, User.Modify)"))
        .expect(1)
        .mount(&server)
        .await;

    // The auth principal is the token: `operator@pve!inherit`.
    let c = persona_client(&server, "operator@pve").await;
    let err = c
        .list_users()
        .await
        .expect_err("privsep=0 does not bypass parent user's ACL");
    assert!(matches!(typed(&err), ApiError::Forbidden(_)));
}

// ── Bonus: blind persona — empty cluster doesn't crash callers ────────

/// `blind@pve` scoped to a single VMID sees `[]` from `/cluster/resources`-
/// style aggregations because PVE filters out resources the caller can't
/// see. Proxxx aggregations (`cpu_pct`, `mem_pct`) MUST guard against
/// zero-divisors. We assert at the data layer: empty `get_nodes` returns
/// `Ok(vec![])`, never a panic.
#[tokio::test]
async fn blind_persona_empty_node_list_does_not_panic() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "blind@pve").await;
    let nodes = c.get_nodes().await.expect("empty array deserializes");
    assert!(nodes.is_empty());
    // Sanity: the dashboard aggregation `total_maxcpu = nodes.iter()
    // .map(|n| n.maxcpu).sum()` on empty input gives 0; the renderer
    // guards `if total_maxcpu > 0`. We assert the data-layer half here;
    // the renderer half is the `if total_maxcpu > 0` invariant in
    // `tui/views/dashboard.rs:93`.
    let total_maxcpu: u32 = nodes.iter().map(|n| n.maxcpu).sum();
    assert_eq!(total_maxcpu, 0, "empty cluster aggregates to 0");
}

/// Same as above but for `/cluster/status` — used by the `cluster_status`
/// trait method in `ProxmoxGateway`. PVE returns `{"data": []}` for a
/// caller with zero cluster privileges.
#[tokio::test]
async fn blind_persona_empty_cluster_status_does_not_panic() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/cluster/status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "blind@pve").await;
    let entries = c
        .cluster_status()
        .await
        .expect("empty cluster_status deserializes");
    assert!(entries.is_empty());
}

// ── Bonus: 403 on /access/acl-write surfaces typed too ────────────────

/// `modify_acl` is a write — same-shape 403 must propagate as
/// `ApiError::Forbidden`. Operator persona tries to grant a role; PVE
/// refuses because they lack Permissions.Modify on the path.
#[tokio::test]
async fn operator_modify_acl_403_propagates_as_typed_error() {
    let server = MockServer::start().await;
    Mock::given(method("PUT"))
        .and(path("/api2/json/access/acl"))
        .respond_with(pve_403(
            "Permission check failed (/access/acl, Permissions.Modify)",
        ))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "operator@pve").await;
    let err = c
        .modify_acl(
            "/vms/100",
            "PVEVMUser",
            Some("attacker@pve"),
            None,
            None,
            true,
            false,
        )
        .await
        .expect_err("operator cannot grant ACLs");
    assert!(matches!(typed(&err), ApiError::Forbidden(_)));
}

// ── Audit-trail helper ─────────────────────────────────────────────────

/// Smoke check on the request body matcher we used above — if wiremock
/// silently changes the form encoding, the privsep tests would all
/// pass falsely. This snapshots the encoding once.
#[tokio::test]
async fn create_token_form_encoding_includes_privsep_kv() {
    let server = MockServer::start().await;
    let captured: std::sync::Arc<std::sync::Mutex<Option<String>>> =
        std::sync::Arc::new(std::sync::Mutex::new(None));
    let captured_clone = std::sync::Arc::clone(&captured);

    Mock::given(method("POST"))
        .and(path("/api2/json/access/users/u%40pve/token/t1"))
        .respond_with(move |req: &Request| {
            let body = String::from_utf8_lossy(&req.body).to_string();
            *captured_clone.lock().unwrap() = Some(body);
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "info": { "tokenid": "t1", "privsep": 0, "comment": "", "expire": 0 },
                    "value": "00000000-aaaa-bbbb-cccc-deadbeefdead"
                }
            }))
        })
        .mount(&server)
        .await;

    let c = persona_client(&server, "root@pam").await;
    let _ = c
        .create_token("u@pve", "t1", false, None, None)
        .await
        .expect("create");

    let body = captured.lock().unwrap().clone().expect("body captured");
    assert!(
        body.contains("privsep=0"),
        "expected privsep=0 in form body, got: {body}"
    );
    // We also expect it to NOT contain privsep=1 (no double-set).
    assert!(
        !body.contains("privsep=1"),
        "must not double-set privsep: {body}"
    );
}

// ════════════════════════════════════════════════════════════════════════
// Phase 8 — read-path & scoped-visibility coverage per the v0.1.10 audit.
//
// The Phase 7 invariants above pinned three contracts (typed Forbidden
// on destructive 403; filtered-empty deserialization; privsep wire
// format). The audit identified a second class of gap: READ paths and
// visibility filtering per persona. Symptom: an operator/auditor/blind
// caller invoking `get_guests` / `get_guest_status` / `cluster_resources`
// could regress silently because nothing pinned what they're allowed to
// see. These 12 tests close that gap.
//
// PVE behaviour reference:
// - `/access/users`         : 403 without User.Modify on /access
// - `/access/acl`           : filtered 200 by visible path
// - `/nodes`                : filtered 200 by Sys.Audit on /nodes/{node}
// - `/nodes/{n}/qemu` (list): filtered 200 by VM.Audit on /vms/{vmid}
// - `/nodes/{n}/qemu/{v}/status/current` (per-VM read): 403 if no VM.Audit
// - `/cluster/resources`    : filtered 200 by union of visible paths
// ════════════════════════════════════════════════════════════════════════

// ── Operator persona (PVEVMAdmin on /vms, no /nodes, no /access) ──────

/// `/nodes` returns 200 with an empty filtered list for an operator
/// who has no Sys.Audit anywhere on `/nodes`. NOT a 403 — PVE prefers
/// filtering for collection endpoints. The dashboard aggregation MUST
/// survive zero-node input (also covered by the blind persona above,
/// but pinned here per-persona so a regression to "always 403 for
/// non-root" is caught).
#[tokio::test]
async fn operator_list_nodes_returns_filtered_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": []
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "operator@pve").await;
    let nodes = c.get_nodes().await.expect("filtered-empty deserializes");
    assert!(
        nodes.is_empty(),
        "operator without /nodes Sys.Audit sees []"
    );
}

/// `/nodes/pve1/qemu` returns 200 with a partial list — only VMIDs the
/// operator has VM.Audit on. Asserts proxxx doesn't filter further on
/// top of PVE's filter (no client-side ACL evaluation) and that the
/// shape deserializes with the operator's typical "I see 2 of 3"
/// reality.
#[tokio::test]
async fn operator_get_guests_filtered_to_owned_vms_only() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/qemu"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {"vmid": 200, "name": "vm-owned-200", "status": "running",
                 "type": "qemu", "node": "pve1"},
                {"vmid": 201, "name": "vm-owned-201", "status": "stopped",
                 "type": "qemu", "node": "pve1"}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;
    // get_guests also queries /lxc on the same node. PVE may return
    // empty filtered list there. Mock both to avoid 404 noise.
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/lxc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
        .mount(&server)
        .await;

    let c = persona_client(&server, "operator@pve").await;
    let guests = c
        .get_guests("pve1")
        .await
        .expect("partial list deserializes");
    assert_eq!(guests.len(), 2, "operator sees exactly the VMs they own");
    let vmids: Vec<u32> = guests.iter().map(|g| g.vmid).collect();
    assert!(vmids.contains(&200) && vmids.contains(&201));
    // Unowned VMID 100 (used in the destructive tests above) must NOT
    // appear in the operator's filtered list.
    assert!(
        !vmids.contains(&100),
        "filtered list must not leak unowned VMIDs"
    );
}

/// Regression: a failed `/qemu` (or `/lxc`) sub-fetch must surface as an ERROR,
/// not a silently-truncated list. The old code `if let Ok`-skipped a failed
/// sub-call and still returned `Ok`, so a transient `/qemu` failure dropped
/// every VM — which made a stopped VM flicker in/out of proxima's 5s poller.
#[tokio::test]
async fn get_guests_errors_on_partial_sub_fetch_failure() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/qemu"))
        .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/lxc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
        .mount(&server)
        .await;

    let c = persona_client(&server, "operator@pve").await;
    assert!(
        c.get_guests("pve1").await.is_err(),
        "a failed sub-fetch must error, never a silent partial list"
    );
}

/// Per-VM `status/current` is a path-scoped endpoint — for a VMID the
/// operator does NOT own, PVE returns 403 (no VM.Audit on /vms/100).
/// `get_guest_status` tries QEMU first then falls back to LXC, so both
/// paths must 403 to surface the typed error cleanly.
#[tokio::test]
async fn operator_get_guest_status_on_unowned_returns_typed_forbidden() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/qemu/100/status/current"))
        .respond_with(pve_403("Permission check failed (/vms/100, VM.Audit)"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/lxc/100/status/current"))
        .respond_with(pve_403("Permission check failed (/vms/100, VM.Audit)"))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "operator@pve").await;
    let err = c
        .get_guest_status("pve1", 100)
        .await
        .expect_err("operator cannot read unowned VM status");
    assert!(
        matches!(typed(&err), ApiError::Forbidden(_)),
        "expected Forbidden, got {:?}",
        typed(&err)
    );
}

/// `/cluster/resources` returns a partial union — only resources the
/// operator can audit on at least one path. The shape must include
/// owned VMs but NOT unowned ones, NOT nodes (no Sys.Audit on /nodes).
#[tokio::test]
async fn operator_cluster_resources_filtered_to_owned_vms() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/cluster/resources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {"id": "qemu/200", "type": "qemu", "node": "pve1",
                 "vmid": 200, "name": "vm-owned-200", "status": "running"},
                {"id": "qemu/201", "type": "qemu", "node": "pve1",
                 "vmid": 201, "name": "vm-owned-201", "status": "stopped"}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "operator@pve").await;
    let resources = c
        .get_cluster_resources(None)
        .await
        .expect("partial cluster_resources deserializes");
    assert_eq!(resources.len(), 2);
    assert!(resources.iter().all(|r| r.resource_type == "qemu"));
    // No node-type entries — operator lacks /nodes Sys.Audit.
    assert!(!resources.iter().any(|r| r.resource_type == "node"));
}

// ── Auditor persona (PVEAuditor global → read everything, write nothing) ─

/// Auditor with Sys.Audit on `/` reads the full guest list — no
/// filtering. Pins that PVE's "filtered list" path is NOT
/// short-circuiting on read for global-audit roles. Counterpart to
/// `operator_get_guests_filtered_to_owned_vms_only`.
#[tokio::test]
async fn auditor_get_guests_sees_full_list_via_audit_role() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/qemu"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {"vmid": 100, "name": "vm-prod-100",  "status": "running",
                 "type": "qemu", "node": "pve1"},
                {"vmid": 200, "name": "vm-owned-200", "status": "running",
                 "type": "qemu", "node": "pve1"},
                {"vmid": 999, "name": "vm-blind-999", "status": "stopped",
                 "type": "qemu", "node": "pve1"}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/lxc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
        .mount(&server)
        .await;

    let c = persona_client(&server, "auditor@pve").await;
    let guests = c.get_guests("pve1").await.expect("full list deserializes");
    assert_eq!(guests.len(), 3, "auditor sees every guest");
}

/// Auditor reads `/access/users` successfully — User.Modify is the
/// write permission; Sys.Audit on `/access` allows the read. Pins that
/// proxxx doesn't pre-gate on `User.Modify` for the read path.
#[tokio::test]
async fn auditor_list_users_returns_full_list() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/access/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {"userid": "root@pam", "enable": 1, "email": "", "comment": "",
                 "firstname": "", "lastname": "", "expire": 0},
                {"userid": "operator@pve", "enable": 1, "email": "", "comment": "",
                 "firstname": "", "lastname": "", "expire": 0},
                {"userid": "auditor@pve", "enable": 1, "email": "", "comment": "",
                 "firstname": "", "lastname": "", "expire": 0}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "auditor@pve").await;
    let users = c.list_users().await.expect("auditor reads /access/users");
    assert_eq!(users.len(), 3);
    let userids: Vec<&str> = users.iter().map(|u| u.userid.as_str()).collect();
    assert!(userids.contains(&"root@pam"));
    assert!(userids.contains(&"auditor@pve"));
}

/// Destructive verb under auditor must 403. `PVEAuditor` grants only
/// `*.Audit` privileges — no `VM.PowerMgmt`. Pins that the typed error
/// flows back through the write path the same way the operator's does.
#[tokio::test]
async fn auditor_stop_guest_returns_typed_forbidden() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api2/json/nodes/pve1/qemu/100/status/stop"))
        .respond_with(pve_403("Permission check failed (/vms/100, VM.PowerMgmt)"))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "auditor@pve").await;
    let err = c
        .stop_guest("pve1", 100, proxxx::api::types::GuestType::Qemu, false)
        .await
        .expect_err("auditor cannot stop VMs");
    assert!(matches!(typed(&err), ApiError::Forbidden(_)));
}

/// Snapshot creation requires VM.Snapshot — denied to auditor. The 403
/// must round-trip as typed Forbidden through the snapshot path, which
/// is a distinct PVE endpoint from `status/stop`. Without this, a regression
/// in the snapshot wiring (e.g. swallowing 403 as a transient error)
/// would not be caught by the existing operator-destructive tests.
#[tokio::test]
async fn auditor_create_snapshot_returns_typed_forbidden() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api2/json/nodes/pve1/qemu/100/snapshot"))
        .respond_with(pve_403("Permission check failed (/vms/100, VM.Snapshot)"))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "auditor@pve").await;
    let err = c
        .create_snapshot(
            "pve1",
            100,
            proxxx::api::types::GuestType::Qemu,
            "test-snap",
        )
        .await
        .expect_err("auditor cannot snapshot");
    assert!(matches!(typed(&err), ApiError::Forbidden(_)));
}

// ── Blind persona (PVEVMUser on /vms/999 only — sees ONE thing) ───────

/// Blind persona scoped to VMID 999 sees a single-entry filtered list
/// from `get_guests`, not an empty one (`blind_persona_empty_node_list_*`
/// covers the all-empty case for `/nodes`). The list must round-trip
/// through the Vec<Guest> deserializer; the renderer must handle "1 VM,
/// 0 nodes" without zero-divide.
#[tokio::test]
async fn blind_get_guests_returns_only_scoped_vmid() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/qemu"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {"vmid": 999, "name": "vm-blind-999", "status": "running",
                 "type": "qemu", "node": "pve1"}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/lxc"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
        .mount(&server)
        .await;

    let c = persona_client(&server, "blind@pve").await;
    let guests = c
        .get_guests("pve1")
        .await
        .expect("single-entry deserializes");
    assert_eq!(guests.len(), 1);
    assert_eq!(guests[0].vmid, 999);
    assert_eq!(guests[0].name, "vm-blind-999");
}

/// `get_guest_status` on the scoped VMID succeeds — blind has VM.Audit
/// on `/vms/999`. Positive control alongside the next 403 test.
#[tokio::test]
async fn blind_get_guest_status_on_scoped_vmid_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/qemu/999/status/current"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "vmid": 999, "name": "vm-blind-999", "status": "running",
                "type": "qemu", "node": "pve1"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "blind@pve").await;
    let guest = c
        .get_guest_status("pve1", 999)
        .await
        .expect("blind sees scoped VMID");
    assert_eq!(guest.vmid, 999);
}

/// `get_guest_status` on a non-scoped VMID is denied. Both QEMU and LXC
/// paths must 403 because the fallback ladder would mask the error if
/// only one was set. This is the canonical "blind cannot peek at
/// neighbours" assertion.
#[tokio::test]
async fn blind_get_guest_status_on_other_vmid_returns_typed_forbidden() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/qemu/100/status/current"))
        .respond_with(pve_403("Permission check failed (/vms/100, VM.Audit)"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api2/json/nodes/pve1/lxc/100/status/current"))
        .respond_with(pve_403("Permission check failed (/vms/100, VM.Audit)"))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "blind@pve").await;
    let err = c
        .get_guest_status("pve1", 100)
        .await
        .expect_err("blind cannot read neighbours");
    assert!(matches!(typed(&err), ApiError::Forbidden(_)));
}

/// `/cluster/resources` returns a single-entry array containing only
/// the scoped VMID. The aggregate-renderer invariants (e.g. dashboard's
/// `if total_maxcpu > 0`) still hold because the lone entry might have
/// nonzero maxcpu — this asserts the data layer; renderer-side guards
/// are pinned in `tui_snapshot.rs::dashboard_*`.
#[tokio::test]
async fn blind_cluster_resources_returns_only_scoped_entry() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api2/json/cluster/resources"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [
                {"id": "qemu/999", "type": "qemu", "node": "pve1",
                 "vmid": 999, "name": "vm-blind-999", "status": "running"}
            ]
        })))
        .expect(1)
        .mount(&server)
        .await;

    let c = persona_client(&server, "blind@pve").await;
    let resources = c
        .get_cluster_resources(None)
        .await
        .expect("single-entry cluster_resources deserializes");
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0].vmid, 999);
    assert_eq!(resources[0].resource_type, "qemu");
    // No node-type entries — blind has no /nodes perms.
    assert!(!resources.iter().any(|r| r.resource_type == "node"));
}
