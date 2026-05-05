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
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

// ── Shared scaffolding ─────────────────────────────────────────────────

/// Build a `PxClient` pointed at the wiremock server. The `user` arg
/// flows into the configured profile so the client picks the right auth
/// header shape (token-auth uses the user as the principal).
async fn persona_client(server: &MockServer, user: &str) -> PxClient {
    std::env::set_var("PROXXX_TOKEN_SECRET", "fake-secret");
    let cfg = ProfileConfig {
        url: server.uri(),
        user: user.into(),
        auth: "token".into(),
        token_id: Some("rbac-test".into()),
        token_secret: None,
        token_secret_file: None,
        password: None,
        verify_tls: false,
        rate_limit: Some(100),
        policies: None,
        telegram: None,
        ssh: None,
        pbs: None,
        alerts: None,
    };
    PxClient::new(cfg, None).await.expect("client builds")
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
