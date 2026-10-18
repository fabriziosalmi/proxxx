#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_arguments,
    clippy::unused_async,
    // The 200+ trait-method stubs below return `Ok(Default::default())`
    // for every endpoint not exercised by these HITL E2E tests. Replacing
    // each with `Ok(<ConcreteType>::default())` would add 17 type names
    // of pure noise to a fake gateway whose only contract is "do not
    // execute and return cheap Ok"; the value of pedantic
    // `default_trait_access` evaporates in this fixture.
    clippy::default_trait_access,
    dead_code
)]
//! Phase 5.13 HITL E2E — wiremock-Telegram driven coverage of the 3
//! deferred HITL invariants in
//! [pre-commit/03-security-invariants.md]:
//!
//! 1. **Replay attack on Telegram callback data rejected** —
//!    `replay_callback_does_not_re_execute`
//! 2. **`secure_mode` flag prevents bypass of `is_destructive`
//!    operations** — `secure_mode_forces_request_approval_for_destructive`
//! 3. **Op approved via Telegram but executed by unprivileged user fails** —
//!    `pve_403_during_execute_surfaces_as_failure`
//!
//! Why wiremock + a mocked `ProxmoxGateway` instead of real Telegram +
//! real PVE: the matrix invariants are about HITL **semantics** (the
//! receiver-side decision logic), not about Telegram's wire format
//! (covered by reqwest+serde tests) or PVE's RBAC (covered by `api_test`).
//! Driving the extracted `handle_callback_update` lets us assert exact
//! outcomes via the `CallbackOutcome` enum.

use std::sync::Mutex;

use anyhow::Result;
use async_trait::async_trait;
use proxxx::api::types::{
    Guest, GuestType, Node, NodeStatus, StoragePool, TaskInfo, TaskLog, TaskStatus,
};
use proxxx::api::ProxmoxGateway;
use proxxx::hitl::daemon::{handle_callback_update, CallbackOutcome};
use proxxx::hitl::pending::PendingApprovals;
use proxxx::hitl::telegram::{CallbackQuery, TelegramGateway, Update, User};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── Helpers ─────────────────────────────────────────────────────────────

/// Compose a signed `callback_data` string the way the daemon expects:
/// `<payload>:<16-hex-tag>`. Used by every test that constructs a
/// callback by hand (since v0.1.22 the daemon refuses unsigned shapes).
///
/// `key` MUST be the same key the gateway holds — `fake_gateway` uses
/// an all-zeros 32-byte test key (see `TelegramGateway::with_base_url`).
fn signed(key: &[u8], payload: &str) -> String {
    let tag = proxxx::hitl::hmac_key::sign(key, payload);
    format!("{payload}:{tag}")
}

/// Build a `CallbackQuery` with the given data string. The other fields
/// are minimal — daemon code only reads `id` and `data`.
fn callback_query(id: &str, data: &str) -> CallbackQuery {
    // Deserialize through serde to avoid having to expose every field
    // as `pub`. The Telegram model types only expose `data`, `id`, and
    // `from`, so we round-trip through JSON.
    let json = serde_json::json!({
        "id": id,
        "from": { "id": TEST_APPROVER, "first_name": "tester" },
        "data": data,
        "message": { "message_id": 1_i64, "chat": { "id": 12345_i64 } },
    });
    serde_json::from_value(json).expect("CallbackQuery deserializes")
}

fn update(update_id: i64, cb: CallbackQuery) -> Update {
    let cb_json = serde_json::to_value(cb).unwrap_or_else(|_| {
        // CallbackQuery only derives Deserialize, not Serialize. Build
        // the JSON manually.
        serde_json::json!({
            "id": "fallback",
            "from": { "id": TEST_APPROVER, "first_name": "tester" },
            "data": "approve:start:1",
            "message": { "message_id": 1_i64, "chat": { "id": 12345_i64 } },
        })
    });
    let json = serde_json::json!({
        "update_id": update_id,
        "callback_query": cb_json,
    });
    serde_json::from_value(json).expect("Update deserializes")
}

/// Wire wiremock with the three Telegram endpoints `handle_callback_update`
/// may hit. `answerCallbackQuery` is the one we always expect; the
/// others are present so any accidental call doesn't 404 and panic the
/// test through a confusing reqwest error.
async fn setup_telegram_mock() -> MockServer {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/botfaketoken/answerCallbackQuery"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true,
            "result": true,
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/botfaketoken/sendMessage"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true,
            "result": { "message_id": 42 },
        })))
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/botfaketoken/getUpdates"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true,
            "result": [],
        })))
        .mount(&server)
        .await;

    // Phase 5.13 polish: lifecycle-edit endpoint. Daemon now calls
    // editMessageText after each outcome to update the inline-keyboard
    // message in place. Mock returns a generic ok so the daemon's
    // `let _ = ...` swallow is exercised.
    Mock::given(method("POST"))
        .and(path("/botfaketoken/editMessageText"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true,
            "result": { "message_id": 42 },
        })))
        .mount(&server)
        .await;

    server
}

/// Build a `TelegramGateway` pointed at the wiremock server.
fn fake_gateway(server: &MockServer) -> TelegramGateway {
    // Since #249 the daemon refuses any callback unless the sender is on
    // the approver allowlist, so every fixture gateway installs the test
    // approver id used by `callback_query` below.
    TelegramGateway::with_base_url(
        "faketoken".to_string(),
        "12345".to_string(),
        format!("{}/bot", server.uri()),
    )
    .with_allowed_approvers(vec![TEST_APPROVER])
}

/// Telegram user id every fixture callback is sent from, and the only
/// id `fake_gateway` authorises.
const TEST_APPROVER: i64 = 4242;

fn temp_pending_store() -> (tempfile::TempDir, PendingApprovals) {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = PendingApprovals::open_at(dir.path().join("hitl_pending.db")).expect("open_at");
    (dir, store)
}

fn mint_pending(store: &PendingApprovals, action: &str, vmid: u32, require: u8) -> String {
    store
        .insert(
            &proxxx::hitl::pending::NewPendingRequest::new(action, Some(vmid), require)
                .with_node("pve01")
                .with_guest_type(GuestType::Qemu),
        )
        .expect("insert pending request")
        .id
}

/// #249 — a correctly-signed callback from a Telegram account that is
/// NOT on the allowlist must be refused without executing anything.
#[tokio::test]
async fn callback_from_unlisted_user_is_refused() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();
    let id = mint_pending(&pending, "stop", 100, 1);
    let data = signed(tg.hmac_key(), &format!("approve:{id}"));
    let cb: CallbackQuery = serde_json::from_value(serde_json::json!({
        "id": "cb-intruder",
        "from": { "id": 9999_i64, "first_name": "intruder" },
        "data": data,
        "message": { "message_id": 1_i64, "chat": { "id": 12345_i64 } },
    }))
    .expect("CallbackQuery deserializes");
    let gw = HitlMockGateway::new();
    let out = handle_callback_update(&update(1, cb), &pending, &gw, &tg)
        .await
        .expect("handle_callback_update");
    assert!(
        matches!(out, CallbackOutcome::UnauthorizedApprover { user_id: 9999 }),
        "an unlisted sender must be refused, got {out:?}"
    );
    assert!(
        gw.calls_for("shutdown_guest").is_empty(),
        "refused callback must not reach the gateway, got {:?}",
        gw.calls_for("shutdown_guest")
    );
}

/// #249 — with no `allowed_approvers` configured the daemon refuses
/// every callback rather than accepting anyone who can see the message.
#[tokio::test]
async fn callback_with_no_allowlist_configured_is_refused() {
    let server = setup_telegram_mock().await;
    // Deliberately NOT calling `.with_allowed_approvers(..)`.
    let tg = TelegramGateway::with_base_url(
        "faketoken".to_string(),
        "12345".to_string(),
        format!("{}/bot", server.uri()),
    );
    let (_dir, pending) = temp_pending_store();
    let id = mint_pending(&pending, "stop", 100, 1);
    let data = signed(tg.hmac_key(), &format!("approve:{id}"));
    let cb = callback_query("cb-noallowlist", &data);
    let gw = HitlMockGateway::new();
    let out = handle_callback_update(&update(1, cb), &pending, &gw, &tg)
        .await
        .expect("handle_callback_update");
    assert!(
        matches!(out, CallbackOutcome::UnauthorizedApprover { .. }),
        "an unconfigured allowlist must fail closed, got {out:?}"
    );
    assert!(
        gw.calls_for("shutdown_guest").is_empty(),
        "nothing may execute"
    );
}

/// #249 — a keyboard forwarded into a different chat cannot drive the
/// daemon even when the sender is an authorised approver.
#[tokio::test]
async fn callback_from_another_chat_is_refused() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server); // configured chat_id = "12345"
    let (_dir, pending) = temp_pending_store();
    let id = mint_pending(&pending, "stop", 100, 1);
    let data = signed(tg.hmac_key(), &format!("approve:{id}"));
    let cb: CallbackQuery = serde_json::from_value(serde_json::json!({
        "id": "cb-forwarded",
        "from": { "id": TEST_APPROVER, "first_name": "tester" },
        "data": data,
        "message": { "message_id": 1_i64, "chat": { "id": 999_i64 } },
    }))
    .expect("CallbackQuery deserializes");
    let gw = HitlMockGateway::new();
    let out = handle_callback_update(&update(1, cb), &pending, &gw, &tg)
        .await
        .expect("handle_callback_update");
    assert!(
        matches!(out, CallbackOutcome::WrongChat { chat_id: 999 }),
        "a forwarded keyboard must be refused, got {out:?}"
    );
    assert!(
        gw.calls_for("shutdown_guest").is_empty(),
        "nothing may execute"
    );
}

/// #250 / #341 — a request with `require = 2` in the store must not execute on
/// the first approval, and must execute once a SECOND distinct approver votes.
#[tokio::test]
async fn quorum_of_two_needs_two_distinct_approvers() {
    const SECOND: i64 = 5150;
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server).with_allowed_approvers(vec![TEST_APPROVER, SECOND]);
    let (_dir, pending) = temp_pending_store();
    let id = mint_pending(&pending, "stop", 100, 2);
    let data = signed(tg.hmac_key(), &format!("approve:{id}"));
    let gw = HitlMockGateway::new().with_node_and_guest("pve01", guest(100, "vm-quorum"));

    let first = handle_callback_update(
        &update(1, callback_query("cb-q1", &data)),
        &pending,
        &gw,
        &tg,
    )
    .await
    .expect("first vote");
    assert!(
        matches!(
            first,
            CallbackOutcome::AwaitingApprovals { have: 1, need: 2 }
        ),
        "first approval must not execute, got {first:?}"
    );
    assert!(
        gw.calls_for("shutdown_guest").is_empty(),
        "nothing may execute on a single vote"
    );

    // The SAME approver pressing again must not complete the quorum.
    let again = handle_callback_update(
        &update(2, callback_query("cb-q1b", &data)),
        &pending,
        &gw,
        &tg,
    )
    .await
    .expect("duplicate vote");
    assert!(
        matches!(
            again,
            CallbackOutcome::AwaitingApprovals { have: 1, need: 2 }
        ),
        "the same approver must not satisfy a 2-of-N quorum, got {again:?}"
    );
    assert!(gw.calls_for("shutdown_guest").is_empty());

    // A second, distinct approver completes it.
    let cb2: CallbackQuery = serde_json::from_value(serde_json::json!({
        "id": "cb-q2",
        "from": { "id": SECOND, "first_name": "second" },
        "data": data,
        "message": { "message_id": 1_i64, "chat": { "id": 12345_i64 } },
    }))
    .expect("CallbackQuery deserializes");
    let done = handle_callback_update(&update(3, cb2), &pending, &gw, &tg)
        .await
        .expect("second vote");
    assert!(
        matches!(done, CallbackOutcome::Executed { .. }),
        "the second distinct approver must complete the quorum, got {done:?}"
    );
}

/// #341 (Decision 5) — Old 3/4-segment keyboards (`approve:stop:100` and
/// `approve:stop:100:r2`) are refused with `"this approval button is from an
/// older proxxx, request again"` and do not execute.
#[tokio::test]
async fn legacy_three_and_four_segment_keyboards_are_refused() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let gw = HitlMockGateway::new().with_node_and_guest("pve1", guest(100, "vm-quorum"));
    let (_dir, pending) = temp_pending_store();

    for legacy_payload in ["approve:stop:100", "approve:stop:100:r2", "deny:stop:100"] {
        let data = signed(tg.hmac_key(), legacy_payload);
        let cb = callback_query("cb-legacy", &data);
        let verified = proxxx::hitl::daemon::verify_callback(&tg, &cb);
        let Err(rej) = verified else {
            panic!("legacy payload {legacy_payload:?} must be rejected by verify_callback");
        };
        assert_eq!(
            rej,
            proxxx::hitl::daemon::CallbackRejection::LegacyFormat { data: data.clone() }
        );
        let answer = rej.answer_text().expect("answer text");
        assert!(
            answer
                .to_ascii_lowercase()
                .contains("from an older proxxx, request again"),
            "legacy rejection answer must tell operator to request again, got: {answer}"
        );

        let out = handle_callback_update(&update(1, cb), &pending, &gw, &tg)
            .await
            .expect("legacy payload handled");
        assert!(
            matches!(out, CallbackOutcome::InvalidFormat { .. }),
            "a 3/4-segment legacy payload must be refused, got {out:?}"
        );
    }
    assert!(gw.calls_for("shutdown_guest").is_empty());
}

/// Helper to build a Node by name.
fn node(name: &str) -> Node {
    Node {
        node: name.to_string(),
        status: NodeStatus::Online,
        cpu: 0.0,
        maxcpu: 1,
        mem: 0,
        maxmem: 0,
        disk: 0,
        maxdisk: 0,
        uptime: 0,
    }
}

/// Helper to build a Guest record.
fn guest(vmid: u32, name: &str) -> Guest {
    Guest {
        vmid,
        name: name.to_string(),
        guest_type: GuestType::Qemu,
        ..Default::default()
    }
}

// ── Mock ProxmoxGateway ─────────────────────────────────────────────────

/// HITL-focused mock. Records every mutation call so tests can assert
/// "this method was (or was not) invoked, with these args".
///
/// Only `get_nodes`, `get_guests`, and the three guest-state mutations
/// are wired with state — the other 58 trait methods bail. This keeps
/// the mock scoped to the daemon's actual call surface.
#[derive(Default)]
struct HitlMockGateway {
    nodes: Vec<Node>,
    guests_by_node: std::collections::HashMap<String, Vec<Guest>>,
    /// (`method_name`, vmid) for every mutation call.
    calls: Mutex<Vec<(String, u32)>>,
    /// Detailed `"method:arg1:arg2:..."` strings for parameter assertions (`#340`).
    detailed_calls: Mutex<Vec<String>>,
    /// Count of read/lookup calls (`get_nodes` / `get_guests`).
    lookup_calls: Mutex<usize>,
    /// When set, mutations return Err(this string).
    fail_with: Option<String>,
    /// When set, guest lookups (`get_nodes` / `get_guests`) return Err(this string).
    fail_lookup_with: Option<String>,
}

impl HitlMockGateway {
    fn new() -> Self {
        Self::default()
    }

    fn with_node_and_guest(mut self, node_name: &str, mut g: Guest) -> Self {
        if !self.nodes.iter().any(|n| n.node == node_name) {
            self.nodes.push(node(node_name));
        }
        if g.node.is_empty() {
            g.node = node_name.to_string();
        }
        self.guests_by_node
            .entry(node_name.to_string())
            .or_default()
            .push(g);
        self
    }

    fn fail_mutations(mut self, error: &str) -> Self {
        self.fail_with = Some(error.to_string());
        self
    }

    fn fail_lookups(mut self, error: &str) -> Self {
        self.fail_lookup_with = Some(error.to_string());
        self
    }

    fn lookup_call_count(&self) -> usize {
        *self.lookup_calls.lock().unwrap()
    }

    fn calls_for(&self, method: &str) -> Vec<u32> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(m, v)| (m == method).then_some(*v))
            .collect()
    }

    fn all_calls(&self) -> Vec<(String, u32)> {
        self.calls.lock().unwrap().clone()
    }

    fn detailed_calls(&self) -> Vec<String> {
        self.detailed_calls.lock().unwrap().clone()
    }

    fn record(&self, method: &str, vmid: u32) {
        self.calls.lock().unwrap().push((method.to_string(), vmid));
    }

    fn record_detail(&self, method: &str, vmid: u32, detail: String) {
        self.record(method, vmid);
        self.detailed_calls.lock().unwrap().push(detail);
    }
}

#[async_trait]
impl ProxmoxGateway for HitlMockGateway {
    async fn get_nodes(&self) -> Result<Vec<Node>> {
        *self.lookup_calls.lock().unwrap() += 1;
        if let Some(ref e) = self.fail_lookup_with {
            anyhow::bail!("{e}");
        }
        Ok(self.nodes.clone())
    }
    async fn get_guests(&self, node: &str) -> Result<Vec<Guest>> {
        *self.lookup_calls.lock().unwrap() += 1;
        if let Some(ref e) = self.fail_lookup_with {
            anyhow::bail!("{e}");
        }
        Ok(self.guests_by_node.get(node).cloned().unwrap_or_default())
    }
    async fn start_guest(&self, node: &str, vmid: u32, gt: GuestType) -> Result<String> {
        self.record_detail(
            "start_guest",
            vmid,
            format!("start_guest:{node}:{vmid}:{}", gt.as_str()),
        );
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(format!("UPID:start:{vmid}"))
    }
    async fn shutdown_guest(
        &self,
        node: &str,
        vmid: u32,
        gt: GuestType,
        timeout_secs: u32,
    ) -> Result<String> {
        self.record_detail(
            "shutdown_guest",
            vmid,
            format!(
                "shutdown_guest:{node}:{vmid}:{}:{timeout_secs}",
                gt.as_str()
            ),
        );
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(format!("UPID:shutdown:{vmid}"))
    }
    async fn restart_guest(&self, node: &str, vmid: u32, gt: GuestType) -> Result<String> {
        self.record_detail(
            "restart_guest",
            vmid,
            format!("restart_guest:{node}:{vmid}:{}", gt.as_str()),
        );
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(format!("UPID:restart:{vmid}"))
    }
    async fn suspend_guest(&self, node: &str, vmid: u32, gt: GuestType) -> Result<String> {
        self.record_detail(
            "suspend_guest",
            vmid,
            format!("suspend_guest:{node}:{vmid}:{}", gt.as_str()),
        );
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(format!("UPID:suspend:{vmid}"))
    }
    async fn resume_guest(&self, node: &str, vmid: u32, gt: GuestType) -> Result<String> {
        self.record_detail(
            "resume_guest",
            vmid,
            format!("resume_guest:{node}:{vmid}:{}", gt.as_str()),
        );
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(format!("UPID:resume:{vmid}"))
    }
    async fn startall_node(&self, _: &str) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn stopall_node(&self, _: &str) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn suspendall_node(&self, _: &str) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn node_apt_repositories(&self, _: &str) -> Result<serde_json::Value> {
        Ok(serde_json::json!({}))
    }
    async fn node_apt_changelog(&self, _: &str, _: &str) -> Result<String> {
        Ok(String::new())
    }
    async fn node_apt_versions(
        &self,
        _: &str,
    ) -> Result<Vec<proxxx::api::types::AptInstalledPackage>> {
        Ok(vec![])
    }
    async fn get_guest_rrddata(
        &self,
        _: &str,
        _: u32,
        _: GuestType,
        _: proxxx::api::types::RrdTimeframe,
        _: proxxx::api::types::RrdCf,
    ) -> Result<Vec<proxxx::api::types::RrdPoint>> {
        Ok(vec![])
    }
    async fn get_node_rrddata(
        &self,
        _: &str,
        _: proxxx::api::types::RrdTimeframe,
        _: proxxx::api::types::RrdCf,
    ) -> Result<Vec<proxxx::api::types::RrdPoint>> {
        Ok(vec![])
    }
    async fn get_storage_rrddata(
        &self,
        _: &str,
        _: &str,
        _: proxxx::api::types::RrdTimeframe,
        _: proxxx::api::types::RrdCf,
    ) -> Result<Vec<proxxx::api::types::RrdPoint>> {
        Ok(vec![])
    }
    async fn get_guest_vncproxy(
        &self,
        _: &str,
        _: u32,
        _: GuestType,
    ) -> Result<proxxx::api::types::VncTicket> {
        anyhow::bail!("unused")
    }
    async fn build_guest_vncwebsocket_url(
        &self,
        _: &str,
        _: u32,
        _: GuestType,
        _: &proxxx::api::types::VncTicket,
    ) -> Result<String> {
        Ok(String::new())
    }
    async fn get_access_permissions(
        &self,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<serde_json::Value> {
        Ok(serde_json::Value::Null)
    }
    async fn change_user_password(&self, _: &str, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn list_lxc_interfaces(
        &self,
        _: &str,
        _: u32,
    ) -> Result<Vec<proxxx::api::types::LxcInterface>> {
        Ok(vec![])
    }
    async fn dump_qemu_cloudinit(&self, _: &str, _: u32, _: &str) -> Result<String> {
        Ok(String::new())
    }
    async fn get_lxc_spiceproxy(&self, _: &str, _: u32) -> Result<proxxx::api::types::SpiceConfig> {
        anyhow::bail!("unused")
    }
    async fn lxc_exec_oneshot(&self, _: &str, _: u32, _: &str) -> Result<serde_json::Value> {
        anyhow::bail!("unused")
    }
    async fn get_node_termproxy(&self, _: &str) -> Result<proxxx::api::types::TermproxyTicket> {
        anyhow::bail!("unused")
    }
    async fn get_node_vncshell(&self, _: &str) -> Result<proxxx::api::types::VncTicket> {
        anyhow::bail!("unused")
    }
    async fn get_node_spiceshell(&self, _: &str) -> Result<proxxx::api::types::SpiceConfig> {
        anyhow::bail!("unused")
    }
    async fn list_backup_jobs(&self) -> Result<Vec<proxxx::api::types::BackupJob>> {
        Ok(vec![])
    }
    async fn get_backup_job(&self, _: &str) -> Result<proxxx::api::types::BackupJob> {
        anyhow::bail!("unused")
    }
    async fn create_backup_job(&self, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn update_backup_job(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_backup_job(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn cluster_backup_info(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({}))
    }
    async fn extract_backup_config(&self, _: &str, _: &str) -> Result<String> {
        Ok(String::new())
    }
    // ── Stubs for the rest of the trait surface ────────────────────────
    // The daemon does not call these, but the trait requires them.
    async fn get_guest_status(&self, _: &str, _: u32) -> Result<Guest> {
        anyhow::bail!("unused in HITL test")
    }
    async fn get_storage_pools(&self, _: &str) -> Result<Vec<StoragePool>> {
        Ok(vec![])
    }
    async fn get_task_log(&self, _: &str, _: &str, _: usize, _: usize) -> Result<TaskLog> {
        anyhow::bail!("unused")
    }
    async fn get_guest_config(
        &self,
        _: &str,
        _: u32,
        _: &GuestType,
    ) -> Result<std::collections::HashMap<String, String>> {
        Ok(std::collections::HashMap::new())
    }
    async fn get_cluster_tasks(&self) -> Result<Vec<TaskInfo>> {
        Ok(vec![])
    }
    async fn get_task_status(&self, _node: &str, upid: &str) -> Result<TaskStatus> {
        Ok(TaskStatus {
            upid: upid.to_string(),
            status: "stopped".to_string(),
            exitstatus: Some("OK".to_string()),
            task_type: "qmclone".to_string(),
            id: "100".to_string(),
            user: "root@pam".to_string(),
            starttime: 1,
        })
    }
    async fn stop_guest(
        &self,
        node: &str,
        vmid: u32,
        gt: GuestType,
        force: bool,
    ) -> Result<String> {
        self.record_detail(
            "stop_guest",
            vmid,
            format!("stop_guest:{node}:{vmid}:{}:{force}", gt.as_str()),
        );
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(format!("UPID:stop:{vmid}"))
    }
    async fn migrate_guest(
        &self,
        node: &str,
        vmid: u32,
        gt: GuestType,
        target_node: &str,
        online: bool,
        _: bool,
        _: bool,
    ) -> Result<String> {
        self.record_detail(
            "migrate_guest",
            vmid,
            format!(
                "migrate_guest:{node}:{vmid}:{}:{target_node}:{online}",
                gt.as_str()
            ),
        );
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(format!("UPID:migrate:{vmid}"))
    }
    async fn delete_guest(&self, node: &str, vmid: u32, gt: GuestType) -> Result<String> {
        self.record_detail(
            "delete_guest",
            vmid,
            format!("delete_guest:{node}:{vmid}:{}", gt.as_str()),
        );
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(format!("UPID:delete:{vmid}"))
    }
    async fn execute_guest_command(
        &self,
        _: &str,
        vmid: u32,
        _: &GuestType,
        _: &str,
    ) -> Result<proxxx::api::types::GuestExecResult> {
        self.record("execute_guest_command", vmid);
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(proxxx::api::types::GuestExecResult {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        })
    }
    async fn qemu_agent_file_read(
        &self,
        _: &str,
        _: u32,
        _: &str,
    ) -> Result<proxxx::api::types::GuestAgentFileContent> {
        Ok(Default::default())
    }
    async fn qemu_agent_file_write(&self, _: &str, _: u32, _: &str, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn qemu_agent_network_get_interfaces(
        &self,
        _: &str,
        _: u32,
    ) -> Result<Vec<proxxx::api::types::GuestAgentNetworkInterface>> {
        Ok(vec![])
    }
    async fn get_node_dns(&self, _: &str) -> Result<proxxx::api::types::NodeDns> {
        Ok(Default::default())
    }
    async fn update_node_dns(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn get_node_hosts(&self, _: &str) -> Result<proxxx::api::types::NodeHosts> {
        Ok(Default::default())
    }
    async fn update_node_hosts(&self, _: &str, _: &str, _: Option<&str>) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn get_node_journal(&self, _: &str, _: &[(&str, &str)]) -> Result<Vec<String>> {
        Ok(vec![])
    }
    async fn get_node_syslog(
        &self,
        _: &str,
        _: &[(&str, &str)],
    ) -> Result<Vec<proxxx::api::types::NodeSyslogLine>> {
        Ok(vec![])
    }
    async fn get_node_time(&self, _: &str) -> Result<proxxx::api::types::NodeTime> {
        Ok(Default::default())
    }
    async fn update_node_timezone(&self, _: &str, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn wakeonlan_node(&self, _: &str) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn get_node_subscription(&self, _: &str) -> Result<proxxx::api::types::NodeSubscription> {
        Ok(Default::default())
    }
    async fn set_node_subscription_key(&self, _: &str, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn refresh_node_subscription(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_node_subscription(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn get_node_certificates_info(
        &self,
        _: &str,
    ) -> Result<Vec<proxxx::api::types::NodeCertificateInfo>> {
        Ok(vec![])
    }
    async fn upload_node_custom_certificate(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_node_custom_certificate(&self, _: &str, _: bool) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn order_node_acme_certificate(&self, _: &str, _: bool) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn get_node_report(&self, _: &str) -> Result<String> {
        Ok(String::new())
    }
    async fn list_pools(&self) -> Result<Vec<proxxx::api::types::Pool>> {
        Ok(vec![])
    }
    async fn get_pool(&self, _: &str) -> Result<proxxx::api::types::PoolDetails> {
        Ok(Default::default())
    }
    async fn create_pool(&self, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn update_pool(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_pool(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn get_cluster_resources(
        &self,
        _: Option<&str>,
    ) -> Result<Vec<proxxx::api::types::ClusterResource>> {
        Ok(vec![])
    }
    async fn get_api_version(&self) -> Result<proxxx::api::types::ApiVersion> {
        Ok(Default::default())
    }
    async fn get_cluster_options(&self) -> Result<proxxx::api::types::ClusterOptions> {
        Ok(Default::default())
    }
    async fn update_cluster_options(&self, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn get_cluster_log(
        &self,
        _: Option<u32>,
    ) -> Result<Vec<proxxx::api::types::ClusterLogEntry>> {
        Ok(vec![])
    }
    async fn create_snapshot(
        &self,
        node: &str,
        vmid: u32,
        gt: GuestType,
        name: &str,
    ) -> Result<String> {
        self.record_detail(
            "create_snapshot",
            vmid,
            format!("create_snapshot:{node}:{vmid}:{}:{name}", gt.as_str()),
        );
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(format!("UPID:snapshot:{vmid}"))
    }
    async fn delete_snapshot(
        &self,
        node: &str,
        vmid: u32,
        gt: GuestType,
        name: &str,
    ) -> Result<String> {
        self.record_detail(
            "delete_snapshot",
            vmid,
            format!("delete_snapshot:{node}:{vmid}:{}:{name}", gt.as_str()),
        );
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(format!("UPID:delsnapshot:{vmid}"))
    }
    async fn rollback_snapshot(&self, _: &str, _: u32, _: GuestType, _: &str) -> Result<String> {
        Ok("UPID:mock:rollback".into())
    }
    async fn update_guest_config(
        &self,
        node: &str,
        vmid: u32,
        gt: GuestType,
        params: &[(String, String)],
    ) -> Result<Option<String>> {
        let joined: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
        self.record_detail(
            "update_guest_config",
            vmid,
            format!(
                "update_guest_config:{node}:{vmid}:{}:{}",
                gt.as_str(),
                joined.join(",")
            ),
        );
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(Some(format!("UPID:cfg:{vmid}")))
    }
    async fn regenerate_cloudinit(&self, node: &str, vmid: u32) -> Result<Option<String>> {
        self.record_detail(
            "regenerate_cloudinit",
            vmid,
            format!("regenerate_cloudinit:{node}:{vmid}"),
        );
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(Some(format!("UPID:ci:{vmid}")))
    }
    async fn list_pending_config(
        &self,
        _: &str,
        _: u32,
        _: GuestType,
    ) -> Result<Vec<proxxx::api::types::PendingConfigEntry>> {
        Ok(vec![])
    }
    async fn convert_to_template(&self, _: &str, _: u32, _: GuestType) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn clone_guest(
        &self,
        node: &str,
        vmid: u32,
        gt: GuestType,
        newid: u32,
        name: Option<&str>,
        _: Option<&str>,
        _: Option<&str>,
        full: bool,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<String> {
        self.record_detail(
            "clone_guest",
            vmid,
            format!(
                "clone_guest:{node}:{vmid}:{}:{newid}:{}:{full}",
                gt.as_str(),
                name.unwrap_or("")
            ),
        );
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(format!("UPID:clone:{vmid}:{newid}"))
    }
    async fn next_free_vmid(&self) -> Result<u32> {
        Ok(777)
    }
    async fn create_backup(
        &self,
        _: &str,
        _: &[u32],
        _: &str,
        _: &str,
        _: Option<&str>,
    ) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn get_spiceproxy(&self, _: &str, _: u32) -> Result<proxxx::api::types::SpiceConfig> {
        anyhow::bail!("unused")
    }
    async fn get_termproxy(
        &self,
        _: &str,
        _: u32,
        _: GuestType,
    ) -> Result<proxxx::api::types::TermproxyTicket> {
        anyhow::bail!("unused")
    }
    async fn list_acl(&self) -> Result<Vec<proxxx::api::types::AclEntry>> {
        Ok(vec![])
    }
    async fn list_users(&self) -> Result<Vec<proxxx::api::types::User>> {
        Ok(vec![])
    }
    async fn list_user_tokens(&self, _: &str) -> Result<Vec<proxxx::api::types::ApiToken>> {
        Ok(vec![])
    }
    async fn list_groups(&self) -> Result<Vec<proxxx::api::types::Group>> {
        Ok(vec![])
    }
    async fn list_roles(&self) -> Result<Vec<proxxx::api::types::Role>> {
        Ok(vec![])
    }
    async fn list_realms(&self) -> Result<Vec<proxxx::api::types::Realm>> {
        Ok(vec![])
    }
    async fn list_tfa(&self, _: &str) -> Result<Vec<proxxx::api::types::TfaEntry>> {
        Ok(vec![])
    }
    async fn create_token(
        &self,
        _: &str,
        _: &str,
        _: bool,
        _: Option<u64>,
        _: Option<&str>,
    ) -> Result<proxxx::api::types::ApiToken> {
        anyhow::bail!("unused")
    }
    async fn revoke_token(&self, _: &str, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn list_cluster_firewall_rules(&self) -> Result<Vec<proxxx::api::types::FirewallRule>> {
        Ok(vec![])
    }
    async fn list_node_firewall_rules(
        &self,
        _: &str,
    ) -> Result<Vec<proxxx::api::types::FirewallRule>> {
        Ok(vec![])
    }
    async fn list_guest_firewall_rules(
        &self,
        _: &str,
        _: u32,
        _: GuestType,
    ) -> Result<Vec<proxxx::api::types::FirewallRule>> {
        Ok(vec![])
    }
    async fn list_cluster_firewall_aliases(
        &self,
    ) -> Result<Vec<proxxx::api::types::FirewallAlias>> {
        Ok(vec![])
    }
    async fn create_cluster_firewall_alias(&self, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn update_cluster_firewall_alias(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_cluster_firewall_alias(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn list_cluster_firewall_groups(
        &self,
    ) -> Result<Vec<proxxx::api::types::FirewallSecurityGroup>> {
        Ok(vec![])
    }
    async fn create_cluster_firewall_group(&self, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_cluster_firewall_group(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn list_cluster_firewall_group_rules(
        &self,
        _: &str,
    ) -> Result<Vec<proxxx::api::types::FirewallRule>> {
        Ok(vec![])
    }
    async fn list_cluster_firewall_ipsets(&self) -> Result<Vec<proxxx::api::types::FirewallIpset>> {
        Ok(vec![])
    }
    async fn create_cluster_firewall_ipset(&self, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_cluster_firewall_ipset(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn list_cluster_firewall_ipset_cidrs(
        &self,
        _: &str,
    ) -> Result<Vec<proxxx::api::types::FirewallIpsetCidr>> {
        Ok(vec![])
    }
    async fn add_cluster_firewall_ipset_cidr(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn remove_cluster_firewall_ipset_cidr(&self, _: &str, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn get_cluster_firewall_options(&self) -> Result<proxxx::api::types::FirewallOptions> {
        Ok(Default::default())
    }
    async fn update_cluster_firewall_options(&self, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn list_guest_firewall_aliases(
        &self,
        _: &str,
        _: u32,
        _: GuestType,
    ) -> Result<Vec<proxxx::api::types::FirewallAlias>> {
        Ok(vec![])
    }
    async fn create_guest_firewall_alias(
        &self,
        _: &str,
        _: u32,
        _: GuestType,
        _: &[(&str, &str)],
    ) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn update_guest_firewall_alias(
        &self,
        _: &str,
        _: u32,
        _: GuestType,
        _: &str,
        _: &[(&str, &str)],
    ) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_guest_firewall_alias(
        &self,
        _: &str,
        _: u32,
        _: GuestType,
        _: &str,
    ) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn get_guest_firewall_options(
        &self,
        _: &str,
        _: u32,
        _: GuestType,
    ) -> Result<proxxx::api::types::GuestFirewallOptions> {
        Ok(Default::default())
    }
    async fn update_guest_firewall_options(
        &self,
        _: &str,
        _: u32,
        _: GuestType,
        _: &[(&str, &str)],
    ) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn list_cluster_mapping_pci(&self) -> Result<Vec<proxxx::api::types::ClusterMappingPci>> {
        Ok(vec![])
    }
    async fn create_cluster_mapping_pci(&self, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn update_cluster_mapping_pci(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_cluster_mapping_pci(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn list_cluster_mapping_usb(&self) -> Result<Vec<proxxx::api::types::ClusterMappingUsb>> {
        Ok(vec![])
    }
    async fn create_cluster_mapping_usb(&self, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn update_cluster_mapping_usb(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_cluster_mapping_usb(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn list_node_network(
        &self,
        _: &str,
    ) -> Result<Vec<proxxx::api::types::NetworkInterface>> {
        Ok(vec![])
    }
    async fn delete_storage_content(&self, _: &str, _: &str, _: &str) -> Result<Option<String>> {
        anyhow::bail!("unused")
    }
    async fn upload_to_storage(
        &self,
        _: &str,
        _: &str,
        _: &std::path::Path,
        _: &str,
        _: Option<&str>,
    ) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn create_user(
        &self,
        _: &str,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<bool>,
        _: Option<u64>,
        _: Option<&str>,
    ) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn update_user(
        &self,
        _: &str,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<bool>,
        _: Option<u64>,
        _: Option<&str>,
    ) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_user(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn create_group(&self, _: &str, _: Option<&str>) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_group(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn modify_acl(
        &self,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: Option<&str>,
        _: Option<&str>,
        _: bool,
        _: bool,
    ) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn create_role(&self, _: &str, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn update_role(&self, _: &str, _: &str, _: bool) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_role(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn list_pci(&self, _: &str) -> Result<Vec<proxxx::api::types::PciDevice>> {
        Ok(vec![])
    }
    async fn list_usb(&self, _: &str) -> Result<Vec<proxxx::api::types::UsbDevice>> {
        Ok(vec![])
    }
    async fn list_node_disks(&self, _: &str) -> Result<Vec<proxxx::api::types::Disk>> {
        Ok(vec![])
    }
    async fn get_disk_smart(&self, _: &str, _: &str) -> Result<proxxx::api::types::DiskSmart> {
        Ok(proxxx::api::types::DiskSmart::default())
    }
    async fn list_node_lvm(&self, _: &str) -> Result<Vec<proxxx::api::types::LvmVolumeGroup>> {
        Ok(vec![])
    }
    async fn list_node_lvmthin(&self, _: &str) -> Result<Vec<proxxx::api::types::LvmThinPool>> {
        Ok(vec![])
    }
    async fn list_node_zfs(&self, _: &str) -> Result<Vec<proxxx::api::types::ZfsPool>> {
        Ok(vec![])
    }
    async fn get_node_zfs_detail(
        &self,
        _: &str,
        _: &str,
    ) -> Result<proxxx::api::types::ZfsPoolDetail> {
        Ok(proxxx::api::types::ZfsPoolDetail::default())
    }
    async fn guest_serial_devices(
        &self,
        _: &str,
        _: u32,
        _: &proxxx::api::types::GuestType,
    ) -> Result<Vec<proxxx::api::types::SerialDevice>> {
        Ok(vec![])
    }
    async fn guest_disk_io_rate(
        &self,
        _: &str,
        _: u32,
        _: &proxxx::api::types::GuestType,
    ) -> Result<Option<proxxx::api::types::DiskIoRate>> {
        Ok(None)
    }
    async fn list_ha_groups(&self) -> Result<Vec<proxxx::api::types::HaGroup>> {
        Ok(vec![])
    }
    async fn list_ha_resources(&self) -> Result<Vec<proxxx::api::types::HaResource>> {
        Ok(vec![])
    }
    async fn ha_manager_status(&self) -> Result<proxxx::api::types::HaManagerStatus> {
        Ok(proxxx::api::types::HaManagerStatus::default())
    }
    async fn get_ha_status_current(&self) -> Result<Vec<proxxx::api::types::HaStatusEntry>> {
        Ok(vec![])
    }
    async fn list_ha_groups_legacy(&self) -> Result<Vec<proxxx::api::types::HaGroup>> {
        Ok(vec![])
    }
    async fn create_ha_group(&self, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn update_ha_group(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_ha_group(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn list_ha_rules(&self) -> Result<Vec<proxxx::api::types::HaRule>> {
        Ok(vec![])
    }
    async fn create_ha_rule(&self, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn update_ha_rule(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_ha_rule(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn create_ha_resource(&self, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn update_ha_resource(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_ha_resource(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn list_notification_endpoints(
        &self,
    ) -> Result<Vec<proxxx::api::types::NotificationEndpoint>> {
        Ok(vec![])
    }
    async fn create_notification_endpoint(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn update_notification_endpoint(
        &self,
        _: &str,
        _: &str,
        _: &[(&str, &str)],
    ) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_notification_endpoint(&self, _: &str, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn list_notification_matchers(
        &self,
    ) -> Result<Vec<proxxx::api::types::NotificationMatcher>> {
        Ok(vec![])
    }
    async fn create_notification_matcher(&self, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn update_notification_matcher(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_notification_matcher(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn list_notification_targets(
        &self,
    ) -> Result<Vec<proxxx::api::types::NotificationTarget>> {
        Ok(vec![])
    }
    async fn get_guest_rrd_image(
        &self,
        _: &str,
        _: u32,
        _: GuestType,
        _: &str,
        _: proxxx::api::types::RrdTimeframe,
        _: proxxx::api::types::RrdCf,
    ) -> Result<proxxx::api::types::RrdImage> {
        Ok(Default::default())
    }
    async fn list_metric_servers(&self) -> Result<Vec<proxxx::api::types::MetricServer>> {
        Ok(vec![])
    }
    async fn get_metric_server(&self, _: &str) -> Result<proxxx::api::types::MetricServer> {
        Ok(Default::default())
    }
    async fn create_metric_server(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn update_metric_server(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_metric_server(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn list_node_tasks(
        &self,
        _: &str,
        _: Option<u32>,
    ) -> Result<Vec<proxxx::api::types::TaskInfo>> {
        Ok(vec![])
    }
    async fn stop_node_task(&self, _: &str, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn get_guest_feature(
        &self,
        _: &str,
        _: u32,
        _: GuestType,
        _: &str,
    ) -> Result<proxxx::api::types::GuestFeatureCheck> {
        Ok(Default::default())
    }
    async fn send_qemu_key(&self, _: &str, _: u32, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn unlink_qemu_disk(&self, _: &str, _: u32, _: &str, _: bool) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn list_node_aplinfo(&self, _: &str) -> Result<Vec<proxxx::api::types::AplTemplate>> {
        Ok(vec![])
    }
    async fn download_node_aplinfo(&self, _: &str, _: &str, _: &str) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn query_url_metadata(
        &self,
        _: &str,
        _: &str,
    ) -> Result<proxxx::api::types::UrlMetadata> {
        Ok(Default::default())
    }
    async fn list_cluster_corosync_nodes(&self) -> Result<Vec<proxxx::api::types::CorosyncNode>> {
        Ok(vec![])
    }
    async fn add_cluster_corosync_node(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn remove_cluster_corosync_node(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn get_cluster_join_info(&self, _: Option<&str>) -> Result<serde_json::Value> {
        Ok(serde_json::Value::Null)
    }
    async fn join_cluster(&self, _: &[(&str, &str)]) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn get_cluster_qdevice(&self) -> Result<serde_json::Value> {
        Ok(serde_json::Value::Null)
    }
    async fn setup_cluster_qdevice(&self, _: &[(&str, &str)]) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn update_cluster_qdevice(&self, _: &[(&str, &str)]) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn remove_cluster_qdevice(&self) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn get_cluster_totem(&self) -> Result<serde_json::Value> {
        Ok(serde_json::Value::Null)
    }
    async fn list_acme_accounts(&self) -> Result<Vec<proxxx::api::types::AcmeAccount>> {
        Ok(vec![])
    }
    async fn get_acme_account(&self, _: &str) -> Result<proxxx::api::types::AcmeAccountDetails> {
        Ok(Default::default())
    }
    async fn create_acme_account(&self, _: &[(&str, &str)]) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn update_acme_account(&self, _: &str, _: &[(&str, &str)]) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn delete_acme_account(&self, _: &str) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn list_acme_plugins(&self) -> Result<Vec<proxxx::api::types::AcmePlugin>> {
        Ok(vec![])
    }
    async fn get_acme_plugin(&self, _: &str) -> Result<proxxx::api::types::AcmePlugin> {
        Ok(Default::default())
    }
    async fn create_acme_plugin(&self, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn update_acme_plugin(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_acme_plugin(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn get_acme_tos(&self, _: Option<&str>) -> Result<String> {
        Ok(String::new())
    }
    async fn list_acme_directories(&self) -> Result<Vec<proxxx::api::types::AcmeDirectory>> {
        Ok(vec![])
    }
    async fn get_acme_challenge_schema(&self) -> Result<serde_json::Value> {
        Ok(serde_json::Value::Null)
    }
    async fn list_cluster_storages(&self) -> Result<Vec<proxxx::api::types::StorageDefinition>> {
        Ok(vec![])
    }
    async fn get_cluster_storage(&self, _: &str) -> Result<proxxx::api::types::StorageDefinition> {
        Ok(Default::default())
    }
    async fn create_cluster_storage(&self, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn update_cluster_storage(&self, _: &str, _: &[(&str, &str)]) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn delete_cluster_storage(&self, _: &str) -> Result<()> {
        anyhow::bail!("unused")
    }
    async fn cluster_status(&self) -> Result<Vec<proxxx::api::types::ClusterStatusEntry>> {
        Ok(vec![])
    }
    async fn list_replication_jobs(&self) -> Result<Vec<proxxx::api::types::ReplicationJob>> {
        Ok(vec![])
    }
    async fn list_replication_status(
        &self,
        _: &str,
    ) -> Result<Vec<proxxx::api::types::ReplicationStatus>> {
        Ok(vec![])
    }
    async fn download_to_storage(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: &str,
        _: Option<&str>,
        _: Option<&str>,
        _: &str,
    ) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn list_storage_content(
        &self,
        _: &str,
        _: &str,
        _: Option<&str>,
    ) -> Result<Vec<proxxx::api::types::StorageContent>> {
        Ok(vec![])
    }
    async fn move_disk(
        &self,
        _: &str,
        vmid: u32,
        _: GuestType,
        _: &str,
        _: &str,
        _: bool,
    ) -> Result<String> {
        self.record("move_disk", vmid);
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(format!("UPID:move_disk:{vmid}"))
    }
    async fn resize_disk(
        &self,
        _: &str,
        vmid: u32,
        _: GuestType,
        _: &str,
        _: &str,
    ) -> Result<String> {
        self.record("resize_disk", vmid);
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(format!("UPID:resize_disk:{vmid}"))
    }
    async fn list_snapshots(
        &self,
        _: &str,
        _: u32,
        _: GuestType,
    ) -> Result<Vec<proxxx::api::types::Snapshot>> {
        Ok(vec![])
    }
    async fn apt_update_refresh(&self, _: &str) -> Result<String> {
        anyhow::bail!("unused")
    }
    async fn apt_list_upgradable(&self, _: &str) -> Result<Vec<proxxx::api::types::AptUpgradable>> {
        Ok(vec![])
    }
    async fn node_status_detail(&self, _: &str) -> Result<proxxx::api::types::NodeStatusDetail> {
        Ok(proxxx::api::types::NodeStatusDetail::default())
    }
    async fn get_next_vmid(&self) -> anyhow::Result<u32> {
        Ok(999)
    }
    async fn create_qemu(&self, node: &str, params: &[(&str, &str)]) -> anyhow::Result<String> {
        let vmid = params
            .iter()
            .find_map(|(k, v)| (*k == "vmid").then(|| v.parse::<u32>().ok()).flatten())
            .unwrap_or(0);
        let joined: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
        self.record_detail(
            "create_qemu",
            vmid,
            format!("create_qemu:{node}:{vmid}:{}", joined.join(";")),
        );
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(format!("UPID:create_qemu:{vmid}"))
    }
    async fn create_lxc(&self, node: &str, params: &[(&str, &str)]) -> anyhow::Result<String> {
        let vmid = params
            .iter()
            .find_map(|(k, v)| (*k == "vmid").then(|| v.parse::<u32>().ok()).flatten())
            .unwrap_or(0);
        let joined: Vec<String> = params.iter().map(|(k, v)| format!("{k}={v}")).collect();
        self.record_detail(
            "create_lxc",
            vmid,
            format!("create_lxc:{node}:{vmid}:{}", joined.join(";")),
        );
        if let Some(ref e) = self.fail_with {
            anyhow::bail!("{e}")
        }
        Ok(format!("UPID:create_lxc:{vmid}"))
    }
    async fn get_user(&self, userid: &str) -> Result<proxxx::api::types::User> {
        Ok(proxxx::api::types::User {
            userid: userid.to_string(),
            ..Default::default()
        })
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

/// Invariant 3 (matrix row 10) — replay attack rejected.
///
/// Set-up: a single approval callback for `stop` of vmid 100.
/// Action: deliver the same `Update` twice.
/// Expected: first delivery → `Executed`, second → `Replay`.
/// `shutdown_guest` is called exactly once.
#[tokio::test]
async fn replay_callback_does_not_re_execute() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();
    let client = HitlMockGateway::new().with_node_and_guest("pve01", guest(100, "vm-prod-01"));

    // v0.1.22+: every callback MUST be HMAC-signed, and the request is
    // persisted in PendingStore under a random 16-hex id.
    let id = mint_pending(&pending, "stop", 100, 1);
    let data = signed(tg.hmac_key(), &format!("approve:{id}"));
    let cb = callback_query("cb-1", &data);
    let upd = update(1, cb);

    // First delivery: should execute.
    let out1 = handle_callback_update(&upd, &pending, &client, &tg)
        .await
        .expect("first call");
    assert!(
        matches!(out1, CallbackOutcome::Executed { ref action, vmid: 100, .. } if action == "stop"),
        "first call must execute, got {out1:?}"
    );

    // Second delivery (same callback data): MUST be rejected as replay.
    let out2 = handle_callback_update(&upd, &pending, &client, &tg)
        .await
        .expect("second call");
    assert!(
        matches!(out2, CallbackOutcome::Replay { ref txn_id } if txn_id == &id),
        "replay must be rejected with request id, got {out2:?}"
    );

    // Critical assertion: the gateway saw exactly one shutdown call.
    let shutdowns = client.calls_for("shutdown_guest");
    assert_eq!(
        shutdowns,
        vec![100],
        "shutdown must be called exactly once across the two callbacks"
    );
    assert_eq!(pending.consumed_count(), 1, "pending must record one txn");
}

/// Invariant 1 (matrix row 8) — execution under unprivileged token surfaces failure.
///
/// Set-up: gateway configured to bail on every mutation (simulating
/// PVE returning 403 because the token lacks VM.PowerMgmt on the
/// target). HITL approval has been granted on Telegram.
/// Action: deliver an approve callback.
/// Expected: `ExecuteFailed` outcome with the gateway's error in the
/// message; the daemon does NOT silently report success. The callback
/// gets answered with the failure text.
#[tokio::test]
async fn pve_403_during_execute_surfaces_as_failure() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();
    let client = HitlMockGateway::new()
        .with_node_and_guest("pve01", guest(200, "vm-restricted"))
        .fail_mutations("403 Forbidden: token has no VM.PowerMgmt on /vms/200");

    let id = mint_pending(&pending, "start", 200, 1);
    let cb = callback_query("cb-403", &signed(tg.hmac_key(), &format!("approve:{id}")));
    let upd = update(2, cb);

    let outcome = handle_callback_update(&upd, &pending, &client, &tg)
        .await
        .expect("handle");
    let CallbackOutcome::ExecuteFailed {
        action,
        vmid,
        error,
    } = outcome
    else {
        panic!("expected ExecuteFailed, got {outcome:?}");
    };
    assert_eq!(action, "start");
    assert_eq!(vmid, 200);
    assert!(
        error.contains("403"),
        "the PVE 403 must be surfaced in the failure message: {error}"
    );

    // The mutation was attempted — Telegram approval does not skip the
    // call, it just authorizes proxxx to make it. The 403 came from PVE.
    let starts = client.calls_for("start_guest");
    assert_eq!(starts, vec![200], "start_guest must be invoked once");

    // Step 9 (#341): failed execution sets status='failed' and records the error in the store.
    let stored = pending.get(&id).expect("get").expect("row exists");
    assert_eq!(stored.status, proxxx::hitl::pending::RequestStatus::Failed);
    assert!(stored.error.as_deref().unwrap_or("").contains("403"));
}

/// #339 Test 1 — Every mutating `SideEffect` variant maps to `Some(HitlTarget)`
/// with the canonical action string, and every local/read-only/batch-wrapper
/// variant maps to `None`.
#[test]
fn hitl_action_classifies_every_mutating_side_effect() {
    use proxxx::app::SideEffect;
    use proxxx::tui::{hitl_action, HitlTarget};

    let n = || "pve01".to_string();
    let check = |eff: SideEffect, action: &'static str, vmid: u32| {
        assert_eq!(hitl_action(&eff), Some(HitlTarget { action, vmid }));
    };
    check(SideEffect::StartGuest { vmid: 101 }, "start", 101);
    check(
        SideEffect::StopGuest {
            vmid: 102,
            force: false,
        },
        "stop",
        102,
    );
    check(SideEffect::RestartGuest { vmid: 103 }, "restart", 103);
    check(SideEffect::DeleteGuest { vmid: 104 }, "delete", 104);
    check(
        SideEffect::CreateSnapshot {
            vmid: 105,
            name: "s".into(),
        },
        "snapshot",
        105,
    );
    check(
        SideEffect::MigrateGuest {
            node: n(),
            vmid: 106,
            target_node: "pve02".into(),
        },
        "migrate",
        106,
    );
    check(
        SideEffect::ExecuteGuestCommand {
            node: n(),
            vmid: 107,
            guest_type: GuestType::Qemu,
            command: "uname -a".into(),
        },
        "exec",
        107,
    );
    check(
        SideEffect::DownloadIso {
            node: n(),
            storage: "local".into(),
            url: "https://example.invalid/debian.iso".into(),
            filename: "debian.iso".into(),
            checksum: None,
            content: "iso".into(),
        },
        "download_iso",
        0,
    );
    check(
        SideEffect::MoveDisk {
            node: n(),
            vmid: 108,
            guest_type: GuestType::Qemu,
            disk: "scsi0".into(),
            target_storage: "ceph".into(),
            delete_source: true,
        },
        "move_disk",
        108,
    );
    check(
        SideEffect::ResizeDisk {
            node: n(),
            vmid: 109,
            guest_type: GuestType::Qemu,
            disk: "scsi0".into(),
            size: "+10G".into(),
        },
        "resize_disk",
        109,
    );

    assert_non_mutating_side_effects_classify_as_none();
}

fn assert_non_mutating_side_effects_classify_as_none() {
    use proxxx::app::SideEffect;
    use proxxx::tui::hitl_action;

    let n = || "pve01".to_string();
    for effect in [
        SideEffect::Quit,
        SideEffect::FetchTaskLog {
            upid: "UPID:1".into(),
            node: n(),
        },
        SideEffect::ExecuteQueue(vec![]),
        SideEffect::ConfigGrep {
            query: "net0".into(),
        },
        SideEffect::OpenSshSession { vmid: 100 },
        SideEffect::SetSshPassphraseAndOpen {
            vmid: 100,
            passphrase: proxxx::util::secret::SecretString::new("secret".into()),
        },
        SideEffect::CloseSshSession,
        SideEffect::FetchSnapshotTree { vmid: 100 },
        SideEffect::FetchHaConsoleData,
        SideEffect::FetchHardwareData { node: n() },
        SideEffect::SwitchProfile("prod".into()),
    ] {
        assert_eq!(
            hitl_action(&effect),
            None,
            "{effect:?} must classify as None"
        );
    }
}

/// Approve `txn_id` via `TelegramGateway::build_approval_keyboard` +
/// `handle_tui_callback_query` and await `DataMsg::HitlApproved(txn_id, true, effect)`.
async fn approve_pending_tui_txn(
    tg: &TelegramGateway,
    coord: &proxxx::tui::HitlCoordinator,
    rx: &mut tokio::sync::mpsc::Receiver<proxxx::tui::DataMsg>,
    cb_id: &str,
    txn_id: &str,
) -> proxxx::app::SideEffect {
    let kb = tg.build_approval_keyboard(txn_id);
    let approve_data = &kb.inline_keyboard[0][0].callback_data;
    let cb = callback_query(cb_id, approve_data);
    let ans = proxxx::tui::handle_tui_callback_query(tg, coord, &cb).await;
    assert_eq!(ans.as_deref(), Some("✅ Approved"));

    while let Ok(Some(msg)) =
        tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await
    {
        if let proxxx::tui::DataMsg::HitlApproved(t, true, eff) = msg {
            assert_eq!(t, txn_id);
            return *eff;
        }
    }
    panic!("approval for {txn_id} must emit DataMsg::HitlApproved(..., true, _)");
}

/// Await `DataMsg::HitlRequested` on `rx` and return its `txn_id`.
async fn recv_hitl_requested(
    rx: &mut tokio::sync::mpsc::Receiver<proxxx::tui::DataMsg>,
    method_name: &str,
) -> String {
    while let Ok(Some(msg)) =
        tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv()).await
    {
        if let proxxx::tui::DataMsg::HitlRequested(txn_id, _) = msg {
            return txn_id;
        }
    }
    panic!("{method_name} under secure_mode must emit DataMsg::HitlRequested");
}

/// #339 Test 2 — Through the real `dispatch_side_effect` path (not a surrogate),
/// with `secure_mode = true` and Telegram stubbed: `DeleteGuest`, `MigrateGuest`,
/// `ExecuteGuestCommand`, `MoveDisk`, and `ResizeDisk` do NOT reach the API stub
/// before approval, and DO reach the API stub after Telegram approval.
#[tokio::test]
async fn secure_mode_forces_request_approval_for_destructive() {
    use proxxx::app::{AppState, SideEffect};
    use proxxx::tui::{dispatch_side_effect, HitlCoordinator};
    use std::sync::Arc;
    use std::time::Duration;

    let server = setup_telegram_mock().await;
    let tg = Arc::new(fake_gateway(&server));
    let coord = Arc::new(HitlCoordinator::new());

    let mut g = guest(200, "vm-prod");
    g.node = "pve01".to_string();
    let client = Arc::new(HitlMockGateway::new().with_node_and_guest("pve01", g.clone()));

    let mut state = AppState::new();
    state.secure_mode = true;
    state.guests = vec![g];

    let effects: [(&str, SideEffect); 5] = [
        ("delete_guest", SideEffect::DeleteGuest { vmid: 200 }),
        (
            "migrate_guest",
            SideEffect::MigrateGuest {
                node: "pve01".into(),
                vmid: 200,
                target_node: "pve02".into(),
            },
        ),
        (
            "execute_guest_command",
            SideEffect::ExecuteGuestCommand {
                node: "pve01".into(),
                vmid: 200,
                guest_type: GuestType::Qemu,
                command: "id".into(),
            },
        ),
        (
            "move_disk",
            SideEffect::MoveDisk {
                node: "pve01".into(),
                vmid: 200,
                guest_type: GuestType::Qemu,
                disk: "scsi0".into(),
                target_storage: "ceph".into(),
                delete_source: true,
            },
        ),
        (
            "resize_disk",
            SideEffect::ResizeDisk {
                node: "pve01".into(),
                vmid: 200,
                guest_type: GuestType::Qemu,
                disk: "scsi0".into(),
                size: "+10G".into(),
            },
        ),
    ];

    for (idx, (method_name, effect)) in effects.into_iter().enumerate() {
        let target = proxxx::tui::hitl_action(&effect).expect("destructive effect classified");
        assert!(proxxx::hitl::DESTRUCTIVE_ACTIONS.contains(&target.action));
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        dispatch_side_effect(
            effect,
            &state,
            &client,
            &tx,
            &[],
            false,
            Some(&tg),
            &coord,
            None,
        )
        .await;

        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            client.calls_for(method_name).is_empty(),
            "{method_name} must NOT reach the API stub before HITL approval"
        );

        let txn_id = recv_hitl_requested(&mut rx, method_name).await;
        let eff =
            approve_pending_tui_txn(&tg, &coord, &mut rx, &format!("cb-sec-{idx}"), &txn_id).await;
        dispatch_side_effect(
            eff,
            &state,
            &client,
            &tx,
            &[],
            true,
            Some(&tg),
            &coord,
            None,
        )
        .await;

        for _ in 0..40 {
            if !client.calls_for(method_name).is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(client.calls_for(method_name), vec![200]);
    }
}

/// #339 Test 3 — `ExecuteQueue` with one gated op (`delete`) and one non-gated
/// op (`start`, no policy, `secure_mode` does not gate `start`): `start` reaches
/// the API immediately, `delete` does not until approved.
#[tokio::test]
async fn execute_queue_gates_destructive_op_while_dispatching_non_gated_op_immediately() {
    use proxxx::app::queue::{OpStatus, QueuedOp};
    use proxxx::app::{update as app_update, Action, AppState};
    use proxxx::tui::{dispatch_side_effect, DataMsg, HitlCoordinator};
    use std::sync::Arc;
    use std::time::Duration;

    let server = setup_telegram_mock().await;
    let tg = Arc::new(fake_gateway(&server));
    let coord = Arc::new(HitlCoordinator::new());

    let mut g_start = guest(100, "vm-dev");
    g_start.node = "pve01".to_string();
    let mut g_delete = guest(200, "vm-prod");
    g_delete.node = "pve01".to_string();
    let client = Arc::new(
        HitlMockGateway::new()
            .with_node_and_guest("pve01", g_start.clone())
            .with_node_and_guest("pve01", g_delete.clone()),
    );

    let mut state = AppState::new();
    state.secure_mode = true;
    state.guests = vec![g_start, g_delete];
    state.op_queue = vec![
        QueuedOp {
            id: "op-start-100".into(),
            action: Box::new(Action::StartGuest { vmid: 100 }),
            description: "Start 100".into(),
            diff: String::new(),
            status: OpStatus::Pending,
            created_at_secs: 1,
            bypass_preflight: false,
        },
        QueuedOp {
            id: "op-delete-200".into(),
            action: Box::new(Action::DeleteGuest { vmid: 200 }),
            description: "Delete 200".into(),
            diff: String::new(),
            status: OpStatus::Pending,
            created_at_secs: 2,
            bypass_preflight: false,
        },
    ];

    let effect = app_update(&mut state, Action::ExecuteQueue).expect("ExecuteQueue side effect");
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    dispatch_side_effect(
        effect,
        &state,
        &client,
        &tx,
        &[],
        false,
        Some(&tg),
        &coord,
        Some("hitl_e2e_queue_test"),
    )
    .await;

    let mut start_succeeded = false;
    let mut delete_txn_id = None;
    let deadline = tokio::time::Instant::now() + Duration::from_millis(300);
    while tokio::time::Instant::now() < deadline && (!start_succeeded || delete_txn_id.is_none()) {
        if let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(25), rx.recv()).await {
            match msg {
                DataMsg::QueueOpStatusChanged(id, OpStatus::Success) if id == "op-start-100" => {
                    start_succeeded = true;
                }
                DataMsg::HitlRequested(txn_id, _) => {
                    delete_txn_id = Some(txn_id);
                }
                _ => {}
            }
        }
    }

    assert_eq!(client.calls_for("start_guest"), vec![100]);
    assert!(
        client.calls_for("delete_guest").is_empty(),
        "gated delete op in ExecuteQueue must NOT reach the API before approval"
    );
    let txn_id = delete_txn_id.expect("gated delete op must emit DataMsg::HitlRequested");

    let eff = approve_pending_tui_txn(&tg, &coord, &mut rx, "cb-queue-del", &txn_id).await;
    dispatch_side_effect(
        eff,
        &state,
        &client,
        &tx,
        &[],
        true,
        Some(&tg),
        &coord,
        Some("hitl_e2e_queue_test"),
    )
    .await;

    for _ in 0..40 {
        if !client.calls_for("delete_guest").is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(client.calls_for("delete_guest"), vec![200]);
}

/// #339 queue fixup — The queue dispatcher derives `target_vmid` solely from
/// `queued_action_hitl_target`: any `Action` not known to that HITL classifier
/// fails closed (`OpStatus::Error("Invalid Action")`) and is not dispatched to
/// the API gateway.
#[tokio::test]
async fn execute_queue_refuses_unclassified_action_without_dispatching() {
    use proxxx::app::queue::{OpStatus, QueuedOp};
    use proxxx::app::{update as app_update, Action, AppState};
    use proxxx::tui::{dispatch_side_effect, DataMsg, HitlCoordinator};
    use std::sync::Arc;
    use std::time::Duration;

    let coord = Arc::new(HitlCoordinator::new());
    let mut g = guest(100, "vm-dev");
    g.node = "pve01".to_string();
    let client = Arc::new(HitlMockGateway::new().with_node_and_guest("pve01", g.clone()));

    let mut state = AppState::new();
    state.guests = vec![g];
    state.op_queue = vec![QueuedOp {
        id: "op-unclassified-snap".into(),
        action: Box::new(Action::CreateSnapshot {
            vmid: 100,
            name: "snap".into(),
        }),
        description: "Snapshot 100".into(),
        diff: String::new(),
        status: OpStatus::Pending,
        created_at_secs: 1,
        bypass_preflight: false,
    }];

    let effect = app_update(&mut state, Action::ExecuteQueue).expect("ExecuteQueue side effect");
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    dispatch_side_effect(
        effect,
        &state,
        &client,
        &tx,
        &[],
        false,
        None,
        &coord,
        Some("hitl_e2e_unclassified_queue_test"),
    )
    .await;

    let mut invalid_status_seen = false;
    while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(150), rx.recv()).await {
        if let DataMsg::QueueOpStatusChanged(id, OpStatus::Error(err)) = msg {
            if id == "op-unclassified-snap" && err.contains("Invalid Action") {
                invalid_status_seen = true;
                break;
            }
        }
    }
    assert!(
        invalid_status_seen,
        "unclassified queued action must fail closed with OpStatus::Error(\"Invalid Action\")"
    );
    assert!(
        client.calls_for("create_snapshot").is_empty(),
        "unclassified queued action must not dispatch to the gateway"
    );
}

/// Bonus: invalid callback data is rejected without invoking the gateway.
/// This guards against the daemon executing on garbled input.
#[tokio::test]
async fn invalid_callback_format_does_not_invoke_gateway() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();
    let client = HitlMockGateway::new();

    // Missing HMAC suffix.
    let cb = callback_query("cb-bad", "approve:stop");
    let upd = update(3, cb);
    let outcome = handle_callback_update(&upd, &pending, &client, &tg)
        .await
        .expect("handle");
    assert!(matches!(outcome, CallbackOutcome::InvalidFormat { .. }));
    assert!(client.calls_for("shutdown_guest").is_empty());
    assert!(client.calls_for("start_guest").is_empty());
    assert_eq!(pending.consumed_count(), 0);
}

/// Bonus: deny callbacks mark the pending request as Denied and do not invoke the gateway.
#[tokio::test]
async fn deny_callback_does_not_invoke_gateway() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();
    let client = HitlMockGateway::new().with_node_and_guest("pve01", guest(50, "vm-test"));

    let id = mint_pending(&pending, "stop", 50, 1);
    let cb = callback_query("cb-deny", &signed(tg.hmac_key(), &format!("deny:{id}")));
    let upd = update(4, cb);
    let outcome = handle_callback_update(&upd, &pending, &client, &tg)
        .await
        .expect("handle");
    assert!(matches!(outcome, CallbackOutcome::Denied { vmid: 50, .. }));
    assert!(client.calls_for("shutdown_guest").is_empty());
}

/// HITL UX polish — verifies the deferred-edit pattern: an op that
/// completes in <1s MUST NOT trigger an `⏳ Executing…` edit
/// (otherwise mobile Telegram clients collapse it into the final edit
/// causing invisible flicker). The mock gateway returns immediately,
/// simulating fast PVE response. We assert by counting editMessageText
/// requests with the `⏳` marker — should be ZERO.
#[tokio::test]
async fn fast_op_skips_intermediate_executing_edit() {
    use wiremock::matchers::body_string_contains;
    let server = MockServer::start().await;

    // The standard mocks (answerCallbackQuery, editMessageText "✅",
    // etc.) — re-mounted here so we can also assert on the
    // intermediate one specifically.
    Mock::given(method("POST"))
        .and(path("/botfaketoken/answerCallbackQuery"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true, "result": true,
        })))
        .mount(&server)
        .await;
    // ⏳ edit MUST NOT fire on a fast op — assert .expect(0).
    Mock::given(method("POST"))
        .and(path("/botfaketoken/editMessageText"))
        .and(body_string_contains("Executing"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true, "result": { "message_id": 42 },
        })))
        .expect(0)
        .mount(&server)
        .await;
    // Final edit (any other body) — match-all fallthrough.
    Mock::given(method("POST"))
        .and(path("/botfaketoken/editMessageText"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "ok": true, "result": { "message_id": 42 },
        })))
        .mount(&server)
        .await;

    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();
    let client = HitlMockGateway::new().with_node_and_guest("pve01", guest(100, "vm-prod-01"));

    // Build a CallbackQuery that includes a `message` so the daemon
    // has a message_id to (potentially) edit. v0.1.22+: sign the
    // callback_data; unsigned shapes are refused upstream.
    let id = mint_pending(&pending, "restart", 100, 1);
    let data = signed(tg.hmac_key(), &format!("approve:{id}"));
    let cb_json = serde_json::json!({
        "id": "cb-fast",
        "from": { "id": TEST_APPROVER, "first_name": "tester" },
        "data": data,
        "message": { "message_id": 42, "chat": { "id": 12345_i64 } },
    });
    let upd: Update = serde_json::from_value(serde_json::json!({
        "update_id": 99,
        "callback_query": cb_json,
    }))
    .expect("Update deserializes");

    // Fast mock — `restart_guest` returns instantly. `select!` should
    // pick the API arm before the 1s timer fires; intermediate edit
    // never sent.
    let outcome = handle_callback_update(&upd, &pending, &client, &tg)
        .await
        .expect("handle");
    assert!(matches!(
        outcome,
        CallbackOutcome::Executed { vmid: 100, .. }
    ));
    // Drop server → wiremock asserts .expect(0) on the ⏳ mock.
    drop(server);
}

/// Bonus: token resolution hierarchy. Verifies Part A by checking that
/// `PROXXX_TELEGRAM_BOT_TOKEN` env var beats inline `bot_token` in the
/// TOML. This is the property operators rely on for credential rotation.
#[tokio::test]
#[serial_test::serial] // env vars are process-global
async fn env_var_beats_inline_bot_token() {
    let cfg = proxxx::config::TelegramConfig {
        allowed_approvers: None,
        bot_token: Some(proxxx::util::secret::SecretString::from("inline-loser")),
        bot_token_file: None,
        chat_id: "12345".to_string(),
    };

    // Sanity: with no env, inline wins.
    std::env::remove_var("PROXXX_TELEGRAM_BOT_TOKEN");
    let resolved = cfg.resolve_bot_token().await.expect("resolve");
    assert_eq!(resolved.as_str(), "inline-loser");

    // With env set, env wins.
    std::env::set_var("PROXXX_TELEGRAM_BOT_TOKEN", "env-winner");
    let resolved = cfg.resolve_bot_token().await.expect("resolve");
    assert_eq!(resolved.as_str(), "env-winner");
    std::env::remove_var("PROXXX_TELEGRAM_BOT_TOKEN");
}

/// Bonus: `bot_token_file` with insecure permissions is refused.
/// Closes the operator footgun where someone copies their token into
/// a 0644 file and forgets to chmod.
#[cfg(unix)]
#[tokio::test]
#[serial_test::serial]
async fn bot_token_file_with_lax_permissions_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bot_token");
    std::fs::write(&path, "secret-token-here").expect("write");
    // Deliberately lax — group + world readable.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

    let cfg = proxxx::config::TelegramConfig {
        allowed_approvers: None,
        bot_token: None,
        bot_token_file: Some(path.to_string_lossy().to_string()),
        chat_id: "12345".to_string(),
    };
    // Make sure no env override leaks in from a previous serial test.
    std::env::remove_var("PROXXX_TELEGRAM_BOT_TOKEN");

    let err = cfg
        .resolve_bot_token()
        .await
        .expect_err("must refuse lax permissions");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("0600") || msg.contains("unsafe permissions"),
        "error must mention permission requirement: {msg}"
    );
}

// Suppress "unused" warnings for helpers that may not be hit in every
// reduced-test run.
#[allow(dead_code)]
fn _force_link(_u: User) {}

// ── Phase 17: HMAC-signed callback_data ─────────────────────────────────

/// Signed callback with a valid tag passes verification and executes
/// when the request id exists in `PendingStore`.
#[tokio::test]
async fn signed_callback_with_valid_tag_executes() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();
    let client = HitlMockGateway::new().with_node_and_guest("pve01", guest(7, "vm-signed-ok"));

    let id = mint_pending(&pending, "stop", 7, 1);
    let payload = format!("approve:{id}");
    let tag = proxxx::hitl::hmac_key::sign(tg.hmac_key(), &payload);
    let signed_data = format!("{payload}:{tag}");

    let cb = callback_query("cb-sig-ok", &signed_data);
    let upd = update(11, cb);

    let outcome = handle_callback_update(&upd, &pending, &client, &tg)
        .await
        .expect("handle");
    assert!(
        matches!(outcome, CallbackOutcome::Executed { vmid: 7, .. }),
        "valid HMAC must pass through to execute, got {outcome:?}"
    );
    assert_eq!(client.calls_for("shutdown_guest"), vec![7]);
}

/// Tampered tag fails verification — daemon refuses to execute and
/// surfaces `InvalidFormat`. This is the defence-in-depth claim
/// against bot-token leak: an attacker who can inject a forged
/// callback CAN'T pass the HMAC step without also stealing the
/// separately-stored HMAC key.
#[tokio::test]
async fn callback_with_tampered_tag_is_refused() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();
    let client = HitlMockGateway::new().with_node_and_guest("pve01", guest(8, "vm-untrusted"));

    let id = mint_pending(&pending, "stop", 8, 1);
    let payload = format!("approve:{id}");
    let mut tag = proxxx::hitl::hmac_key::sign(tg.hmac_key(), &payload);
    // Flip one hex digit — the verifier compares constant-time so
    // any single-bit difference rejects.
    let last = tag.pop().expect("tag non-empty");
    let flipped = if last == '0' { '1' } else { '0' };
    tag.push(flipped);
    let tampered = format!("{payload}:{tag}");

    let cb = callback_query("cb-tampered", &tampered);
    let upd = update(12, cb);

    let outcome = handle_callback_update(&upd, &pending, &client, &tg)
        .await
        .expect("handle");
    assert!(
        matches!(outcome, CallbackOutcome::InvalidFormat { .. }),
        "tampered tag must be refused, got {outcome:?}"
    );
    // Critical: no PVE-side call must have been made.
    assert!(client.calls_for("shutdown_guest").is_empty());
    assert!(client.calls_for("start_guest").is_empty());
    assert_eq!(
        pending.consumed_count(),
        0,
        "txn must not be marked consumed"
    );
}

/// Tag signed with a different key fails — models the bot-token-leak
/// scenario where the attacker can inject `callback_data` but doesn't
/// have the HMAC key. The forged tag is mathematically valid hex but
/// computed under the wrong secret.
#[tokio::test]
async fn callback_signed_with_wrong_key_is_refused() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();
    let client = HitlMockGateway::new().with_node_and_guest("pve01", guest(9, "vm-target"));

    // Attacker's key — different from the all-zeros key the test
    // gateway holds. Both are 32 bytes so the signing succeeds; only
    // the verifier catches the mismatch.
    let attacker_key = vec![0x42u8; 32];
    let id = mint_pending(&pending, "stop", 9, 1);
    let payload = format!("approve:{id}");
    let attacker_tag = proxxx::hitl::hmac_key::sign(&attacker_key, &payload);
    let forged = format!("{payload}:{attacker_tag}");

    let cb = callback_query("cb-wrong-key", &forged);
    let upd = update(13, cb);

    let outcome = handle_callback_update(&upd, &pending, &client, &tg)
        .await
        .expect("handle");
    assert!(
        matches!(outcome, CallbackOutcome::InvalidFormat { .. }),
        "wrong-key forgery must be refused, got {outcome:?}"
    );
    assert!(client.calls_for("shutdown_guest").is_empty());
}

/// v0.1.22: the one-release shim from v0.1.21 is gone. Unsigned
/// callbacks are now refused outright — symmetric with the
/// tampered-tag / wrong-key tests above. The test name was
/// `legacy_unsigned_callback_still_accepted_in_v0_1_21` and is now
/// inverted; the original test name is preserved in this comment so
/// `git log --grep` finds the v0.1.21 → v0.1.22 transition.
///
/// Critical assertions:
///   1. Outcome is `InvalidFormat`, not `Executed`.
///   2. No PVE-side mutation was attempted (the unsigned callback is
///      rejected BEFORE the gateway is touched).
///   3. The replay-protection store stays untouched — a refused
///      unsigned callback must not consume the txn slot, otherwise
///      a re-signed retry of the SAME txn would falsely 401 as
///      replay.
#[tokio::test]
async fn legacy_unsigned_callback_is_refused_in_v0_1_22() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();
    let client = HitlMockGateway::new().with_node_and_guest("pve01", guest(10, "vm-legacy"));

    // No `:hex16` tail — pre-Phase-17 shape.
    let cb = callback_query("cb-legacy", "approve:stop:10");
    let upd = update(14, cb);

    let outcome = handle_callback_update(&upd, &pending, &client, &tg)
        .await
        .expect("handle");
    assert!(
        matches!(outcome, CallbackOutcome::InvalidFormat { .. }),
        "legacy unsigned callback must be refused in v0.1.22+, got {outcome:?}"
    );
    assert!(client.calls_for("shutdown_guest").is_empty());
    assert_eq!(
        pending.consumed_count(),
        0,
        "refused txn must not consume the slot"
    );
}

// ── Issues #336 + #337: Unified callback verification & TUI round-trip ──

/// Issue #336: TUI round trip with a stub gateway — register a txn via the
/// TUI coordinator, build the `callback_data` with the REAL keyboard builder
/// from `telegram.rs` (`build_approval_keyboard`), feed it to the TUI poller's
/// handling function (`handle_tui_callback_query`) -> the op resolves approved.
#[tokio::test]
async fn tui_round_trip_with_real_keyboard_builder_resolves_approved() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let coord = proxxx::tui::HitlCoordinator::new();

    let txn_id = proxxx::hitl::pending::generate_request_id().expect("id");
    let mut rx = coord.register(txn_id.clone()).await;

    // Build callback_data with the REAL keyboard builder from telegram.rs.
    let keyboard = tg.build_approval_keyboard(&txn_id);
    let approve_btn = &keyboard.inline_keyboard[0][0];
    assert!(approve_btn.text.contains("Approve"));

    let cb: CallbackQuery = serde_json::from_value(serde_json::json!({
        "id": "cb-tui-ok",
        "from": { "id": TEST_APPROVER, "first_name": "tester" },
        "data": approve_btn.callback_data,
        "message": { "message_id": 42_i64, "chat": { "id": 12345_i64 } },
    }))
    .expect("CallbackQuery deserializes");

    let answer = proxxx::tui::handle_tui_callback_query(&tg, &coord, &cb)
        .await
        .expect("callback answered");
    assert!(
        answer.contains("Approved") || answer.contains("Executed"),
        "expected Approved/Executed callback answer, got: {answer}"
    );

    let resolved = rx
        .try_recv()
        .expect("TUI pending op must be resolved after valid approve callback");
    assert!(resolved, "op must resolve as approved (true)");
}

fn build_tui_callback_for_test(
    id: &str,
    from_id: i64,
    first_name: &str,
    data: &str,
    chat_id: i64,
) -> CallbackQuery {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "from": { "id": from_id, "first_name": first_name },
        "data": data,
        "message": { "message_id": 1_i64, "chat": { "id": chat_id } },
    }))
    .expect("CallbackQuery")
}

async fn assert_tui_rejections(
    tg: &TelegramGateway,
    coord: &proxxx::tui::HitlCoordinator,
    rx: &mut tokio::sync::oneshot::Receiver<bool>,
    approve_data: &str,
) {
    // 1. Wrong chat id -> NOT resolved, answer explains wrong chat.
    let cb_wrong_chat = build_tui_callback_for_test(
        "cb-wrong-chat",
        TEST_APPROVER,
        "tester",
        approve_data,
        99999,
    );
    let ans = proxxx::tui::handle_tui_callback_query(tg, coord, &cb_wrong_chat)
        .await
        .expect("answer");
    assert!(
        ans.to_ascii_lowercase().contains("wrong chat"),
        "wrong chat answer must explain why, got: {ans}"
    );
    assert!(
        rx.try_recv().is_err(),
        "wrong chat must not resolve the pending op"
    );

    // 2. Sender not in allowed_approvers -> NOT resolved, answer explains unauthorised.
    let cb_unlisted =
        build_tui_callback_for_test("cb-unlisted", 7777, "intruder", approve_data, 12345);
    let ans = proxxx::tui::handle_tui_callback_query(tg, coord, &cb_unlisted)
        .await
        .expect("answer");
    assert!(
        ans.to_ascii_lowercase()
            .contains("not an authorised approver")
            || ans.to_ascii_lowercase().contains("refused"),
        "unauthorised sender answer must explain why, got: {ans}"
    );
    assert!(
        rx.try_recv().is_err(),
        "unauthorised sender must not resolve the pending op"
    );

    // 3. Tampered HMAC -> NOT resolved, answer explains signature failure.
    let mut tampered = approve_data.to_string();
    let last = tampered.pop().expect("non-empty");
    tampered.push(if last == '0' { '1' } else { '0' });
    let cb_tampered =
        build_tui_callback_for_test("cb-tampered", TEST_APPROVER, "tester", &tampered, 12345);
    let ans = proxxx::tui::handle_tui_callback_query(tg, coord, &cb_tampered)
        .await
        .expect("answer");
    assert!(
        ans.to_ascii_lowercase().contains("signature"),
        "tampered HMAC answer must mention signature verification failure, got: {ans}"
    );
    assert!(
        rx.try_recv().is_err(),
        "tampered HMAC must not resolve the pending op"
    );
}

/// Issue #337: TUI rejections (wrong chat id, sender not in `allowed_approvers`,
/// tampered HMAC -> op NOT resolved and the callback answer says why) and
/// `require = 2` quorum enforcement (one press -> not resolved; same user twice
/// -> not resolved; a second distinct approver -> resolved).
#[tokio::test]
async fn tui_rejections_and_quorum_enforcement() {
    const SECOND_APPROVER: i64 = 5150;
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server).with_allowed_approvers(vec![TEST_APPROVER, SECOND_APPROVER]);
    let coord = proxxx::tui::HitlCoordinator::new();

    let txn_id = proxxx::hitl::pending::generate_request_id().expect("id");
    let mut rx = coord.register_with_quorum(txn_id.clone(), 2).await;

    let keyboard = tg.build_approval_keyboard(&txn_id);
    let approve_data = keyboard.inline_keyboard[0][0].callback_data.clone();

    assert_tui_rejections(&tg, &coord, &mut rx, &approve_data).await;

    // 4. Quorum require = 2: first press by TEST_APPROVER -> recorded (1/2), NOT resolved.
    let cb_vote1 =
        build_tui_callback_for_test("cb-vote1", TEST_APPROVER, "tester", &approve_data, 12345);
    let ans1 = proxxx::tui::handle_tui_callback_query(&tg, &coord, &cb_vote1)
        .await
        .expect("answer");
    assert!(
        ans1.contains("1/2"),
        "first vote of require=2 must report 1/2 progress, got: {ans1}"
    );
    assert!(
        rx.try_recv().is_err(),
        "single vote must not resolve a require=2 op"
    );

    // 5. Same user pressing a second time -> duplicate (1/2), still NOT resolved.
    let ans1_dup = proxxx::tui::handle_tui_callback_query(&tg, &coord, &cb_vote1)
        .await
        .expect("answer");
    assert!(
        ans1_dup.contains("already approved") && ans1_dup.contains("1/2"),
        "duplicate vote must report already approved 1/2, got: {ans1_dup}"
    );
    assert!(
        rx.try_recv().is_err(),
        "same approver pressing twice must not resolve a require=2 op"
    );

    // 6. Second distinct approver -> resolves approved!
    let cb_vote2 =
        build_tui_callback_for_test("cb-vote2", SECOND_APPROVER, "second", &approve_data, 12345);
    let ans2 = proxxx::tui::handle_tui_callback_query(&tg, &coord, &cb_vote2)
        .await
        .expect("answer");
    assert!(
        ans2.contains("Approved") || ans2.contains("Executed"),
        "second distinct vote must report Approved/Executed, got: {ans2}"
    );
    assert!(rx.try_recv().expect("require=2 op must now resolve"));

    // 7. Subsequent press after resolution -> "Expired or unknown request".
    let ans_stale = proxxx::tui::handle_tui_callback_query(&tg, &coord, &cb_vote2)
        .await
        .expect("answer");
    assert!(
        ans_stale.contains("Expired or unknown request"),
        "callback for already-resolved/unknown txn must say 'Expired or unknown request', got: {ans_stale}"
    );
}

/// Requirement 4: Daemon behaviour unchanged and `verify_callback` enforces
/// HMAC, `chat_id`, `allowed_approvers`, and payload parsing in order before
/// `handle_callback_update` dispatches.
#[tokio::test]
async fn daemon_verify_callback_and_handle_callback_update_round_trip() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();
    let id = mint_pending(&pending, "stop", 100, 1);
    let keyboard = tg.build_approval_keyboard(&id);
    let approve_data = keyboard.inline_keyboard[0][0].callback_data.clone();

    let cb: CallbackQuery = serde_json::from_value(serde_json::json!({
        "id": "cb-daemon-verify",
        "from": { "id": TEST_APPROVER, "first_name": "tester" },
        "data": approve_data,
        "message": { "message_id": 10_i64, "chat": { "id": 12345_i64 } },
    }))
    .expect("CallbackQuery");

    let verified = proxxx::hitl::daemon::verify_callback(&tg, &cb)
        .expect("verify_callback must accept valid signed callback");
    assert_eq!(
        verified.decision,
        proxxx::hitl::daemon::CallbackDecision::Approve
    );
    assert_eq!(verified.txn_id, id);
    assert_eq!(verified.approver_id, TEST_APPROVER);

    let gw = HitlMockGateway::new().with_node_and_guest("pve01", guest(100, "vm-100"));
    let out = handle_callback_update(&update(1, cb), &pending, &gw, &tg)
        .await
        .expect("handle_callback_update");
    assert!(
        matches!(out, CallbackOutcome::Executed { vmid: 100, .. }),
        "daemon must execute after verify_callback, got {out:?}"
    );
}

/// A callback without an originating chat (`message: None` or `message.chat: None`)
/// must be rejected by `verify_callback`, the daemon, and the TUI poller.
#[tokio::test]
async fn callback_without_originating_chat_is_rejected() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let coord = proxxx::tui::HitlCoordinator::new();
    let (_dir, pending) = temp_pending_store();
    let txn_id = mint_pending(&pending, "stop", 100, 1);
    let mut rx = coord.register(txn_id.clone()).await;

    let keyboard = tg.build_approval_keyboard(&txn_id);
    let approve_data = keyboard.inline_keyboard[0][0].callback_data.clone();

    let cb_no_message: CallbackQuery = serde_json::from_value(serde_json::json!({
        "id": "cb-no-msg",
        "from": { "id": TEST_APPROVER, "first_name": "tester" },
        "data": approve_data,
    }))
    .expect("CallbackQuery");

    let cb_no_chat: CallbackQuery = serde_json::from_value(serde_json::json!({
        "id": "cb-no-chat",
        "from": { "id": TEST_APPROVER, "first_name": "tester" },
        "data": approve_data,
        "message": { "message_id": 1_i64 },
    }))
    .expect("CallbackQuery");

    for cb in [&cb_no_message, &cb_no_chat] {
        let verified = proxxx::hitl::daemon::verify_callback(&tg, cb);
        assert_eq!(
            verified,
            Err(proxxx::hitl::daemon::CallbackRejection::MissingChat),
            "verify_callback must reject callback without chat as MissingChat"
        );

        let ans = proxxx::tui::handle_tui_callback_query(&tg, &coord, cb)
            .await
            .expect("answer");
        assert!(
            ans.to_ascii_lowercase().contains("wrong chat"),
            "TUI rejection for missing chat must explain wrong chat, got: {ans}"
        );
        assert!(
            rx.try_recv().is_err(),
            "callback without chat must not resolve TUI pending op"
        );

        let gw = HitlMockGateway::new().with_node_and_guest("pve1", guest(100, "vm-100"));
        let out = handle_callback_update(&update(1, cb.clone()), &pending, &gw, &tg)
            .await
            .expect("handle_callback_update");
        assert!(
            matches!(out, CallbackOutcome::WrongChat { .. }),
            "daemon must reject callback without chat as WrongChat, got: {out:?}"
        );
        assert!(
            gw.calls_for("shutdown_guest").is_empty(),
            "callback without chat must not execute on gateway"
        );
    }
}

// ── Issue #338: CLI `--secure` destructive-operation gate ───────────────

fn write_dead_cluster_config(dir: &std::path::Path) -> std::path::PathBuf {
    let cfg_path = dir.join("config.toml");
    std::fs::write(
        &cfg_path,
        "url = \"https://127.0.0.1:1/\"\n\
         user = \"root@pam\"\n\
         token_id = \"test\"\n\
         token_secret = \"00000000-0000-0000-0000-000000000000\"\n\
         verify_tls = false\n",
    )
    .expect("write config.toml");
    cfg_path
}

fn run_proxxx_with_dead_config(
    cfg_path: &std::path::Path,
    audit_dir: &std::path::Path,
    args: &[&str],
) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .args(args)
        .env("PROXXX_CONFIG", cfg_path)
        .env("PROXXX_AUDIT_DIR", audit_dir)
        .output()
        .expect("spawn proxxx")
}

/// #338 Test 1 — End-to-end with the built binary, temp `PROXXX_CONFIG`
/// pointing at `https://127.0.0.1:1/`, temp `PROXXX_AUDIT_DIR`:
/// `--secure delete 100 --yes`, `--secure stop 100`, and
/// `--secure migrate 100 x` exit 8 and do not attempt a connection
/// (the error is the `--secure` refusal, not a transport error).
#[test]
fn cli_secure_refuses_destructive_commands_with_exit_8_before_connecting() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_dir = tempfile::tempdir().expect("audit tempdir");
    let cfg_path = write_dead_cluster_config(dir.path());

    let cases: [(&[&str], &str); 3] = [
        (&["--secure", "delete", "100", "--yes"], "delete"),
        (&["--secure", "stop", "100"], "stop"),
        (&["--secure", "migrate", "100", "x"], "migrate"),
    ];

    for (args, expected_action) in cases {
        let out = run_proxxx_with_dead_config(&cfg_path, audit_dir.path(), args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(8),
            "expected exit 8 for `{args:?}`, got {:?}\nstderr: {stderr}",
            out.status.code()
        );
        assert!(
            stderr.contains(&format!("--secure: {expected_action} requires human approval")),
            "stderr for `{args:?}` must contain the --secure refusal for `{expected_action}`, got:\n{stderr}"
        );
        assert!(
            !stderr.contains("127.0.0.1:1") && !stderr.contains("Connection refused"),
            "`{args:?}` must refuse BEFORE any connection attempt, got:\n{stderr}"
        );
    }
}

/// #338 Test 2 — `--secure ls nodes` (non-destructive) gets past the
/// `--secure` gate and fails later with the transport error (`exit != 8`).
#[test]
fn cli_secure_allows_non_destructive_commands_past_the_gate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_dir = tempfile::tempdir().expect("audit tempdir");
    let cfg_path = write_dead_cluster_config(dir.path());

    let out =
        run_proxxx_with_dead_config(&cfg_path, audit_dir.path(), &["--secure", "ls", "nodes"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "`--secure ls nodes` against 127.0.0.1:1 must fail at transport layer"
    );
    assert_ne!(
        out.status.code(),
        Some(8),
        "`--secure ls nodes` must NOT be refused with exit 8, stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("requires human approval"),
        "non-destructive `ls nodes` must not trigger the --secure refusal:\n{stderr}"
    );
    assert!(
        stderr.contains("127.0.0.1:1") || stderr.contains("error sending request"),
        "`--secure ls nodes` must reach the HTTP transport layer, got:\n{stderr}"
    );
}

fn build_tui_destructive_effect(action: &str) -> proxxx::app::SideEffect {
    use proxxx::app::SideEffect;

    match action {
        "stop" => SideEffect::StopGuest {
            vmid: 100,
            force: false,
        },
        "delete" => SideEffect::DeleteGuest { vmid: 100 },
        "restart" => SideEffect::RestartGuest { vmid: 100 },
        "migrate" => SideEffect::MigrateGuest {
            node: "pve1".into(),
            vmid: 100,
            target_node: "pve2".into(),
        },
        "exec" => SideEffect::ExecuteGuestCommand {
            node: "pve1".into(),
            vmid: 100,
            guest_type: GuestType::Qemu,
            command: "id".into(),
        },
        "move_disk" => SideEffect::MoveDisk {
            node: "pve1".into(),
            vmid: 100,
            guest_type: GuestType::Qemu,
            disk: "scsi0".into(),
            target_storage: "ceph".into(),
            delete_source: true,
        },
        "resize_disk" => SideEffect::ResizeDisk {
            node: "pve1".into(),
            vmid: 100,
            guest_type: GuestType::Qemu,
            disk: "scsi0".into(),
            size: "+10G".into(),
        },
        other => panic!("unmapped destructive action in TUI test helper: {other}"),
    }
}

fn build_cli_destructive_command(action: &str) -> proxxx::cli::Command {
    use proxxx::cli::vm::DiskCommand;
    use proxxx::cli::Command;

    match action {
        "stop" => Command::Stop {
            vmids: vec![100],
            force: false,
            strict: false,
            allow_risk: false,
            stop_timeout: 60,
            policy: "continue".into(),
        },
        "delete" => Command::Delete {
            vmids: vec![100],
            yes: true,
            strict: false,
            allow_risk: false,
        },
        "restart" => Command::Restart {
            vmids: vec![100],
            strict: false,
            allow_risk: false,
            policy: "continue".into(),
        },
        "migrate" => Command::Migrate {
            vmid: 100,
            target: "pve2".into(),
            yes: true,
            with_local_disks: false,
            allow_risk: false,
            wait: false,
            stream: false,
        },
        "exec" => Command::Exec {
            vmid: 100,
            command: vec!["id".into()],
        },
        "move_disk" => Command::Disk {
            action: DiskCommand::Move {
                vmid: 100,
                disk: "scsi0".into(),
                storage: "ceph".into(),
                delete_source: true,
                yes: true,
                allow_risk: false,
                wait: false,
            },
        },
        "resize_disk" => Command::Disk {
            action: DiskCommand::Resize {
                vmid: 100,
                disk: "scsi0".into(),
                size: "+10G".into(),
                yes: true,
                allow_risk: false,
            },
        },
        other => panic!("unmapped destructive action in CLI test helper: {other}"),
    }
}

/// #338 Test 3 — The single shared `proxxx::hitl::DESTRUCTIVE_ACTIONS` set and
/// `proxxx::hitl::is_destructive_action` helper are consulted by both the TUI
/// classifier (`proxxx::tui::hitl_action`) and the CLI `--secure` gate
/// (`proxxx::cli::cli_hitl_action` + `proxxx::cli::enforce_cli_secure_mode`).
#[test]
fn shared_destructive_actions_gate_both_tui_and_cli() {
    use proxxx::cli::Command;
    use proxxx::hitl::{is_destructive_action, SecureModeRefusal, DESTRUCTIVE_ACTIONS};

    assert_eq!(
        DESTRUCTIVE_ACTIONS,
        &[
            "stop",
            "delete",
            "restart",
            "migrate",
            "exec",
            "move_disk",
            "resize_disk"
        ]
    );
    assert_eq!(SecureModeRefusal::EXIT_CODE, 8);

    for &expected in DESTRUCTIVE_ACTIONS {
        assert!(is_destructive_action(expected));
        let effect = build_tui_destructive_effect(expected);
        let tui_target = proxxx::tui::hitl_action(&effect).expect("TUI classifies destructive op");
        assert_eq!(tui_target.action, expected);
        assert!(is_destructive_action(tui_target.action));

        let cmd = build_cli_destructive_command(expected);
        assert_eq!(proxxx::cli::cli_hitl_action(&cmd), Some(expected));
        assert!(
            proxxx::cli::enforce_cli_secure_mode(&cmd, false).is_ok(),
            "without --secure, `{expected}` is not refused by enforce_cli_secure_mode"
        );
        let err = proxxx::cli::enforce_cli_secure_mode(&cmd, true)
            .expect_err("with --secure, destructive CLI command must be refused");
        let refusal = err
            .downcast_ref::<SecureModeRefusal>()
            .expect("error must downcast to SecureModeRefusal");
        assert_eq!(refusal.action, expected);
    }

    for non_destructive in ["start", "snapshot", "download_iso", "ls"] {
        assert!(!is_destructive_action(non_destructive));
    }
    let start_cmd = Command::Start {
        vmids: vec![100],
        strict: false,
        policy: "continue".into(),
    };
    assert!(proxxx::cli::enforce_cli_secure_mode(&start_cmd, true).is_ok());
}

// ── Issue #341: Persisted pending-approval store, random IDs & TTL ──────

/// #341 Test 1 — Replay after daemon restart (reopening the `SQLite` store from
/// the same on-disk path) is refused with `CallbackOutcome::Replay` and does
/// NOT re-execute the PVE mutation.
#[tokio::test]
async fn replay_after_daemon_restart_is_refused() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("hitl_pending.db");
    let client = HitlMockGateway::new().with_node_and_guest("pve01", guest(100, "vm-prod-01"));

    let id = {
        let store1 = PendingApprovals::open_at(&db_path).expect("open store1");
        let id = mint_pending(&store1, "stop", 100, 1);
        let data = signed(tg.hmac_key(), &format!("approve:{id}"));
        let out1 = handle_callback_update(
            &update(1, callback_query("cb-r1", &data)),
            &store1,
            &client,
            &tg,
        )
        .await
        .expect("first delivery");
        assert!(matches!(out1, CallbackOutcome::Executed { vmid: 100, .. }));
        id
    };
    assert_eq!(client.calls_for("shutdown_guest"), vec![100]);

    // Simulate daemon restart by opening a fresh PendingStore handle on the same file.
    let store2 = PendingApprovals::open_at(&db_path).expect("reopen store2");
    let data = signed(tg.hmac_key(), &format!("approve:{id}"));
    let out2 = handle_callback_update(
        &update(2, callback_query("cb-r2", &data)),
        &store2,
        &client,
        &tg,
    )
    .await
    .expect("replay delivery after restart");
    assert!(
        matches!(out2, CallbackOutcome::Replay { ref txn_id } if txn_id == &id),
        "replay after daemon restart must be refused, got {out2:?}"
    );
    assert_eq!(
        client.calls_for("shutdown_guest"),
        vec![100],
        "shutdown_guest must not be called a second time after daemon restart"
    );
}

/// #341 Test 2 — An expired request (`expires_at < now`) is refused with
/// `CallbackOutcome::Expired`, transitions to `status = 'expired'` in `SQLite`,
/// and does not invoke the PVE gateway.
#[tokio::test]
async fn expired_request_is_refused_and_not_executed() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();
    let client = HitlMockGateway::new().with_node_and_guest("pve01", guest(100, "vm-prod-01"));

    let now = proxxx::hitl::pending::now_unix_secs();
    let id = pending
        .insert_at(
            &proxxx::hitl::pending::NewPendingRequest::new("stop", Some(100), 1)
                .with_node("pve01")
                .with_guest_type(GuestType::Qemu)
                .with_ttl_secs(120),
            now - 300,
        )
        .expect("insert expired request")
        .id;

    let data = signed(tg.hmac_key(), &format!("approve:{id}"));
    let out = handle_callback_update(
        &update(1, callback_query("cb-exp", &data)),
        &pending,
        &client,
        &tg,
    )
    .await
    .expect("handle expired");
    assert!(
        matches!(out, CallbackOutcome::Expired { id: ref exp_id } if exp_id == &id),
        "expired request must return CallbackOutcome::Expired, got {out:?}"
    );
    assert!(client.calls_for("shutdown_guest").is_empty());
    let row = pending.get(&id).expect("get").expect("row");
    assert_eq!(row.status, proxxx::hitl::pending::RequestStatus::Expired);
}

/// #341 Test 3 — A second legitimate request for the same `(action, vmid)`
/// within the same daemon session gets a fresh random id and succeeds, rather
/// than colliding with the first request's consumed entry.
#[tokio::test]
async fn second_legitimate_request_for_same_action_vmid_succeeds() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();
    let client = HitlMockGateway::new().with_node_and_guest("pve01", guest(100, "vm-prod-01"));

    let id1 = mint_pending(&pending, "stop", 100, 1);
    let id2 = mint_pending(&pending, "stop", 100, 1);
    assert_ne!(
        id1, id2,
        "two requests for stop:100 must receive distinct random IDs"
    );

    let data1 = signed(tg.hmac_key(), &format!("approve:{id1}"));
    let out1 = handle_callback_update(
        &update(1, callback_query("cb-s1", &data1)),
        &pending,
        &client,
        &tg,
    )
    .await
    .expect("first stop:100");
    assert!(matches!(out1, CallbackOutcome::Executed { vmid: 100, .. }));

    let data2 = signed(tg.hmac_key(), &format!("approve:{id2}"));
    let out2 = handle_callback_update(
        &update(2, callback_query("cb-s2", &data2)),
        &pending,
        &client,
        &tg,
    )
    .await
    .expect("second legitimate stop:100");
    assert!(matches!(out2, CallbackOutcome::Executed { vmid: 100, .. }));
    assert_eq!(client.calls_for("shutdown_guest"), vec![100, 100]);
}

/// #341 Test 4 — Quorum is counted from the persisted `SQLite` store (not from
/// the callback button), so vote 1 persists on disk and vote 2 after a daemon
/// restart completes the quorum and executes.
#[tokio::test]
async fn quorum_counted_from_store_across_daemon_restarts() {
    const SECOND_APPROVER: i64 = 5150;
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server).with_allowed_approvers(vec![TEST_APPROVER, SECOND_APPROVER]);
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("hitl_pending.db");
    let client = HitlMockGateway::new().with_node_and_guest("pve01", guest(100, "vm-quorum"));

    let id = {
        let store1 = PendingApprovals::open_at(&db_path).expect("open store1");
        let id = mint_pending(&store1, "stop", 100, 2);
        let kb = tg.build_approval_keyboard(&id);
        let data = &kb.inline_keyboard[0][0].callback_data;
        assert!(
            !data.contains(":r2:"),
            "button must not carry :r2: segment: {data}"
        );
        let cb1 = build_tui_callback_for_test("cb-q1", TEST_APPROVER, "tester", data, 12345);
        let out1 = handle_callback_update(&update(1, cb1), &store1, &client, &tg)
            .await
            .expect("vote 1");
        assert!(matches!(
            out1,
            CallbackOutcome::AwaitingApprovals { have: 1, need: 2 }
        ));
        id
    };
    assert!(client.calls_for("shutdown_guest").is_empty());

    let store2 = PendingApprovals::open_at(&db_path).expect("reopen store2");
    let data = tg.build_approval_keyboard(&id).inline_keyboard[0][0]
        .callback_data
        .clone();
    let cb2 = build_tui_callback_for_test("cb-q2", SECOND_APPROVER, "second", &data, 12345);
    let out2 = handle_callback_update(&update(2, cb2), &store2, &client, &tg)
        .await
        .expect("vote 2 after restart");
    assert!(matches!(out2, CallbackOutcome::Executed { vmid: 100, .. }));
    assert_eq!(client.calls_for("shutdown_guest"), vec![100]);
}

// ── Issue #340: HITL daemon executors, guest binding & typed decoding ───

struct VariantCase {
    action: &'static str,
    vmid: Option<u32>,
    node: &'static str,
    guest_type: GuestType,
    params: serde_json::Value,
    expected_upid: &'static str,
    expected_details: &'static [&'static str],
}

#[allow(clippy::too_many_lines)]
fn build_all_approved_op_variant_cases() -> Vec<VariantCase> {
    vec![
        // 1. CliStart
        VariantCase {
            action: "start",
            vmid: Some(101),
            node: "pve01",
            guest_type: GuestType::Qemu,
            params: serde_json::json!({}),
            expected_upid: "UPID:start:101",
            expected_details: &["start_guest:pve01:101:qemu"],
        },
        // 2a. CliStop (graceful shutdown with custom timeout)
        VariantCase {
            action: "stop",
            vmid: Some(102),
            node: "pve01",
            guest_type: GuestType::Qemu,
            params: serde_json::json!({"force": false, "timeout": 45}),
            expected_upid: "UPID:shutdown:102",
            expected_details: &["shutdown_guest:pve01:102:qemu:45"],
        },
        // 2b. CliStop (force stop)
        VariantCase {
            action: "stop",
            vmid: Some(103),
            node: "pve01",
            guest_type: GuestType::Qemu,
            params: serde_json::json!({"force": true, "timeout": 45}),
            expected_upid: "UPID:stop:103",
            expected_details: &["stop_guest:pve01:103:qemu:true"],
        },
        // 3. CliRestart
        VariantCase {
            action: "restart",
            vmid: Some(104),
            node: "pve01",
            guest_type: GuestType::Qemu,
            params: serde_json::json!({}),
            expected_upid: "UPID:restart:104",
            expected_details: &["restart_guest:pve01:104:qemu"],
        },
        // 4. CliSuspend
        VariantCase {
            action: "suspend",
            vmid: Some(105),
            node: "pve01",
            guest_type: GuestType::Qemu,
            params: serde_json::json!({}),
            expected_upid: "UPID:suspend:105",
            expected_details: &["suspend_guest:pve01:105:qemu"],
        },
        // 5. CliResume
        VariantCase {
            action: "resume",
            vmid: Some(106),
            node: "pve01",
            guest_type: GuestType::Qemu,
            params: serde_json::json!({}),
            expected_upid: "UPID:resume:106",
            expected_details: &["resume_guest:pve01:106:qemu"],
        },
        // 6a. McpStopGuest (graceful)
        VariantCase {
            action: "stop_guest",
            vmid: Some(201),
            node: "pve01",
            guest_type: GuestType::Qemu,
            params: serde_json::json!({"guest_id": 201, "force": false}),
            expected_upid: "UPID:shutdown:201",
            expected_details: &["shutdown_guest:pve01:201:qemu:60"],
        },
        // 6b. McpStopGuest (force)
        VariantCase {
            action: "stop_guest",
            vmid: Some(202),
            node: "pve01",
            guest_type: GuestType::Qemu,
            params: serde_json::json!({"guest_id": 202, "force": true}),
            expected_upid: "UPID:stop:202",
            expected_details: &["stop_guest:pve01:202:qemu:true"],
        },
        // 7. McpRestartGuest
        VariantCase {
            action: "restart_guest",
            vmid: Some(203),
            node: "pve01",
            guest_type: GuestType::Qemu,
            params: serde_json::json!({"guest_id": 203}),
            expected_upid: "UPID:restart:203",
            expected_details: &["restart_guest:pve01:203:qemu"],
        },
        // 8. McpDeleteGuest
        VariantCase {
            action: "delete_guest",
            vmid: Some(204),
            node: "pve01",
            guest_type: GuestType::Qemu,
            params: serde_json::json!({"guest_id": 204}),
            expected_upid: "UPID:delete:204",
            expected_details: &["delete_guest:pve01:204:qemu"],
        },
        // 9. McpCreateSnapshot
        VariantCase {
            action: "create_snapshot",
            vmid: Some(205),
            node: "pve01",
            guest_type: GuestType::Qemu,
            params: serde_json::json!({"guest_id": 205, "name": "snap_pre_upgrade"}),
            expected_upid: "UPID:snapshot:205",
            expected_details: &["create_snapshot:pve01:205:qemu:snap_pre_upgrade"],
        },
        // 10. McpDeleteSnapshot
        VariantCase {
            action: "delete_snapshot",
            vmid: Some(206),
            node: "pve01",
            guest_type: GuestType::Qemu,
            params: serde_json::json!({"guest_id": 206, "name": "snap_old"}),
            expected_upid: "UPID:delsnapshot:206",
            expected_details: &["delete_snapshot:pve01:206:qemu:snap_old"],
        },
        // 11. McpSuspendGuest
        VariantCase {
            action: "suspend_guest",
            vmid: Some(207),
            node: "pve01",
            guest_type: GuestType::Qemu,
            params: serde_json::json!({"guest_id": 207}),
            expected_upid: "UPID:suspend:207",
            expected_details: &["suspend_guest:pve01:207:qemu"],
        },
        // 12. McpCloneGuest
        VariantCase {
            action: "clone_guest",
            vmid: Some(208),
            node: "pve01",
            guest_type: GuestType::Qemu,
            params: serde_json::json!({
                "guest_id": 208,
                "newid": 308,
                "name": "vm-clone-308",
                "full": true
            }),
            expected_upid: "UPID:clone:208:308",
            expected_details: &["clone_guest:pve01:208:qemu:308:vm-clone-308:true"],
        },
        // 13. McpMigrateGuest
        VariantCase {
            action: "migrate_guest",
            vmid: Some(209),
            node: "pve01",
            guest_type: GuestType::Qemu,
            params: serde_json::json!({
                "guest_id": 209,
                "target_node": "pve02",
                "online": true
            }),
            expected_upid: "UPID:migrate:209",
            expected_details: &["migrate_guest:pve01:209:qemu:pve02:true"],
        },
        // 14a. McpCreateGuest (QEMU)
        VariantCase {
            action: "create_guest",
            vmid: Some(401),
            node: "pve01",
            guest_type: GuestType::Qemu,
            params: serde_json::json!({
                "node": "pve01",
                "type": "qemu",
                "vmid": 401,
                "name": "new-vm-401",
                "memory": 2048,
                "cores": 2,
                "storage": "local-lvm",
                "disk_size": 40
            }),
            expected_upid: "UPID:create_qemu:401",
            expected_details: &[
                "create_qemu:pve01:401:vmid=401;memory=2048;cores=2;ostype=l26;scsihw=virtio-scsi-pci;net0=virtio,bridge=vmbr0;name=new-vm-401;scsi0=local-lvm:40",
            ],
        },
        // 14b. McpCreateGuest (LXC)
        VariantCase {
            action: "create_guest",
            vmid: Some(402),
            node: "pve01",
            guest_type: GuestType::Lxc,
            params: serde_json::json!({
                "node": "pve01",
                "type": "lxc",
                "vmid": 402,
                "name": "new-ct-402",
                "template": "local:vztmpl/debian-12.tar.zst",
                "memory": 1024,
                "cores": 2
            }),
            expected_upid: "UPID:create_lxc:402",
            expected_details: &[
                "create_lxc:pve01:402:vmid=402;ostemplate=local:vztmpl/debian-12.tar.zst;memory=1024;cores=2;rootfs=local-lvm:8;net0=name=eth0,bridge=vmbr0,ip=dhcp;hostname=new-ct-402",
            ],
        },
        // 15. McpCloneWithCloudinit
        VariantCase {
            action: "clone_with_cloudinit",
            vmid: Some(210),
            node: "pve01",
            guest_type: GuestType::Qemu,
            params: serde_json::json!({
                "guest_id": 210,
                "newid": 310,
                "name": "vm-ci-310",
                "full": true,
                "ciuser": "ubuntu",
                "ipconfig0": "ip=dhcp"
            }),
            expected_upid: "UPID:clone:210:310",
            expected_details: &[
                "clone_guest:pve01:210:qemu:310:vm-ci-310:true",
                "update_guest_config:pve01:310:qemu:ciuser=ubuntu,ipconfig0=ip=dhcp",
                "regenerate_cloudinit:pve01:310",
            ],
        },
    ]
}

/// #340 Test 1 — Every `ApprovedOp` variant (all 5 CLI batch ops + all 10
/// destructive MCP tools) decodes from `(action, params_json)` in `PendingStore`,
/// executes on an approved callback, invokes the mock gateway with the exact
/// stored parameters, and records `status = 'executed'` and `upid` in the store.
#[tokio::test]
async fn every_approved_op_variant_executes_with_stored_parameters() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();

    for (idx, case) in build_all_approved_op_variant_cases()
        .into_iter()
        .enumerate()
    {
        let mut gw = HitlMockGateway::new();
        if case.action != "create_guest" {
            let vmid = case.vmid.expect("existing guest vmid");
            let mut g = guest(vmid, &format!("vm-{vmid}"));
            g.guest_type = case.guest_type;
            gw = gw.with_node_and_guest(case.node, g);
        }

        let req = pending
            .insert(
                &proxxx::hitl::pending::NewPendingRequest::new(case.action, case.vmid, 1)
                    .with_node(case.node)
                    .with_guest_type(case.guest_type)
                    .with_params(case.params.clone()),
            )
            .expect("insert pending request");

        let data = signed(tg.hmac_key(), &format!("approve:{}", req.id));
        let cb = callback_query(&format!("cb-var-{idx}"), &data);
        let out = handle_callback_update(&update(idx as i64 + 1, cb), &pending, &gw, &tg)
            .await
            .expect("handle_callback_update");

        let CallbackOutcome::Executed {
            ref action,
            vmid,
            ref upid,
        } = out
        else {
            panic!(
                "variant {} ({}) must execute, got {out:?}",
                idx, case.action
            );
        };
        assert_eq!(action, case.action);
        assert_eq!(vmid, case.vmid.unwrap_or(0));
        assert_eq!(upid, case.expected_upid);

        let expected_vec: Vec<String> = case
            .expected_details
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        assert_eq!(
            gw.detailed_calls(),
            expected_vec,
            "mismatch in mock gateway calls for variant '{}'",
            case.action
        );

        let stored = pending.get(&req.id).expect("get").expect("stored row");
        assert_eq!(
            stored.status,
            proxxx::hitl::pending::RequestStatus::Executed
        );
        assert_eq!(stored.upid.as_deref(), Some(case.expected_upid));
    }
}

/// #340 Test 2 — MCP end-to-end: `delete_guest` through
/// `mcp::dispatch::handle_tool_call_with_store` with a matching policy creates a
/// `PendingStore` row (without calling `delete_guest` yet), and a subsequent
/// signed approve callback executes `delete_guest` once on the mock gateway.
#[tokio::test]
async fn mcp_delete_guest_policy_to_store_to_daemon_executes_once() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();
    let gw = HitlMockGateway::new().with_node_and_guest("pve01", guest(500, "vm-mcp-del"));

    let cfg: proxxx::config::ProfileConfig = toml::from_str(
        r#"
        url = "https://127.0.0.1:8006/"
        user = "root@pam"
        token_id = "test"
        token_secret = "00000000-0000-0000-0000-000000000000"

        [[policies]]
        action = "delete_guest"
        target = "*"
        require = 1
        channel = "telegram"
        "#,
    )
    .expect("parse ProfileConfig");

    let args = serde_json::json!({ "guest_id": 500 });
    let resp = proxxx::mcp::dispatch::handle_tool_call_with_store(
        &gw,
        &cfg,
        "delete_guest",
        &args,
        Some(&pending),
    )
    .await
    .expect("handle_tool_call_with_store");

    let text = resp["content"][0]["text"]
        .as_str()
        .expect("MCP response text");
    assert!(
        text.contains("Action intercepted by HITL policy"),
        "expected HITL interception message, got: {text}"
    );
    let txn_id = text
        .rsplit("Transaction: ")
        .next()
        .expect("extract txn_id")
        .trim()
        .to_string();

    assert!(
        gw.calls_for("delete_guest").is_empty(),
        "delete_guest must NOT be called before human approval"
    );

    let stored_before = pending.get(&txn_id).expect("get").expect("row exists");
    assert_eq!(stored_before.action, "delete_guest");
    assert_eq!(stored_before.vmid, Some(500));
    assert_eq!(stored_before.node.as_deref(), Some("pve01"));
    assert_eq!(stored_before.guest_type, Some(GuestType::Qemu));
    assert_eq!(
        stored_before.status,
        proxxx::hitl::pending::RequestStatus::Pending
    );

    let data = signed(tg.hmac_key(), &format!("approve:{txn_id}"));
    let out = handle_callback_update(
        &update(1, callback_query("cb-mcp-del", &data)),
        &pending,
        &gw,
        &tg,
    )
    .await
    .expect("daemon handle_callback_update");

    assert!(
        matches!(
            out,
            CallbackOutcome::Executed {
                ref action,
                vmid: 500,
                ref upid
            } if action == "delete_guest" && upid == "UPID:delete:500"
        ),
        "expected Executed for delete_guest 500, got {out:?}"
    );
    assert_eq!(
        gw.detailed_calls(),
        vec!["delete_guest:pve01:500:qemu".to_string()]
    );

    let stored_after = pending.get(&txn_id).expect("get").expect("row exists");
    assert_eq!(
        stored_after.status,
        proxxx::hitl::pending::RequestStatus::Executed
    );
    assert_eq!(stored_after.upid.as_deref(), Some("UPID:delete:500"));
}

/// #340 Test 3 — Guest binding (VMID reuse protection):
/// - If an existing guest moved to another node or changed type (`qemu` -> `lxc`)
///   or disappeared between request time and approval time, the daemon marks the
///   row `failed` with `"guest changed since the request (expected <node>/<type>, found ...)"`
///   and makes zero mutation calls.
/// - If `create_guest` or `clone_guest` specifies a target VMID that is now taken
///   at execution time, the daemon marks the row `failed` and makes zero calls.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn guest_binding_refuses_moved_retyped_or_taken_vmid_without_executing() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();

    // Case A: Guest 100 moved from pve01 to pve02 since request time.
    let gw_moved = HitlMockGateway::new().with_node_and_guest("pve02", guest(100, "vm-moved"));
    let req_moved = pending
        .insert(
            &proxxx::hitl::pending::NewPendingRequest::new("delete_guest", Some(100), 1)
                .with_node("pve01")
                .with_guest_type(GuestType::Qemu)
                .with_params(serde_json::json!({"guest_id": 100})),
        )
        .expect("insert moved");
    let data_moved = signed(tg.hmac_key(), &format!("approve:{}", req_moved.id));
    let out_moved = handle_callback_update(
        &update(1, callback_query("cb-bind-moved", &data_moved)),
        &pending,
        &gw_moved,
        &tg,
    )
    .await
    .expect("handle moved");
    let CallbackOutcome::ExecuteFailed {
        error: err_moved, ..
    } = out_moved
    else {
        panic!("moved guest must fail binding check, got {out_moved:?}");
    };
    assert!(
        err_moved
            .contains("guest changed since the request (expected pve01/qemu, found pve02/qemu)"),
        "unexpected error for moved guest: {err_moved}"
    );
    assert!(gw_moved.all_calls().is_empty());
    assert_eq!(
        pending.get(&req_moved.id).unwrap().unwrap().status,
        proxxx::hitl::pending::RequestStatus::Failed
    );

    // Case B: VMID 100 was deleted and recreated as LXC on pve01 since request time.
    let mut lxc_guest = guest(100, "ct-reused");
    lxc_guest.guest_type = GuestType::Lxc;
    let gw_retyped = HitlMockGateway::new().with_node_and_guest("pve01", lxc_guest);
    let req_retyped = pending
        .insert(
            &proxxx::hitl::pending::NewPendingRequest::new("stop", Some(100), 1)
                .with_node("pve01")
                .with_guest_type(GuestType::Qemu)
                .with_params(serde_json::json!({"force": true, "timeout": 30})),
        )
        .expect("insert retyped");
    let data_retyped = signed(tg.hmac_key(), &format!("approve:{}", req_retyped.id));
    let out_retyped = handle_callback_update(
        &update(2, callback_query("cb-bind-retyped", &data_retyped)),
        &pending,
        &gw_retyped,
        &tg,
    )
    .await
    .expect("handle retyped");
    let CallbackOutcome::ExecuteFailed {
        error: err_retyped, ..
    } = out_retyped
    else {
        panic!("retyped guest must fail binding check, got {out_retyped:?}");
    };
    assert!(
        err_retyped
            .contains("guest changed since the request (expected pve01/qemu, found pve01/lxc)"),
        "unexpected error for retyped guest: {err_retyped}"
    );
    assert!(gw_retyped.all_calls().is_empty());

    // Case C: `create_guest` target VMID 600 is now taken on the cluster.
    let gw_taken = HitlMockGateway::new().with_node_and_guest("pve01", guest(600, "already-there"));
    let req_create = pending
        .insert(
            &proxxx::hitl::pending::NewPendingRequest::new("create_guest", Some(600), 1)
                .with_node("pve01")
                .with_guest_type(GuestType::Qemu)
                .with_params(serde_json::json!({
                    "node": "pve01",
                    "type": "qemu",
                    "vmid": 600,
                    "name": "colliding-vm"
                })),
        )
        .expect("insert create");
    let data_create = signed(tg.hmac_key(), &format!("approve:{}", req_create.id));
    let out_create = handle_callback_update(
        &update(3, callback_query("cb-bind-create", &data_create)),
        &pending,
        &gw_taken,
        &tg,
    )
    .await
    .expect("handle create collision");
    let CallbackOutcome::ExecuteFailed {
        error: err_create, ..
    } = out_create
    else {
        panic!("create_guest with taken VMID must fail, got {out_create:?}");
    };
    assert!(
        err_create.contains(
            "guest changed since the request (expected target VMID 600 to be free, found pve01/qemu)"
        ),
        "unexpected error for taken create_guest VMID: {err_create}"
    );
    assert!(gw_taken.all_calls().is_empty());
    assert_eq!(
        pending.get(&req_create.id).unwrap().unwrap().status,
        proxxx::hitl::pending::RequestStatus::Failed
    );
}

/// #340 Test 4 — Any stored row whose `(action, params_json)` cannot be decoded
/// into `ApprovedOp` (unknown field rejected by `deny_unknown_fields`, malformed
/// JSON, missing required field, invalid `Shape::Name`, or unknown action)
/// transitions to `status = 'failed'` with `"cannot decode approved operation: ..."`
/// and invokes zero methods on the mock gateway.
#[tokio::test]
async fn undecodable_params_json_marks_failed_and_makes_no_gateway_call() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();
    let gw = HitlMockGateway::new().with_node_and_guest("pve01", guest(100, "vm-100"));

    let bad_rows: &[(&str, Option<u32>, serde_json::Value)] = &[
        // Unknown field rejected by #[serde(deny_unknown_fields)]
        (
            "delete_guest",
            Some(100),
            serde_json::json!({"guest_id": 100, "unexpected_field": true}),
        ),
        // Unknown field on CLI stop
        (
            "stop",
            Some(100),
            serde_json::json!({"force": true, "bogus": 1}),
        ),
        // Missing required `guest_id` on MCP tool
        ("restart_guest", Some(100), serde_json::json!({})),
        // Path traversal in snapshot name rejected by Shape::Name
        (
            "create_snapshot",
            Some(100),
            serde_json::json!({"guest_id": 100, "name": "../etc/passwd"}),
        ),
        // Disagreement between row.vmid and params.guest_id
        (
            "delete_guest",
            Some(100),
            serde_json::json!({"guest_id": 999}),
        ),
        // Unknown action name
        ("drop_database", Some(100), serde_json::json!({})),
    ];

    for (idx, (action, vmid, params)) in bad_rows.iter().enumerate() {
        let req = pending
            .insert(
                &proxxx::hitl::pending::NewPendingRequest::new(*action, *vmid, 1)
                    .with_node("pve01")
                    .with_guest_type(GuestType::Qemu)
                    .with_params(params.clone()),
            )
            .expect("insert bad row");
        let data = signed(tg.hmac_key(), &format!("approve:{}", req.id));
        let out = handle_callback_update(
            &update(
                idx as i64 + 1,
                callback_query(&format!("cb-bad-{idx}"), &data),
            ),
            &pending,
            &gw,
            &tg,
        )
        .await
        .expect("handle undecodable row");

        let CallbackOutcome::ExecuteFailed { ref error, .. } = out else {
            panic!("bad row {idx} ({action}) must return ExecuteFailed, got {out:?}");
        };
        assert!(
            error.starts_with("cannot decode approved operation:"),
            "error must start with 'cannot decode approved operation:', got: {error}"
        );
        let row = pending.get(&req.id).expect("get").expect("row");
        assert_eq!(row.status, proxxx::hitl::pending::RequestStatus::Failed);
        assert!(row
            .error
            .as_deref()
            .unwrap_or("")
            .starts_with("cannot decode approved operation:"));
    }

    assert!(
        gw.all_calls().is_empty(),
        "undecodable rows must never invoke the PVE gateway, got {:?}",
        gw.all_calls()
    );
}

/// #340 Rev. 14 — An existing-guest request row with `node = NULL` or
/// `guest_type = NULL` is refused before any gateway call, marked `failed` with
/// `"request has no recorded guest binding (node/type); request again"`, and
/// never executes against the cluster.
#[tokio::test]
async fn unbound_row_missing_node_or_guest_type_marks_failed_and_makes_no_gateway_call() {
    let server = setup_telegram_mock().await;
    let tg = fake_gateway(&server);
    let (_dir, pending) = temp_pending_store();
    let gw = HitlMockGateway::new().with_node_and_guest("pve01", guest(100, "vm-100"));

    // Case 1: `node = NULL`, `guest_type = Some(Qemu)` for `delete_guest`.
    let req_no_node = pending
        .insert(
            &proxxx::hitl::pending::NewPendingRequest::new("delete_guest", Some(100), 1)
                .with_guest_type(GuestType::Qemu)
                .with_params(serde_json::json!({"guest_id": 100})),
        )
        .expect("insert row without node");
    let data_no_node = signed(tg.hmac_key(), &format!("approve:{}", req_no_node.id));
    let out_no_node = handle_callback_update(
        &update(1, callback_query("cb-no-node", &data_no_node)),
        &pending,
        &gw,
        &tg,
    )
    .await
    .expect("handle row without node");
    let CallbackOutcome::ExecuteFailed {
        error: ref err_no_node,
        ..
    } = out_no_node
    else {
        panic!("row with node=NULL must fail, got {out_no_node:?}");
    };
    assert_eq!(
        err_no_node,
        "request has no recorded guest binding (node/type); request again"
    );
    let stored_no_node = pending.get(&req_no_node.id).unwrap().unwrap();
    assert_eq!(
        stored_no_node.status,
        proxxx::hitl::pending::RequestStatus::Failed
    );
    assert_eq!(
        stored_no_node.error.as_deref(),
        Some("request has no recorded guest binding (node/type); request again")
    );

    // Case 2: `node = Some("pve01")`, `guest_type = NULL` for `delete_guest`.
    let req_no_type = pending
        .insert(
            &proxxx::hitl::pending::NewPendingRequest::new("delete_guest", Some(100), 1)
                .with_node("pve01")
                .with_params(serde_json::json!({"guest_id": 100})),
        )
        .expect("insert row without guest_type");
    let data_no_type = signed(tg.hmac_key(), &format!("approve:{}", req_no_type.id));
    let out_no_type = handle_callback_update(
        &update(2, callback_query("cb-no-type", &data_no_type)),
        &pending,
        &gw,
        &tg,
    )
    .await
    .expect("handle row without guest_type");
    let CallbackOutcome::ExecuteFailed {
        error: ref err_no_type,
        ..
    } = out_no_type
    else {
        panic!("row with guest_type=NULL must fail, got {out_no_type:?}");
    };
    assert_eq!(
        err_no_type,
        "request has no recorded guest binding (node/type); request again"
    );
    let stored_no_type = pending.get(&req_no_type.id).unwrap().unwrap();
    assert_eq!(
        stored_no_type.status,
        proxxx::hitl::pending::RequestStatus::Failed
    );
    assert_eq!(
        stored_no_type.error.as_deref(),
        Some("request has no recorded guest binding (node/type); request again")
    );

    assert!(
        gw.all_calls().is_empty(),
        "unbound rows must not invoke any mutation on the gateway"
    );
    assert_eq!(
        gw.lookup_call_count(),
        0,
        "unbound rows must be rejected before any gateway lookup call"
    );
}

/// #340 Rev. 14 — When the MCP sender cannot resolve an existing guest at
/// request time (either because `find_guest` returns a lookup error or because
/// the guest does not exist), `handle_tool_call_with_store` returns an `Err` to
/// the caller (not swallowed) and inserts NO row into `PendingStore`.
#[tokio::test]
async fn mcp_delete_guest_with_failing_lookup_inserts_no_row_and_returns_error() {
    let (_dir, pending) = temp_pending_store();
    let cfg: proxxx::config::ProfileConfig = toml::from_str(
        r#"
        url = "https://127.0.0.1:8006/"
        user = "root@pam"
        token_id = "test"
        token_secret = "00000000-0000-0000-0000-000000000000"

        [[policies]]
        action = "delete_guest"
        target = "*"
        require = 1
        channel = "telegram"
        "#,
    )
    .expect("parse ProfileConfig");

    // Case 1: `find_guest` fails with a transient lookup error. Even if caller
    // passes extra `node`/`type` fields in `args`, the sender must NOT fall back
    // to them or swallow the lookup error.
    let gw_err = HitlMockGateway::new()
        .with_node_and_guest("pve01", guest(500, "vm-500"))
        .fail_lookups("PVE cluster unreachable");
    let args = serde_json::json!({ "guest_id": 500, "node": "pve01", "type": "qemu" });
    let err = proxxx::mcp::dispatch::handle_tool_call_with_store(
        &gw_err,
        &cfg,
        "delete_guest",
        &args,
        Some(&pending),
    )
    .await
    .expect_err("failing guest lookup must return Err, not swallow it");
    assert!(
        err.to_string().contains("PVE cluster unreachable"),
        "expected lookup error to be propagated, got: {err:#}"
    );
    assert_eq!(
        pending.total_count(),
        0,
        "no row may be inserted when guest lookup fails"
    );
    assert!(gw_err.all_calls().is_empty());

    // Case 2: `find_guest` succeeds but guest 500 does not exist on the cluster.
    let gw_missing = HitlMockGateway::new();
    let err_missing = proxxx::mcp::dispatch::handle_tool_call_with_store(
        &gw_missing,
        &cfg,
        "delete_guest",
        &serde_json::json!({ "guest_id": 500 }),
        Some(&pending),
    )
    .await
    .expect_err("missing guest must return Err at request time");
    assert!(
        err_missing.to_string().contains("Guest 500 not found"),
        "expected missing guest error, got: {err_missing:#}"
    );
    assert_eq!(
        pending.total_count(),
        0,
        "no row may be inserted when guest is missing"
    );
}
