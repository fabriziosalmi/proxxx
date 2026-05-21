//! HITL daemon callback handler — extracted from `cli::hitl_serve` so
//! the per-callback logic is unit-testable without a 30-second
//! Telegram poll loop.
//!
//! Phase 5.13 — refactor that closes the 3 deferred HITL invariants
//! in [pre-commit/03-security-invariants.md]:
//! 1. Replay protection — every accepted callback first goes through
//!    `PendingApprovals::consume`; redelivered callbacks return
//!    `Replay` and the daemon answers the user with a "stale approval"
//!    notice instead of executing again.
//! 2. Privilege escalation refusal — when the executing PVE token is
//!    unprivileged, the gateway call returns `Err(403)` and we surface
//!    `ExecuteFailed`. The daemon does NOT silently succeed.
//! 3. Secure-mode enforcement — the gate that ATTACHES the HITL
//!    requirement to a destructive op lives in the senders (TUI, CLI
//!    batch, MCP). This module exists for the receiver side; the
//!    secure-mode invariant is covered by the sender-side test in
//!    `tests/hitl_e2e.rs`.

use crate::api::types::GuestType;
use crate::api::ProxmoxGateway;
use crate::hitl::pending::{PendingApprovals, ReplayError};
use crate::hitl::telegram::{TelegramGateway, Update};
use anyhow::Result;
use tracing::{error, info, warn};

/// Outcome of handling one callback. Returned so tests can assert the
/// daemon took the right path without inspecting log output.
#[derive(Debug, Clone)]
pub enum CallbackOutcome {
    /// User approved + execution succeeded. Holds the upid PVE returned.
    Executed {
        action: String,
        vmid: u32,
        upid: String,
    },
    /// User approved but execution failed (PVE 403, missing node, …).
    /// The daemon answered the callback with the failure message.
    ExecuteFailed {
        action: String,
        vmid: u32,
        error: String,
    },
    /// User pressed Deny.
    Denied { action: String, vmid: u32 },
    /// Callback for a `txn_id` we already consumed — replay rejected.
    /// The daemon did NOT execute.
    Replay { txn_id: String },
    /// Callback parsed but referred to a vmid we couldn't locate on
    /// any node (operator deleted the guest in the meantime?).
    NodeNotFound { vmid: u32 },
    /// Update had no `callback_query` (we ignore non-callback updates).
    NotACallback,
    /// Callback data didn't match the expected `decision:action:vmid`
    /// format. Ignored.
    InvalidFormat { data: String },
    /// Unknown action token (not start/stop/restart). Ignored.
    UnknownAction { action: String, vmid: u32 },
}

/// Process exactly one Telegram update.
///
/// This is the function the wiremock E2E tests drive. Behaviour is a
/// straight extraction of the original loop body in `cli::hitl_serve`
/// with one substantive addition: replay protection via the injected
/// `PendingApprovals`.
///
/// The `&dyn ProxmoxGateway` indirection (instead of a concrete
/// `PxClient`) is what makes the function testable — tests pass a mock
/// gateway that returns canned `Ok(upid)` / `Err(403)` responses.
///
/// # Errors
/// Never returns `Err` — all failure modes surface through
/// `CallbackOutcome`. The `Result` return is reserved for future
/// expansion (e.g. propagating shutdown signals).
pub async fn handle_callback_update(
    update: &Update,
    pending: &PendingApprovals,
    client: &(dyn ProxmoxGateway + Send + Sync),
    tg_gateway: &TelegramGateway,
) -> Result<CallbackOutcome> {
    let Some(cb) = update.callback_query.as_ref() else {
        return Ok(CallbackOutcome::NotACallback);
    };
    let Some(data) = cb.data.as_ref() else {
        return Ok(CallbackOutcome::NotACallback);
    };
    info!("Received HITL callback: {}", data);

    // Phase 18 — every callback MUST carry a valid HMAC tag. The
    // v0.1.21 backward-compat shim that accepted unsigned legacy
    // callbacks is gone, per the contract documented in v0.1.21's
    // CHANGELOG and tested by `legacy_unsigned_callback_still_accepted_in_v0_1_21`
    // (now inverted to `legacy_unsigned_callback_is_refused_in_v0_1_22`).
    //
    // Canonical shape after v0.1.22:
    //     decision:action:vmid[-timestamp]:hmac_hex
    // where hmac_hex is exactly 16 hex chars (8 raw bytes).
    //
    // The tag is split off at the LAST `:` so the txn_id segment can
    // freely contain hyphens, digits, or any non-colon byte. A
    // callback whose tail isn't a 16-hex-char chunk is refused
    // outright — no quiet-acceptance branch, no telemetry alert
    // window. Operators who haven't restarted their HITL daemon
    // since v0.1.21 will see refusals; the message points them to
    // upgrade.
    let payload_for_parse = {
        let parts: Vec<&str> = data.rsplitn(2, ':').collect();
        if parts.len() != 2
            || parts[0].len() != 16
            || !parts[0].chars().all(|c| c.is_ascii_hexdigit())
        {
            warn!(
                "HITL callback without HMAC tag — refused (v0.1.22+ requires \
                 signed callbacks; restart your HITL daemon to mint a fresh \
                 keyboard): {data}"
            );
            let _ = tg_gateway
                .answer_callback(
                    &cb.id,
                    "❌ Unsigned callback refused — daemon upgrade needed",
                )
                .await;
            return Ok(CallbackOutcome::InvalidFormat { data: data.clone() });
        }
        let tail_tag = parts[0];
        let head_payload = parts[1];
        if !crate::hitl::hmac_key::verify(tg_gateway.hmac_key(), head_payload, tail_tag) {
            warn!("HITL callback failed HMAC verify: {data}");
            let _ = tg_gateway
                .answer_callback(&cb.id, "❌ Signature verification failed")
                .await;
            return Ok(CallbackOutcome::InvalidFormat { data: data.clone() });
        }
        head_payload.to_string()
    };

    let parts: Vec<&str> = payload_for_parse.split(':').collect();
    if parts.len() < 3 {
        let _ = tg_gateway
            .answer_callback(&cb.id, "❌ Invalid transaction ID format")
            .await;
        return Ok(CallbackOutcome::InvalidFormat { data: data.clone() });
    }
    let decision = parts[0];
    let action = parts[1];
    let Ok(vmid) = parts[2].parse::<u32>() else {
        let _ = tg_gateway.answer_callback(&cb.id, "❌ Invalid vmid").await;
        return Ok(CallbackOutcome::InvalidFormat { data: data.clone() });
    };

    // Lifecycle UX (Phase 5.13 polish): the callback carries the
    // original message_id, so the daemon can edit the inline-keyboard
    // message in-place to show outcome state instead of leaving a
    // stale prompt forever. Available for every code path below.
    let msg_id = cb.message.as_ref().map(|m| m.message_id);
    let edit_status = |status: &str, who: &str| {
        // Format the lifecycle footer the same way every branch.
        let body = format!("🔔 HITL request: {action} VMID {vmid}\n\n{status} (by @{who})");
        async move {
            if let Some(id) = msg_id {
                let _ = tg_gateway.edit_message_text(id, &body).await;
            }
        }
    };

    if decision != "approve" {
        let _ = tg_gateway.answer_callback(&cb.id, "🚫 Denied").await;
        edit_status(
            "🚫 Denied",
            cb.from.username.as_deref().unwrap_or(&cb.from.first_name),
        )
        .await;
        return Ok(CallbackOutcome::Denied {
            action: action.to_string(),
            vmid,
        });
    }

    // Replay gate. The full callback data string IS the txn_id from the
    // dedup engine's perspective — two identical callbacks (same data)
    // are by definition the same transaction. Distinct legitimate ops
    // produce distinct txn_id suffixes (timestamp / nonce) thanks to
    // the senders in `tui::mod` and `cli::mod::hitl_handler`.
    if pending.consume(data) == Err(ReplayError::AlreadyConsumed) {
        warn!("HITL replay rejected: {data}");
        let _ = tg_gateway
            .answer_callback(&cb.id, "⚠️ Stale approval — already executed")
            .await;
        // Don't edit the message on replay — the original message
        // already shows the first outcome; overwriting would erase
        // valid history.
        return Ok(CallbackOutcome::Replay {
            txn_id: data.clone(),
        });
    }

    // Approved + first time. We DON'T eagerly emit "⏳ Executing…"
    // anymore: PVE's start/stop/restart return in <300ms, so an
    // immediate edit lands at Telegram ~200ms before the final
    // outcome edit and gets collapsed by the mobile client (no flicker
    // = invisible). The deferred edit below only fires if the op
    // takes >1s, which is the regime where the operator NEEDS the
    // visual feedback ("did the daemon pick up the click?").

    // Find which node + guest_type this vmid lives on.
    let mut target_node: Option<String> = None;
    let mut guest_type: Option<GuestType> = None;
    if let Ok(nodes) = client.get_nodes().await {
        for n in nodes {
            if let Ok(guests) = client.get_guests(&n.node).await {
                if let Some(g) = guests.iter().find(|g| g.vmid == vmid) {
                    target_node = Some(n.node.clone());
                    guest_type = Some(g.guest_type);
                    break;
                }
            }
        }
    }

    let (Some(node), Some(gt)) = (target_node, guest_type) else {
        let _ = tg_gateway
            .answer_callback(&cb.id, "❌ Node not found")
            .await;
        edit_status(
            "❌ Node not found",
            cb.from.username.as_deref().unwrap_or(&cb.from.first_name),
        )
        .await;
        return Ok(CallbackOutcome::NodeNotFound { vmid });
    };

    // Race the API call against a 1-second deferred-emit timer.
    //
    // If the API resolves first (fast op like restart/stop/start —
    // typically <300ms), the timer's `intermediate` future is dropped
    // before its sleep completes, so NO `⏳` edit is sent. The final
    // outcome edit is the only thing the operator sees on Telegram.
    //
    // If the API takes longer than 1s (live migration, big backup
    // dispatch), the timer fires, edits the message to `⏳ Executing…`,
    // and we then continue waiting on the API future. Final outcome
    // edit overwrites `⏳` with `✅ Done — UPID:…` or `❌ Failed: …`.
    //
    // `biased` in the select! makes tokio poll the API future FIRST
    // each round, so if both are ready in the same tick (boundary at
    // exactly ~1s), the API arm wins and no flicker is emitted.
    let user_label = cb
        .from
        .username
        .as_deref()
        .unwrap_or(&cb.from.first_name)
        .to_string();
    type ApiFut<'a> =
        std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<String>> + Send + 'a>>;
    let api_fut: ApiFut = match action {
        "start" => Box::pin(client.start_guest(&node, vmid, gt)),
        "stop" => Box::pin(client.shutdown_guest(&node, vmid, gt, 60)),
        "restart" => Box::pin(client.restart_guest(&node, vmid, gt)),
        other => {
            warn!("Unknown action: {}", other);
            let _ = tg_gateway
                .answer_callback(&cb.id, &format!("❌ Unknown action: {other}"))
                .await;
            edit_status(&format!("❌ Unknown action: {other}"), &user_label).await;
            return Ok(CallbackOutcome::UnknownAction {
                action: other.to_string(),
                vmid,
            });
        }
    };
    tokio::pin!(api_fut);

    let intermediate_body =
        format!("🔔 HITL request: {action} VMID {vmid}\n\n⏳ Executing… (by @{user_label})");
    let intermediate = async {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if let Some(id) = msg_id {
            let _ = tg_gateway.edit_message_text(id, &intermediate_body).await;
        }
    };
    tokio::pin!(intermediate);

    let res: anyhow::Result<String> = tokio::select! {
        biased;
        r = &mut api_fut => r,
        () = &mut intermediate => {
            // Slow-op branch: `⏳` has been emitted; now wait for the
            // API call to finish so we can produce the final outcome.
            api_fut.await
        }
    };

    match res {
        Ok(upid) => {
            let _ = tg_gateway.answer_callback(&cb.id, "✅ Executed").await;
            edit_status(
                &format!("✅ Done — {upid}"),
                cb.from.username.as_deref().unwrap_or(&cb.from.first_name),
            )
            .await;
            Ok(CallbackOutcome::Executed {
                action: action.to_string(),
                vmid,
                upid,
            })
        }
        Err(e) => {
            // Critical: a 403 from PVE (e.g. token without VM.PowerMgmt
            // privilege on the target VM) MUST surface here, not be
            // swallowed. The HITL approval does not confer extra
            // privilege — proxxx just sends the same PVE-side request
            // it would have sent without HITL, and PVE's RBAC decides.
            error!("Execution failed: {}", e);
            let err_str = format!("{e}");
            let _ = tg_gateway
                .answer_callback(&cb.id, &format!("❌ Failed: {err_str}"))
                .await;
            // Truncate long error strings in the message body —
            // Telegram's 4096-char limit + readability. Char-boundary
            // safe: PVE error text is frequently non-ASCII, and a naive
            // `&err_str[..200]` byte slice panics when byte 200 splits a
            // multi-byte char.
            let err_short = crate::util::sanitize::truncate_ellipsis(&err_str, 200);
            edit_status(
                &format!("❌ Failed: {err_short}"),
                cb.from.username.as_deref().unwrap_or(&cb.from.first_name),
            )
            .await;
            Ok(CallbackOutcome::ExecuteFailed {
                action: action.to_string(),
                vmid,
                error: err_str,
            })
        }
    }
}
