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
    /// The callback was well-formed and correctly signed, but the
    /// Telegram account that pressed the button is not on the configured
    /// approver allowlist — or no allowlist is configured at all, which
    /// is treated the same way. The daemon did NOT execute.
    UnauthorizedApprover { user_id: i64 },
    /// The callback originated in a chat other than the configured
    /// `chat_id` — a forwarded keyboard. The daemon did NOT execute.
    WrongChat { chat_id: i64 },
    /// The vote was recorded but the policy's `require` quorum is not
    /// yet met. The daemon did NOT execute; it is waiting for more
    /// distinct approvers.
    AwaitingApprovals { have: usize, need: usize },
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
#[allow(clippy::too_many_lines)] // audit #272: wide, flat dispatch — see Cargo.toml
pub async fn handle_callback_update(
    update: &Update,
    pending: &PendingApprovals,
    client: &(dyn ProxmoxGateway + Send + Sync),
    tg_gateway: &TelegramGateway,
) -> Result<CallbackOutcome> {
    let Some(cb) = update.callback_query.as_ref() else {
        return Ok(CallbackOutcome::NotACallback);
    };
    let verified = match verify_callback(tg_gateway, cb) {
        Ok(v) => v,
        Err(rej) => {
            if let Some(ans) = rej.answer_text() {
                let _ = tg_gateway.answer_callback(&cb.id, ans).await;
            }
            return Ok(match rej {
                CallbackRejection::MissingData => CallbackOutcome::NotACallback,
                CallbackRejection::Unsigned { data } => {
                    warn!(
                        "HITL callback without HMAC tag — refused (v0.1.22+ requires \
                         signed callbacks; restart your HITL daemon to mint a fresh \
                         keyboard): {data}"
                    );
                    CallbackOutcome::InvalidFormat { data }
                }
                CallbackRejection::InvalidSignature { data } => {
                    warn!("HITL callback failed HMAC verify: {data}");
                    CallbackOutcome::InvalidFormat { data }
                }
                CallbackRejection::MissingChat => {
                    warn!(
                        "HITL callback without originating chat (configured chat is {}) — refused",
                        tg_gateway.chat_id()
                    );
                    CallbackOutcome::WrongChat { chat_id: 0 }
                }
                CallbackRejection::WrongChat { chat_id } => {
                    warn!(
                        "HITL callback from chat {} but configured chat is {} — refused",
                        chat_id,
                        tg_gateway.chat_id()
                    );
                    CallbackOutcome::WrongChat { chat_id }
                }
                CallbackRejection::NoApproversConfigured { user_id } => {
                    warn!(
                        "HITL callback from user {} refused: no `allowed_approvers` configured. \
                         Add the approving Telegram user ids to the profile's [telegram] section \
                         (numeric ids, e.g. from @userinfobot) — proxxx will not act on an \
                         unauthenticated approval.",
                        user_id
                    );
                    CallbackOutcome::UnauthorizedApprover { user_id }
                }
                CallbackRejection::UnauthorizedApprover { user_id } => {
                    warn!(
                        "HITL callback from unauthorised user {} (@{}) — refused",
                        user_id,
                        cb.from.username.as_deref().unwrap_or("?")
                    );
                    CallbackOutcome::UnauthorizedApprover { user_id }
                }
                CallbackRejection::InvalidPayload { data } => {
                    CallbackOutcome::InvalidFormat { data }
                }
            });
        }
    };

    let data = &verified.raw_data;
    info!("Received HITL callback: {}", data);

    let Some((action, vmid_str)) = verified.txn_id.split_once(':') else {
        let _ = tg_gateway
            .answer_callback(&cb.id, "❌ Invalid transaction ID format")
            .await;
        return Ok(CallbackOutcome::InvalidFormat { data: data.clone() });
    };
    let Ok(vmid) = vmid_str.parse::<u32>() else {
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

    if verified.decision != CallbackDecision::Approve {
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

    // #250 — quorum. `require` rides in the signed payload as a
    // trailing `:r<N>` segment; a keyboard minted before v0.13.4 has no
    // such segment and means "one approver", which is the historic
    // behaviour.
    let require = verified.require;

    // Vote BEFORE the replay gate: every approver presses the same
    // keyboard, so their callback data is identical by construction and
    // the replay gate would reject the second signature as a duplicate.
    // Only the callback that completes the quorum falls through to
    // `consume`, which then makes the whole transaction single-use.
    match pending.record_vote(data, verified.approver_id, require) {
        crate::hitl::pending::VoteProgress::Satisfied => {}
        crate::hitl::pending::VoteProgress::Waiting {
            have,
            need,
            duplicate,
        } => {
            let note = if duplicate {
                format!("You already approved — {have}/{need}")
            } else {
                format!("Recorded — {have}/{need} approvals")
            };
            info!("HITL quorum not yet met for {data}: {have}/{need}");
            let _ = tg_gateway.answer_callback(&cb.id, &note).await;
            edit_status(
                &format!("\u{23f3} Awaiting approval ({have}/{need})"),
                cb.from.username.as_deref().unwrap_or(&cb.from.first_name),
            )
            .await;
            return Ok(CallbackOutcome::AwaitingApprovals { have, need });
        }
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

    // Find which node + guest_type this vmid lives on. Propagate a fetch error
    // (a transient failure must not read as "not found" and silently drop an
    // already-approved action).
    let guest = client.find_guest(vmid).await?;
    let target_node = guest.as_ref().map(|g| g.node.clone());
    let guest_type = guest.map(|g| g.guest_type);

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

/// Decision encoded in a HITL callback payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackDecision {
    Approve,
    Deny,
}

/// Parsed `<decision>:<txn_id>[:r<require>]` payload after HMAC strip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCallback {
    pub decision: CallbackDecision,
    pub txn_id: String,
    pub require: u8,
}

/// Verified and parsed Telegram callback query (#336, #337).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCallback {
    pub decision: CallbackDecision,
    pub txn_id: String,
    pub require: u8,
    pub raw_data: String,
    pub approver_id: i64,
}

/// Reason a Telegram callback query was rejected by [`verify_callback`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackRejection {
    MissingData,
    Unsigned { data: String },
    InvalidSignature { data: String },
    MissingChat,
    WrongChat { chat_id: i64 },
    NoApproversConfigured { user_id: i64 },
    UnauthorizedApprover { user_id: i64 },
    InvalidPayload { data: String },
}

impl CallbackRejection {
    /// Text sent back to Telegram via `answerCallbackQuery` for this rejection.
    #[must_use]
    pub const fn answer_text(&self) -> Option<&'static str> {
        match self {
            Self::MissingData => None,
            Self::Unsigned { .. } => Some("❌ Unsigned callback refused — daemon upgrade needed"),
            Self::InvalidSignature { .. } => Some("❌ Signature verification failed"),
            Self::MissingChat | Self::WrongChat { .. } => Some("❌ Wrong chat — refused"),
            Self::NoApproversConfigured { .. } => {
                Some("❌ No approver allowlist configured — refused. See `allowed_approvers`.")
            }
            Self::UnauthorizedApprover { .. } => Some("❌ Not an authorised approver — refused"),
            Self::InvalidPayload { .. } => Some("❌ Invalid transaction ID format"),
        }
    }
}

/// Parse a verified callback payload (after the trailing `:hmac_hex` tag has
/// been stripped).
///
/// Grammar: `<decision> ":" <txn_id> [":r" <digits>]`
/// - `<decision>` is stripped at the first `:` (`"approve"` or `"deny"`).
/// - An optional trailing `:r<digits>` quorum segment is stripped next; if
///   absent, `require` defaults to `1` (backward-compatible with 3-segment
///   keyboards minted before v0.13.4).
/// - The remaining middle slice is `txn_id` (which may itself contain `:`).
///
/// # Errors
///
/// Returns an error if the payload has no `:`, if the decision is neither
/// `"approve"` nor `"deny"`, if the `:r<digits>` segment overflows `u8`, or if
/// `txn_id` is empty.
pub fn parse_callback_payload(payload: &str) -> Result<ParsedCallback> {
    let Some((decision_str, rest)) = payload.split_once(':') else {
        anyhow::bail!("missing ':' separator in callback payload");
    };
    let decision = match decision_str {
        "approve" => CallbackDecision::Approve,
        "deny" => CallbackDecision::Deny,
        other => anyhow::bail!("unknown callback decision: {other}"),
    };
    let (txn_id_str, require) = match rest.rsplit_once(":r") {
        Some((head, digits))
            if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) =>
        {
            let req = digits
                .parse::<u8>()
                .map_err(|e| anyhow::anyhow!("invalid quorum count ':r{digits}': {e}"))?
                .max(1);
            (head, req)
        }
        _ => (rest, 1),
    };
    if txn_id_str.is_empty() {
        anyhow::bail!("empty txn_id in callback payload");
    }
    Ok(ParsedCallback {
        decision,
        txn_id: txn_id_str.to_string(),
        require,
    })
}

/// Verify and parse a Telegram `CallbackQuery` for both the HITL daemon and the
/// TUI poller (#336, #337).
///
/// Performs four checks in fail-closed order:
/// 1. 16-hex-char HMAC tag present at the last `:` and valid under `gateway.hmac_key()`.
/// 2. Originating chat (`cb.message.chat.id`) is present and matches `gateway.chat_id()`.
/// 3. `cb.from.id` is listed in `gateway.allowed_approvers()` (empty allowlist refuses all).
/// 4. Payload parses via [`parse_callback_payload`].
///
/// # Errors
///
/// Returns [`CallbackRejection`] describing the first check that failed.
pub fn verify_callback(
    gateway: &TelegramGateway,
    cb: &crate::hitl::telegram::CallbackQuery,
) -> std::result::Result<VerifiedCallback, CallbackRejection> {
    let Some(data) = cb.data.as_ref() else {
        return Err(CallbackRejection::MissingData);
    };
    let parts: Vec<&str> = data.rsplitn(2, ':').collect();
    if parts.len() != 2 || parts[0].len() != 16 || !parts[0].chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err(CallbackRejection::Unsigned { data: data.clone() });
    }
    let tail_tag = parts[0];
    let head_payload = parts[1];
    if !crate::hitl::hmac_key::verify(gateway.hmac_key(), head_payload, tail_tag) {
        return Err(CallbackRejection::InvalidSignature { data: data.clone() });
    }
    let Some(chat) = cb.message.as_ref().and_then(|m| m.chat.as_ref()) else {
        return Err(CallbackRejection::MissingChat);
    };
    if gateway.chat_id() != chat.id.to_string() {
        return Err(CallbackRejection::WrongChat { chat_id: chat.id });
    }
    let approvers = gateway.allowed_approvers();
    if approvers.is_empty() {
        return Err(CallbackRejection::NoApproversConfigured {
            user_id: cb.from.id,
        });
    }
    if !approvers.contains(&cb.from.id) {
        return Err(CallbackRejection::UnauthorizedApprover {
            user_id: cb.from.id,
        });
    }
    let parsed = parse_callback_payload(head_payload)
        .map_err(|_| CallbackRejection::InvalidPayload { data: data.clone() })?;
    Ok(VerifiedCallback {
        decision: parsed.decision,
        txn_id: parsed.txn_id,
        require: parsed.require,
        raw_data: data.clone(),
        approver_id: cb.from.id,
    })
}

#[cfg(test)]
mod callback_verify_tests {
    use super::*;

    type ExpectedParsed = Option<(CallbackDecision, &'static str, u8)>;

    #[test]
    fn parse_callback_payload_table_test() {
        let cases: &[(&str, ExpectedParsed)] = &[
            (
                "approve:stop:100:r2",
                Some((CallbackDecision::Approve, "stop:100", 2)),
            ),
            (
                "approve:stop:100-1739999999999:r1",
                Some((CallbackDecision::Approve, "stop:100-1739999999999", 1)),
            ),
            (
                "deny:stop:100",
                Some((CallbackDecision::Deny, "stop:100", 1)),
            ),
            (
                "approve:stop:100",
                Some((CallbackDecision::Approve, "stop:100", 1)),
            ),
            ("nope:stop:100", None),
            ("", None),
        ];

        for (input, expected) in cases {
            let res = parse_callback_payload(input);
            match expected {
                Some((decision, txn_id, require)) => {
                    let parsed = res.unwrap_or_else(|e| {
                        panic!("expected Ok for payload {input:?}, got Err: {e}")
                    });
                    assert_eq!(
                        parsed.decision, *decision,
                        "decision mismatch for {input:?}"
                    );
                    assert_eq!(parsed.txn_id, *txn_id, "txn_id mismatch for {input:?}");
                    assert_eq!(parsed.require, *require, "require mismatch for {input:?}");
                }
                None => {
                    assert!(
                        res.is_err(),
                        "expected Err for payload {input:?}, got {res:?}"
                    );
                }
            }
        }
    }
}
