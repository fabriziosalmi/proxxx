//! HITL daemon callback handler — extracted from `cli::hitl_serve` so
//! the per-callback logic is unit-testable without a 30-second
//! Telegram poll loop.
//!
//! Phase 5.13 / `#336` / `#337` / `#341`:
//! 1. **Verification (`verify_callback`)** — enforces HMAC signature,
//!    originating `chat_id`, `allowed_approvers`, and the `<decision>:<id>`
//!    callback grammar (refusing legacy 3/4-segment keyboards).
//! 2. **Persisted store lookup (`PendingStore::process_callback`)** —
//!    atomically checks existence, TTL (`expires_at`), replay status
//!    (`pending` vs `approved`/`denied`/`expired`/`executed`/`failed`),
//!    and multi-approver quorum (`require`) from `<config_dir>/hitl_pending.db`.
//! 3. **Execution & status recording** — transitions to `approved`
//!    ("execution in flight") before calling PVE, then records `executed`
//!    on `Ok(upid)` or `failed` (with `error`) on failure.

use crate::api::ProxmoxGateway;
use crate::hitl::pending::{PendingApprovals, StoreOutcome};
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
    /// The daemon answered the callback with the failure message and
    /// marked the store row `failed`.
    ExecuteFailed {
        action: String,
        vmid: u32,
        error: String,
    },
    /// User pressed Deny.
    Denied { action: String, vmid: u32 },
    /// Callback for a request whose store status is no longer `pending`
    /// (`approved`, `denied`, `executed`, `failed`) — replay rejected,
    /// including across daemon restarts.
    Replay { txn_id: String },
    /// Callback referred to a request ID whose `expires_at` has passed.
    /// Marked `expired` in the store; not executed.
    Expired { id: String },
    /// Callback referred to a request ID not present in `hitl_pending.db`.
    UnknownRequest { id: String },
    /// Callback was approved in the store, but `vmid` could not be located
    /// on any node at execution time.
    NodeNotFound { vmid: u32 },
    /// Update had no `callback_query` (we ignore non-callback updates).
    NotACallback,
    /// Callback data failed signature verification, used a legacy
    /// 3/4-segment format, or had a malformed `<decision>:<id>` payload.
    InvalidFormat { data: String },
    /// Unknown action token in the stored request.
    UnknownAction { action: String, vmid: u32 },
    /// The callback was well-formed and correctly signed, but the
    /// Telegram account that pressed the button is not on the configured
    /// approver allowlist — or no allowlist is configured at all.
    UnauthorizedApprover { user_id: i64 },
    /// The callback originated in a chat other than the configured
    /// `chat_id` — a forwarded keyboard.
    WrongChat { chat_id: i64 },
    /// The vote was recorded in the store, but the request's `require`
    /// quorum is not yet met.
    AwaitingApprovals { have: usize, need: usize },
}

fn map_rejection_to_outcome(
    rej: CallbackRejection,
    tg_gateway: &TelegramGateway,
    username: Option<&str>,
) -> CallbackOutcome {
    match rej {
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
                username.unwrap_or("?")
            );
            CallbackOutcome::UnauthorizedApprover { user_id }
        }
        CallbackRejection::LegacyFormat { data } => {
            warn!(
                "HITL callback uses legacy 3/4-segment format — refused (#341 requires \
                 store-backed <decision>:<id> callbacks): {data}"
            );
            CallbackOutcome::InvalidFormat { data }
        }
        CallbackRejection::InvalidPayload { data } => CallbackOutcome::InvalidFormat { data },
    }
}

/// Process exactly one Telegram update against [`PendingApprovals`] (`PendingStore`).
///
/// # Errors
///
/// Propagates store I/O errors or transient `find_guest` errors (after recording
/// `failed` in the store).
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
            return Ok(map_rejection_to_outcome(
                rej,
                tg_gateway,
                cb.from.username.as_deref(),
            ));
        }
    };

    let data = &verified.raw_data;
    info!("Received HITL callback: {}", data);

    let msg_id = cb.message.as_ref().map(|m| m.message_id);
    let user_label = cb
        .from
        .username
        .as_deref()
        .unwrap_or(&cb.from.first_name)
        .to_string();
    let edit_status = |action: &str, vmid: u32, status: &str, who: &str| {
        let body = format!("🔔 HITL request: {action} VMID {vmid}\n\n{status} (by @{who})");
        async move {
            if let Some(id) = msg_id {
                let _ = tg_gateway.edit_message_text(id, &body).await;
            }
        }
    };

    let request = match pending.process_callback(
        &verified.txn_id,
        verified.decision,
        verified.approver_id,
    )? {
        StoreOutcome::UnknownRequest => {
            warn!("HITL callback for unknown request id: {}", verified.txn_id);
            let _ = tg_gateway
                .answer_callback(&cb.id, "⚠️ Unknown request")
                .await;
            return Ok(CallbackOutcome::UnknownRequest {
                id: verified.txn_id,
            });
        }
        StoreOutcome::Expired { request } => {
            warn!("HITL callback for expired request id: {}", request.id);
            let _ = tg_gateway
                .answer_callback(&cb.id, "⏰ Request expired — request again")
                .await;
            edit_status(
                &request.action,
                request.vmid.unwrap_or(0),
                "⏰ Expired",
                &user_label,
            )
            .await;
            return Ok(CallbackOutcome::Expired { id: request.id });
        }
        StoreOutcome::AlreadyHandled { request } => {
            warn!(
                "HITL replay rejected for {} (status={}): {data}",
                request.id, request.status
            );
            let _ = tg_gateway
                .answer_callback(&cb.id, &format!("⚠️ Already handled ({})", request.status))
                .await;
            return Ok(CallbackOutcome::Replay { txn_id: request.id });
        }
        StoreOutcome::Denied { request } => {
            let vmid = request.vmid.unwrap_or(0);
            let _ = tg_gateway.answer_callback(&cb.id, "🚫 Denied").await;
            edit_status(&request.action, vmid, "🚫 Denied", &user_label).await;
            return Ok(CallbackOutcome::Denied {
                action: request.action,
                vmid,
            });
        }
        StoreOutcome::AwaitingApprovals {
            request,
            have,
            need,
            duplicate,
        } => {
            let vmid = request.vmid.unwrap_or(0);
            let note = if duplicate {
                format!("You already approved — {have}/{need}")
            } else {
                format!("Recorded — {have}/{need} approvals")
            };
            info!("HITL quorum not yet met for {}: {have}/{need}", request.id);
            let _ = tg_gateway.answer_callback(&cb.id, &note).await;
            edit_status(
                &request.action,
                vmid,
                &format!("\u{23f3} Awaiting approval ({have}/{need})"),
                &user_label,
            )
            .await;
            return Ok(CallbackOutcome::AwaitingApprovals { have, need });
        }
        StoreOutcome::Approved { request } => request,
    };

    let action = request.action.as_str();
    let vmid = request.vmid.unwrap_or(0);

    let guest = match client.find_guest(vmid).await {
        Ok(g) => g,
        Err(e) => {
            let _ = pending.mark_failed(&request.id, &format!("{e:#}"));
            return Err(e);
        }
    };
    let target_node = guest.as_ref().map(|g| g.node.clone());
    let guest_type = guest.map(|g| g.guest_type);

    let (Some(node), Some(gt)) = (target_node, guest_type) else {
        let _ = pending.mark_failed(&request.id, "node not found");
        let _ = tg_gateway
            .answer_callback(&cb.id, "❌ Node not found")
            .await;
        edit_status(action, vmid, "❌ Node not found", &user_label).await;
        return Ok(CallbackOutcome::NodeNotFound { vmid });
    };

    type ApiFut<'a> =
        std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<String>> + Send + 'a>>;
    let api_fut: ApiFut = match action {
        "start" => Box::pin(client.start_guest(&node, vmid, gt)),
        "stop" => Box::pin(client.shutdown_guest(&node, vmid, gt, 60)),
        "restart" => Box::pin(client.restart_guest(&node, vmid, gt)),
        other => {
            warn!("Unknown action: {}", other);
            let _ = pending.mark_failed(&request.id, &format!("unknown action: {other}"));
            let _ = tg_gateway
                .answer_callback(&cb.id, &format!("❌ Unknown action: {other}"))
                .await;
            edit_status(
                action,
                vmid,
                &format!("❌ Unknown action: {other}"),
                &user_label,
            )
            .await;
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
            api_fut.await
        }
    };

    match res {
        Ok(upid) => {
            let _ = pending.mark_executed(&request.id);
            let _ = tg_gateway.answer_callback(&cb.id, "✅ Executed").await;
            edit_status(action, vmid, &format!("✅ Done — {upid}"), &user_label).await;
            Ok(CallbackOutcome::Executed {
                action: request.action,
                vmid,
                upid,
            })
        }
        Err(e) => {
            error!("Execution failed: {}", e);
            let err_str = format!("{e}");
            let _ = pending.mark_failed(&request.id, &err_str);
            let _ = tg_gateway
                .answer_callback(&cb.id, &format!("❌ Failed: {err_str}"))
                .await;
            let err_short = crate::util::sanitize::truncate_ellipsis(&err_str, 200);
            edit_status(
                action,
                vmid,
                &format!("❌ Failed: {err_short}"),
                &user_label,
            )
            .await;
            Ok(CallbackOutcome::ExecuteFailed {
                action: request.action,
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

/// Parsed `<decision>:<id>` payload after HMAC strip (`#341`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCallback {
    pub decision: CallbackDecision,
    pub txn_id: String,
}

/// Verified and parsed Telegram callback query (`#336`, `#337`, `#341`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCallback {
    pub decision: CallbackDecision,
    pub txn_id: String,
    pub raw_data: String,
    pub approver_id: i64,
}

/// Reason a Telegram callback query was rejected by [`verify_callback`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallbackRejection {
    MissingData,
    Unsigned {
        data: String,
    },
    InvalidSignature {
        data: String,
    },
    MissingChat,
    WrongChat {
        chat_id: i64,
    },
    NoApproversConfigured {
        user_id: i64,
    },
    UnauthorizedApprover {
        user_id: i64,
    },
    /// Old 3-segment (`approve:<action>:<vmid>`) or 4-segment
    /// (`approve:<action>:<vmid>:r<N>`) keyboard from an earlier proxxx release.
    LegacyFormat {
        data: String,
    },
    InvalidPayload {
        data: String,
    },
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
            Self::LegacyFormat { .. } => {
                Some("⚠️ This approval button is from an older proxxx, request again")
            }
            Self::InvalidPayload { .. } => Some("❌ Invalid transaction ID format"),
        }
    }
}

/// Reason [`parse_callback_payload`] rejected a signed payload head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadParseError {
    /// Multi-colon legacy payload (`approve:<action>:<vmid>[:r<N>]`).
    LegacyFormat,
    /// Missing `:`, unknown decision prefix, empty ID, or non-URL-safe characters.
    Invalid,
}

impl std::fmt::Display for PayloadParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LegacyFormat => {
                f.write_str("legacy multi-segment callback format is no longer accepted")
            }
            Self::Invalid => f.write_str("invalid callback payload format"),
        }
    }
}

impl std::error::Error for PayloadParseError {}

/// Parse a verified callback payload (after the trailing `:hmac_hex` tag has
/// been stripped).
///
/// Grammar (`#341`): `<decision> ":" <id>`
/// - `<decision>` is `"approve"` or `"deny"`.
/// - `<id>` is a single non-empty URL-safe token (`[A-Za-z0-9_-]{1,64}`) with
///   **no** `:` separator.
/// - Old 3/4-segment payloads containing an extra `:` (e.g.
///   `approve:stop:100` or `approve:stop:100:r2`) return
///   `Err(PayloadParseError::LegacyFormat)` so callers can tell the operator
///   that the button was minted by an older proxxx and must be requested again.
///
/// # Errors
///
/// Returns [`PayloadParseError::LegacyFormat`] when the ID portion contains `:`,
/// or [`PayloadParseError::Invalid`] when the decision prefix or ID token is
/// missing or malformed.
pub fn parse_callback_payload(
    payload: &str,
) -> std::result::Result<ParsedCallback, PayloadParseError> {
    let Some((decision_str, id_str)) = payload.split_once(':') else {
        return Err(PayloadParseError::Invalid);
    };
    let decision = match decision_str {
        "approve" => CallbackDecision::Approve,
        "deny" => CallbackDecision::Deny,
        _ => return Err(PayloadParseError::Invalid),
    };
    if id_str.is_empty() {
        return Err(PayloadParseError::Invalid);
    }
    if id_str.contains(':') {
        return Err(PayloadParseError::LegacyFormat);
    }
    if id_str.len() > 64
        || !id_str
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(PayloadParseError::Invalid);
    }
    Ok(ParsedCallback {
        decision,
        txn_id: id_str.to_string(),
    })
}

/// Verify and parse a Telegram `CallbackQuery` for both the HITL daemon and the
/// TUI poller (`#336`, `#337`, `#341`).
///
/// Performs four checks in fail-closed order:
/// 1. 16-hex-char HMAC tag present at the last `:` and valid under `gateway.hmac_key()`.
/// 2. Originating chat (`cb.message.chat.id`) is present and matches `gateway.chat_id()`.
/// 3. `cb.from.id` is listed in `gateway.allowed_approvers()` (empty allowlist refuses all).
/// 4. Payload parses via [`parse_callback_payload`] (rejecting legacy 3/4-segment
///    buttons with [`CallbackRejection::LegacyFormat`]).
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
    let parsed = match parse_callback_payload(head_payload) {
        Ok(p) => p,
        Err(PayloadParseError::LegacyFormat) => {
            return Err(CallbackRejection::LegacyFormat { data: data.clone() });
        }
        Err(PayloadParseError::Invalid) => {
            return Err(CallbackRejection::InvalidPayload { data: data.clone() });
        }
    };
    Ok(VerifiedCallback {
        decision: parsed.decision,
        txn_id: parsed.txn_id,
        raw_data: data.clone(),
        approver_id: cb.from.id,
    })
}

#[cfg(test)]
mod callback_verify_tests {
    use super::*;

    type ExpectedParsed = std::result::Result<(CallbackDecision, &'static str), PayloadParseError>;

    #[test]
    fn parse_callback_payload_table_test() {
        let cases: &[(&str, ExpectedParsed)] = &[
            (
                "approve:0123456789abcdef",
                Ok((CallbackDecision::Approve, "0123456789abcdef")),
            ),
            (
                "deny:fedcba9876543210",
                Ok((CallbackDecision::Deny, "fedcba9876543210")),
            ),
            ("approve:stop:100", Err(PayloadParseError::LegacyFormat)),
            ("approve:stop:100:r2", Err(PayloadParseError::LegacyFormat)),
            ("deny:stop:100", Err(PayloadParseError::LegacyFormat)),
            ("nope:0123456789abcdef", Err(PayloadParseError::Invalid)),
            ("approve:", Err(PayloadParseError::Invalid)),
            ("", Err(PayloadParseError::Invalid)),
        ];

        for (input, expected) in cases {
            let res = parse_callback_payload(input);
            match expected {
                Ok((decision, txn_id)) => {
                    let parsed = res.unwrap_or_else(|e| {
                        panic!("expected Ok for payload {input:?}, got Err: {e}")
                    });
                    assert_eq!(parsed.decision, *decision);
                    assert_eq!(parsed.txn_id, *txn_id);
                }
                Err(expected_err) => {
                    assert_eq!(
                        res,
                        Err(*expected_err),
                        "unexpected Err variant for {input:?}"
                    );
                }
            }
        }
    }
}
