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

    let fail_before_exec = |err_str: String, target_vmid: u32| {
        let action_owned = request.action.clone();
        let req_id = request.id.clone();
        let cb_id = cb.id.clone();
        let label = user_label.clone();
        async move {
            error!("HITL pre-execution check failed for {req_id}: {err_str}");
            let _ = pending.mark_failed(&req_id, &err_str);
            let _ = tg_gateway
                .answer_callback(&cb_id, &format!("❌ Failed: {err_str}"))
                .await;
            let err_short = crate::util::sanitize::truncate_ellipsis(&err_str, 200);
            edit_status(
                &action_owned,
                target_vmid,
                &format!("❌ Failed: {err_short}"),
                &label,
            )
            .await;
            CallbackOutcome::ExecuteFailed {
                action: action_owned,
                vmid: target_vmid,
                error: err_str,
            }
        }
    };

    let op = match ApprovedOp::decode(&request) {
        Ok(op) => op,
        Err(reason) => {
            let err_str = format!("cannot decode approved operation: {reason}");
            return Ok(fail_before_exec(err_str, vmid).await);
        }
    };

    let effective_vmid = op.target_vmid(&request);

    // Guest binding (#340 Decision 3):
    // - For operations on an existing guest, `request.node` and `request.guest_type`
    //   are mandatory; if either is missing, refuse before making any gateway call.
    //   Then resolve `find_guest(vmid)` and verify that the guest still exists on
    //   `request.node` with `request.guest_type`.
    // - For `create_guest` / `clone_guest` / `clone_with_cloudinit`, verify that any
    //   explicit target VMID (`vmid` / `newid`) is still free on the cluster.
    let bound_existing = if let Some(source_vmid) = op.existing_guest_vmid(&request) {
        let (Some(exp_node), Some(exp_gt)) = (
            request.node.as_deref().filter(|s| !s.is_empty()),
            request.guest_type,
        ) else {
            let err_str =
                "request has no recorded guest binding (node/type); request again".to_string();
            return Ok(fail_before_exec(err_str, source_vmid).await);
        };
        let live = match client.find_guest(source_vmid).await {
            Ok(g) => g,
            Err(e) => {
                let _ = pending.mark_failed(&request.id, &format!("{e:#}"));
                return Err(e);
            }
        };
        let exp_gt_str = exp_gt.as_str();
        match live {
            Some(g) if g.node == exp_node && g.guest_type == exp_gt => {
                Some((source_vmid, g.node, g.guest_type))
            }
            Some(g) => {
                let err_str = format!(
                    "guest changed since the request (expected {exp_node}/{exp_gt_str}, found {}/{})",
                    g.node,
                    g.guest_type.as_str()
                );
                return Ok(fail_before_exec(err_str, source_vmid).await);
            }
            None => {
                let err_str = format!(
                    "guest changed since the request (expected {exp_node}/{exp_gt_str}, found missing)"
                );
                return Ok(fail_before_exec(err_str, source_vmid).await);
            }
        }
    } else {
        if let ApprovedOp::McpCreateGuest(ref params) = op {
            let exp_node = request.node.as_deref();
            let exp_gt = request.guest_type.map(crate::api::types::GuestType::as_str);
            if exp_node.is_some_and(|n| n != params.node)
                || exp_gt.is_some_and(|t| t != params.guest_type)
            {
                let err_str = format!(
                    "guest changed since the request (expected {}/{}, found {}/{})",
                    exp_node.unwrap_or("<any>"),
                    exp_gt.unwrap_or("<any>"),
                    params.node,
                    params.guest_type
                );
                return Ok(fail_before_exec(err_str, effective_vmid).await);
            }
        }
        None
    };

    if let Some(new_vmid) = op.free_target_vmid(&request) {
        let existing = match client.find_guest(new_vmid).await {
            Ok(g) => g,
            Err(e) => {
                let _ = pending.mark_failed(&request.id, &format!("{e:#}"));
                return Err(e);
            }
        };
        if let Some(g) = existing {
            let err_str = format!(
                "guest changed since the request (expected target VMID {new_vmid} to be free, found {}/{})",
                g.node,
                g.guest_type.as_str()
            );
            return Ok(fail_before_exec(err_str, effective_vmid).await);
        }
    }

    let api_fut = execute_approved_op(client, &op, request.vmid, bound_existing);
    tokio::pin!(api_fut);

    let intermediate_body = format!(
        "🔔 HITL request: {action} VMID {effective_vmid}\n\n⏳ Executing… (by @{user_label})"
    );
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
            let _ = pending.mark_executed(&request.id, &upid);
            let _ = tg_gateway.answer_callback(&cb.id, "✅ Executed").await;
            edit_status(
                action,
                effective_vmid,
                &format!("✅ Done — {upid}"),
                &user_label,
            )
            .await;
            Ok(CallbackOutcome::Executed {
                action: request.action,
                vmid: effective_vmid,
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
                effective_vmid,
                &format!("❌ Failed: {err_short}"),
                &user_label,
            )
            .await;
            Ok(CallbackOutcome::ExecuteFailed {
                action: request.action,
                vmid: effective_vmid,
                error: err_str,
            })
        }
    }
}

const fn default_cli_stop_timeout() -> u32 {
    60
}

const fn default_true() -> bool {
    true
}

/// Empty parameter payload for CLI batch actions (`start`, `restart`, `suspend`, `resume`).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliEmptyParams {}

/// Parameter payload for the CLI `stop` batch action (`#340`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CliStopParams {
    #[serde(default)]
    pub force: bool,
    #[serde(default = "default_cli_stop_timeout", alias = "timeout")]
    pub timeout_secs: u32,
}

impl Default for CliStopParams {
    fn default() -> Self {
        Self {
            force: false,
            timeout_secs: default_cli_stop_timeout(),
        }
    }
}

/// Parameter payload for the MCP `stop_guest` tool (`#340`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpStopGuestParams {
    pub guest_id: u32,
    #[serde(default)]
    pub force: bool,
}

/// Parameter payload for MCP tools taking only `guest_id` (`restart_guest`,
/// `delete_guest`, `suspend_guest`) (`#340`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpGuestIdParams {
    pub guest_id: u32,
}

/// Parameter payload for MCP snapshot tools (`create_snapshot`, `delete_snapshot`) (`#340`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpSnapshotParams {
    pub guest_id: u32,
    pub name: String,
}

/// Parameter payload for the MCP `clone_guest` tool (`#340`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpCloneGuestParams {
    pub guest_id: u32,
    #[serde(default)]
    pub newid: u32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub full: bool,
}

/// Parameter payload for the MCP `migrate_guest` tool (`#340`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpMigrateGuestParams {
    pub guest_id: u32,
    pub target_node: String,
    #[serde(default = "default_true")]
    pub online: bool,
}

/// Parameter payload for the MCP `create_guest` tool (`#340`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpCreateGuestParams {
    pub node: String,
    #[serde(rename = "type")]
    pub guest_type: String,
    #[serde(default)]
    pub vmid: Option<u32>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub memory: Option<u64>,
    #[serde(default)]
    pub cores: Option<u64>,
    #[serde(default)]
    pub storage: Option<String>,
    #[serde(default)]
    pub disk_size: Option<u64>,
    #[serde(default)]
    pub template: Option<String>,
    #[serde(default)]
    pub iso: Option<String>,
    #[serde(default)]
    pub bridge: Option<String>,
}

/// Parameter payload for the MCP `clone_with_cloudinit` tool (`#340`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpCloneWithCloudinitParams {
    pub guest_id: u32,
    #[serde(default)]
    pub newid: u32,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub full: bool,
    #[serde(default)]
    pub ciuser: Option<String>,
    #[serde(default)]
    pub sshkey: Option<String>,
    #[serde(default)]
    pub ipconfig0: Option<String>,
    #[serde(default)]
    pub searchdomain: Option<String>,
    #[serde(default)]
    pub nameserver: Option<String>,
}

/// Typed representation of every HITL-approvable operation (`#340`).
///
/// Covers all 5 CLI batch actions (`start`, `stop`, `restart`, `suspend`, `resume`)
/// and all 10 destructive MCP tools (`stop_guest`, `restart_guest`, `delete_guest`,
/// `create_snapshot`, `delete_snapshot`, `suspend_guest`, `clone_guest`,
/// `migrate_guest`, `create_guest`, `clone_with_cloudinit`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovedOp {
    CliStart(CliEmptyParams),
    CliStop(CliStopParams),
    CliRestart(CliEmptyParams),
    CliSuspend(CliEmptyParams),
    CliResume(CliEmptyParams),
    McpStopGuest(McpStopGuestParams),
    McpRestartGuest(McpGuestIdParams),
    McpDeleteGuest(McpGuestIdParams),
    McpCreateSnapshot(McpSnapshotParams),
    McpDeleteSnapshot(McpSnapshotParams),
    McpSuspendGuest(McpGuestIdParams),
    McpCloneGuest(McpCloneGuestParams),
    McpMigrateGuest(McpMigrateGuestParams),
    McpCreateGuest(McpCreateGuestParams),
    McpCloneWithCloudinit(McpCloneWithCloudinitParams),
}

impl ApprovedOp {
    /// Decode `(request.action, request.params_json)` into a typed [`ApprovedOp`]
    /// and validate path-bearing parameters (`Shape::Name`) and `request.vmid`
    /// consistency (`#340` Decision 1).
    ///
    /// # Errors
    ///
    /// Returns a human-readable reason when `action` is unknown, `params_json`
    /// fails `#[serde(deny_unknown_fields)]` deserialization, a path-bearing
    /// parameter fails [`crate::mcp::tools::Shape::Name`], or `request.vmid`
    /// disagrees with `params`.
    pub fn decode(
        request: &crate::hitl::pending::PendingRequest,
    ) -> std::result::Result<Self, String> {
        use crate::mcp::tools::Shape;

        let raw = request.params_json.as_str();
        let decode_empty_cli = |name: &str| -> std::result::Result<CliEmptyParams, String> {
            Self::check_cli_vmid(request)?;
            serde_json::from_str(raw).map_err(|e| format!("{name}: {e}"))
        };
        let decode_guest_id_mcp = |name: &str| -> std::result::Result<McpGuestIdParams, String> {
            let p: McpGuestIdParams =
                serde_json::from_str(raw).map_err(|e| format!("{name}: {e}"))?;
            Self::check_mcp_guest_id(request.vmid, p.guest_id)?;
            Ok(p)
        };
        let decode_snapshot_mcp = |name: &str| -> std::result::Result<McpSnapshotParams, String> {
            let p: McpSnapshotParams =
                serde_json::from_str(raw).map_err(|e| format!("{name}: {e}"))?;
            Self::check_mcp_guest_id(request.vmid, p.guest_id)?;
            Shape::Name
                .check(&p.name)
                .map_err(|e| format!("{name}.name: {e}"))?;
            Ok(p)
        };

        match request.action.as_str() {
            "start" => Ok(Self::CliStart(decode_empty_cli("start")?)),
            "stop" => {
                Self::check_cli_vmid(request)?;
                let p: CliStopParams =
                    serde_json::from_str(raw).map_err(|e| format!("stop: {e}"))?;
                Ok(Self::CliStop(p))
            }
            "restart" => Ok(Self::CliRestart(decode_empty_cli("restart")?)),
            "suspend" => Ok(Self::CliSuspend(decode_empty_cli("suspend")?)),
            "resume" => Ok(Self::CliResume(decode_empty_cli("resume")?)),
            "stop_guest" => {
                let p: McpStopGuestParams =
                    serde_json::from_str(raw).map_err(|e| format!("stop_guest: {e}"))?;
                Self::check_mcp_guest_id(request.vmid, p.guest_id)?;
                Ok(Self::McpStopGuest(p))
            }
            "restart_guest" => Ok(Self::McpRestartGuest(decode_guest_id_mcp("restart_guest")?)),
            "delete_guest" => Ok(Self::McpDeleteGuest(decode_guest_id_mcp("delete_guest")?)),
            "create_snapshot" => Ok(Self::McpCreateSnapshot(decode_snapshot_mcp(
                "create_snapshot",
            )?)),
            "delete_snapshot" => Ok(Self::McpDeleteSnapshot(decode_snapshot_mcp(
                "delete_snapshot",
            )?)),
            "suspend_guest" => Ok(Self::McpSuspendGuest(decode_guest_id_mcp("suspend_guest")?)),
            "clone_guest" => {
                let p: McpCloneGuestParams =
                    serde_json::from_str(raw).map_err(|e| format!("clone_guest: {e}"))?;
                Self::check_mcp_guest_id(request.vmid, p.guest_id)?;
                if let Some(ref name) = p.name {
                    Shape::Name
                        .check(name)
                        .map_err(|e| format!("clone_guest.name: {e}"))?;
                }
                Ok(Self::McpCloneGuest(p))
            }
            "migrate_guest" => {
                let p: McpMigrateGuestParams =
                    serde_json::from_str(raw).map_err(|e| format!("migrate_guest: {e}"))?;
                Self::check_mcp_guest_id(request.vmid, p.guest_id)?;
                Shape::Name
                    .check(&p.target_node)
                    .map_err(|e| format!("migrate_guest.target_node: {e}"))?;
                Ok(Self::McpMigrateGuest(p))
            }
            "create_guest" => Self::decode_create_guest(raw, request.vmid),
            "clone_with_cloudinit" => {
                let p: McpCloneWithCloudinitParams =
                    serde_json::from_str(raw).map_err(|e| format!("clone_with_cloudinit: {e}"))?;
                Self::check_mcp_guest_id(request.vmid, p.guest_id)?;
                if let Some(ref name) = p.name {
                    Shape::Name
                        .check(name)
                        .map_err(|e| format!("clone_with_cloudinit.name: {e}"))?;
                }
                Ok(Self::McpCloneWithCloudinit(p))
            }
            other => Err(format!("unknown action '{other}'")),
        }
    }

    fn check_cli_vmid(
        request: &crate::hitl::pending::PendingRequest,
    ) -> std::result::Result<u32, String> {
        match request.vmid {
            Some(v) if v > 0 => Ok(v),
            _ => Err(format!(
                "missing positive vmid for CLI action '{}'",
                request.action
            )),
        }
    }

    fn check_mcp_guest_id(row_vmid: Option<u32>, guest_id: u32) -> std::result::Result<(), String> {
        if guest_id == 0 {
            return Err("guest_id must be positive".to_string());
        }
        if let Some(rv) = row_vmid {
            if rv != guest_id {
                return Err(format!(
                    "row vmid ({rv}) does not match params.guest_id ({guest_id})"
                ));
            }
        }
        Ok(())
    }

    fn decode_create_guest(raw: &str, row_vmid: Option<u32>) -> std::result::Result<Self, String> {
        use crate::mcp::tools::Shape;

        let p: McpCreateGuestParams =
            serde_json::from_str(raw).map_err(|e| format!("create_guest: {e}"))?;
        Shape::Name
            .check(&p.node)
            .map_err(|e| format!("create_guest.node: {e}"))?;
        if p.guest_type != "qemu" && p.guest_type != "lxc" {
            return Err(format!(
                "create_guest: invalid type '{}' (expected 'qemu' or 'lxc')",
                p.guest_type
            ));
        }
        if p.guest_type == "lxc" && p.template.is_none() {
            return Err("create_guest lxc: missing 'template'".to_string());
        }
        if let Some(ref name) = p.name {
            Shape::Name
                .check(name)
                .map_err(|e| format!("create_guest.name: {e}"))?;
        }
        if let Some(ref storage) = p.storage {
            Shape::Name
                .check(storage)
                .map_err(|e| format!("create_guest.storage: {e}"))?;
        }
        if let (Some(rv), Some(pv)) = (row_vmid, p.vmid) {
            if rv != pv {
                return Err(format!("row vmid ({rv}) does not match params.vmid ({pv})"));
            }
        }
        Ok(Self::McpCreateGuest(p))
    }

    /// Return the existing guest VMID that must exist and match `(request.node, request.guest_type)`
    /// before execution, or `None` for `create_guest`.
    #[must_use]
    pub const fn existing_guest_vmid(
        &self,
        request: &crate::hitl::pending::PendingRequest,
    ) -> Option<u32> {
        match self {
            Self::CliStart(_)
            | Self::CliStop(_)
            | Self::CliRestart(_)
            | Self::CliSuspend(_)
            | Self::CliResume(_) => request.vmid,
            Self::McpStopGuest(p) => Some(p.guest_id),
            Self::McpRestartGuest(p) | Self::McpDeleteGuest(p) | Self::McpSuspendGuest(p) => {
                Some(p.guest_id)
            }
            Self::McpCreateSnapshot(p) | Self::McpDeleteSnapshot(p) => Some(p.guest_id),
            Self::McpCloneGuest(p) => Some(p.guest_id),
            Self::McpMigrateGuest(p) => Some(p.guest_id),
            Self::McpCreateGuest(_) => None,
            Self::McpCloneWithCloudinit(p) => Some(p.guest_id),
        }
    }

    /// Return any explicit new/target VMID (`vmid` for `create_guest`, `newid` for
    /// `clone_guest` / `clone_with_cloudinit`) that must still be free at execution time.
    #[must_use]
    pub fn free_target_vmid(&self, request: &crate::hitl::pending::PendingRequest) -> Option<u32> {
        match self {
            Self::McpCreateGuest(p) => p.vmid.or(request.vmid).filter(|&v| v > 0),
            Self::McpCloneGuest(p) if p.newid > 0 => Some(p.newid),
            Self::McpCloneWithCloudinit(p) if p.newid > 0 => Some(p.newid),
            Self::CliStart(_)
            | Self::CliStop(_)
            | Self::CliRestart(_)
            | Self::CliSuspend(_)
            | Self::CliResume(_)
            | Self::McpStopGuest(_)
            | Self::McpRestartGuest(_)
            | Self::McpDeleteGuest(_)
            | Self::McpCreateSnapshot(_)
            | Self::McpDeleteSnapshot(_)
            | Self::McpSuspendGuest(_)
            | Self::McpCloneGuest(_)
            | Self::McpMigrateGuest(_)
            | Self::McpCloneWithCloudinit(_) => None,
        }
    }

    /// Primary VMID reported in [`CallbackOutcome`] and Telegram status messages.
    #[must_use]
    pub fn target_vmid(&self, request: &crate::hitl::pending::PendingRequest) -> u32 {
        self.existing_guest_vmid(request)
            .or_else(|| self.free_target_vmid(request))
            .or(request.vmid)
            .unwrap_or(0)
    }
}

/// Execute a decoded [`ApprovedOp`] using the shared CLI and MCP executors (`#340` Decision 2).
///
/// The `match` over [`ApprovedOp`] is intentionally exhaustive (no wildcard arm).
async fn execute_approved_op(
    client: &(dyn ProxmoxGateway + Send + Sync),
    op: &ApprovedOp,
    row_vmid: Option<u32>,
    bound_existing: Option<(u32, String, crate::api::types::GuestType)>,
) -> Result<String> {
    use crate::cli::common::{exec_cli_batch_op, BatchOp};
    use crate::mcp::dispatch;

    let require_bound = || -> Result<(u32, String, crate::api::types::GuestType)> {
        bound_existing.ok_or_else(|| anyhow::anyhow!("missing bound guest context"))
    };

    match op {
        ApprovedOp::CliStart(_params) => {
            let (vmid, node, gt) = require_bound()?;
            exec_cli_batch_op(client, &node, vmid, gt, BatchOp::Start).await
        }
        ApprovedOp::CliStop(params) => {
            let (vmid, node, gt) = require_bound()?;
            let batch_op = BatchOp::Stop {
                force: params.force,
                timeout_secs: params.timeout_secs,
            };
            exec_cli_batch_op(client, &node, vmid, gt, batch_op).await
        }
        ApprovedOp::CliRestart(_params) => {
            let (vmid, node, gt) = require_bound()?;
            exec_cli_batch_op(client, &node, vmid, gt, BatchOp::Restart).await
        }
        ApprovedOp::CliSuspend(_params) => {
            let (vmid, node, gt) = require_bound()?;
            exec_cli_batch_op(client, &node, vmid, gt, BatchOp::Suspend).await
        }
        ApprovedOp::CliResume(_params) => {
            let (vmid, node, gt) = require_bound()?;
            exec_cli_batch_op(client, &node, vmid, gt, BatchOp::Resume).await
        }
        ApprovedOp::McpStopGuest(params) => {
            let (_vmid, node, gt) = require_bound()?;
            dispatch::exec_stop_guest(client, &node, gt, params).await
        }
        ApprovedOp::McpRestartGuest(params) => {
            let (_vmid, node, gt) = require_bound()?;
            dispatch::exec_restart_guest(client, &node, gt, params).await
        }
        ApprovedOp::McpDeleteGuest(params) => {
            let (_vmid, node, gt) = require_bound()?;
            dispatch::exec_delete_guest(client, &node, gt, params).await
        }
        ApprovedOp::McpCreateSnapshot(params) => {
            let (_vmid, node, gt) = require_bound()?;
            dispatch::exec_create_snapshot(client, &node, gt, params).await
        }
        ApprovedOp::McpDeleteSnapshot(params) => {
            let (_vmid, node, gt) = require_bound()?;
            dispatch::exec_delete_snapshot(client, &node, gt, params).await
        }
        ApprovedOp::McpSuspendGuest(params) => {
            let (_vmid, node, gt) = require_bound()?;
            dispatch::exec_suspend_guest(client, &node, gt, params).await
        }
        ApprovedOp::McpCloneGuest(params) => {
            let (_vmid, node, gt) = require_bound()?;
            dispatch::exec_clone_guest(client, &node, gt, params)
                .await
                .map(|(_newid, upid)| upid)
        }
        ApprovedOp::McpMigrateGuest(params) => {
            let (_vmid, node, gt) = require_bound()?;
            dispatch::exec_migrate_guest(client, &node, gt, params).await
        }
        ApprovedOp::McpCreateGuest(params) => {
            let mut effective = params.clone();
            if effective.vmid.is_none() {
                effective.vmid = row_vmid;
            }
            dispatch::exec_create_guest(client, &effective)
                .await
                .map(|(_vmid, upid)| upid)
        }
        ApprovedOp::McpCloneWithCloudinit(params) => {
            let (_vmid, node, gt) = require_bound()?;
            dispatch::exec_clone_with_cloudinit(client, &node, gt, params)
                .await
                .map(|(_newid, upid, _ci)| upid)
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
