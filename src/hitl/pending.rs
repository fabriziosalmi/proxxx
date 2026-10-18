//! Persisted pending-approvals store for the HITL daemon and senders (`#341`).
//!
//! Stores pending, approved, denied, expired, executed, and failed HITL
//! approval requests in `<config_dir>/hitl_pending.db` (next to
//! `<config_dir>/telegram_hmac.key`, directory mode `0700`, file mode `0600`).
//!
//! Sharing the `SQLite` store between senders (CLI policy path, MCP policy path)
//! and the HITL daemon ensures that:
//! - Outbound Telegram buttons carry only `approve:<id>:<hmac16>` /
//!   `deny:<id>:<hmac16>` where `<id>` is a 16-hex-character (64-bit) CSPRNG
//!   token (`<= 41` bytes total, well under Telegram's 64-byte `callback_data`
//!   cap regardless of action name or VMID length).
//! - Each request has an explicit `issued_at` and `expires_at` (default 120 s
//!   TTL), preventing indefinite replay of old approval buttons.
//! - Replay protection, quorum (`require`), and guest binding (`vmid`, `node`,
//!   `guest_type`, `params_json`) are enforced atomically in `SQLite` (`BEGIN
//!   IMMEDIATE`) and survive daemon restarts.
//! - On open, terminal rows (`denied`, `expired`, `executed`, `failed`) older
//!   than 7 days (`RETENTION_SECS`) are pruned automatically.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::api::types::GuestType;
use crate::hitl::daemon::CallbackDecision;

/// Default time-to-live (in seconds) for a pending HITL approval request.
/// Matches the 120-second TUI HITL timeout (`Duration::from_mins(2)`).
pub const DEFAULT_HITL_TTL_SECS: i64 = 120;

/// Retention window (7 days in seconds) for terminal rows (`denied`, `expired`,
/// `executed`, `failed`), swept automatically when the store is opened.
pub const RETENTION_SECS: i64 = 7 * 24 * 60 * 60;

/// Generate a fresh 16-hex-character (64-bit) cryptographically random HITL request ID.
///
/// Format: 16 lowercase ASCII hex characters (`[0-9a-f]{16}`), URL-safe, containing
/// no `:` or `-` characters.
///
/// # Errors
///
/// Returns an error if the OS CSPRNG (`getrandom`) fails.
pub fn generate_request_id() -> Result<String> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).context("getrandom failed seeding HITL request id")?;
    Ok(hex::encode(bytes))
}

/// Resolve the default on-disk path for the HITL pending-approval `SQLite` store:
/// `<config_dir>/hitl_pending.db`, next to `<config_dir>/telegram_hmac.key`.
///
/// Senders (CLI, MCP) and the HITL daemon already share `<config_dir>` to read
/// `telegram_hmac.key` (`src/hitl/hmac_key.rs`), so placing `hitl_pending.db`
/// in the same directory ensures both sides see the same rows under
/// `User=proxxx-ops`.
///
/// # Errors
///
/// Returns an error if the platform config directory cannot be resolved.
pub fn pending_store_path() -> Result<PathBuf> {
    let key_path = crate::hitl::hmac_key::hmac_key_path()?;
    Ok(key_path.with_file_name("hitl_pending.db"))
}

/// Current Unix epoch timestamp in seconds.
#[must_use]
pub fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Lifecycle state of a HITL approval request in `hitl_pending.db`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus {
    /// Waiting for human approval(s) within `expires_at`.
    Pending,
    /// Quorum reached; execution is currently in flight against Proxmox.
    /// A row that remains `Approved` indicates an interrupted/crashed in-flight call.
    Approved,
    /// Explicitly denied by an authorised approver (terminal).
    Denied,
    /// `expires_at` passed before quorum was met (terminal).
    Expired,
    /// Approved and executed against Proxmox with `Ok(upid)` (terminal).
    Executed,
    /// Approved, but the Proxmox execution failed (terminal; failure stored in `error`).
    Failed,
}

impl RequestStatus {
    /// Canonical lowercase string stored in `SQLite`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Executed => "executed",
            Self::Failed => "failed",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "pending" => Ok(Self::Pending),
            "approved" => Ok(Self::Approved),
            "denied" => Ok(Self::Denied),
            "expired" => Ok(Self::Expired),
            "executed" => Ok(Self::Executed),
            "failed" => Ok(Self::Failed),
            other => anyhow::bail!("unknown HITL request status in store: {other}"),
        }
    }
}

impl fmt::Display for RequestStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A persisted HITL approval request row from `hitl_pending_requests`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    pub id: String,
    pub action: String,
    pub vmid: Option<u32>,
    pub node: Option<String>,
    pub guest_type: Option<GuestType>,
    pub params_json: String,
    pub require: u8,
    pub issued_at: i64,
    pub expires_at: i64,
    pub status: RequestStatus,
    pub approvers: Vec<i64>,
    pub error: Option<String>,
}

/// Parameters for inserting a new pending HITL approval request.
#[derive(Debug, Clone)]
pub struct NewPendingRequest {
    pub action: String,
    pub vmid: Option<u32>,
    pub node: Option<String>,
    pub guest_type: Option<GuestType>,
    pub params: serde_json::Value,
    pub require: u8,
    pub ttl_secs: i64,
}

impl NewPendingRequest {
    /// Construct a new pending request with default TTL (`120 s`) and empty JSON parameters.
    #[must_use]
    pub fn new(action: impl Into<String>, vmid: Option<u32>, require: u8) -> Self {
        Self {
            action: action.into(),
            vmid,
            node: None,
            guest_type: None,
            params: serde_json::json!({}),
            require: require.max(1),
            ttl_secs: DEFAULT_HITL_TTL_SECS,
        }
    }

    /// Attach the resolved Proxmox node name for guest binding (`#340`).
    #[must_use]
    pub fn with_node(mut self, node: impl Into<String>) -> Self {
        self.node = Some(node.into());
        self
    }

    /// Attach the resolved guest type (`qemu` / `lxc`) for guest binding (`#340`).
    #[must_use]
    pub const fn with_guest_type(mut self, guest_type: GuestType) -> Self {
        self.guest_type = Some(guest_type);
        self
    }

    /// Attach operation parameters (`serde_json::Value`) for `#340` executors.
    #[must_use]
    pub fn with_params(mut self, params: serde_json::Value) -> Self {
        self.params = params;
        self
    }

    /// Override the request TTL in seconds.
    #[must_use]
    pub const fn with_ttl_secs(mut self, ttl_secs: i64) -> Self {
        self.ttl_secs = ttl_secs;
        self
    }
}

/// Outcome of processing a verified callback against [`PendingStore`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreOutcome {
    /// No row with this `id` exists in `hitl_pending_requests`.
    UnknownRequest,
    /// `expires_at` has passed (`now_secs >= expires_at`) or the row was already `expired`.
    Expired { request: PendingRequest },
    /// The row is not in `pending` state (`approved`, `denied`, `executed`, or `failed`).
    AlreadyHandled { request: PendingRequest },
    /// An authorised approver pressed Deny on a pending, unexpired request.
    Denied { request: PendingRequest },
    /// Vote recorded on a pending, unexpired request, but quorum (`require`) is not yet met.
    AwaitingApprovals {
        request: PendingRequest,
        have: usize,
        need: usize,
        duplicate: bool,
    },
    /// Quorum reached on a pending, unexpired request; status transitioned to `approved`.
    Approved { request: PendingRequest },
}

/// `SQLite`-backed store of HITL pending and handled approval requests (`#341`).
pub struct PendingStore {
    path: PathBuf,
    conn: Mutex<Connection>,
}

/// Type alias preserving compatibility with callers that name [`PendingApprovals`].
pub type PendingApprovals = PendingStore;

const SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS hitl_pending_requests (
    id             TEXT PRIMARY KEY,
    action         TEXT NOT NULL,
    vmid           INTEGER,
    node           TEXT,
    guest_type     TEXT CHECK (guest_type IS NULL OR guest_type IN ('qemu', 'lxc')),
    params_json    TEXT NOT NULL DEFAULT '{}',
    require        INTEGER NOT NULL CHECK (require >= 1),
    issued_at      INTEGER NOT NULL,
    expires_at     INTEGER NOT NULL,
    status         TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'executed', 'failed')),
    approvers_json TEXT NOT NULL DEFAULT '[]',
    error          TEXT
);
CREATE INDEX IF NOT EXISTS idx_hitl_pending_status_expires
    ON hitl_pending_requests (status, expires_at);
";

fn ensure_parent_dir_0700(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .with_context(|| format!("create HITL store dir {}", parent.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create HITL store dir {}", parent.display()))?;
    }
    Ok(())
}

fn ensure_file_0600(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        if !path.exists() {
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .open(path)
                .with_context(|| format!("create HITL store file {}", path.display()))?;
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
        for suffix in ["-wal", "-shm"] {
            let mut os = path.as_os_str().to_os_string();
            os.push(suffix);
            let sidecar = PathBuf::from(os);
            if sidecar.exists() {
                let _ = std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

const fn guest_type_to_str(gt: GuestType) -> &'static str {
    match gt {
        GuestType::Qemu => "qemu",
        GuestType::Lxc => "lxc",
    }
}

fn str_to_guest_type(s: &str) -> Result<GuestType> {
    match s {
        "qemu" => Ok(GuestType::Qemu),
        "lxc" => Ok(GuestType::Lxc),
        other => anyhow::bail!("unknown guest_type in HITL store: {other}"),
    }
}

fn row_to_pending_request(row: &rusqlite::Row<'_>) -> rusqlite::Result<PendingRequest> {
    let id: String = row.get(0)?;
    let action: String = row.get(1)?;
    let vmid_raw: Option<i64> = row.get(2)?;
    let node: Option<String> = row.get(3)?;
    let gt_raw: Option<String> = row.get(4)?;
    let params_json: String = row.get(5)?;
    let require_raw: i64 = row.get(6)?;
    let issued_at: i64 = row.get(7)?;
    let expires_at: i64 = row.get(8)?;
    let status_raw: String = row.get(9)?;
    let approvers_raw: String = row.get(10)?;
    let error: Option<String> = row.get(11)?;

    let vmid = vmid_raw.and_then(|v| u32::try_from(v).ok());
    let guest_type = gt_raw
        .as_deref()
        .map(str_to_guest_type)
        .transpose()
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Text,
                e.into_boxed_dyn_error(),
            )
        })?;
    let require = u8::try_from(require_raw).unwrap_or(1).max(1);
    let status = RequestStatus::parse(&status_raw).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            9,
            rusqlite::types::Type::Text,
            e.into_boxed_dyn_error(),
        )
    })?;
    let approvers: Vec<i64> = serde_json::from_str(&approvers_raw).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(10, rusqlite::types::Type::Text, Box::new(e))
    })?;

    Ok(PendingRequest {
        id,
        action,
        vmid,
        node,
        guest_type,
        params_json,
        require,
        issued_at,
        expires_at,
        status,
        approvers,
        error,
    })
}

impl PendingStore {
    /// Open the default on-disk store at `<config_dir>/hitl_pending.db` (next to
    /// `telegram_hmac.key`), creating it with `0600` permissions if absent and
    /// pruning terminal rows older than 7 days.
    ///
    /// # Errors
    ///
    /// Returns an error if the config directory or `SQLite` file cannot be opened
    /// or initialised.
    pub fn open_default() -> Result<Self> {
        let path = pending_store_path()?;
        Self::open_at(path)
    }

    /// Open (or create) the store at an explicit filesystem path. Used by
    /// production code via [`Self::open_default`] and by tests to keep store
    /// state hermetic in a temporary directory.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory, `SQLite` database, or schema
    /// cannot be initialised.
    pub fn open_at(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_at_with_now(path, now_unix_secs())
    }

    /// Open (or create) the store at `path` using `now_secs` as the reference
    /// clock for the 7-day retention sweep of terminal rows.
    ///
    /// # Errors
    ///
    /// Returns an error if the `SQLite` database or schema cannot be initialised.
    pub fn open_at_with_now(path: impl AsRef<Path>, now_secs: i64) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        ensure_parent_dir_0700(&path)?;
        ensure_file_0600(&path)?;

        let conn = Connection::open(&path)
            .with_context(|| format!("open HITL pending store at {}", path.display()))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;",
        )
        .context("configure SQLite pragmas on HITL pending store")?;
        conn.execute_batch(SCHEMA_SQL)
            .context("initialise hitl_pending_requests schema")?;

        let cutoff = now_secs.saturating_sub(RETENTION_SECS);
        conn.execute(
            "DELETE FROM hitl_pending_requests
             WHERE status IN ('denied', 'expired', 'executed', 'failed')
               AND issued_at < ?1",
            params![cutoff],
        )
        .context("prune expired terminal HITL rows older than 7 days")?;

        ensure_file_0600(&path)?;

        Ok(Self {
            path,
            conn: Mutex::new(conn),
        })
    }

    /// Filesystem path of this `SQLite` store.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Insert a new pending request with a fresh 16-hex-char random ID and the
    /// current system clock.
    ///
    /// # Errors
    ///
    /// Returns an error if ID generation or the `SQLite` insert fails.
    pub fn insert(&self, req: &NewPendingRequest) -> Result<PendingRequest> {
        self.insert_at(req, now_unix_secs())
    }

    /// Insert a new pending request using `now_secs` as `issued_at` (`expires_at =
    /// now_secs + req.ttl_secs`).
    ///
    /// # Errors
    ///
    /// Returns an error if ID generation or the `SQLite` insert fails.
    pub fn insert_at(&self, req: &NewPendingRequest, now_secs: i64) -> Result<PendingRequest> {
        let id = generate_request_id()?;
        let require = req.require.max(1);
        let expires_at = now_secs.saturating_add(req.ttl_secs);
        let params_json =
            serde_json::to_string(&req.params).context("serialize HITL params_json")?;
        let gt_str = req.guest_type.map(guest_type_to_str);

        let guard = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .execute(
                "INSERT INTO hitl_pending_requests
                    (id, action, vmid, node, guest_type, params_json, require,
                     issued_at, expires_at, status, approvers_json, error)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'pending', '[]', NULL)",
                params![
                    id,
                    req.action,
                    req.vmid.map(i64::from),
                    req.node,
                    gt_str,
                    params_json,
                    i64::from(require),
                    now_secs,
                    expires_at,
                ],
            )
            .context("insert row into hitl_pending_requests")?;
        drop(guard);

        Ok(PendingRequest {
            id,
            action: req.action.clone(),
            vmid: req.vmid,
            node: req.node.clone(),
            guest_type: req.guest_type,
            params_json,
            require,
            issued_at: now_secs,
            expires_at,
            status: RequestStatus::Pending,
            approvers: Vec::new(),
            error: None,
        })
    }

    /// Fetch a request row by `id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the `SQLite` query or row deserialization fails.
    pub fn get(&self, id: &str) -> Result<Option<PendingRequest>> {
        let guard = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .query_row(
                "SELECT id, action, vmid, node, guest_type, params_json, require,
                        issued_at, expires_at, status, approvers_json, error
                 FROM hitl_pending_requests
                 WHERE id = ?1",
                params![id],
                row_to_pending_request,
            )
            .optional()
            .map_err(anyhow::Error::from)
    }

    /// Atomically evaluate a verified callback (`Approve` or `Deny`) against the
    /// store using the current system clock.
    ///
    /// # Errors
    ///
    /// Returns an error if the `SQLite` transaction fails.
    pub fn process_callback(
        &self,
        id: &str,
        decision: CallbackDecision,
        approver_id: i64,
    ) -> Result<StoreOutcome> {
        self.process_callback_at(id, decision, approver_id, now_unix_secs())
    }

    /// Atomically evaluate a verified callback against the store at `now_secs`
    /// inside a `BEGIN IMMEDIATE` transaction.
    ///
    /// Evaluation order (Decision 3):
    /// 1. Missing `id` -> [`StoreOutcome::UnknownRequest`].
    /// 2. `status == 'expired'` or (`status == 'pending'` and `now_secs >= expires_at`)
    ///    -> transitions to `expired` if needed and returns [`StoreOutcome::Expired`].
    /// 3. `status != 'pending'` (`approved`, `denied`, `executed`, `failed`)
    ///    -> returns [`StoreOutcome::AlreadyHandled`] (no replay, including across restarts).
    /// 4. `decision == Deny` -> transitions to `denied` and returns [`StoreOutcome::Denied`].
    /// 5. `decision == Approve` -> records distinct `approver_id` in `approvers_json`;
    ///    if `have < require`, returns [`StoreOutcome::AwaitingApprovals`]; otherwise
    ///    transitions to `approved` ("execution in flight") and returns
    ///    [`StoreOutcome::Approved`].
    ///
    /// # Errors
    ///
    /// Returns an error if the `SQLite` transaction fails.
    pub fn process_callback_at(
        &self,
        id: &str,
        decision: CallbackDecision,
        approver_id: i64,
        now_secs: i64,
    ) -> Result<StoreOutcome> {
        let mut guard = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tx = guard
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("begin immediate transaction on hitl_pending_requests")?;

        let Some(mut req) = tx
            .query_row(
                "SELECT id, action, vmid, node, guest_type, params_json, require,
                        issued_at, expires_at, status, approvers_json, error
                 FROM hitl_pending_requests
                 WHERE id = ?1",
                params![id],
                row_to_pending_request,
            )
            .optional()?
        else {
            tx.commit()?;
            return Ok(StoreOutcome::UnknownRequest);
        };

        if req.status == RequestStatus::Expired {
            tx.commit()?;
            return Ok(StoreOutcome::Expired { request: req });
        }
        if req.status == RequestStatus::Pending && now_secs >= req.expires_at {
            tx.execute(
                "UPDATE hitl_pending_requests SET status = 'expired' WHERE id = ?1",
                params![id],
            )?;
            req.status = RequestStatus::Expired;
            tx.commit()?;
            return Ok(StoreOutcome::Expired { request: req });
        }
        if req.status != RequestStatus::Pending {
            tx.commit()?;
            return Ok(StoreOutcome::AlreadyHandled { request: req });
        }

        if decision == CallbackDecision::Deny {
            tx.execute(
                "UPDATE hitl_pending_requests SET status = 'denied' WHERE id = ?1",
                params![id],
            )?;
            req.status = RequestStatus::Denied;
            tx.commit()?;
            return Ok(StoreOutcome::Denied { request: req });
        }

        let duplicate = req.approvers.contains(&approver_id);
        if !duplicate {
            req.approvers.push(approver_id);
        }
        let have = req.approvers.len();
        let need = req.require.max(1) as usize;
        let approvers_json = serde_json::to_string(&req.approvers)?;

        if have >= need {
            tx.execute(
                "UPDATE hitl_pending_requests
                 SET approvers_json = ?2, status = 'approved'
                 WHERE id = ?1",
                params![id, approvers_json],
            )?;
            req.status = RequestStatus::Approved;
            tx.commit()?;
            Ok(StoreOutcome::Approved { request: req })
        } else {
            tx.execute(
                "UPDATE hitl_pending_requests
                 SET approvers_json = ?2
                 WHERE id = ?1",
                params![id, approvers_json],
            )?;
            tx.commit()?;
            Ok(StoreOutcome::AwaitingApprovals {
                request: req,
                have,
                need,
                duplicate,
            })
        }
    }

    /// Mark an `approved` request as `executed` after the Proxmox API call succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error if the `SQLite` update fails.
    pub fn mark_executed(&self, id: &str) -> Result<()> {
        let guard = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.execute(
            "UPDATE hitl_pending_requests
             SET status = 'executed', error = NULL
             WHERE id = ?1",
            params![id],
        )?;
        Ok(())
    }

    /// Mark an `approved` request as `failed` and record the failure reason in
    /// `error` when the Proxmox API call (or pre-execution lookup) fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the `SQLite` update fails.
    pub fn mark_failed(&self, id: &str, error_msg: &str) -> Result<()> {
        let guard = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.execute(
            "UPDATE hitl_pending_requests
             SET status = 'failed', error = ?2
             WHERE id = ?1",
            params![id, error_msg],
        )?;
        Ok(())
    }

    /// Count how many requests have reached an execution state (`approved`,
    /// `executed`, or `failed`).
    #[must_use]
    pub fn consumed_count(&self) -> usize {
        let guard = self
            .conn
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard
            .query_row(
                "SELECT COUNT(*) FROM hitl_pending_requests
                 WHERE status IN ('approved', 'executed', 'failed')",
                [],
                |r| r.get::<_, i64>(0),
            )
            .ok()
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, PendingStore) {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("hitl_pending.db");
        let store = PendingStore::open_at(&db_path).expect("open store");
        (dir, store)
    }

    #[test]
    fn generate_request_id_has_64_bits_hex_entropy_and_is_url_safe() {
        let id1 = generate_request_id().expect("id1");
        let id2 = generate_request_id().expect("id2");
        assert_eq!(id1.len(), 16);
        assert_eq!(id2.len(), 16);
        assert_ne!(id1, id2);
        assert!(id1
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert!(!id1.contains(':'));
    }

    #[test]
    fn pending_store_path_is_next_to_hmac_key() {
        let key_path = crate::hitl::hmac_key::hmac_key_path().expect("hmac_key_path");
        let store_path = pending_store_path().expect("pending_store_path");
        assert_eq!(store_path.parent(), key_path.parent());
        assert_eq!(
            store_path.file_name().and_then(|s| s.to_str()),
            Some("hitl_pending.db")
        );
    }

    #[cfg(unix)]
    #[test]
    fn store_file_and_parent_dir_created_with_0600_and_0700_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let nested_dir = dir.path().join("proxxx-cfg");
        let db_path = nested_dir.join("hitl_pending.db");
        let _store = PendingStore::open_at(&db_path).expect("open store");

        let dir_mode = std::fs::metadata(&nested_dir)
            .expect("dir metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "parent dir must be 0700, got {dir_mode:o}");

        let file_mode = std::fs::metadata(&db_path)
            .expect("db metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            file_mode, 0o600,
            "store file must be 0600, got {file_mode:o}"
        );
    }

    #[test]
    fn guest_type_and_failed_status_persisted_in_store() {
        let (_dir, store) = temp_store();
        let inserted = store
            .insert_at(
                &NewPendingRequest::new("delete", Some(100), 1)
                    .with_node("pve01")
                    .with_guest_type(GuestType::Lxc)
                    .with_params(serde_json::json!({"purge": true})),
                1_700_000_000,
            )
            .expect("insert");
        assert_eq!(inserted.guest_type, Some(GuestType::Lxc));
        assert_eq!(inserted.node.as_deref(), Some("pve01"));

        let out = store
            .process_callback_at(&inserted.id, CallbackDecision::Approve, 4242, 1_700_000_010)
            .expect("approve");
        assert!(matches!(out, StoreOutcome::Approved { .. }));

        store
            .mark_failed(&inserted.id, "403 Forbidden: permission check failed")
            .expect("mark_failed");
        let loaded = store.get(&inserted.id).expect("get").expect("row exists");
        assert_eq!(loaded.status, RequestStatus::Failed);
        assert_eq!(
            loaded.error.as_deref(),
            Some("403 Forbidden: permission check failed")
        );
        assert_eq!(loaded.guest_type, Some(GuestType::Lxc));
    }

    #[test]
    fn retention_on_open_prunes_terminal_rows_older_than_seven_days() {
        let dir = tempfile::tempdir().expect("tempdir");
        let db_path = dir.path().join("hitl_pending.db");
        let t0 = 1_700_000_000_i64;
        let store = PendingStore::open_at_with_now(&db_path, t0).expect("open at t0");

        let old_exec = store
            .insert_at(&NewPendingRequest::new("stop", Some(101), 1), t0)
            .expect("insert old_exec");
        store
            .process_callback_at(&old_exec.id, CallbackDecision::Approve, 1, t0 + 1)
            .expect("approve");
        store.mark_executed(&old_exec.id).expect("mark_executed");

        let old_denied = store
            .insert_at(&NewPendingRequest::new("stop", Some(102), 1), t0)
            .expect("insert old_denied");
        store
            .process_callback_at(&old_denied.id, CallbackDecision::Deny, 1, t0 + 1)
            .expect("deny");

        let old_failed = store
            .insert_at(&NewPendingRequest::new("stop", Some(103), 1), t0)
            .expect("insert old_failed");
        store
            .process_callback_at(&old_failed.id, CallbackDecision::Approve, 1, t0 + 1)
            .expect("approve");
        store
            .mark_failed(&old_failed.id, "boom")
            .expect("mark_failed");

        let old_pending = store
            .insert_at(&NewPendingRequest::new("stop", Some(104), 1), t0)
            .expect("insert old_pending");

        let recent_exec = store
            .insert_at(
                &NewPendingRequest::new("stop", Some(105), 1),
                t0 + RETENTION_SECS - 10,
            )
            .expect("insert recent_exec");
        store
            .process_callback_at(
                &recent_exec.id,
                CallbackDecision::Approve,
                1,
                t0 + RETENTION_SECS - 5,
            )
            .expect("approve recent");
        store
            .mark_executed(&recent_exec.id)
            .expect("mark_executed recent");
        drop(store);

        let reopened =
            PendingStore::open_at_with_now(&db_path, t0 + RETENTION_SECS + 1).expect("reopen");
        assert!(reopened.get(&old_exec.id).expect("get").is_none());
        assert!(reopened.get(&old_denied.id).expect("get").is_none());
        assert!(reopened.get(&old_failed.id).expect("get").is_none());
        assert!(
            reopened.get(&old_pending.id).expect("get").is_some(),
            "non-terminal pending row must not be deleted by terminal retention sweep"
        );
        assert!(
            reopened.get(&recent_exec.id).expect("get").is_some(),
            "terminal row younger than 7 days must be kept"
        );
    }
}
