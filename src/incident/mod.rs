//! Incident-response primitives.
//!
//! `freeze`/`thaw` is a write kill-switch with two scopes:
//!   * **global** (fleet-wide) at `<data_dir>/freeze.lock` — blocks
//!     mutations to *every* profile;
//!   * **per-profile** at `<data_dir>/freeze.<profile>.lock` — blocks
//!     mutations for one cluster only, leaving the rest writable.
//!
//! A `PxClient` mutation is refused if the global lock OR its own
//! profile's lock is active (see [`check_not_frozen_for`]); freezing one
//! profile never blocks another. When a lock is present (and not
//! expired), the call site refuses immediately. Reads keep working —
//! investigators need observation.
//!
//! ## File format
//!
//! TOML at `<data_dir>/freeze.lock`, written atomically (write to a
//! sibling temp file + `rename`) so a racing reader never sees a
//! half-written file. Permissions 0600 on Unix.
//!
//! ```toml
//! reason     = "compromised pveuser-bot token, rotating"
//! operator   = "fab@laptop"
//! frozen_at  = 1747700000     # unix epoch seconds
//! ttl_secs   = 14400          # auto-thaw after 4h (None ⇒ omit)
//! ```
//!
//! ## TTL semantics
//!
//! The lock file *never* gets touched by a daemon — auto-thaw is
//! purely a read-time check: `is_frozen()` evaluates
//! `frozen_at + ttl_secs <= now()` and treats an expired lock as
//! absent. The next operator-issued `freeze` / `thaw` rewrites the
//! file. Trade-off: a freeze stays "valid" only as long as someone
//! checks. Acceptable because every mutation entry point checks on
//! every call.
//!
//! ## What's wired today
//!
//! - `api::PxClient::{post, put, delete}` calls
//!   [`check_not_frozen`] before issuing the request.
//! - `proxxx incident {freeze, thaw, status}` is the operator
//!   interface (CLI dispatch in `cli/incident.rs`).
//! - Audit log entries on freeze + thaw, with the operator's
//!   reason in `params_json`.
//!
//! ## Deferred per #64 "out of scope until needed"
//!
//! - MCP dispatch integration — the MCP server checks
//!   [`check_not_frozen`] on every tool-call boundary. Tracked in
//!   a follow-up PR.
//! - Telegram HITL daemon broadcast on freeze events. Same.
//! - Scheduler tick gating — the future scheduler (issue #63)
//!   will plug in via the same primitive.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Persisted freeze state. Serialised to / from the lock file as TOML.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FreezeState {
    /// Free-form reason text the operator provided. Surfaced in the
    /// refusal message + audit log so future-self / teammates know
    /// why mutations got refused.
    pub reason: String,
    /// Best-effort operator identity — `$USER@hostname` when we can
    /// resolve them, falling back to `unknown@unknown`. Used for the
    /// audit log; not load-bearing for the freeze itself.
    pub operator: String,
    /// Unix epoch seconds at which the freeze was created.
    pub frozen_at: u64,
    /// Optional TTL — when set, `frozen_at + ttl_secs > now()` is
    /// the "still active" predicate. `None` means "until explicitly
    /// thawed" (no auto-expiry).
    pub ttl_secs: Option<u64>,
    /// Freeze scope. `None` = the global (fleet-wide) kill-switch that
    /// blocks mutations to *every* profile; `Some(name)` = a single
    /// profile's freeze. Backward-compatible: lock files written before
    /// per-profile freeze existed (and every global freeze) omit this
    /// field, so it reads back as `None` = global.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

impl FreezeState {
    /// True if this state is still active given `now` (unix epoch
    /// seconds). Encapsulates the TTL math so callers don't have to
    /// re-derive it.
    #[must_use]
    pub const fn is_active_at(&self, now: u64) -> bool {
        match self.ttl_secs {
            Some(ttl) => self.frozen_at.saturating_add(ttl) > now,
            None => true,
        }
    }
}

/// Refusal error returned by [`check_not_frozen`] when the freeze is
/// active. Like `PreflightRefusal`, carried via `anyhow` so callers
/// can `?` through it unchanged; `main.rs` downcasts to map the
/// dedicated exit code.
#[derive(Debug, thiserror::Error)]
#[error(
    "refusing mutation — {scope} is FROZEN (reason: {reason}, since {frozen_at}). \
     Run `proxxx incident thaw --reason '...'` to lift the freeze, or wait for \
     the TTL to expire."
)]
pub struct FreezeRefusal {
    pub reason: String,
    pub frozen_at: u64,
    /// Human label for what's frozen: `the fleet` (global) or
    /// `profile '<name>'`. Derived from the lock's `profile` field.
    pub scope: String,
}

impl FreezeRefusal {
    /// Process exit code for a freeze refusal. Matches the documented
    /// "Incident lockdown active" contract (docs/reference/exit-codes.md).
    pub const EXIT_CODE: i32 = 8;
}

/// Resolve the path to the freeze lock file. Platform default is
/// `<data_local_dir>/freeze.lock`; overridable for tests via the
/// `PROXXX_FREEZE_PATH` environment variable.
///
/// Returning `PathBuf` (not `Result`) — if `directories::ProjectDirs`
/// can't resolve a home directory, we fall back to `/tmp/proxxx` so
/// the binary still functions in odd container environments.
#[must_use]
pub fn freeze_path() -> PathBuf {
    freeze_locations().1
}

/// `(base_dir, global_lock_path)`. The `PROXXX_FREEZE_PATH` override names
/// the GLOBAL lock file; per-profile locks are siblings in its parent dir.
fn freeze_locations() -> (PathBuf, PathBuf) {
    if let Ok(p) = std::env::var("PROXXX_FREEZE_PATH") {
        let global = PathBuf::from(p);
        let dir = global
            .parent()
            .map_or_else(|| PathBuf::from("."), std::path::Path::to_path_buf);
        return (dir, global);
    }
    let dir = directories::ProjectDirs::from("dev", "proxxx", "proxxx").map_or_else(
        || PathBuf::from("/tmp/proxxx"),
        |d| d.data_local_dir().to_path_buf(),
    );
    let global = dir.join("freeze.lock");
    (dir, global)
}

/// Resolve the lock path for a freeze scope. `None` → the global lock
/// (`freeze.lock`, unchanged); `Some(name)` → that profile's lock
/// (`freeze.<name>.lock`, with the name sanitized for filesystem safety).
#[must_use]
pub fn freeze_path_for(profile: Option<&str>) -> PathBuf {
    let (dir, global) = freeze_locations();
    match profile {
        None => global,
        Some(name) => dir.join(format!("freeze.{}.lock", sanitize_profile(name))),
    }
}

/// Map a profile name to a filesystem-safe lock-file stem. Profile names are
/// TOML config keys, conventionally `[A-Za-z0-9_-]`; any other char folds to
/// `_`. The real (unsanitized) name is stored INSIDE the lock as `profile`, so
/// display + audit stay accurate. Two exotic names that fold to the same stem
/// would share a lock — acceptable given the convention, same best-effort
/// trade-off as the operator/hostname resolution above.
fn sanitize_profile(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if s.is_empty() {
        "_".to_string()
    } else {
        s
    }
}

/// Human label for a freeze scope, used in the refusal message + status.
fn scope_label(profile: Option<&str>) -> String {
    match profile {
        None => "the fleet".to_string(),
        Some(p) => format!("profile '{p}'"),
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Identify the operator for the audit trail.
///
/// Audit 2026-09-09 (#256): this used to read `$USER`, which the calling
/// process controls — `USER=someone-else proxxx incident freeze` wrote
/// and then cryptographically sealed an entry attributing the action to
/// whoever was named. The v2 chain format binds the actor into the MAC
/// specifically so a local tamperer cannot rewrite it afterwards; that
/// is worth nothing if the field was never true to begin with.
///
/// The real uid cannot be set by the environment, so it is the anchor.
/// The resolved login name is a convenience on top: if `$USER` disagrees
/// with the uid's passwd entry, the uid wins and the claimed name is
/// recorded separately as unverified, rather than being silently
/// believed or silently dropped.
/// Public wrapper so the CLI's audit hooks label the operator exactly
/// the way the freeze writer does.
#[must_use]
pub fn operator_label() -> String {
    operator_id()
}

fn operator_id() -> String {
    let uid = real_uid();
    compose_operator_id(
        login_name_for_uid(uid).as_deref(),
        std::env::var("USER").ok().as_deref(),
        uid,
        &hostname_or_unknown(),
    )
}

/// The operator label from its parts: the passwd name of the real uid
/// (`resolved`), the name the environment claims (`claimed`), the uid and
/// the host.
fn compose_operator_id(
    resolved: Option<&str>,
    claimed: Option<&str>,
    uid: u32,
    host: &str,
) -> String {
    let who = match (resolved, claimed) {
        // Resolved name and the environment agree — the ordinary case.
        (Some(r), Some(c)) if r == c => r.to_string(),
        // Disagreement, or no passwd entry: keep the uid, which is
        // authoritative, and mark the claim as unverified.
        (Some(r), Some(c)) => format!("{r}(uid:{uid};claimed:{c})"),
        (Some(r), None) => r.to_string(),
        (None, Some(c)) => format!("uid:{uid}(claimed:{c})"),
        (None, None) => format!("uid:{uid}"),
    };
    format!("{who}@{host}")
}

/// The real (not effective) uid of this process. Unlike `$USER` this is
/// kernel state and cannot be set by whoever launched us.
#[cfg(unix)]
fn real_uid() -> u32 {
    // SAFETY: `getuid` is always successful, takes no arguments and
    // touches no memory we own. It is one of the few genuinely
    // infallible syscalls.
    unsafe { libc::getuid() }
}

/// Resolve a uid to its login name via the passwd database.
///
/// `getpwuid_r` with a buffer owned by this call: `getpwuid` returns a
/// pointer into one static buffer shared by every thread, and this runs
/// from the audit hooks inside the multi-threaded runtime, so two lookups
/// at once made the copy a data race (#476).
#[cfg(unix)]
fn login_name_for_uid(uid: u32) -> Option<String> {
    login_name_for_uid_with(uid, 1024)
}

/// [`login_name_for_uid`] starting from a `capacity`-byte buffer, doubled
/// on `ERANGE` up to 1 MiB.
#[cfg(unix)]
fn login_name_for_uid_with(uid: u32, capacity: usize) -> Option<String> {
    const MAX_BUFFER: usize = 1 << 20;
    let mut buf: Vec<libc::c_char> = vec![0; capacity.max(1)];
    loop {
        let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is to memory owned by this frame: `pwd`
        // is written by libc before `result` points at it, `buf` holds
        // the strings `pwd` refers to and is `buf.len()` bytes long, and
        // `result` is a valid out-pointer. Nothing is shared with other
        // threads.
        let rc = unsafe {
            libc::getpwuid_r(
                uid as libc::uid_t,
                pwd.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                &raw mut result,
            )
        };
        if rc == libc::EINTR {
            continue;
        }
        if rc == libc::ERANGE && buf.len() < MAX_BUFFER {
            let grown = buf.len() * 2;
            buf.resize(grown, 0);
            continue;
        }
        if rc != 0 {
            return None;
        }
        // Not found. A separate test on purpose: joined to the line above
        // with `||`, one wrong operator would read `pwd` uninitialised.
        if result.is_null() {
            return None;
        }
        // SAFETY: a zero return with a non-null `result` means libc found
        // the entry and filled `pwd` (POSIX: `result` then points at
        // `pwd`), so it is initialised. `result` itself is only compared
        // with null, never dereferenced.
        let pwd = unsafe { pwd.assume_init() };
        // `pw_name` is NULL or a NUL-terminated string inside `buf`, which
        // is still alive here.
        let name = pwd.pw_name;
        if name.is_null() {
            return None;
        }
        // SAFETY: as above, `name` is NUL-terminated within `buf`.
        return unsafe { std::ffi::CStr::from_ptr(name) }
            .to_str()
            .ok()
            .map(str::to_owned);
    }
}

/// Fallbacks for targets without a passwd database. The release targets
/// are unix (AR-5); these keep the crate building elsewhere and are left
/// out of mutation testing, which runs on unix where they do not compile.
#[cfg(not(unix))]
mod portable {
    pub(super) fn real_uid() -> u32 {
        0
    }

    pub(super) fn login_name_for_uid(_uid: u32) -> Option<String> {
        std::env::var("USERNAME").ok()
    }
}

#[cfg(not(unix))]
use portable::{login_name_for_uid, real_uid};

fn hostname_or_unknown() -> String {
    // Avoid pulling in a hostname crate — `gethostname()` via libc
    // would be a new dep. Use the environment fallback chain that
    // covers the common cases (HOSTNAME exported, or NIX-style
    // `HOST` exported).
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown".into())
}

/// Read the current freeze state from disk. Returns `Ok(None)` for:
///   * file does not exist
///   * file exists but TTL has expired (treated as auto-thawed)
///
/// Returns `Err` only for real I/O failure (permission denied,
/// disk error) or malformed TOML — those should surface, not be
/// silently swallowed.
pub fn current_state() -> Result<Option<FreezeState>> {
    current_state_at(&freeze_path())
}

/// `current_state` with an explicit lock-file path. Tests use this
/// form to avoid mutating process-global env vars in parallel.
pub fn current_state_at(path: &std::path::Path) -> Result<Option<FreezeState>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("reading freeze lock at {}", path.display()))?;
    let state: FreezeState = toml::from_str(&content)
        .with_context(|| format!("parsing freeze lock at {}", path.display()))?;
    if state.is_active_at(now_secs()) {
        Ok(Some(state))
    } else {
        // Expired — treat as thawed. Don't auto-delete the file; the
        // next freeze/thaw command will overwrite it. Leaving it
        // around preserves the forensic trail.
        Ok(None)
    }
}

/// Refuse the calling operation if the freeze is currently active.
/// Every mutation entry point (`PxClient::{post, put, delete}`,
/// future MCP dispatch, future scheduler tick) calls this at the
/// top before any side-effect.
///
/// A lock file that exists but cannot be read or parsed is treated as
/// an ACTIVE freeze, not as an absent one (#252). Only a missing file
/// means "not frozen". The earlier posture — over-permit on any I/O
/// error, per the #64 discussion — did not distinguish the two, so a
/// corrupt lock silently disarmed the kill-switch.
pub fn check_not_frozen() -> Result<()> {
    check_not_frozen_at(&freeze_path())
}

/// Refuse if EITHER the global freeze OR the given profile's freeze is
/// active. Every `PxClient` mutation calls this with its own profile name
/// (`None` for the flat/default profile → only the global lock applies, so a
/// single-cluster setup is fully covered by a global freeze). Freezing one
/// profile never blocks another.
pub fn check_not_frozen_for(profile: Option<&str>) -> Result<()> {
    let (global, prof) = lock_paths_for(profile);
    check_not_frozen_paths(&global, prof.as_deref())
}

/// The locks that govern `profile`: the global lock, plus that profile's
/// own lock when it has a name. Every freeze check for a profile reads
/// both (#504: the daemon's converge gate read only the profile's).
#[must_use]
pub fn lock_paths_for(profile: Option<&str>) -> (PathBuf, Option<PathBuf>) {
    (
        freeze_path_for(None),
        profile.map(|n| freeze_path_for(Some(n))),
    )
}

/// Combination check with explicit paths (the global lock, plus an optional
/// per-profile lock). Tests use this to exercise scope isolation without
/// touching process-global env vars.
///
/// # Errors
/// A [`FreezeRefusal`] when either lock is active, or an error when either
/// exists and cannot be read (an unreadable lock counts as frozen).
pub fn check_not_frozen_paths(
    global: &std::path::Path,
    profile: Option<&std::path::Path>,
) -> Result<()> {
    check_not_frozen_at(global)?;
    if let Some(p) = profile {
        check_not_frozen_at(p)?;
    }
    Ok(())
}

/// `check_not_frozen` with an explicit lock-file path. Tests use
/// this form. The refusal's scope label is derived from the lock's own
/// `profile` field, so it reads "the fleet" or "profile '<name>'" correctly
/// regardless of which path it was handed.
pub fn check_not_frozen_at(path: &std::path::Path) -> Result<()> {
    match current_state_at(path) {
        Ok(Some(state)) => Err(anyhow::Error::from(FreezeRefusal {
            scope: scope_label(state.profile.as_deref()),
            reason: state.reason,
            frozen_at: state.frozen_at,
        })),
        Ok(None) => Ok(()),
        // Audit 2026-09-09 (#252) — an unreadable lock is UNKNOWN state,
        // not absent state, and for a kill-switch unknown must mean
        // stopped.
        //
        // This branch used to return `Ok(())` on the reasoning that a
        // transient I/O error should not lock the cluster out. But the
        // two cases were conflated: `current_state_at` already returns
        // `Ok(None)` when the file does not exist, which is the only
        // case that legitimately means "not frozen". Reaching here means
        // the file IS there and could not be read or parsed — a torn
        // write after power loss, a truncated copy, a full disk, or
        // tampering — and proceeding then silently disarms the control
        // at exactly the moment it is being relied on.
        //
        // `proxxx incident thaw` rewrites the file, so the operator
        // still has a deliberate way out that does not involve the
        // process guessing.
        Err(e) => {
            tracing::warn!(
                "freeze: lock at {} exists but is unreadable — refusing the operation: {e:#}",
                path.display()
            );
            Err(anyhow::Error::from(FreezeRefusal {
                scope: "the fleet (lock unreadable)".to_string(),
                reason: format!(
                    "the freeze lock at {} could not be read or parsed, so proxxx cannot \
                     tell whether a freeze is active. Run `proxxx incident thaw` to clear \
                     it deliberately, or repair the file. Underlying error: {e}",
                    path.display()
                ),
                frozen_at: 0,
            }))
        }
    }
}

/// Activate the freeze. Atomically writes `freeze_path()` with the
/// supplied reason + optional TTL, returning the persisted state.
/// Caller is responsible for the audit-log entry.
pub fn freeze(reason: &str, ttl_secs: Option<u64>) -> Result<FreezeState> {
    freeze_for(None, reason, ttl_secs)
}

/// Freeze a scope: `None` = the global (fleet-wide) kill-switch, `Some(name)`
/// = a single profile. The persisted state records the scope in its `profile`
/// field. Caller is responsible for the audit-log entry.
pub fn freeze_for(
    profile: Option<&str>,
    reason: &str,
    ttl_secs: Option<u64>,
) -> Result<FreezeState> {
    write_freeze_at(&freeze_path_for(profile), profile, reason, ttl_secs)
}

/// `freeze` with an explicit lock-file path (global scope). Tests use this form.
pub fn freeze_at(
    path: &std::path::Path,
    reason: &str,
    ttl_secs: Option<u64>,
) -> Result<FreezeState> {
    write_freeze_at(path, None, reason, ttl_secs)
}

/// Core writer: validate, build the `FreezeState` (stamping `profile`), and
/// persist it atomically. Shared by every freeze entry point.
fn write_freeze_at(
    path: &std::path::Path,
    profile: Option<&str>,
    reason: &str,
    ttl_secs: Option<u64>,
) -> Result<FreezeState> {
    if reason.trim().is_empty() {
        anyhow::bail!("freeze reason is required (operator + reviewers need it later)");
    }
    let state = FreezeState {
        reason: reason.to_string(),
        operator: operator_id(),
        frozen_at: now_secs(),
        ttl_secs,
        profile: profile.map(str::to_string),
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating data dir {}", parent.display()))?;
    }
    write_atomic(path, &toml::to_string_pretty(&state)?)?;
    Ok(state)
}

/// Lift the freeze. Removes the lock file; if there's no lock to
/// remove, returns `Ok(None)` (idempotent — thawing a clean cluster
/// is not an error).
pub fn thaw() -> Result<Option<FreezeState>> {
    thaw_at(&freeze_path())
}

/// Lift the freeze for a scope: `None` = global, `Some(name)` = that profile.
pub fn thaw_for(profile: Option<&str>) -> Result<Option<FreezeState>> {
    thaw_at(&freeze_path_for(profile))
}

/// List every active freeze — the global one plus any per-profile locks —
/// by scanning the lock directory. Expired locks are filtered out. The global
/// freeze (if any) sorts first. For `proxxx incident status`.
pub fn list_active_freezes() -> Result<Vec<FreezeState>> {
    list_active_in(&freeze_locations().0)
}

fn list_active_in(dir: &std::path::Path) -> Result<Vec<FreezeState>> {
    let mut out = Vec::new();
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        // No lock directory yet = nothing frozen.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(anyhow::Error::from(e).context(format!("reading {}", dir.display()))),
    };
    for entry in rd {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // `freeze.lock` (global) and `freeze.<profile>.lock`; the atomic-write
        // temp files (`freeze.lock.tmp.<pid>.<ts>`) don't end in `.lock`.
        if !(name.starts_with("freeze.") && name.ends_with(".lock")) {
            continue;
        }
        if let Ok(Some(state)) = current_state_at(&entry.path()) {
            out.push(state);
        }
    }
    // Global (profile == None) first, then profiles alphabetically.
    out.sort_by(|a, b| a.profile.cmp(&b.profile));
    Ok(out)
}

/// `thaw` with an explicit lock-file path. Tests use this form.
pub fn thaw_at(path: &std::path::Path) -> Result<Option<FreezeState>> {
    if !path.exists() {
        return Ok(None);
    }
    let prior = current_state_at(path).ok().flatten();
    std::fs::remove_file(path)
        .with_context(|| format!("removing freeze lock at {}", path.display()))?;
    Ok(prior)
}

/// Write `content` to `path` atomically: write to a sibling tempfile,
/// fsync, then `rename` over the target. A reader who opens `path`
/// either sees the full new content or the previous content; never a
/// half-written file. On Unix the file mode is forced to 0600 because
/// the reason text may name a compromised user / system.
fn write_atomic(path: &std::path::Path, content: &str) -> Result<()> {
    path.parent()
        .context("freeze lock path has no parent — refusing to write to root")?;
    // 0600 from the first byte, fsync, durable rename (#268, #376). The
    // freeze lock above all: a rename that does not survive a power loss
    // means the kill-switch is off after the reboot, while the operator was
    // told the fleet was frozen.
    crate::util::durable::write_private_atomic(path, content.as_bytes())
        .with_context(|| format!("writing freeze lock {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    /// #252 — a lock file that exists but cannot be parsed is UNKNOWN
    /// state, and a kill-switch must treat unknown as stopped. Before
    /// v0.13.4 this returned `Ok(())`, so a torn or truncated lock
    /// silently disarmed the control.
    #[test]
    fn unreadable_lock_refuses_the_operation() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("freeze.lock");
        std::fs::write(&path, b"\xff\xfe not toml at all \x00").expect("write garbage");
        let err = super::check_not_frozen_at(&path)
            .expect_err("a corrupt lock must refuse, not pass through");
        let refusal = err
            .downcast_ref::<super::FreezeRefusal>()
            .expect("must surface as a typed FreezeRefusal (exit code 8)");
        assert!(
            refusal.reason.contains("could not be read or parsed"),
            "the refusal must tell the operator why: {}",
            refusal.reason
        );
    }

    /// The distinction that matters: absent still means not frozen.
    #[test]
    fn absent_lock_still_passes() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("does-not-exist.lock");
        super::check_not_frozen_at(&path).expect("an absent lock means not frozen");
    }

    use super::*;

    /// Each test gets its own private temp directory + lock file
    /// path. Uses the explicit-path variants of every function so
    /// no process-global state (env vars) is touched — safe to run
    /// in parallel with every other test.
    fn temp_path() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("freeze.lock");
        (dir, path)
    }

    #[test]
    fn current_state_returns_none_when_lock_absent() {
        let (_dir, p) = temp_path();
        assert!(current_state_at(&p).unwrap().is_none());
    }

    #[test]
    fn freeze_then_current_state_round_trips() {
        let (_dir, p) = temp_path();
        let written = freeze_at(&p, "ransomware indicator on pve-1", Some(3600)).unwrap();
        let read = current_state_at(&p).unwrap().unwrap();
        assert_eq!(read.reason, "ransomware indicator on pve-1");
        assert_eq!(read.ttl_secs, Some(3600));
        assert_eq!(read.frozen_at, written.frozen_at);
    }

    #[test]
    fn freeze_refuses_empty_reason() {
        let (_dir, p) = temp_path();
        assert!(freeze_at(&p, "", Some(60)).is_err());
        assert!(freeze_at(&p, "   ", Some(60)).is_err());
    }

    #[test]
    fn thaw_removes_the_lock() {
        let (_dir, p) = temp_path();
        freeze_at(&p, "test", None).unwrap();
        assert!(p.exists());
        let removed = thaw_at(&p).unwrap();
        assert!(removed.is_some(), "thaw should return the prior state");
        assert!(!p.exists(), "lock file should be gone after thaw");
    }

    #[test]
    fn thaw_is_idempotent_when_no_freeze_active() {
        let (_dir, p) = temp_path();
        let r = thaw_at(&p).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn ttl_expired_lock_reads_as_thawed() {
        let (_dir, p) = temp_path();
        // Hand-craft an expired state — frozen 2 hours ago, TTL 1 hour.
        let expired = FreezeState {
            reason: "old".into(),
            operator: "test@host".into(),
            frozen_at: now_secs().saturating_sub(7200),
            ttl_secs: Some(3600),
            profile: None,
        };
        std::fs::write(&p, toml::to_string_pretty(&expired).unwrap()).unwrap();
        assert!(current_state_at(&p).unwrap().is_none());
    }

    #[test]
    fn ttl_active_lock_still_shows_frozen() {
        let (_dir, p) = temp_path();
        freeze_at(&p, "active", Some(3600)).unwrap();
        assert!(current_state_at(&p).unwrap().is_some());
    }

    #[test]
    fn check_not_frozen_returns_typed_refusal_when_active() {
        let (_dir, p) = temp_path();
        freeze_at(&p, "locked", None).unwrap();
        let err = check_not_frozen_at(&p).unwrap_err();
        assert!(
            err.downcast_ref::<FreezeRefusal>().is_some(),
            "expected FreezeRefusal, got: {err:#}"
        );
    }

    #[test]
    fn check_not_frozen_passes_when_no_lock() {
        let (_dir, p) = temp_path();
        assert!(check_not_frozen_at(&p).is_ok());
    }

    #[test]
    fn is_active_at_handles_no_ttl_as_indefinite() {
        let s = FreezeState {
            reason: "x".into(),
            operator: "test@host".into(),
            frozen_at: 100,
            ttl_secs: None,
            profile: None,
        };
        assert!(s.is_active_at(0));
        assert!(s.is_active_at(u64::MAX));
    }

    #[test]
    fn is_active_at_respects_ttl_boundary() {
        let s = FreezeState {
            reason: "x".into(),
            operator: "test@host".into(),
            frozen_at: 100,
            ttl_secs: Some(50),
            profile: None,
        };
        assert!(s.is_active_at(149)); // before expiry
        assert!(!s.is_active_at(150)); // exactly at expiry (frozen_at + ttl = 150)
        assert!(!s.is_active_at(200)); // long after
    }

    // ── Per-profile scope ──────────────────────────────────────────

    #[test]
    fn freeze_for_stamps_the_profile_into_the_state() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("freeze.prod.lock");
        let st = write_freeze_at(&p, Some("prod"), "rotating prod token", Some(3600)).unwrap();
        assert_eq!(st.profile.as_deref(), Some("prod"));
        let read = current_state_at(&p).unwrap().unwrap();
        assert_eq!(read.profile.as_deref(), Some("prod"));
    }

    #[test]
    fn global_freeze_writes_no_profile_field() {
        // Back-compat: a global freeze serialises identically to pre-feature
        // locks (no `profile` key), so old readers stay happy.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("freeze.lock");
        freeze_at(&p, "fleet-wide", None).unwrap();
        let toml = std::fs::read_to_string(&p).unwrap();
        assert!(
            !toml.contains("profile"),
            "global lock must omit profile: {toml}"
        );
    }

    #[test]
    fn per_profile_freeze_does_not_block_other_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let global = dir.path().join("freeze.lock"); // no global freeze
        let prof_a = dir.path().join("freeze.a.lock");
        let prof_b = dir.path().join("freeze.b.lock");
        write_freeze_at(&prof_a, Some("a"), "incident on A", None).unwrap();
        // A is blocked …
        assert!(check_not_frozen_paths(&global, Some(&prof_a)).is_err());
        // … but B is untouched (only global + B's own lock are consulted).
        assert!(check_not_frozen_paths(&global, Some(&prof_b)).is_ok());
    }

    #[test]
    fn global_freeze_blocks_every_profile_and_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let global = dir.path().join("freeze.lock");
        let prof = dir.path().join("freeze.x.lock"); // x not frozen on its own
        freeze_at(&global, "fleet-wide lockdown", None).unwrap();
        assert!(check_not_frozen_paths(&global, Some(&prof)).is_err());
        assert!(check_not_frozen_paths(&global, None).is_err()); // flat/default client
    }

    #[test]
    fn refusal_scope_label_distinguishes_global_and_profile() {
        let dir = tempfile::tempdir().unwrap();
        let g = dir.path().join("freeze.lock");
        freeze_at(&g, "x", None).unwrap();
        let e = check_not_frozen_at(&g).unwrap_err();
        assert_eq!(
            e.downcast_ref::<FreezeRefusal>().unwrap().scope,
            "the fleet"
        );

        let p = dir.path().join("freeze.prod.lock");
        write_freeze_at(&p, Some("prod"), "x", None).unwrap();
        let e2 = check_not_frozen_at(&p).unwrap_err();
        assert_eq!(
            e2.downcast_ref::<FreezeRefusal>().unwrap().scope,
            "profile 'prod'"
        );
    }

    #[test]
    fn sanitize_profile_folds_unsafe_chars() {
        assert_eq!(sanitize_profile("prod"), "prod");
        assert_eq!(sanitize_profile("dc-1_west"), "dc-1_west");
        assert_eq!(sanitize_profile("a/b c"), "a_b_c");
        assert_eq!(sanitize_profile(""), "_");
    }

    #[test]
    fn freeze_path_for_filenames() {
        let fname = |p: PathBuf| p.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(fname(freeze_path_for(None)), "freeze.lock");
        assert_eq!(fname(freeze_path_for(Some("prod"))), "freeze.prod.lock");
        assert_eq!(fname(freeze_path_for(Some("a/b"))), "freeze.a_b.lock");
        // None resolves to the same path the legacy global accessor returns.
        assert_eq!(freeze_path_for(None), freeze_path());
    }

    #[test]
    fn list_active_in_reports_global_and_profiles_sorted() {
        let dir = tempfile::tempdir().unwrap();
        freeze_at(&dir.path().join("freeze.lock"), "fleet", None).unwrap();
        write_freeze_at(
            &dir.path().join("freeze.beta.lock"),
            Some("beta"),
            "b",
            None,
        )
        .unwrap();
        write_freeze_at(
            &dir.path().join("freeze.alpha.lock"),
            Some("alpha"),
            "a",
            None,
        )
        .unwrap();
        // Expired per-profile lock — must be filtered out.
        let expired = FreezeState {
            reason: "old".into(),
            operator: "t@h".into(),
            frozen_at: now_secs().saturating_sub(7200),
            ttl_secs: Some(3600),
            profile: Some("gamma".into()),
        };
        std::fs::write(
            dir.path().join("freeze.gamma.lock"),
            toml::to_string_pretty(&expired).unwrap(),
        )
        .unwrap();
        // Atomic-write temp file — must be ignored (doesn't end in `.lock`).
        std::fs::write(dir.path().join("freeze.lock.tmp.999.1"), "garbage").unwrap();

        let scopes: Vec<Option<String>> = list_active_in(dir.path())
            .unwrap()
            .iter()
            .map(|s| s.profile.clone())
            .collect();
        assert_eq!(
            scopes,
            vec![None, Some("alpha".into()), Some("beta".into())]
        );
    }
}

#[cfg(test)]
mod operator_identity_tests {
    /// #476: uid 0 is `root` on every unix proxxx supports; starting
    /// from a 1-byte buffer forces the `ERANGE` growth path.
    #[cfg(unix)]
    #[test]
    fn a_passwd_lookup_grows_its_own_buffer() {
        assert_eq!(
            super::login_name_for_uid_with(0, 1).as_deref(),
            Some("root")
        );
        assert_eq!(super::login_name_for_uid(0).as_deref(), Some("root"));
    }

    /// #476: lookups from many threads at once agree with a single one.
    /// This cannot prove the absence of a data race; the source check
    /// below is what keeps the non-reentrant calls out.
    #[cfg(unix)]
    #[test]
    fn concurrent_lookups_agree() {
        let uid = super::real_uid();
        let expected = super::login_name_for_uid(uid);
        let handles: Vec<_> = (0..16)
            .map(|_| {
                std::thread::spawn(move || {
                    (0..200)
                        .map(|_| super::login_name_for_uid(uid))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for h in handles {
            for got in h.join().unwrap() {
                assert_eq!(got, expected);
            }
        }
    }

    /// #476: the passwd functions that return a pointer into a static
    /// buffer are not used anywhere in `src/`.
    #[test]
    fn no_non_reentrant_passwd_calls_in_src() {
        fn walk(dir: &std::path::Path, hits: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, hits);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    for (n, line) in text.lines().enumerate() {
                        let code = line.split("//").next().unwrap_or("");
                        for f in [
                            "getpwuid(",
                            "getpwnam(",
                            "getpwent(",
                            "getgrgid(",
                            "getgrnam(",
                        ] {
                            if code.contains(&format!("::{f}")) {
                                hits.push(format!("{}:{}: {f}", path.display(), n + 1));
                            }
                        }
                    }
                }
            }
        }
        let mut hits = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut hits,
        );
        assert!(
            hits.is_empty(),
            "non-reentrant passwd/group calls: {hits:?}"
        );
    }

    /// #256 — the audit actor must be anchored on the real uid, which
    /// the caller cannot set, rather than on `$USER`, which it can.
    ///
    /// This test does not mutate the environment (it is process-global
    /// and other tests in this binary run in parallel); it asserts the
    /// structural property instead: whatever `$USER` says, the label
    /// resolves from the passwd entry for our real uid, and a
    /// disagreement is marked rather than believed.
    /// Assertion messages here deliberately describe the SHAPE of the
    /// label rather than interpolating it. A uid is not a credential,
    /// but it is account-identifying, and `CodeQL`'s `rust/cleartext-logging`
    /// is right that a test failure should not be the thing that prints
    /// it into CI output. The structural description is what a reader
    /// debugging a failure actually needs.
    #[test]
    fn operator_label_is_anchored_on_the_real_uid() {
        let label = super::operator_label();
        assert!(
            label.contains('@'),
            "the label must carry a host component (got {} chars, no '@')",
            label.len()
        );
        let who = label.split('@').next().unwrap_or_default();
        assert!(!who.is_empty(), "the actor part must not be empty");

        // Either the resolved passwd name (agreeing with $USER), or an
        // explicit marker that the two disagreed / could not be resolved.
        let resolved = super::login_name_for_uid(super::real_uid());
        let claimed = std::env::var("USER").ok();
        match (resolved.as_deref(), claimed.as_deref()) {
            (Some(r), Some(c)) if r == c => assert_eq!(
                who, r,
                "when passwd and $USER agree the label must be that name verbatim"
            ),
            (Some(_), Some(_)) => assert!(
                who.contains("uid:") && who.contains("claimed:"),
                "passwd and $USER disagree, so the label must carry both the uid \
                 and the unverified claim — it carried neither marker"
            ),
            _ => assert!(
                who.contains("uid:") || Some(who) == resolved.as_deref(),
                "with no passwd entry or no $USER, the label must fall back to the \
                 uid form or to the resolved name"
            ),
        }
    }

    /// The uid is kernel state, checked against a second kernel source: the
    /// owner of a file this process creates. (`#297`: the previous version
    /// compared `real_uid()` with itself and could not fail.)
    #[cfg(unix)]
    #[test]
    fn real_uid_owns_the_files_this_process_creates() {
        use std::os::unix::fs::MetadataExt as _;
        let file = tempfile::NamedTempFile::new().expect("tempfile");
        let owner = file.as_file().metadata().expect("stat").uid();
        assert!(
            super::real_uid() == owner,
            "real_uid() must be the uid that owns a file this process creates"
        );
    }

    /// `#297`: a uid with no passwd entry resolves to no name.
    #[cfg(unix)]
    #[test]
    fn an_unknown_uid_has_no_login_name() {
        assert_eq!(super::login_name_for_uid(3_999_999_999), None);
        assert_eq!(super::login_name_for_uid_with(3_999_999_999, 1), None);
    }

    /// `#256`, `#297`: every combination of passwd name and `$USER` claim.
    /// Fake names and uids only, so a failure prints nothing real.
    #[test]
    fn the_operator_label_believes_the_passwd_name_and_marks_a_claim() {
        let cases = [
            (Some("alice"), Some("alice"), "alice@h"),
            (
                Some("alice"),
                Some("mallory"),
                "alice(uid:4242;claimed:mallory)@h",
            ),
            (Some("alice"), None, "alice@h"),
            (None, Some("mallory"), "uid:4242(claimed:mallory)@h"),
            (None, None, "uid:4242@h"),
        ];
        for (resolved, claimed, want) in cases {
            assert_eq!(
                super::compose_operator_id(resolved, claimed, 4242, "h"),
                want,
                "{resolved:?} {claimed:?}"
            );
        }
    }
}
