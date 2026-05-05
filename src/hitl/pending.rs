//! Pending-approvals registry for the HITL daemon.
//!
//! Phase 5.13 — defense against callback replay. Without this, the
//! daemon at [`crate::cli::hitl_serve`] would execute every well-formed
//! `approve:action:vmid` callback it received, regardless of whether
//! that callback represents a fresh approval or a stale one being
//! redelivered.
//!
//! Threat model:
//! - **In-session replay**: Telegram redelivers an update due to a
//!   network hiccup before the daemon advances `offset`. Without dedup,
//!   the same op fires twice.
//! - **Post-restart redelivery**: the daemon crashes between executing
//!   an approval and advancing `offset`. On restart, `offset = 0` and
//!   Telegram re-sends the last 24 h of unacknowledged updates. Without
//!   dedup, every approval in that window re-fires.
//! - **Token-capture forgery**: an attacker who has read the bot token
//!   from disk can forge a callback by calling the Telegram API
//!   directly. Stateless dedup-by-txn-id means each forged callback
//!   only fires once — better than infinite replay, but fundamentally
//!   the bot token IS the credential. Real defense is keychain storage
//!   + rotation (see `TelegramConfig::resolve_bot_token`).
//!
//! Scope honesty: this is **session-local** dedup. A daemon restart
//! with `--reset-offset` would re-execute. A multi-replica daemon
//! deployment would deduplicate per-replica only — operators running
//! HA daemons must coordinate offset externally (we don't ship that).
//! The Telegram offset advancement (`offset = max(offset, id+1)`) is
//! the cross-restart line of defense.

use std::collections::HashSet;
use std::sync::Mutex;

/// Reason a callback was rejected by the dedup gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayError {
    /// This `txn_id` was already consumed in this daemon session.
    AlreadyConsumed,
}

/// In-memory dedup of approved transaction IDs.
///
/// Each `txn_id` may be consumed at most once per session. Subsequent
/// `consume()` calls for the same id return `Err(ReplayError::AlreadyConsumed)`
/// and the caller is expected to refuse execution + answer the callback
/// with a "stale approval" message.
///
/// The `HashSet` has no upper bound — under sustained legitimate load
/// (~100 ops/day in a homelab, ~1000s in a fleet) memory growth is
/// trivial. For a long-running daemon this could be capped via LRU, but
/// the `txn_id` strings are ~40 bytes so 100k entries ≈ 4 MiB — well
/// below any reasonable concern.
pub struct PendingApprovals {
    consumed: Mutex<HashSet<String>>,
}

impl Default for PendingApprovals {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingApprovals {
    #[must_use]
    pub fn new() -> Self {
        Self {
            consumed: Mutex::new(HashSet::new()),
        }
    }

    /// Atomically check-and-mark a `txn_id`.
    ///
    /// Returns `Ok(())` on first call (the caller may proceed to
    /// execute the approved action), `Err(ReplayError::AlreadyConsumed)`
    /// on subsequent calls (the caller must refuse execution).
    ///
    /// The lock is held across the `contains` + `insert` to make the
    /// operation linearizable — without the atomicity guarantee, two
    /// concurrent callbacks for the same `txn_id` could both pass the
    /// check.
    ///
    /// # Errors
    /// `ReplayError::AlreadyConsumed` if `txn_id` was previously
    /// consumed in this session.
    pub fn consume(&self, txn_id: &str) -> Result<(), ReplayError> {
        let mut guard = self
            .consumed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.contains(txn_id) {
            return Err(ReplayError::AlreadyConsumed);
        }
        guard.insert(txn_id.to_string());
        Ok(())
    }

    /// How many txns have been consumed this session.
    ///
    /// Used by tests to assert "after replay attempt, exactly 1 entry"
    /// — and exposed publicly (rather than `#[cfg(test)]`) so the
    /// integration tests in `tests/hitl_e2e.rs` can read it. In
    /// production it's also useful as a daemon-health metric (active
    /// approvals processed since startup).
    #[must_use]
    pub fn consumed_count(&self) -> usize {
        self.consumed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_consume_succeeds() {
        let p = PendingApprovals::new();
        assert!(p.consume("txn-abc").is_ok());
        assert_eq!(p.consumed_count(), 1);
    }

    #[test]
    fn second_consume_returns_replay() {
        let p = PendingApprovals::new();
        p.consume("txn-abc").expect("first consume");
        let err = p.consume("txn-abc").expect_err("second consume must fail");
        assert_eq!(err, ReplayError::AlreadyConsumed);
        // The HashSet is not double-inserted on replay.
        assert_eq!(p.consumed_count(), 1);
    }

    #[test]
    fn distinct_txns_are_independent() {
        let p = PendingApprovals::new();
        assert!(p.consume("txn-1").is_ok());
        assert!(p.consume("txn-2").is_ok());
        assert!(p.consume("txn-3").is_ok());
        assert_eq!(p.consumed_count(), 3);
        // But each is still single-use.
        assert!(p.consume("txn-2").is_err());
    }

    #[test]
    fn poisoned_lock_recovers() {
        // If another thread panicked mid-insert and poisoned the lock,
        // we still want the daemon to keep working — better to allow
        // a possible-replay than to deadlock the entire HITL channel.
        // PoisonError::into_inner gives us the data back regardless.
        let p = std::sync::Arc::new(PendingApprovals::new());
        let p2 = std::sync::Arc::clone(&p);
        let t = std::thread::spawn(move || {
            let _g = p2.consumed.lock().expect("test lock");
            panic!("intentional");
        });
        let _ = t.join();
        // After the panic, the lock is poisoned — but consume() must
        // still complete.
        assert!(p.consume("post-poison").is_ok());
    }
}
