//! Alert dedup cache (feature #8).
//!
//! Suppresses re-firing the same `(rule_name, target)` pair within a
//! configurable window. In-memory; the alert daemon (`alerts watch`)
//! persists it to SQLite via `app::cache::{load,save}_alert_dedup`
//! after each tick so a routine restart (config reload, kernel update,
//! accidental SIGHUP) does not re-fire every active alert.

use std::collections::HashMap;

#[derive(Debug, Default)]
pub struct DedupCache {
    last_fired: HashMap<(String, String), u64>,
}

impl DedupCache {
    /// Should this event fire? Updates the cache as a side effect when
    /// we decide to fire. Returns `true` if the caller should send.
    pub fn allow(&mut self, rule: &str, target: &str, dedup_secs: u64, now: u64) -> bool {
        let key = (rule.to_string(), target.to_string());
        match self.last_fired.get(&key) {
            Some(&last) if now.saturating_sub(last) < dedup_secs => false,
            _ => {
                self.last_fired.insert(key, now);
                true
            }
        }
    }

    /// Drop entries older than `now - max_age_secs`. Cheap housekeeping
    /// the daemon calls periodically so the map doesn't grow unboundedly
    /// when targets churn (e.g. transient guests creating new sids).
    pub fn evict_older_than(&mut self, max_age_secs: u64, now: u64) {
        self.last_fired
            .retain(|_, last| now.saturating_sub(*last) < max_age_secs);
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.last_fired.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.last_fired.is_empty()
    }

    /// Snapshot the cache as `(rule, target, last_fired)` tuples. Used
    /// by the alert daemon to write the in-memory state to SQLite via
    /// `app::cache::save_alert_dedup` after each tick. Sorted output
    /// is not guaranteed — the SQL layer pins ordering on write.
    #[must_use]
    pub fn entries(&self) -> Vec<(String, String, u64)> {
        self.last_fired
            .iter()
            .map(|((r, t), ts)| (r.clone(), t.clone(), *ts))
            .collect()
    }

    /// Repopulate the cache from a previously-persisted snapshot.
    /// Used by the alert daemon at startup. Duplicate `(rule, target)`
    /// keys keep the last value seen — the SQL primary key prevents
    /// duplicates on disk so this is theoretical.
    pub fn from_entries<I>(it: I) -> Self
    where
        I: IntoIterator<Item = (String, String, u64)>,
    {
        let mut c = Self::default();
        for (r, t, ts) in it {
            c.last_fired.insert((r, t), ts);
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_fire_allowed() {
        let mut c = DedupCache::default();
        assert!(c.allow("r", "node:pve1", 300, 1000));
    }

    #[test]
    fn within_window_suppressed() {
        let mut c = DedupCache::default();
        assert!(c.allow("r", "t", 300, 1000));
        assert!(!c.allow("r", "t", 300, 1100), "100s < 300s window");
    }

    #[test]
    fn after_window_allowed_again() {
        let mut c = DedupCache::default();
        assert!(c.allow("r", "t", 300, 1000));
        assert!(c.allow("r", "t", 300, 1301), "301s >= 300s window");
    }

    #[test]
    fn distinct_targets_independent() {
        let mut c = DedupCache::default();
        assert!(c.allow("r", "node:pve1", 300, 1000));
        assert!(c.allow("r", "node:pve2", 300, 1000));
    }

    #[test]
    fn distinct_rules_independent() {
        let mut c = DedupCache::default();
        assert!(c.allow("r1", "t", 300, 1000));
        assert!(c.allow("r2", "t", 300, 1000));
    }

    #[test]
    fn evict_drops_old_entries() {
        let mut c = DedupCache::default();
        c.allow("r", "t1", 300, 1000);
        c.allow("r", "t2", 300, 2000);
        c.evict_older_than(500, 2100);
        assert_eq!(
            c.len(),
            1,
            "t1 dropped (1100s old > 500), t2 kept (100s old)"
        );
    }

    #[test]
    fn entries_round_trip_via_from_entries() {
        // Pin the persistence contract: snapshot → restore → behave
        // identically. A daemon restart reading state from disk MUST
        // suppress an event that the pre-restart daemon would have
        // suppressed.
        let mut original = DedupCache::default();
        original.allow("storage", "node:pve1", 300, 1000);
        original.allow("replication", "100-0", 600, 1500);

        let snapshot = original.entries();
        assert_eq!(snapshot.len(), 2);

        let restored = DedupCache::from_entries(snapshot);
        assert_eq!(restored.len(), 2);

        // Restored cache: a query within the original window must be
        // suppressed exactly as the original would have been.
        let mut restored = restored;
        assert!(
            !restored.allow("storage", "node:pve1", 300, 1100),
            "restored cache must suppress re-fire within window"
        );
        assert!(
            restored.allow("storage", "node:pve1", 300, 1500),
            "restored cache must allow re-fire after window"
        );
    }
}
