use serde::{Deserialize, Serialize};

use super::deserialize_bool_from_int;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricServer {
    pub id: String,
    /// `influxdb` | `graphite`.
    #[serde(rename = "type")]
    pub server_type: String,
    pub server: String,
    pub port: u16,
    pub comment: String,
    /// 1 = exporter is paused (no metrics shipped).
    #[serde(deserialize_with = "deserialize_bool_from_int", default)]
    pub disable: bool,
    /// influxdb-specific: HTTP / UDP write API. `udp` | `http` | `https`.
    pub influxdbproto: String,
    /// graphite-specific: `tcp` | `udp`.
    pub proto: String,
    /// influxdb-specific: org name (cloud) or db name (OSS).
    pub organization: String,
    pub bucket: String,
    /// graphite-specific: top-level path prefix.
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReplicationJob {
    /// Job id, e.g. `"100-0"` (vmid + '-' + index).
    pub id: String,
    /// Job type — `"local"` for pve-zsync style, etc.
    #[serde(rename = "type", default)]
    pub job_type: String,
    /// Source node.
    #[serde(default)]
    pub source: String,
    /// Target node.
    #[serde(default)]
    pub target: String,
    /// Cron-like schedule, e.g. `"*/15"` for every 15 minutes.
    #[serde(default)]
    pub schedule: String,
    /// Disabled flag — Proxmox stores as `1`/`0` int.
    #[serde(default, deserialize_with = "deserialize_bool_from_int")]
    pub disable: bool,
    #[serde(default)]
    pub comment: String,
}

impl ReplicationJob {
    /// Extract the VMID from the job id (`"100-0"` → 100).
    #[must_use]
    pub fn vmid(&self) -> Option<u32> {
        self.id
            .split_once('-')
            .and_then(|(v, _)| v.parse::<u32>().ok())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ReplicationStatus {
    pub id: String,
    /// Last successful sync timestamp (Unix seconds). 0 if never ran.
    #[serde(default)]
    pub last_sync: u64,
    /// Duration of the last sync in seconds.
    #[serde(default)]
    pub duration: f64,
    /// Last reported error string. Empty if last run was OK.
    #[serde(default)]
    pub error: String,
    /// Consecutive failure count.
    #[serde(default)]
    pub fail_count: u32,
    /// Source node (often duplicated with the parent job).
    #[serde(default)]
    pub source: String,
    /// Target node.
    #[serde(default)]
    pub target: String,
}

impl ReplicationStatus {
    /// Recovery Point Objective lag in seconds — how stale is the
    /// replica? Returns `u64::MAX` if `last_sync` is 0 (never ran).
    /// `now` lets tests inject a deterministic clock.
    #[must_use]
    pub const fn rpo_secs(&self, now: u64) -> u64 {
        if self.last_sync == 0 {
            return u64::MAX;
        }
        now.saturating_sub(self.last_sync)
    }

    /// Health: green if recent + no errors, yellow if stale, red if
    /// failing. `expected_period_secs` is the schedule's period for
    /// staleness comparison (e.g. 900 for `*/15`).
    #[must_use]
    pub const fn health(&self, now: u64, expected_period_secs: u64) -> ReplicationHealth {
        if self.fail_count > 0 || !self.error.is_empty() {
            return ReplicationHealth::Failing;
        }
        let rpo = self.rpo_secs(now);
        // Yellow when RPO exceeds 2× the expected period — typical
        // "you missed one tick" threshold used in DR runbooks.
        if rpo > expected_period_secs.saturating_mul(2) {
            ReplicationHealth::Stale
        } else {
            ReplicationHealth::Healthy
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplicationHealth {
    Healthy,
    Stale,
    Failing,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replication_rpo_never_synced_is_stale() {
        let s = ReplicationStatus {
            id: "100-0".into(),
            last_sync: 0,
            ..Default::default()
        };
        assert_eq!(s.rpo_secs(1_700_000_000), u64::MAX);
        // Never-synced is Stale by current rule (rpo > 2× period
        // because rpo == u64::MAX). The UI should distinguish this
        // visually but the worst-case classification is appropriate
        // — a never-replicated job is exactly as useful for DR.
        assert_eq!(s.health(1_700_000_000, 900), ReplicationHealth::Stale);
    }

    #[test]
    fn replication_rpo_recent_synced() {
        let s = ReplicationStatus {
            id: "100-0".into(),
            last_sync: 1_700_000_000,
            ..Default::default()
        };
        assert_eq!(s.rpo_secs(1_700_000_300), 300);
        assert_eq!(s.health(1_700_000_300, 900), ReplicationHealth::Healthy);
    }

    #[test]
    fn replication_health_stale_after_2x_period() {
        let s = ReplicationStatus {
            id: "100-0".into(),
            last_sync: 1_700_000_000,
            ..Default::default()
        };
        // Period = 15 min (900s). 2× = 1800. 1801s elapsed → Stale.
        assert_eq!(s.health(1_700_001_801, 900), ReplicationHealth::Stale);
    }

    #[test]
    fn replication_health_failing_when_error_present() {
        let s = ReplicationStatus {
            id: "100-0".into(),
            last_sync: 1_700_000_000,
            error: "ssh: connect: Network is unreachable".into(),
            fail_count: 0,
            ..Default::default()
        };
        // Even if RPO is fresh, presence of error → failing.
        assert_eq!(s.health(1_700_000_060, 900), ReplicationHealth::Failing);
    }

    #[test]
    fn replication_health_failing_when_fail_count_nonzero() {
        let s = ReplicationStatus {
            id: "100-0".into(),
            last_sync: 1_700_000_000,
            fail_count: 3,
            ..Default::default()
        };
        assert_eq!(s.health(1_700_000_030, 900), ReplicationHealth::Failing);
    }

    #[test]
    fn replication_job_extracts_vmid_from_id() {
        let j = ReplicationJob {
            id: "100-0".into(),
            job_type: "local".into(),
            source: "pve1".into(),
            target: "pve2".into(),
            schedule: "*/15".into(),
            disable: false,
            comment: String::new(),
        };
        assert_eq!(j.vmid(), Some(100));

        let bad = ReplicationJob {
            id: "garbage".into(),
            job_type: "local".into(),
            source: String::new(),
            target: String::new(),
            schedule: String::new(),
            disable: false,
            comment: String::new(),
        };
        assert_eq!(bad.vmid(), None);
    }
}
