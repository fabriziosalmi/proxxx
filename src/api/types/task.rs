use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskLog {
    pub total: usize,
    pub data: Vec<TaskLogLine>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskLogLine {
    pub n: usize,
    pub t: String,
}

#[derive(Debug, Deserialize)]
pub struct ApiResponse<T> {
    pub data: T,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct EntityId {
    pub profile: String,
    pub vmid: u32,
}

impl std::fmt::Display for EntityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.profile, self.vmid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskInfo {
    pub upid: String,
    pub node: String,
    pub user: String,
    pub id: String,
    #[serde(rename = "type")]
    pub task_type: String,
    pub status: Option<String>,
    pub starttime: u64,
    pub endtime: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskStatus {
    pub upid: String,
    pub status: String,
    pub exitstatus: Option<String>,
    #[serde(rename = "type")]
    pub task_type: String,
    pub id: String,
    pub user: String,
    pub starttime: u64,
}

impl TaskStatus {
    /// True when PVE has finished running the task (status == "stopped").
    /// Polling can stop here; callers then check `is_success()` for
    /// the outcome.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.status == "stopped"
    }
    /// True only after `is_done() && exitstatus == Some("OK")`. Anything
    /// else — partial completion, error string, missing exitstatus —
    /// is a failure from the caller's perspective.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.is_done() && self.exitstatus.as_deref() == Some("OK")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiVersion {
    /// e.g. `"9.1.9"`.
    pub version: String,
    /// e.g. `"9.1"`.
    pub release: String,
    /// Build identifier (git revision short).
    pub repoid: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RrdImage {
    /// Server-side path (e.g. `/var/cache/pve-graphs/rrd-….png`).
    pub filename: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UrlMetadata {
    /// Bytes (parsed from Content-Length). 0 when unknown.
    pub size: u64,
    /// Filename derived from URL or Content-Disposition.
    pub filename: String,
    pub mimetype: String,
}

/// One time-bucketed sample of the PVE rrddata response. `time` is
/// epoch-seconds; every other field is `Option<f64>` because the
/// available metrics depend on the SOURCE (guest vs node vs storage).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RrdPoint {
    /// Bucket midpoint, Unix epoch seconds.
    pub time: u64,

    // Common — guest + node
    pub cpu: Option<f64>,
    pub maxcpu: Option<f64>,
    pub mem: Option<f64>,
    pub maxmem: Option<f64>,
    pub disk: Option<f64>,
    pub maxdisk: Option<f64>,
    pub diskread: Option<f64>,
    pub diskwrite: Option<f64>,
    pub netin: Option<f64>,
    pub netout: Option<f64>,

    // Node-only
    pub loadavg: Option<f64>,
    pub iowait: Option<f64>,
    pub memtotal: Option<f64>,
    pub memused: Option<f64>,
    pub memavailable: Option<f64>,
    pub swaptotal: Option<f64>,
    pub swapused: Option<f64>,
    pub roottotal: Option<f64>,
    pub rootused: Option<f64>,
    pub arcsize: Option<f64>,

    // Pressure stall info (PSI), Linux 5.2+. Both guest + node.
    pub pressurecpusome: Option<f64>,
    pub pressurecpufull: Option<f64>,
    pub pressurememorysome: Option<f64>,
    pub pressurememoryfull: Option<f64>,
    pub pressureiosome: Option<f64>,
    pub pressureiofull: Option<f64>,

    // QEMU-only
    pub memhost: Option<f64>,

    // Storage-only
    pub used: Option<f64>,
    pub total: Option<f64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RrdTimeframe {
    Hour,
    Day,
    Week,
    Month,
    Year,
}

impl RrdTimeframe {
    /// PVE wire form (lowercase, matches `?timeframe=` URL param).
    #[must_use]
    pub const fn as_pve_str(self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Week => "week",
            Self::Month => "month",
            Self::Year => "year",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RrdCf {
    Average,
    Max,
}

impl RrdCf {
    #[must_use]
    pub const fn as_pve_str(self) -> &'static str {
        match self {
            Self::Average => "AVERAGE",
            Self::Max => "MAX",
        }
    }
}
