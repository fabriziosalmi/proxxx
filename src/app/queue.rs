use crate::app::cache::{PersistedOp, PersistedOpStatus, PersistedQueueEntry};
use crate::app::{Action, AppState};

#[derive(Debug, Clone)]
pub struct QueuedOp {
    pub id: String,
    pub action: Box<Action>,
    pub description: String,
    pub diff: String,
    pub status: OpStatus,
    /// Unix seconds when this op was first enqueued. Used by the GC
    /// (SPOF 5.2) to age out completed ops. Set to 0 for entries
    /// loaded from older persistence formats — they look "ancient" to
    /// the GC and get evicted on the next sweep, which is fine.
    pub created_at_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpStatus {
    Pending,
    Running,
    Success,
    Error(String),
}

impl QueuedOp {
    #[must_use]
    pub fn new(action: Box<Action>, state: &AppState) -> Self {
        let (description, diff) = match &*action {
            Action::StartGuest { vmid } => {
                let name = state
                    .guests
                    .iter()
                    .find(|g| g.vmid == *vmid)
                    .map(|g| g.name.clone())
                    .unwrap_or_default();
                (
                    format!("Start Guest {vmid} ({name})"),
                    format!("{vmid} status: stopped -> running"),
                )
            }
            Action::StopGuest { vmid, force } => {
                let name = state
                    .guests
                    .iter()
                    .find(|g| g.vmid == *vmid)
                    .map(|g| g.name.clone())
                    .unwrap_or_default();
                let f = if *force { " (Force)" } else { "" };
                (
                    format!("Stop Guest {vmid} ({name}){f}"),
                    format!("{vmid} status: running -> stopped"),
                )
            }
            Action::RestartGuest { vmid } => {
                let name = state
                    .guests
                    .iter()
                    .find(|g| g.vmid == *vmid)
                    .map(|g| g.name.clone())
                    .unwrap_or_default();
                (
                    format!("Restart Guest {vmid} ({name})"),
                    format!("{vmid} status: running -> running"),
                )
            }
            Action::DeleteGuest { vmid } => {
                let name = state
                    .guests
                    .iter()
                    .find(|g| g.vmid == *vmid)
                    .map(|g| g.name.clone())
                    .unwrap_or_default();
                (
                    format!("Delete Guest {vmid} ({name})"),
                    format!("- {vmid} {name}"),
                )
            }
            Action::MigrateGuest { vmid, target_node } => {
                let name = state
                    .guests
                    .iter()
                    .find(|g| g.vmid == *vmid)
                    .map(|g| g.name.clone())
                    .unwrap_or_default();
                let source_node = state
                    .guests
                    .iter()
                    .find(|g| g.vmid == *vmid)
                    .map(|g| g.node.clone())
                    .unwrap_or_default();
                (
                    format!("Migrate Guest {vmid} ({name})"),
                    format!("{vmid} node: {source_node} -> {target_node}"),
                )
            }
            Action::MoveDisk {
                vmid,
                disk,
                target_storage,
                delete_source,
            } => {
                let name = state
                    .guests
                    .iter()
                    .find(|g| g.vmid == *vmid)
                    .map(|g| g.name.clone())
                    .unwrap_or_default();
                let suffix = if *delete_source {
                    " (delete source)"
                } else {
                    " (keep source as unused)"
                };
                (
                    format!("Move Disk {disk} of guest {vmid} ({name}) → {target_storage}{suffix}"),
                    format!(
                        "{vmid} disk {disk}: -> {target_storage}{}",
                        if *delete_source {
                            ", remove source"
                        } else {
                            ""
                        }
                    ),
                )
            }
            Action::ResizeDisk { vmid, disk, size } => {
                let name = state
                    .guests
                    .iter()
                    .find(|g| g.vmid == *vmid)
                    .map(|g| g.name.clone())
                    .unwrap_or_default();
                (
                    format!("Resize Disk {disk} of guest {vmid} ({name}) by/to {size}"),
                    format!("{vmid} disk {disk}: size {size} (Proxmox grow-only)"),
                )
            }
            _ => ("Unknown Action".to_string(), "No diff".to_string()),
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            id: now.as_micros().to_string(),
            action,
            description,
            diff,
            status: OpStatus::Pending,
            created_at_secs: now.as_secs(),
        }
    }

    #[must_use]
    pub fn export_script(&self, state: &AppState) -> String {
        let (node, vmid_str, action_str, pvesh_cmd) = match &*self.action {
            Action::StartGuest { vmid } => {
                let node = state
                    .guests
                    .iter()
                    .find(|g| g.vmid == *vmid)
                    .map_or_else(|| "pve".to_string(), |g| g.node.clone());
                (
                    node,
                    vmid.to_string(),
                    "start",
                    format!("pvesh create /nodes/{{node}}/qemu/{vmid}/status/start"),
                )
            }
            Action::StopGuest { vmid, force } => {
                let node = state
                    .guests
                    .iter()
                    .find(|g| g.vmid == *vmid)
                    .map_or_else(|| "pve".to_string(), |g| g.node.clone());
                let action = if *force { "stop" } else { "shutdown" };
                (
                    node,
                    vmid.to_string(),
                    action,
                    format!("pvesh create /nodes/{{node}}/qemu/{vmid}/status/{action}"),
                )
            }
            Action::RestartGuest { vmid } => {
                let node = state
                    .guests
                    .iter()
                    .find(|g| g.vmid == *vmid)
                    .map_or_else(|| "pve".to_string(), |g| g.node.clone());
                (
                    node,
                    vmid.to_string(),
                    "restart",
                    format!("pvesh create /nodes/{{node}}/qemu/{vmid}/status/reboot"),
                )
            }
            Action::DeleteGuest { vmid } => {
                let node = state
                    .guests
                    .iter()
                    .find(|g| g.vmid == *vmid)
                    .map_or_else(|| "pve".to_string(), |g| g.node.clone());
                (
                    node,
                    vmid.to_string(),
                    "delete",
                    format!("pvesh delete /nodes/{{node}}/qemu/{vmid}"),
                )
            }
            Action::MigrateGuest { vmid, target_node } => {
                let node = state
                    .guests
                    .iter()
                    .find(|g| g.vmid == *vmid)
                    .map_or_else(|| "pve".to_string(), |g| g.node.clone());
                (
                    node,
                    vmid.to_string(),
                    "migrate",
                    format!(
                        "pvesh create /nodes/{{node}}/qemu/{vmid}/migrate -target {target_node}"
                    ),
                )
            }
            _ => return "N/A".to_string(),
        };

        let pvesh_cmd = pvesh_cmd.replace("{node}", &node);

        if action_str == "migrate" {
            let target = match &*self.action {
                Action::MigrateGuest { target_node, .. } => target_node.clone(),
                _ => String::new(),
            };
            format!(
                "▶ CLI\nproxxx migrate {vmid_str} --target {target}\n\n▶ pvesh\n{pvesh_cmd}\n\n▶ curl\ncurl -k -X POST https://{node}:8006/api2/json/nodes/{node}/qemu/{vmid_str}/migrate -d target={target} \\\n  -H \"Authorization: PVEAPIToken=USER@realm!tokenid=secret\"\n\n▶ Ansible\n- name: Migrate guest\n  community.general.proxmox_kvm:\n    api_host: {node}\n    node: {node}\n    vmid: {vmid_str}\n    target_node: {target}"
            )
        } else {
            format!(
                "▶ CLI\nproxxx {action_str} {vmid_str}\n\n▶ pvesh\n{pvesh_cmd}\n\n▶ curl\ncurl -k -X POST https://{node}:8006/api2/json/nodes/{node}/qemu/{vmid_str}/status/{action_str} \\\n  -H \"Authorization: PVEAPIToken=USER@realm!tokenid=secret\"\n\n▶ Ansible\n- name: {action_str} guest\n  community.general.proxmox_kvm:\n    api_host: {node}\n    node: {node}\n    vmid: {vmid_str}\n    state: {action_str}"
            )
        }
    }

    /// Try to express this op in the persistable subset. Non-persistable
    /// ops (e.g. random other Actions enqueued for testing) return None
    /// and are skipped at save time — they're transient by definition.
    #[must_use]
    pub fn to_persisted(&self) -> Option<PersistedQueueEntry> {
        let op = match &*self.action {
            Action::StartGuest { vmid } => PersistedOp::StartGuest { vmid: *vmid },
            Action::StopGuest { vmid, force } => PersistedOp::StopGuest {
                vmid: *vmid,
                force: *force,
            },
            Action::RestartGuest { vmid } => PersistedOp::RestartGuest { vmid: *vmid },
            Action::DeleteGuest { vmid } => PersistedOp::DeleteGuest { vmid: *vmid },
            Action::MigrateGuest { vmid, target_node } => PersistedOp::MigrateGuest {
                vmid: *vmid,
                target_node: target_node.clone(),
            },
            Action::MoveDisk {
                vmid,
                disk,
                target_storage,
                delete_source,
            } => PersistedOp::MoveDisk {
                vmid: *vmid,
                disk: disk.clone(),
                target_storage: target_storage.clone(),
                delete_source: *delete_source,
            },
            Action::ResizeDisk { vmid, disk, size } => PersistedOp::ResizeDisk {
                vmid: *vmid,
                disk: disk.clone(),
                size: size.clone(),
            },
            _ => return None,
        };
        let status = match &self.status {
            OpStatus::Pending => PersistedOpStatus::Pending,
            OpStatus::Running => PersistedOpStatus::Running,
            OpStatus::Success => PersistedOpStatus::Success,
            OpStatus::Error(s) => PersistedOpStatus::Error(s.clone()),
        };
        Some(PersistedQueueEntry {
            id: self.id.clone(),
            description: self.description.clone(),
            diff: self.diff.clone(),
            status,
            op,
            created_at_secs: self.created_at_secs,
        })
    }

    /// Reconstruct from a persisted entry. Pure mapping — no state needed.
    #[must_use]
    pub fn from_persisted(entry: PersistedQueueEntry) -> Self {
        let action = match entry.op {
            PersistedOp::StartGuest { vmid } => Action::StartGuest { vmid },
            PersistedOp::StopGuest { vmid, force } => Action::StopGuest { vmid, force },
            PersistedOp::RestartGuest { vmid } => Action::RestartGuest { vmid },
            PersistedOp::DeleteGuest { vmid } => Action::DeleteGuest { vmid },
            PersistedOp::MigrateGuest { vmid, target_node } => {
                Action::MigrateGuest { vmid, target_node }
            }
            PersistedOp::MoveDisk {
                vmid,
                disk,
                target_storage,
                delete_source,
            } => Action::MoveDisk {
                vmid,
                disk,
                target_storage,
                delete_source,
            },
            PersistedOp::ResizeDisk { vmid, disk, size } => Action::ResizeDisk { vmid, disk, size },
        };
        let status = match entry.status {
            PersistedOpStatus::Pending => OpStatus::Pending,
            PersistedOpStatus::Running => OpStatus::Running,
            PersistedOpStatus::Success => OpStatus::Success,
            PersistedOpStatus::Error(s) => OpStatus::Error(s),
        };
        Self {
            id: entry.id,
            action: Box::new(action),
            description: entry.description,
            diff: entry.diff,
            status,
            created_at_secs: entry.created_at_secs,
        }
    }
}

// ── SPOF 5.2 (Category 5 audit) — queue garbage collection ──
//
// Without bounds, the op queue grows forever: completed ops never get
// evicted, errored ops accumulate every time a background dispatch
// fails, and the persisted SQLite table grows linearly with usage.
//
// Policy:
// - SUCCESS_TTL_SECS: drop Success entries older than this many seconds.
//   They served their purpose (showing "done" briefly) and are
//   confusing once stale.
// - ERROR_KEEP: keep at most this many Error entries. They're more
//   valuable than Success (forensic — what went wrong) so we keep more
//   and evict by age only when the count exceeds the cap.
// - HARD_CAP: ultimate safety net. If the queue still exceeds this
//   after the above passes, drop oldest entries regardless of status.
pub const SUCCESS_TTL_SECS: u64 = 300; // 5 min
pub const ERROR_KEEP: usize = 50;
pub const HARD_CAP: usize = 200;

/// Run the queue GC. `now_secs` is the current Unix time; passed in so
/// the function stays pure / deterministically testable.
///
/// Returns the number of entries evicted (for logging / tests).
pub fn garbage_collect(queue: &mut Vec<QueuedOp>, now_secs: u64) -> usize {
    let before = queue.len();

    // Pass 1: drop stale Success entries.
    queue.retain(|op| {
        if matches!(op.status, OpStatus::Success) {
            now_secs.saturating_sub(op.created_at_secs) < SUCCESS_TTL_SECS
        } else {
            true
        }
    });

    // Pass 2: cap Error entries to ERROR_KEEP, dropping oldest first.
    let error_count = queue
        .iter()
        .filter(|op| matches!(op.status, OpStatus::Error(_)))
        .count();
    if error_count > ERROR_KEEP {
        let mut to_drop = error_count - ERROR_KEEP;
        // Indices of Error entries, oldest first (queue is already
        // chronologically ordered by enqueue time).
        let victim_indices: Vec<usize> = queue
            .iter()
            .enumerate()
            .filter(|(_, op)| matches!(op.status, OpStatus::Error(_)))
            .map(|(i, _)| i)
            .take(to_drop)
            .collect();
        // Remove in reverse so earlier indices remain valid.
        for i in victim_indices.into_iter().rev() {
            queue.remove(i);
            to_drop = to_drop.saturating_sub(1);
            if to_drop == 0 {
                break;
            }
        }
    }

    // Pass 3: hard cap — if still over, drop oldest non-Pending.
    if queue.len() > HARD_CAP {
        let mut to_drop = queue.len() - HARD_CAP;
        let victim_indices: Vec<usize> = queue
            .iter()
            .enumerate()
            .filter(|(_, op)| !matches!(op.status, OpStatus::Pending))
            .map(|(i, _)| i)
            .take(to_drop)
            .collect();
        for i in victim_indices.into_iter().rev() {
            queue.remove(i);
            to_drop = to_drop.saturating_sub(1);
            if to_drop == 0 {
                break;
            }
        }
    }

    // Pass 4: absolute safety net — if STILL over (too many Pending),
    // drop oldest Pending too. Should be very rare.
    while queue.len() > HARD_CAP {
        queue.remove(0);
    }

    before - queue.len()
}

#[cfg(test)]
mod gc_tests {
    use super::*;

    fn op_with(id: &str, status: OpStatus, age_secs: u64, now: u64) -> QueuedOp {
        QueuedOp {
            id: id.into(),
            action: Box::new(Action::StartGuest { vmid: 1 }),
            description: id.into(),
            diff: String::new(),
            status,
            created_at_secs: now.saturating_sub(age_secs),
        }
    }

    #[test]
    fn drops_stale_success_entries() {
        let now = 10_000;
        let mut q = vec![
            op_with("fresh", OpStatus::Success, 30, now),
            op_with("stale", OpStatus::Success, SUCCESS_TTL_SECS + 60, now),
            op_with("pending", OpStatus::Pending, 0, now),
        ];
        let dropped = garbage_collect(&mut q, now);
        assert_eq!(dropped, 1);
        assert_eq!(q.len(), 2);
        assert!(q.iter().all(|op| op.id != "stale"));
    }

    #[test]
    fn caps_error_entries_at_keep_limit() {
        let now = 10_000;
        let mut q: Vec<QueuedOp> = (0..(ERROR_KEEP + 10))
            .map(|i| {
                op_with(
                    &format!("err{i}"),
                    OpStatus::Error(format!("e{i}")),
                    u64::try_from(i).unwrap_or(0),
                    now,
                )
            })
            .collect();
        let dropped = garbage_collect(&mut q, now);
        assert_eq!(dropped, 10);
        assert_eq!(q.len(), ERROR_KEEP);
        // Newest Errors retained; oldest removed.
        assert!(q.iter().all(|op| op.id.starts_with("err")));
    }

    #[test]
    fn hard_cap_truncates_runaway_queue() {
        let now = 10_000;
        // Mix of Pending (un-dropable in pass 3) and Success (dropable).
        // Way over HARD_CAP.
        let mut q: Vec<QueuedOp> = (0..(HARD_CAP + 100))
            .map(|i| {
                let status = if i % 3 == 0 {
                    OpStatus::Pending
                } else {
                    OpStatus::Success
                };
                op_with(&format!("op{i}"), status, 60, now)
            })
            .collect();
        garbage_collect(&mut q, now);
        assert!(
            q.len() <= HARD_CAP,
            "must respect HARD_CAP, got {}",
            q.len()
        );
    }

    #[test]
    fn pending_entries_are_preserved() {
        let now = 10_000;
        let mut q = vec![
            op_with("p1", OpStatus::Pending, 7200, now),
            op_with("p2", OpStatus::Pending, 0, now),
            op_with("ok", OpStatus::Success, SUCCESS_TTL_SECS + 1, now),
        ];
        garbage_collect(&mut q, now);
        // Both Pending must survive — only Success was stale.
        assert!(q.iter().any(|op| op.id == "p1"));
        assert!(q.iter().any(|op| op.id == "p2"));
        assert!(q.iter().all(|op| op.id != "ok"));
    }

    #[test]
    fn empty_queue_is_a_noop() {
        let mut q: Vec<QueuedOp> = Vec::new();
        let dropped = garbage_collect(&mut q, 10_000);
        assert_eq!(dropped, 0);
        assert!(q.is_empty());
    }
}
