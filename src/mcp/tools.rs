// MCP Tool Definitions — COMPILE-TIME CONST
//
// SECURITY INVARIANT: This is the ONLY place tools are defined.
// No dynamic registration. No config-driven schemas. No runtime mutation.
// `const TOOLS` is baked into the binary. Period.

use serde::Serialize;

// ── Closed Action Enum ──────────────────────────────────
// No `Other(String)`. No dynamic variants. Exhaustive match enforced by compiler.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolAction {
    // ── Guest lifecycle ──────────────────────────────────
    ListGuests,
    GetGuestStatus,
    StartGuest,
    StopGuest,
    RestartGuest,
    SuspendGuest,
    ResumeGuest,
    DeleteGuest,
    CloneGuest,
    MigrateGuest,
    // ── Snapshots ────────────────────────────────────────
    CreateSnapshot,
    ListSnapshots,
    DeleteSnapshot,
    // ── Nodes ────────────────────────────────────────────
    ListNodes,
    GetNodeResources,
    GetNodeStatus,
    // ── Cluster ──────────────────────────────────────────
    GetClusterStatus,
    ListTasks,
    GetTaskLog,
    // ── Storage ──────────────────────────────────────────
    GetStoragePools,
    // ── Backup / Replication ─────────────────────────────
    ListBackupJobs,
    GetReplicationStatus,
    // ── Guest creation ───────────────────────────────────
    CreateGuest,
}

// ── Const Tool Definitions ──────────────────────────────

#[derive(Debug)]
pub struct ToolDef {
    pub name: &'static str,
    pub description: &'static str,
    pub params: &'static [ParamDef],
    pub action: ToolAction,
    pub destructive: bool,
    /// Per-tool execution-budget in seconds. Wrapped around
    /// `handle_tool_call` in the server's request loop via
    /// `tokio::time::timeout`. On expiry the tool returns a JSON-RPC
    /// error code `-32001` (server-defined) with the budget in the
    /// message — the request loop continues, no server crash.
    ///
    /// Bounds the `DoS` surface for misbehaving / hostile LLM agents:
    /// without this, a single tool call that hangs (network stall,
    /// upstream PVE wedged on a lock, etc.) would block the next
    /// JSON-RPC request indefinitely. JSON-RPC over stdio serializes
    /// requests, so one slow tool blocks ALL subsequent traffic.
    ///
    /// `DEFAULT_TIMEOUT_SECS` (30) is comfortably above any
    /// PVE-API-side return time on a healthy cluster — the typed
    /// `ApiError::StorageHang` already surfaces 595s much earlier
    /// for the read paths. Tools that legitimately do longer work
    /// (snapshot, delete) get explicit higher budgets below.
    pub timeout_secs: u64,
}

/// Default per-tool budget. Read-only tools sit comfortably under
/// this. Per-tool overrides go in the registry below.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;

#[derive(Debug)]
pub struct ParamDef {
    pub name: &'static str,
    pub description: &'static str,
    pub param_type: ParamType,
    pub required: bool,
}

#[derive(Debug)]
pub enum ParamType {
    Str,
    Int,
    Bool,
}

/// THE REGISTRY. Immutable. Baked into the binary. Cannot be extended at runtime.
pub const TOOLS: &[ToolDef] = &[
    ToolDef {
        name: "list_nodes",
        description: "List all Proxmox nodes with status and resource usage",
        params: &[ParamDef {
            name: "profile",
            description: "Connection profile name",
            param_type: ParamType::Str,
            required: false,
        }],
        action: ToolAction::ListNodes,
        destructive: false,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
    },
    ToolDef {
        name: "list_guests",
        description: "List all VMs and LXC containers",
        params: &[
            ParamDef {
                name: "profile",
                description: "Connection profile",
                param_type: ParamType::Str,
                required: false,
            },
            ParamDef {
                name: "node",
                description: "Filter by node name",
                param_type: ParamType::Str,
                required: false,
            },
        ],
        action: ToolAction::ListGuests,
        destructive: false,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
    },
    ToolDef {
        name: "get_guest_status",
        description: "Get detailed status of a specific VM or container",
        params: &[ParamDef {
            name: "guest_id",
            description: "Guest VMID (100-999999)",
            param_type: ParamType::Int,
            required: true,
        }],
        action: ToolAction::GetGuestStatus,
        destructive: false,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
    },
    ToolDef {
        name: "start_guest",
        description: "Start a VM or LXC container",
        params: &[ParamDef {
            name: "guest_id",
            description: "Guest VMID (100-999999)",
            param_type: ParamType::Int,
            required: true,
        }],
        action: ToolAction::StartGuest,
        destructive: false,
        timeout_secs: 60,
    },
    ToolDef {
        name: "stop_guest",
        description: "Stop a VM or LXC container",
        params: &[
            ParamDef {
                name: "guest_id",
                description: "Guest VMID (100-999999)",
                param_type: ParamType::Int,
                required: true,
            },
            ParamDef {
                name: "force",
                description: "Force stop without graceful shutdown",
                param_type: ParamType::Bool,
                required: false,
            },
        ],
        action: ToolAction::StopGuest,
        destructive: true,
        timeout_secs: 60,
    },
    ToolDef {
        name: "restart_guest",
        description: "Restart a VM or LXC container",
        params: &[ParamDef {
            name: "guest_id",
            description: "Guest VMID (100-999999)",
            param_type: ParamType::Int,
            required: true,
        }],
        action: ToolAction::RestartGuest,
        destructive: true,
        timeout_secs: 60,
    },
    ToolDef {
        name: "delete_guest",
        description: "Permanently delete a VM or LXC container",
        params: &[ParamDef {
            name: "guest_id",
            description: "Guest VMID (100-999999)",
            param_type: ParamType::Int,
            required: true,
        }],
        action: ToolAction::DeleteGuest,
        destructive: true, // ALWAYS triggers HITL gate
        // 120s HITL response window + headroom for the actual delete +
        // task-log poll. Tighter than this risks a Telegram-approved
        // delete still timing out at the MCP layer.
        timeout_secs: 180,
    },
    ToolDef {
        name: "create_snapshot",
        description: "Create a snapshot of a VM or container",
        params: &[
            ParamDef {
                name: "guest_id",
                description: "Guest VMID",
                param_type: ParamType::Int,
                required: true,
            },
            ParamDef {
                name: "name",
                description: "Snapshot name",
                param_type: ParamType::Str,
                required: true,
            },
        ],
        action: ToolAction::CreateSnapshot,
        destructive: false,
        timeout_secs: 120,
    },
    ToolDef {
        name: "delete_snapshot",
        description: "Delete a snapshot",
        params: &[
            ParamDef {
                name: "guest_id",
                description: "Guest VMID",
                param_type: ParamType::Int,
                required: true,
            },
            ParamDef {
                name: "name",
                description: "Snapshot name",
                param_type: ParamType::Str,
                required: true,
            },
        ],
        action: ToolAction::DeleteSnapshot,
        destructive: true,
        timeout_secs: 120,
    },
    ToolDef {
        name: "get_storage_pools",
        description: "List storage pools on a node",
        params: &[ParamDef {
            name: "node",
            description: "Node name",
            param_type: ParamType::Str,
            required: true,
        }],
        action: ToolAction::GetStoragePools,
        destructive: false,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
    },
    // ── Previously in ToolAction but not registered ──────
    ToolDef {
        name: "list_snapshots",
        description: "List all snapshots for a VM or container",
        params: &[ParamDef {
            name: "guest_id",
            description: "Guest VMID",
            param_type: ParamType::Int,
            required: true,
        }],
        action: ToolAction::ListSnapshots,
        destructive: false,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
    },
    ToolDef {
        name: "get_task_log",
        description: "Retrieve the log output of a Proxmox task by UPID",
        params: &[
            ParamDef {
                name: "node",
                description: "Node name where the task ran",
                param_type: ParamType::Str,
                required: true,
            },
            ParamDef {
                name: "upid",
                description: "Task UPID string",
                param_type: ParamType::Str,
                required: true,
            },
        ],
        action: ToolAction::GetTaskLog,
        destructive: false,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
    },
    ToolDef {
        name: "get_node_resources",
        description: "Get CPU, memory and status detail for a specific node",
        params: &[ParamDef {
            name: "node",
            description: "Node name",
            param_type: ParamType::Str,
            required: true,
        }],
        action: ToolAction::GetNodeResources,
        destructive: false,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
    },
    // ── New tools ─────────────────────────────────────────
    ToolDef {
        name: "suspend_guest",
        description: "Suspend (pause) a running VM or container",
        params: &[ParamDef {
            name: "guest_id",
            description: "Guest VMID",
            param_type: ParamType::Int,
            required: true,
        }],
        action: ToolAction::SuspendGuest,
        destructive: false,
        timeout_secs: 60,
    },
    ToolDef {
        name: "resume_guest",
        description: "Resume a suspended VM or container",
        params: &[ParamDef {
            name: "guest_id",
            description: "Guest VMID",
            param_type: ParamType::Int,
            required: true,
        }],
        action: ToolAction::ResumeGuest,
        destructive: false,
        timeout_secs: 60,
    },
    ToolDef {
        name: "clone_guest",
        description: "Clone a VM or container to a new ID",
        params: &[
            ParamDef {
                name: "guest_id",
                description: "Source VMID to clone",
                param_type: ParamType::Int,
                required: true,
            },
            ParamDef {
                name: "newid",
                description: "New VMID (0 = auto-assign next free)",
                param_type: ParamType::Int,
                required: false,
            },
            ParamDef {
                name: "name",
                description: "Name for the new guest",
                param_type: ParamType::Str,
                required: false,
            },
            ParamDef {
                name: "full",
                description: "Full clone (true) vs linked clone (false, default)",
                param_type: ParamType::Bool,
                required: false,
            },
        ],
        action: ToolAction::CloneGuest,
        destructive: true,
        timeout_secs: 180,
    },
    ToolDef {
        name: "migrate_guest",
        description: "Live-migrate a VM or container to another node",
        params: &[
            ParamDef {
                name: "guest_id",
                description: "Guest VMID",
                param_type: ParamType::Int,
                required: true,
            },
            ParamDef {
                name: "target_node",
                description: "Destination node name",
                param_type: ParamType::Str,
                required: true,
            },
            ParamDef {
                name: "online",
                description: "Live migration while guest is running (default true)",
                param_type: ParamType::Bool,
                required: false,
            },
        ],
        action: ToolAction::MigrateGuest,
        destructive: true,
        timeout_secs: 300,
    },
    ToolDef {
        name: "get_cluster_status",
        description: "Get cluster-wide status including quorum, nodes and services",
        params: &[],
        action: ToolAction::GetClusterStatus,
        destructive: false,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
    },
    ToolDef {
        name: "list_tasks",
        description: "List recent cluster tasks (running and completed)",
        params: &[ParamDef {
            name: "node",
            description: "Filter by node (optional, omit for cluster-wide)",
            param_type: ParamType::Str,
            required: false,
        }],
        action: ToolAction::ListTasks,
        destructive: false,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
    },
    ToolDef {
        name: "get_node_status",
        description: "Get detailed status of a node (CPU, memory, disk, uptime, kernel)",
        params: &[ParamDef {
            name: "node",
            description: "Node name",
            param_type: ParamType::Str,
            required: true,
        }],
        action: ToolAction::GetNodeStatus,
        destructive: false,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
    },
    ToolDef {
        name: "list_backup_jobs",
        description: "List all configured backup (vzdump) jobs",
        params: &[],
        action: ToolAction::ListBackupJobs,
        destructive: false,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
    },
    ToolDef {
        name: "get_replication_status",
        description: "Get replication job status for a node",
        params: &[ParamDef {
            name: "node",
            description: "Node name",
            param_type: ParamType::Str,
            required: true,
        }],
        action: ToolAction::GetReplicationStatus,
        destructive: false,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
    },
    ToolDef {
        name: "create_guest",
        description: "Create a new QEMU VM or LXC container. For QEMU: provide node, type=qemu, memory, cores, and optionally iso. For LXC: provide node, type=lxc, template (ostemplate volid), memory, cores. Returns vmid and task UPID.",
        params: &[
            ParamDef {
                name: "node",
                description: "Target Proxmox node name",
                param_type: ParamType::Str,
                required: true,
            },
            ParamDef {
                name: "type",
                description: "Guest type: qemu or lxc",
                param_type: ParamType::Str,
                required: true,
            },
            ParamDef {
                name: "vmid",
                description: "VMID to assign (auto-assigned from cluster nextid if omitted)",
                param_type: ParamType::Int,
                required: false,
            },
            ParamDef {
                name: "name",
                description: "VM name (QEMU) or hostname (LXC)",
                param_type: ParamType::Str,
                required: false,
            },
            ParamDef {
                name: "memory",
                description: "Memory in MiB (default: 1024 for QEMU, 512 for LXC)",
                param_type: ParamType::Int,
                required: false,
            },
            ParamDef {
                name: "cores",
                description: "CPU cores (default: 1)",
                param_type: ParamType::Int,
                required: false,
            },
            ParamDef {
                name: "storage",
                description: "Storage id for boot disk (e.g. local-lvm). If omitted, no disk is created.",
                param_type: ParamType::Str,
                required: false,
            },
            ParamDef {
                name: "disk_size",
                description: "Disk size in GiB (default: 32 QEMU, 8 LXC)",
                param_type: ParamType::Int,
                required: false,
            },
            ParamDef {
                name: "template",
                description: "LXC only: ostemplate volid (e.g. local:vztmpl/debian-12-standard_12.0-1_amd64.tar.zst)",
                param_type: ParamType::Str,
                required: false,
            },
            ParamDef {
                name: "iso",
                description: "QEMU only: ISO image volid for CD-ROM (e.g. local:iso/ubuntu-24.04.iso)",
                param_type: ParamType::Str,
                required: false,
            },
            ParamDef {
                name: "bridge",
                description: "Network bridge (default: vmbr0)",
                param_type: ParamType::Str,
                required: false,
            },
        ],
        action: ToolAction::CreateGuest,
        destructive: true,
        timeout_secs: 120,
    },
];

/// Serialize the entire tool registry to JSON (for `proxxx mcp tools --json`)
#[must_use]
pub fn registry_json() -> serde_json::Value {
    let tools: Vec<serde_json::Value> = TOOLS
        .iter()
        .map(|t| {
            let params: Vec<serde_json::Value> = t
                .params
                .iter()
                .map(|p| {
                    serde_json::json!({
                        "name": p.name,
                        "description": p.description,
                        "type": format!("{:?}", p.param_type).to_lowercase(),
                        "required": p.required,
                    })
                })
                .collect();

            serde_json::json!({
                "name": t.name,
                "description": t.description,
                "parameters": params,
                "destructive": t.destructive,
                "timeout_secs": t.timeout_secs,
            })
        })
        .collect();

    serde_json::json!({ "tools": tools })
}

/// Build the MCP `tools/list` response array.
///
/// Each entry follows the MCP 2025-03-26 spec shape:
/// ```json
/// {
///   "name": "...",
///   "description": "...",
///   "inputSchema": {
///     "type": "object",
///     "properties": { "param": { "type": "...", "description": "..." } },
///     "required": ["param"]
///   }
/// }
/// ```
/// The `destructive` and `timeout_secs` fields are included as
/// extensions (prefixed `x_proxxx_`) so spec-conforming clients
/// ignore them and proxxx-aware clients can surface the metadata.
#[must_use]
pub fn tools_list_schema() -> serde_json::Value {
    let tools: Vec<serde_json::Value> = TOOLS
        .iter()
        .map(|t| {
            let mut properties = serde_json::Map::new();
            let mut required: Vec<serde_json::Value> = Vec::new();
            for p in t.params {
                let json_type = match p.param_type {
                    ParamType::Str => "string",
                    ParamType::Int => "integer",
                    ParamType::Bool => "boolean",
                };
                properties.insert(
                    p.name.to_string(),
                    serde_json::json!({
                        "type": json_type,
                        "description": p.description,
                    }),
                );
                if p.required {
                    required.push(serde_json::Value::String(p.name.to_string()));
                }
            }
            let mut input_schema = serde_json::json!({
                "type": "object",
                "properties": properties,
            });
            if !required.is_empty() {
                input_schema["required"] = serde_json::Value::Array(required);
            }
            serde_json::json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": input_schema,
                "x_proxxx_destructive": t.destructive,
                "x_proxxx_timeout_secs": t.timeout_secs,
            })
        })
        .collect();
    serde_json::Value::Array(tools)
}

/// SHA-256 checksum of the serialized tool registry (for audit verification).
///
/// The returned string is 64 lowercase hex characters — a real SHA-256 digest
/// of the JSON serialization of `registry_json()`. Stable across builds for
/// the same registry contents; changes whenever a tool name, description,
/// parameter, or flag changes.
#[must_use]
pub fn registry_checksum() -> String {
    use sha2::{Digest, Sha256};
    let json = registry_json().to_string();
    let digest = Sha256::digest(json.as_bytes());
    format!("{digest:x}")
}
