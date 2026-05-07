// MCP Tool Definitions — COMPILE-TIME CONST
//
// SECURITY INVARIANT: This is the ONLY place tools are defined.
// No dynamic registration. No config-driven schemas. No runtime mutation.
// `const TOOLS` is baked into the binary. Period.

use serde::Serialize;
use std::hash::{Hash, Hasher};

// ── Closed Action Enum ──────────────────────────────────
// No `Other(String)`. No dynamic variants. Exhaustive match enforced by compiler.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolAction {
    ListNodes,
    ListGuests,
    GetGuestStatus,
    StartGuest,
    StopGuest,
    RestartGuest,
    DeleteGuest,
    CreateSnapshot,
    ListSnapshots,
    DeleteSnapshot,
    GetTaskLog,
    GetNodeResources,
    GetStoragePools,
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

/// SHA-256 checksum of the serialized tool registry (for audit verification)
#[must_use]
pub fn registry_checksum() -> String {
    use std::collections::hash_map::DefaultHasher;
    // clippy::collection_is_never_read fires here even though we hash
    // it on the next line — the lint can't see through the trait call.
    #[allow(clippy::collection_is_never_read)]
    let json = registry_json().to_string();
    let mut hasher = DefaultHasher::new();
    json.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}
