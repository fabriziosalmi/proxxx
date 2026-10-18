// HITL — Human-in-the-Loop approval gates
// Zero new dependencies (reuses reqwest + tokio)

pub mod daemon;
pub mod hmac_key;
pub mod pending;
pub mod policy;
pub mod telegram;

/// Canonical set of destructive HITL action names shared between the TUI
/// (`src/tui/mod.rs`) and the CLI `--secure` gate (`src/cli/mod.rs`) (#338, #339).
pub const DESTRUCTIVE_ACTIONS: &[&str] = &[
    "stop",
    "delete",
    "restart",
    "migrate",
    "exec",
    "move_disk",
    "resize_disk",
];

/// Return `true` when `action` belongs to [`DESTRUCTIVE_ACTIONS`].
#[must_use]
pub fn is_destructive_action(action: &str) -> bool {
    DESTRUCTIVE_ACTIONS.contains(&action)
}

/// Refusal returned when a destructive CLI command is invoked under `--secure`
/// (#338). Carried via `anyhow` so `main.rs` downcasts it to exit code 8
/// ("mutation refused by a local lock", shared with `read_only` and
/// `incident freeze`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "--secure: {action} requires human approval, which the CLI does not implement yet; \
     run it from the TUI with --secure, or drop --secure"
)]
pub struct SecureModeRefusal {
    pub action: &'static str,
}

impl SecureModeRefusal {
    /// Process exit code — matches the "mutation refused by a local lock"
    /// family (`read_only` / `incident freeze`, exit code 8).
    pub const EXIT_CODE: i32 = 8;
}
