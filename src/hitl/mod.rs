// HITL — Human-in-the-Loop approval gates
// Zero new dependencies (reuses reqwest + tokio)

pub mod daemon;
pub mod hmac_key;
pub mod pending;
pub mod policy;
pub mod telegram;

/// Canonical set of destructive HITL action names shared between the TUI
/// (`src/tui/mod.rs`) and the CLI `--secure` gate (`src/cli/mod.rs`) (#338, #339, #399).
///
/// # Classification rule (#399)
///
/// An action is **destructive** if it is irreversible, removes data or a
/// resource, or interrupts availability.
///
/// - **Destructive** examples: any `delete` / `destroy` / `remove` / `revoke` /
///   `purge`, `stop` / `shutdown` / `reboot` / `suspend` of a guest or a node
///   (single or bulk), snapshot `rollback`, `template` conversion, disk `move` /
///   `resize`, `migrate`, `exec` (and non-interactive `ssh --cmd` / QGA file
///   writes), ACL or permission removal (`acl-unset`, `pool remove-members`),
///   network `apply` / `reload`, `state apply`, and `reconcile converge`
///   (convergence can delete resources under `--prune`).
/// - **Not destructive**: `start` / `resume`, `create` / `add` of a new object,
///   read-only commands, and reversible config edits that do not interrupt the
///   guest.
pub const DESTRUCTIVE_ACTIONS: &[&str] = &[
    // Shared with TUI SideEffect (`src/tui/mod.rs` `hitl_action`):
    "stop",
    "delete",
    "restart",
    "migrate",
    "exec",
    "move_disk",
    "resize_disk",
    // Guest / task / node availability & irreversible lifecycle (#399):
    "suspend",
    "task_stop",
    "backup_stop",
    "template",
    "snapshot_delete",
    "patch_apply",
    "node_stopall",
    "node_suspendall",
    "vm_raw_set",
    "vm_sendkey",
    "vm_unlink",
    "ct_raw_set",
    "qga_write",
    "ssh_cmd",
    // Resource / data / config deletion, revocation & disruptive updates (#399):
    "ha_group_delete",
    "backup_job_delete",
    "firewall_alias_update",
    "firewall_alias_delete",
    "firewall_group_delete",
    "firewall_ipset_add_cidr",
    "firewall_ipset_delete",
    "firewall_ipset_remove_cidr",
    "firewall_options_set",
    "guest_firewall_alias_update",
    "guest_firewall_alias_delete",
    "guest_firewall_options_set",
    "cluster_mapping_pci_delete",
    "cluster_mapping_usb_delete",
    "node_subscription_delete",
    "node_cert_delete",
    "pool_remove_members",
    "pool_delete",
    "metric_server_delete",
    "notification_endpoint_delete",
    "notification_matcher_delete",
    "storage_def_update",
    "storage_def_delete",
    "storage_delete",
    "pbs_restore",
    "acme_account_delete",
    "acme_plugin_delete",
    "corosync_node_add",
    "corosync_node_remove",
    "cluster_join",
    "qdevice_setup",
    "qdevice_update",
    "qdevice_delete",
    "user_update",
    "user_delete",
    "group_delete",
    "acl_unset",
    "access_password",
    "token_revoke",
    "token_bootstrap_rotate",
    "schedule_remove",
    // Declarative convergence (can delete resources under `--prune`, #399):
    "state_apply",
    "reconcile_converge",
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
