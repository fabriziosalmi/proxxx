#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
// Unit tests for the Elm Architecture reducer (app.rs)
// Tests the PURE state machine — zero I/O, zero async.

#[cfg(test)]
mod tests {
    use proxxx::app::*;

    fn fresh_state() -> AppState {
        let mut state = AppState::new();
        state.is_loading = false;
        state
    }

    fn state_with_nodes() -> AppState {
        use proxxx::api::types::*;
        let mut state = fresh_state();
        state.nodes = vec![
            Node {
                node: "pve1".into(),
                status: NodeStatus::Online,
                cpu: 2.0,
                maxcpu: 8,
                mem: 8_000_000_000,
                maxmem: 32_000_000_000,
                disk: 100_000_000_000,
                maxdisk: 500_000_000_000,
                uptime: 86400,
            },
            Node {
                node: "pve2".into(),
                status: NodeStatus::Online,
                cpu: 6.0,
                maxcpu: 8,
                mem: 28_000_000_000,
                maxmem: 64_000_000_000,
                disk: 200_000_000_000,
                maxdisk: 1_000_000_000_000,
                uptime: 172800,
            },
        ];
        state
    }

    fn state_with_guests() -> AppState {
        use proxxx::api::types::*;
        let mut state = state_with_nodes();
        state.guests = vec![
            Guest {
                vmid: 100,
                name: "web".into(),
                status: GuestStatus::Running,
                guest_type: GuestType::Qemu,
                node: "pve1".into(),
                cpu: 0.5,
                cpus: 2,
                mem: 2_000_000_000,
                maxmem: 4_000_000_000,
                disk: 10_000_000_000,
                maxdisk: 30_000_000_000,
                uptime: 86400,
                tags: "prod;web".into(),
                lock: String::new(),
                hastate: String::new(),
            },
            Guest {
                vmid: 101,
                name: "db".into(),
                status: GuestStatus::Stopped,
                guest_type: GuestType::Qemu,
                node: "pve1".into(),
                cpu: 0.0,
                cpus: 4,
                mem: 0,
                maxmem: 16_000_000_000,
                disk: 0,
                maxdisk: 100_000_000_000,
                uptime: 0,
                tags: "prod;database".into(),
                lock: String::new(),
                hastate: String::new(),
            },
            Guest {
                vmid: 200,
                name: "dev-box".into(),
                status: GuestStatus::Running,
                guest_type: GuestType::Lxc,
                node: "pve2".into(),
                cpu: 0.1,
                cpus: 2,
                mem: 500_000_000,
                maxmem: 2_000_000_000,
                disk: 5_000_000_000,
                maxdisk: 20_000_000_000,
                uptime: 3600,
                tags: "dev".into(),
                lock: String::new(),
                hastate: String::new(),
            },
        ];
        state
    }

    // ── Navigation Tests ────────────────────────────────

    // ── V27.1 + V27.4 (audit) — destructive-op gating ─────

    fn locked_guest(vmid: u32, lock_kind: &str) -> proxxx::api::types::Guest {
        proxxx::api::types::Guest {
            vmid,
            name: format!("locked-{vmid}"),
            status: proxxx::api::types::GuestStatus::Running,
            guest_type: proxxx::api::types::GuestType::Qemu,
            node: "pve1".into(),
            lock: lock_kind.into(),
            ..Default::default()
        }
    }

    fn ha_managed_guest(vmid: u32, ha_state: &str) -> proxxx::api::types::Guest {
        proxxx::api::types::Guest {
            vmid,
            name: format!("ha-{vmid}"),
            status: proxxx::api::types::GuestStatus::Running,
            guest_type: proxxx::api::types::GuestType::Qemu,
            node: "pve1".into(),
            hastate: ha_state.into(),
            ..Default::default()
        }
    }

    #[test]
    fn v27_4_stop_refused_when_lock_present_no_side_effect() {
        // Lock = backup means PVE will reject the stop with 500 VM
        // is locked. The reducer must surface a specific message
        // BEFORE making the API call.
        let mut state = fresh_state();
        state.guests = vec![locked_guest(500, "backup")];
        let effect = update(
            &mut state,
            Action::StopGuest {
                vmid: 500,
                force: false,
            },
        );
        assert!(effect.is_none(), "must NOT emit a SideEffect when locked");
        let err = state.error.as_deref().unwrap_or("");
        assert!(
            err.contains("locked") && err.contains("backup"),
            "error must name the lock kind, got: {err}"
        );
    }

    #[test]
    fn v27_1_stop_refused_when_ha_managed_no_side_effect() {
        // HA-managed guest at state=started — raw /status/stop
        // would be undone by the CRM in seconds. Refuse.
        let mut state = fresh_state();
        state.guests = vec![ha_managed_guest(600, "started")];
        let effect = update(
            &mut state,
            Action::StopGuest {
                vmid: 600,
                force: true,
            },
        );
        assert!(
            effect.is_none(),
            "must NOT emit SideEffect on HA-managed guest"
        );
        let err = state.error.as_deref().unwrap_or("");
        assert!(
            err.to_lowercase().contains("ha") && err.contains("/cluster/ha/resources"),
            "error must direct user to HA endpoint, got: {err}"
        );
    }

    #[test]
    fn v27_4_delete_refused_when_lock_present() {
        let mut state = fresh_state();
        state.guests = vec![locked_guest(700, "snapshot")];
        let effect = update(&mut state, Action::DeleteGuest { vmid: 700 });
        assert!(effect.is_none());
        let err = state.error.as_deref().unwrap_or("");
        assert!(
            err.contains("locked") && err.contains("snapshot"),
            "got: {err}"
        );
    }

    #[test]
    fn v27_4_snapshot_refused_when_lock_present() {
        let mut state = fresh_state();
        state.guests = vec![locked_guest(800, "clone")];
        let effect = update(
            &mut state,
            Action::CreateSnapshot {
                vmid: 800,
                name: "snap".into(),
            },
        );
        assert!(effect.is_none());
        let err = state.error.as_deref().unwrap_or("");
        assert!(
            err.contains("locked") && err.contains("clone"),
            "got: {err}"
        );
    }

    #[test]
    fn v27_4_migrate_refused_when_lock_present_but_ha_allowed() {
        // HA-managed guests CAN be migrated (CRM coordinates it),
        // but locks still block. Verify both branches.
        let mut state = fresh_state();
        state.guests = vec![ha_managed_guest(900, "started")];
        let effect = update(
            &mut state,
            Action::MigrateGuest {
                vmid: 900,
                target_node: "pve2".into(),
            },
        );
        assert!(
            effect.is_some(),
            "HA-managed migration is allowed (CRM coordinates) — must emit SideEffect"
        );

        let mut state2 = fresh_state();
        state2.guests = vec![locked_guest(901, "backup")];
        let effect2 = update(
            &mut state2,
            Action::MigrateGuest {
                vmid: 901,
                target_node: "pve2".into(),
            },
        );
        assert!(effect2.is_none(), "locked guest must refuse migrate");
    }

    #[test]
    fn v27_6_stale_pvestatd_flagged_when_uptime_does_not_advance() {
        use proxxx::api::types::{Node, NodeStatus};
        let mut state = fresh_state();
        // First fetch: pve1 uptime = 1000.
        state.nodes = vec![Node {
            node: "pve1".into(),
            status: NodeStatus::Online,
            uptime: 1000,
            ..Default::default()
        }];
        // Second fetch: same uptime, same status → pvestatd hasn't ticked.
        update(
            &mut state,
            Action::NodesLoaded(vec![Node {
                node: "pve1".into(),
                status: NodeStatus::Online,
                uptime: 1000,
                ..Default::default()
            }]),
        );
        assert!(
            state.nodes_with_stale_stats.contains("pve1"),
            "uptime stuck at same value across two ticks → flagged stale"
        );

        // Third fetch: uptime advanced → flag cleared.
        update(
            &mut state,
            Action::NodesLoaded(vec![Node {
                node: "pve1".into(),
                status: NodeStatus::Online,
                uptime: 1005,
                ..Default::default()
            }]),
        );
        assert!(
            !state.nodes_with_stale_stats.contains("pve1"),
            "uptime advanced → flag cleared"
        );
    }

    #[test]
    fn test_quit_returns_quit_effect() {
        let mut state = fresh_state();
        let effect = update(&mut state, Action::Quit);
        assert!(matches!(effect, Some(SideEffect::Quit)));
    }

    #[test]
    fn test_back_at_root_quits() {
        let mut state = fresh_state();
        assert_eq!(state.nav_stack.len(), 1);
        let effect = update(&mut state, Action::Back);
        assert!(matches!(effect, Some(SideEffect::Quit)));
    }

    #[test]
    fn test_back_pops_navigation_stack() {
        let mut state = fresh_state();
        state.push_view(View::GuestList);
        assert_eq!(state.nav_stack.len(), 2);

        let effect = update(&mut state, Action::Back);
        assert!(effect.is_none());
        assert_eq!(state.nav_stack.len(), 1);
        assert_eq!(*state.current_view(), View::Dashboard);
    }

    #[test]
    fn test_back_from_search_returns_to_normal() {
        let mut state = fresh_state();
        state.mode = AppMode::Search;
        state.search_query = "test".into();

        let effect = update(&mut state, Action::Back);
        assert!(effect.is_none());
        assert_eq!(state.mode, AppMode::Normal);
        assert!(state.search_query.is_empty());
    }

    #[test]
    fn test_navigate_down() {
        let mut state = state_with_nodes();
        assert_eq!(state.selected_index, 0);

        update(&mut state, Action::NavigateDown);
        assert_eq!(state.selected_index, 1);

        // Should not go past the end
        update(&mut state, Action::NavigateDown);
        assert_eq!(state.selected_index, 1); // still 1, only 2 nodes
    }

    #[test]
    fn test_navigate_up() {
        let mut state = state_with_nodes();
        state.selected_index = 1;

        update(&mut state, Action::NavigateUp);
        assert_eq!(state.selected_index, 0);

        // Should not go below 0
        update(&mut state, Action::NavigateUp);
        assert_eq!(state.selected_index, 0);
    }

    #[test]
    fn test_switch_view_resets_selection() {
        let mut state = state_with_nodes();
        state.selected_index = 5;

        update(&mut state, Action::SwitchView(View::GuestList));
        assert_eq!(state.selected_index, 0);
        assert_eq!(*state.current_view(), View::GuestList);
    }

    #[test]
    fn test_select_on_dashboard_goes_to_guests() {
        let mut state = state_with_nodes();
        let effect = update(&mut state, Action::Select);
        assert!(effect.is_none());
        assert_eq!(*state.current_view(), View::GuestList);
    }

    #[test]
    fn test_select_on_guest_list_goes_to_detail() {
        let mut state = state_with_guests();
        state.push_view(View::GuestList);
        state.selected_index = 0;

        let effect = update(&mut state, Action::Select);
        assert!(effect.is_none());
        assert!(matches!(
            state.current_view(),
            View::GuestDetail { vmid: 100 }
        ));
    }

    // ── Data Loading Tests ──────────────────────────────

    #[test]
    fn test_nodes_loaded_clears_loading() {
        use proxxx::api::types::*;
        let mut state = AppState::new();
        assert!(state.is_loading);

        let nodes = vec![Node {
            node: "test".into(),
            status: NodeStatus::Online,
            cpu: 1.0,
            maxcpu: 4,
            mem: 0,
            maxmem: 0,
            disk: 0,
            maxdisk: 0,
            uptime: 0,
        }];

        update(&mut state, Action::NodesLoaded(nodes));
        assert!(!state.is_loading);
        assert_eq!(state.nodes.len(), 1);
    }

    #[test]
    fn test_error_clears_loading() {
        let mut state = fresh_state();
        update(
            &mut state,
            Action::ErrorOccurred("connection failed".into()),
        );
        assert!(!state.is_loading);
        assert_eq!(state.error.as_deref(), Some("connection failed"));
    }

    // ── Side Effect Tests ───────────────────────────────

    #[test]
    fn test_start_guest_produces_side_effect() {
        let mut state = fresh_state();
        let effect = update(&mut state, Action::StartGuest { vmid: 100 });
        assert!(matches!(effect, Some(SideEffect::StartGuest { vmid: 100 })));
    }

    #[test]
    fn test_delete_guest_produces_side_effect() {
        // The reducer declares intent; HITL gating lives downstream in the
        // controller (it inspects the SideEffect and applies policy before
        // executing). The reducer does not wrap destructive ops itself.
        let mut state = fresh_state();
        let effect = update(&mut state, Action::DeleteGuest { vmid: 100 });
        assert!(matches!(
            effect,
            Some(SideEffect::DeleteGuest { vmid: 100 })
        ));
    }

    #[test]
    fn test_stop_guest_side_effect() {
        let mut state = fresh_state();
        let effect = update(
            &mut state,
            Action::StopGuest {
                vmid: 101,
                force: true,
            },
        );
        assert!(matches!(
            effect,
            Some(SideEffect::StopGuest {
                vmid: 101,
                force: true
            })
        ));
    }

    // ── HITL Approval Tests ─────────────────────────────

    #[test]
    fn test_approval_received_updates_status() {
        let mut state = fresh_state();
        state.pending_approvals.push(PendingApproval {
            txn_id: "abc123".into(),
            description: "delete vm-100".into(),
            status: ApprovalStatus::Pending,
        });

        update(
            &mut state,
            Action::ApprovalReceived {
                txn_id: "abc123".into(),
                approved: true,
            },
        );

        assert_eq!(state.pending_approvals[0].status, ApprovalStatus::Approved);
    }

    #[test]
    fn test_approval_denied() {
        let mut state = fresh_state();
        state.pending_approvals.push(PendingApproval {
            txn_id: "def456".into(),
            description: "stop vm-200".into(),
            status: ApprovalStatus::Pending,
        });

        update(
            &mut state,
            Action::ApprovalReceived {
                txn_id: "def456".into(),
                approved: false,
            },
        );

        assert_eq!(state.pending_approvals[0].status, ApprovalStatus::Denied);
    }

    #[test]
    fn test_approval_unknown_txn_is_noop() {
        let mut state = fresh_state();
        // No pending approvals — should not panic
        let effect = update(
            &mut state,
            Action::ApprovalReceived {
                txn_id: "nonexistent".into(),
                approved: true,
            },
        );
        assert!(effect.is_none());
    }

    // ── Mode Transition Tests ───────────────────────────

    #[test]
    fn test_search_mode_activation() {
        let mut state = fresh_state();
        update(&mut state, Action::SearchInput("test".into()));
        assert_eq!(state.mode, AppMode::Search);
        assert_eq!(state.search_query, "test");
    }

    #[test]
    fn test_command_mode_activation() {
        let mut state = fresh_state();
        update(&mut state, Action::CommandInput(":start".into()));
        assert_eq!(state.mode, AppMode::Command);
        assert_eq!(state.command_input, ":start");
    }

    #[test]
    fn test_command_submit_clears_input() {
        let mut state = fresh_state();
        state.mode = AppMode::Command;
        state.command_input = ":stop 100".into();

        update(&mut state, Action::CommandSubmit);
        assert_eq!(state.mode, AppMode::Normal);
        assert!(state.command_input.is_empty());
    }

    // ── SSH guest session (feature 1a) ──────────────────────

    #[test]
    fn test_parse_command_ssh_returns_open_action() {
        let action = parse_command_action("ssh 100").expect("ssh 100 parses");
        assert_eq!(action, Action::OpenGuestSsh { vmid: 100 });

        // Tolerates extra whitespace.
        let action = parse_command_action("  ssh   200 ").expect("ssh 200 parses");
        assert_eq!(action, Action::OpenGuestSsh { vmid: 200 });
    }

    #[test]
    fn test_parse_command_ssh_rejects_invalid() {
        assert!(parse_command_action("ssh").is_none(), "missing vmid");
        assert!(
            parse_command_action("ssh abc").is_none(),
            "non-numeric vmid"
        );
        assert!(parse_command_action("not-a-cmd").is_none(), "unknown");
        assert!(parse_command_action("").is_none(), "empty");
    }

    #[test]
    fn test_open_guest_ssh_pushes_view_and_emits_side_effect() {
        let mut state = fresh_state();
        let prior_view = state.current_view().clone();
        let effect = update(&mut state, Action::OpenGuestSsh { vmid: 100 });

        assert!(matches!(
            effect,
            Some(SideEffect::OpenSshSession { vmid: 100 })
        ));
        assert_eq!(state.mode, AppMode::SshSession { vmid: 100 });
        assert_eq!(*state.current_view(), View::GuestSshSession { vmid: 100 });
        // Ensure we pushed (not replaced) so Esc returns to where we were.
        assert_ne!(*state.current_view(), prior_view);
    }

    #[test]
    fn test_close_ssh_session_pops_view_and_emits_side_effect() {
        let mut state = fresh_state();
        update(&mut state, Action::OpenGuestSsh { vmid: 100 });
        assert!(matches!(state.mode, AppMode::SshSession { .. }));

        let effect = update(&mut state, Action::CloseSshSession);
        assert!(matches!(effect, Some(SideEffect::CloseSshSession)));
        assert_eq!(state.mode, AppMode::Normal);
        assert!(!matches!(
            state.current_view(),
            View::GuestSshSession { .. }
        ));
    }

    #[test]
    fn test_close_ssh_session_when_not_in_ssh_is_noop() {
        let mut state = fresh_state();
        let effect = update(&mut state, Action::CloseSshSession);
        assert!(
            effect.is_none(),
            "CloseSshSession outside SSH must not emit"
        );
        assert_eq!(state.mode, AppMode::Normal);
    }

    #[test]
    fn test_ssh_session_failed_pops_view_and_sets_error() {
        let mut state = fresh_state();
        update(&mut state, Action::OpenGuestSsh { vmid: 100 });
        assert!(matches!(state.mode, AppMode::SshSession { .. }));

        update(
            &mut state,
            Action::SshSessionFailed {
                vmid: 100,
                error: "auth denied".into(),
            },
        );
        assert_eq!(state.mode, AppMode::Normal);
        assert!(!matches!(
            state.current_view(),
            View::GuestSshSession { .. }
        ));
        let err = state.error.as_deref().unwrap_or_default();
        assert!(err.contains("100"), "error mentions vmid: {err}");
        assert!(err.contains("auth denied"), "error contains cause: {err}");
    }

    // ── Feature #4: HW console ───────────────────────────────

    #[test]
    fn test_open_hardware_pushes_view_with_node_and_emits_fetch() {
        let mut state = state_with_nodes();
        let effect = update(
            &mut state,
            Action::OpenHardware {
                node: "pve1".into(),
            },
        );
        assert!(matches!(
            effect,
            Some(SideEffect::FetchHardwareData { ref node }) if node == "pve1"
        ));
        assert_eq!(
            *state.current_view(),
            View::Hardware {
                node: "pve1".into()
            }
        );
        assert!(state.hw_loading);
        assert_eq!(state.hw_node, "pve1");
    }

    #[test]
    fn test_hw_data_loaded_only_accepts_matching_node() {
        use proxxx::api::types::*;
        let mut state = state_with_nodes();
        update(
            &mut state,
            Action::OpenHardware {
                node: "pve1".into(),
            },
        );
        // Stale fetch result for a different node — must be ignored.
        update(
            &mut state,
            Action::HwDataLoaded {
                node: "pve2".into(),
                pci: vec![PciDevice {
                    id: "0000:99:99.9".into(),
                    class: "0x030000".into(),
                    vendor: "0x10de".into(),
                    device: "0xdead".into(),
                    vendor_name: String::new(),
                    device_name: String::new(),
                    iommugroup: 99,
                    mdev: false,
                }],
                usb: vec![],
                configs: std::collections::HashMap::new(),
            },
        );
        assert!(state.hw_pci.is_empty(), "stale fetch ignored");
        assert!(state.hw_loading, "still waiting for the right node");

        // Fresh fetch for the requested node — accepted.
        update(
            &mut state,
            Action::HwDataLoaded {
                node: "pve1".into(),
                pci: vec![PciDevice {
                    id: "0000:01:00.0".into(),
                    class: "0x030000".into(),
                    vendor: "0x10de".into(),
                    device: "0x2484".into(),
                    vendor_name: "NVIDIA".into(),
                    device_name: "RTX 3070".into(),
                    iommugroup: 1,
                    mdev: true,
                }],
                usb: vec![],
                configs: std::collections::HashMap::new(),
            },
        );
        assert_eq!(state.hw_pci.len(), 1);
        assert!(!state.hw_loading);
    }

    #[test]
    fn test_parse_command_hw_aliases() {
        assert_eq!(
            parse_command_action("hw pve1"),
            Some(Action::OpenHardware {
                node: "pve1".into()
            })
        );
        assert_eq!(
            parse_command_action("hardware pve2"),
            Some(Action::OpenHardware {
                node: "pve2".into()
            })
        );
        assert_eq!(
            parse_command_action("passthrough pve1"),
            Some(Action::OpenHardware {
                node: "pve1".into()
            })
        );
        assert!(parse_command_action("hw").is_none(), "missing node");
    }

    // ── Feature #5: HA console ───────────────────────────────

    #[test]
    fn test_open_ha_console_pushes_view_and_emits_fetch() {
        let mut state = state_with_nodes();
        let effect = update(&mut state, Action::OpenHaConsole);
        assert!(matches!(effect, Some(SideEffect::FetchHaConsoleData)));
        assert_eq!(*state.current_view(), View::HaConsole);
        assert!(state.ha_loading);
    }

    #[test]
    fn test_ha_data_loaded_clears_loading_flag() {
        use proxxx::api::types::*;
        let mut state = state_with_nodes();
        update(&mut state, Action::OpenHaConsole);
        assert!(state.ha_loading);

        update(
            &mut state,
            Action::HaDataLoaded {
                groups: vec![HaGroup {
                    name: "g1".into(),
                    nodes: "pve1:2,pve2".into(),
                    restricted: false,
                    nofailback: false,
                    comment: String::new(),
                }],
                resources: vec![HaResource {
                    sid: "vm:100".into(),
                    group: "g1".into(),
                    state: "started".into(),
                    max_restart: 1,
                    max_relocate: 1,
                    comment: String::new(),
                }],
                manager: HaManagerStatus {
                    master: "pve1".into(),
                    mode: "active".into(),
                    node_status: std::collections::HashMap::new(),
                },
                cluster: vec![],
                repl_jobs: vec![],
                repl_status: vec![],
            },
        );
        assert!(!state.ha_loading);
        assert_eq!(state.ha_groups.len(), 1);
        assert_eq!(state.ha_resources.len(), 1);
        assert_eq!(state.ha_manager.as_ref().unwrap().master, "pve1");
    }

    #[test]
    fn test_parse_command_ha_aliases() {
        assert_eq!(parse_command_action("ha"), Some(Action::OpenHaConsole));
        assert_eq!(
            parse_command_action("replication"),
            Some(Action::OpenHaConsole)
        );
    }

    // ── Feature #2: ISO library ──────────────────────────────

    #[test]
    fn test_open_iso_library_pushes_view() {
        let mut state = fresh_state();
        let effect = update(&mut state, Action::OpenIsoLibrary);
        assert!(effect.is_none());
        assert_eq!(*state.current_view(), View::IsoLibrary);
    }

    #[test]
    fn test_download_iso_pinned_entry_dispatches_side_effect() {
        // After BLOCKER 1 was closed by real upstream pinning, every
        // entry in LIBRARY ships with `Some(Checksum::Sha256/Sha512)`.
        // The reducer must now SUCCEED for a known-pinned entry and
        // emit a DownloadIso side effect carrying (algo, hex).
        let mut state = state_with_nodes();
        let effect = update(
            &mut state,
            Action::DownloadIso {
                entry_id: "ubuntu-24.04-cloud".into(),
                node: "pve1".into(),
                storage: "local".into(),
            },
        );
        match effect {
            Some(SideEffect::DownloadIso {
                checksum: Some((algo, hex)),
                ..
            }) => {
                assert_eq!(algo, "sha256", "Ubuntu Noble pin uses SHA-256");
                assert_eq!(hex.len(), 64, "SHA-256 digest is 64 hex chars");
            }
            other => panic!("expected DownloadIso with pinned checksum, got {other:?}"),
        }
        assert!(state.error.is_none(), "no error on pinned dispatch");
    }

    #[test]
    fn test_download_iso_debian_uses_sha512_pin() {
        // Debian's upstream manifest publishes only SHA-512. The
        // BLOCKER 1 schema extension supports both algorithms; this
        // test pins that Debian's Checksum variant survives the
        // reducer round-trip and reaches the dispatch as ("sha512",
        // 128-hex).
        let mut state = state_with_nodes();
        let effect = update(
            &mut state,
            Action::DownloadIso {
                entry_id: "debian-12-cloud".into(),
                node: "pve1".into(),
                storage: "local".into(),
            },
        );
        match effect {
            Some(SideEffect::DownloadIso {
                checksum: Some((algo, hex)),
                ..
            }) => {
                assert_eq!(algo, "sha512");
                assert_eq!(hex.len(), 128, "SHA-512 digest is 128 hex chars");
            }
            other => panic!("expected SHA-512 DownloadIso, got {other:?}"),
        }
    }

    #[test]
    fn test_download_iso_unknown_id_sets_error() {
        let mut state = state_with_nodes();
        let effect = update(
            &mut state,
            Action::DownloadIso {
                entry_id: "ghost-distro".into(),
                node: "pve1".into(),
                storage: "local".into(),
            },
        );
        assert!(effect.is_none());
        assert!(state.error.is_some());
        assert!(
            state.error.as_deref().unwrap().contains("ghost-distro"),
            "error names the bad id"
        );
    }

    #[test]
    fn test_download_iso_curated_resolves_node_when_empty() {
        // Companion to the dispatch test: with an empty node, the
        // reducer falls back to the first online node from cluster
        // state. With all entries now pinned (BLOCKER 1 closed), the
        // pinned alpine entry must dispatch successfully against the
        // resolved node.
        let mut state = state_with_nodes();
        let effect = update(
            &mut state,
            Action::DownloadIso {
                entry_id: "alpine-3.21-iso".into(),
                node: String::new(),
                storage: "local".into(),
            },
        );
        match effect {
            Some(SideEffect::DownloadIso { node, .. }) => {
                assert!(
                    !node.is_empty(),
                    "node fallback must resolve to an online node"
                );
            }
            other => panic!("expected DownloadIso, got {other:?}"),
        }
    }

    #[test]
    fn test_download_iso_custom_url_passes_through() {
        let mut state = fresh_state();
        let effect = update(
            &mut state,
            Action::DownloadIsoCustom {
                url: "https://example.com/private.qcow2".into(),
                filename: "private.qcow2".into(),
                node: "pve1".into(),
                storage: "local".into(),
                checksum: Some(("sha256".into(), "deadbeef".into())),
                content: "import".into(),
            },
        );
        match effect {
            Some(SideEffect::DownloadIso {
                url,
                filename,
                checksum,
                ..
            }) => {
                assert_eq!(url, "https://example.com/private.qcow2");
                assert_eq!(filename, "private.qcow2");
                assert_eq!(
                    checksum.as_ref().map(|(a, h)| (a.as_str(), h.as_str())),
                    Some(("sha256", "deadbeef"))
                );
            }
            other => panic!("expected DownloadIso, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_command_iso_aliases() {
        assert_eq!(parse_command_action("iso"), Some(Action::OpenIsoLibrary));
        assert_eq!(parse_command_action("images"), Some(Action::OpenIsoLibrary));
        assert_eq!(
            parse_command_action("library"),
            Some(Action::OpenIsoLibrary)
        );
    }

    // ── Feature #6: disk operations force-enqueue ───────────

    #[test]
    fn test_move_disk_action_enqueues_never_emits_side_effect() {
        let mut state = state_with_guests();
        let initial_queue_len = state.op_queue.len();
        let effect = update(
            &mut state,
            Action::MoveDisk {
                vmid: 100,
                disk: "scsi0".into(),
                target_storage: "ceph-rbd".into(),
                delete_source: true,
            },
        );
        // Critical invariant: the reducer NEVER emits SideEffect::MoveDisk.
        // Disk ops MUST go through the queue.
        assert!(
            effect.is_none(),
            "Action::MoveDisk must never emit a direct SideEffect, got {effect:?}"
        );
        assert_eq!(state.op_queue.len(), initial_queue_len + 1);
        let queued = state.op_queue.last().unwrap();
        assert!(
            matches!(*queued.action, Action::MoveDisk { vmid: 100, .. }),
            "queued action wraps MoveDisk"
        );
        // Description includes destructive intent for review.
        assert!(
            queued.description.contains("scsi0"),
            "queue desc shows disk: {}",
            queued.description
        );
        assert!(
            queued.description.contains("ceph-rbd"),
            "queue desc shows target: {}",
            queued.description
        );
        assert!(
            queued.description.to_lowercase().contains("delete source"),
            "queue desc surfaces delete-source flag: {}",
            queued.description
        );
        // View flips to OperationQueue so user sees what's pending.
        assert_eq!(*state.current_view(), View::OperationQueue);
    }

    #[test]
    fn test_resize_disk_action_enqueues_never_emits_side_effect() {
        let mut state = state_with_guests();
        let effect = update(
            &mut state,
            Action::ResizeDisk {
                vmid: 100,
                disk: "scsi0".into(),
                size: "+10G".into(),
            },
        );
        assert!(effect.is_none(), "ResizeDisk must enqueue, not dispatch");
        assert_eq!(state.op_queue.len(), 1);
        assert!(matches!(
            *state.op_queue[0].action,
            Action::ResizeDisk { vmid: 100, .. }
        ));
    }

    #[test]
    fn test_move_disk_keep_source_description() {
        let mut state = state_with_guests();
        update(
            &mut state,
            Action::MoveDisk {
                vmid: 100,
                disk: "scsi0".into(),
                target_storage: "ceph".into(),
                delete_source: false,
            },
        );
        let queued = state.op_queue.last().unwrap();
        assert!(
            queued.description.to_lowercase().contains("keep source"),
            "non-delete variant must say keep-source: {}",
            queued.description
        );
    }

    // ── Feature #7: snapshot tree ────────────────────────────

    #[test]
    fn test_open_snapshot_tree_pushes_view_and_emits_fetch() {
        let mut state = state_with_guests();
        let effect = update(&mut state, Action::OpenSnapshotTree { vmid: 100 });
        assert!(matches!(
            effect,
            Some(SideEffect::FetchSnapshotTree { vmid: 100 })
        ));
        assert_eq!(*state.current_view(), View::SnapshotTree { vmid: 100 });
        assert!(state.snap_tree.is_none(), "tree starts unset");
        assert!(state.snap_tree_loading, "loading flag set");
        assert!(state.snap_tree_selected.is_none());
    }

    #[test]
    fn test_snapshots_loaded_assembles_tree_and_picks_current() {
        use proxxx::api::types::Snapshot;
        let mut state = state_with_guests();
        update(&mut state, Action::OpenSnapshotTree { vmid: 100 });
        let snaps = vec![
            Snapshot {
                name: "root".into(),
                parent: String::new(),
                description: String::new(),
                snaptime: 100,
                vmstate: 0,
            },
            Snapshot {
                name: "A".into(),
                parent: "root".into(),
                description: String::new(),
                snaptime: 200,
                vmstate: 0,
            },
            Snapshot {
                name: "current".into(),
                parent: "A".into(),
                description: String::new(),
                snaptime: 0,
                vmstate: 0,
            },
        ];
        let effect = update(&mut state, Action::SnapshotsLoaded { vmid: 100, snaps });
        assert!(effect.is_none(), "loading is pure state mutation");
        assert!(!state.snap_tree_loading);
        let tree = state.snap_tree.as_ref().expect("tree assembled");
        assert_eq!(tree.total_count(), 3);
        assert_eq!(state.snap_tree_selected.as_deref(), Some("current"));
    }

    #[test]
    fn test_snapshots_loaded_empty_picks_no_selection() {
        let mut state = state_with_guests();
        update(&mut state, Action::OpenSnapshotTree { vmid: 100 });
        update(
            &mut state,
            Action::SnapshotsLoaded {
                vmid: 100,
                snaps: vec![],
            },
        );
        assert!(state.snap_tree_loading == false);
        let tree = state.snap_tree.as_ref().expect("tree assembled");
        assert_eq!(tree.total_count(), 0);
        assert!(state.snap_tree_selected.is_none());
    }

    #[test]
    fn test_snapshots_loaded_for_stale_vmid_is_ignored() {
        // Open VMID 100, then VMID 200; a late SnapshotsLoaded for 100
        // must NOT clobber the tree of 200 (Category 1 SPOF 1.3 guard).
        use proxxx::api::types::Snapshot;
        let mut state = state_with_guests();
        update(&mut state, Action::OpenSnapshotTree { vmid: 100 });
        update(&mut state, Action::OpenSnapshotTree { vmid: 200 });
        // Sanity: the current view is 200's tree, in loading state.
        assert_eq!(*state.current_view(), View::SnapshotTree { vmid: 200 });
        assert!(state.snap_tree.is_none());
        assert!(state.snap_tree_loading);

        let stale_snaps = vec![Snapshot {
            name: "from_100".into(),
            parent: String::new(),
            description: String::new(),
            snaptime: 1,
            vmstate: 0,
        }];
        update(
            &mut state,
            Action::SnapshotsLoaded {
                vmid: 100,
                snaps: stale_snaps,
            },
        );
        // Guard fired: nothing about VMID 200's view changed.
        assert!(state.snap_tree.is_none(), "stale fetch must not assemble");
        assert!(state.snap_tree_loading, "loading flag must stay set");
    }

    #[test]
    fn test_parse_command_tree_aliases() {
        assert_eq!(
            parse_command_action("snaps 100"),
            Some(Action::OpenSnapshotTree { vmid: 100 })
        );
        assert_eq!(
            parse_command_action("tree 200"),
            Some(Action::OpenSnapshotTree { vmid: 200 })
        );
        assert_eq!(
            parse_command_action("snapshots 300"),
            Some(Action::OpenSnapshotTree { vmid: 300 })
        );
        assert!(parse_command_action("snaps").is_none());
        assert!(parse_command_action("snaps abc").is_none());
    }

    // ── Architectural review #2: queue persistence dirty flag ──

    #[test]
    fn test_enqueue_disk_move_sets_queue_dirty() {
        let mut state = state_with_guests();
        assert!(!state.queue_dirty, "starts clean");
        update(
            &mut state,
            Action::MoveDisk {
                vmid: 100,
                disk: "scsi0".into(),
                target_storage: "ceph".into(),
                delete_source: false,
            },
        );
        assert!(state.queue_dirty, "MoveDisk enqueue must mark queue dirty");
    }

    #[test]
    fn test_dequeue_sets_queue_dirty() {
        use proxxx::app::queue::{OpStatus, QueuedOp};
        let mut state = state_with_guests();
        let op = QueuedOp {
            id: "test-1".into(),
            action: Box::new(Action::StartGuest { vmid: 100 }),
            description: "Start 100".into(),
            diff: String::new(),
            status: OpStatus::Pending,
            created_at_secs: 0,
        };
        state.op_queue.push(op);
        state.queue_dirty = false;
        update(&mut state, Action::DequeueOperation(0));
        assert!(state.queue_dirty);
        assert_eq!(state.op_queue.len(), 0);
    }

    #[test]
    fn test_queue_op_status_changed_sets_queue_dirty() {
        use proxxx::app::queue::{OpStatus, QueuedOp};
        let mut state = state_with_guests();
        state.op_queue.push(QueuedOp {
            id: "abc".into(),
            action: Box::new(Action::StartGuest { vmid: 100 }),
            description: "Start 100".into(),
            diff: String::new(),
            status: OpStatus::Pending,
            created_at_secs: 0,
        });
        state.queue_dirty = false;
        update(
            &mut state,
            Action::QueueOpStatusChanged("abc".into(), OpStatus::Success),
        );
        assert!(state.queue_dirty);
        assert!(matches!(state.op_queue[0].status, OpStatus::Success));
    }

    #[test]
    fn test_queue_persisted_roundtrip_preserves_disk_op() {
        use proxxx::app::queue::{OpStatus, QueuedOp};
        let original = QueuedOp {
            id: "roundtrip-1".into(),
            action: Box::new(Action::MoveDisk {
                vmid: 100,
                disk: "scsi0".into(),
                target_storage: "ceph-rbd".into(),
                delete_source: true,
            }),
            description: "Move scsi0 …".into(),
            diff: "100 disk scsi0 → ceph-rbd".into(),
            status: OpStatus::Running,
            created_at_secs: 1_700_000_000,
        };
        let persisted = original.to_persisted().expect("persistable op");
        let json = serde_json::to_string(&persisted).expect("serializes");
        let parsed: proxxx::app::cache::PersistedQueueEntry =
            serde_json::from_str(&json).expect("deserializes");
        let restored = QueuedOp::from_persisted(parsed);
        assert_eq!(restored.id, original.id);
        assert_eq!(restored.description, original.description);
        match (*restored.action, *original.action) {
            (
                Action::MoveDisk {
                    vmid: a,
                    disk: b,
                    target_storage: c,
                    delete_source: d,
                },
                Action::MoveDisk {
                    vmid: e,
                    disk: f,
                    target_storage: g,
                    delete_source: h,
                },
            ) => {
                assert_eq!(a, e);
                assert_eq!(b, f);
                assert_eq!(c, g);
                assert_eq!(d, h);
            }
            _ => panic!("action variant mismatch after roundtrip"),
        }
        assert!(matches!(restored.status, OpStatus::Running));
    }

    #[test]
    fn test_to_persisted_filters_unsupported_actions() {
        use proxxx::app::queue::{OpStatus, QueuedOp};
        // Quit isn't a queueable op — to_persisted must return None
        // so the persistence layer can skip it cleanly.
        let op = QueuedOp {
            id: "x".into(),
            action: Box::new(Action::Quit),
            description: "x".into(),
            diff: String::new(),
            status: OpStatus::Pending,
            created_at_secs: 0,
        };
        assert!(op.to_persisted().is_none());
    }

    // ── Architectural review: per-poll status updates ──────

    #[test]
    fn test_guest_status_polled_updates_active_tasks() {
        let mut state = state_with_guests();
        let effect = update(
            &mut state,
            Action::GuestStatusPolled {
                vmid: 100,
                status: "running".into(),
                elapsed_secs: 27,
            },
        );
        assert!(effect.is_none(), "pure state mutation");
        let task_label = state.active_tasks.get(&100).cloned().unwrap_or_default();
        assert!(
            task_label.contains("27"),
            "label includes elapsed: {task_label}"
        );
        assert!(
            task_label.contains("running"),
            "label includes observed status: {task_label}"
        );
    }

    // ── Bug #2 enhancement: ACPI shutdown timeout flow ──────

    #[test]
    fn test_shutdown_timed_out_opens_confirm_modal_for_force() {
        let mut state = state_with_guests(); // includes vmid 100 named "web"
        let effect = update(
            &mut state,
            Action::ShutdownTimedOut {
                vmid: 100,
                elapsed_secs: 60,
            },
        );
        assert!(effect.is_none(), "no SideEffect — only mode transition");
        match &state.mode {
            AppMode::Confirm {
                description,
                action,
            } => {
                assert!(
                    description.contains("100"),
                    "description names vmid: {description}"
                );
                assert!(
                    description.contains("60s"),
                    "description includes elapsed: {description}"
                );
                assert!(
                    matches!(
                        **action,
                        Action::StopGuest {
                            vmid: 100,
                            force: true
                        }
                    ),
                    "the boxed action is the hard-stop variant: {action:?}"
                );
            }
            other => panic!("expected Confirm mode, got {other:?}"),
        }
    }

    #[test]
    fn test_shutdown_timed_out_then_confirm_dispatches_force_stop() {
        let mut state = state_with_guests();
        update(
            &mut state,
            Action::ShutdownTimedOut {
                vmid: 100,
                elapsed_secs: 60,
            },
        );
        // User accepts the modal → reducer should re-dispatch StopGuest{force:true}
        let effect = update(&mut state, Action::ConfirmAccept);
        assert!(matches!(
            effect,
            Some(SideEffect::StopGuest {
                vmid: 100,
                force: true
            })
        ));
        assert_eq!(state.mode, AppMode::Normal);
    }

    // ── Bug #9 fix: MigrateGuest direct dispatch ────────────

    #[test]
    fn test_migrate_guest_direct_dispatch_emits_side_effect() {
        let mut state = state_with_guests();
        // vmid 100 is on pve1 (set up in state_with_guests).
        let effect = update(
            &mut state,
            Action::MigrateGuest {
                vmid: 100,
                target_node: "pve2".into(),
            },
        );
        assert!(matches!(
            effect,
            Some(SideEffect::MigrateGuest { ref node, vmid: 100, ref target_node })
                if node == "pve1" && target_node == "pve2"
        ));
        assert!(state.active_tasks.contains_key(&100));
    }

    #[test]
    fn test_migrate_guest_unknown_surface_error() {
        let mut state = fresh_state(); // empty guests
        let effect = update(
            &mut state,
            Action::MigrateGuest {
                vmid: 999,
                target_node: "pve2".into(),
            },
        );
        assert!(effect.is_none());
        assert!(state.error.is_some());
        let err = state.error.as_deref().unwrap_or_default();
        assert!(err.contains("999"), "error mentions vmid: {err}");
        // active_tasks must not retain the entry on failure.
        assert!(!state.active_tasks.contains_key(&999));
    }

    #[test]
    fn test_command_submit_ssh_dispatches_open_action() {
        let mut state = fresh_state();
        state.mode = AppMode::Command;
        state.command_input = "ssh 100".into();
        let effect = update(&mut state, Action::CommandSubmit);
        assert!(matches!(
            effect,
            Some(SideEffect::OpenSshSession { vmid: 100 })
        ));
        assert_eq!(state.mode, AppMode::SshSession { vmid: 100 });
        assert!(state.command_input.is_empty());
    }
}
