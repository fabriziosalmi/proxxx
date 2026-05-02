#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! API client integration tests using wiremock.
//!
//! Targeted at bug #1 (LXC vs QEMU dispatch) and bug #2 (graceful shutdown).
//! These exercise the actual URL paths the client builds, asserting that:
//! - LXC ops route to `/lxc/...`, never `/qemu/...`
//! - QEMU ops route to `/qemu/...`, never `/lxc/...`
//! - `shutdown_guest` calls `/status/shutdown`, not `/status/stop`

#[cfg(test)]
mod tests {
    use proxxx::api::types::GuestType;
    use proxxx::api::{ProxmoxGateway, PxClient};
    use proxxx::config::ProfileConfig;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn ok_upid(prefix: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": format!("UPID:{prefix}:00000000:00000000:test::root@pam:")
        }))
    }

    async fn mock_client(server: &MockServer) -> PxClient {
        // Use a token-auth profile pointing at the mock server. Token
        // secret comes from env so we don't read filesystem keychain.
        std::env::set_var("PROXXX_TOKEN_SECRET", "fake-secret");
        let cfg = ProfileConfig {
            url: server.uri(),
            user: "root@pam".into(),
            auth: "token".into(),
            token_id: Some("test".into()),
            token_secret: None,
            token_secret_file: None,
            password: None,
            verify_tls: false,
            rate_limit: Some(100),
            policies: None,
            telegram: None,
            ssh: None,
            pbs: None,
            alerts: None,
        };
        PxClient::new(cfg, None).await.expect("client builds")
    }

    // ── Bug #1: LXC routing ─────────────────────────────────

    #[tokio::test]
    async fn lxc_start_hits_lxc_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/lxc/200/status/start"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.start_guest("pve1", 200, GuestType::Lxc)
            .await
            .expect("start");
    }

    #[tokio::test]
    async fn lxc_stop_hits_lxc_path_not_qemu() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/lxc/200/status/stop"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        // Negative mount: any /qemu/ path → fail loud
        Mock::given(path("/api2/json/nodes/pve1/qemu/200/status/stop"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.stop_guest("pve1", 200, GuestType::Lxc, true)
            .await
            .expect("stop");
    }

    #[tokio::test]
    async fn lxc_delete_hits_lxc_path() {
        // SPOF 2.3 (Cat. 2 audit): delete now does a pre-flight status
        // check and refuses if the guest is not Stopped. Mock both calls.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/lxc/200/status/current"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "vmid": 200,
                    "name": "ct200",
                    "status": "stopped",
                    "type": "lxc",
                    "node": "pve1"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api2/json/nodes/pve1/lxc/200"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.delete_guest("pve1", 200, GuestType::Lxc)
            .await
            .expect("delete");
    }

    #[tokio::test]
    async fn delete_refuses_when_guest_is_running_toctou_guard() {
        // SPOF 2.3 regression: after HITL approval but before the DELETE
        // lands, an admin starts the guest. The pre-flight gate must
        // refuse and emit a clear error — no DELETE should be issued.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/status/current"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "vmid": 100,
                    "name": "vm100",
                    "status": "running",
                    "type": "qemu",
                    "node": "pve1"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        // Negative: DELETE must NEVER fire on a running guest.
        Mock::given(method("DELETE"))
            .and(path("/api2/json/nodes/pve1/qemu/100"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let err = c
            .delete_guest("pve1", 100, GuestType::Qemu)
            .await
            .expect_err("must refuse delete-while-running");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("refusing destructive delete") && msg.contains("Running"),
            "expected TOCTOU refusal, got: {msg}"
        );
    }

    #[tokio::test]
    async fn lxc_snapshot_create_hits_lxc_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/lxc/200/snapshot"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.create_snapshot("pve1", 200, GuestType::Lxc, "pre-upgrade")
            .await
            .expect("snap");
    }

    #[tokio::test]
    async fn lxc_migrate_hits_lxc_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/lxc/200/migrate"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.migrate_guest("pve1", 200, GuestType::Lxc, "pve2")
            .await
            .expect("migrate");
    }

    // ── QEMU still works ────────────────────────────────────

    #[tokio::test]
    async fn qemu_start_hits_qemu_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/status/start"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.start_guest("pve1", 100, GuestType::Qemu)
            .await
            .expect("start");
    }

    // ── Bug #2: graceful shutdown ───────────────────────────

    #[tokio::test]
    async fn shutdown_qemu_hits_shutdown_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/status/shutdown"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        // Negative: must NOT call /status/stop
        Mock::given(path("/api2/json/nodes/pve1/qemu/100/status/stop"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.shutdown_guest("pve1", 100, GuestType::Qemu)
            .await
            .expect("shutdown");
    }

    #[tokio::test]
    async fn shutdown_lxc_hits_lxc_shutdown_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/lxc/200/status/shutdown"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.shutdown_guest("pve1", 200, GuestType::Lxc)
            .await
            .expect("shutdown");
    }

    #[tokio::test]
    async fn force_stop_qemu_uses_stop_path_with_force() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/status/stop"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.stop_guest("pve1", 100, GuestType::Qemu, true)
            .await
            .expect("force stop");
    }

    // ── Bug #2 enhancement: wait_for_stopped polling ─────────

    fn status_response(status: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": {
                "vmid": 100,
                "status": status,
                "name": "test"
            }
        }))
    }

    #[tokio::test]
    async fn wait_for_stopped_returns_stopped_when_status_flips() {
        use proxxx::tui::{wait_for_stopped, WaitOutcome};
        use std::time::Duration;

        let server = MockServer::start().await;
        // First call returns running, subsequent return stopped.
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/status/current"))
            .respond_with(status_response("running"))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/status/current"))
            .respond_with(status_response("stopped"))
            .mount(&server)
            .await;

        let c = mock_client(&server).await;
        let outcome = wait_for_stopped(
            &c,
            "pve1",
            100,
            Duration::from_secs(10),
            Duration::from_millis(50),
        )
        .await;
        assert!(
            matches!(outcome, WaitOutcome::Stopped { .. }),
            "expected Stopped, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn wait_for_stopped_returns_timeout_when_never_stops() {
        use proxxx::tui::{wait_for_stopped, WaitOutcome};
        use std::time::Duration;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/status/current"))
            .respond_with(status_response("running"))
            .mount(&server)
            .await;

        let c = mock_client(&server).await;
        let outcome = wait_for_stopped(
            &c,
            "pve1",
            100,
            Duration::from_millis(300),
            Duration::from_millis(80),
        )
        .await;
        match outcome {
            WaitOutcome::Timeout { elapsed_secs: _ } => { /* expected */ }
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    // ── Feature #1c: SPICE handoff ──────────────────────────

    #[tokio::test]
    async fn get_spiceproxy_returns_flat_keys_for_vv_file() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/spiceproxy"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "type": "spice",
                    "host": "192.168.1.10",
                    "port": "5900",
                    "tls-port": "5901",
                    "password": "PVESPICE:abc",
                    "title": "VM 100",
                    "delete-this-file": "1",
                    "release-cursor": "Ctrl+Alt+R",
                    "host-subject": "CN=pve1.lan",
                    "ca": "-----BEGIN CERTIFICATE-----\nXXX\n-----END CERTIFICATE-----"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let cfg = c.get_spiceproxy("pve1", 100).await.expect("spiceproxy");
        assert_eq!(cfg.host(), Some("192.168.1.10"));
        // The .vv rendering must include all PVE-supplied keys verbatim,
        // with PEM newlines escaped.
        let vv = cfg.to_vv_file();
        assert!(vv.starts_with("[virt-viewer]\n"));
        assert!(vv.contains("password=PVESPICE:abc"));
        assert!(vv.contains("ca=-----BEGIN CERTIFICATE-----\\nXXX\\n-----END CERTIFICATE-----"));
        assert!(vv.contains("delete-this-file=1"));
    }

    // ── Feature #1b: termproxy ticket ───────────────────────

    #[tokio::test]
    async fn get_termproxy_qemu_returns_ticket_and_port() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/termproxy"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "port": 5900,
                    "ticket": "PVE:user@pam:abc/def+xyz",
                    "user": "user@pam",
                    "upid": "UPID:pve1:00:00:term:user@pam:"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let t = c
            .get_termproxy("pve1", 100, GuestType::Qemu)
            .await
            .expect("termproxy");
        assert_eq!(t.port, 5900);
        assert_eq!(t.user, "user@pam");
        assert!(t.ticket.contains("abc/def+xyz"));
    }

    #[tokio::test]
    async fn get_termproxy_lxc_routes_to_lxc_path_not_qemu() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/lxc/200/termproxy"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"port": 5901, "ticket": "T", "user": "u@pve"}
            })))
            .expect(1)
            .mount(&server)
            .await;
        // Negative: must NOT hit /qemu
        Mock::given(path("/api2/json/nodes/pve1/qemu/200/termproxy"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.get_termproxy("pve1", 200, GuestType::Lxc)
            .await
            .expect("termproxy lxc");
    }

    // ── Feature #10: access (ACL, users, groups, roles, realms, tokens) ──

    #[tokio::test]
    async fn list_acl_returns_entries() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/access/acl"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"path": "/", "type": "user", "ugid": "root@pam", "roleid": "Administrator", "propagate": 1},
                    {"path": "/vms/100", "type": "user", "ugid": "ops@pve", "roleid": "PVEVMUser", "propagate": 0}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let acl = c.list_acl().await.expect("acl");
        assert_eq!(acl.len(), 2);
        assert!(acl[0].propagate);
        assert!(!acl[1].propagate);
    }

    #[tokio::test]
    async fn list_users_returns_users() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/access/users"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"userid": "root@pam", "enable": 1, "comment": "root"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let users = c.list_users().await.expect("users");
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].userid, "root@pam");
        assert!(users[0].enable);
    }

    #[tokio::test]
    async fn list_user_tokens_url_encodes_userid_at_sign() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/access/users/root%40pam/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"tokenid": "ci", "privsep": 1, "comment": "CI token"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let tokens = c.list_user_tokens("root@pam").await.expect("tokens");
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].tokenid, "ci");
        assert!(tokens[0].privsep);
        // Listing never returns the secret.
        assert!(tokens[0].value.is_none());
    }

    #[tokio::test]
    async fn create_token_returns_secret_value_once() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/access/users/svc%40pve/token/ci-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "info": {"privsep": 1, "expire": 0, "comment": ""},
                    "value": "00000000-0000-0000-0000-000000000abc"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let tok = c
            .create_token("svc@pve", "ci-key", true, None, None)
            .await
            .expect("create");
        assert_eq!(tok.tokenid, "ci-key");
        assert!(tok.privsep);
        assert_eq!(
            tok.value.as_deref(),
            Some("00000000-0000-0000-0000-000000000abc")
        );
    }

    #[tokio::test]
    async fn revoke_token_uses_delete_method() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api2/json/access/users/svc%40pve/token/old-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.revoke_token("svc@pve", "old-key").await.expect("revoke");
    }

    #[tokio::test]
    async fn list_realms_distinguishes_kinds() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/access/domains"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"realm": "pam", "type": "pam"},
                    {"realm": "pve", "type": "pve"},
                    {"realm": "corp-ad", "type": "ad", "comment": "internal AD"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let realms = c.list_realms().await.expect("realms");
        let kinds: Vec<&str> = realms.iter().map(|r| r.kind.as_str()).collect();
        assert!(kinds.contains(&"pam"));
        assert!(kinds.contains(&"ad"));
    }

    #[tokio::test]
    async fn list_tfa_returns_per_user_entries() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/access/tfa/oncall%40pve"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"id": "abc1", "type": "totp", "description": "phone", "enable": 1, "created": 0},
                    {"id": "abc2", "type": "recovery", "description": "codes", "enable": 1, "created": 0}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let tfa = c.list_tfa("oncall@pve").await.expect("tfa");
        assert_eq!(tfa.len(), 2);
        assert_eq!(tfa[0].kind, "totp");
        assert_eq!(tfa[1].kind, "recovery");
    }

    // ── Feature #4: hardware inventory ──────────────────────

    #[tokio::test]
    async fn list_pci_returns_devices_with_iommu_group() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/hardware/pci"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "id": "0000:01:00.0",
                        "class": "0x030000",
                        "vendor": "0x10de",
                        "device": "0x2484",
                        "vendor_name": "NVIDIA Corporation",
                        "device_name": "GA104 [GeForce RTX 3070]",
                        "iommugroup": 1,
                        "mdev": 1
                    },
                    {
                        "id": "0000:01:00.1",
                        "class": "0x040300",
                        "vendor": "0x10de",
                        "device": "0x228b",
                        "iommugroup": 1,
                        "mdev": 0
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let pci = c.list_pci("pve1").await.expect("pci");
        assert_eq!(pci.len(), 2);
        assert_eq!(pci[0].iommugroup, 1);
        assert!(pci[0].is_gpu());
        assert!(pci[0].mdev);
        assert!(!pci[1].is_gpu(), "audio class isn't GPU");
        assert!(!pci[1].mdev);
    }

    #[tokio::test]
    async fn list_pci_handles_missing_iommu_group() {
        // Older kernels / IOMMU disabled — Proxmox returns no iommugroup.
        // Our default = -1 must apply.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/hardware/pci"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"id": "0000:01:00.0", "class": "0x030000", "vendor": "0x10de", "device": "0x2484"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let pci = c.list_pci("pve1").await.expect("pci");
        assert_eq!(pci[0].iommugroup, -1);
        assert!(!pci[0].mdev);
    }

    #[tokio::test]
    async fn list_usb_returns_devices() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/hardware/usb"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "busnum": 1,
                        "devnum": 3,
                        "vendid": "0x046d",
                        "prodid": "0xc52b",
                        "manufacturer": "Logitech",
                        "product": "Unifying Receiver",
                        "class": "03"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let usb = c.list_usb("pve1").await.expect("usb");
        assert_eq!(usb.len(), 1);
        assert_eq!(usb[0].proxmox_id(), "046d:c52b");
    }

    // ── Feature #5: HA + replication endpoints ──────────────

    #[tokio::test]
    async fn list_ha_groups_hits_cluster_ha_groups() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/ha/groups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"group": "g1", "nodes": "pve1:2,pve2:1,pve3", "restricted": 0, "nofailback": 1, "comment": "primary"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let groups = c.list_ha_groups().await.expect("groups");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "g1");
        assert!(groups[0].nofailback);
        assert!(!groups[0].restricted);
    }

    #[tokio::test]
    async fn list_ha_resources_hits_cluster_ha_resources() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/ha/resources"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"sid": "vm:100", "group": "g1", "state": "started", "max_restart": 1, "max_relocate": 1}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let resources = c.list_ha_resources().await.expect("resources");
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].vmid(), Some(100));
        assert_eq!(resources[0].kind(), "vm");
    }

    #[tokio::test]
    async fn ha_manager_status_hits_manager_status_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/ha/status/manager_status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "master": "pve1",
                    "mode": "active",
                    "node_status": {"pve1": "online", "pve2": "online"}
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let m = c.ha_manager_status().await.expect("status");
        assert_eq!(m.master, "pve1");
        assert_eq!(m.mode, "active");
    }

    #[tokio::test]
    async fn cluster_status_returns_node_entries() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"type": "cluster", "name": "homelab", "nodes": 3, "quorate": 1, "online": 1},
                    {"type": "node", "name": "pve1", "online": 1, "local": 1},
                    {"type": "node", "name": "pve2", "online": 1, "local": 0},
                    {"type": "node", "name": "pve3", "online": 0, "local": 0}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let entries = c.cluster_status().await.expect("status");
        assert_eq!(entries.len(), 4);
        let nodes_online: Vec<&str> = entries
            .iter()
            .filter(|e| e.entry_type == "node" && e.online)
            .map(|e| e.name.as_str())
            .collect();
        assert_eq!(nodes_online, vec!["pve1", "pve2"]);
    }

    #[tokio::test]
    async fn list_replication_jobs_hits_cluster_replication() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/replication"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"id": "100-0", "type": "local", "source": "pve1", "target": "pve2", "schedule": "*/15", "disable": 0}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let jobs = c.list_replication_jobs().await.expect("jobs");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].vmid(), Some(100));
    }

    #[tokio::test]
    async fn list_replication_status_hits_node_replication_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/replication"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"id": "100-0", "last_sync": 1700000000u64, "duration": 12.5, "fail_count": 0, "source": "pve1", "target": "pve2"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let s = c.list_replication_status("pve1").await.expect("status");
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].id, "100-0");
        assert_eq!(s[0].last_sync, 1_700_000_000);
        assert!(s[0].error.is_empty());
    }

    // ── Feature #2: ISO download + storage content ──────────

    #[tokio::test]
    async fn download_to_storage_hits_download_url_endpoint() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/storage/local/download-url"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        // Negative: must NOT hit the legacy /upload endpoint
        Mock::given(path("/api2/json/nodes/pve1/storage/local/upload"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let upid = c
            .download_to_storage(
                "pve1",
                "local",
                "https://example.com/test.img",
                "test.img",
                Some("sha256"),
                Some("aabb"),
                "iso",
            )
            .await
            .expect("download");
        assert!(upid.contains("UPID"));
    }

    #[tokio::test]
    async fn download_to_storage_omits_checksum_when_none() {
        let server = MockServer::start().await;
        // Wiremock matches on URL + method; we don't assert form body
        // contents directly, but if checksum WAS sent the test below
        // wouldn't observe a 200 because we don't mount a fallback.
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/storage/local/download-url"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.download_to_storage(
            "pve1",
            "local",
            "https://example.com/test.img",
            "test.img",
            None,
            None,
            "iso",
        )
        .await
        .expect("download without checksum");
    }

    #[tokio::test]
    async fn list_storage_content_filters_by_content_type() {
        let server = MockServer::start().await;
        // With filter (?content=iso) — only ISOs returned.
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/storage/local/content"))
            .and(wiremock::matchers::query_param("content", "iso"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"volid": "local:iso/debian-12.iso", "content": "iso", "size": 100, "format": ""}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let items = c
            .list_storage_content("pve1", "local", Some("iso"))
            .await
            .expect("list");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].filename(), "debian-12.iso");
    }

    // ── Feature #6: disk operations ─────────────────────────

    #[tokio::test]
    async fn move_disk_qemu_routes_to_move_disk() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/move_disk"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.move_disk("pve1", 100, GuestType::Qemu, "scsi0", "ceph-rbd", true)
            .await
            .expect("move");
    }

    #[tokio::test]
    async fn move_disk_lxc_routes_to_move_volume_not_qemu() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/lxc/200/move_volume"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        // Negative: LXC must NOT call /move_disk OR /qemu/...
        Mock::given(path("/api2/json/nodes/pve1/lxc/200/move_disk"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(path("/api2/json/nodes/pve1/qemu/200/move_volume"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.move_disk("pve1", 200, GuestType::Lxc, "rootfs", "local-zfs", false)
            .await
            .expect("move");
    }

    #[tokio::test]
    async fn resize_disk_qemu_uses_put_method() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/nodes/pve1/qemu/100/resize"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "UPID:pve1:resize:::root@pam:"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let upid = c
            .resize_disk("pve1", 100, GuestType::Qemu, "scsi0", "+10G")
            .await
            .expect("resize");
        assert!(upid.contains("UPID"), "got: {upid}");
    }

    #[tokio::test]
    async fn resize_disk_lxc_routes_to_lxc_path() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/nodes/pve1/lxc/200/resize"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        // Negative: must NOT hit /qemu/.
        Mock::given(path("/api2/json/nodes/pve1/qemu/200/resize"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let result = c
            .resize_disk("pve1", 200, GuestType::Lxc, "rootfs", "10G")
            .await
            .expect("resize");
        assert_eq!(result, "synchronous", "null UPID becomes the sentinel");
    }

    // ── Feature #7: list_snapshots routing ──────────────────

    #[tokio::test]
    async fn list_snapshots_qemu_routes_to_qemu_path() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/snapshot"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"name": "current", "parent": "A", "snaptime": 0, "vmstate": 0},
                    {"name": "A", "parent": "", "snaptime": 1700000000, "vmstate": 0}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let snaps = c
            .list_snapshots("pve1", 100, GuestType::Qemu)
            .await
            .expect("list");
        assert_eq!(snaps.len(), 2);
    }

    #[tokio::test]
    async fn list_snapshots_lxc_routes_to_lxc_path_not_qemu() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/lxc/200/snapshot"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        // Negative: must NOT call /qemu
        Mock::given(path("/api2/json/nodes/pve1/qemu/200/snapshot"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.list_snapshots("pve1", 200, GuestType::Lxc)
            .await
            .expect("list");
    }

    #[tokio::test]
    async fn wait_for_stopped_with_progress_emits_per_poll_callback() {
        use proxxx::tui::{wait_for_stopped_with_progress, WaitOutcome};
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        let server = MockServer::start().await;
        // 2 running responses then stopped — verifies progress fires
        // for each interim poll AND for the final stopped poll.
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/status/current"))
            .respond_with(status_response("running"))
            .up_to_n_times(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/status/current"))
            .respond_with(status_response("stopped"))
            .mount(&server)
            .await;

        let progress: Arc<Mutex<Vec<(String, u64)>>> = Arc::new(Mutex::new(Vec::new()));
        let progress_capture = Arc::clone(&progress);
        let c = mock_client(&server).await;
        let outcome = wait_for_stopped_with_progress(
            &c,
            "pve1",
            100,
            Duration::from_secs(30),
            Duration::from_millis(40),
            move |status: &str, elapsed: u64| {
                progress_capture
                    .lock()
                    .unwrap()
                    .push((status.to_string(), elapsed));
            },
        )
        .await;

        assert!(matches!(outcome, WaitOutcome::Stopped { .. }));
        let polls = progress.lock().unwrap();
        assert!(
            polls.len() >= 3,
            "expected ≥3 polls (2 running + 1 stopped), got {polls:?}"
        );
        // Last entry must be the terminating "stopped".
        assert_eq!(polls.last().unwrap().0, "stopped");
        // Earlier entries report "running".
        assert!(polls.iter().any(|(s, _)| s == "running"));
    }

    #[tokio::test]
    async fn wait_for_stopped_tolerates_status_errors() {
        use proxxx::tui::{wait_for_stopped, WaitOutcome};
        use std::time::Duration;

        let server = MockServer::start().await;
        // First call: 500 (transient error during shutdown).
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/status/current"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        // Then: stopped.
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/status/current"))
            .respond_with(status_response("stopped"))
            .mount(&server)
            .await;

        let c = mock_client(&server).await;
        let outcome = wait_for_stopped(
            &c,
            "pve1",
            100,
            Duration::from_secs(5),
            Duration::from_millis(50),
        )
        .await;
        assert!(
            matches!(outcome, WaitOutcome::Stopped { .. }),
            "transient error must not break the loop, got {outcome:?}"
        );
    }

    // ── SPOF 2.2 (Cat. 2 audit): 503 retry storm guard ──────

    #[tokio::test]
    async fn get_retries_on_503_then_succeeds() {
        // Simulate pvedaemon hiccup: first two calls return 503, the
        // third returns the real payload. The retry helper must absorb
        // the transient failures and surface success.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(2)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": [] })),
            )
            .mount(&server)
            .await;

        let c = mock_client(&server).await;
        let nodes = c.get_nodes().await.expect("nodes after retries");
        assert!(nodes.is_empty());
    }

    #[tokio::test]
    async fn get_gives_up_after_max_attempts_on_persistent_503() {
        // Permanent 503: must surface error after the retry budget is
        // exhausted, not retry forever.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let c = mock_client(&server).await;
        let err = c.get_nodes().await.expect_err("must fail eventually");
        let msg = format!("{err:#}");
        assert!(msg.contains("503"), "expected 503 in surfaced error: {msg}");
    }

    // ── Vector 11 (Gemini wave-3): reactive 401 re-auth ──────

    #[tokio::test]
    async fn token_auth_401_propagates_without_infinite_loop() {
        // Token-auth profile cannot refresh (no password). After a 401,
        // `force_reauth` returns Err and the response is surfaced. The
        // critical invariant is "no infinite retry loop" — we already
        // retry exactly once for the auth path, then return.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes"))
            .respond_with(ResponseTemplate::new(401))
            .expect(1) // ONE call only — retry must NOT happen for token-auth
            .mount(&server)
            .await;

        let c = mock_client(&server).await;
        // The second call is suppressed by force_reauth() returning Err
        // when AuthMethod is Token. The 401 surfaces directly.
        let err = c.get_nodes().await.expect_err("401 should surface");
        // V26.4: assert via the typed downcast — the Display string no
        // longer contains the literal "401" because ApiError abstracts
        // away the HTTP status into a category. The TUI consumer also
        // does this downcast to decide whether to show a "re-auth"
        // modal vs a generic error toast.
        let typed = err
            .downcast_ref::<proxxx::api::ApiError>()
            .expect("must downcast to ApiError");
        assert!(
            typed.is_unauthorized(),
            "expected ApiError::Unauthorized, got: {typed:?}"
        );
    }

    // ── Vector 14 (Gemini wave-3): bounded response body ─────

    #[tokio::test]
    async fn refuses_response_body_over_32mib_cap() {
        // Generate a body larger than the 32 MiB Vector-14 cap. We do
        // NOT lie about Content-Length — wiremock sets it correctly,
        // so the pre-flight check aborts before any bytes are pulled
        // off the wire. Mathematical guarantee: peak RAM during this
        // test is the body buffer in wiremock + our refusal — never
        // a 2 GiB OOM scenario the audit posited.
        let server = MockServer::start().await;
        let body = vec![b'x'; 33 * 1024 * 1024]; // 33 MiB, just over the cap
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body))
            .mount(&server)
            .await;

        let c = mock_client(&server).await;
        let err = c.get_nodes().await.expect_err("oversized must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("exceeds") || msg.contains("limit"),
            "expected size-limit error, got: {msg}"
        );
    }

    // ── Vector 25 (macro audit): lax deserialization ─────────

    /// V25 — every API response struct must tolerate missing fields.
    /// The struct-level `#[serde(default)]` + `Default` derive means
    /// a future PVE version dropping a field surfaces as the field's
    /// Default value, not a deserialization panic.
    #[test]
    fn node_deserializes_with_no_fields_at_all() {
        use proxxx::api::types::{Node, NodeStatus};
        // Worst-case: PVE 8.3 returns a node entry as `{}`. We must
        // produce a Default-shaped Node, not error out and lose the
        // entire `get_nodes` payload.
        let json = "{}";
        let n: Node = serde_json::from_str(json).expect("Node tolerates empty object");
        assert_eq!(n.node, "");
        assert_eq!(n.status, NodeStatus::Unknown);
        assert_eq!(n.cpu, 0.0);
    }

    #[test]
    fn guest_deserializes_with_only_extra_unknown_field() {
        use proxxx::api::types::Guest;
        // PVE 8.4 hypothetically adds a `gpu_groups` field and removes
        // `tags`. proxxx must:
        //   1. Ignore the unknown `gpu_groups` (serde does this by
        //      default — no `deny_unknown_fields`).
        //   2. Default-fill the missing `tags`.
        let json = r#"{ "vmid": 100, "gpu_groups": ["a","b"] }"#;
        let g: Guest = serde_json::from_str(json).expect("Guest tolerates unknown + missing");
        assert_eq!(g.vmid, 100);
        assert_eq!(g.tags, "");
    }

    #[test]
    fn task_info_deserializes_with_minimal_payload() {
        use proxxx::api::types::TaskInfo;
        // Even if PVE strips most fields (`upid` is the only thing
        // proxxx absolutely needs), the deserialization must succeed.
        let json = r#"{ "upid": "UPID:test:0:0:0:0:0:0:0:" }"#;
        let t: TaskInfo = serde_json::from_str(json).expect("TaskInfo tolerates minimal");
        assert_eq!(t.upid, "UPID:test:0:0:0:0:0:0:0:");
        assert_eq!(t.starttime, 0);
    }

    #[test]
    fn snapshot_deserializes_with_no_fields() {
        use proxxx::api::types::Snapshot;
        let s: Snapshot = serde_json::from_str("{}").expect("Snapshot tolerates empty");
        assert_eq!(s.name, "");
        assert_eq!(s.parent, "");
    }
}
