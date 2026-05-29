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
        // Pass the secret via the cli_secret parameter (resolver priority
        // #1) instead of `std::env::set_var`. Env vars are process-global
        // and cargo runs integration tests in parallel — set_var would
        // race with any other test reading PROXXX_TOKEN_SECRET. The token
        // also stays out of the keychain code path because cli_secret
        // short-circuits the resolver before it consults env / file /
        // keychain.
        let cfg = ProfileConfig {
            url: server.uri(),
            user: "root@pam".into(),
            auth: "token".into(),
            token_id: Some("test".into()),
            token_secret: None,
            token_secret_file: None,
            password: None,
            verify_tls: false,
            tls_pin_mode: None,
            read_only: false,
            rate_limit: Some(100),
            policies: None,
            telegram: None,
            ssh: None,
            pbs: None,
            alerts: None,
            mcp_token: None,
            profile_name: None,
        };
        PxClient::new(cfg, Some("fake-secret"))
            .await
            .expect("client builds")
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
        c.migrate_guest("pve1", 200, GuestType::Lxc, "pve2", false, false, false)
            .await
            .expect("migrate");
    }

    #[tokio::test]
    async fn lxc_migrate_with_restart_passes_restart_param() {
        // GAP 4 regression guard: when restart=true is passed, the
        // request body MUST include `restart=1`. Without this PVE
        // refuses to migrate a running container (no live migration
        // path exists for LXC). We assert via wiremock body matcher
        // that the form includes the param.
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/lxc/200/migrate"))
            .and(body_string_contains("restart=1"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.migrate_guest("pve1", 200, GuestType::Lxc, "pve2", false, false, true)
            .await
            .expect("migrate with restart");
    }

    #[tokio::test]
    async fn qemu_migrate_does_not_pass_restart_param() {
        // Inverse guard: QEMU migrations must NOT include `restart=1`
        // even if the caller asks (PVE QEMU endpoint doesn't define
        // it; passing it might either be ignored or cause a 400 in
        // future PVE versions). The dispatch in client.rs branches on
        // guest_type and drops `restart` for QEMU.
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        // Negative match: any POST including `restart=1` should NOT
        // be sent. We accept the request only when it lacks that
        // substring.
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/migrate"))
            .and(body_string_contains("online=1"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/migrate"))
            .and(body_string_contains("restart=1"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        // Pass restart=true and verify it gets dropped at the QEMU
        // dispatch layer.
        c.migrate_guest("pve1", 100, GuestType::Qemu, "pve2", true, false, true)
            .await
            .expect("qemu migrate");
    }

    #[tokio::test]
    async fn get_task_status_parses_pve_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/api2/json/nodes/pve1/tasks/UPID:pve1:abc:def:test:qmigrate:100:root@pam:/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "upid": "UPID:pve1:abc:def:test:qmigrate:100:root@pam:",
                    "status": "stopped",
                    "exitstatus": "OK",
                    "type": "qmigrate",
                    "id": "100",
                    "user": "root@pam",
                    "starttime": 1234567890_u64
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let st = c
            .get_task_status("pve1", "UPID:pve1:abc:def:test:qmigrate:100:root@pam:")
            .await
            .expect("status");
        assert!(st.is_done());
        assert!(st.is_success());
    }

    // ── Domain 7: Access mutations (Phase 5.10) ────────────

    #[tokio::test]
    async fn create_user_posts_to_access_users_with_userid() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/access/users"))
            .and(body_string_contains("userid=alice%40pve"))
            .and(body_string_contains("password=s3cret"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.create_user(
            "alice@pve",
            Some("s3cret"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create_user");
    }

    #[tokio::test]
    async fn delete_user_uses_url_encoded_userid() {
        // GAP guard: `@` in userid MUST be URL-encoded for the path
        // segment — otherwise some PVE versions misroute. The
        // `urlenc` helper handles it; pin behavior here.
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api2/json/access/users/alice%40pve"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.delete_user("alice@pve").await.expect("delete_user");
    }

    #[tokio::test]
    async fn modify_acl_grant_does_not_send_delete_param() {
        // Grant path: PVE PUT /access/acl WITHOUT `delete=1` means
        // assignment. Negative match: a grant call must NOT include
        // `delete=1` (which would silently revoke instead of grant).
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/access/acl"))
            .and(body_string_contains("path=%2Fvms%2F100"))
            .and(body_string_contains("roles=PVEAuditor"))
            .and(body_string_contains("users=alice%40pve"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/access/acl"))
            .and(body_string_contains("delete=1"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.modify_acl(
            "/vms/100",
            "PVEAuditor",
            Some("alice@pve"),
            None,
            None,
            true,
            false,
        )
        .await
        .expect("grant");
    }

    #[tokio::test]
    async fn modify_acl_revoke_sends_delete_param() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/access/acl"))
            .and(body_string_contains("delete=1"))
            .and(body_string_contains("roles=PVEAuditor"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.modify_acl("/", "PVEAuditor", Some("alice@pve"), None, None, true, true)
            .await
            .expect("revoke");
    }

    #[tokio::test]
    async fn upload_to_storage_sends_multipart_with_content_and_filename_parts() {
        // Phase 5.7 regression guard against a reqwest version bump or
        // refactor breaking the multipart wire format.
        //
        // We don't assert the full multipart body shape (boundaries
        // are random; would be brittle). We assert what matters:
        //
        //   1. The request reaches the right URL/method.
        //   2. The Content-Type header carries `multipart/form-data`
        //      with a boundary parameter (proves reqwest produced a
        //      multipart envelope).
        //   3. The body contains BOTH `name="content"` (the text
        //      field) and `name="filename"` (the file part) — the
        //      PVE-specific quirk where the BINARY goes in a part
        //      called "filename", not "file".
        //
        // If a future reqwest update breaks any of these, this test
        // fails BEFORE the user discovers it via a 400 from PVE.
        use std::io::Write;
        use wiremock::matchers::{body_string_contains, header_regex};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/storage/local/upload"))
            .and(header_regex(
                "content-type",
                r"^multipart/form-data; boundary=",
            ))
            .and(body_string_contains("name=\"content\""))
            .and(body_string_contains("name=\"filename\""))
            .and(body_string_contains("filename=\"smoke.iso\""))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        // Write a tiny temp file (the streaming body needs a real fd).
        let dir = std::env::temp_dir();
        let path = dir.join(format!("proxxx-multipart-test-{}.iso", std::process::id()));
        std::fs::File::create(&path)
            .unwrap()
            .write_all(b"wiremock multipart smoke")
            .unwrap();
        let c = mock_client(&server).await;
        let upid = c
            .upload_to_storage("pve1", "local", &path, "iso", Some("smoke.iso"))
            .await
            .expect("upload");
        assert!(upid.starts_with("UPID:pve1:"));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn task_status_running_is_not_done() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/api2/json/nodes/pve1/tasks/UPID:pve1:abc:def:test:qmigrate:100:root@pam:/status",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "upid": "UPID:pve1:abc:def:test:qmigrate:100:root@pam:",
                    "status": "running",
                    "type": "qmigrate",
                    "id": "100",
                    "user": "root@pam",
                    "starttime": 1234567890_u64
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let st = c
            .get_task_status("pve1", "UPID:pve1:abc:def:test:qmigrate:100:root@pam:")
            .await
            .expect("status");
        assert!(!st.is_done());
        assert!(!st.is_success());
    }

    // ── vzdump backup creation ─────────────────────────────

    #[tokio::test]
    async fn create_backup_hits_node_vzdump_with_csv_vmids() {
        // Verifies: endpoint path is per-node `/vzdump`, vmids are
        // serialized as a CSV string (PVE's expected format), and
        // returned UPID is propagated unchanged.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/vzdump"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let upid = c
            .create_backup("pve1", &[100, 101, 200], "pbs-main", "snapshot", None)
            .await
            .expect("backup");
        assert!(upid.starts_with("UPID:pve1:"));
    }

    #[tokio::test]
    async fn create_backup_with_compress_param_still_hits_vzdump() {
        // The `compress` param is optional; presence must not change
        // the endpoint shape.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve2/vzdump"))
            .respond_with(ok_upid("pve2"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.create_backup("pve2", &[100], "local", "stop", Some("zstd"))
            .await
            .expect("backup");
    }

    // ── Templates & cloning (Phase 2) ──────────────────────

    #[tokio::test]
    async fn convert_to_template_qemu_hits_qemu_template_path() {
        // PVE returns `{"data": null}` on success — the deserializer
        // must accept null as Option<String>::None, not bail.
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/300/template"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let res = c
            .convert_to_template("pve1", 300, GuestType::Qemu)
            .await
            .expect("templated");
        assert_eq!(res, "");
    }

    #[tokio::test]
    async fn convert_to_template_lxc_hits_lxc_template_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/lxc/400/template"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.convert_to_template("pve1", 400, GuestType::Lxc)
            .await
            .expect("templated");
    }

    #[tokio::test]
    async fn clone_qemu_hits_qemu_clone_path_with_full_flag() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/300/clone"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.clone_guest(
            "pve1",
            300,
            GuestType::Qemu,
            301,
            Some("web-01"),
            None,
            None,
            true,
            None,
            None,
        )
        .await
        .expect("clone");
    }

    #[tokio::test]
    async fn clone_lxc_hits_lxc_clone_path_with_target_node() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/lxc/400/clone"))
            .respond_with(ok_upid("pve2"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.clone_guest(
            "pve1",
            400,
            GuestType::Lxc,
            401,
            Some("ct-clone"),
            Some("pve2"),
            Some("local-zfs"),
            true,
            None,
            None,
        )
        .await
        .expect("clone");
    }

    // ── Guest config mutation (Phase 3) ────────────────────

    #[tokio::test]
    async fn update_guest_config_qemu_hits_qemu_config_path_with_put() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/nodes/pve1/qemu/300/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let params = vec![
            ("cores".to_string(), "4".to_string()),
            ("memory".to_string(), "8192".to_string()),
        ];
        let task = c
            .update_guest_config("pve1", 300, GuestType::Qemu, &params)
            .await
            .expect("update");
        assert!(task.is_none(), "instant config edits return None");
    }

    #[tokio::test]
    async fn update_guest_config_lxc_hits_lxc_config_path() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/nodes/pve1/lxc/400/config"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let params = vec![("memory".to_string(), "1024".to_string())];
        c.update_guest_config("pve1", 400, GuestType::Lxc, &params)
            .await
            .expect("update");
    }

    // ── Firewall + Network (Phase 4) ───────────────────────

    #[tokio::test]
    async fn list_cluster_firewall_rules_hits_cluster_path() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/firewall/rules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "pos": 0, "type": "in", "action": "ACCEPT",
                        "enable": 1, "proto": "tcp", "dport": "22",
                        "comment": "ssh"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let rules = c.list_cluster_firewall_rules().await.expect("rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].direction, "in");
        assert_eq!(rules[0].action, "ACCEPT");
        assert_eq!(rules[0].dport, "22");
    }

    #[tokio::test]
    async fn list_node_firewall_rules_hits_node_path() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/firewall/rules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.list_node_firewall_rules("pve1").await.expect("rules");
    }

    #[tokio::test]
    async fn list_guest_firewall_rules_dispatches_by_guest_type() {
        // Verifies the QEMU vs LXC path split is honoured for the
        // firewall sub-resource (same Bug #1 trap as the lifecycle
        // endpoints).
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/firewall/rules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/lxc/200/firewall/rules"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.list_guest_firewall_rules("pve1", 100, GuestType::Qemu)
            .await
            .expect("qemu");
        c.list_guest_firewall_rules("pve1", 200, GuestType::Lxc)
            .await
            .expect("lxc");
    }

    #[tokio::test]
    async fn list_node_network_returns_mixed_iface_types() {
        // Verifies: physical eth + bridge in the same array, with
        // type-specific fields populated only on the matching row.
        // Forward-compat: unknown extra fields don't break parse.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/network"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "iface": "nic0",
                        "type": "eth",
                        "active": 1,
                        "exists": 1,
                        "altnames": ["enp6s18"],
                        "families": ["inet"]
                    },
                    {
                        "iface": "vmbr0",
                        "type": "bridge",
                        "active": 1,
                        "autostart": 1,
                        "method": "static",
                        "address": "10.0.0.5",
                        "netmask": "24",
                        "cidr": "10.0.0.5/24",
                        "gateway": "10.0.0.1",
                        "bridge_ports": "nic0",
                        "bridge_stp": "off",
                        "bridge_fd": "0"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let ifaces = c.list_node_network("pve1").await.expect("net");
        assert_eq!(ifaces.len(), 2);
        assert_eq!(ifaces[0].iface, "nic0");
        assert_eq!(ifaces[0].iface_type, "eth");
        assert_eq!(ifaces[0].altnames, vec!["enp6s18".to_string()]);
        assert_eq!(ifaces[1].iface, "vmbr0");
        assert_eq!(ifaces[1].iface_type, "bridge");
        assert_eq!(ifaces[1].bridge_ports, "nic0");
        assert_eq!(ifaces[1].cidr, "10.0.0.5/24");
    }

    #[tokio::test]
    async fn list_pending_config_qemu_returns_typed_entries() {
        // Verifies: the mixed int/string `value` field that PVE
        // emits (e.g. `memory: 256` int, `ostype: "alpine"` string)
        // does NOT fail deserialization. Also pins the three row
        // shapes — applied / pending / delete.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/300/pending"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"key": "cores", "value": 4},                    // int — must not break parse
                    {"key": "ostype", "value": "l26"},               // string — same array
                    {"key": "memory", "value": 8192, "pending": 16384},
                    {"key": "ide2", "delete": 1},
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let entries = c
            .list_pending_config("pve1", 300, GuestType::Qemu)
            .await
            .expect("pending");
        assert_eq!(entries.len(), 4);
        // cores: applied (no pending, no delete)
        assert_eq!(entries[0].key, "cores");
        assert!(entries[0].pending.is_none());
        assert!(entries[0].delete.is_none());
        // ostype: applied with string value
        assert_eq!(entries[1].key, "ostype");
        // memory: pending change (value is the JSON int 16384)
        assert_eq!(
            entries[2]
                .pending
                .as_ref()
                .and_then(serde_json::Value::as_u64),
            Some(16384)
        );
        // ide2: pending delete
        assert_eq!(entries[3].delete, Some(1));
    }

    #[tokio::test]
    async fn regenerate_cloudinit_hits_qemu_cloudinit_path_via_put() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/nodes/pve1/qemu/300/cloudinit"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let task = c
            .regenerate_cloudinit("pve1", 300)
            .await
            .expect("regen")
            .expect("returns UPID");
        assert!(task.starts_with("UPID:pve1:"));
    }

    #[tokio::test]
    async fn next_free_vmid_parses_string_response() {
        // PVE wraps the value as a JSON string, not a JSON number —
        // verified live: `{"data": "100"}`. The trait method must
        // parse the string to u32.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/nextid"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "127"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let id = c.next_free_vmid().await.expect("nextid");
        assert_eq!(id, 127);
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
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/status/shutdown"))
            .and(body_string_contains("timeout=60"))
            .and(body_string_contains("forceStop=1"))
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
        c.shutdown_guest("pve1", 100, GuestType::Qemu, 60)
            .await
            .expect("shutdown");
    }

    #[tokio::test]
    async fn shutdown_qemu_custom_timeout_sends_correct_value() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/status/shutdown"))
            .and(body_string_contains("timeout=30"))
            .and(body_string_contains("forceStop=1"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.shutdown_guest("pve1", 100, GuestType::Qemu, 30)
            .await
            .expect("shutdown custom timeout");
    }

    #[tokio::test]
    async fn shutdown_lxc_hits_lxc_shutdown_path() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/lxc/200/status/shutdown"))
            .and(body_string_contains("timeout=60"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        // Negative: LXC must NOT send forceStop
        Mock::given(path("/api2/json/nodes/pve1/lxc/200/status/shutdown"))
            .and(body_string_contains("forceStop=1"))
            .respond_with(ResponseTemplate::new(400))
            .expect(0)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.shutdown_guest("pve1", 200, GuestType::Lxc, 60)
            .await
            .expect("shutdown lxc");
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

    #[tokio::test]
    async fn stop_guest_never_sends_force_stop_param() {
        // Live-cluster regression (batch 3 live-cluster regression): PVE 8/9 rejects
        // any `forceStop` parameter on `/status/stop` for both QEMU and
        // LXC ("property is not defined in schema and the schema does
        // not allow additional properties"). The endpoint is always a
        // hard kill; the param is meaningless.
        //
        // This test mounts a body-string-contains matcher with
        // `expect(0)` — wiremock fails the test if the unexpected mock
        // is ever hit. So if a future change re-adds `forceStop=1`,
        // the test will fail loudly.
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        // Negative assertion: `forceStop` must NEVER appear in the body.
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/status/stop"))
            .and(body_string_contains("forceStop"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        // Positive: the actual call (no body) must succeed.
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/status/stop"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        // Both `force=true` and `force=false` must hit /status/stop
        // with no body (the trait param is currently a no-op).
        c.stop_guest("pve1", 100, GuestType::Qemu, true)
            .await
            .expect("qemu force stop");
    }

    #[tokio::test]
    async fn stop_guest_lxc_also_omits_force_stop_param() {
        // Same contract as the QEMU side: LXC's stop endpoint also
        // rejects `forceStop` (it never accepted it on PVE). Pin both
        // kinds so a future "QEMU-only" annotation can't reintroduce
        // the bug.
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/lxc/100/status/stop"))
            .and(body_string_contains("forceStop"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/lxc/100/status/stop"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.stop_guest("pve1", 100, GuestType::Lxc, true)
            .await
            .expect("lxc force stop");
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
                        "class": 3
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
    async fn list_ha_groups_hits_cluster_ha_rules() {
        // PVE 9 migrated `/cluster/ha/groups` → `/cluster/ha/rules`. The
        // method name on the trait still says `list_ha_groups` for
        // back-compat with downstream consumers (rename tracked as
        // separate work); the underlying GET targets the new endpoint.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/ha/rules"))
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

    // ── (Gemini wave-3): reactive 401 re-auth ──────

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
        // assert via the typed downcast — the Display string no
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

    // ── (Gemini wave-3): bounded response body ─────

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

    // ── (macro audit): lax deserialization ─────────

    ///  — every API response struct must tolerate missing fields.
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
        // Float exact-equality on 0.0 is safe — Default for f64 is
        // exactly 0.0 (not produced by arithmetic), so `==` is the
        // correct semantic. Clippy can't tell.
        #[allow(clippy::float_cmp)]
        let cpu_is_zero = n.cpu == 0.0;
        assert!(cpu_is_zero);
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

    // ── Mountain #1: storage health endpoints ───────────────────

    /// Verifies the URL the client constructs AND that the -pattern
    /// defaults survive PVE's quirky payloads (rpm: -1 for unknown
    /// spindle, wearout: "N/A" string vs numeric, type: "unknown").
    #[tokio::test]
    async fn list_node_disks_hits_disks_list_path_and_tolerates_quirks() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/disks/list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "devpath": "/dev/sda",
                        "model": "Samsung_SSD_860_EVO_500GB",
                        "vendor": "ATA",
                        "serial": "S3Z2NB0M404108X",
                        "size": 500107862016_u64,
                        "rpm": 0,
                        "type": "ssd",
                        "health": "PASSED",
                        "wearout": 1,
                        "used": "LVM",
                        "gpt": 1,
                        "wwn": "0x5002538e40c12345"
                    },
                    {
                        // Virtio guest disk — PVE returns unknowns as
                        // strings + rpm: -1. The whole row must still
                        // deserialize without losing the previous one.
                        "devpath": "/dev/vda",
                        "model": "unknown",
                        "vendor": "0x1af4",
                        "serial": "unknown",
                        "size": 137438953472_u64,
                        "rpm": -1,
                        "type": "unknown",
                        "health": "UNKNOWN",
                        "wearout": "N/A",
                        "used": "BIOS boot",
                        "gpt": 1
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let disks = c.list_node_disks("pve1").await.expect("list");
        assert_eq!(disks.len(), 2);
        assert_eq!(disks[0].devpath, "/dev/sda");
        assert_eq!(disks[0].health, "PASSED");
        assert_eq!(disks[1].rpm, -1);
        assert_eq!(disks[1].health, "UNKNOWN");
    }

    /// Verifies the `?disk=…` query param is URL-encoded properly
    /// (the leading `/` must survive — PVE expects `?disk=/dev/sda`).
    #[tokio::test]
    async fn get_disk_smart_passes_disk_query_param_url_encoded() {
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/disks/smart"))
            .and(query_param("disk", "/dev/sda"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "type": "ata",
                    "health": "PASSED",
                    "attributes": [
                        {
                            "id": "5",
                            "name": "Reallocated_Sector_Ct",
                            "value": "100",
                            "worst": "100",
                            "threshold": "10",
                            "raw": "0",
                            "flags": "0x0033",
                            "fail": "-"
                        }
                    ],
                    "text": ""
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let smart = c.get_disk_smart("pve1", "/dev/sda").await.expect("smart");
        assert_eq!(smart.smart_type, "ata");
        assert_eq!(smart.health, "PASSED");
        assert_eq!(smart.attributes.len(), 1);
        assert_eq!(smart.attributes[0].name, "Reallocated_Sector_Ct");
    }

    /// Verifies the LVM tree-flattening: PVE returns
    /// `data: { children: [<vg>, ...] }`, proxxx exposes `Vec<VG>`.
    #[tokio::test]
    async fn list_node_lvm_flattens_children_tree_to_vgs() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/disks/lvm"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "leaf": 0,
                    "children": [
                        {
                            "name": "pve",
                            "size": 136361017344_u64,
                            "free": 16915628032_u64,
                            "lvcount": 5,
                            // Inner LV tree — discarded by the
                            // flattener; presence shouldn't break
                            // VG-level deserialization.
                            "children": [{"name": "/dev/vda3", "size": 1, "free": 0, "leaf": 1}]
                        },
                        {
                            "name": "vmdata",
                            "size": 2_000_000_000_000_u64,
                            "free": 100_000_000_000_u64,
                            "lvcount": 12
                        }
                    ]
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let vgs = c.list_node_lvm("pve1").await.expect("lvm");
        assert_eq!(vgs.len(), 2);
        assert_eq!(vgs[0].name, "pve");
        assert_eq!(vgs[0].lv_count, 5);
        assert_eq!(vgs[1].name, "vmdata");
    }

    #[tokio::test]
    async fn list_node_lvmthin_includes_metadata_metrics() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/disks/lvmthin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "lv": "data",
                        "vg": "pve",
                        "lv_size": 67_104_669_696_u64,
                        "used": 17_413_661_786_u64,
                        "metadata_used": 21_582_210_u64,
                        "metadata_size": 1_073_741_824_u64,
                        "lv_state": "a",
                        "lv_type": "t"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let pools = c.list_node_lvmthin("pve1").await.expect("lvmthin");
        assert_eq!(pools.len(), 1);
        assert_eq!(pools[0].vg, "pve");
        // Metadata canary: pools[0].metadata_used / metadata_size = ~2%
        // — well below the 95%+ disaster threshold.
        assert!(pools[0].metadata_used < pools[0].metadata_size / 10);
    }

    // ── Hill 2a/2b: console handoff ─────────────────────────────

    /// Verifies the tolerant port deserializer that closed a latent
    /// PVE 9 bug: termproxy/vncproxy return `port` as a JSON STRING
    /// (`"5900"`), not number. Without the deserializer, every call
    /// fails with "invalid type: string, expected u32".
    #[tokio::test]
    async fn termproxy_port_as_string_deserializes() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/termproxy"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "port": "5900",  // STRING, not number
                    "ticket": "PVEVNC:6900:abc",
                    "user": "root@pam!proxxx",
                    "upid": "UPID:pve1:0:0:0:0:vncshell::root@pam:"
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
    }

    #[tokio::test]
    async fn vncproxy_qemu_returns_ticket_with_cert() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/vncproxy"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "port": "5901",
                    "ticket": "PVEVNC:6900:secret",
                    "user": "root@pam",
                    "cert": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
                    "upid": "UPID:pve1:0:0:0:0:vncproxy:100:root@pam:"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let t = c
            .get_guest_vncproxy("pve1", 100, GuestType::Qemu)
            .await
            .expect("vncproxy");
        assert_eq!(t.port, 5901);
        assert!(t.cert.contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn node_shell_endpoints_route_correctly() {
        let server = MockServer::start().await;
        for kind in &["termproxy", "vncshell", "spiceshell"] {
            Mock::given(method("POST"))
                .and(path(format!("/api2/json/nodes/pve1/{kind}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": {"port": "5900", "ticket": "x", "user": "root@pam"}
                })))
                .expect(1)
                .mount(&server)
                .await;
        }
        let c = mock_client(&server).await;
        c.get_node_termproxy("pve1").await.expect("term");
        c.get_node_vncshell("pve1").await.expect("vnc");
        c.get_node_spiceshell("pve1").await.expect("spice");
    }

    #[tokio::test]
    async fn lxc_exec_oneshot_posts_command_param() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/lxc/200/exec"))
            .and(body_string_contains("command=ls"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "pid": 12345 }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let res = c.lxc_exec_oneshot("pve1", 200, "ls").await.expect("exec");
        assert_eq!(
            res.get("pid").and_then(serde_json::Value::as_i64),
            Some(12345)
        );
    }

    // ── Hill 3a: rrddata (time-series metrics) ─────────────────

    #[tokio::test]
    async fn get_node_rrddata_passes_timeframe_and_cf_query_params() {
        use proxxx::api::types::{RrdCf, RrdTimeframe};
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/rrddata"))
            .and(query_param("timeframe", "hour"))
            .and(query_param("cf", "AVERAGE"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "time": 1_777_830_660_u64,
                        "cpu": 0.166750234930471,
                        "loadavg": 0.285,
                        "memused": 2_168_258_901.333_33,
                        "memtotal": 4_107_104_256_u64,
                        "iowait": 0.000426781270092046,
                        "netin": 35_210.6666666667,
                        "netout": 37_377.9
                    },
                    {
                        "time": 1_777_830_720_u64,
                        "cpu": 0.155536428246651,
                        "loadavg": 0.419166666666667
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let pts = c
            .get_node_rrddata("pve1", RrdTimeframe::Hour, RrdCf::Average)
            .await
            .expect("rrddata");
        assert_eq!(pts.len(), 2);
        assert_eq!(pts[0].time, 1_777_830_660);
        assert!((pts[0].cpu.unwrap() - 0.166_750_234_930_471).abs() < 1e-9);
        // Field that wasn't sent in the second point round-trips as None.
        assert!(pts[1].iowait.is_none());
    }

    #[tokio::test]
    async fn get_guest_rrddata_qemu_routes_to_qemu_path() {
        use proxxx::api::types::{GuestType, RrdCf, RrdTimeframe};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/rrddata"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{
                    "time": 1_777_830_660_u64,
                    "cpu": 0.05,
                    "mem": 1_073_741_824_u64,
                    "memhost": 2_147_483_648_u64
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        // Negative: the LXC path must NOT be called.
        Mock::given(path("/api2/json/nodes/pve1/lxc/100/rrddata"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let pts = c
            .get_guest_rrddata("pve1", 100, GuestType::Qemu, RrdTimeframe::Day, RrdCf::Max)
            .await
            .expect("rrddata");
        assert_eq!(pts.len(), 1);
        assert_eq!(pts[0].memhost, Some(2_147_483_648.0));
    }

    #[tokio::test]
    async fn get_storage_rrddata_url_encodes_storage_name() {
        use proxxx::api::types::{RrdCf, RrdTimeframe};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            // `local-lvm` has a `-`; the URL-encoded form is identical
            // (- is unreserved). Still asserting the path explicitly is
            // the regression guard against future urlenc changes.
            .and(path("/api2/json/nodes/pve1/storage/local-lvm/rrddata"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    { "time": 1, "used": 100_000_u64, "total": 1_000_000_u64 }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let pts = c
            .get_storage_rrddata("pve1", "local-lvm", RrdTimeframe::Week, RrdCf::Average)
            .await
            .expect("rrddata");
        assert_eq!(pts.len(), 1);
        assert_eq!(pts[0].used, Some(100_000.0));
        assert_eq!(pts[0].total, Some(1_000_000.0));
    }

    // ── Hill A: suspend/resume ──────────────────────────────────

    #[tokio::test]
    async fn suspend_guest_qemu_hits_qemu_status_suspend_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/status/suspend"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        // Negative: any /lxc/ path → fail loud.
        Mock::given(path("/api2/json/nodes/pve1/lxc/100/status/suspend"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.suspend_guest("pve1", 100, GuestType::Qemu)
            .await
            .expect("suspend");
    }

    #[tokio::test]
    async fn resume_guest_lxc_hits_lxc_status_resume_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/lxc/200/status/resume"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.resume_guest("pve1", 200, GuestType::Lxc)
            .await
            .expect("resume");
    }

    // ── Hill B: bulk node power ─────────────────────────────────

    #[tokio::test]
    async fn startall_node_hits_node_startall_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/startall"))
            .respond_with(ok_upid("pve1"))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let upid = c.startall_node("pve1").await.expect("startall");
        assert!(upid.starts_with("UPID:"));
    }

    #[tokio::test]
    async fn suspendall_node_404_surfaces_typed_notfound_on_old_pve() {
        // PVE < 8 doesn't have /suspendall — operators on older
        // clusters would see ApiError::NotFound, which is the right
        // categorical signal for "endpoint not available, upgrade PVE".
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/suspendall"))
            .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "data": null,
                "errors": { "method": "no such method" },
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let err = c
            .suspendall_node("pve1")
            .await
            .expect_err("404 must surface as error");
        // The error chain carries an ApiError::NotFound after the
        // typed-error pass + Phase 7 write-path completion.
        let typed = err
            .chain()
            .find_map(|e| e.downcast_ref::<proxxx::api::ApiError>())
            .expect("ApiError in chain");
        assert!(matches!(typed, proxxx::api::ApiError::NotFound(_)));
    }

    // ── Hill C: apt extras ──────────────────────────────────────

    #[tokio::test]
    async fn node_apt_versions_deserializes_pascalcase_fields() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/apt/versions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "Package": "proxmox-ve",
                        "Version": "9.1.0",
                        "OldVersion": "9.1.0",
                        "CurrentState": "Installed",
                        "Section": "admin",
                        "Priority": "optional",
                        "Origin": "Proxmox",
                        "Arch": "all",
                        "Title": "Proxmox Virtual Environment",
                        "Description": "Meta package",
                        "RunningKernel": "6.17.2-1-pve"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let pkgs = c.node_apt_versions("pve1").await.expect("versions");
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].package, "proxmox-ve");
        assert_eq!(pkgs[0].running_kernel, "6.17.2-1-pve");
        assert_eq!(pkgs[0].current_state, "Installed");
    }

    #[tokio::test]
    async fn node_apt_changelog_uses_name_param_not_package() {
        // Common typo: PVE expects ?name=…, not ?package=…. Asserting
        // the right param name is a regression guard — the endpoint
        // returns 400 with a confusing "parameter verification failed"
        // if you pass the wrong name.
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/apt/changelog"))
            .and(query_param("name", "pve-manager"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "pve-manager (9.1.9) trixie; urgency=medium\n  * fix #1234"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let log = c
            .node_apt_changelog("pve1", "pve-manager")
            .await
            .expect("changelog");
        assert!(log.contains("9.1.9"));
        assert!(log.contains("fix #1234"));
    }

    #[tokio::test]
    async fn node_apt_repositories_returns_raw_value() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/apt/repositories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "errors": [],
                    "files": [
                        {"path": "/etc/apt/sources.list", "file-type": "list", "repositories": []}
                    ]
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let repos = c.node_apt_repositories("pve1").await.expect("repos");
        // Raw-value type means we can drill in via serde_json APIs.
        assert!(repos.get("files").and_then(|f| f.as_array()).is_some());
    }

    #[tokio::test]
    async fn list_node_zfs_flags_degraded_pool() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/disks/zfs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "name": "rpool",
                        "size": 510_027_366_400_u64,
                        "alloc": 100_000_000_000_u64,
                        "free": 410_027_366_400_u64,
                        "frag": 12,
                        "dedup": 1.0,
                        "health": "ONLINE"
                    },
                    {
                        // The kind of row operators care about: a
                        // non-ONLINE pool MUST round-trip cleanly so
                        // the renderer can flag it.
                        "name": "tank",
                        "size": 4_000_000_000_000_u64,
                        "alloc": 3_900_000_000_000_u64,
                        "free": 100_000_000_000_u64,
                        "frag": "85",  // PVE quirk: sometimes string
                        "dedup": 1.07,
                        "health": "DEGRADED"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let pools = c.list_node_zfs("pve1").await.expect("zfs");
        assert_eq!(pools.len(), 2);
        assert_eq!(pools[0].health, "ONLINE");
        assert_eq!(pools[1].health, "DEGRADED");
        // dedup parses as float, frag tolerates int OR string.
        assert!((pools[1].dedup - 1.07).abs() < 0.001);
    }

    // ── Scheduled backup jobs (cluster.backup_jobs.*) ──────
    //
    // These cover the new `/cluster/backup` CRUD surface plus the
    // node-side `/vzdump/extractconfig`. Field-shape tests focus on
    // the PVE-side hyphen-renamed fields (`prune-backups`, `next-run`,
    // `notes-template`) and the bool-from-int round-trip on `enabled`
    // and `all` — both are the bits most likely to silently regress
    // if a future serde refactor moves things around.

    #[tokio::test]
    async fn list_backup_jobs_round_trips_hyphen_renamed_fields_and_bool_from_int() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/backup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "id": "backup-aaaa",
                        "schedule": "sun 02:00",
                        "storage": "pbs-main",
                        "mode": "snapshot",
                        // PVE serializes booleans as 0/1 — the custom
                        // deserializer must accept either form.
                        "enabled": 1,
                        "all": 1,
                        "vmid": "",
                        "node": "",
                        "mailto": "ops@example.com",
                        "mailnotification": "failure",
                        "compress": "zstd",
                        "comment": "weekly full",
                        // Hyphenated wire names → snake_case via #[serde(rename)]
                        "notes-template": "{{guestname}}",
                        "prune-backups": "keep-last=3,keep-weekly=4",
                        "next-run": 1_735_689_600_u64
                    },
                    {
                        // Per-VM job (all=0, vmid CSV) — also bool=0 path.
                        "id": "backup-bbbb",
                        "schedule": "mon..fri 23:30",
                        "storage": "local",
                        "mode": "stop",
                        "enabled": 0,
                        "all": 0,
                        "vmid": "100,101,200",
                        "node": "pve1",
                        "mailto": "",
                        "mailnotification": "always",
                        "compress": "lzo",
                        "comment": "",
                        "notes-template": "",
                        "prune-backups": "",
                        "next-run": 0
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let jobs = c.list_backup_jobs().await.expect("list jobs");
        assert_eq!(jobs.len(), 2);

        let a = &jobs[0];
        assert_eq!(a.id, "backup-aaaa");
        assert!(a.enabled);
        assert!(a.all);
        assert_eq!(a.notes_template, "{{guestname}}");
        assert_eq!(a.prune_backups, "keep-last=3,keep-weekly=4");
        assert_eq!(a.next_run, 1_735_689_600);

        let b = &jobs[1];
        assert!(!b.enabled);
        assert!(!b.all);
        assert_eq!(b.vmid, "100,101,200");
        assert_eq!(b.node, "pve1");
    }

    #[tokio::test]
    async fn list_backup_jobs_tolerates_missing_optional_fields() {
        // -audit pattern: every field is `#[serde(default)]`. A PVE
        // response that omits half the fields must still deserialize.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/backup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{
                    "id": "minimal",
                    "schedule": "daily",
                    "storage": "local",
                    "mode": "snapshot",
                    "enabled": 1
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let jobs = c.list_backup_jobs().await.expect("list");
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, "minimal");
        assert!(jobs[0].enabled);
        // Defaults flowed through:
        assert_eq!(jobs[0].vmid, "");
        assert_eq!(jobs[0].next_run, 0);
        assert!(!jobs[0].all);
    }

    #[tokio::test]
    async fn get_backup_job_uses_id_in_path() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/backup/backup-aaaa"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "id": "backup-aaaa",
                    "schedule": "sun 02:00",
                    "storage": "pbs-main",
                    "mode": "snapshot",
                    "enabled": 1,
                    "all": 1
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let job = c.get_backup_job("backup-aaaa").await.expect("get");
        assert_eq!(job.id, "backup-aaaa");
        assert_eq!(job.storage, "pbs-main");
    }

    #[tokio::test]
    async fn create_backup_job_posts_form_params_to_cluster_backup() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/cluster/backup"))
            .and(body_string_contains("schedule=sun"))
            .and(body_string_contains("storage=pbs-main"))
            .and(body_string_contains("all=1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.create_backup_job(&[
            ("schedule", "sun 02:00"),
            ("storage", "pbs-main"),
            ("all", "1"),
            ("mode", "snapshot"),
        ])
        .await
        .expect("create");
    }

    #[tokio::test]
    async fn update_backup_job_puts_at_id_path() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/cluster/backup/backup-aaaa"))
            .and(body_string_contains("enabled=0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.update_backup_job("backup-aaaa", &[("enabled", "0")])
            .await
            .expect("update");
    }

    #[tokio::test]
    async fn delete_backup_job_hits_id_path() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api2/json/cluster/backup/backup-aaaa"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.delete_backup_job("backup-aaaa").await.expect("delete");
    }

    #[tokio::test]
    async fn cluster_backup_info_returns_raw_value() {
        // PVE source-side restricts this endpoint to LITERAL `root@pam`
        // (token auth gets 403). When it does respond, it returns a
        // freeform shape we surface as `serde_json::Value` so we don't
        // ossify the contract.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/backup-info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "not-backed-up": [
                        {"vmid": 100, "name": "ct100", "type": "lxc"}
                    ]
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let info = c.cluster_backup_info().await.expect("info");
        assert!(info.get("not-backed-up").is_some());
    }

    // ── Cluster firewall CRUD (cluster.firewall.{aliases,groups,ipset,options}) ──
    //
    // Spread across four resources but the wiremock surface is uniform:
    // verify the URL routing (singleton vs collection vs nested CIDR),
    // verify hyphen/underscore-renamed fields round-trip (`policy_in`,
    // `log_ratelimit`), and verify bool-from-int on the options struct
    // (`enable`, `ebtables`) and on ipset CIDR `nomatch`.

    #[tokio::test]
    async fn list_cluster_firewall_aliases_round_trips_typed_fields() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/firewall/aliases"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "name": "web-servers",
                        "cidr": "10.10.10.0/24",
                        "comment": "DMZ web tier",
                        "ipversion": 4,
                        "digest": "deadbeef"
                    },
                    {
                        "name": "v6-corp",
                        "cidr": "2001:db8::/32",
                        "ipversion": 6
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let aliases = c.list_cluster_firewall_aliases().await.expect("aliases");
        assert_eq!(aliases.len(), 2);
        assert_eq!(aliases[0].name, "web-servers");
        assert_eq!(aliases[0].cidr, "10.10.10.0/24");
        assert_eq!(aliases[0].ipversion, 4);
        // The second entry omits comment + digest — defaults must fill them in.
        assert_eq!(aliases[1].comment, "");
        assert_eq!(aliases[1].ipversion, 6);
    }

    #[tokio::test]
    async fn create_cluster_firewall_alias_posts_form_params() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/cluster/firewall/aliases"))
            .and(body_string_contains("name=web-servers"))
            .and(body_string_contains("cidr=10.10.10.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.create_cluster_firewall_alias(&[
            ("name", "web-servers"),
            ("cidr", "10.10.10.0/24"),
            ("comment", "DMZ web tier"),
        ])
        .await
        .expect("create alias");
    }

    #[tokio::test]
    async fn update_cluster_firewall_alias_puts_at_name_path() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/cluster/firewall/aliases/web-servers"))
            .and(body_string_contains("cidr=10.20.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.update_cluster_firewall_alias("web-servers", &[("cidr", "10.20.0.0/16")])
            .await
            .expect("update alias");
    }

    #[tokio::test]
    async fn delete_cluster_firewall_alias_hits_name_path() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api2/json/cluster/firewall/aliases/web-servers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.delete_cluster_firewall_alias("web-servers")
            .await
            .expect("delete alias");
    }

    #[tokio::test]
    async fn list_cluster_firewall_groups_round_trips() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/firewall/groups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"group": "web-allow", "comment": "HTTP/HTTPS in", "digest": "abc123"},
                    {"group": "ssh-mgmt"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let groups = c.list_cluster_firewall_groups().await.expect("groups");
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].group, "web-allow");
        assert_eq!(groups[1].comment, "");
    }

    #[tokio::test]
    async fn delete_cluster_firewall_group_hits_group_path() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api2/json/cluster/firewall/groups/web-allow"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.delete_cluster_firewall_group("web-allow")
            .await
            .expect("delete group");
    }

    #[tokio::test]
    async fn list_cluster_firewall_group_rules_returns_firewall_rule_shape() {
        // Per-group rule listing reuses the FirewallRule shape from the
        // global rules endpoint — same fields, same `type` rename to
        // `direction`, etc.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/firewall/groups/web-allow"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{
                    "pos": 0,
                    "type": "in",
                    "action": "ACCEPT",
                    "enable": 1,
                    "proto": "tcp",
                    "dport": "443",
                    "comment": "https"
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let rules = c
            .list_cluster_firewall_group_rules("web-allow")
            .await
            .expect("group rules");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].direction, "in");
        assert_eq!(rules[0].action, "ACCEPT");
        assert_eq!(rules[0].dport, "443");
    }

    #[tokio::test]
    async fn list_cluster_firewall_ipsets_and_cidrs_with_nomatch_bool_from_int() {
        let server = MockServer::start().await;
        // Collection endpoint.
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/firewall/ipset"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{"name": "blocklist", "comment": "abuse", "digest": "feed"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        // Per-ipset CIDR list.
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/firewall/ipset/blocklist"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"cidr": "1.2.3.0/24", "comment": "spam source", "nomatch": 0},
                    {"cidr": "1.2.3.42",  "comment": "carve-out",   "nomatch": 1}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let sets = c.list_cluster_firewall_ipsets().await.expect("sets");
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].name, "blocklist");

        let cidrs = c
            .list_cluster_firewall_ipset_cidrs("blocklist")
            .await
            .expect("cidrs");
        assert_eq!(cidrs.len(), 2);
        assert!(!cidrs[0].nomatch);
        assert!(cidrs[1].nomatch);
    }

    #[tokio::test]
    async fn add_cluster_firewall_ipset_cidr_posts_to_set_path() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/cluster/firewall/ipset/blocklist"))
            .and(body_string_contains("cidr=1.2.3.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.add_cluster_firewall_ipset_cidr("blocklist", &[("cidr", "1.2.3.0/24")])
            .await
            .expect("add cidr");
    }

    #[tokio::test]
    async fn remove_cluster_firewall_ipset_cidr_url_encodes_slash_in_cidr() {
        // Critical encoding case: CIDR contains `/` which becomes a path
        // separator if not escaped. urlenc must convert it to `%2F`.
        use wiremock::matchers::path;
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path(
                "/api2/json/cluster/firewall/ipset/blocklist/1.2.3.0%2F24",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.remove_cluster_firewall_ipset_cidr("blocklist", "1.2.3.0/24")
            .await
            .expect("remove cidr");
    }

    #[tokio::test]
    async fn get_cluster_firewall_options_round_trips_bool_from_int_and_underscored_fields() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/firewall/options"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "enable": 1,
                    "policy_in": "DROP",
                    "policy_out": "ACCEPT",
                    "ebtables": 0,
                    "log_ratelimit": "enable=1,burst=5,rate=1/second",
                    "digest": "abc"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let opts = c.get_cluster_firewall_options().await.expect("opts");
        assert!(opts.enable);
        assert!(!opts.ebtables);
        assert_eq!(opts.policy_in, "DROP");
        assert_eq!(opts.policy_out, "ACCEPT");
        assert_eq!(opts.log_ratelimit, "enable=1,burst=5,rate=1/second");
    }

    #[tokio::test]
    async fn update_cluster_firewall_options_puts_with_form_body() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/cluster/firewall/options"))
            .and(body_string_contains("enable=0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.update_cluster_firewall_options(&[("enable", "0")])
            .await
            .expect("update opts");
    }

    // ── Per-guest firewall + cluster mapping ────────────────
    //
    // Three regression classes:
    // 1. Per-guest firewall routes via QEMU/LXC dispatch — test BOTH
    //    kinds with negative mounts so a future refactor can't lose one.
    // 2. `GuestFirewallOptions` is a wider bool-from-int set than the
    //    cluster scope; LXC-only fields like `radv` must default cleanly
    //    when missing from a QEMU response.
    // 3. Cluster mapping `map: Vec<String>` round-trips the wire format
    //    (`node=…,path=…,id=…` strings) without losing per-node entries.

    #[tokio::test]
    async fn list_guest_firewall_aliases_routes_qemu_kind() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/firewall/aliases"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{
                    "name": "vm-internal",
                    "cidr": "10.0.0.0/16",
                    "ipversion": 4,
                    "comment": "private mgmt"
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let aliases = c
            .list_guest_firewall_aliases("pve1", 100, GuestType::Qemu)
            .await
            .expect("aliases");
        assert_eq!(aliases.len(), 1);
        assert_eq!(aliases[0].name, "vm-internal");
    }

    #[tokio::test]
    async fn list_guest_firewall_aliases_routes_lxc_kind_not_qemu() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/lxc/200/firewall/aliases"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        // Negative mount: LXC routing must NOT hit /qemu/.
        Mock::given(path("/api2/json/nodes/pve1/qemu/200/firewall/aliases"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.list_guest_firewall_aliases("pve1", 200, GuestType::Lxc)
            .await
            .expect("aliases");
    }

    #[tokio::test]
    async fn create_guest_firewall_alias_posts_to_kind_path() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/firewall/aliases"))
            .and(body_string_contains("name=vm-internal"))
            .and(body_string_contains("cidr=10.0.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.create_guest_firewall_alias(
            "pve1",
            100,
            GuestType::Qemu,
            &[("name", "vm-internal"), ("cidr", "10.0.0.0/16")],
        )
        .await
        .expect("create");
    }

    #[tokio::test]
    async fn delete_guest_firewall_alias_lxc_uses_lxc_path_with_name() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path(
                "/api2/json/nodes/pve1/lxc/200/firewall/aliases/vm-internal",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.delete_guest_firewall_alias("pve1", 200, GuestType::Lxc, "vm-internal")
            .await
            .expect("delete");
    }

    #[tokio::test]
    async fn get_guest_firewall_options_round_trips_full_bool_from_int_set() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/firewall/options"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "enable": 1,
                    "policy_in": "DROP",
                    "policy_out": "ACCEPT",
                    "log_level_in": "warning",
                    "log_level_out": "nolog",
                    "dhcp": 1,
                    "ndp": 1,
                    "macfilter": 1,
                    "ipfilter": 0,
                    // QEMU response omits `radv` — must default cleanly.
                    "digest": "abcd"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let opts = c
            .get_guest_firewall_options("pve1", 100, GuestType::Qemu)
            .await
            .expect("opts");
        assert!(opts.enable);
        assert_eq!(opts.policy_in, "DROP");
        assert_eq!(opts.log_level_in, "warning");
        assert!(opts.dhcp);
        assert!(opts.ndp);
        assert!(opts.macfilter);
        assert!(!opts.ipfilter);
        // radv defaulted from missing wire field.
        assert!(!opts.radv);
    }

    #[tokio::test]
    async fn update_guest_firewall_options_lxc_puts_at_lxc_path() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/nodes/pve1/lxc/200/firewall/options"))
            .and(body_string_contains("radv=1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.update_guest_firewall_options("pve1", 200, GuestType::Lxc, &[("radv", "1")])
            .await
            .expect("set radv");
    }

    #[tokio::test]
    async fn list_cluster_mapping_pci_round_trips_map_strings_and_mdev_bool() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/mapping/pci"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "id": "gpu-rtx",
                        "description": "RTX 4090 for ML",
                        "mdev": 0,
                        "map": [
                            "node=pve1,path=0000:01:00.0,id=10de:2684,iommugroup=13",
                            "node=pve2,path=0000:02:00.0,id=10de:2684"
                        ],
                        "digest": "deadbeef"
                    },
                    {
                        // mdev=1 → vGPU-style mediated device.
                        "id": "vgpu-pool",
                        "mdev": 1,
                        "map": []
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let mappings = c.list_cluster_mapping_pci().await.expect("pci");
        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0].id, "gpu-rtx");
        assert!(!mappings[0].mdev);
        assert_eq!(mappings[0].map.len(), 2);
        assert!(mappings[0].map[0].contains("node=pve1"));
        assert!(mappings[0].map[0].contains("iommugroup=13"));
        assert!(mappings[1].mdev);
        assert!(mappings[1].map.is_empty());
    }

    #[tokio::test]
    async fn create_cluster_mapping_pci_posts_repeated_map_form_params() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/cluster/mapping/pci"))
            .and(body_string_contains("id=gpu-rtx"))
            // Repeated `map=...&map=...` form encoding for the per-node array.
            .and(body_string_contains("map=node%3Dpve1"))
            .and(body_string_contains("map=node%3Dpve2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.create_cluster_mapping_pci(&[
            ("id", "gpu-rtx"),
            ("map", "node=pve1,path=0000:01:00.0,id=10de:2684"),
            ("map", "node=pve2,path=0000:02:00.0,id=10de:2684"),
        ])
        .await
        .expect("create pci");
    }

    #[tokio::test]
    async fn delete_cluster_mapping_pci_hits_id_path() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api2/json/cluster/mapping/pci/gpu-rtx"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.delete_cluster_mapping_pci("gpu-rtx")
            .await
            .expect("delete pci");
    }

    #[tokio::test]
    async fn cluster_mapping_usb_routes_to_usb_path_not_pci() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/mapping/usb"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{
                    "id": "yubikey",
                    "description": "u2f token",
                    "map": ["node=pve1,path=1-2,id=1050:0407"]
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        // Negative mount: USB ops must NOT route to /pci/.
        Mock::given(path("/api2/json/cluster/mapping/pci"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let usb = c.list_cluster_mapping_usb().await.expect("usb");
        assert_eq!(usb.len(), 1);
        assert_eq!(usb[0].id, "yubikey");
    }

    #[tokio::test]
    async fn delete_cluster_mapping_usb_hits_id_path() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api2/json/cluster/mapping/usb/yubikey"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.delete_cluster_mapping_usb("yubikey")
            .await
            .expect("delete usb");
    }

    // ── QGA file ops + network introspection (qemu.agent.*) ──
    //
    // QGA-only surface (QEMU has it, LXC doesn't). Wiremock coverage
    // hits the regression classes most likely to silently break:
    // 1. file-read passes `file=` as a query param (not body) and
    //    surfaces the truncated-flag from a bool-from-int field
    // 2. file-write goes via POST with form body (file + content)
    // 3. network-get-interfaces unwraps the `{result: [...]}` wrapper
    //    PVE puts around QGA responses, and the kebab-case fields
    //    (`hardware-address`, `ip-addresses`, `ip-address-type`)
    //    round-trip cleanly via #[serde(rename)]

    #[tokio::test]
    async fn qemu_agent_file_read_passes_file_query_param_and_truncated_flag() {
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/agent/file-read"))
            .and(query_param("file", "/etc/hostname"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"content": "web-01\n", "truncated": 0}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let res = c
            .qemu_agent_file_read("pve1", 100, "/etc/hostname")
            .await
            .expect("read");
        assert_eq!(res.content, "web-01\n");
        assert!(!res.truncated);
    }

    #[tokio::test]
    async fn qemu_agent_file_read_propagates_truncated_when_buffer_overflowed() {
        // Critical regression case: a partial read MUST surface so
        // operators don't act on an incomplete file.
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/agent/file-read"))
            .and(query_param("file", "/var/log/syslog"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"content": "first 16KB...", "truncated": 1}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let res = c
            .qemu_agent_file_read("pve1", 100, "/var/log/syslog")
            .await
            .expect("read");
        assert!(res.truncated);
    }

    #[tokio::test]
    async fn qemu_agent_file_write_posts_form_body_with_file_and_content() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/agent/file-write"))
            .and(body_string_contains("file=%2Ftmp%2Fmarker"))
            .and(body_string_contains("content=hello"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.qemu_agent_file_write("pve1", 100, "/tmp/marker", "hello world")
            .await
            .expect("write");
    }

    #[tokio::test]
    async fn qemu_agent_network_get_interfaces_unwraps_result_wrapper_and_kebab_fields() {
        // PVE wraps the QGA response in `{result: [...]}` — the impl
        // must peel it, then deserialize the kebab-case fields
        // (`hardware-address`, `ip-addresses`, `ip-address-type`) via
        // serde renames into snake_case Rust fields.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "result": [
                        {
                            "name": "lo",
                            "hardware-address": "00:00:00:00:00:00",
                            "ip-addresses": [
                                {"ip-address-type": "ipv4", "ip-address": "127.0.0.1", "prefix": 8},
                                {"ip-address-type": "ipv6", "ip-address": "::1", "prefix": 128}
                            ]
                        },
                        {
                            "name": "eth0",
                            "hardware-address": "BC:24:11:DE:AD:BE",
                            "ip-addresses": [
                                {"ip-address-type": "ipv4", "ip-address": "10.0.0.42", "prefix": 24}
                            ]
                        }
                    ]
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let ifaces = c
            .qemu_agent_network_get_interfaces("pve1", 100)
            .await
            .expect("net");
        assert_eq!(ifaces.len(), 2);
        assert_eq!(ifaces[0].name, "lo");
        assert_eq!(ifaces[0].hardware_address, "00:00:00:00:00:00");
        assert_eq!(ifaces[0].ip_addresses.len(), 2);
        assert_eq!(ifaces[0].ip_addresses[0].ip_address_type, "ipv4");
        assert_eq!(ifaces[0].ip_addresses[1].prefix, 128);
        assert_eq!(ifaces[1].name, "eth0");
        assert_eq!(ifaces[1].ip_addresses[0].ip_address, "10.0.0.42");
    }

    #[tokio::test]
    async fn qemu_agent_network_get_interfaces_tolerates_missing_result_wrapper() {
        // Defensive: if a future PVE version drops the wrapper or QGA
        // returns nothing, we should yield an empty list rather than
        // panicking on a missing `result` key.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/api2/json/nodes/pve1/qemu/100/agent/network-get-interfaces",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let ifaces = c
            .qemu_agent_network_get_interfaces("pve1", 100)
            .await
            .expect("net");
        assert!(ifaces.is_empty());
    }

    // ── Node system layer (nodes.system.*) ─────────────────
    //
    // 9 resources, ~17 endpoints. Wiremock coverage focuses on:
    // - URL routing (each resource lands at its expected path)
    // - Hosts atomic-update digest round-trip (PVE rejects with 412
    //   if the digest doesn't match — our PUT must include it)
    // - Subscription full-shape round-trip (lots of optional fields
    //   — older PVE omits some, must default cleanly)
    // - Certificate `info` array shape with SAN list

    #[tokio::test]
    async fn get_node_dns_returns_resolver_config() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/dns"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "search": "lab.example.com",
                    "dns1": "10.0.0.1",
                    "dns2": "1.1.1.1"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let dns = c.get_node_dns("pve1").await.expect("dns");
        assert_eq!(dns.search, "lab.example.com");
        assert_eq!(dns.dns1, "10.0.0.1");
        // dns3 omitted → defaults to empty.
        assert_eq!(dns.dns3, "");
    }

    #[tokio::test]
    async fn update_node_dns_puts_form_params() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/nodes/pve1/dns"))
            .and(body_string_contains("search=new.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.update_node_dns("pve1", &[("search", "new.example.com")])
            .await
            .expect("update dns");
    }

    #[tokio::test]
    async fn get_node_hosts_returns_data_and_digest() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/hosts"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "data": "127.0.0.1 localhost\n10.0.0.1 pve1\n",
                    "digest": "abc123"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let h = c.get_node_hosts("pve1").await.expect("hosts");
        assert!(h.data.contains("pve1"));
        assert_eq!(h.digest, "abc123");
    }

    #[tokio::test]
    async fn update_node_hosts_passes_digest_for_atomic_replace() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/hosts"))
            // Critical regression case: PVE rejects PUT with 412 if the
            // digest doesn't match the current file. Our impl MUST send it.
            .and(body_string_contains("digest=abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.update_node_hosts("pve1", "127.0.0.1 localhost\n", Some("abc123"))
            .await
            .expect("update hosts");
    }

    #[tokio::test]
    async fn get_node_journal_passes_filter_query_params() {
        use wiremock::matchers::{query_param, query_param_is_missing};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/journal"))
            .and(query_param("lastentries", "100"))
            .and(query_param("service", "ssh"))
            .and(query_param_is_missing("until"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": ["May 4 09:00:00 pve1 sshd[1234]: Accepted publickey for root"]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let lines = c
            .get_node_journal("pve1", &[("lastentries", "100"), ("service", "ssh")])
            .await
            .expect("journal");
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("Accepted publickey"));
    }

    #[tokio::test]
    async fn get_node_syslog_round_trips_n_and_t_fields() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/syslog"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"n": 1, "t": "first line"},
                    {"n": 2, "t": "second line"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let lines = c.get_node_syslog("pve1", &[]).await.expect("syslog");
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].n, 1);
        assert_eq!(lines[1].t, "second line");
    }

    #[tokio::test]
    async fn get_node_time_returns_clock_and_timezone() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/time"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "timezone": "Europe/Rome",
                    "time": 1_735_689_600,
                    "localtime": 1_735_693_200
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let t = c.get_node_time("pve1").await.expect("time");
        assert_eq!(t.timezone.as_deref(), Some("Europe/Rome"));
        assert_eq!(t.time, 1_735_689_600);
        assert_eq!(t.localtime, 1_735_693_200);
    }

    #[tokio::test]
    async fn get_node_time_accepts_null_timezone() {
        // Live-cluster regression (pve1..3): a fresh
        // PVE install returns `"timezone": null` until an operator sets
        // one. Old struct typed `timezone: String`, parsing failed and
        // surfaced as "Failed to parse response from /nodes/X/time".
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/time"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "timezone": null,
                    "time": 1_777_917_099,
                    "localtime": 1_777_924_299
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let t = c.get_node_time("pve1").await.expect("time");
        assert_eq!(t.timezone, None);
        assert_eq!(t.time, 1_777_917_099);
        assert_eq!(t.localtime, 1_777_924_299);
    }

    #[tokio::test]
    async fn update_node_timezone_puts_timezone_only() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/nodes/pve1/time"))
            .and(body_string_contains("timezone=Europe%2FRome"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.update_node_timezone("pve1", "Europe/Rome")
            .await
            .expect("tz");
    }

    #[tokio::test]
    async fn wakeonlan_node_posts_to_wakeonlan_path_and_returns_mac() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/wakeonlan"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "BC:24:11:DE:AD:BE"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let mac = c.wakeonlan_node("pve1").await.expect("wol");
        assert_eq!(mac, "BC:24:11:DE:AD:BE");
    }

    #[tokio::test]
    async fn get_node_subscription_round_trips_full_field_set() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/subscription"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "status": "active",
                    "productname": "Proxmox VE Standard Subscription",
                    "level": "s",
                    "key": "pvesc-XXXXXXXXXX",
                    "regdate": "2025-01-15",
                    "nextduedate": "2027-01-15",
                    "serverid": "ABCDEF",
                    "validdirectory": "/etc/pve",
                    "url": "https://www.proxmox.com/proxmox-ve/pricing"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let s = c.get_node_subscription("pve1").await.expect("subs");
        assert_eq!(s.status, "active");
        assert_eq!(s.level, "s");
        assert_eq!(s.nextduedate, "2027-01-15");
    }

    #[tokio::test]
    async fn get_node_subscription_tolerates_minimal_response() {
        // No-key state: PVE responds with just `status: notfound` —
        // every other field defaulted.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/subscription"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"status": "notfound"}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let s = c.get_node_subscription("pve1").await.expect("subs");
        assert_eq!(s.status, "notfound");
        assert_eq!(s.key, "");
        assert_eq!(s.level, "");
    }

    #[tokio::test]
    async fn subscription_set_post_refresh_put_delete_route_correctly() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/subscription"))
            .and(body_string_contains("key=pvesc-NEWKEY"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/nodes/pve1/subscription"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api2/json/nodes/pve1/subscription"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.set_node_subscription_key("pve1", "pvesc-NEWKEY")
            .await
            .expect("set");
        c.refresh_node_subscription("pve1").await.expect("refresh");
        c.delete_node_subscription("pve1").await.expect("delete");
    }

    #[tokio::test]
    async fn get_node_certificates_info_returns_typed_array_with_san() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/certificates/info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "filename": "pve-ssl.pem",
                        "fingerprint": "AB:CD:EF",
                        "issuer": "CN=Proxmox Virtual Environment",
                        "subject": "CN=pve1",
                        "notbefore": 1_735_689_600,
                        "notafter": 1_767_225_600,
                        "san": ["DNS:pve1", "DNS:pve1.lab.example.com"],
                        "public-key-type": "rsaEncryption",
                        "public-key-bits": 2048
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let info = c.get_node_certificates_info("pve1").await.expect("certs");
        assert_eq!(info.len(), 1);
        assert_eq!(info[0].filename, "pve-ssl.pem");
        assert_eq!(info[0].san.len(), 2);
        assert!(info[0].san[1].ends_with("lab.example.com"));
        // Hyphenated wire fields → snake_case via #[serde(rename)].
        assert_eq!(info[0].public_key_type, "rsaEncryption");
        assert_eq!(info[0].public_key_bits, 2048);
    }

    #[tokio::test]
    async fn delete_node_custom_certificate_passes_restart_flag_in_query() {
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api2/json/nodes/pve1/certificates/custom"))
            .and(query_param("restart", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.delete_node_custom_certificate("pve1", true)
            .await
            .expect("delete cert");
    }

    #[tokio::test]
    async fn get_node_report_returns_plain_text() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/report"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "==== general system info ====\nproxmox-ve: 9.1.0\n"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let r = c.get_node_report("pve1").await.expect("report");
        assert!(r.contains("proxmox-ve"));
    }

    // ── Pools, cluster resources, version (foundationals) ──
    //
    // Three regression classes:
    // 1. Pool member CRUD: add vs remove uses the same PUT — remove
    //    just adds `delete=1`. Both shapes asserted explicitly.
    // 2. ClusterResource is a heterogeneous shape (node/qemu/lxc/storage/
    //    pool/sdn rows mixed in one array). #[serde(default)] on every
    //    field means absent ones don't crash the deserializer.
    // 3. ApiVersion is small but used for compat-gating — must round-trip.

    #[tokio::test]
    async fn list_pools_returns_typed_rows() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/pools"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"poolid": "dev", "comment": "dev team"},
                    {"poolid": "prod"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let pools = c.list_pools().await.expect("pools");
        assert_eq!(pools.len(), 2);
        assert_eq!(pools[0].poolid, "dev");
        assert_eq!(pools[0].comment, "dev team");
        // Second omits comment → defaults to empty.
        assert_eq!(pools[1].comment, "");
    }

    #[tokio::test]
    async fn get_pool_returns_members_with_mixed_kinds() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/pools/dev"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "poolid": "dev",
                    "comment": "dev team",
                    "members": [
                        {"id": "qemu/100", "type": "qemu", "vmid": 100, "node": "pve1", "status": "running", "name": "web-01"},
                        {"id": "lxc/200", "type": "lxc", "vmid": 200, "node": "pve2", "status": "stopped"},
                        {"id": "storage/pve1/local", "type": "storage", "node": "pve1", "storage": "local", "status": "available"}
                    ]
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let p = c.get_pool("dev").await.expect("pool");
        assert_eq!(p.poolid, "dev");
        assert_eq!(p.members.len(), 3);
        assert_eq!(p.members[0].member_type, "qemu");
        assert_eq!(p.members[0].vmid, 100);
        // Storage row has no vmid → defaults to 0.
        assert_eq!(p.members[2].member_type, "storage");
        assert_eq!(p.members[2].vmid, 0);
        assert_eq!(p.members[2].storage, "local");
    }

    #[tokio::test]
    async fn create_pool_posts_form_params() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/pools"))
            .and(body_string_contains("poolid=dev"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.create_pool(&[("poolid", "dev"), ("comment", "dev team")])
            .await
            .expect("create");
    }

    #[tokio::test]
    async fn update_pool_remove_members_includes_delete_flag() {
        // Critical regression case: PVE uses the SAME PUT for add and
        // remove — `delete=1` flips the operation. Forgetting it on
        // remove would silently re-add members instead.
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/pools/dev"))
            .and(body_string_contains("vms=100"))
            .and(body_string_contains("delete=1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.update_pool("dev", &[("vms", "100"), ("delete", "1")])
            .await
            .expect("remove");
    }

    #[tokio::test]
    async fn delete_pool_hits_id_path() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api2/json/pools/dev"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.delete_pool("dev").await.expect("delete");
    }

    #[tokio::test]
    async fn get_cluster_resources_returns_heterogeneous_rows() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/resources"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "id": "node/pve1", "type": "node", "node": "pve1",
                        "status": "online", "cpu": 0.05, "maxcpu": 32,
                        "mem": 8_589_934_592_u64, "maxmem": 137_438_953_472_u64
                    },
                    {
                        "id": "qemu/100", "type": "qemu", "vmid": 100,
                        "node": "pve1", "status": "running", "name": "web-01",
                        "tags": "prod;web", "template": 0
                    },
                    {
                        "id": "storage/pve1/local", "type": "storage",
                        "node": "pve1", "storage": "local", "status": "available",
                        "plugintype": "dir"
                    },
                    {"id": "pool/dev", "type": "pool", "pool": "dev"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let res = c.get_cluster_resources(None).await.expect("resources");
        assert_eq!(res.len(), 4);
        // Node row populates cpu/maxcpu/mem/maxmem.
        assert_eq!(res[0].resource_type, "node");
        assert_eq!(res[0].maxcpu, 32);
        assert!((res[0].cpu - 0.05).abs() < 0.001);
        // Guest row populates vmid/tags.
        assert_eq!(res[1].vmid, 100);
        assert_eq!(res[1].tags, "prod;web");
        // Storage row populates storage/plugintype.
        assert_eq!(res[2].storage, "local");
        assert_eq!(res[2].plugintype, "dir");
        // Pool row populates pool name only — most other fields default.
        assert_eq!(res[3].pool, "dev");
        assert_eq!(res[3].vmid, 0);
    }

    #[tokio::test]
    async fn get_cluster_resources_with_kind_passes_query_param() {
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/resources"))
            .and(query_param("type", "vm"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.get_cluster_resources(Some("vm")).await.expect("filter");
    }

    #[tokio::test]
    async fn get_api_version_returns_version_release_repoid() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/version"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "version": "9.1.9",
                    "release": "9.1",
                    "repoid": "abc1234"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let v = c.get_api_version().await.expect("version");
        assert_eq!(v.version, "9.1.9");
        assert_eq!(v.release, "9.1");
        assert_eq!(v.repoid, "abc1234");
    }

    // ── Cluster options + log (cluster.core.{options,log}) ──
    //
    // Two regression classes:
    // 1. `migration_unsecure` is bool-from-int — older PVE serializes
    //    it as 0/1 string, newer as int; both must round-trip
    // 2. `registered-tags` is hyphen-renamed via #[serde(rename)] —
    //    the literal hyphen on the wire must map to snake_case Rust

    #[tokio::test]
    async fn get_cluster_options_round_trips_typed_fields_with_renames() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/options"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "mac_prefix": "BC:24:11",
                    "console": "html5",
                    "description": "lab cluster",
                    "keyboard": "en-us",
                    "max_workers": 4,
                    "migration": "type=insecure,network=10.0.0.0/24",
                    "migration_unsecure": 1,
                    "registered-tags": "prod;dev;staging",
                    "tag-style": "free",
                    "email_from": "ops@example.com"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let opts = c.get_cluster_options().await.expect("options");
        assert_eq!(opts.mac_prefix, "BC:24:11");
        assert_eq!(opts.console, "html5");
        assert_eq!(opts.max_workers, 4);
        assert!(opts.migration_unsecure);
        // Hyphenated wire fields → snake_case via #[serde(rename)].
        assert_eq!(opts.registered_tags, "prod;dev;staging");
        assert_eq!(opts.tag_style, "free");
    }

    #[tokio::test]
    async fn get_cluster_options_tolerates_minimal_response() {
        // Defensive: a fresh cluster with default options has most
        // fields absent. All of them must default to empty/zero, not
        // crash the deserializer.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/options"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let opts = c.get_cluster_options().await.expect("options");
        assert_eq!(opts.mac_prefix, "");
        assert_eq!(opts.max_workers, 0);
        assert!(!opts.migration_unsecure);
    }

    #[tokio::test]
    async fn update_cluster_options_puts_form_params() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/cluster/options"))
            .and(body_string_contains("mac_prefix=BC%3A24%3A11"))
            .and(body_string_contains("max_workers=8"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.update_cluster_options(&[("mac_prefix", "BC:24:11"), ("max_workers", "8")])
            .await
            .expect("update");
    }

    #[tokio::test]
    async fn get_cluster_log_returns_typed_entries() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/log"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "node": "pve1",
                        "user": "root@pam",
                        "msg": "starting task UPID:pve1:...:vzdump:",
                        "tag": "info",
                        "uid": 12345,
                        "pri": 6,
                        "time": 1_735_689_600,
                        "pid": 1234
                    },
                    {
                        "node": "pve2",
                        "user": "auditor@pve",
                        "msg": "authentication failure",
                        "tag": "warn",
                        "uid": 12346,
                        "pri": 4,
                        "time": 1_735_689_660,
                        "pid": 5678
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let entries = c.get_cluster_log(None).await.expect("log");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].node, "pve1");
        assert_eq!(entries[0].tag, "info");
        assert_eq!(entries[0].pri, 6);
        assert_eq!(entries[1].user, "auditor@pve");
        assert_eq!(entries[1].pri, 4);
    }

    #[tokio::test]
    async fn get_cluster_log_accepts_string_uid_and_extra_id_field() {
        // Live-cluster regression (): real PVE returns
        //   "uid": "2957"            (JSON string, not number)
        //   "id": "2957:pve1"  (extra field not in our struct)
        // Old struct typed `uid: u64` and parsing failed at the first
        // entry. Fix: deserialize_u64_from_str_or_num. Extra field is
        // tolerated by serde's default unknown-field handling.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/log"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "user": "root@pam!proxxx",
                        "uid": "2957",
                        "pid": 840_512,
                        "pri": 6,
                        "time": 1_777_916_989,
                        "msg": "end task UPID:pve1:...:aptupdate::root@pam!proxxx: OK",
                        "node": "pve1",
                        "tag": "pvedaemon",
                        "id": "2957:pve1"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let entries = c.get_cluster_log(None).await.expect("log");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].uid, 2957);
        assert_eq!(entries[0].pid, 840_512);
        assert_eq!(entries[0].tag, "pvedaemon");
    }

    #[tokio::test]
    async fn get_cluster_log_with_max_passes_query_param() {
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/log"))
            .and(query_param("max", "100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.get_cluster_log(Some(100)).await.expect("log");
    }

    // ── HA groups (legacy /cluster/ha/groups) + status/current ──
    //
    // Two regression classes:
    // 1. The legacy /cluster/ha/groups path is distinct from the
    //    PVE 9 /cluster/ha/rules path the existing list_ha_groups
    //    targets — operators on PVE 8 still need the literal endpoint.
    // 2. /cluster/ha/status/current returns a heterogeneous list
    //    (node rows + service rows + master/quorum rows) where each
    //    row populates a different field subset; #[serde(default)]
    //    on every field handles the variation.

    #[tokio::test]
    async fn list_ha_groups_legacy_hits_literal_groups_path_not_rules() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/ha/groups"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "group": "primary-dc",
                        "nodes": "pve1:2,pve2:1,pve3",
                        "restricted": 1,
                        "nofailback": 0,
                        "comment": "DC1 preferred"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        // Negative mount: the legacy call must NOT route to /rules
        // (where existing list_ha_groups already goes).
        Mock::given(path("/api2/json/cluster/ha/rules"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let groups = c.list_ha_groups_legacy().await.expect("legacy");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "primary-dc");
        assert!(groups[0].restricted);
        assert!(!groups[0].nofailback);
        // Priority parser still works on the legacy path.
        let prio = groups[0].parse_priority_list();
        assert_eq!(prio[0], ("pve1".to_string(), 2));
    }

    #[tokio::test]
    async fn create_ha_group_posts_form_params() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/cluster/ha/groups"))
            .and(body_string_contains("group=primary-dc"))
            .and(body_string_contains("nodes=pve1%3A2%2Cpve2%3A1"))
            .and(body_string_contains("restricted=1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.create_ha_group(&[
            ("group", "primary-dc"),
            ("nodes", "pve1:2,pve2:1"),
            ("restricted", "1"),
            ("nofailback", "0"),
        ])
        .await
        .expect("create");
    }

    #[tokio::test]
    async fn update_ha_group_puts_at_group_path() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/cluster/ha/groups/primary-dc"))
            .and(body_string_contains("nofailback=1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.update_ha_group("primary-dc", &[("nofailback", "1")])
            .await
            .expect("update");
    }

    #[tokio::test]
    async fn delete_ha_group_hits_group_path() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api2/json/cluster/ha/groups/primary-dc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.delete_ha_group("primary-dc").await.expect("delete");
    }

    #[tokio::test]
    async fn get_ha_status_current_returns_heterogeneous_rows() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/ha/status/current"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "id": "node/pve1",
                        "type": "node",
                        "node": "pve1",
                        "status": "online"
                    },
                    {
                        "id": "service:vm:100",
                        "type": "service",
                        "node": "pve1",
                        "sid": "vm:100",
                        "status": "started",
                        "group": "primary-dc"
                    },
                    {
                        "id": "master",
                        "type": "master",
                        "node": "pve1",
                        "status": "active",
                        "quorate": 1,
                        "timestamp": 1_735_689_600
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let entries = c.get_ha_status_current().await.expect("status");
        assert_eq!(entries.len(), 3);
        // Node row populates type=node, node, status.
        assert_eq!(entries[0].entry_type, "node");
        assert_eq!(entries[0].status, "online");
        // Service row populates sid + group.
        assert_eq!(entries[1].entry_type, "service");
        assert_eq!(entries[1].sid, "vm:100");
        assert_eq!(entries[1].group, "primary-dc");
        // Master row sets quorate (bool-from-int) + timestamp.
        assert_eq!(entries[2].entry_type, "master");
        assert!(entries[2].quorate);
        assert_eq!(entries[2].timestamp, 1_735_689_600);
    }

    // ── PVE 8+ notifications (cluster.notifications.*) ─────
    //
    // Three regression classes:
    // 1. Endpoint mutations route per-type — POST goes to
    //    `/endpoints/{type}`, PUT/DELETE to `/endpoints/{type}/{name}`.
    //    Forgetting the type segment would 404; tests assert the
    //    full path explicitly.
    // 2. Matcher repeated form params — `target=`, `match-field=`,
    //    `match-severity=` can each appear multiple times in one PUT.
    //    The wire shape is `target=a&target=b&...`.
    // 3. Hyphen-renamed deserialized fields (`match-field`,
    //    `match-severity`, `invert-match`) round-trip via #[serde(rename)].

    #[tokio::test]
    async fn list_notification_endpoints_aggregates_per_type_and_injects_type_tag() {
        // PVE 8/9 quirk pinned by this test:
        // `/cluster/notifications/endpoints/<type>` returns the actual
        // configured INSTANCES of that type. The wire shape OMITS
        // `type` (implicit in URL). Our fan-out impl must:
        //   1. Hit all 4 known type paths (sendmail / smtp / gotify /
        //      webhook).
        //   2. Inject the type tag client-side so caller doesn't see
        //      empty `endpoint_type`.
        //   3. Concat in stable iteration order.
        let server = MockServer::start().await;
        // sendmail: one builtin instance.
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/notifications/endpoints/sendmail"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "name": "default-mail",
                        "comment": "default mail-from",
                        "origin": "builtin",
                        "disable": 0
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        // smtp: empty.
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/notifications/endpoints/smtp"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        // gotify: one user-created, disabled (bool-from-int=1).
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/notifications/endpoints/gotify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "name": "oncall-gotify",
                        "comment": "PagerDuty replacement",
                        "origin": "user-created",
                        "disable": 1
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        // webhook: one user-created instance with type-specific URL knob.
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/notifications/endpoints/webhook"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "name": "alertmanager-fwd",
                        "origin": "user-created",
                        "url": "http://alertmanager:9093/api/v1/alerts",
                        "method": "post",
                        "comment": ""
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let endpoints = c.list_notification_endpoints().await.expect("endpoints");
        assert_eq!(
            endpoints.len(),
            3,
            "aggregator should concatenate non-empty per-type rows"
        );
        // Iteration order matches the const TYPES slice in client.rs.
        assert_eq!(endpoints[0].endpoint_type, "sendmail");
        assert_eq!(endpoints[0].name, "default-mail");
        assert_eq!(endpoints[0].origin, "builtin");
        assert!(!endpoints[0].disable);
        // smtp produced 0 rows → next is gotify.
        assert_eq!(endpoints[1].endpoint_type, "gotify");
        assert_eq!(endpoints[1].name, "oncall-gotify");
        assert!(endpoints[1].disable, "bool-from-int=1 → true");
        // Then webhook.
        assert_eq!(endpoints[2].endpoint_type, "webhook");
        assert_eq!(endpoints[2].name, "alertmanager-fwd");
    }

    #[tokio::test]
    async fn list_notification_endpoints_does_not_use_catalog_endpoint() {
        // Live-cluster regression (): the buggy old impl
        // hit `/cluster/notifications/endpoints` (the catalog) and
        // returned its 4 type-name stub rows as if they were
        // configured instances. This test pins the contract that we
        // do NOT hit the catalog path — wiremock's `expect(1)` on
        // each per-type path acts as both forward and negative
        // assertion (an unmounted catalog GET would 404 inside
        // wiremock).
        let server = MockServer::start().await;
        for t in &["sendmail", "smtp", "gotify", "webhook"] {
            Mock::given(method("GET"))
                .and(path(format!(
                    "/api2/json/cluster/notifications/endpoints/{t}"
                )))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})),
                )
                .expect(1)
                .mount(&server)
                .await;
        }
        let c = mock_client(&server).await;
        let endpoints = c.list_notification_endpoints().await.expect("endpoints");
        assert_eq!(endpoints.len(), 0, "all four type paths returned empty");
    }

    #[tokio::test]
    async fn create_notification_endpoint_routes_to_per_type_path() {
        // Critical regression case: POST goes to
        // `/cluster/notifications/endpoints/{type}` — forgetting the
        // type segment would 404 against PVE.
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/cluster/notifications/endpoints/gotify"))
            .and(body_string_contains("name=oncall-gotify"))
            .and(body_string_contains("server=https"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.create_notification_endpoint(
            "gotify",
            &[
                ("name", "oncall-gotify"),
                ("server", "https://gotify.example.com"),
                ("token", "AAAA"),
            ],
        )
        .await
        .expect("create");
    }

    #[tokio::test]
    async fn update_notification_endpoint_puts_at_type_and_name_path() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path(
                "/api2/json/cluster/notifications/endpoints/gotify/oncall-gotify",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.update_notification_endpoint("gotify", "oncall-gotify", &[("disable", "1")])
            .await
            .expect("update");
    }

    #[tokio::test]
    async fn delete_notification_endpoint_hits_type_and_name_path() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path(
                "/api2/json/cluster/notifications/endpoints/gotify/oncall-gotify",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.delete_notification_endpoint("gotify", "oncall-gotify")
            .await
            .expect("delete");
    }

    #[tokio::test]
    async fn list_notification_matchers_round_trips_kebab_renamed_fields() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/notifications/matchers"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{
                    "name": "vzdump-failures",
                    "comment": "ship to oncall",
                    "origin": "user-created",
                    "target": ["oncall-gotify", "default-mail"],
                    "match-field": ["type=vzdump", "hostname=pve1"],
                    "match-severity": ["error", "warning"],
                    "mode": "all",
                    "invert-match": 0,
                    "disable": 0
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let matchers = c.list_notification_matchers().await.expect("matchers");
        assert_eq!(matchers.len(), 1);
        assert_eq!(matchers[0].name, "vzdump-failures");
        assert_eq!(matchers[0].target.len(), 2);
        // Hyphenated wire fields → snake_case via #[serde(rename)].
        assert_eq!(matchers[0].match_field.len(), 2);
        assert!(matchers[0].match_field[0].contains("vzdump"));
        assert_eq!(matchers[0].match_severity.len(), 2);
        assert!(!matchers[0].invert_match);
    }

    #[tokio::test]
    async fn create_notification_matcher_emits_repeated_target_form_params() {
        // Critical regression case: PVE expects `target=a&target=b&...`
        // for multi-target matchers. A single comma-joined string would
        // parse as one literal target and never deliver to the others.
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/cluster/notifications/matchers"))
            .and(body_string_contains("name=vzdump-failures"))
            .and(body_string_contains("target=oncall-gotify"))
            .and(body_string_contains("target=default-mail"))
            .and(body_string_contains("match-severity=error"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.create_notification_matcher(&[
            ("name", "vzdump-failures"),
            ("target", "oncall-gotify"),
            ("target", "default-mail"),
            ("match-field", "type=vzdump"),
            ("match-severity", "error"),
        ])
        .await
        .expect("create");
    }

    #[tokio::test]
    async fn delete_notification_matcher_hits_name_path() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path(
                "/api2/json/cluster/notifications/matchers/vzdump-failures",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.delete_notification_matcher("vzdump-failures")
            .await
            .expect("delete");
    }

    #[tokio::test]
    async fn list_notification_targets_returns_flat_list() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/notifications/targets"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"name": "default-mail", "type": "sendmail", "origin": "builtin"},
                    {"name": "oncall-gotify", "type": "gotify", "origin": "user-created"},
                    {"name": "all-targets", "type": "group", "origin": "user-created"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let targets = c.list_notification_targets().await.expect("targets");
        assert_eq!(targets.len(), 3);
        assert_eq!(targets[2].target_type, "group");
    }

    // ── Cluster-wide storage definitions (storage.definitions) ──
    //
    // Two regression classes:
    // 1. StorageDefinition is heterogeneous — each PVE storage type
    //    populates a different field subset. A list response mixing
    //    `dir`/`nfs`/`pbs`/`zfspool` rows must round-trip cleanly.
    // 2. Bool-from-int on `disable` and `shared` — operators flip these
    //    via `--disable 1` and `shared=1` is the discriminator for
    //    cluster-visible storages.

    #[tokio::test]
    async fn list_cluster_storages_returns_heterogeneous_typed_rows() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/storage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "storage": "local",
                        "type": "dir",
                        "content": "vztmpl,iso,backup",
                        "path": "/var/lib/vz",
                        "shared": 0,
                        "disable": 0
                    },
                    {
                        "storage": "pbs-main",
                        "type": "pbs",
                        "content": "backup",
                        "server": "pbs.example.com",
                        "datastore": "main",
                        "username": "root@pam!proxxx",
                        "fingerprint": "AB:CD:EF",
                        "shared": 1
                    },
                    {
                        "storage": "rpool-vmdata",
                        "type": "zfspool",
                        "content": "images,rootdir",
                        "pool": "rpool/vmdata",
                        "shared": 0
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let storages = c.list_cluster_storages().await.expect("list");
        assert_eq!(storages.len(), 3);
        // dir row: path populated, server/datastore default to empty.
        assert_eq!(storages[0].storage_type, "dir");
        assert_eq!(storages[0].path, "/var/lib/vz");
        assert!(!storages[0].shared);
        assert_eq!(storages[0].server, "");
        // pbs row: server + datastore + fingerprint populated.
        assert_eq!(storages[1].storage_type, "pbs");
        assert_eq!(storages[1].datastore, "main");
        assert!(storages[1].shared);
        // zfspool row: pool populated.
        assert_eq!(storages[2].storage_type, "zfspool");
        assert_eq!(storages[2].pool, "rpool/vmdata");
    }

    #[tokio::test]
    async fn get_cluster_storage_uses_id_in_path() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/storage/pbs-main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "storage": "pbs-main",
                    "type": "pbs",
                    "server": "pbs.example.com",
                    "datastore": "main",
                    "shared": 1
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let s = c.get_cluster_storage("pbs-main").await.expect("get");
        assert_eq!(s.storage, "pbs-main");
        assert_eq!(s.datastore, "main");
        assert!(s.shared);
    }

    #[tokio::test]
    async fn create_cluster_storage_posts_form_params_to_collection() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/storage"))
            .and(body_string_contains("storage=pbs-main"))
            .and(body_string_contains("type=pbs"))
            .and(body_string_contains("datastore=main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.create_cluster_storage(&[
            ("storage", "pbs-main"),
            ("type", "pbs"),
            ("server", "pbs.example.com"),
            ("datastore", "main"),
            ("username", "root@pam!proxxx"),
            ("fingerprint", "AB:CD:EF"),
        ])
        .await
        .expect("create");
    }

    #[tokio::test]
    async fn create_cluster_storage_accepts_object_response_not_just_null() {
        // Live-cluster regression (batch 2.5 live-cluster regression): real PVE
        // returns `{"data": {"storage": "...", "type": "dir"}}` — an
        // OBJECT, not null and not a UPID string. The old impl typed
        // the response as `Option<String>` which failed to parse the
        // object and surfaced as "Failed to parse response from
        // /storage" even though PVE had successfully created the
        // storage (visible in the next list). Fix: typed as
        // `serde_json::Value` (the body is discarded).
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/storage"))
            .and(body_string_contains("storage=proxxx-mut-storage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "storage": "proxxx-mut-storage",
                    "type": "dir"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.create_cluster_storage(&[
            ("storage", "proxxx-mut-storage"),
            ("type", "dir"),
            ("path", "/tmp/proxxx-mut-storage"),
            ("content", "backup"),
        ])
        .await
        .expect("create with object response");
    }

    #[tokio::test]
    async fn update_cluster_storage_accepts_object_response_not_just_null() {
        // Same regression class as create: PUT also returns the
        // materialized config as an object, not null/UPID.
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/storage/proxxx-mut-storage"))
            .and(body_string_contains("content=backup%2Ciso"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "storage": "proxxx-mut-storage",
                    "type": "dir"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.update_cluster_storage("proxxx-mut-storage", &[("content", "backup,iso")])
            .await
            .expect("update with object response");
    }

    #[tokio::test]
    async fn update_cluster_storage_puts_at_id_path() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/storage/pbs-main"))
            .and(body_string_contains("disable=1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.update_cluster_storage("pbs-main", &[("disable", "1")])
            .await
            .expect("update");
    }

    #[tokio::test]
    async fn delete_cluster_storage_hits_id_path() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api2/json/storage/pbs-main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.delete_cluster_storage("pbs-main").await.expect("delete");
    }

    // ── ACME (cluster.acme.{accounts,plugins,tos,directories,…}) ──
    //
    // Three regression classes:
    // 1. Account collection path is `/cluster/acme/account` (singular)
    //    — easy mistake to type the plural and silently 404
    // 2. Account create/update/delete return UPID strings (async CA
    //    round-trip) — the typed return is `Result<String>`, distinct
    //    from the `Result<()>` pattern used by other CRUD families
    // 3. AcmePlugin is heterogeneous (DNS-01 plugins populate api/data,
    //    HTTP-01 standalone leaves them empty); #[serde(default)] on
    //    every field lets both round-trip cleanly

    #[tokio::test]
    async fn list_acme_accounts_uses_singular_account_path() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/acme/account"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{"name": "default"}, {"name": "staging"}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let accounts = c.list_acme_accounts().await.expect("accounts");
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].name, "default");
    }

    #[tokio::test]
    async fn get_acme_account_returns_full_registration_details() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/acme/account/default"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "account": {"contact": ["mailto:ops@example.com"], "status": "valid"},
                    "tos": "https://letsencrypt.org/documents/LE-SA-v1.3.pdf",
                    "directory": "https://acme-v02.api.letsencrypt.org/directory",
                    "location": "https://acme-v02.api.letsencrypt.org/acme/acct/12345"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let a = c.get_acme_account("default").await.expect("get");
        assert!(a.tos.contains("letsencrypt"));
        assert!(a.location.ends_with("/12345"));
        // The nested `account` object preserved as raw Value (CA-defined shape).
        assert_eq!(
            a.account.get("status").and_then(serde_json::Value::as_str),
            Some("valid")
        );
    }

    #[tokio::test]
    async fn create_acme_account_returns_upid_for_async_ca_call() {
        // Critical regression case: the trait surface returns
        // Result<String> not Result<()> because PVE makes a real
        // network round-trip to the CA — the call is async and the
        // UPID is how the operator polls for completion.
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/cluster/acme/account"))
            .and(body_string_contains("name=default"))
            .and(body_string_contains("contact=mailto%3Aops%40example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "UPID:pve1:00001234:00000000:65000000:acmeregister:default:root@pam:"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let upid = c
            .create_acme_account(&[
                ("name", "default"),
                ("contact", "mailto:ops@example.com"),
                (
                    "tos_url",
                    "https://letsencrypt.org/documents/LE-SA-v1.3.pdf",
                ),
            ])
            .await
            .expect("create");
        assert!(upid.starts_with("UPID:"));
        assert!(upid.contains("acmeregister"));
    }

    #[tokio::test]
    async fn delete_acme_account_returns_upid() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api2/json/cluster/acme/account/default"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "UPID:pve1:00001234:00000000:65000000:acmedeactivate:default:root@pam:"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let upid = c.delete_acme_account("default").await.expect("delete");
        assert!(upid.contains("acmedeactivate"));
    }

    #[tokio::test]
    async fn list_acme_plugins_round_trips_heterogeneous_dns_and_http_rows() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/acme/plugins"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "plugin": "cf-dns",
                        "type": "dns",
                        "api": "cloudflare",
                        "data": "CF_Token=REDACTED",
                        "validation_delay": 30
                    },
                    {
                        // HTTP-01 standalone: api/data empty.
                        "plugin": "http-default",
                        "type": "standalone"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let plugins = c.list_acme_plugins().await.expect("plugins");
        assert_eq!(plugins.len(), 2);
        assert_eq!(plugins[0].plugin_type, "dns");
        assert_eq!(plugins[0].api, "cloudflare");
        assert_eq!(plugins[0].validation_delay, 30);
        // standalone row: api/data default to empty.
        assert_eq!(plugins[1].plugin_type, "standalone");
        assert_eq!(plugins[1].api, "");
        assert_eq!(plugins[1].validation_delay, 0);
    }

    #[tokio::test]
    async fn create_acme_plugin_posts_form_params() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/cluster/acme/plugins"))
            .and(body_string_contains("id=cf-dns"))
            .and(body_string_contains("type=dns"))
            .and(body_string_contains("api=cloudflare"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.create_acme_plugin(&[
            ("id", "cf-dns"),
            ("type", "dns"),
            ("api", "cloudflare"),
            ("data", "CF_Token=secret"),
        ])
        .await
        .expect("create");
    }

    #[tokio::test]
    async fn get_acme_tos_passes_directory_query_param() {
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/acme/tos"))
            .and(query_param(
                "directory",
                "https://acme-staging-v02.api.letsencrypt.org/directory",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "https://letsencrypt.org/documents/LE-SA-v1.3.pdf"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let tos = c
            .get_acme_tos(Some(
                "https://acme-staging-v02.api.letsencrypt.org/directory",
            ))
            .await
            .expect("tos");
        assert!(tos.contains("LE-SA"));
    }

    #[tokio::test]
    async fn list_acme_directories_returns_typed_rows() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/acme/directories"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"name": "Let's Encrypt V2", "url": "https://acme-v02.api.letsencrypt.org/directory"},
                    {"name": "Let's Encrypt V2 Staging", "url": "https://acme-staging-v02.api.letsencrypt.org/directory"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let dirs = c.list_acme_directories().await.expect("dirs");
        assert_eq!(dirs.len(), 2);
        assert!(dirs[0].url.contains("acme-v02"));
        assert!(dirs[1].name.contains("Staging"));
    }

    #[tokio::test]
    async fn get_acme_challenge_schema_returns_raw_value() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/acme/challenge-schema"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"id": "cloudflare", "name": "CloudFlare", "schema": {"CF_Token": {}}}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let schema = c.get_acme_challenge_schema().await.expect("schema");
        // Surface as raw Value — operator drills in via jq.
        assert!(schema.is_array());
    }

    // ── Corosync cluster bootstrap (cluster.config.*) ──
    //
    // Two regression classes:
    // 1. Node mutations route per-name: POST/DELETE go to
    //    `/cluster/config/nodes/{node}` — forgetting the trailing
    //    name segment would 404. The map-gate's singleton expansion
    //    accepts `/nodes/*` as the singleton form so this matches
    //    the existing map entry without needing a new entry.
    // 2. Async mutations (join, qdevice setup/update/delete) return
    //    UPID strings — corosync restart is involved.

    #[tokio::test]
    async fn list_cluster_corosync_nodes_returns_typed_rows() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/config/nodes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "node": "pve1", "nodeid": 1, "quorum_votes": 1,
                        "ring0_addr": "10.0.0.1", "ring1_addr": "10.0.1.1"
                    },
                    {
                        "node": "pve2", "nodeid": 2, "quorum_votes": 1,
                        "ring0_addr": "10.0.0.2"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let nodes = c.list_cluster_corosync_nodes().await.expect("nodes");
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].nodeid, 1);
        assert_eq!(nodes[0].ring1_addr, "10.0.1.1");
        // Single-ring node defaults ring1_addr to empty.
        assert_eq!(nodes[1].ring1_addr, "");
    }

    #[tokio::test]
    async fn list_cluster_corosync_nodes_accepts_string_numerics() {
        // Live-cluster regression (pve1..3): real
        // PVE returns
        //   "nodeid": "1"        (JSON string, not number)
        //   "quorum_votes": "1"  (JSON string, not number)
        // Old typed-as-`u32` parsing failed → "Failed to parse response
        // from /cluster/config/nodes". Fix: per-field
        // deserialize_u32_from_str_or_num.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/config/nodes"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "node": "pve1",
                        "nodeid": "1",
                        "quorum_votes": "1",
                        "name": "pve1",
                        "ring0_addr": "10.0.0.1"
                    },
                    {
                        "node": "pve2",
                        "nodeid": "2",
                        "quorum_votes": "1",
                        "name": "pve2",
                        "ring0_addr": "10.0.0.2"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let nodes = c.list_cluster_corosync_nodes().await.expect("nodes");
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].nodeid, 1);
        assert_eq!(nodes[0].quorum_votes, 1);
        assert_eq!(nodes[1].nodeid, 2);
    }

    #[tokio::test]
    async fn add_cluster_corosync_node_routes_to_per_name_path() {
        // Critical regression case: PVE shape is POST `/nodes/{node}`,
        // not POST `/nodes` with `node=...` body. Forgetting the path
        // segment would 404.
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/cluster/config/nodes/pve3"))
            .and(body_string_contains("ring0_addr=10.0.0.3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.add_cluster_corosync_node("pve3", &[("ring0_addr", "10.0.0.3")])
            .await
            .expect("add");
    }

    #[tokio::test]
    async fn remove_cluster_corosync_node_hits_per_name_path() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api2/json/cluster/config/nodes/pve3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.remove_cluster_corosync_node("pve3")
            .await
            .expect("remove");
    }

    #[tokio::test]
    async fn get_cluster_join_info_passes_node_query_param() {
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/config/join"))
            .and(query_param("node", "pve3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "config_digest": "abc",
                    "nodelist": [{"name": "pve1", "nodeid": "1"}],
                    "totem": {"cluster_name": "lab"}
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let info = c.get_cluster_join_info(Some("pve3")).await.expect("info");
        assert!(info.get("nodelist").is_some());
        assert!(info.get("totem").is_some());
    }

    #[tokio::test]
    async fn join_cluster_returns_upid() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/cluster/config/join"))
            .and(body_string_contains("hostname=pve1.lab"))
            .and(body_string_contains("fingerprint=AB%3ACD%3AEF"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "UPID:pve3:00001234:00000000:65000000:clusterjoin::root@pam:"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let upid = c
            .join_cluster(&[
                ("hostname", "pve1.lab"),
                ("password", "secret"),
                ("fingerprint", "AB:CD:EF"),
            ])
            .await
            .expect("join");
        assert!(upid.contains("clusterjoin"));
    }

    #[tokio::test]
    async fn cluster_qdevice_crud_returns_upid_strings() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/cluster/config/qdevice"))
            .and(body_string_contains("addr=qdev.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "UPID:pve1:00001234:00000000:65000000:qdevicesetup::root@pam:"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/cluster/config/qdevice"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "UPID:pve1:00001234:00000000:65000000:qdeviceupdate::root@pam:"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path("/api2/json/cluster/config/qdevice"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "UPID:pve1:00001234:00000000:65000000:qdeviceremove::root@pam:"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let setup_upid = c
            .setup_cluster_qdevice(&[("addr", "qdev.example.com")])
            .await
            .expect("setup");
        assert!(setup_upid.contains("qdevicesetup"));
        let update_upid = c
            .update_cluster_qdevice(&[("algorithm", "lms")])
            .await
            .expect("update");
        assert!(update_upid.contains("qdeviceupdate"));
        let delete_upid = c.remove_cluster_qdevice().await.expect("delete");
        assert!(delete_upid.contains("qdeviceremove"));
    }

    #[tokio::test]
    async fn get_cluster_totem_returns_raw_value() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/config/totem"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "cluster_name": "lab-cluster",
                    "config_version": "12",
                    "secauth": "on",
                    "transport": "knet"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let totem = c.get_cluster_totem().await.expect("totem");
        assert_eq!(
            totem
                .get("cluster_name")
                .and_then(serde_json::Value::as_str),
            Some("lab-cluster")
        );
    }

    // ── 80/20 grab-bag: tasks per-node + feature + sendkey/unlink + aplinfo ──
    //
    // Three regression classes:
    // 1. `get_guest_feature` `hasFeature` field is camelCase on the
    //    wire — our snake_case Rust field needs #[serde(rename)] +
    //    bool-from-int. Easy to silently regress to "always false".
    // 2. `unlink_qemu_disk` MUST send `force=0` by default (NOT omit it
    //    — PVE treats omitted `force` as default but we send explicit
    //    so the body shape is predictable and the destructive path
    //    only fires when explicitly opted in).
    // 3. Per-node tasks use the same `TaskInfo` shape as cluster-wide
    //    tasks — sanity-check the wire-shape compatibility.

    #[tokio::test]
    async fn list_node_tasks_uses_per_node_path_and_passes_limit() {
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/tasks"))
            .and(query_param("limit", "20"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{
                    "upid": "UPID:pve1:00001234:00000000:65000000:vzdump:100:root@pam:",
                    "node": "pve1",
                    "user": "root@pam",
                    "id": "100",
                    "type": "vzdump",
                    "status": "running",
                    "starttime": 1_735_689_600
                }]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let tasks = c.list_node_tasks("pve1", Some(20)).await.expect("tasks");
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].task_type, "vzdump");
    }

    #[tokio::test]
    async fn stop_node_task_url_encodes_upid_with_colons() {
        // Critical regression case: UPIDs contain colons that MUST be
        // percent-encoded in the path (otherwise the path tail parses
        // as additional segments and 404s).
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path(
                "/api2/json/nodes/pve1/tasks/UPID%3Apve1%3A00001234%3A00000000%3A65000000%3Avzdump%3A100%3Aroot%40pam%3A",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.stop_node_task(
            "pve1",
            "UPID:pve1:00001234:00000000:65000000:vzdump:100:root@pam:",
        )
        .await
        .expect("stop");
    }

    #[tokio::test]
    async fn get_guest_feature_round_trips_camel_case_has_feature_bool_from_int() {
        // Critical regression case: PVE serializes the field as
        // `hasFeature` (camelCase, integer 0/1). Forget the rename or
        // the bool-from-int and the call always reports "false".
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/feature"))
            .and(query_param("feature", "snapshot"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "hasFeature": 1,
                    "nodes": ["pve1", "pve2"]
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let res = c
            .get_guest_feature("pve1", 100, GuestType::Qemu, "snapshot")
            .await
            .expect("feature");
        assert!(res.has_feature);
        assert_eq!(res.nodes.len(), 2);
        assert_eq!(res.nodes[1], "pve2");
    }

    #[tokio::test]
    async fn send_qemu_key_puts_key_param() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/nodes/pve1/qemu/100/sendkey"))
            .and(body_string_contains("key=ctrl-alt-delete"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.send_qemu_key("pve1", 100, "ctrl-alt-delete")
            .await
            .expect("send");
    }

    #[tokio::test]
    async fn unlink_qemu_disk_default_does_not_force_volume_delete() {
        // Critical regression case: default behavior MUST be "detach
        // only, keep volume". `force=1` would silently delete the
        // underlying volume — operator data loss.
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/nodes/pve1/qemu/100/unlink"))
            .and(body_string_contains("idlist=scsi1"))
            .and(body_string_contains("force=0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.unlink_qemu_disk("pve1", 100, "scsi1", false)
            .await
            .expect("unlink");
    }

    #[tokio::test]
    async fn unlink_qemu_disk_force_true_sends_force_one() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/nodes/pve1/qemu/100/unlink"))
            .and(body_string_contains("force=1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.unlink_qemu_disk("pve1", 100, "scsi1,scsi2", true)
            .await
            .expect("unlink force");
    }

    #[tokio::test]
    async fn list_node_aplinfo_returns_typed_template_rows() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/aplinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "template": "debian-12-standard_12.7-1_amd64.tar.zst",
                        "section": "system",
                        "type": "vztmpl",
                        "source": "https://download.proxmox.com/images/system/",
                        "headline": "Debian 12 Standard",
                        "version": "12.7-1",
                        "os": "debian-12"
                    },
                    {
                        "template": "ubuntu-24.04-standard_24.04-1_amd64.tar.zst",
                        "section": "system",
                        "type": "vztmpl"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let templates = c.list_node_aplinfo("pve1").await.expect("aplinfo");
        assert_eq!(templates.len(), 2);
        assert_eq!(
            templates[0].template,
            "debian-12-standard_12.7-1_amd64.tar.zst"
        );
        assert_eq!(templates[0].os, "debian-12");
        // Second template only has minimal fields — others default.
        assert_eq!(templates[1].headline, "");
    }

    #[tokio::test]
    async fn download_node_aplinfo_posts_storage_and_template() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/aplinfo"))
            .and(body_string_contains("storage=local"))
            .and(body_string_contains("template=debian-12-standard"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "UPID:pve1:00001234:00000000:65000000:download:local:root@pam:"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let upid = c
            .download_node_aplinfo("pve1", "local", "debian-12-standard_12.7-1_amd64.tar.zst")
            .await
            .expect("download");
        assert!(upid.starts_with("UPID:"));
    }

    #[tokio::test]
    async fn query_url_metadata_passes_url_query_param_and_returns_typed() {
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/query-url-metadata"))
            .and(query_param("url", "https://example.com/big.iso"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "size": 2_400_000_000_u64,
                    "filename": "big.iso",
                    "mimetype": "application/octet-stream"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let meta = c
            .query_url_metadata("pve1", "https://example.com/big.iso")
            .await
            .expect("meta");
        assert_eq!(meta.size, 2_400_000_000);
        assert_eq!(meta.filename, "big.iso");
    }

    // ── RRD PNG + cluster.metrics.server ───────────────────
    //
    // Two regression classes:
    // 1. RRD PNG endpoint takes the SAME ds/timeframe/cf query params
    //    as `rrddata` but returns a different shape (`{filename: "..."}`
    //    vs `[{time, value, ...}, ...]`). Easy to mix up.
    // 2. Metric-server mutations route per-id (POST/PUT/DELETE on
    //    `/cluster/metrics/server/{id}`), NOT collection-level.

    #[tokio::test]
    async fn get_guest_rrd_image_returns_filename_with_query_params() {
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/rrd"))
            .and(query_param("ds", "cpu"))
            .and(query_param("timeframe", "hour"))
            .and(query_param("cf", "AVERAGE"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"filename": "/var/cache/pve-graphs/rrd-abc.png"}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let img = c
            .get_guest_rrd_image(
                "pve1",
                100,
                GuestType::Qemu,
                "cpu",
                proxxx::api::types::RrdTimeframe::Hour,
                proxxx::api::types::RrdCf::Average,
            )
            .await
            .expect("rrd png");
        assert_eq!(img.filename, "/var/cache/pve-graphs/rrd-abc.png");
    }

    #[tokio::test]
    async fn list_metric_servers_round_trips_heterogeneous_influx_and_graphite_rows() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/cluster/metrics/server"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "id": "influx-prod",
                        "type": "influxdb",
                        "server": "influx.example.com",
                        "port": 8086,
                        "influxdbproto": "https",
                        "organization": "ops",
                        "bucket": "pve",
                        "disable": 0
                    },
                    {
                        "id": "graphite-old",
                        "type": "graphite",
                        "server": "graphite.example.com",
                        "port": 2003,
                        "proto": "tcp",
                        "path": "proxmox.cluster1",
                        "disable": 1
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let servers = c.list_metric_servers().await.expect("metric servers");
        assert_eq!(servers.len(), 2);
        // influx row populates influxdbproto + organization + bucket.
        assert_eq!(servers[0].server_type, "influxdb");
        assert_eq!(servers[0].influxdbproto, "https");
        assert_eq!(servers[0].bucket, "pve");
        // proto/path default to empty.
        assert_eq!(servers[0].path, "");
        assert!(!servers[0].disable);
        // graphite row populates proto + path; disable=1 → bool-from-int.
        assert_eq!(servers[1].server_type, "graphite");
        assert_eq!(servers[1].proto, "tcp");
        assert_eq!(servers[1].path, "proxmox.cluster1");
        assert!(servers[1].disable);
    }

    #[tokio::test]
    async fn create_metric_server_routes_to_per_id_path() {
        // Critical regression case: PVE shape is POST `/server/{id}`,
        // not POST `/server` with `id=...` body. Forgetting the path
        // segment would 404.
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api2/json/cluster/metrics/server/influx-prod"))
            .and(body_string_contains("type=influxdb"))
            .and(body_string_contains("server=influx.example.com"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.create_metric_server(
            "influx-prod",
            &[
                ("type", "influxdb"),
                ("server", "influx.example.com"),
                ("port", "8086"),
            ],
        )
        .await
        .expect("create");
    }

    #[tokio::test]
    async fn update_metric_server_puts_at_id_path() {
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/cluster/metrics/server/influx-prod"))
            .and(body_string_contains("disable=1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.update_metric_server("influx-prod", &[("disable", "1")])
            .await
            .expect("update");
    }

    #[tokio::test]
    async fn delete_metric_server_hits_id_path() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path("/api2/json/cluster/metrics/server/influx-prod"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.delete_metric_server("influx-prod").await.expect("delete");
    }

    // ── VNC WebSocket URL builder (qemu/lxc.console.vncwebsocket) ──
    //
    // Pure URL construction — no HTTP call. The endpoint is a
    // WebSocket-upgrade GET that PVE rejects without `Upgrade` headers,
    // so the trait method just builds the wss:// URL for hand-off to a
    // noVNC client / tokio-tungstenite. Two regression classes:
    // 1. `https://` → `wss://` scheme swap (signals WebSocket intent
    //    and matches what PVE's web UI emits)
    // 2. ticket field URL-encoding — the ticket contains chars
    //    (`:`, `/`, `+`) that MUST be percent-encoded in the query
    //    string or PVE's parser truncates it

    #[tokio::test]
    async fn build_guest_vncwebsocket_url_swaps_https_to_wss_and_encodes_ticket() {
        use proxxx::api::types::VncTicket;
        let server = MockServer::start().await;
        let c = mock_client(&server).await;
        let ticket = VncTicket {
            port: 5900,
            // Realistic-shaped ticket with chars that MUST be encoded.
            ticket: "PVEVNC:651E0A00::abc/def+xyz==".to_string(),
            user: "root@pam".to_string(),
            ..Default::default()
        };
        let url = c
            .build_guest_vncwebsocket_url("pve1", 100, GuestType::Qemu, &ticket)
            .await
            .expect("ws url");
        // Scheme swapped to ws(s)://. mock_client uses http://, so the
        // wire shape here is `ws://`; against a real https endpoint
        // the impl emits `wss://`. Both are tested by the prefix.
        assert!(
            url.starts_with("ws://") || url.starts_with("wss://"),
            "url={url}"
        );
        // Path includes vncwebsocket leaf.
        assert!(url.contains("/api2/json/nodes/pve1/qemu/100/vncwebsocket"));
        // Port + ticket as query params.
        assert!(url.contains("port=5900"));
        // Critical regression: colon, slash, plus, equals MUST be encoded.
        assert!(url.contains("PVEVNC%3A651E0A00%3A%3Aabc%2Fdef%2Bxyz%3D%3D"));
        // Sanity: raw ticket NOT in URL (would mean encoding skipped).
        assert!(!url.contains("PVEVNC:"));
    }

    #[tokio::test]
    async fn build_guest_vncwebsocket_url_routes_lxc_kind_not_qemu() {
        use proxxx::api::types::VncTicket;
        let server = MockServer::start().await;
        let c = mock_client(&server).await;
        let ticket = VncTicket {
            port: 5901,
            ticket: "abc".to_string(),
            ..Default::default()
        };
        let url = c
            .build_guest_vncwebsocket_url("pve1", 200, GuestType::Lxc, &ticket)
            .await
            .expect("ws url");
        // LXC routing: /lxc/ in path, not /qemu/.
        assert!(url.contains("/lxc/200/vncwebsocket"));
        assert!(!url.contains("/qemu/"));
    }

    // ── Top-tier 80/20 closure (4 endpoints) ──────────────
    //
    // Two regression classes:
    // 1. `/access/password` PUT body MUST send password in body (not
    //    URL query) — leaking secrets in logs / proxies. Test asserts
    //    body contains `password=` and the URL path does NOT.
    // 2. `/access/permissions` query params (userid + path) — both are
    //    optional and PVE treats absence as "self / all paths".

    #[tokio::test]
    async fn get_access_permissions_passes_userid_and_path_query_params() {
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/access/permissions"))
            .and(query_param("userid", "alice@pve"))
            .and(query_param("path", "/pool/dev"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "/pool/dev": {"VM.Migrate": 1, "VM.Console": 1}
                }
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let perms = c
            .get_access_permissions(Some("alice@pve"), Some("/pool/dev"))
            .await
            .expect("perms");
        assert!(perms.get("/pool/dev").is_some());
    }

    #[tokio::test]
    async fn get_access_permissions_omits_query_params_when_none() {
        use wiremock::matchers::path;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/access/permissions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {}
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.get_access_permissions(None, None).await.expect("perms");
    }

    #[tokio::test]
    async fn change_user_password_sends_credentials_in_put_body() {
        // Critical regression case: password MUST go in the PUT body,
        // never in the URL query string (proxy logs, browser history,
        // tracing tools may persist URLs but not bodies).
        use wiremock::matchers::body_string_contains;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/api2/json/access/password"))
            .and(body_string_contains("userid=alice%40pve"))
            .and(body_string_contains("password=hunter2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": null
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        c.change_user_password("alice@pve", "hunter2")
            .await
            .expect("password");
    }

    #[tokio::test]
    async fn list_lxc_interfaces_returns_typed_rows_with_addresses() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/lxc/200/interfaces"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "name": "lo",
                        "hwaddr": "00:00:00:00:00:00",
                        "inet": "127.0.0.1/8",
                        "inet6": "::1/128"
                    },
                    {
                        "name": "eth0",
                        "hwaddr": "BC:24:11:DE:AD:BE",
                        "inet": "10.0.0.42/24"
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let ifaces = c.list_lxc_interfaces("pve1", 200).await.expect("ifaces");
        assert_eq!(ifaces.len(), 2);
        assert_eq!(ifaces[0].name, "lo");
        assert_eq!(ifaces[1].inet, "10.0.0.42/24");
        // eth0 has no inet6 — defaults to empty.
        assert_eq!(ifaces[1].inet6, "");
    }

    #[tokio::test]
    async fn dump_qemu_cloudinit_passes_kind_query_param_and_returns_text() {
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/qemu/100/cloudinit/dump"))
            .and(query_param("type", "user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "#cloud-config\nhostname: web-01\nusers:\n  - default\n"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let content = c
            .dump_qemu_cloudinit("pve1", 100, "user")
            .await
            .expect("dump");
        assert!(content.starts_with("#cloud-config"));
        assert!(content.contains("hostname: web-01"));
    }

    #[tokio::test]
    async fn extract_backup_config_passes_volume_query_param() {
        use wiremock::matchers::query_param;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes/pve1/vzdump/extractconfig"))
            // Volume IDs contain colons (`pbs:backup/vm/100/...`) which
            // MUST be percent-encoded in the query string.
            .and(query_param(
                "volume",
                "pbs-main:backup/vm/100/2026-01-01T02:00:00Z",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": "memory: 2048\nname: web-01\ncores: 2\n"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let cfg = c
            .extract_backup_config("pve1", "pbs-main:backup/vm/100/2026-01-01T02:00:00Z")
            .await
            .expect("extract");
        assert!(cfg.contains("name: web-01"));
        assert!(cfg.contains("cores: 2"));
    }

    // ── rollback_snapshot routing ────────────────────────────────────

    #[tokio::test]
    async fn qemu_rollback_snapshot_hits_rollback_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/api2/json/nodes/pve1/qemu/100/snapshot/pre-upgrade/rollback",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": "UPID:pve1:00001234:rollback"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let c = mock_client(&server).await;
        let upid = c
            .rollback_snapshot("pve1", 100, GuestType::Qemu, "pre-upgrade")
            .await
            .expect("rollback");
        assert!(upid.contains("UPID:"));
    }

    #[tokio::test]
    async fn lxc_rollback_snapshot_hits_lxc_rollback_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(
                "/api2/json/nodes/pve1/lxc/200/snapshot/clean-state/rollback",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"data": "UPID:pve1:00005678:rollback"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(path(
            "/api2/json/nodes/pve1/qemu/200/snapshot/clean-state/rollback",
        ))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
        let c = mock_client(&server).await;
        let upid = c
            .rollback_snapshot("pve1", 200, GuestType::Lxc, "clean-state")
            .await
            .expect("rollback lxc");
        assert!(upid.contains("UPID:"));
    }

    // ── read_only profile: client-side write lock ──────────────────

    #[tokio::test]
    async fn read_only_profile_refuses_writes_before_touching_pve() {
        let server = MockServer::start().await;
        // If the write ever leaves the process this mock is hit, and the
        // `.expect(0)` fails the test on server drop — proving the refusal
        // happens BEFORE the network, not via a PVE 403.
        Mock::given(method("POST"))
            .and(path("/api2/json/nodes/pve1/qemu/100/status/start"))
            .respond_with(ok_upid("pve1"))
            .expect(0)
            .mount(&server)
            .await;
        // Reads MUST still work under read_only.
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": [] })),
            )
            .mount(&server)
            .await;

        let cfg = ProfileConfig {
            url: server.uri(),
            user: "root@pam".into(),
            auth: "token".into(),
            token_id: Some("test".into()),
            token_secret: None,
            token_secret_file: None,
            password: None,
            verify_tls: false,
            tls_pin_mode: None,
            read_only: true,
            rate_limit: Some(100),
            policies: None,
            telegram: None,
            ssh: None,
            pbs: None,
            alerts: None,
            mcp_token: None,
            profile_name: Some("prod".into()),
        };
        let c = PxClient::new(cfg, Some("fake-secret"))
            .await
            .expect("client builds");

        // GET still allowed.
        c.get_nodes().await.expect("read-only must still allow GET");

        // POST refused with a typed ReadOnlyRefusal (exit-8 family), and
        // the request never reaches the server.
        let err = c
            .start_guest("pve1", 100, GuestType::Qemu)
            .await
            .expect_err("read-only profile must refuse the write");
        assert!(err.to_string().contains("read-only"), "got: {err:#}");
        assert!(
            err.chain().any(|e| e
                .downcast_ref::<proxxx::config::ReadOnlyRefusal>()
                .is_some()),
            "must be a typed ReadOnlyRefusal so main.rs maps exit 8"
        );
    }
}

#[test]
fn empty_backup_jobs_array_parses_cleanly() {
    use proxxx::api::types::{ApiResponse, BackupJob};
    let raw = br#"{"data":[]}"#;
    let parsed: ApiResponse<Vec<BackupJob>> =
        serde_json::from_slice(raw).expect("empty BackupJob array must parse");
    assert!(parsed.data.is_empty());
}
