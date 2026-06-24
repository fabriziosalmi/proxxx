#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! Fleet view integration tests.
//!
//! Exercises the REAL read path: a `PxClient` per fake cluster
//! (wiremock-backed, built exactly like the production client), driven
//! through `tui::fleet::fetch_with_gateway`, then folded into
//! `FleetState` via the real `apply` reducer. Proves:
//!   * aggregation across clusters with correct counts,
//!   * one-cluster-down graceful degradation (a 500 on `/nodes`
//!     becomes a `ClusterError`, never aborts the others),
//!   * attribution-by-containment (each guest carries its OWNING
//!     cluster's profile, even when a VMID is shared).
//!
//! This is the highest-fidelity test: it spans `PxClient` HTTP, the
//! trait-default `get_all_guests`/`get_all_storage_pools`, and the
//! reducer — the exact production pipeline minus the config-file
//! enumeration (which the live script covers against real hosts).

#[cfg(test)]
mod tests {
    use proxxx::api::PxClient;
    use proxxx::config::ProfileConfig;
    use proxxx::tui::fleet::{apply, fetch_with_gateway, FleetDataMsg, FleetFocus, FleetState};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg_for(server: &MockServer) -> ProfileConfig {
        ProfileConfig {
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
            reconcile: None,
            profile_name: None,
        }
    }

    async fn client_for(server: &MockServer) -> PxClient {
        PxClient::new(cfg_for(server), Some("fake-secret"))
            .await
            .expect("client builds")
    }

    #[allow(clippy::needless_pass_by_value)] // moved into the json! macro
    fn data(body: serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": body }))
    }

    /// Mount `/nodes` listing the given online node names.
    async fn mount_nodes(server: &MockServer, nodes: &[&str]) {
        let arr: Vec<_> = nodes
            .iter()
            .map(|n| {
                serde_json::json!({
                    "node": n, "status": "online",
                    "maxcpu": 8, "cpu": 0.1,
                    "mem": 16_u64 << 30, "maxmem": 64_u64 << 30,
                    "disk": 0, "maxdisk": 0, "uptime": 1000
                })
            })
            .collect();
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes"))
            .respond_with(data(serde_json::json!(arr)))
            .mount(server)
            .await;
    }

    /// Mount a node's qemu + lxc guest lists and its storage pools.
    async fn mount_node_detail(
        server: &MockServer,
        node: &str,
        qemu: serde_json::Value,
        lxc: serde_json::Value,
        storage: serde_json::Value,
    ) {
        Mock::given(method("GET"))
            .and(path(format!("/api2/json/nodes/{node}/qemu")))
            .respond_with(data(qemu))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api2/json/nodes/{node}/lxc")))
            .respond_with(data(lxc))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/api2/json/nodes/{node}/storage")))
            .respond_with(data(storage))
            .mount(server)
            .await;
    }

    fn vm(vmid: u32, name: &str, status: &str) -> serde_json::Value {
        serde_json::json!({"vmid": vmid, "name": name, "status": status, "type": "qemu"})
    }
    fn ct(vmid: u32, name: &str, status: &str) -> serde_json::Value {
        serde_json::json!({"vmid": vmid, "name": name, "status": status, "type": "lxc"})
    }
    fn pool(name: &str, used: u64, total: u64) -> serde_json::Value {
        serde_json::json!({"storage": name, "type": "dir", "used": used, "total": total,
                           "avail": total - used, "active": 1, "content": "images"})
    }

    #[tokio::test]
    async fn fleet_aggregates_across_clusters_and_degrades_gracefully() {
        // ── alpha: 2 online nodes, 3 guests, shared nfs pool ──
        let alpha = MockServer::start().await;
        mount_nodes(&alpha, &["a1", "a2"]).await;
        mount_node_detail(
            &alpha,
            "a1",
            serde_json::json!([vm(100, "alpha-web", "running")]),
            serde_json::json!([]),
            serde_json::json!([pool("local", 50, 100), pool("nfs", 1000, 4000)]),
        )
        .await;
        mount_node_detail(
            &alpha,
            "a2",
            serde_json::json!([vm(101, "alpha-db", "stopped")]),
            serde_json::json!([ct(200, "alpha-ct", "running")]),
            // nfs reported again by a2 — must be de-duplicated.
            serde_json::json!([pool("local", 50, 100), pool("nfs", 1000, 4000)]),
        )
        .await;

        // ── beta: 1 online node, 1 guest (VMID 100 — shared with alpha!) ──
        let beta = MockServer::start().await;
        mount_nodes(&beta, &["b1"]).await;
        mount_node_detail(
            &beta,
            "b1",
            serde_json::json!([vm(100, "beta-web", "running")]),
            serde_json::json!([]),
            serde_json::json!([pool("local", 10, 100)]),
        )
        .await;

        // ── gamma: /nodes returns 500 → whole cluster unreachable ──
        let gamma = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/nodes"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&gamma)
            .await;

        // Drive the real fetch seam per cluster, fold via the real reducer.
        let mut state = FleetState::default();

        let ca = client_for(&alpha).await;
        match fetch_with_gateway(&ca).await {
            Ok((nodes, guests, storage)) => apply(
                &mut state,
                FleetDataMsg::ClusterSnapshot {
                    profile: "alpha".into(),
                    nodes,
                    guests,
                    storage,
                },
            ),
            Err(e) => panic!("alpha should be reachable: {e:#}"),
        }

        let cb = client_for(&beta).await;
        let (nodes, guests, storage) = fetch_with_gateway(&cb).await.expect("beta reachable");
        apply(
            &mut state,
            FleetDataMsg::ClusterSnapshot {
                profile: "beta".into(),
                nodes,
                guests,
                storage,
            },
        );

        let cg = client_for(&gamma).await;
        let err = fetch_with_gateway(&cg)
            .await
            .expect_err("gamma 500 must error");
        apply(
            &mut state,
            FleetDataMsg::ClusterError {
                profile: "gamma".into(),
                error: format!("{err:#}"),
            },
        );

        // ── assertions ──
        assert_eq!(state.clusters.len(), 3, "alpha + beta + gamma");
        let names: Vec<&str> = state.clusters.iter().map(|c| c.profile.as_str()).collect();
        assert_eq!(names, ["alpha", "beta", "gamma"], "stable-sorted");

        let alpha_c = state
            .clusters
            .iter()
            .find(|c| c.profile == "alpha")
            .unwrap();
        assert!(alpha_c.reachable);
        assert_eq!(alpha_c.nodes.len(), 2);
        assert_eq!(alpha_c.guests.len(), 3, "100 + 101 + 200");
        assert_eq!(alpha_c.running_guests(), 2);
        assert_eq!(alpha_c.stopped_guests(), 1);
        // Both pools ("local", "nfs") are reported by BOTH nodes; dedup
        // by name counts each once: local 50/100 + nfs 1000/4000.
        assert_eq!(alpha_c.storage_used(), 1050, "local + nfs, deduped");
        assert_eq!(alpha_c.storage_total(), 4100, "local + nfs, deduped");

        let beta_c = state.clusters.iter().find(|c| c.profile == "beta").unwrap();
        assert!(beta_c.reachable);
        assert_eq!(beta_c.guests.len(), 1);

        // gamma down but present, with an error, surviving siblings intact.
        let gamma_c = state
            .clusters
            .iter()
            .find(|c| c.profile == "gamma")
            .unwrap();
        assert!(!gamma_c.reachable);
        assert!(gamma_c.error.is_some());
        assert!(gamma_c.guests.is_empty());

        // Fleet-wide guest view: 3 (alpha) + 1 (beta) = 4, each attributed
        // to its OWNING cluster even though VMID 100 exists in both.
        state.focus = FleetFocus::AllGuests;
        let pairs = state.visible_guests();
        assert_eq!(pairs.len(), 4);
        let alpha_100 = pairs
            .iter()
            .find(|(p, g)| *p == "alpha" && g.vmid == 100)
            .unwrap();
        let beta_100 = pairs
            .iter()
            .find(|(p, g)| *p == "beta" && g.vmid == 100)
            .unwrap();
        assert_eq!(alpha_100.1.name, "alpha-web");
        assert_eq!(beta_100.1.name, "beta-web");
    }
}
