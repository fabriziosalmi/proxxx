#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! PBS integration tests (feature #3).
//!
//! Targets:
//! - Endpoint routing: datastores list / snapshots list / files list
//! - Auth header format (`PBSAPIToken=user!tokenid=secret`)
//! - Filter query string assembly for snapshot list
//!
//! Restore is shell-out — covered by unit tests in `pbs::restore` (binary
//! detection, repository string format, target validation).

#[cfg(test)]
mod tests {
    use proxxx::config::PbsConfig;
    use proxxx::pbs::{PbsClient, PbsGateway};
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn client(server: &MockServer) -> PbsClient {
        let cfg = PbsConfig {
            url: server.uri(),
            user: "proxxx@pbs".into(),
            token_id: "reader".into(),
            token_secret: Some("s3cret".into()),
            token_secret_file: None,
            verify_tls: false,
            rate_limit: Some(100),
        };
        PbsClient::new(cfg, None).await.expect("client builds")
    }

    #[tokio::test]
    async fn list_datastores_hits_admin_datastore() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/admin/datastore"))
            // Auth header must be the canonical PBS form.
            .and(header(
                "Authorization",
                "PBSAPIToken=proxxx@pbs!reader=s3cret",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"store": "main", "comment": "primary"},
                    {"store": "offsite", "comment": ""}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let stores = client(&server).await.list_datastores().await.expect("list");
        assert_eq!(stores.len(), 2);
        assert_eq!(stores[0].store, "main");
    }

    #[tokio::test]
    async fn list_snapshots_with_filters_passes_query_params() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/admin/datastore/main/snapshots"))
            .and(query_param("backup-type", "vm"))
            .and(query_param("backup-id", "100"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "backup-type": "vm",
                        "backup-id": "100",
                        "backup-time": 1705312800u64,
                        "size": 12345,
                        "owner": "proxxx@pbs!reader",
                        "protected": false
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let snaps = client(&server)
            .await
            .list_snapshots("main", Some("vm"), Some("100"))
            .await
            .expect("list");
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].backup_id, "100");
        assert_eq!(snaps[0].snapshot_ref(), "vm/100/2024-01-15T10:00:00Z");
    }

    #[tokio::test]
    async fn list_snapshots_without_filters_omits_query_params() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/admin/datastore/main/snapshots"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .expect(1)
            .mount(&server)
            .await;
        let snaps = client(&server)
            .await
            .list_snapshots("main", None, None)
            .await
            .expect("list");
        assert!(snaps.is_empty());
    }

    #[tokio::test]
    async fn list_snapshot_files_hits_files_endpoint_with_all_params() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/admin/datastore/main/files"))
            .and(query_param("backup-type", "vm"))
            .and(query_param("backup-id", "100"))
            .and(query_param("backup-time", "1705312800"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {"filename": "root.pxar.didx", "size": 1000, "crypt-mode": "none"},
                    {"filename": "drive-scsi0.img.fidx", "size": 99999, "crypt-mode": "encrypt"}
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;
        let files = client(&server)
            .await
            .list_snapshot_files("main", "vm", "100", 1_705_312_800)
            .await
            .expect("files");
        assert_eq!(files.len(), 2);
        assert!(files[0].is_pxar());
        assert!(!files[0].is_encrypted());
        assert!(!files[1].is_pxar());
        assert!(files[1].is_encrypted());
    }

    #[tokio::test]
    async fn list_datastores_surfaces_5xx_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api2/json/admin/datastore"))
            .respond_with(ResponseTemplate::new(503).set_body_string("PBS down"))
            .mount(&server)
            .await;
        let err = client(&server)
            .await
            .list_datastores()
            .await
            .expect_err("must error on 503");
        assert!(
            err.to_string().contains("503"),
            "error mentions status: {err}"
        );
    }
}
