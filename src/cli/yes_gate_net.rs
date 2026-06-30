//! Behavioural "test net" for the destructive-confirmation gates (#172).
//!
//! Every destructive CLI command routes its `--yes` check through
//! [`crate::cli::common::require_yes`] (unit-tested in `common.rs`). This net
//! goes one level higher: it drives the *real* command handlers with
//! `yes = false` and asserts they refuse **before touching the network**.
//!
//! The client points at a dead endpoint (`127.0.0.1:1`). If a handler's gate
//! were ever dropped, the command would fall through to its API call and fail
//! with a *connection* error — visibly different from the `--yes` refusal this
//! net asserts. So a silently-dropped gate turns a green test red, which is
//! exactly the regression the issue calls out (today it passes CI unnoticed).
//!
//! Coverage is representative, not exhaustive: one handler per a couple of
//! families, enough to prove the gate fires in the real dispatch path. The
//! single chokepoint (`require_yes`) is what makes per-command enumeration
//! unnecessary for the common case.

use std::sync::Arc;

use crate::api::PxClient;
use crate::config::ProfileConfig;

/// Build a `PxClient` that never needs the network: token auth with an inline
/// dummy secret (no login round-trip), TOFU off, pointed at a black-hole URL.
async fn offline_client() -> Arc<PxClient> {
    let cfg = ProfileConfig {
        url: "http://127.0.0.1:1".into(),
        user: "root@pam".into(),
        auth: "token".into(),
        token_id: Some("net".into()),
        token_secret: Some(zeroize::Zeroizing::new("dummy".into())),
        token_secret_file: None,
        password: None,
        verify_tls: false,
        tls_pin_mode: None,
        read_only: false,
        rate_limit: None,
        policies: None,
        telegram: None,
        ssh: None,
        pbs: None,
        alerts: None,
        mcp_token: None,
        reconcile: None,
        profile_name: None,
    };
    Arc::new(
        PxClient::new(cfg, Some("dummy"))
            .await
            .expect("offline token-auth client must build without a network round-trip"),
    )
}

/// A representative destructive command from each of two families refuses with
/// the `--yes` guidance and never reaches its gateway call.
#[tokio::test]
async fn destructive_commands_refuse_without_yes() {
    use super::access::{execute_access, AccessCommand};
    use super::cluster::{execute_pool, PoolCommand};

    let client = offline_client().await;

    let err = execute_pool(
        &client,
        PoolCommand::Delete {
            poolid: "net-test".into(),
            yes: false,
        },
    )
    .await
    .expect_err("pool delete must refuse without --yes");
    assert!(
        err.to_string().contains("--yes"),
        "pool delete should refuse with --yes guidance, got: {err}"
    );

    let err = execute_access(
        &client,
        AccessCommand::UserDelete {
            userid: "net@pam".into(),
            yes: false,
        },
    )
    .await
    .expect_err("user delete must refuse without --yes");
    assert!(
        err.to_string().contains("--yes"),
        "user delete should refuse with --yes guidance, got: {err}"
    );
}
