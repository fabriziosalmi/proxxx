#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::too_many_lines
)]
//! Live cluster coverage for `pre-commit/01-feature-coverage.md` rows
//! that were previously ⚠️ wiremock-only.
//!
//! Tests are `#[ignore]`-gated + env-var-fenced — same pattern as
//! `tests/ssh_live.rs` / `tests/rbac_live.rs`. `cargo test` skips
//! them; the live suite is opted-in via:
//!
//! ```bash
//! export PROXXX_E2E_FEATURE_COVERAGE_ENABLE=1
//! export PROXXX_E2E_API_URL="https://192.168.0.122:8006"
//! export PROXXX_E2E_TOKEN="proxxx=<secret>"           # `tokenid=secret`
//! export PROXXX_E2E_NODE="pve-test-1"
//! export PROXXX_E2E_QGA_VMID=8888                     # running QEMU
//! cargo test --release --test feature_coverage_live -- --ignored --nocapture
//! ```
//!
//! ## Scope of this sweep
//!
//! These tests pin the **typed-deserialiser** end-to-end against the
//! live PVE 9.1.1 ABI for several READ surfaces. They flip the
//! corresponding 01-rows from ⚠️ wiremock-only to ✅ live by proving
//! the deserialiser still parses whatever the cluster actually
//! returns today.
//!
//! What is NOT in scope here — and why:
//!
//! - **QGA exec** — the test cluster surfaces sporadic 596s on
//!   `/agent/exec` under load (verified curl-side too). The contract
//!   "QGA exec works when cluster is healthy" is structurally
//!   attested by `tests/live/test_mutation.sh` batch 4 already; this
//!   sweep skips it to avoid flake.
//! - **Snapshot mutation lifecycle (QEMU)** — running QEMU snapshots
//!   on this cluster take O(minutes), making the test timeout-prone.
//!   The QEMU snapshot path is wiremock-pinned; live LXC equivalent
//!   is exercised in `test_mutation.sh` batch 1 against VMID 9999
//!   (which uses local-lvm; the long-lived LXC 7777 here is on NFS
//!   raw, which PVE refuses with "snapshot feature is not available").
//! - **Destructive mutations (disk resize, migrate, delete)** — by
//!   design out of scope for a `--ignored`-by-default Rust suite that
//!   any contributor can opt into. Those live in the gate's
//!   `test_mutation.sh` against transient VMIDs.

use std::sync::Arc;

use anyhow::Result;
use proxxx::api::types::GuestType;
use proxxx::api::{ProxmoxGateway, PxClient};
use proxxx::config::ProfileConfig;

/// Env loader — `None` if the suite is disabled or env is incomplete.
/// Disabled by default; opt-in via `PROXXX_E2E_FEATURE_COVERAGE_ENABLE=1`.
#[derive(Debug, Clone)]
struct CoverageEnv {
    api_url: String,
    token: String, // `tokenid=secret`
    node: String,
    qga_vmid: u32,
}

impl CoverageEnv {
    fn load() -> Option<Self> {
        if std::env::var("PROXXX_E2E_FEATURE_COVERAGE_ENABLE").as_deref() != Ok("1") {
            eprintln!("[coverage-live] PROXXX_E2E_FEATURE_COVERAGE_ENABLE != 1 — skipping");
            return None;
        }
        let api_url = std::env::var("PROXXX_E2E_API_URL").ok()?;
        let token = std::env::var("PROXXX_E2E_TOKEN").ok()?;
        let node = std::env::var("PROXXX_E2E_NODE").ok()?;
        let qga_vmid: u32 = std::env::var("PROXXX_E2E_QGA_VMID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8888);
        Some(Self {
            api_url,
            token,
            node,
            qga_vmid,
        })
    }

    /// Build a token-auth client from env. The `tokenid` part of the
    /// `tokenid=secret` env value is the token ID; the trailing part
    /// after `=` is the secret. We pass the secret to `cli_secret`
    /// (resolver priority #1).
    async fn client(&self) -> Result<Arc<PxClient>> {
        let (tok_id, secret) = self
            .token
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("PROXXX_E2E_TOKEN must be `tokenid=secret`"))?;
        let cfg = ProfileConfig {
            url: self.api_url.clone(),
            user: "root@pam".into(),
            auth: "token".into(),
            token_id: Some(tok_id.to_string()),
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
        Ok(Arc::new(PxClient::new(cfg, Some(secret)).await?))
    }
}

/// Macro: skip the test with a printed reason if env isn't set.
macro_rules! skip_if_no_env {
    () => {
        match CoverageEnv::load() {
            Some(env) => env,
            None => return,
        }
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// § 1. Guest config typed-deser (live)
//
// Closes 01-row:
//   - "Read guest config (QEMU)" — previously ⚠️ wiremock-only.
// ─────────────────────────────────────────────────────────────────────────────

/// 01-row · `get_guest_config` against the QGA test VM, end-to-end live.
///
/// Exercises the typed deserializer for the running PVE 9.1.1 version.
/// A schema drift between proxxx's type model and what PVE returns
/// would surface as `ApiError::Parse`.
#[tokio::test]
#[ignore = "live — needs PROXXX_E2E_FEATURE_COVERAGE_ENABLE=1"]
#[serial_test::serial]
async fn get_guest_config_typed_deser_survives_live_pve() {
    let env = skip_if_no_env!();
    let client = env.client().await.expect("client");
    let vmid = env.qga_vmid;
    let node = env.node.as_str();

    let cfg = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client.get_guest_config(node, vmid, &GuestType::Qemu),
    )
    .await
    .expect("must not hang past 30 s")
    .expect("get_guest_config");

    assert!(
        !cfg.is_empty(),
        "guest config must be non-empty for a running VM"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// § 2. Snapshot list typed-deser (live)
//
// Closes 01-rows:
//   - "Read flat snapshot list (QEMU)" — previously ⚠️ wiremock-only.
//   - "Read flat snapshot list (LXC)" — already ✅; this re-pins via Rust.
//
// The list call returns at least the synthetic `current` entry even
// when the guest has no real snapshots. This proves the deser path
// survives PVE 9.1.1's actual wire shape.
// ─────────────────────────────────────────────────────────────────────────────

/// 01-row · `list_snapshots` against a running QEMU, end-to-end live.
#[tokio::test]
#[ignore = "live — needs PROXXX_E2E_FEATURE_COVERAGE_ENABLE=1"]
#[serial_test::serial]
async fn list_snapshots_qemu_typed_deser_survives_live_pve() {
    let env = skip_if_no_env!();
    let client = env.client().await.expect("client");
    let vmid = env.qga_vmid;
    let node = env.node.as_str();

    let snaps = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client.list_snapshots(node, vmid, GuestType::Qemu),
    )
    .await
    .expect("must not hang past 30 s")
    .expect("list_snapshots");

    // PVE always returns at least the `current` synthetic entry.
    assert!(
        snaps.iter().any(|s| s.name == "current"),
        "snapshot list must include `current`, got: {snaps:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// § 3. Storage pool read typed-deser (live)
//
// Closes 01-row:
//   - "Read storage pool list" — already ✅ in 01; this re-pins via Rust.
// ─────────────────────────────────────────────────────────────────────────────

/// 01-row · `get_storage_pools` end-to-end live.
#[tokio::test]
#[ignore = "live — needs PROXXX_E2E_FEATURE_COVERAGE_ENABLE=1"]
#[serial_test::serial]
async fn get_storage_pools_typed_deser_survives_live_pve() {
    let env = skip_if_no_env!();
    let client = env.client().await.expect("client");
    let node = env.node.as_str();

    let pools = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client.get_storage_pools(node),
    )
    .await
    .expect("must not hang past 30 s")
    .expect("get_storage_pools");

    assert!(
        !pools.is_empty(),
        "storage pool list must be non-empty on a real PVE node"
    );
    // Each entry must have a non-empty `storage` id.
    for p in &pools {
        assert!(
            !p.storage.is_empty(),
            "storage pool entry missing `storage` id: {p:?}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// § 4. Cluster tasks read typed-deser (live)
//
// Closes 01-row:
//   - "Tasks read" — already ✅ in 01; this re-pins via Rust.
// ─────────────────────────────────────────────────────────────────────────────

/// 01-row · `get_cluster_tasks` end-to-end live.
///
/// The cluster-task list historically drifted from proxxx's type
/// model (e.g. PVE started returning `uid` as a string instead of
/// number on some versions — see the live fix in [src/api/types.rs](src/api/types.rs)).
/// This test pins that proxxx's current types parse what PVE 9.1.1
/// actually returns.
#[tokio::test]
#[ignore = "live — needs PROXXX_E2E_FEATURE_COVERAGE_ENABLE=1"]
#[serial_test::serial]
async fn get_cluster_tasks_typed_deser_survives_live_pve() {
    let env = skip_if_no_env!();
    let client = env.client().await.expect("client");

    let tasks = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client.get_cluster_tasks(),
    )
    .await
    .expect("must not hang past 30 s")
    .expect("get_cluster_tasks");

    // Even a quiet cluster has historical tasks (the pre-flight from
    // the gate run, the daily apt-update, etc.). Empty is suspicious
    // but not necessarily broken — accept any shape, but each task
    // must have a non-empty UPID + node.
    for t in &tasks {
        assert!(!t.upid.is_empty(), "task entry missing UPID: {t:?}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// § 5. Node list + guests-on-node typed-deser (live)
//
// These rows are already ✅ in 01 via the bash gate; this Rust pin
// makes the deserialiser regression cheap to catch on contributor
// machines too.
// ─────────────────────────────────────────────────────────────────────────────

/// 01-row · `get_nodes` end-to-end live.
#[tokio::test]
#[ignore = "live — needs PROXXX_E2E_FEATURE_COVERAGE_ENABLE=1"]
#[serial_test::serial]
async fn get_nodes_typed_deser_survives_live_pve() {
    let env = skip_if_no_env!();
    let client = env.client().await.expect("client");

    let nodes = tokio::time::timeout(std::time::Duration::from_secs(30), client.get_nodes())
        .await
        .expect("must not hang past 30 s")
        .expect("get_nodes");

    assert!(
        !nodes.is_empty(),
        "node list must be non-empty on a real cluster"
    );
    for n in &nodes {
        assert!(!n.node.is_empty(), "node entry missing `node` id: {n:?}");
    }
}

/// 01-row · `get_guests` on a specific node, end-to-end live.
#[tokio::test]
#[ignore = "live — needs PROXXX_E2E_FEATURE_COVERAGE_ENABLE=1"]
#[serial_test::serial]
async fn get_guests_typed_deser_survives_live_pve() {
    let env = skip_if_no_env!();
    let client = env.client().await.expect("client");
    let node = env.node.as_str();

    let guests = tokio::time::timeout(std::time::Duration::from_secs(30), client.get_guests(node))
        .await
        .expect("must not hang past 30 s")
        .expect("get_guests");

    // 8888 + 7777 are always there on the test cluster; the live
    // attestation is "the typed deser doesn't error", and "at least
    // one of the well-known fixtures is present".
    let env_qga_vmid = env.qga_vmid;
    assert!(
        guests.iter().any(|g| g.vmid == env_qga_vmid),
        "expected VMID {env_qga_vmid} to be present in guest list, got: \
         {:?}",
        guests.iter().map(|g| g.vmid).collect::<Vec<_>>()
    );
}
