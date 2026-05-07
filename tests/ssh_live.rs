#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]
//! Live SSH-layer coverage.
//!
//! `proxxx perms` and `proxxx patch apply` shell out via the SSH
//! layer (`src/ssh/`). Without a live test, every regression in
//! `russh` integration, `known_hosts` TOFU, or session-pool eviction
//! lands as a runtime failure on the operator's first invocation.
//!
//! Why this file (separate from `tests/rbac_live.rs`): the SSH layer
//! is independent of PVE's REST API — TOFU, key auth, channel
//! eviction are all on the SSH side. Keeping the env contract narrow
//! (SSH-only env vars) means an operator who has SSH-but-not-RBAC, or
//! RBAC-but-not-SSH, only has to provision the half they need.
//!
//! ## Env contract
//!
//! ```bash
//! export PROXXX_E2E_SSH_ENABLE=1
//! export PROXXX_E2E_SSH_HOST="10.0.0.1"        # PVE node hostname/IP
//! export PROXXX_E2E_SSH_USER="root"             # default: root
//! export PROXXX_E2E_SSH_KEY_PATH="$HOME/.ssh/proxxx_e2e_ed25519"
//! cargo test --release --test ssh_live -- --ignored --nocapture
//! ```
//!
//! The test:
//! 1. Builds an `SshConfig` from the env (NOT from the user's
//!    `config.toml` — the live harness must not depend on the
//!    operator's writable config).
//! 2. Points `known_hosts` at a per-test temp file so the suite never
//!    contaminates the operator's existing host key store.
//! 3. Runs a deterministic read-only command (`uname -a`) via
//!    `SshPool::exec` and pins exit code + stdout shape.
//!
//! The `setup_demo.sh --with-ssh` flag (this PR) is the operator's
//! companion script: it verifies the env vars are set, the key file
//! is reachable + 0600, and an `ssh -i ${KEY}` round-trip works,
//! BEFORE the test reaches `SshSession::connect` — making failures
//! diagnose-able from the script's "missing this env var" message
//! rather than a russh handshake error mid-test.

use std::collections::HashMap;
use std::path::PathBuf;

use proxxx::config::SshConfig;
use proxxx::ssh::{ExecOptions, SshPool};

struct SshEnv {
    host: String,
    user: String,
    key_path: PathBuf,
    /// Per-process tmp `known_hosts`. Cleaned up at test end (best-effort).
    known_hosts: PathBuf,
}

impl SshEnv {
    fn load_or_skip() -> Option<Self> {
        if std::env::var("PROXXX_E2E_SSH_ENABLE").as_deref() != Ok("1") {
            eprintln!("[ssh-live] PROXXX_E2E_SSH_ENABLE != 1 — skipping");
            return None;
        }
        let host = std::env::var("PROXXX_E2E_SSH_HOST").ok()?;
        let user = std::env::var("PROXXX_E2E_SSH_USER").unwrap_or_else(|_| "root".to_string());
        let key_path: PathBuf = std::env::var("PROXXX_E2E_SSH_KEY_PATH").ok()?.into();
        if !key_path.exists() {
            eprintln!(
                "[ssh-live] PROXXX_E2E_SSH_KEY_PATH={} does not exist — skipping",
                key_path.display()
            );
            return None;
        }
        // Per-process tmp known_hosts so the test never writes to the
        // operator's real proxxx known_hosts. PID-suffix avoids
        // collisions when multiple tests run in parallel (rare here —
        // there's only one ssh test — but cheap insurance).
        let known_hosts = std::env::temp_dir().join(format!(
            "proxxx-ssh-live-test-known_hosts-{}",
            std::process::id()
        ));
        // Clean any leftover from a previous run before the suite starts.
        let _ = std::fs::remove_file(&known_hosts);
        Some(Self {
            host,
            user,
            key_path,
            known_hosts,
        })
    }

    /// Build an `SshConfig` synthesised from the env (NOT loaded from
    /// the user's `config.toml`). Uses the first-class `tofu` policy
    /// so the test self-bootstraps the host key on first connection.
    fn ssh_config(&self) -> SshConfig {
        let mut hosts = HashMap::new();
        // The pool keys sessions by node name; we use a synthetic node
        // name and map it to the env-supplied host so the test isn't
        // hardcoded to any specific PVE topology.
        hosts.insert("e2e-node".to_string(), self.host.clone());

        SshConfig {
            user: self.user.clone(),
            key_path: Some(self.key_path.to_string_lossy().into_owned()),
            hosts,
            known_hosts: Some(self.known_hosts.to_string_lossy().into_owned()),
            strict_host_key_checking: "tofu".to_string(),
            max_concurrent: 4,
            idle_timeout_secs: 60,
            exec_timeout_secs: 30,
            guests: HashMap::new(),
        }
    }
}

impl Drop for SshEnv {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.known_hosts);
    }
}

macro_rules! ssh_env_or_skip {
    () => {{
        let Some(env) = SshEnv::load_or_skip() else {
            return;
        };
        env
    }};
}

/// Closes the "SSH layer · live exec contract" row in
/// [pre-commit/01-feature-coverage.md]. Pre-fix coverage was
/// wiremock-only at the russh layer (impossible — russh is the
/// transport), so this is the FIRST live verification that
/// `SshPool::new + exec` round-trips correctly against a real PVE
/// node. Failure modes this catches that unit tests cannot:
///   - russh handshake regression (key exchange / auth)
///   - `known_hosts` TOFU first-write does not corrupt the file
///   - session pool initialises and tears down cleanly
///   - exec result fields (`stdout`, `exit_code`) are populated by the
///     channel event loop, not just defaulted
#[tokio::test]
#[ignore = "live SSH: requires PROXXX_E2E_SSH_ENABLE=1 + reachable PVE node"]
async fn ssh_pool_exec_uname_round_trip() {
    let env = ssh_env_or_skip!();
    let cfg = env.ssh_config();

    let pool = SshPool::new(cfg, None).expect("SshPool::new");

    // `uname -a` is universally available on every PVE node (Debian)
    // and produces a predictable single-line stdout starting with
    // `Linux ` — the most boring assertion possible.
    let res = pool
        .exec("e2e-node", "uname -a", ExecOptions::default())
        .await
        .expect("ssh exec");

    assert!(
        res.ok(),
        "uname -a must exit 0; got exit_code={:?} stderr={}",
        res.exit_code,
        res.stderr.trim()
    );
    assert!(
        res.stdout.starts_with("Linux"),
        "uname -a stdout must start with 'Linux', got: {:?}",
        res.stdout.trim()
    );
}

/// A second probe targeting the contract-relevant `pveum` shell-out
/// path — the same code path `proxxx perms` uses. `pveum user
/// permissions root@pam` is read-only and exists on every PVE node.
/// The output is a Unicode-bordered table with `ACL path` /
/// `Permissions` columns. We pin the header so a silent `pveum`
/// regression (exit 0 + empty / column rename) can't slip past.
#[tokio::test]
#[ignore = "live SSH: requires PROXXX_E2E_SSH_ENABLE=1 + reachable PVE node"]
async fn ssh_pool_exec_pveum_user_permissions_round_trip() {
    let env = ssh_env_or_skip!();
    let cfg = env.ssh_config();

    let pool = SshPool::new(cfg, None).expect("SshPool::new");

    let res = pool
        .exec(
            "e2e-node",
            "pveum user permissions root@pam",
            ExecOptions::default(),
        )
        .await
        .expect("ssh exec");

    assert!(
        res.ok(),
        "pveum user permissions root@pam must exit 0; got exit_code={:?} stderr={}",
        res.exit_code,
        res.stderr.trim()
    );
    // pveum renders a Unicode-bordered table with `ACL path` and
    // `Permissions` columns. Root@pam always has perms on `/`, so a
    // valid output contains BOTH the header AND a `/` row line. This
    // catches: (a) silent format change, (b) empty-table 0-exit, (c)
    // raw stdout being JSON or YAML rather than the rendered table.
    assert!(
        res.stdout.contains("ACL path") && res.stdout.contains("Permissions"),
        "pveum stdout must include the table header (ACL path / Permissions); got: {:?}",
        res.stdout.chars().take(500).collect::<String>()
    );
    assert!(
        res.stdout.lines().any(|l| l.contains("│ /")),
        "pveum output must include at least one ACL row for root@pam (root path); got: {:?}",
        res.stdout.chars().take(500).collect::<String>()
    );
}
