//! Mission 2 — E2E test infrastructure.
//!
//! This module is `#[path = "common/mod.rs"] mod common;`-included by
//! every `tests/e2e_*.rs` binary. It enforces the three inviolable
//! dogmas:
//!
//! 1. **No `sleep()`** — convergence is verified via [`poll_until`].
//!    Asserting "VM is now running" is a state question, not a time
//!    question. Polling re-queries the API on a configurable cadence
//!    until either the predicate returns `Some(_)` or the wall-clock
//!    timeout fires.
//!
//! 2. **Serial execution** — every mutation test must wear
//!    `#[serial_test::serial]`. The shared cluster cannot tolerate
//!    two tests racing the same VMID; PVE returns `500: VM is locked`
//!    and the test aborts mid-flight, leaving zombies.
//!
//! 3. **RAII teardown** — [`TestResourceGuard`] registers every
//!    resource the test mutates. On `Drop` (whether the test passed,
//!    failed, or panicked), the guard issues stop-and-delete on each
//!    registered resource, on a fresh tokio runtime spawned in a
//!    side thread. The cluster ends every test in the same shape it
//!    started — no manual cleanup, no zombies.
//!
//! ## Env contract
//!
//! E2E tests are `#[ignore]`-gated by default. `cargo test` skips
//! them silently. To run:
//!
//! ```bash
//! export PROXXX_E2E_ENABLE=1
//! export PROXXX_E2E_API_URL=https://pve1.lan:8006
//! export PROXXX_E2E_USER=root@pam
//! export PROXXX_E2E_TOKEN_ID=test
//! export PROXXX_E2E_TOKEN_SECRET=...
//! export PROXXX_E2E_NODE=pve1
//! export PROXXX_E2E_VMID=9999            # the playground VMID
//! export PROXXX_E2E_TEMPLATE=local:vztmpl/debian-12-standard_12.7-1_amd64.tar.zst
//! export PROXXX_E2E_STORAGE=local-lvm
//! cargo test --release --test e2e_alpha -- --ignored --nocapture
//! ```

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc
)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use proxxx::api::types::GuestType;
use proxxx::api::{ProxmoxGateway, PxClient};

// ── Env gate ────────────────────────────────────────────

/// Read-only snapshot of the env contract. Constructed once per test
/// via [`E2eEnv::load`]; failure to load means the test should
/// silently skip.
#[derive(Debug, Clone)]
pub struct E2eEnv {
    pub api_url: String,
    pub user: String,
    pub token_id: String,
    pub token_secret: String,
    pub node: String,
    pub vmid: u32,
    pub template: Option<String>,
    pub storage: Option<String>,
    pub allow_delete: bool,
}

impl E2eEnv {
    /// Returns `Some(env)` if every required variable is present and
    /// `PROXXX_E2E_ENABLE=1`, else `None`. Call sites:
    /// `let Some(env) = common::E2eEnv::load() else { return; };`
    /// produces a cleanly-skipped test on dev machines.
    pub fn load() -> Option<Self> {
        if std::env::var("PROXXX_E2E_ENABLE").as_deref() != Ok("1") {
            eprintln!("[e2e] PROXXX_E2E_ENABLE != 1 — skipping");
            return None;
        }
        let api_url = std::env::var("PROXXX_E2E_API_URL").ok()?;
        let user = std::env::var("PROXXX_E2E_USER").ok()?;
        let token_id = std::env::var("PROXXX_E2E_TOKEN_ID").ok()?;
        let token_secret = std::env::var("PROXXX_E2E_TOKEN_SECRET").ok()?;
        let node = std::env::var("PROXXX_E2E_NODE").ok()?;
        let vmid: u32 = std::env::var("PROXXX_E2E_VMID").ok()?.parse().ok()?;
        let template = std::env::var("PROXXX_E2E_TEMPLATE").ok();
        let storage = std::env::var("PROXXX_E2E_STORAGE").ok();
        let allow_delete = std::env::var("PROXXX_E2E_ALLOW_DELETE").as_deref() == Ok("1");
        Some(Self {
            api_url,
            user,
            token_id,
            token_secret,
            node,
            vmid,
            template,
            storage,
            allow_delete,
        })
    }

    /// Build a `PxClient` from the env. Token-only (no password
    /// fallback in E2E to keep the test deterministic).
    pub async fn build_client(&self) -> Result<Arc<PxClient>> {
        // We construct a `ProfileConfig` directly rather than going
        // through the TOML loader — the E2E env IS the source of truth
        // and we don't want to touch ~/.config/proxxx.
        //
        // The token secret is passed via cli_secret (resolver priority
        // #1) instead of being injected through PROXXX_TOKEN_SECRET. The
        // env-var path is process-global; with concurrent test binaries
        // sharing a parent shell environment, a stale set_var can leak
        // into a sibling suite that legitimately wants the env empty.
        let cfg = proxxx::config::ProfileConfig {
            url: self.api_url.clone(),
            user: self.user.clone(),
            auth: "token".into(),
            token_id: Some(self.token_id.clone()),
            token_secret: None,
            token_secret_file: None,
            password: None,
            verify_tls: false,
            tls_pin_mode: None,
            read_only: false,
            rate_limit: Some(20),
            policies: None,
            telegram: None,
            ssh: None,
            pbs: None,
            alerts: None,
            mcp_token: None,
            reconcile: None,
            profile_name: None,
        };
        let client = PxClient::new(cfg, Some(&self.token_secret))
            .await
            .context("PxClient::new from E2E env")?;
        Ok(Arc::new(client))
    }
}

// ── poll_until — anti-flake convergence helper ──────────

/// Repeatedly invoke `check` until it returns `Some(value)` or the
/// `timeout` elapses. Sleeps `interval` between calls.
///
/// **Why no `sleep` in tests, but `sleep` here?** The interval sleep
/// is the polling cadence, not the assertion. The assertion is
/// `Some(value)` — i.e., state convergence. A fast cluster passes
/// after one poll; a slow cluster takes more polls; either way the
/// test asserts the same thing about the same observable state. The
/// only thing the timeout bounds is "how long do we wait before
/// giving up" — never "how long do we wait before asserting".
pub async fn poll_until<F, Fut, T>(
    description: &str,
    timeout: Duration,
    interval: Duration,
    mut check: F,
) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Option<T>>>,
{
    let start = Instant::now();
    loop {
        match check().await {
            Ok(Some(v)) => return Ok(v),
            Ok(None) => { /* not yet — fall through to sleep+retry */ }
            Err(e) => {
                // Transient errors (e.g. 503 mid-checkpoint) get the
                // same "retry next interval" treatment as a None.
                eprintln!("[poll_until] {description}: transient error: {e:#}");
            }
        }
        if start.elapsed() >= timeout {
            anyhow::bail!(
                "poll_until timed out after {:?} waiting for: {description}",
                timeout
            );
        }
        tokio::time::sleep(interval).await;
    }
}

// ── TestResourceGuard — RAII teardown ───────────────────

#[derive(Debug, Clone)]
pub enum Resource {
    /// A guest (VM or LXC) that the test created or claimed. On
    /// teardown we attempt force-stop and then delete.
    Guest {
        node: String,
        vmid: u32,
        guest_type: GuestType,
    },
    /// A snapshot owned by the test. Teardown deletes it before the
    /// guest is itself deleted.
    Snapshot {
        node: String,
        vmid: u32,
        guest_type: GuestType,
        name: String,
    },
}

/// Tracks resources mutated during a test and cleans them up on
/// `Drop` — even if the test panics. The cleanup runs on a
/// dedicated thread with a fresh tokio runtime, because we cannot
/// `block_on` from within the existing test runtime.
pub struct TestResourceGuard {
    client: Arc<PxClient>,
    resources: Arc<Mutex<Vec<Resource>>>,
    /// When true, the explicit `cleanup().await` path was taken and
    /// `Drop` becomes a no-op. Set this once at the end of the
    /// happy path to avoid the slower thread-based cleanup.
    consumed: Arc<Mutex<bool>>,
}

impl TestResourceGuard {
    pub fn new(client: Arc<PxClient>) -> Self {
        Self {
            client,
            resources: Arc::new(Mutex::new(Vec::new())),
            consumed: Arc::new(Mutex::new(false)),
        }
    }

    pub fn register(&self, r: Resource) {
        eprintln!("[guard] register: {r:?}");
        self.resources.lock().expect("poison").push(r);
    }

    /// Explicit cleanup on the happy path. Marks the guard as
    /// consumed so Drop becomes a no-op.
    pub async fn cleanup(&self) {
        let resources: Vec<Resource> = std::mem::take(&mut *self.resources.lock().expect("poison"));
        for r in resources {
            cleanup_one(&self.client, &r).await;
        }
        *self.consumed.lock().expect("poison") = true;
    }
}

impl Drop for TestResourceGuard {
    fn drop(&mut self) {
        if *self.consumed.lock().expect("poison") {
            return;
        }
        let resources: Vec<Resource> = std::mem::take(&mut *self.resources.lock().expect("poison"));
        if resources.is_empty() {
            return;
        }
        eprintln!(
            "[guard] EMERGENCY teardown: {} resources (test panicked or skipped explicit cleanup)",
            resources.len()
        );
        // We can't `block_on` the current runtime from within Drop —
        // it'd panic with "Cannot block the current thread from
        // within a runtime". Spawn a dedicated thread + a fresh
        // single-threaded runtime instead. Best-effort; failures are
        // logged but don't propagate (Drop can't return errors).
        let client = Arc::clone(&self.client);
        let handle = std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("[guard] could not build teardown runtime: {e}");
                    return;
                }
            };
            rt.block_on(async {
                for r in resources {
                    cleanup_one(&client, &r).await;
                }
            });
        });
        if let Err(e) = handle.join() {
            eprintln!("[guard] teardown thread panicked: {e:?}");
        }
    }
}

/// Recognise PVE's "guest is gone" error shapes. PVE returns
/// `404 Not Found` on some paths, `500 + "Configuration file 'nodes/X/lxc/N.conf' does not exist"`
/// on `/status/current` for a deleted LXC, and equivalent shapes for
/// QEMU. The teardown poll loop classified the 500 case as transient
/// and timed out for 60s on every clean run — this helper lets the
/// poll exit immediately when the guest is already gone.
fn pve_error_is_gone(e: &anyhow::Error) -> bool {
    let msg = format!("{e:#}");
    msg.contains("404")
        || msg.contains("not found")
        || msg.to_ascii_lowercase().contains("does not exist")
}

/// Cheap existence check used by the RAII teardown's fast-path: if
/// the guest is already gone (test already deleted, or guard runs
/// twice on a re-entry), skip the stop/poll/delete dance.
async fn guest_is_gone(client: &Arc<PxClient>, node: &str, vmid: u32) -> bool {
    match client.get_guest_status(node, vmid).await {
        Ok(_) => false,
        Err(e) => pve_error_is_gone(&e),
    }
}

/// Best-effort cleanup of a single resource. Any error is logged but
/// not raised — Drop semantics demand we keep going.
async fn cleanup_one(client: &Arc<PxClient>, r: &Resource) {
    match r {
        Resource::Guest {
            node,
            vmid,
            guest_type,
        } => {
            eprintln!("[guard] tearing down guest {vmid} on {node}");
            // Fast-path: if the test already deleted the guest, skip
            // the whole stop/poll/delete dance. PVE returns
            //     500 "Configuration file 'nodes/X/lxc/N.conf' does not exist"
            // for a missing LXC (NOT 404 — Proxmox quirk that bit the
            // pre-fix teardown loop for 60s every clean run).
            if guest_is_gone(client, node, *vmid).await {
                eprintln!("[guard] guest {vmid} already gone — skipping teardown");
                return;
            }
            // Force-stop first; ignore errors (it may already be stopped).
            let _ = client.stop_guest(node, *vmid, *guest_type, true).await;
            // Wait until status is stopped — bounded so we don't hang
            // forever on a wedged cluster.
            let _ = poll_until(
                &format!("teardown: guest {vmid} reaches stopped"),
                Duration::from_mins(1),
                Duration::from_millis(500),
                || async {
                    match client.get_guest_status(node, *vmid).await {
                        Ok(g) if g.status == proxxx::api::types::GuestStatus::Stopped => {
                            Ok(Some(()))
                        }
                        Ok(_) => Ok(None),
                        Err(e) => {
                            // "Already gone" — treat as done. Covers
                            // both the rare clean 404 (PVE >= 9 on
                            // some paths) and the PVE 500 +
                            // "Configuration file ... does not exist"
                            // shape, which is what `/status/current`
                            // emits for a missing LXC.
                            if pve_error_is_gone(&e) {
                                Ok(Some(()))
                            } else {
                                Err(e)
                            }
                        }
                    }
                },
            )
            .await;
            // Re-check existence before the delete call — if the test
            // raced us and deleted between the poll exit and here,
            // we'd hit the same misclassified 500 in delete_guest's
            // pre-flight. Cheap idempotent skip.
            if guest_is_gone(client, node, *vmid).await {
                eprintln!("[guard] guest {vmid} disappeared mid-teardown — done");
                return;
            }
            // Now delete. The new TOCTOU pre-flight gate refuses if
            // status != Stopped, but since we just polled stopped
            // we should be safe. Still best-effort.
            if let Err(e) = client.delete_guest(node, *vmid, *guest_type).await {
                eprintln!("[guard] delete_guest({vmid}) failed: {e:#} (best-effort)");
            }
        }
        Resource::Snapshot {
            node,
            vmid,
            guest_type,
            name,
        } => {
            eprintln!("[guard] tearing down snapshot {name} on guest {vmid}");
            if let Err(e) = client.delete_snapshot(node, *vmid, *guest_type, name).await {
                eprintln!("[guard] delete_snapshot failed: {e:#} (best-effort)");
            }
        }
    }
}

// ── CLI binary contract runner ──────────────────────────

/// Lazily synthesize a proxxx `config.toml` from the E2E env, written once per
/// test process (0600). The CLI loads a config FILE (`PROXXX_CONFIG` or the
/// default path) — it does NOT build a connection from `PROXXX_E2E_*` — so
/// without this every `run_proxxx` subprocess call exits 3 ("Config not found").
/// Returns `None` on a dev machine where the E2E token env isn't set.
pub fn e2e_cli_config_path() -> Option<&'static std::path::Path> {
    use std::sync::OnceLock;
    static PATH: OnceLock<Option<std::path::PathBuf>> = OnceLock::new();
    PATH.get_or_init(|| {
        let url = std::env::var("PROXXX_E2E_API_URL").ok()?;
        let user = std::env::var("PROXXX_E2E_USER").ok()?;
        let token_id = std::env::var("PROXXX_E2E_TOKEN_ID").ok()?;
        let token_secret = std::env::var("PROXXX_E2E_TOKEN_SECRET").ok()?;
        let toml = format!(
            "url = \"{url}\"\nuser = \"{user}\"\nauth = \"token\"\n\
             token_id = \"{token_id}\"\ntoken_secret = \"{token_secret}\"\nverify_tls = false\n"
        );
        let dir = std::env::temp_dir().join("proxxx-e2e");
        std::fs::create_dir_all(&dir).ok()?;
        let path = dir.join("cli-config.toml");
        std::fs::write(&path, toml).ok()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Some(path)
    })
    .as_deref()
}

/// Run the proxxx binary with the given args and return its
/// `std::process::Output`. `CARGO_BIN_EXE_proxxx` is set by Cargo
/// for integration tests, so the binary is always built before the
/// test runs.
///
/// The subprocess gets `PROXXX_CONFIG` pointing at a config synthesized from the
/// E2E env (see [`e2e_cli_config_path`]) so CLI calls are turnkey — unless the
/// caller already pinned `PROXXX_CONFIG`, which is respected.
pub fn run_proxxx(args: &[&str]) -> std::process::Output {
    let bin = env!("CARGO_BIN_EXE_proxxx");
    eprintln!("[cli] {bin} {}", args.join(" "));
    let mut cmd = std::process::Command::new(bin);
    cmd.args(args);
    if std::env::var_os("PROXXX_CONFIG").is_none() {
        if let Some(cfg) = e2e_cli_config_path() {
            cmd.env("PROXXX_CONFIG", cfg);
        }
    }
    cmd.output().expect("spawn proxxx binary")
}

/// Invoke `proxxx` and return `(stdout_str, stderr_str, exit_code)`.
pub fn run_proxxx_capture(args: &[&str]) -> (String, String, i32) {
    let out = run_proxxx(args);
    let code = out.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (stdout, stderr, code)
}
