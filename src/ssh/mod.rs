//! SSH layer: SSH layer.
//!
//! Why this exists: a chunk of Proxmox functionality is not API-callable
//! (apt upgrade, qemu-img convert, lspci IOMMU groups, zfs list -t snapshot,
//! corosync-cmapctl). Without an SSH layer, features #4/#6/#7/#9 are fiction.
//!
//! Scope (intentionally narrow):
//! - publickey auth only (no password fallback)
//! - exec + `exec_stream`
//! - dedicated TOFU `known_hosts` (not user's ~/.`ssh/known_hosts`)
//! - per-(profile, node) connection pool
//! - automatic fallback to the profile's `url` host (port 22) ONLY for the
//!   API-local node, verified via remote `hostname` before any command runs (`#328`)
//!
//! Out of scope: SSH agent forwarding, SCP/SFTP transfers, long-lived PTY
//! (the latter is feature #1a's job, not infrastructure).

pub mod exec;
pub mod known_hosts;
pub mod pty;
pub mod session;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::{OnceCell, RwLock, Semaphore};
use tracing::{debug, info};

pub use exec::{ExecOptions, ExecResult, StreamLine};
pub use known_hosts::{HostKey, HostMatch, KnownHosts};
pub use session::{HostKeyDecision, HostKeyVerifier, PolicyVerifier, SshSession};

use crate::config::{
    api_local_node_from_status, HostKeyPolicy, ResolvedNodeSsh, SshConfig, SshHostSource,
};

#[cfg(test)]
#[async_trait::async_trait]
trait FakeSshSession: Send + Sync {
    async fn idle_for(&self) -> Duration {
        Duration::ZERO
    }
    async fn exec(&self, command: &str, opts: ExecOptions) -> Result<ExecResult>;
}

#[cfg(test)]
#[async_trait::async_trait]
trait FakeSshConnector: Send + Sync {
    async fn connect(&self, host: &str, port: u16) -> Result<Arc<dyn FakeSshSession>>;
}

/// Verify that a session opened via the profile `url` fallback actually landed
/// on `expected_node` before any user command runs (`#328`).
///
/// Compares the short hostname returned by `hostname` (`<short>[.<domain>]`)
/// against `expected_node` (case-insensitively). Refuses if `hostname` exits
/// non-zero, prints an empty string, or names a different node (e.g. when
/// `url` points at a VIP or load balancer in front of a cluster).
///
/// # Errors
/// Returns an error if `hostname` fails or reports a different node name.
pub fn verify_remote_hostname_output(
    expected_node: &str,
    host: &str,
    port: u16,
    res: &ExecResult,
) -> Result<()> {
    if !res.ok() {
        anyhow::bail!(
            "SSH identity check failed for node '{expected_node}' on {host}:{port} \
             (`hostname` exited {:?}): {}",
            res.exit_code,
            res.stderr.trim()
        );
    }
    let raw_remote = res.stdout.trim();
    let remote_short = raw_remote.split('.').next().unwrap_or("").trim();
    let expected_short = expected_node
        .split('.')
        .next()
        .unwrap_or(expected_node)
        .trim();

    if remote_short.is_empty()
        || (!raw_remote.eq_ignore_ascii_case(expected_node)
            && !remote_short.eq_ignore_ascii_case(expected_short))
    {
        anyhow::bail!(
            "SSH target identity mismatch for node '{expected_node}': connected to {host}:{port} \
             (via profile URL fallback), but remote hostname is '{raw_remote}' (expected '{expected_node}'). \
             The profile URL may point to a VIP or load balancer; configure an explicit address under [ssh]:\n\
             hosts = {{ {expected_node} = \"<ip>:22\" }}"
        );
    }
    Ok(())
}

async fn verify_session_identity_if_fallback<F, Fut>(
    node: &str,
    target: &ResolvedNodeSsh,
    run_hostname: F,
) -> Result<()>
where
    F: FnOnce(ExecOptions) -> Fut,
    Fut: std::future::Future<Output = Result<ExecResult>>,
{
    if target.source == SshHostSource::ApiUrlFallback {
        let id_res = run_hostname(ExecOptions {
            timeout: Some(Duration::from_secs(10)),
            max_capture_bytes: 4096,
        })
        .await
        .with_context(|| {
            format!(
                "running SSH hostname identity check on {}:{} for node '{node}'",
                target.host, target.port
            )
        })?;
        verify_remote_hostname_output(node, &target.host, target.port, &id_res)?;
    }
    Ok(())
}

/// Source of `/cluster/status` entries used by [`SshPool`] to resolve the
/// API-local node on demand (`#328`).
#[async_trait::async_trait]
pub trait ClusterStatusSource: Send + Sync {
    async fn cluster_status(&self) -> Result<Vec<crate::api::types::ClusterStatusEntry>>;
}

#[async_trait::async_trait]
impl<T: crate::api::ProxmoxGateway + ?Sized + 'static> ClusterStatusSource for Arc<T> {
    async fn cluster_status(&self) -> Result<Vec<crate::api::types::ClusterStatusEntry>> {
        (**self).cluster_status().await
    }
}

/// Per-profile SSH gateway: pool of node sessions + `key/known_hosts` state.
pub struct SshPool {
    cfg: SshConfig,
    known: Arc<RwLock<KnownHosts>>,
    verifier: Arc<dyn HostKeyVerifier>,
    sessions: RwLock<HashMap<String, Arc<SshSession>>>,
    #[cfg(test)]
    fake_sessions: RwLock<HashMap<String, Arc<dyn FakeSshSession>>>,
    #[cfg(test)]
    fake_connector: Option<Arc<dyn FakeSshConnector>>,
    semaphore: Arc<Semaphore>,
    passphrase: Option<crate::util::secret::SecretString>,
    api_url: Option<String>,
    api_gateway: Option<Arc<dyn ClusterStatusSource>>,
    local_node: OnceCell<Option<String>>,
}

impl SshPool {
    /// Build a pool from a profile's `[ssh]` block.
    ///
    /// Chain [`Self::with_api`] at construction so the pool can fall back to
    /// the profile `url` host when targeting the API-local node (`#328`).
    ///
    /// # Errors
    /// Returns an error if the `known_hosts` file exists and cannot be parsed.
    pub fn new(cfg: SshConfig, passphrase: Option<String>) -> Result<Self> {
        let known_path = cfg.known_hosts_path();
        let known = KnownHosts::load(known_path).context("loading known_hosts")?;
        let policy = HostKeyPolicy::from_str(&cfg.strict_host_key_checking);
        let verifier: Arc<dyn HostKeyVerifier> = Arc::new(PolicyVerifier { policy });
        let max = cfg.max_concurrent.max(1) as usize;
        Ok(Self {
            cfg,
            known: Arc::new(RwLock::new(known)),
            verifier,
            sessions: RwLock::new(HashMap::new()),
            #[cfg(test)]
            fake_sessions: RwLock::new(HashMap::new()),
            #[cfg(test)]
            fake_connector: None,
            semaphore: Arc::new(Semaphore::new(max)),
            passphrase: passphrase.map(crate::util::secret::SecretString::new),
            api_url: None,
            api_gateway: None,
            local_node: OnceCell::new(),
        })
    }

    /// Attach the profile's API `url` and `/cluster/status` source (e.g.
    /// `Arc<PxClient>` or `Arc<dyn ProxmoxGateway>`) so the pool can resolve
    /// the API-local node once (via `/cluster/status`, skipped when
    /// `cfg.hosts[node]` is present) and fall back to the URL host for that
    /// node (`#328`).
    #[must_use]
    pub fn with_api<S: ClusterStatusSource + 'static>(
        mut self,
        api_url: impl Into<String>,
        api: S,
    ) -> Self {
        self.api_url = Some(api_url.into());
        self.api_gateway = Some(Arc::new(api));
        self
    }

    /// Pre-seed the profile's API `url` and resolved API-local node name
    /// (`#328`).
    #[must_use]
    pub fn with_local_node(
        mut self,
        api_url: impl Into<String>,
        local_node: Option<String>,
    ) -> Self {
        self.api_url = Some(api_url.into());
        self.local_node = OnceCell::from(local_node);
        self
    }

    /// Override the host key verifier (e.g. TUI plugs in a modal-based one).
    #[must_use]
    pub fn with_verifier(mut self, verifier: Arc<dyn HostKeyVerifier>) -> Self {
        self.verifier = verifier;
        self
    }

    #[cfg(test)]
    #[must_use]
    fn with_fake_connector(mut self, connector: Arc<dyn FakeSshConnector>) -> Self {
        self.fake_connector = Some(connector);
        self
    }

    /// Resolve the `(host, port, source)` target for `node` (`#328`).
    ///
    /// 1. If `cfg.hosts[node]` is present, returns it immediately without
    ///    calling `/cluster/status`.
    /// 2. Otherwise queries `/cluster/status` at most once per pool (cached in
    ///    `self.local_node`) and falls back to the host in `self.api_url`
    ///    (port 22) iff `node` is the API-local node.
    ///
    /// # Errors
    /// Returns an error if `/cluster/status` fails or if `node` is neither in
    /// `cfg.hosts` nor the API-local node.
    pub async fn resolve_node_target(&self, node: &str) -> Result<ResolvedNodeSsh> {
        if let Some((host, port)) = self.cfg.resolve_explicit_host(node) {
            return Ok(ResolvedNodeSsh {
                host,
                port,
                source: SshHostSource::ExplicitHosts,
            });
        }

        let local_node = self
            .local_node
            .get_or_try_init(|| async {
                let Some(ref api) = self.api_gateway else {
                    return Ok::<Option<String>, anyhow::Error>(None);
                };
                let entries = api
                    .cluster_status()
                    .await
                    .context("fetching /cluster/status to resolve API-local SSH node")?;
                Ok(api_local_node_from_status(&entries))
            })
            .await?;

        self.cfg
            .resolve_host(node, self.api_url.as_deref(), local_node.as_deref())
    }

    #[cfg(test)]
    async fn fake_session_for(&self, node: &str) -> Result<Arc<dyn FakeSshSession>> {
        {
            let map = self.fake_sessions.read().await;
            if let Some(s) = map.get(node) {
                let idle = s.idle_for().await;
                if idle < Duration::from_secs(self.cfg.idle_timeout_secs) {
                    return Ok(Arc::clone(s));
                }
            }
        }

        let target = self.resolve_node_target(node).await?;
        let connector = self
            .fake_connector
            .as_ref()
            .context("fake_connector not set")?;
        let session = connector.connect(&target.host, target.port).await?;

        verify_session_identity_if_fallback(node, &target, |opts| {
            let s = Arc::clone(&session);
            async move { s.exec("hostname", opts).await }
        })
        .await?;

        let mut map = self.fake_sessions.write().await;
        map.insert(node.to_string(), Arc::clone(&session));
        Ok(session)
    }

    /// Get an existing session for `node`, or open a new one.
    /// Stale sessions (idle > `idle_timeout_secs`) are dropped and reopened.
    ///
    /// When the session is opened via the profile `url` fallback (`#328`),
    /// verifies the remote node identity (`hostname`) before caching or
    /// returning the session.
    ///
    /// # Errors
    /// Returns an error if key resolution, target resolution, SSH connection,
    /// or fallback hostname verification fails.
    pub async fn session_for(&self, node: &str) -> Result<Arc<SshSession>> {
        // Fast path
        {
            let map = self.sessions.read().await;
            if let Some(s) = map.get(node) {
                let idle = s.idle_for().await;
                if idle < Duration::from_secs(self.cfg.idle_timeout_secs) {
                    return Ok(Arc::clone(s));
                }
                debug!("ssh session for {node} stale ({idle:?}), reopening");
            }
        }

        let key_path = self
            .cfg
            .key_path_resolved()
            .context("ssh.key_path not configured for this profile")?;

        let target = self.resolve_node_target(node).await?;
        let session = SshSession::connect(
            target.host.clone(),
            target.port,
            self.cfg.user.clone(),
            &key_path,
            self.passphrase.as_deref(),
            Arc::clone(&self.known),
            Arc::clone(&self.verifier),
        )
        .await?;

        verify_session_identity_if_fallback(node, &target, |opts| {
            exec::exec(&session, "hostname", opts)
        })
        .await?;

        let arc = Arc::new(session);
        let mut map = self.sessions.write().await;
        map.insert(node.to_string(), Arc::clone(&arc));
        info!("ssh session opened for node {node}");
        Ok(arc)
    }

    /// Run a command, capture output. Concurrency-capped by `max_concurrent`.
    ///
    /// # Errors
    /// Returns an error if opening the session, verifying fallback node
    /// identity, or executing the command fails.
    pub async fn exec(&self, node: &str, command: &str, opts: ExecOptions) -> Result<ExecResult> {
        let _permit = Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .context("ssh semaphore closed")?;
        #[cfg(test)]
        if self.fake_connector.is_some() {
            let session = self.fake_session_for(node).await?;
            return session.exec(command, opts).await;
        }
        let session = self.session_for(node).await?;
        exec::exec(&session, command, opts).await
    }

    /// Stream a command line-by-line. Concurrency-capped by `max_concurrent`.
    ///
    /// # Errors
    /// Returns an error if opening the session, verifying fallback node
    /// identity, or streaming the command fails.
    pub async fn exec_stream<F>(
        &self,
        node: &str,
        command: &str,
        opts: ExecOptions,
        on_line: F,
    ) -> Result<Option<u32>>
    where
        F: FnMut(StreamLine) + Send,
    {
        let _permit = Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .context("ssh semaphore closed")?;
        let session = self.session_for(node).await?;
        exec::exec_stream(&session, command, opts, on_line).await
    }

    /// Drop a node's session (e.g. on reboot orchestration).
    pub async fn drop_session(&self, node: &str) {
        let mut map = self.sessions.write().await;
        if map.remove(node).is_some() {
            info!("ssh session dropped for node {node}");
        }
    }
}

/// Trait abstraction for testability. `SshPool` is the production impl.
#[async_trait::async_trait]
pub trait SshGateway: Send + Sync {
    async fn exec(&self, node: &str, command: &str, opts: ExecOptions) -> Result<ExecResult>;
}

#[async_trait::async_trait]
impl SshGateway for SshPool {
    async fn exec(&self, node: &str, command: &str, opts: ExecOptions) -> Result<ExecResult> {
        Self::exec(self, node, command, opts).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::ClusterStatusEntry;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn empty_ssh_config() -> SshConfig {
        let tmp = std::env::temp_dir().join(format!(
            "proxxx-ssh-step19-known-hosts-{}",
            std::process::id()
        ));
        SshConfig {
            user: "root".to_string(),
            key_path: Some("~/.ssh/id_ed25519".to_string()),
            hosts: HashMap::new(),
            known_hosts: Some(tmp.display().to_string()),
            strict_host_key_checking: "tofu".to_string(),
            max_concurrent: 8,
            idle_timeout_secs: 300,
            exec_timeout_secs: 60,
            guests: HashMap::new(),
        }
    }

    struct MockClusterStatusGateway {
        calls: Arc<AtomicUsize>,
        entries: Vec<ClusterStatusEntry>,
    }

    #[async_trait::async_trait]
    impl ClusterStatusSource for Arc<MockClusterStatusGateway> {
        async fn cluster_status(&self) -> Result<Vec<ClusterStatusEntry>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.entries.clone())
        }
    }

    struct ScriptedFakeSession {
        remote_hostname: String,
        commands_run: Arc<Mutex<Vec<String>>>,
        connected_target: (String, u16),
    }

    #[async_trait::async_trait]
    impl FakeSshSession for ScriptedFakeSession {
        async fn exec(&self, command: &str, _opts: ExecOptions) -> Result<ExecResult> {
            self.commands_run.lock().unwrap().push(command.to_string());
            if command == "hostname" {
                return Ok(ExecResult {
                    stdout: format!("{}\n", self.remote_hostname),
                    stderr: String::new(),
                    exit_code: Some(0),
                });
            }
            Ok(ExecResult {
                stdout: format!(
                    "executed on {}:{} -> {command}\n",
                    self.connected_target.0, self.connected_target.1
                ),
                stderr: String::new(),
                exit_code: Some(0),
            })
        }
    }

    struct ScriptedFakeConnector {
        remote_hostname: String,
        commands_run: Arc<Mutex<Vec<String>>>,
        connects: Arc<Mutex<Vec<(String, u16)>>>,
    }

    #[async_trait::async_trait]
    impl FakeSshConnector for ScriptedFakeConnector {
        async fn connect(&self, host: &str, port: u16) -> Result<Arc<dyn FakeSshSession>> {
            self.connects.lock().unwrap().push((host.to_string(), port));
            Ok(Arc::new(ScriptedFakeSession {
                remote_hostname: self.remote_hostname.clone(),
                commands_run: Arc::clone(&self.commands_run),
                connected_target: (host.to_string(), port),
            }))
        }
    }

    /// Test 1 (`#328`):
    /// Standalone install (one node, `local = true`, no `hosts` map):
    /// the SSH target is the URL host on port 22.
    #[tokio::test]
    async fn test_1_standalone_node_with_no_hosts_falls_back_to_url_host() {
        let cfg = empty_ssh_config();
        let status = vec![ClusterStatusEntry {
            entry_type: "node".to_string(),
            name: "opti7".to_string(),
            online: true,
            local: true,
            ..Default::default()
        }];

        // Direct resolver test with injected status
        let resolved = cfg
            .resolve_host_with_status("opti7", "https://192.168.0.203:8006", &status)
            .expect("standalone node must resolve to URL host");
        assert_eq!(
            resolved,
            ResolvedNodeSsh {
                host: "192.168.0.203".to_string(),
                port: 22,
                source: SshHostSource::ApiUrlFallback,
            }
        );

        // Also via SshPool with injected gateway
        let calls = Arc::new(AtomicUsize::new(0));
        let gw = Arc::new(MockClusterStatusGateway {
            calls: Arc::clone(&calls),
            entries: status,
        });
        let pool = SshPool::new(cfg, None)
            .unwrap()
            .with_api("https://192.168.0.203:8006", gw);
        let pool_target = pool
            .resolve_node_target("opti7")
            .await
            .expect("pool target");
        assert_eq!(pool_target.host, "192.168.0.203");
        assert_eq!(pool_target.port, 22);
        assert_eq!(pool_target.source, SshHostSource::ApiUrlFallback);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// Test 2 (`#328`):
    /// Multi-node cluster:
    /// - When `node` is the local node (`local = true`), target is the URL host (port 22).
    /// - When `node` is another cluster member (`local = false`), returns an error
    ///   naming the node and showing `hosts = { <node> = "<ip>:22" }`, never the URL host.
    #[tokio::test]
    async fn test_2_cluster_local_node_uses_url_host_and_other_member_errors_with_hosts_hint() {
        let cfg = empty_ssh_config();
        let status = vec![
            ClusterStatusEntry {
                entry_type: "cluster".to_string(),
                name: "homelab".to_string(),
                nodes: 3,
                quorate: true,
                ..Default::default()
            },
            ClusterStatusEntry {
                entry_type: "node".to_string(),
                name: "pve-test-1".to_string(),
                online: true,
                local: true,
                ..Default::default()
            },
            ClusterStatusEntry {
                entry_type: "node".to_string(),
                name: "pve-test-2".to_string(),
                online: true,
                local: false,
                ..Default::default()
            },
            ClusterStatusEntry {
                entry_type: "node".to_string(),
                name: "pve-test-3".to_string(),
                online: true,
                local: false,
                ..Default::default()
            },
        ];

        let calls = Arc::new(AtomicUsize::new(0));
        let gw = Arc::new(MockClusterStatusGateway {
            calls: Arc::clone(&calls),
            entries: status,
        });
        let pool = SshPool::new(cfg, None)
            .unwrap()
            .with_api("https://192.168.0.122:8006", gw);

        // Local node -> URL host
        let local_target = pool
            .resolve_node_target("pve-test-1")
            .await
            .expect("API-local node must resolve to URL host");
        assert_eq!(
            local_target,
            ResolvedNodeSsh {
                host: "192.168.0.122".to_string(),
                port: 22,
                source: SshHostSource::ApiUrlFallback,
            }
        );

        // Non-local cluster member -> error naming the node and suggesting the exact `hosts` line
        let err = pool
            .resolve_node_target("pve-test-2")
            .await
            .expect_err("non-API cluster member without hosts entry must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("pve-test-2"),
            "error must name the target node, got: {msg}"
        );
        assert!(
            msg.contains("hosts = { pve-test-2 = \"<ip>:22\" }"),
            "error must show exact hosts line to add, got: {msg}"
        );
        assert!(
            !msg.contains("192.168.0.122"),
            "error must not suggest or leak the API node's IP for another member: {msg}"
        );

        // `/cluster/status` was called only once across both resolutions on the same pool
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "/cluster/status must be resolved once per pool, not per command"
        );
    }

    /// Test 3 (`#328`):
    /// When `hosts[node]` is present, it always wins (even if `node` is not the
    /// local node or if `node` IS the local node with a custom IP/port), and
    /// `/cluster/status` is NEVER called (`calls == 0`).
    #[tokio::test]
    async fn test_3_explicit_hosts_entry_always_wins_with_zero_cluster_status_calls() {
        let mut cfg = empty_ssh_config();
        cfg.hosts
            .insert("pve-test-1".to_string(), "10.10.0.11:2222".to_string());
        cfg.hosts
            .insert("pve-test-2".to_string(), "10.10.0.12:22".to_string());

        let calls = Arc::new(AtomicUsize::new(0));
        let gw = Arc::new(MockClusterStatusGateway {
            calls: Arc::clone(&calls),
            entries: vec![],
        });
        let commands_run = Arc::new(Mutex::new(Vec::new()));
        let connects = Arc::new(Mutex::new(Vec::new()));
        let connector = Arc::new(ScriptedFakeConnector {
            remote_hostname: "different-hostname-allowed-for-explicit".to_string(),
            commands_run: Arc::clone(&commands_run),
            connects: Arc::clone(&connects),
        });

        let pool = SshPool::new(cfg, None)
            .unwrap()
            .with_api("https://192.168.0.122:8006", gw)
            .with_fake_connector(connector);

        let t1 = pool.resolve_node_target("pve-test-1").await.unwrap();
        assert_eq!(
            t1,
            ResolvedNodeSsh {
                host: "10.10.0.11".to_string(),
                port: 2222,
                source: SshHostSource::ExplicitHosts,
            }
        );
        let t2 = pool.resolve_node_target("pve-test-2").await.unwrap();
        assert_eq!(
            t2,
            ResolvedNodeSsh {
                host: "10.10.0.12".to_string(),
                port: 22,
                source: SshHostSource::ExplicitHosts,
            }
        );

        let res = pool
            .exec("pve-test-1", "uname -a", ExecOptions::default())
            .await
            .expect("explicit hosts exec");
        assert!(res.stdout.contains("10.10.0.11:2222"));

        assert_eq!(
            calls.load(Ordering::SeqCst),
            0,
            "explicit hosts entry must never call /cluster/status"
        );
        assert_eq!(
            *commands_run.lock().unwrap(),
            vec!["uname -a".to_string()],
            "explicit hosts entry keeps existing behaviour (no hostname probe)"
        );
    }

    /// Test 4 (`#328`):
    /// Identity check on the URL fallback path:
    /// - When the remote session's `hostname` differs from `node`, `SshPool::exec`
    ///   refuses with a clear error BEFORE the real command runs (`commands_run`
    ///   contains only `["hostname"]`, never the user command).
    /// - When `hostname` matches `node`, the user command runs, and a subsequent
    ///   command on the same pooled session reuses the verified session without
    ///   re-running `hostname`.
    #[tokio::test]
    async fn test_4_fallback_identity_check_refuses_mismatched_hostname_before_real_command() {
        let cfg = empty_ssh_config();
        let status = vec![ClusterStatusEntry {
            entry_type: "node".to_string(),
            name: "pve-test-1".to_string(),
            online: true,
            local: true,
            ..Default::default()
        }];

        // 4a. Mismatched remote hostname -> refused before real command runs
        let bad_commands = Arc::new(Mutex::new(Vec::new()));
        let bad_connects = Arc::new(Mutex::new(Vec::new()));
        let bad_connector = Arc::new(ScriptedFakeConnector {
            remote_hostname: "pve-vip-other-node".to_string(),
            commands_run: Arc::clone(&bad_commands),
            connects: Arc::clone(&bad_connects),
        });
        let bad_gw = Arc::new(MockClusterStatusGateway {
            calls: Arc::new(AtomicUsize::new(0)),
            entries: status.clone(),
        });
        let bad_pool = SshPool::new(cfg.clone(), None)
            .unwrap()
            .with_api("https://192.168.0.122:8006", bad_gw)
            .with_fake_connector(bad_connector);

        let err = bad_pool
            .exec(
                "pve-test-1",
                "apt-get dist-upgrade -y",
                ExecOptions::default(),
            )
            .await
            .expect_err("mismatched remote hostname must be refused");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("pve-test-1") && msg.contains("pve-vip-other-node"),
            "error must name both expected node and remote hostname, got: {msg}"
        );
        assert!(
            msg.contains("hosts = { pve-test-1 = \"<ip>:22\" }"),
            "error must suggest the explicit hosts entry, got: {msg}"
        );
        assert_eq!(
            *bad_commands.lock().unwrap(),
            vec!["hostname".to_string()],
            "real command must NEVER execute when hostname identity check fails"
        );

        // 4b. Matching remote hostname (including FQDN `pve-test-1.lab.internal`) -> succeeds once
        let ok_commands = Arc::new(Mutex::new(Vec::new()));
        let ok_connects = Arc::new(Mutex::new(Vec::new()));
        let ok_connector = Arc::new(ScriptedFakeConnector {
            remote_hostname: "pve-test-1.lab.internal".to_string(),
            commands_run: Arc::clone(&ok_commands),
            connects: Arc::clone(&ok_connects),
        });
        let ok_gw = Arc::new(MockClusterStatusGateway {
            calls: Arc::new(AtomicUsize::new(0)),
            entries: status,
        });
        let ok_pool = SshPool::new(cfg, None)
            .unwrap()
            .with_api("https://192.168.0.122:8006", ok_gw)
            .with_fake_connector(ok_connector);

        let r1 = ok_pool
            .exec(
                "pve-test-1",
                "pveum user permissions root@pam",
                ExecOptions::default(),
            )
            .await
            .expect("matching hostname must allow command");
        assert!(r1.stdout.contains("192.168.0.122:22"));

        let r2 = ok_pool
            .exec("pve-test-1", "uptime", ExecOptions::default())
            .await
            .expect("second command on pooled session");
        assert!(r2.stdout.contains("uptime"));

        assert_eq!(
            *ok_commands.lock().unwrap(),
            vec![
                "hostname".to_string(),
                "pveum user permissions root@pam".to_string(),
                "uptime".to_string(),
            ],
            "hostname check runs once before the first command on the fallback session"
        );
    }

    /// Test 5 (`#328`):
    /// URL host forms: IPv4, IPv6 literal (`[::1]`), and DNS name all resolve to
    /// port 22 on fallback, while `hosts` overrides can set custom ports or bare hosts.
    #[test]
    fn test_5_url_host_forms_ipv4_ipv6_dns_and_hosts_port_overrides() {
        let status = vec![ClusterStatusEntry {
            entry_type: "node".to_string(),
            name: "opti7".to_string(),
            online: true,
            local: true,
            ..Default::default()
        }];
        let cfg = empty_ssh_config();

        // 5a. IPv4 URL
        let v4 = cfg
            .resolve_host_with_status("opti7", "https://192.168.0.203:8006", &status)
            .unwrap();
        assert_eq!(v4.host, "192.168.0.203");
        assert_eq!(v4.port, 22);
        assert_eq!(v4.source, SshHostSource::ApiUrlFallback);

        // 5b. IPv6 literal URL (`[::1]`) -> unbracketed `"::1"`, port 22
        let v6 = cfg
            .resolve_host_with_status("opti7", "https://[::1]:8006", &status)
            .unwrap();
        assert_eq!(v6.host, "::1");
        assert_eq!(v6.port, 22);
        assert_eq!(v6.source, SshHostSource::ApiUrlFallback);

        // 5c. DNS name URL
        let dns = cfg
            .resolve_host_with_status("opti7", "https://opti7.lan.example:8006/api2/json", &status)
            .unwrap();
        assert_eq!(dns.host, "opti7.lan.example");
        assert_eq!(dns.port, 22);
        assert_eq!(dns.source, SshHostSource::ApiUrlFallback);

        // 5d. `hosts` overrides port (or defaults to 22 when port omitted)
        let mut cfg_custom = empty_ssh_config();
        cfg_custom
            .hosts
            .insert("opti7".to_string(), "192.168.0.203:2222".to_string());
        cfg_custom
            .hosts
            .insert("v6node".to_string(), "[::1]:2200".to_string());
        cfg_custom
            .hosts
            .insert("dnsnode".to_string(), "pve.lan.example".to_string());

        let c1 = cfg_custom
            .resolve_host_with_status("opti7", "https://192.168.0.203:8006", &status)
            .unwrap();
        assert_eq!(c1.host, "192.168.0.203");
        assert_eq!(c1.port, 2222);
        assert_eq!(c1.source, SshHostSource::ExplicitHosts);

        let c2 = cfg_custom
            .resolve_host_with_status("v6node", "https://192.168.0.203:8006", &status)
            .unwrap();
        assert_eq!(c2.host, "::1");
        assert_eq!(c2.port, 2200);
        assert_eq!(c2.source, SshHostSource::ExplicitHosts);

        let c3 = cfg_custom
            .resolve_host_with_status("dnsnode", "https://192.168.0.203:8006", &status)
            .unwrap();
        assert_eq!(c3.host, "pve.lan.example");
        assert_eq!(c3.port, 22);
        assert_eq!(c3.source, SshHostSource::ExplicitHosts);
    }
}
