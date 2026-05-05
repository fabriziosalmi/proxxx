//! Pillar 0: SSH layer.
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
use tokio::sync::{RwLock, Semaphore};
use tracing::{debug, info};

pub use exec::{ExecOptions, ExecResult, StreamLine};
pub use known_hosts::{HostKey, HostMatch, KnownHosts};
pub use session::{HostKeyDecision, HostKeyVerifier, PolicyVerifier, SshSession};

use crate::config::{HostKeyPolicy, SshConfig};

/// Per-profile SSH gateway: pool of node sessions + `key/known_hosts` state.
pub struct SshPool {
    cfg: SshConfig,
    known: Arc<RwLock<KnownHosts>>,
    verifier: Arc<dyn HostKeyVerifier>,
    sessions: RwLock<HashMap<String, Arc<SshSession>>>,
    semaphore: Arc<Semaphore>,
    passphrase: Option<String>,
}

impl SshPool {
    /// Build a pool from a profile's `[ssh]` block.
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
            semaphore: Arc::new(Semaphore::new(max)),
            passphrase,
        })
    }

    /// Override the host key verifier (e.g. TUI plugs in a modal-based one).
    #[must_use]
    pub fn with_verifier(mut self, verifier: Arc<dyn HostKeyVerifier>) -> Self {
        self.verifier = verifier;
        self
    }

    /// Get an existing session for `node`, or open a new one.
    /// Stale sessions (idle > `idle_timeout_secs`) are dropped and reopened.
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

        let (host, port) = self.cfg.resolve_host(node);
        let session = SshSession::connect(
            host,
            port,
            self.cfg.user.clone(),
            &key_path,
            self.passphrase.as_deref(),
            Arc::clone(&self.known),
            Arc::clone(&self.verifier),
        )
        .await?;

        let arc = Arc::new(session);
        let mut map = self.sessions.write().await;
        map.insert(node.to_string(), Arc::clone(&arc));
        info!("ssh session opened for node {node}");
        Ok(arc)
    }

    /// Run a command, capture output. Concurrency-capped by `max_concurrent`.
    pub async fn exec(&self, node: &str, command: &str, opts: ExecOptions) -> Result<ExecResult> {
        let _permit = Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .context("ssh semaphore closed")?;
        let session = self.session_for(node).await?;
        exec::exec(&session, command, opts).await
    }

    /// Stream a command line-by-line. Concurrency-capped by `max_concurrent`.
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
