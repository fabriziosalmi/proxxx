//! SSH connection lifecycle: connect, authenticate, hold, drop.
//!
//! One `SshSession` per `(profile, node)`. The `SshPool` owns them.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use russh::client::{self, Config, Handle, Handler};
use russh::keys::key::PublicKey;
use russh::keys::PublicKeyBase64;
use tokio::sync::RwLock;
use tracing::{info, warn};

use super::known_hosts::{HostKey, HostMatch, KnownHosts};
use crate::config::HostKeyPolicy;

/// Decision returned by a `HostKeyVerifier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyDecision {
    /// Accept this connection. If `remember` is true, persist to known_hosts.
    Accept { remember: bool },
    /// Reject the connection. Connection setup will fail.
    Reject,
}

/// Pluggable host key verifier — TUI provides a modal-based one;
/// CLI/non-interactive mode uses the default policy-based one.
#[async_trait::async_trait]
pub trait HostKeyVerifier: Send + Sync {
    async fn verify(
        &self,
        host: &str,
        port: u16,
        key: &HostKey,
        status: HostMatch,
    ) -> HostKeyDecision;
}

/// Non-interactive verifier: applies the configured policy without prompting.
///
/// - TOFU + Unknown   → Accept { remember: true }, log a warning with fingerprint.
/// - TOFU + Match     → Accept { remember: false }
/// - TOFU + Mismatch  → Reject (possible MitM).
/// - Strict + Unknown → Reject (must be pre-trusted).
/// - Strict + Match   → Accept { remember: false }
/// - Strict + Mismatch→ Reject.
/// - Off + *          → Accept { remember: false } — for CI/lab only.
pub struct PolicyVerifier {
    pub policy: HostKeyPolicy,
}

#[async_trait::async_trait]
impl HostKeyVerifier for PolicyVerifier {
    async fn verify(
        &self,
        host: &str,
        port: u16,
        key: &HostKey,
        status: HostMatch,
    ) -> HostKeyDecision {
        match (self.policy, status) {
            (HostKeyPolicy::Off, _) => HostKeyDecision::Accept { remember: false },
            (HostKeyPolicy::Strict, HostMatch::Match) => {
                HostKeyDecision::Accept { remember: false }
            }
            (HostKeyPolicy::Strict, _) => {
                warn!(
                    "ssh strict mode: rejecting {host}:{port}, fingerprint {}",
                    key.fingerprint_short()
                );
                HostKeyDecision::Reject
            }
            (HostKeyPolicy::Tofu, HostMatch::Match) => HostKeyDecision::Accept { remember: false },
            (HostKeyPolicy::Tofu, HostMatch::Unknown) => {
                warn!(
                    "ssh tofu: trusting unknown host {host}:{port} on first use, fingerprint {}",
                    key.fingerprint_short()
                );
                HostKeyDecision::Accept { remember: true }
            }
            (HostKeyPolicy::Tofu, HostMatch::Mismatch) => {
                warn!(
                    "ssh tofu: REJECTING {host}:{port} due to host key MISMATCH (possible MitM), fingerprint {}",
                    key.fingerprint_short()
                );
                HostKeyDecision::Reject
            }
        }
    }
}

/// Internal russh client handler. Performs TOFU check via the injected verifier
/// and the shared `KnownHosts` store.
///
/// Visibility note (reviewer P1): `pub(crate)` matches the visibility
/// of `SshSession::handle()` which returns `&Handle<SshHandler>`. This
/// closes the `private_interfaces` warning that would have become a
/// hard error in edition 2024.
pub(crate) struct SshHandler {
    host: String,
    port: u16,
    known: Arc<RwLock<KnownHosts>>,
    verifier: Arc<dyn HostKeyVerifier>,
}

#[async_trait::async_trait]
impl Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let key_type = server_public_key.name().to_string();
        let key_blob = server_public_key.public_key_bytes();
        let key = HostKey { key_type, key_blob };

        let status = {
            let store = self.known.read().await;
            store.check(&self.host, self.port, &key)
        };

        let decision = self
            .verifier
            .verify(&self.host, self.port, &key, status)
            .await;

        match decision {
            HostKeyDecision::Reject => Ok(false),
            HostKeyDecision::Accept { remember } => {
                if remember {
                    let mut w = self.known.write().await;
                    if let Err(e) = w.trust(&self.host, self.port, key) {
                        warn!("failed to persist known_hosts: {e:#}");
                    }
                }
                Ok(true)
            }
        }
    }
}

/// One live SSH connection.
pub struct SshSession {
    pub host: String,
    pub port: u16,
    pub user: String,
    handle: Handle<SshHandler>,
    last_used: Arc<RwLock<Instant>>,
}

impl SshSession {
    /// Establish a new SSH session: TCP → handshake → publickey auth.
    pub async fn connect(
        host: String,
        port: u16,
        user: String,
        key_path: &std::path::Path,
        passphrase: Option<&str>,
        known: Arc<RwLock<KnownHosts>>,
        verifier: Arc<dyn HostKeyVerifier>,
    ) -> Result<Self> {
        let key_pair = russh::keys::load_secret_key(key_path, passphrase)
            .with_context(|| format!("loading SSH key {}", key_path.display()))?;

        let config = Arc::new(Config {
            inactivity_timeout: Some(Duration::from_secs(300)),
            keepalive_interval: Some(Duration::from_secs(30)),
            ..Config::default()
        });

        let handler = SshHandler {
            host: host.clone(),
            port,
            known,
            verifier,
        };

        info!("ssh connecting to {user}@{host}:{port}");
        let mut handle = client::connect(config, (host.as_str(), port), handler)
            .await
            .with_context(|| format!("ssh connect {host}:{port}"))?;

        let auth_ok = handle
            .authenticate_publickey(user.clone(), Arc::new(key_pair))
            .await
            .with_context(|| format!("ssh auth {user}@{host}"))?;

        if !auth_ok {
            anyhow::bail!("ssh publickey auth rejected by {host}:{port} for user {user}");
        }

        info!("ssh authenticated {user}@{host}:{port}");

        Ok(Self {
            host,
            port,
            user,
            handle,
            last_used: Arc::new(RwLock::new(Instant::now())),
        })
    }

    pub async fn touch(&self) {
        let mut t = self.last_used.write().await;
        *t = Instant::now();
    }

    pub async fn idle_for(&self) -> Duration {
        let t = self.last_used.read().await;
        t.elapsed()
    }

    pub async fn open_channel(&self) -> Result<russh::Channel<russh::client::Msg>> {
        self.touch().await;
        self.handle
            .channel_open_session()
            .await
            .context("opening ssh channel")
    }
}
