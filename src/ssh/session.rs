//! SSH connection lifecycle: connect, authenticate, hold, drop.
//!
//! One `SshSession` per `(profile, node)`. The `SshPool` owns them.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use russh::client::{self, AuthResult, Config, Handle, Handler};
// russh 0.60: `russh::keys::key::PublicKey` is private; the public
// type is re-exported at `russh::keys::PublicKey`. The `ssh-key`
// trait `PublicKeyBase64` lives in the re-exported `ssh_key` module.
use russh::keys::ssh_key::public::PublicKey;
use russh::keys::ssh_key::Algorithm;
use russh::keys::PrivateKeyWithHashAlg;
use russh::Preferred;
use tokio::sync::RwLock;
use tracing::{info, warn};

use super::known_hosts::{HostKey, HostMatch, KnownHosts};
use crate::config::HostKeyPolicy;

/// Decision returned by a `HostKeyVerifier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyDecision {
    /// Accept this connection. If `remember` is true, persist to `known_hosts`.
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
/// - TOFU + Mismatch  → Reject (possible `MitM`).
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

// russh 0.60 switched `Handler` to native AFIT (async fn in trait
// via RPIT), so we can NOT use the `#[async_trait]` macro here —
// that would generate a `Box<dyn Future>` signature that doesn't
// match the trait's `impl Future<Output = …> + Send`. Plain
// `async fn` in the impl works since Rust 1.75.
impl Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        // russh 0.60: PublicKey is now ssh_key::PublicKey (a re-export
        // of the `ssh-key` crate type). Method names changed:
        //   `.name()` → `.algorithm().as_str()`
        //   `.public_key_bytes()` → `.to_bytes()` (returns the wire-
        //                           format SSH public key blob).
        let key_type = server_public_key.algorithm().as_str().to_string();
        let key_blob = server_public_key.to_bytes().unwrap_or_default();
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
                    if let Err(e) = w.trust(&self.host, self.port, &key) {
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
            inactivity_timeout: Some(Duration::from_mins(5)),
            keepalive_interval: Some(Duration::from_secs(30)),
            preferred: hardened_algorithms(),
            ..Config::default()
        });

        let handler = SshHandler {
            host: host.clone(),
            port,
            known,
            verifier,
        };

        info!("ssh connecting to {user}@{host}:{port}");
        // Bound the TCP + SSH handshake. `Config.inactivity_timeout`
        // governs an *established idle* session, not the initial
        // connect — so without this a SYN to a black-holed host hangs
        // until the OS TCP timeout (minutes). Affects the TUI PTY view
        // and the `proxxx logs` cross-node fanout.
        const SSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
        let mut handle = tokio::time::timeout(
            SSH_CONNECT_TIMEOUT,
            client::connect(config, (host.as_str(), port), handler),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!("ssh connect {host}:{port} timed out after {SSH_CONNECT_TIMEOUT:?}")
        })?
        .with_context(|| format!("ssh connect {host}:{port}"))?;

        // russh 0.60: `authenticate_publickey` now takes a
        // `PrivateKeyWithHashAlg` (the hash-alg pin lets the client
        // negotiate rsa-sha2-256/512 instead of the deprecated
        // ssh-rsa-sha1). Passing `None` lets russh choose the
        // strongest mutually-supported algorithm — for ed25519 keys
        // (our only supported type per known_hosts policy) the hash
        // alg is irrelevant.
        let key_with_alg = PrivateKeyWithHashAlg::new(Arc::new(key_pair), None);
        let auth_result = handle
            .authenticate_publickey(user.clone(), key_with_alg)
            .await
            .with_context(|| format!("ssh auth {user}@{host}"))?;

        // russh 0.60: returns AuthResult enum (Success / Failure {…} /
        // Partial), not bool. Match for clean error reporting —
        // PartialFailure includes which methods the server still
        // expects (useful for debugging "I gave it a key but it
        // wants password too").
        match auth_result {
            AuthResult::Success => {}
            other => {
                anyhow::bail!(
                    "ssh publickey auth rejected by {host}:{port} for user {user}: {other:?}"
                );
            }
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

/// Phase 5.13 GAP 2 — explicit modern-only algorithm whitelist.
///
/// `russh::Preferred::DEFAULT` already excludes SHA-1 MACs and includes
/// only `EtM` HMACs, so the SHA1 invariant in the security matrix is met
/// out-of-the-box. This function tightens further: we narrow the
/// negotiated set to the algorithms our threat model actually wants,
/// rejecting older (but technically not-yet-broken) options like AES-CTR
/// and DH-G14.
///
/// Policy (matches the operational directive):
/// - **kex**: curve25519-sha256 only (plus the OpenSSH `ext-info-c` and
///   strict-kex extension markers — these are NOT real KEX algorithms,
///   they are signal flags the spec requires inside the kex list).
/// - **cipher**: ChaCha20-Poly1305 + AES-256-GCM only. Both are AEAD;
///   no separate MAC negotiation is required when these win.
/// - **mac**: HMAC-SHA-512-ETM + HMAC-SHA-256-ETM only. Used only as
///   fallback if a non-AEAD cipher were ever selected (it can't, given
///   the cipher list above) — kept defensively in case a future Proxmox
///   build advertises only CTR ciphers.
/// - **key (host key)**: Ed25519 only. Matches the `known_hosts` policy
///   in `super::known_hosts` which already rejects non-Ed25519 host
///   keys. Included here so the kex round trip narrows correctly
///   instead of negotiating an algorithm we'll then reject post-hoc.
/// - **compression**: NONE only. Compression-side-channel attacks
///   (CRIME-class) on a credential-bearing protocol are not worth the
///   trade; bandwidth is not the constraint on a console handoff.
///
/// Operator quote from the directive:
/// > Se un nodo Proxmox è talmente vecchio da supportare solo SHA-1,
/// > merita di non essere amministrato via SSH.
///
/// Concrete consequence: a Proxmox node configured to advertise only
/// `diffie-hellman-group14-sha1` + `aes128-ctr` + `hmac-sha1` will see
/// the russh client send a `kexinit` containing only the names above
/// and the server will reject the kex. proxxx will surface a
/// `KexInit failed` error rather than silently downgrading.
const fn hardened_algorithms() -> Preferred {
    Preferred {
        kex: Cow::Borrowed(&[
            russh::kex::CURVE25519,
            russh::kex::CURVE25519_PRE_RFC_8731,
            // Spec requires these to be sent in the kex list to signal
            // OpenSSH extension support + strict-kex (CVE-2023-48795
            // Terrapin attack mitigation). Removing them silently
            // disables the protection.
            russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
            russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
        ]),
        key: Cow::Borrowed(&[Algorithm::Ed25519]),
        cipher: Cow::Borrowed(&[russh::cipher::CHACHA20_POLY1305, russh::cipher::AES_256_GCM]),
        mac: Cow::Borrowed(&[russh::mac::HMAC_SHA512_ETM, russh::mac::HMAC_SHA256_ETM]),
        compression: Cow::Borrowed(&[russh::compression::NONE]),
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::hardened_algorithms;

    #[test]
    fn whitelist_excludes_sha1_kex() {
        let p = hardened_algorithms();
        let names: Vec<String> = p.kex.iter().map(|n| format!("{n:?}")).collect();
        let joined = names.join(",");
        // No SHA-1 KEX, no DH-group14-sha1, no DH-GEX-sha1.
        assert!(!joined.contains("sha1"), "sha1 KEX leaked: {joined}");
        // Curve25519 must be present.
        assert!(
            joined.contains("curve25519"),
            "curve25519 missing: {joined}"
        );
    }

    #[test]
    fn whitelist_excludes_legacy_ciphers() {
        let p = hardened_algorithms();
        let names: Vec<String> = p.cipher.iter().map(|n| format!("{n:?}")).collect();
        let joined = names.join(",");
        assert!(!joined.contains("aes128"), "aes128 leaked: {joined}");
        assert!(!joined.contains("ctr"), "CTR cipher leaked: {joined}");
        assert!(!joined.contains("3des"), "3des leaked: {joined}");
        assert!(!joined.contains("cbc"), "cbc leaked: {joined}");
        assert!(joined.contains("chacha20"), "chacha20 missing: {joined}");
        assert!(
            joined.contains("aes256-gcm"),
            "aes256-gcm missing: {joined}"
        );
    }

    #[test]
    fn whitelist_excludes_sha1_mac() {
        let p = hardened_algorithms();
        let names: Vec<String> = p.mac.iter().map(|n| format!("{n:?}")).collect();
        let joined = names.join(",");
        assert!(!joined.contains("hmac-sha1"), "hmac-sha1 leaked: {joined}");
        assert!(joined.contains("etm"), "EtM MAC missing: {joined}");
    }

    #[test]
    fn whitelist_keeps_strict_kex_extension() {
        // Without these markers russh will not negotiate strict-kex,
        // re-opening CVE-2023-48795 (Terrapin). This is a regression
        // guard.
        let p = hardened_algorithms();
        let names: Vec<String> = p.kex.iter().map(|n| format!("{n:?}")).collect();
        let joined = names.join(",");
        assert!(
            joined.contains("ext-info-c"),
            "ext-info-c missing — strict-kex won't negotiate: {joined}"
        );
        assert!(
            joined.contains("kex-strict-c"),
            "strict-kex client marker missing: {joined}"
        );
    }
}
