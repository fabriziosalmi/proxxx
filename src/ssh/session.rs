//! SSH connection lifecycle: connect, authenticate, hold, drop.
//!
//! One `SshSession` per `(profile, node)`. The `SshPool` owns them.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use russh::client::{self, AuthResult, Config, Handle, Handler};
// russh 0.64: `check_server_key` receives `PublicKeyOrCertificate`.
// Plain host keys are matched via `PublicKeyOrCertificate::PublicKey`;
// certificates are rejected because `proxxx` pins bare host keys in its
// own `KnownHosts` store and does not configure an OpenSSH CA trust list.
use russh::keys::ssh_key::Algorithm;
use russh::keys::{PrivateKeyWithHashAlg, PublicKeyOrCertificate};
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

impl SshHandler {
    /// Verify an encoded server public key blob against `KnownHosts` and the
    /// configured [`HostKeyVerifier`].
    ///
    /// Rejects (`Ok(false)`) any serialization error or empty key blob before
    /// consulting `KnownHosts` or the policy verifier, so a failed `to_bytes()`
    /// can never be compared against or pinned as an empty key.
    async fn verify_server_key_bytes(
        &self,
        key_type: &str,
        key_bytes: std::result::Result<Vec<u8>, russh::keys::ssh_key::Error>,
    ) -> Result<bool, russh::Error> {
        let key_blob = match key_bytes {
            Ok(blob) if !blob.is_empty() => blob,
            Ok(_) => {
                warn!(
                    "ssh host key verification: rejecting {}:{} due to empty serialized key blob",
                    self.host, self.port
                );
                return Ok(false);
            }
            Err(e) => {
                warn!(
                    "ssh host key verification: rejecting {}:{} due to public key serialization failure: {e}",
                    self.host, self.port
                );
                return Ok(false);
            }
        };

        let key = HostKey {
            key_type: key_type.to_string(),
            key_blob,
        };

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

// russh 0.60 switched `Handler` to native AFIT (async fn in trait
// via RPIT), so we can NOT use the `#[async_trait]` macro here —
// that would generate a `Box<dyn Future>` signature that doesn't
// match the trait's `impl Future<Output = …> + Send`. Plain
// `async fn` in the impl works since Rust 1.75.
impl Handler for SshHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        // russh 0.64 passes `PublicKeyOrCertificate`. `proxxx` does not
        // advertise host certificate algorithms (`host_key_certificates`
        // is empty) and does not validate OpenSSH CA signatures, so any
        // `Certificate` variant is rejected unconditionally.
        let PublicKeyOrCertificate::PublicKey { key, .. } = server_public_key else {
            warn!(
                "ssh host key verification: rejecting {}:{} because server presented a certificate instead of a plain host key",
                self.host, self.port
            );
            return Ok(false);
        };

        let algorithm = key.algorithm();
        self.verify_server_key_bytes(algorithm.as_str(), key.to_bytes())
            .await
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

        // russh 0.60: `authenticate_publickey` takes a `PrivateKeyWithHashAlg`.
        // For an RSA key we MUST pin rsa-sha2 (SHA-512) — passing `None` makes
        // russh sign with the key's default algorithm, which for RSA is the
        // deprecated `ssh-rsa` (SHA-1). Modern OpenSSH sshd (PVE 9 / Debian 13)
        // has ssh-rsa out of `PubkeyAcceptedAlgorithms` by default, so a `None`
        // RSA signature is rejected and RSA keys become unusable — even though
        // the same key works fine over the OpenSSH client (which negotiates
        // rsa-sha2 automatically). Ed25519 / ECDSA ignore the hash alg → `None`.
        let key_pair = Arc::new(key_pair);
        let hash_alg = if matches!(key_pair.algorithm(), russh::keys::Algorithm::Rsa { .. }) {
            Some(russh::keys::HashAlg::Sha512)
        } else {
            None
        };
        let key_with_alg = PrivateKeyWithHashAlg::new(key_pair, hash_alg);
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
        // Do not advertise `*-cert-v01@openssh.com`: proxxx pins plain
        // Ed25519 keys in its own `known_hosts` store and does not
        // validate OpenSSH host certificates against a trusted CA list.
        host_key_certificates: Cow::Borrowed(&[]),
        cipher: Cow::Borrowed(&[russh::cipher::CHACHA20_POLY1305, russh::cipher::AES_256_GCM]),
        mac: Cow::Borrowed(&[russh::mac::HMAC_SHA512_ETM, russh::mac::HMAC_SHA256_ETM]),
        compression: Cow::Borrowed(&[russh::compression::NONE]),
    }
}

#[cfg(test)]
mod hardening_tests {
    use std::sync::Arc;

    use russh::client::Handler as _;
    use russh::keys::ssh_key::private::Ed25519Keypair;
    use russh::keys::ssh_key::{Algorithm, LineEnding, PrivateKey};
    use russh::keys::PublicKeyOrCertificate;
    use tokio::net::TcpListener;
    use tokio::sync::RwLock;

    use super::{
        hardened_algorithms, HostKey, HostKeyPolicy, HostKeyVerifier, KnownHosts, PolicyVerifier,
        SshHandler, SshSession,
    };
    use crate::ssh::known_hosts::HostMatch;

    fn sample_private_key(seed_byte: u8) -> PrivateKey {
        let kp = Ed25519Keypair::from_seed(&[seed_byte; 32]);
        PrivateKey::from(kp)
    }

    fn make_handler(policy: HostKeyPolicy, known: Arc<RwLock<KnownHosts>>) -> SshHandler {
        let verifier: Arc<dyn HostKeyVerifier> = Arc::new(PolicyVerifier { policy });
        SshHandler {
            host: "127.0.0.1".to_string(),
            port: 2222,
            known,
            verifier,
        }
    }

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

    #[test]
    fn whitelist_disables_host_key_certificates() {
        let p = hardened_algorithms();
        assert_eq!(
            p.host_key_certificates.as_ref(),
            &[] as &[Algorithm],
            "host_key_certificates must be empty when no CA validation is configured"
        );
        assert_eq!(p.key.as_ref(), &[Algorithm::Ed25519]);
    }

    #[tokio::test]
    async fn host_key_policy_verification_matrix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let known_path = dir.path().join("known_hosts");
        let key_a = sample_private_key(0x11).public_key().clone();
        let key_b = sample_private_key(0x22).public_key().clone();
        let host_key_a = HostKey {
            key_type: key_a.algorithm().as_str().to_string(),
            key_blob: key_a.to_bytes().expect("key_a bytes"),
        };

        // 1. strict + unknown -> reject
        let known = Arc::new(RwLock::new(
            KnownHosts::load(known_path.clone()).expect("load"),
        ));
        let mut strict_handler = make_handler(HostKeyPolicy::Strict, Arc::clone(&known));
        let accepted = strict_handler
            .check_server_key(&PublicKeyOrCertificate::from(key_a.clone()))
            .await
            .expect("check_server_key");
        assert!(!accepted, "strict + unknown must reject");
        assert_eq!(
            known.read().await.check("127.0.0.1", 2222, &host_key_a),
            HostMatch::Unknown
        );

        // 2. tofu + unknown -> accept and pinned
        let mut tofu_handler = make_handler(HostKeyPolicy::Tofu, Arc::clone(&known));
        let accepted = tofu_handler
            .check_server_key(&PublicKeyOrCertificate::from(key_a.clone()))
            .await
            .expect("check_server_key");
        assert!(accepted, "tofu + unknown must accept");
        assert_eq!(
            known.read().await.check("127.0.0.1", 2222, &host_key_a),
            HostMatch::Match,
            "tofu must pin the newly accepted key"
        );

        // 3. strict + known match -> accept
        let accepted = strict_handler
            .check_server_key(&PublicKeyOrCertificate::from(key_a.clone()))
            .await
            .expect("check_server_key");
        assert!(accepted, "strict + known match must accept");

        // 4. strict + changed key -> reject; tofu + changed key -> reject
        let accepted_strict_mismatch = strict_handler
            .check_server_key(&PublicKeyOrCertificate::from(key_b.clone()))
            .await
            .expect("check_server_key");
        assert!(
            !accepted_strict_mismatch,
            "strict + changed key must reject"
        );

        let accepted_tofu_mismatch = tofu_handler
            .check_server_key(&PublicKeyOrCertificate::from(key_b))
            .await
            .expect("check_server_key");
        assert!(!accepted_tofu_mismatch, "tofu + changed key must reject");
    }

    #[tokio::test]
    async fn host_key_serialization_failure_and_certificates_are_rejected() {
        use russh::keys::ssh_key::certificate::{Builder, CertType};

        let dir = tempfile::tempdir().expect("tempdir");
        let known_path = dir.path().join("known_hosts");
        let known = Arc::new(RwLock::new(KnownHosts::load(known_path).expect("load")));

        let subject_key = sample_private_key(0x66);
        let ca_key = sample_private_key(0x77);
        let mut cert_builder = Builder::new(
            [0xAAu8; 32],
            subject_key.public_key().key_data().clone(),
            0,
            u64::MAX,
        )
        .expect("cert builder");
        cert_builder.serial(1).expect("serial");
        cert_builder.key_id("host-cert").expect("key_id");
        cert_builder.cert_type(CertType::Host).expect("cert_type");
        cert_builder
            .valid_principal("127.0.0.1")
            .expect("valid_principal");
        let cert = cert_builder.sign(&ca_key).expect("sign cert");

        for policy in [
            HostKeyPolicy::Strict,
            HostKeyPolicy::Tofu,
            HostKeyPolicy::Off,
        ] {
            let mut handler = make_handler(policy, Arc::clone(&known));
            let accepted_err = handler
                .verify_server_key_bytes(
                    "ssh-ed25519",
                    Err(russh::keys::ssh_key::Error::AlgorithmUnknown),
                )
                .await
                .expect("verify_server_key_bytes");
            assert!(
                !accepted_err,
                "serialization failure must be rejected under {policy:?}"
            );

            let accepted_empty = handler
                .verify_server_key_bytes("ssh-ed25519", Ok(Vec::new()))
                .await
                .expect("verify_server_key_bytes");
            assert!(
                !accepted_empty,
                "empty serialized key blob must be rejected under {policy:?}"
            );

            let accepted_cert = handler
                .check_server_key(&PublicKeyOrCertificate::Certificate(cert.clone()))
                .await
                .expect("check_server_key cert");
            assert!(
                !accepted_cert,
                "host certificate must be rejected under {policy:?} when CA validation is not configured"
            );
        }

        // Verify nothing was pinned to known_hosts even under Tofu.
        let empty_key = HostKey {
            key_type: "ssh-ed25519".to_string(),
            key_blob: Vec::new(),
        };
        assert_eq!(
            known.read().await.check("127.0.0.1", 2222, &empty_key),
            HostMatch::Unknown,
            "failed serialization must never pin an empty blob in KnownHosts"
        );
    }

    struct InProcessSshServer;

    impl russh::server::Handler for InProcessSshServer {
        type Error = russh::Error;

        async fn auth_publickey(
            &mut self,
            _user: &str,
            _public_key: &russh::keys::ssh_key::PublicKey,
        ) -> Result<russh::server::Auth, Self::Error> {
            Ok(russh::server::Auth::Accept)
        }
    }

    async fn spawn_in_process_server(host_key: PrivateKey) -> u16 {
        let mut server_config = russh::server::Config::default();
        server_config.keys.push(host_key);
        let server_config = Arc::new(server_config);

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind 127.0.0.1:0");
        let port = listener.local_addr().expect("local_addr").port();

        tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                let _ = russh::server::run_stream(server_config, socket, InProcessSshServer).await;
            }
        });

        port
    }

    #[tokio::test]
    async fn in_process_russh_server_accepts_matching_key_and_refuses_swapped_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let client_key = sample_private_key(0x33);
        let client_key_openssh = client_key
            .to_openssh(LineEnding::LF)
            .expect("encode client key");
        let client_key_path = dir.path().join("id_ed25519");
        std::fs::write(&client_key_path, client_key_openssh.as_bytes()).expect("write client key");

        let server_key_a = sample_private_key(0x44);
        let server_pub_a = server_key_a.public_key().clone();
        let server_key_b = sample_private_key(0x55);

        // 1. Server with key A: pre-trusted in KnownHosts under Strict policy -> connects.
        let port_ok = spawn_in_process_server(server_key_a).await;
        let known_ok_path = dir.path().join("known_hosts_ok");
        let mut known_ok = KnownHosts::load(known_ok_path).expect("load known_hosts");
        known_ok
            .trust(
                "127.0.0.1",
                port_ok,
                &HostKey {
                    key_type: server_pub_a.algorithm().as_str().to_string(),
                    key_blob: server_pub_a.to_bytes().expect("server_pub_a bytes"),
                },
            )
            .expect("trust key A");
        let known_ok = Arc::new(RwLock::new(known_ok));
        let strict_verifier: Arc<dyn HostKeyVerifier> = Arc::new(PolicyVerifier {
            policy: HostKeyPolicy::Strict,
        });

        let session = SshSession::connect(
            "127.0.0.1".to_string(),
            port_ok,
            "root".to_string(),
            &client_key_path,
            None,
            known_ok,
            Arc::clone(&strict_verifier),
        )
        .await
        .expect("matching host key must connect and authenticate");
        assert_eq!(session.port, port_ok);

        // 2. Server with swapped key B while KnownHosts pins key A -> refused.
        let port_bad = spawn_in_process_server(server_key_b).await;
        let known_bad_path = dir.path().join("known_hosts_bad");
        let mut known_bad = KnownHosts::load(known_bad_path).expect("load known_hosts");
        known_bad
            .trust(
                "127.0.0.1",
                port_bad,
                &HostKey {
                    key_type: server_pub_a.algorithm().as_str().to_string(),
                    key_blob: server_pub_a.to_bytes().expect("server_pub_a bytes"),
                },
            )
            .expect("trust key A for port_bad");
        let known_bad = Arc::new(RwLock::new(known_bad));

        let err = SshSession::connect(
            "127.0.0.1".to_string(),
            port_bad,
            "root".to_string(),
            &client_key_path,
            None,
            known_bad,
            strict_verifier,
        )
        .await
        .err()
        .expect("swapped host key must be refused");
        let chain = format!("{err:#}");
        assert!(
            chain.contains("Unknown server key"),
            "expected Unknown server key error in chain, got: {chain}"
        );
    }
}
