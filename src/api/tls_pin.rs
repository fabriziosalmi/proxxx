//! TLS leaf-certificate pinning (`tls_pin_mode = "tofu"` for PVE `#320`, and
//! `pbs.fingerprint` for PBS `#414`).
//!
//! Options for cluster TLS verification:
//! - `verify_tls = true` — strict `WebPKI` CA + hostname validation (production)
//! - `verify_tls = false` — accept ANY cert (homelab, MITM-able)
//! - `tls_pin_mode = "tofu"` (PVE) / `fingerprint = "AB:CD:..."` (PBS) —
//!   custom [`rustls::client::danger::ServerCertVerifier`] ([`PinnedLeafVerifier`])
//!   that verifies the presented end-entity certificate's SHA-256 digest in
//!   constant time and cryptographically verifies the TLS 1.2 / TLS 1.3
//!   handshake signature against the certificate's public key using `ring`.
//!
//! Why a custom [`ServerCertVerifier`] instead of `add_root_certificate(leaf)`
//! (`#320`): a stock Proxmox VE node serves a leaf certificate (`pve-ssl.pem`,
//! `CN=<node>`) issued by the cluster CA (`pve-root-ca.pem`,
//! `O=PVE Cluster Manager CA`). Passing the leaf to `add_root_certificate`
//! with `tls_built_in_root_certs(false)` made `WebPKI` treat the non-CA leaf as a
//! trust anchor, failing every connection with `UnknownIssuer` (and
//! `InvalidCertName` when connecting by IP). [`PinnedLeafVerifier`] pins the
//! end-entity leaf directly — replacing chain and hostname checks — while
//! still enforcing `rustls::crypto::verify_tls12_signature` and
//! `rustls::crypto::verify_tls13_signature` so a peer that replays the public
//! certificate without holding its private key is rejected.
//!
//! Storage layout: `<config_dir>/known_certs/<host>_<port>.der` (overridable via
//! explicit directory injection in tests or `PROXXX_KNOWN_CERTS_DIR`).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Constant-time 32-byte equality comparison for SHA-256 certificate digests.
fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= std::hint::black_box(a[i] ^ b[i]);
    }
    std::hint::black_box(diff) == 0
}

/// Format a 32-byte SHA-256 digest as uppercase colon-separated hex
/// (`"AB:CD:...:EF"`), matching `openssl x509 -fingerprint -sha256` and
/// `proxmox-backup-manager cert info`.
#[must_use]
pub fn format_colon_fingerprint(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(95);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        let _ = write!(out, "{b:02X}");
    }
    out
}

/// Parse a SHA-256 certificate fingerprint from either 32 colon-separated hex
/// byte pairs (`"AB:CD:...:23"`) or 64 contiguous hex characters
/// (`"abcd...23"`), case-insensitive (`#414`).
///
/// # Errors
/// Returns an error if `raw` does not decode to 32 bytes (64 hex digits).
pub fn parse_sha256_fingerprint(raw: &str) -> Result<[u8; 32]> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        anyhow::bail!(
            "config key `pbs.fingerprint` is empty — expected a SHA-256 fingerprint \
             (32 colon-separated hex byte pairs like \"AB:CD:...:EF\" or 64 hex digits), \
             or omit `fingerprint` when not pinning"
        );
    }

    let mut out = [0u8; 32];
    if trimmed.contains(':') {
        let parts: Vec<&str> = trimmed.split(':').collect();
        if parts.len() != 32 {
            anyhow::bail!(
                "config key `pbs.fingerprint` is {raw:?}, which has {} colon-separated \
                 byte(s) instead of 32 (expected SHA-256 format \"AB:CD:...:EF\")",
                parts.len()
            );
        }
        for (idx, part) in parts.iter().enumerate() {
            if part.len() != 2 {
                anyhow::bail!(
                    "config key `pbs.fingerprint` is {raw:?}: segment #{idx} ({part:?}) \
                     must be exactly 2 hex digits (expected SHA-256 format \"AB:CD:...:EF\")"
                );
            }
            out[idx] = u8::from_str_radix(part, 16).map_err(|_| {
                anyhow::anyhow!(
                    "config key `pbs.fingerprint` is {raw:?}: segment #{idx} ({part:?}) \
                     contains non-hex characters (expected SHA-256 format \"AB:CD:...:EF\")"
                )
            })?;
        }
    } else {
        if trimmed.len() != 64 {
            anyhow::bail!(
                "config key `pbs.fingerprint` is {raw:?}, which is {} character(s) long \
                 (expected 32 colon-separated hex byte pairs \"AB:CD:...:EF\" or 64 hex digits)",
                trimmed.len()
            );
        }
        let decoded = hex::decode(trimmed).map_err(|e| {
            anyhow::anyhow!(
                "config key `pbs.fingerprint` is {raw:?}, which is not valid hex ({e}); \
                 expected 32 colon-separated hex byte pairs \"AB:CD:...:EF\" or 64 hex digits"
            )
        })?;
        out.copy_from_slice(&decoded);
    }

    Ok(out)
}

/// Origin of a pinned leaf fingerprint, used to format actionable remediation
/// instructions when a server presents a non-matching certificate (`#320`, `#414`).
#[derive(Debug, Clone)]
pub enum PinSource {
    /// Pinned via TOFU (`tls_pin_mode = "tofu"`) at `path`.
    TofuFile { cluster_url: String, path: PathBuf },
    /// Pinned via explicit `fingerprint = "..."` in `config.toml` (`#414`).
    ConfigFingerprint,
}

/// Custom [`ServerCertVerifier`] that pins the SHA-256 digest of the leaf
/// certificate (`#320`, `#414`).
///
/// - [`Self::verify_server_cert`] checks `SHA-256(end_entity)` against the
///   pinned 32-byte digest in constant time. Chain and hostname checks are
///   intentionally skipped because the pin itself authenticates the exact
///   endpoint certificate (supporting self-signed and cluster-CA-signed PVE/PBS
///   leaf certs accessed by IP or internal hostname).
/// - [`Self::verify_tls12_signature`] and [`Self::verify_tls13_signature`]
///   delegate to `rustls::crypto::verify_tls12_signature` /
///   `rustls::crypto::verify_tls13_signature` with the `ring` crypto provider's
///   signature verification algorithms, ensuring the server proves possession of
///   the private key matching the pinned leaf certificate.
#[derive(Debug)]
pub struct PinnedLeafVerifier {
    expected_sha256: [u8; 32],
    source: PinSource,
    provider: Arc<CryptoProvider>,
}

impl PinnedLeafVerifier {
    /// Construct a verifier pinning the SHA-256 of `cert_der` loaded from (or
    /// saved to) `path` for `cluster_url`.
    #[must_use]
    pub fn from_der(cert_der: &[u8], cluster_url: impl Into<String>, path: PathBuf) -> Self {
        let expected_sha256: [u8; 32] = Sha256::digest(cert_der).into();
        Self {
            expected_sha256,
            source: PinSource::TofuFile {
                cluster_url: cluster_url.into(),
                path,
            },
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }

    /// Construct a verifier pinning an explicit 32-byte SHA-256 digest (e.g.
    /// from `pbs.fingerprint`, `#414`).
    #[must_use]
    pub fn from_fingerprint(expected_sha256: [u8; 32]) -> Self {
        Self {
            expected_sha256,
            source: PinSource::ConfigFingerprint,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }

    /// Return the expected 32-byte SHA-256 digest.
    #[must_use]
    pub const fn expected_sha256(&self) -> &[u8; 32] {
        &self.expected_sha256
    }

    /// Wrap this verifier in a [`rustls::ClientConfig`] suitable for
    /// `reqwest::ClientBuilder::use_preconfigured_tls` and
    /// `tokio_tungstenite::Connector::Rustls`.
    #[must_use]
    pub fn into_client_config(self: Arc<Self>) -> ClientConfig {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(self)
            .with_no_client_auth()
    }
}

impl ServerCertVerifier for PinnedLeafVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        let presented_sha256: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if ct_eq_32(&presented_sha256, &self.expected_sha256) {
            return Ok(ServerCertVerified::assertion());
        }

        let pinned_hex = hex::encode(self.expected_sha256);
        let presented_hex = hex::encode(presented_sha256);
        let pinned_colon = format_colon_fingerprint(&self.expected_sha256);
        let presented_colon = format_colon_fingerprint(&presented_sha256);

        let msg = match &self.source {
            PinSource::TofuFile { cluster_url, path } => format!(
                "TLS certificate pin mismatch for {cluster_url}: \
                 pinned sha256={pinned_hex} ({pinned_colon}) at {}, \
                 but server presented sha256={presented_hex} ({presented_colon}). \
                 To re-trust after a legitimate certificate renewal, verify the new \
                 fingerprint out of band and delete {}",
                path.display(),
                path.display()
            ),
            PinSource::ConfigFingerprint => format!(
                "TLS certificate pin mismatch: \
                 configured fingerprint sha256={pinned_hex} ({pinned_colon}), \
                 but server presented sha256={presented_hex} ({presented_colon}). \
                 Verify the server's new certificate fingerprint out of band and \
                 update `fingerprint` in config.toml"
            ),
        };
        Err(RustlsError::General(msg))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Open a TLS connection to `url` and return the leaf certificate as
/// raw DER bytes. The connection is closed immediately after the
/// handshake — we only want the cert, not the channel.
///
/// Uses an "accept any cert, verify handshake signature" verifier because we
/// have no trust anchor yet on first TOFU connect. The operator pays the
/// trust-on-first-use cost once; subsequent connects enforce the pinned leaf
/// via [`PinnedLeafVerifier`].
pub async fn probe_leaf_cert(url: &str) -> Result<Vec<u8>> {
    let parsed = reqwest::Url::parse(url).context("invalid URL for TLS probe")?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL has no host: {url}"))?
        .to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AlwaysAcceptVerifier::new()))
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));

    let tcp = TcpStream::connect((host.as_str(), port))
        .await
        .with_context(|| format!("TCP connect to {host}:{port} for TLS probe"))?;
    let server_name = ServerName::try_from(host.clone())
        .with_context(|| format!("invalid server name for TLS probe: {host}"))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .with_context(|| format!("TLS handshake to {host}:{port}"))?;

    let (_io, conn) = tls.get_ref();
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| anyhow::anyhow!("server presented no certificates"))?;
    let leaf = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty certificate chain from server"))?;
    Ok(leaf.as_ref().to_vec())
}

/// SHA-256 of the certificate DER, rendered as lowercase hex.
/// Used for logging and the cert-rotation error message — gives the
/// operator a value they can cross-check against `openssl x509
/// -fingerprint -sha256` or PVE's web UI cert page.
#[must_use]
pub fn fingerprint_sha256(cert_der: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cert_der);
    hex::encode(hasher.finalize())
}

/// Resolve the default `known_certs` directory: `PROXXX_KNOWN_CERTS_DIR` when
/// set and non-empty, otherwise `<config_dir>/known_certs`.
pub fn default_known_certs_dir() -> Result<PathBuf> {
    if let Ok(override_dir) = std::env::var("PROXXX_KNOWN_CERTS_DIR") {
        let trimmed = override_dir.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    let dirs = directories::ProjectDirs::from("dev", "proxxx", "proxxx")
        .ok_or_else(|| anyhow::anyhow!("could not resolve proxxx config dir"))?;
    Ok(dirs.config_dir().join("known_certs"))
}

/// Per-cluster path for the pinned cert file inside `known_certs_dir` (or the
/// default `known_certs` directory when `None`), keyed by `host_port`.
pub fn pinned_cert_path_in(cluster_url: &str, known_certs_dir: Option<&Path>) -> Result<PathBuf> {
    let parsed = reqwest::Url::parse(cluster_url).context("invalid URL for cert pin path")?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL has no host: {cluster_url}"))?;
    let port = parsed.port_or_known_default().unwrap_or(443);
    // Sanitise: any character that's not host-safe gets replaced with
    // `_`. IPv6 colons in `[::1]` would collide with the file separator
    // on macOS; replacing them keeps the file system happy.
    let safe_host: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let base_dir = match known_certs_dir {
        Some(d) => d.to_path_buf(),
        None => default_known_certs_dir()?,
    };
    Ok(base_dir.join(format!("{safe_host}_{port}.der")))
}

/// Per-cluster path for the pinned cert file, keyed by `host_port`.
/// Different profiles targeting the same cluster share this file —
/// the pin is a property of the cluster's identity, not the operator's
/// auth identity.
pub fn pinned_cert_path(cluster_url: &str) -> Result<PathBuf> {
    pinned_cert_path_in(cluster_url, None)
}

/// Load the pinned certificate DER bytes for `cluster_url` from
/// `known_certs_dir` (or the default directory when `None`).
/// Returns `Ok(None)` when the file doesn't exist.
pub fn load_pinned_cert_in(
    cluster_url: &str,
    known_certs_dir: Option<&Path>,
) -> Result<Option<Vec<u8>>> {
    let path = pinned_cert_path_in(cluster_url, known_certs_dir)?;
    match std::fs::read(&path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading pinned cert {}", path.display())),
    }
}

/// Load the pinned certificate DER bytes for `cluster_url` if present.
/// Returns `Ok(None)` when the file doesn't exist — caller treats
/// that as "first connect, need to probe + save".
pub fn load_pinned_cert(cluster_url: &str) -> Result<Option<Vec<u8>>> {
    load_pinned_cert_in(cluster_url, None)
}

/// Save the DER-encoded cert atomically (temp file + durable rename) into
/// `known_certs_dir` (or the default directory when `None`), returning the
/// final path.
pub fn save_pinned_cert_in(
    cluster_url: &str,
    cert_der: &[u8],
    known_certs_dir: Option<&Path>,
) -> Result<PathBuf> {
    let path = pinned_cert_path_in(cluster_url, known_certs_dir)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = path.with_extension("der.proxxx-tofu-tmp");
    std::fs::write(&tmp, cert_der).with_context(|| format!("writing tmp {}", tmp.display()))?;
    crate::util::durable::rename_durable(&tmp, &path)
        .with_context(|| format!("renaming tmp to {}", path.display()))?;
    Ok(path)
}

/// Save the DER-encoded cert atomically (temp file + durable rename) so a
/// crash mid-write can't leave a half-written file the next start
/// would refuse to parse.
pub fn save_pinned_cert(cluster_url: &str, cert_der: &[u8]) -> Result<()> {
    save_pinned_cert_in(cluster_url, cert_der, None).map(|_| ())
}

/// rustls verifier used ONLY during the initial TOFU bootstrap probe
/// ([`probe_leaf_cert`]) when no pin exists on disk yet. Accepts the
/// server's certificate chain so `peer_certificates()` can be read, while
/// still verifying the handshake signature against the presented leaf's public
/// key.
#[derive(Debug)]
struct AlwaysAcceptVerifier {
    provider: Arc<CryptoProvider>,
}

impl AlwaysAcceptVerifier {
    fn new() -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl ServerCertVerifier for AlwaysAcceptVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// SHA-256 of the empty input is well-defined: `e3b0c44298fc1c149a…`.
    /// Pins the algorithm choice + hex casing.
    #[test]
    fn fingerprint_sha256_empty_input() {
        let h = fingerprint_sha256(&[]);
        assert_eq!(
            h,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// SHA-256 is deterministic — same input always yields the same hex.
    /// Catches accidental nondeterminism (e.g. a future contributor
    /// adding salt for "security").
    #[test]
    fn fingerprint_sha256_deterministic() {
        let a = fingerprint_sha256(b"hello, proxxx");
        let b = fingerprint_sha256(b"hello, proxxx");
        assert_eq!(a, b);
        // Different input → different hash (collision resistance is
        // beyond our scope; this just catches a totally-broken impl).
        let c = fingerprint_sha256(b"hello, proxxX");
        assert_ne!(a, c);
    }

    /// Pinned-cert round-trip: save bytes, load bytes, compare inside an
    /// isolated `tempfile::tempdir()` so tests never touch the developer's
    /// real `<config_dir>/known_certs/` directory (`#320`).
    #[test]
    fn pinned_cert_save_load_round_trip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let url = "https://test.example.invalid:8006";
        let cert = b"fake-der-bytes-for-test".to_vec();

        // Pre-condition: no file exists yet in the isolated temp dir.
        let path = pinned_cert_path_in(url, Some(tmp.path())).expect("path resolves");
        assert!(!path.exists());
        assert!(
            load_pinned_cert_in(url, Some(tmp.path()))
                .expect("load")
                .is_none(),
            "fresh cluster must have no pinned cert"
        );

        save_pinned_cert_in(url, &cert, Some(tmp.path())).expect("save");
        let loaded = load_pinned_cert_in(url, Some(tmp.path()))
            .expect("load")
            .expect("must exist after save");
        assert_eq!(loaded, cert);
    }

    /// `load_pinned_cert_in` returns Ok(None) for a missing file — not
    /// Err. This is the contract callers depend on to drive the "first
    /// connect → probe → save" branch.
    #[test]
    fn load_pinned_cert_missing_file_returns_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let url = "https://missing.example.invalid:8006";
        assert!(load_pinned_cert_in(url, Some(tmp.path()))
            .expect("load")
            .is_none());
    }

    /// `pinned_cert_path_in` sanitises non-host-safe chars (IPv6 colons,
    /// path separators) so the file system accepts the name. Pin this
    /// because a regression would land the file in an unexpected
    /// location and silently invalidate every existing pin.
    #[test]
    fn pinned_cert_path_sanitises_special_chars() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let url = "https://[2001:db8::1]:8006";
        let path = pinned_cert_path_in(url, Some(tmp.path())).expect("path resolves");
        let filename = path
            .file_name()
            .expect("has filename")
            .to_string_lossy()
            .into_owned();
        // No raw `[`, `]`, or `:` from the IPv6 literal should leak.
        assert!(!filename.contains('['), "filename has '['");
        assert!(!filename.contains(']'), "filename has ']'");
        assert!(!filename.contains(':'), "filename has ':'");
        assert!(
            filename.ends_with("_8006.der"),
            "filename should end with the port + .der"
        );
    }

    /// Two URLs pointing at the same host:port share the pinned cert
    /// path — the pin is a cluster property, not a URL string property.
    /// Catches regression that would re-pin per-URL even when host:port
    /// is identical (e.g. trailing slash, fragment).
    #[test]
    fn pinned_cert_path_collapses_url_variants_to_same_path() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let a = pinned_cert_path_in("https://pve.lan:8006", Some(tmp.path())).unwrap();
        let b = pinned_cert_path_in("https://pve.lan:8006/", Some(tmp.path())).unwrap();
        let c = pinned_cert_path_in("https://pve.lan:8006/api2/json", Some(tmp.path())).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }

    #[test]
    fn parse_sha256_fingerprint_accepts_colon_and_raw_hex_and_rejects_malformed() {
        let raw_bytes = [0xABu8; 32];
        let colon = format_colon_fingerprint(&raw_bytes);
        let hex_lower = hex::encode(raw_bytes);

        assert_eq!(parse_sha256_fingerprint(&colon).unwrap(), raw_bytes);
        assert_eq!(
            parse_sha256_fingerprint(&colon.to_ascii_lowercase()).unwrap(),
            raw_bytes
        );
        assert_eq!(parse_sha256_fingerprint(&hex_lower).unwrap(), raw_bytes);

        assert!(parse_sha256_fingerprint("").is_err());
        assert!(parse_sha256_fingerprint("AB:CD:EF").is_err());
        assert!(parse_sha256_fingerprint("not-a-valid-fingerprint").is_err());
        let bad_seg = format!("GG{}", &colon[2..]);
        assert!(parse_sha256_fingerprint(&bad_seg).is_err());
    }

    // ── Live local tokio-rustls test harness (#320, #414) ─────────────

    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::ServerConfig;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    struct CaBundle {
        ca_der: CertificateDer<'static>,
        issuer: Issuer<'static, KeyPair>,
    }

    struct LeafCert {
        cert_der: CertificateDer<'static>,
        key_der: PrivateKeyDer<'static>,
    }

    fn generate_pve_ca() -> CaBundle {
        let mut params = CertificateParams::new(Vec::new()).expect("ca params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "PVE Cluster Manager CA");
        params
            .distinguished_name
            .push(DnType::CommonName, "Proxmox Virtual Environment SD-CA");
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let key = KeyPair::generate().expect("ca keypair");
        let cert = params.self_signed(&key).expect("self-signed ca");
        let ca_der = cert.der().clone();
        CaBundle {
            ca_der,
            issuer: Issuer::new(params, key),
        }
    }

    /// Issue a non-CA leaf certificate signed by `ca` whose CN and SAN are
    /// `node_cn` (e.g. `"pve-test-1.lab"` — deliberately NOT `"127.0.0.1"` or
    /// `"localhost"` so connecting to `https://127.0.0.1:<port>` exercises
    /// both non-self-signed CA chain and IP/hostname mismatch).
    fn issue_leaf(ca: &CaBundle, node_cn: &str) -> LeafCert {
        let mut params =
            CertificateParams::new(vec![node_cn.to_string()]).expect("leaf cert params");
        params.is_ca = IsCa::NoCa;
        params.distinguished_name.push(DnType::CommonName, node_cn);
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let key = KeyPair::generate().expect("leaf keypair");
        let cert = params.signed_by(&key, &ca.issuer).expect("ca signs leaf");
        let cert_der = cert.der().clone();
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        LeafCert { cert_der, key_der }
    }

    struct LocalTlsServer {
        url: String,
        port: u16,
        accepts: Arc<AtomicUsize>,
        handle: tokio::task::JoinHandle<()>,
    }

    impl LocalTlsServer {
        async fn start(server_config: ServerConfig) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            let port = addr.port();
            let url = format!("https://127.0.0.1:{port}");
            let accepts = Arc::new(AtomicUsize::new(0));
            let accepts_bg = Arc::clone(&accepts);
            let acceptor = TlsAcceptor::from(Arc::new(server_config));

            let handle = tokio::spawn(async move {
                while let Ok((tcp, _peer)) = listener.accept().await {
                    accepts_bg.fetch_add(1, Ordering::SeqCst);
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let mut buf = [0u8; 2048];
                        let _ = tls.read(&mut buf).await;
                        let body =
                            r#"{"data":{"version":"9.1.1","release":"9.1","repoid":"deadbeef"}}"#;
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = tls.write_all(resp.as_bytes()).await;
                        let _ = tls.shutdown().await;
                    });
                }
            });

            Self {
                url,
                port,
                accepts,
                handle,
            }
        }

        fn accept_count(&self) -> usize {
            self.accepts.load(Ordering::SeqCst)
        }
    }

    impl Drop for LocalTlsServer {
        fn drop(&mut self) {
            self.handle.abort();
        }
    }

    fn server_config_for_leaf(leaf: &LeafCert, ca_der: &CertificateDer<'static>) -> ServerConfig {
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.cert_der.clone(), ca_der.clone()],
                leaf.key_der.clone_key(),
            )
            .expect("valid server config")
    }

    fn test_profile_config(
        url: &str,
        verify_tls: bool,
        tls_pin_mode: Option<&str>,
    ) -> crate::config::ProfileConfig {
        crate::config::ProfileConfig {
            url: url.to_string(),
            user: "root@pam".to_string(),
            auth: "token".to_string(),
            token_id: Some("proxxx".to_string()),
            token_secret: Some(crate::util::secret::SecretString::from("test-secret")),
            token_secret_file: None,
            password: None,
            verify_tls,
            tls_pin_mode: tls_pin_mode.map(str::to_string),
            read_only: false,
            rate_limit: Some(100),
            policies: None,
            telegram: None,
            ssh: None,
            pbs: None,
            alerts: None,
            mcp_token: None,
            reconcile: None,
            profile_name: Some("lab".to_string()),
        }
    }

    /// Test 1 (#320):
    /// PVE shape: CA -> leaf (leaf NOT self-signed, CN `pve-test-1.lab`
    /// different from URL host `127.0.0.1`). Pin the leaf: a request succeeds
    /// (whereas adding the leaf as a trust anchor fails with `UnknownIssuer`).
    #[tokio::test]
    async fn pve_ca_issued_leaf_with_mismatched_cn_succeeds_when_pinned() {
        use crate::api::ProxmoxGateway;

        let ca = generate_pve_ca();
        let leaf = issue_leaf(&ca, "pve-test-1.lab");
        let srv = LocalTlsServer::start(server_config_for_leaf(&leaf, &ca.ca_der)).await;

        // Sanity check: the pre-#320 trust-anchor approach (`add_root_certificate`
        // with a non-CA leaf) fails against this exact server.
        let legacy_cert = reqwest::Certificate::from_der(leaf.cert_der.as_ref()).unwrap();
        let legacy_http = reqwest::Client::builder()
            .tls_built_in_root_certs(false)
            .add_root_certificate(legacy_cert)
            .build()
            .unwrap();
        assert!(
            legacy_http
                .get(format!("{}/api2/json/version", srv.url))
                .send()
                .await
                .is_err(),
            "legacy add_root_certificate(leaf) must fail against a CA-issued PVE leaf"
        );

        let tmp = tempfile::tempdir().expect("tempdir");
        save_pinned_cert_in(&srv.url, leaf.cert_der.as_ref(), Some(tmp.path())).expect("pin leaf1");

        let cfg = test_profile_config(&srv.url, true, Some("tofu"));
        let client = crate::api::PxClient::new_with_known_certs_dir(cfg, None, Some(tmp.path()))
            .await
            .expect("client builds with pinned CA-issued leaf");
        let ver = client
            .get_api_version()
            .await
            .expect("request succeeds with PinnedLeafVerifier");
        assert_eq!(ver.version, "9.1.1");
    }

    /// Test 2 (#320):
    /// A different leaf from the SAME CA is rejected with the pin-mismatch
    /// error showing both fingerprints and the pinned file path, and makes
    /// exactly ONE connection attempt (no 4x retry on TLS/cert failure).
    #[tokio::test]
    async fn different_leaf_from_same_ca_is_rejected_with_both_fingerprints_and_single_attempt() {
        use crate::api::ProxmoxGateway;

        let ca = generate_pve_ca();
        let leaf1 = issue_leaf(&ca, "pve-test-1.lab");
        let leaf2 = issue_leaf(&ca, "pve-test-2.lab");

        // Server presents leaf2 (signed by the SAME CA), while leaf1 is pinned.
        let srv = LocalTlsServer::start(server_config_for_leaf(&leaf2, &ca.ca_der)).await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let pinned_path = save_pinned_cert_in(&srv.url, leaf1.cert_der.as_ref(), Some(tmp.path()))
            .expect("pin leaf1");

        let cfg = test_profile_config(&srv.url, true, Some("tofu"));
        let client = crate::api::PxClient::new_with_known_certs_dir(cfg, None, Some(tmp.path()))
            .await
            .expect("client builds");

        let err = client
            .get_api_version()
            .await
            .expect_err("different leaf from same CA must be rejected");
        let full = format!("{err:#}");

        let fp1 = fingerprint_sha256(leaf1.cert_der.as_ref());
        let fp2 = fingerprint_sha256(leaf2.cert_der.as_ref());
        assert!(
            full.contains("pin mismatch"),
            "error must state pin mismatch, got: {full}"
        );
        assert!(
            full.contains(&fp1),
            "error must include pinned SHA-256 ({fp1}), got: {full}"
        );
        assert!(
            full.contains(&fp2),
            "error must include presented SHA-256 ({fp2}), got: {full}"
        );
        assert!(
            full.contains(&pinned_path.display().to_string()),
            "error must include pinned cert file path ({}), got: {full}",
            pinned_path.display()
        );
        assert_eq!(
            srv.accept_count(),
            1,
            "pin mismatch is not transient and must not be retried 4 times"
        );
    }

    /// Test 3a (#320 — TLS 1.3):
    /// Key check over TLS 1.3: a server presenting the exact pinned certificate
    /// DER but holding a DIFFERENT private key is rejected during
    /// `verify_tls13_signature`. Fails if `verify_tls13_signature` returns
    /// `HandshakeSignatureValid::assertion()`.
    #[tokio::test]
    async fn server_presenting_pinned_cert_with_wrong_private_key_is_rejected() {
        use crate::api::ProxmoxGateway;

        let ca = generate_pve_ca();
        let leaf1 = issue_leaf(&ca, "pve-test-1.lab");
        let wrong_leaf = issue_leaf(&ca, "impostor.lab");

        // Build a ServerConfig that sends `leaf1.cert_der` (the pinned public
        // certificate) in the TLS Certificate message, but signs the handshake
        // CertificateVerify with `wrong_leaf.key_der`.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let wrong_signing_key = provider
            .key_provider
            .load_private_key(wrong_leaf.key_der.clone_key())
            .expect("load wrong private key");
        let forged_certified_key = rustls::sign::CertifiedKey::new(
            vec![leaf1.cert_der.clone(), ca.ca_der.clone()],
            wrong_signing_key,
        );
        let rogue_server_cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                forged_certified_key,
            )));

        let srv = LocalTlsServer::start(rogue_server_cfg).await;
        let tmp = tempfile::tempdir().expect("tempdir");
        save_pinned_cert_in(&srv.url, leaf1.cert_der.as_ref(), Some(tmp.path()))
            .expect("pin leaf1");

        let cfg = test_profile_config(&srv.url, true, Some("tofu"));
        let client = crate::api::PxClient::new_with_known_certs_dir(cfg, None, Some(tmp.path()))
            .await
            .expect("client builds");

        let err = client
            .get_api_version()
            .await
            .expect_err("server without the pinned certificate's private key must be rejected");
        let full = format!("{err:#}");
        assert!(
            !full.contains("pin mismatch"),
            "cert bytes matched, so rejection must come from handshake signature verification, got: {full}"
        );
        assert_eq!(
            srv.accept_count(),
            1,
            "bad handshake signature must not be retried"
        );
    }

    /// Test 3b (#320 — TLS 1.2):
    /// Key check over TLS 1.2: a MITM holding the public pinned certificate can
    /// force TLS 1.2 in `ServerHello` so `verify_tls12_signature` (not 1.3) runs.
    /// Verifies that:
    /// 1. A TLS 1.2-only server with the matching private key succeeds when pinned.
    /// 2. A TLS 1.2-only server presenting the pinned certificate DER but signing
    ///    `ServerKeyExchange` with a DIFFERENT private key is rejected during
    ///    `verify_tls12_signature` on the first attempt (`accept_count() == 1`).
    /// Fails if `verify_tls12_signature` returns `HandshakeSignatureValid::assertion()`.
    #[tokio::test]
    async fn server_presenting_pinned_cert_with_wrong_private_key_over_tls12_is_rejected() {
        use crate::api::ProxmoxGateway;

        let ca = generate_pve_ca();
        let leaf1 = issue_leaf(&ca, "pve-test-1.lab");
        let wrong_leaf = issue_leaf(&ca, "impostor.lab");

        // 1. Control check: TLS 1.2-only server with the legitimate private key succeeds.
        let valid_tls12_cfg =
            ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
                .with_no_client_auth()
                .with_single_cert(
                    vec![leaf1.cert_der.clone(), ca.ca_der.clone()],
                    leaf1.key_der.clone_key(),
                )
                .expect("valid TLS 1.2 server config");
        let valid_srv = LocalTlsServer::start(valid_tls12_cfg).await;
        let valid_tmp = tempfile::tempdir().expect("tempdir");
        save_pinned_cert_in(
            &valid_srv.url,
            leaf1.cert_der.as_ref(),
            Some(valid_tmp.path()),
        )
        .expect("pin leaf1 for valid TLS 1.2 server");
        let valid_client = crate::api::PxClient::new_with_known_certs_dir(
            test_profile_config(&valid_srv.url, true, Some("tofu")),
            None,
            Some(valid_tmp.path()),
        )
        .await
        .expect("client builds");
        let ver = valid_client
            .get_api_version()
            .await
            .expect("TLS 1.2 server with matching key must succeed");
        assert_eq!(ver.version, "9.1.1");

        // 2. Forged TLS 1.2-only server presenting `leaf1.cert_der` with `wrong_leaf.key_der`.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let wrong_signing_key = provider
            .key_provider
            .load_private_key(wrong_leaf.key_der.clone_key())
            .expect("load wrong private key");
        let forged_certified_key = rustls::sign::CertifiedKey::new(
            vec![leaf1.cert_der.clone(), ca.ca_der.clone()],
            wrong_signing_key,
        );
        let rogue_tls12_cfg =
            ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(
                    forged_certified_key,
                )));

        let srv = LocalTlsServer::start(rogue_tls12_cfg).await;
        let tmp = tempfile::tempdir().expect("tempdir");
        save_pinned_cert_in(&srv.url, leaf1.cert_der.as_ref(), Some(tmp.path()))
            .expect("pin leaf1");

        let cfg = test_profile_config(&srv.url, true, Some("tofu"));
        let client = crate::api::PxClient::new_with_known_certs_dir(cfg, None, Some(tmp.path()))
            .await
            .expect("client builds");

        let err = client.get_api_version().await.expect_err(
            "TLS 1.2 server without the pinned certificate's private key must be rejected",
        );
        let full = format!("{err:#}");
        assert!(
            !full.contains("pin mismatch"),
            "cert bytes matched, so TLS 1.2 rejection must come from verify_tls12_signature, got: {full}"
        );
        assert_eq!(
            srv.accept_count(),
            1,
            "TLS 1.2 bad handshake signature must not be retried"
        );
    }

    /// Test 4 (#320):
    /// TOFU first connect against an injected empty `known_certs` directory
    /// probes and pins the presented leaf; second connect loads the pin from
    /// disk and succeeds without re-probing.
    #[tokio::test]
    async fn tofu_first_connect_pins_leaf_in_temp_dir_and_second_connect_succeeds() {
        use crate::api::ProxmoxGateway;

        let ca = generate_pve_ca();
        let leaf = issue_leaf(&ca, "pve-test-1.lab");
        let srv = LocalTlsServer::start(server_config_for_leaf(&leaf, &ca.ca_der)).await;
        let tmp = tempfile::tempdir().expect("tempdir");

        assert!(
            load_pinned_cert_in(&srv.url, Some(tmp.path()))
                .unwrap()
                .is_none(),
            "known_certs dir must start empty"
        );

        let cfg = test_profile_config(&srv.url, true, Some("tofu"));
        let client1 =
            crate::api::PxClient::new_with_known_certs_dir(cfg.clone(), None, Some(tmp.path()))
                .await
                .expect("first connect probes and saves leaf");
        let v1 = client1.get_api_version().await.expect("first GET /version");
        assert_eq!(v1.version, "9.1.1");

        let pinned_bytes = load_pinned_cert_in(&srv.url, Some(tmp.path()))
            .unwrap()
            .expect("leaf must be persisted after first connect");
        assert_eq!(pinned_bytes.as_slice(), leaf.cert_der.as_ref());

        let accepts_after_first = srv.accept_count();
        // Second connect: pin is already on disk, so `PxClient::new_with_known_certs_dir`
        // must NOT open a probe connection.
        let client2 = crate::api::PxClient::new_with_known_certs_dir(cfg, None, Some(tmp.path()))
            .await
            .expect("second connect loads existing pin");
        assert_eq!(
            srv.accept_count(),
            accepts_after_first,
            "second connect must load pin from disk without a new TLS probe"
        );
        let v2 = client2
            .get_api_version()
            .await
            .expect("second GET /version");
        assert_eq!(v2.version, "9.1.1");
    }

    /// Test 5 (#320):
    /// Serial console path: `wsterm::connect` with a `PinnedLeafVerifier`
    /// rejects a mismatching leaf.
    #[tokio::test]
    async fn wsterm_connect_with_pin_rejects_mismatching_leaf() {
        let ca = generate_pve_ca();
        let leaf1 = issue_leaf(&ca, "pve-test-1.lab");
        let leaf2 = issue_leaf(&ca, "pve-test-2.lab");

        let srv = LocalTlsServer::start(server_config_for_leaf(&leaf2, &ca.ca_der)).await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let pin_path = save_pinned_cert_in(&srv.url, leaf1.cert_der.as_ref(), Some(tmp.path()))
            .expect("pin leaf1");
        let verifier = Arc::new(PinnedLeafVerifier::from_der(
            leaf1.cert_der.as_ref(),
            &srv.url,
            pin_path,
        ));

        let target = crate::wsterm::build_ws_target(
            &srv.url,
            "pve1",
            100,
            crate::api::types::GuestType::Qemu,
            u32::from(srv.port),
            "PVEVNC:00000000::ticket",
            "root@pam",
        );

        let err = crate::wsterm::connect(&target, false, Some(verifier), &[])
            .await
            .expect_err(
                "wsterm::connect must reject a mismatching leaf even when verify_tls=false",
            );
        let full = format!("{err:#}");
        assert!(
            full.contains("pin mismatch"),
            "wsterm error must report pin mismatch, got: {full}"
        );
        assert!(
            full.contains(&fingerprint_sha256(leaf1.cert_der.as_ref())),
            "wsterm error must include pinned fingerprint, got: {full}"
        );
        assert!(
            full.contains(&fingerprint_sha256(leaf2.cert_der.as_ref())),
            "wsterm error must include presented fingerprint, got: {full}"
        );
    }

    /// Test 6 (#414 / T3):
    /// PBS: `fingerprint` set to the test leaf -> `PbsClient` request succeeds
    /// with `verify_tls = true`; wrong fingerprint -> rejected; malformed
    /// fingerprint -> config load error (`ConfigError::InvalidValue`).
    #[tokio::test]
    async fn pbs_client_enforces_fingerprint_pin_and_config_rejects_malformed_fingerprint() {
        use crate::pbs::PbsGateway;

        let ca = generate_pve_ca();
        let leaf1 = issue_leaf(&ca, "pbs.lab");
        let leaf2 = issue_leaf(&ca, "pbs-other.lab");
        let srv = LocalTlsServer::start(server_config_for_leaf(&leaf1, &ca.ca_der)).await;

        let leaf1_sha: [u8; 32] = Sha256::digest(leaf1.cert_der.as_ref()).into();
        let leaf2_sha: [u8; 32] = Sha256::digest(leaf2.cert_der.as_ref()).into();

        // 1. Matching fingerprint with verify_tls = true succeeds against
        //    CA-issued leaf with CN != 127.0.0.1.
        let ok_cfg = crate::config::PbsConfig {
            url: srv.url.clone(),
            user: "proxxx@pbs".to_string(),
            token_id: "reader".to_string(),
            token_secret: Some(crate::util::secret::SecretString::from("pbs-secret")),
            token_secret_file: None,
            verify_tls: true,
            fingerprint: Some(format_colon_fingerprint(&leaf1_sha)),
            rate_limit: Some(100),
        };
        let pbs_ok = crate::pbs::PbsClient::new(ok_cfg, None)
            .await
            .expect("PbsClient builds with valid fingerprint");
        let ver = pbs_ok
            .version()
            .await
            .expect("PBS version succeeds when leaf matches configured fingerprint");
        assert_eq!(ver.version, "9.1.1");

        // 2. Wrong fingerprint is rejected with pin mismatch.
        let wrong_cfg = crate::config::PbsConfig {
            url: srv.url.clone(),
            user: "proxxx@pbs".to_string(),
            token_id: "reader".to_string(),
            token_secret: Some(crate::util::secret::SecretString::from("pbs-secret")),
            token_secret_file: None,
            verify_tls: true,
            fingerprint: Some(format_colon_fingerprint(&leaf2_sha)),
            rate_limit: Some(100),
        };
        let pbs_wrong = crate::pbs::PbsClient::new(wrong_cfg, None)
            .await
            .expect("PbsClient builds");
        let wrong_err = pbs_wrong
            .version()
            .await
            .expect_err("PBS request must fail when server cert does not match fingerprint");
        let wrong_msg = format!("{wrong_err:#}");
        assert!(
            wrong_msg.contains("pin mismatch"),
            "expected pin mismatch error from PBS client, got: {wrong_msg}"
        );

        // 3. Malformed fingerprint is rejected at config load with ConfigError (exit code 3).
        let tmp_cfg = tempfile::NamedTempFile::new().expect("temp config");
        std::fs::write(
            tmp_cfg.path(),
            format!(
                r#"
url = "{}"
user = "root@pam"
token_id = "proxxx"
token_secret = "secret"

[pbs]
url = "{}"
user = "proxxx@pbs"
token_id = "reader"
token_secret = "pbs-secret"
verify_tls = true
fingerprint = "not-a-valid-sha256-fingerprint"
"#,
                srv.url, srv.url
            ),
        )
        .expect("write temp config");

        let cfg_err = crate::config::load_config_from_path(tmp_cfg.path(), None)
            .expect_err("malformed pbs.fingerprint must fail at config load");
        let downcast = cfg_err
            .downcast_ref::<crate::config::ConfigError>()
            .expect("must be typed ConfigError");
        assert_eq!(crate::config::ConfigError::EXIT_CODE, 3);
        assert!(
            downcast.to_string().contains("pbs.fingerprint"),
            "config error must name `pbs.fingerprint`, got: {downcast}"
        );
    }
}
