//! TLS certificate pinning (Trust On First Use) for the REST API client.
//!
//! Phase 13 audit fix. The pre-existing options were:
//! - `verify_tls = true` — strict CA validation (production)
//! - `verify_tls = false` — accept ANY cert (homelab, but MITM-able)
//!
//! TOFU sits between the two: on first connect proxxx fetches the
//! cluster's leaf certificate, hashes it, and pins it to disk; every
//! subsequent connect builds reqwest with that cert as the only
//! trusted root. If the cluster rotates its cert (legit renewal, or a
//! MITM swap), reqwest's standard verifier rejects the new cert and
//! the operator gets a clear error pointing at the pinned cert path
//! so they can verify out-of-band and delete the file to re-trust.
//!
//! Storage layout: `<config_dir>/known_certs/<host>_<port>.der`. Keyed
//! by `host_port`, not by profile name — two profiles that target the
//! same cluster (e.g. `--profile readonly` vs `--profile admin`) share
//! the pinned cert because it's the same cluster.
//!
//! DER bytes are saved raw (no PEM encoding) because reqwest's
//! `Certificate::from_der` accepts them directly — one fewer crate
//! dependency (no `base64` / `pem`). The fingerprint is computed
//! on-the-fly from the DER for logging.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// Open a TLS connection to `url` and return the leaf certificate as
/// raw DER bytes. The connection is closed immediately after the
/// handshake — we only want the cert, not the channel.
///
/// Uses an "accept any" verifier because we have no trust anchor yet
/// (the whole point of TOFU is establishing one). The operator pays
/// the trust cost once, on first connect; subsequent connects use
/// the pinned cert.
pub async fn probe_leaf_cert(url: &str) -> Result<Vec<u8>> {
    let parsed = reqwest::Url::parse(url).context("invalid URL for TLS probe")?;
    let host = parsed
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL has no host: {url}"))?
        .to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AlwaysAcceptVerifier))
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

/// Per-cluster path for the pinned cert file, keyed by `host_port`.
/// Different profiles targeting the same cluster share this file —
/// the pin is a property of the cluster's identity, not the operator's
/// auth identity. Path lives under `directories::ProjectDirs` so it
/// follows the OS's standard config dir (`XDG_CONFIG_HOME` on Linux,
/// ~/Library/Preferences on macOS).
pub fn pinned_cert_path(cluster_url: &str) -> Result<PathBuf> {
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
    let dirs = directories::ProjectDirs::from("dev", "proxxx", "proxxx")
        .ok_or_else(|| anyhow::anyhow!("could not resolve proxxx config dir"))?;
    Ok(dirs
        .config_dir()
        .join("known_certs")
        .join(format!("{safe_host}_{port}.der")))
}

/// Load the pinned certificate DER bytes for `cluster_url` if present.
/// Returns `Ok(None)` when the file doesn't exist — caller treats
/// that as "first connect, need to probe + save".
pub fn load_pinned_cert(cluster_url: &str) -> Result<Option<Vec<u8>>> {
    let path = pinned_cert_path(cluster_url)?;
    match std::fs::read(&path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading pinned cert {}", path.display())),
    }
}

/// Save the DER-encoded cert atomically (temp file + rename) so a
/// crash mid-write can't leave a half-written file the next start
/// would refuse to parse.
pub fn save_pinned_cert(cluster_url: &str, cert_der: &[u8]) -> Result<()> {
    let path = pinned_cert_path(cluster_url)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let tmp = path.with_extension("der.proxxx-tofu-tmp");
    std::fs::write(&tmp, cert_der).with_context(|| format!("writing tmp {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("renaming tmp to {}", path.display()))?;
    Ok(())
}

/// rustls verifier that accepts any server cert. Used ONLY during the
/// TOFU bootstrap probe — once a cert is pinned, the standard reqwest
/// TLS path (with the pinned cert as the only root) does real
/// validation.
#[derive(Debug)]
struct AlwaysAcceptVerifier;

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
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Mirror the schemes the default rustls verifier advertises —
        // we're bypassing validation, not capability negotiation.
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

#[cfg(test)]
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

    /// Pinned-cert round-trip: save bytes, load bytes, compare. Uses a
    /// PID-scoped fake URL so concurrent test runs don't collide.
    /// Cleanup at end is best-effort — leftover files are tiny and
    /// land in a known dir.
    #[test]
    fn pinned_cert_save_load_round_trip() {
        let url = format!("https://test-{}.example.invalid:8006", std::process::id());
        let cert = b"fake-der-bytes-for-test".to_vec();

        // Pre-condition: no file exists yet.
        let path = pinned_cert_path(&url).expect("path resolves");
        let _ = std::fs::remove_file(&path);
        assert!(
            load_pinned_cert(&url).expect("load").is_none(),
            "fresh cluster must have no pinned cert"
        );

        save_pinned_cert(&url, &cert).expect("save");
        let loaded = load_pinned_cert(&url)
            .expect("load")
            .expect("must exist after save");
        assert_eq!(loaded, cert);

        // Cleanup.
        let _ = std::fs::remove_file(&path);
    }

    /// `load_pinned_cert` returns Ok(None) for a missing file — not
    /// Err. This is the contract callers depend on to drive the "first
    /// connect → probe → save" branch.
    #[test]
    fn load_pinned_cert_missing_file_returns_none() {
        let url = format!(
            "https://missing-{}.example.invalid:8006",
            std::process::id()
        );
        let path = pinned_cert_path(&url).expect("path resolves");
        let _ = std::fs::remove_file(&path);
        assert!(load_pinned_cert(&url).expect("load").is_none());
    }

    /// `pinned_cert_path` sanitises non-host-safe chars (IPv6 colons,
    /// path separators) so the file system accepts the name. Pin this
    /// because a regression would land the file in an unexpected
    /// location and silently invalidate every existing pin.
    #[test]
    fn pinned_cert_path_sanitises_special_chars() {
        let url = "https://[2001:db8::1]:8006";
        let path = pinned_cert_path(url).expect("path resolves");
        let filename = path
            .file_name()
            .expect("has filename")
            .to_string_lossy()
            .into_owned();
        // No raw `[`, `]`, or `:` from the IPv6 literal should leak.
        assert!(!filename.contains('['), "filename has '[': {filename}");
        assert!(!filename.contains(']'), "filename has ']': {filename}");
        assert!(!filename.contains(':'), "filename has ':': {filename}");
        assert!(
            filename.ends_with("_8006.der"),
            "filename should end with the port + .der: {filename}"
        );
    }

    /// Two URLs pointing at the same host:port share the pinned cert
    /// path — the pin is a cluster property, not a URL string property.
    /// Catches regression that would re-pin per-URL even when host:port
    /// is identical (e.g. trailing slash, fragment).
    #[test]
    fn pinned_cert_path_collapses_url_variants_to_same_path() {
        let a = pinned_cert_path("https://pve.lan:8006").unwrap();
        let b = pinned_cert_path("https://pve.lan:8006/").unwrap();
        let c = pinned_cert_path("https://pve.lan:8006/api2/json").unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
    }
}
