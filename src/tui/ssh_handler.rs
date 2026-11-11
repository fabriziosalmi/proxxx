//! Owns the active SSH PTY session for the TUI loop.
//!
//! `AppState` is plain data — it can't hold tokio channels or a `PtySession`.
//! This handler is the bridge: the TUI loop holds an `Arc<SshSessionHandler>`,
//! dispatches keys to it, and asks for the parser snapshot at render time.
//!
//! Concurrency: the active session lives behind a `std::sync::Mutex<Option<Arc<PtySession>>>`.
//! Lock hold time is always sub-millisecond — just an Arc clone or swap.
//! All `PtySession` methods we use (`parser`, `send_bytes`, `resize`, `close`,
//! `is_finished`) are synchronous, so the lock is never held across `.await`.
//!
//! Open is async (TCP + handshake + auth) and runs without holding the lock —
//! we install the resulting session at the very end with a brief lock.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use crossterm::event::KeyEvent;
use tokio::sync::RwLock as TokioRwLock;
use tracing::warn;

use crate::config::{HostKeyPolicy, ProfileConfig};
use crate::ssh::known_hosts::KnownHosts;
use crate::ssh::pty::{encode_key, PtySession, SharedParser};
use crate::ssh::session::{HostKeyVerifier, PolicyVerifier};

pub struct SshSessionHandler {
    profile: ProfileConfig,
    known: Arc<TokioRwLock<KnownHosts>>,
    verifier: Arc<dyn HostKeyVerifier>,
    /// SSH key passphrase. Seeded at startup from
    /// `PROXXX_SSH_KEY_PASSPHRASE` (if set), and otherwise filled in at
    /// runtime by the interactive TUI prompt (see [`Self::needs_passphrase`]
    /// / [`Self::set_passphrase`]). Behind a `Mutex` so the prompt can
    /// set it on the shared `Arc<SshSessionHandler>` without `&mut`.
    passphrase: Mutex<Option<crate::util::secret::SecretString>>,
    active: Mutex<Option<Arc<PtySession>>>,
}

impl SshSessionHandler {
    /// Build a handler from a profile. Lenient by design: a missing or
    /// unreadable `known_hosts` file is logged but does not fail the
    /// constructor — we'd rather start with an empty TOFU store than
    /// crash the entire TUI on first run.
    pub fn new(profile: ProfileConfig) -> Self {
        let (known, verifier) = if let Some(ref ssh) = profile.ssh {
            let mut policy = HostKeyPolicy::from_str(&ssh.strict_host_key_checking);
            let kh = match ssh.known_hosts_path() {
                Ok(known_path) => KnownHosts::load(known_path.clone())
                    .with_context(|| format!("loading known_hosts {}", known_path.display()))
                    .unwrap_or_else(|e| {
                        warn!("known_hosts load failed: {e:#} — starting with empty store");
                        KnownHosts::default()
                    }),
                Err(e) => {
                    // No private known_hosts location: trust nothing new
                    // rather than accept keys that cannot be persisted (#375).
                    warn!("{e:#} — SSH host keys will be checked strictly");
                    policy = HostKeyPolicy::Strict;
                    KnownHosts::default()
                }
            };
            let v: Arc<dyn HostKeyVerifier> = Arc::new(PolicyVerifier { policy });
            (Arc::new(TokioRwLock::new(kh)), v)
        } else {
            let v: Arc<dyn HostKeyVerifier> = Arc::new(PolicyVerifier {
                policy: HostKeyPolicy::Tofu,
            });
            (Arc::new(TokioRwLock::new(KnownHosts::default())), v)
        };

        let passphrase = std::env::var("PROXXX_SSH_KEY_PASSPHRASE")
            .ok()
            .map(crate::util::secret::SecretString::new);

        Self {
            profile,
            known,
            verifier,
            passphrase: Mutex::new(passphrase),
            active: Mutex::new(None),
        }
    }

    fn passphrase(&self) -> Option<crate::util::secret::SecretString> {
        match self.passphrase.lock() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// Store a passphrase entered via the interactive prompt. Reused for
    /// every subsequent connection this session, so the operator is
    /// prompted at most once.
    pub fn set_passphrase(&self, passphrase: crate::util::secret::SecretString) {
        match self.passphrase.lock() {
            Ok(mut g) => *g = Some(passphrase),
            Err(p) => *p.into_inner() = Some(passphrase),
        }
    }

    /// True when opening a session would need a passphrase we don't have
    /// yet: the configured key file is an encrypted OpenSSH key AND no
    /// passphrase is currently set (neither env nor a prior prompt). The
    /// TUI checks this before connecting and, if true, prompts first.
    #[must_use]
    pub fn needs_passphrase(&self) -> bool {
        if self.passphrase().is_some() {
            return false;
        }
        let Some(ssh) = self.profile.ssh.as_ref() else {
            return false;
        };
        // Profile-level key (tilde-expanded). A per-guest key override is
        // rare; if one is encrypted and the profile key isn't, the worst
        // case is the old behaviour (connect surfaces the encrypted-key
        // error) rather than a prompt — acceptable for the heuristic.
        let Some(key_path) = ssh.key_path_resolved() else {
            return false;
        };
        key_file_is_encrypted(&key_path)
    }

    /// Open a new PTY session. Closes any existing one first.
    /// `cols`/`rows` reflect the available pane size at open time.
    /// Async — caller should `tokio::spawn` this so the TUI doesn't freeze.
    pub async fn open(
        &self,
        client: &Arc<crate::api::PxClient>,
        vmid: u32,
        cols: u16,
        rows: u16,
    ) -> Result<()> {
        // Pop the prior session before connecting (the new one will replace it).
        // Done in a tight scope so the std::sync::Mutex isn't held over .await.
        let prior = {
            let mut g = match self.active.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            g.take()
        };
        if let Some(p) = prior {
            p.close();
        }

        // Same resolution as `proxxx ssh` (#545): the profile's
        // [ssh.guests."<vmid>"], else QGA / LXC-interface discovery.
        let (target, _source) =
            crate::cli::resolve_guest_target(client, &self.profile, vmid).await?;
        crate::config::validate_ssh_destination(&target.user, &target.host)
            .map_err(|why| anyhow::anyhow!("refusing to open SSH to guest {vmid}: {why}"))?;

        let pass = self.passphrase();
        let session = PtySession::open(
            vmid,
            target,
            pass.as_deref(),
            Arc::clone(&self.known),
            Arc::clone(&self.verifier),
            cols,
            rows,
            5_000, // scrollback lines
        )
        .await?;

        let mut g = match self.active.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        *g = Some(Arc::new(session));
        Ok(())
    }

    pub fn close(&self) {
        let prior = {
            let mut g = match self.active.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            g.take()
        };
        if let Some(s) = prior {
            s.close();
        }
    }

    /// Get the active session as a cheap Arc clone, or None.
    fn snapshot(&self) -> Option<Arc<PtySession>> {
        let g = match self.active.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.as_ref().map(Arc::clone)
    }

    /// Cheap clone of the parser handle for the renderer. None if no
    /// session is active.
    #[must_use]
    pub fn parser(&self) -> Option<SharedParser> {
        self.snapshot().map(|s| s.parser())
    }

    /// Forward a key event to the remote PTY. No-op if no session.
    pub fn forward_key(&self, key: &KeyEvent) {
        let Some(session) = self.snapshot() else {
            return;
        };
        let Some(bytes) = encode_key(key) else {
            warn!("unhandled key in PTY mode: {key:?}");
            return;
        };
        session.send_bytes(bytes);
    }

    /// Inform the remote PTY of a new terminal size.
    pub fn resize(&self, cols: u16, rows: u16) {
        if let Some(s) = self.snapshot() {
            s.resize(cols, rows);
        }
    }

    /// Has the active session ended (remote shell exited, connection lost)?
    /// False when no session exists.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.snapshot().is_some_and(|s| s.is_finished())
    }

    /// Currently-active VMID, if any. Public for diagnostic CLI; not
    /// yet wired into the TUI status bar (planned next iteration).
    #[must_use]
    #[allow(dead_code)]
    pub fn active_vmid(&self) -> Option<u32> {
        self.snapshot().map(|s| s.vmid)
    }

    /// Currently-active host string for the status bar, if any.
    #[must_use]
    pub fn active_host(&self) -> Option<String> {
        self.snapshot().map(|s| s.host.clone())
    }

    /// Currently-active user for the status bar, if any.
    #[must_use]
    pub fn active_user(&self) -> Option<String> {
        self.snapshot().map(|s| s.user.clone())
    }
}

/// Whether `key_path` is an *encrypted* OpenSSH private key (one that
/// needs a passphrase to load). Reads metadata only — no passphrase
/// required to answer. Returns `false` if the file is missing,
/// unreadable, not an OpenSSH key, or an unencrypted key: in every such
/// case we let the normal `load_secret_key` path run and surface any
/// real error at connect time, rather than prompting spuriously.
fn key_file_is_encrypted(key_path: &std::path::Path) -> bool {
    use russh::keys::ssh_key::PrivateKey;
    std::fs::read_to_string(key_path)
        .ok()
        .and_then(|pem| PrivateKey::from_openssh(&pem).ok())
        .is_some_and(|k| k.is_encrypted())
}

#[cfg(test)]
mod tests {
    use super::key_file_is_encrypted;
    use std::io::Write;

    #[test]
    fn encrypted_check_false_for_missing_file() {
        let p = std::path::Path::new("/nonexistent/proxxx/no-such-key");
        assert!(!key_file_is_encrypted(p));
    }

    #[test]
    fn encrypted_check_false_for_non_key_content() {
        // A file that isn't an OpenSSH key must read as "not encrypted"
        // (false) so we don't prompt — the real error surfaces at
        // connect time instead.
        let mut f = tempfile::NamedTempFile::new().expect("tempfile");
        writeln!(f, "this is not a private key").expect("write");
        assert!(!key_file_is_encrypted(f.path()));
    }
}

#[cfg(test)]
mod target_resolution_tests {
    //! #545: the TUI resolves a guest through the same code as `proxxx ssh`.
    //! Before, it read only [ssh.guests] and answered
    //! `guest 200 not configured under [profiles.X.ssh.guests."200"]`.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::sync::Arc;

    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::SshSessionHandler;
    use crate::api::PxClient;
    use crate::config::ProfileConfig;

    #[tokio::test]
    async fn the_tui_reports_a_stopped_guest_with_the_profile_header() {
        let server = MockServer::start().await;
        for (p, data) in [
            (
                "/cluster/resources",
                json!([{"vmid": 200, "type": "lxc", "node": "pve1", "status": "stopped", "name": "ct"}]),
            ),
            (
                "/nodes/pve1/lxc",
                json!([{"vmid": 200, "status": "stopped", "name": "ct"}]),
            ),
            ("/nodes/pve1/qemu", json!([])),
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/api2/json{p}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": data })))
                .mount(&server)
                .await;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let ssh = toml::from_str(&format!(
            "user = \"root\"\nkey_path = \"/nonexistent/id_ed25519\"\nknown_hosts = \"{}\"\n",
            dir.path().join("known_hosts").display()
        ))
        .expect("ssh table parses");
        let cfg = ProfileConfig {
            url: server.uri(),
            user: "root@pam".into(),
            auth: "token".into(),
            token_id: Some("t".into()),
            token_secret: Some(crate::util::secret::SecretString::from("dummy")),
            token_secret_file: None,
            password: None,
            verify_tls: false,
            tls_pin_mode: None,
            read_only: false,
            rate_limit: None,
            policies: None,
            telegram: None,
            ssh: Some(ssh),
            pbs: None,
            alerts: None,
            mcp_token: None,
            reconcile: None,
            profile_name: Some("lab".into()),
        };
        let client = Arc::new(
            PxClient::new(cfg.clone(), Some("dummy"))
                .await
                .expect("client builds"),
        );
        let handler = SshSessionHandler::new(cfg);
        let err = format!(
            "{:#}",
            handler.open(&client, 200, 80, 24).await.unwrap_err()
        );
        assert!(err.contains("guest 200 is stopped on node pve1"), "{err}");
        assert!(err.contains("[profiles.lab.ssh.guests.\"200\"]"), "{err}");
        assert!(!err.contains("profiles.X"), "{err}");
    }
}
