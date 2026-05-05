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
    /// SSH key passphrase (read once at startup from env). For now we
    /// don't prompt interactively — passphrase-protected keys must be
    /// either unlocked by ssh-agent (not yet supported here) or have
    /// `PROXXX_SSH_KEY_PASSPHRASE` set in the environment.
    passphrase: Option<String>,
    active: Mutex<Option<Arc<PtySession>>>,
}

impl SshSessionHandler {
    /// Build a handler from a profile. Lenient by design: a missing or
    /// unreadable `known_hosts` file is logged but does not fail the
    /// constructor — we'd rather start with an empty TOFU store than
    /// crash the entire TUI on first run.
    pub fn new(profile: ProfileConfig) -> Self {
        let (known, verifier) = if let Some(ref ssh) = profile.ssh {
            let known_path = ssh.known_hosts_path();
            let kh = KnownHosts::load(known_path.clone())
                .with_context(|| format!("loading known_hosts {}", known_path.display()))
                .unwrap_or_else(|e| {
                    warn!("known_hosts load failed: {e:#} — starting with empty store");
                    KnownHosts::default()
                });
            let policy = HostKeyPolicy::from_str(&ssh.strict_host_key_checking);
            let v: Arc<dyn HostKeyVerifier> = Arc::new(PolicyVerifier { policy });
            (Arc::new(TokioRwLock::new(kh)), v)
        } else {
            let v: Arc<dyn HostKeyVerifier> = Arc::new(PolicyVerifier {
                policy: HostKeyPolicy::Tofu,
            });
            (Arc::new(TokioRwLock::new(KnownHosts::default())), v)
        };

        let passphrase = std::env::var("PROXXX_SSH_KEY_PASSPHRASE").ok();

        Self {
            profile,
            known,
            verifier,
            passphrase,
            active: Mutex::new(None),
        }
    }

    /// Open a new PTY session. Closes any existing one first.
    /// `cols`/`rows` reflect the available pane size at open time.
    /// Async — caller should `tokio::spawn` this so the TUI doesn't freeze.
    pub async fn open(&self, vmid: u32, cols: u16, rows: u16) -> Result<()> {
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

        let ssh_cfg = self
            .profile
            .ssh
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("profile has no [ssh] block; SSH disabled"))?;
        let target = ssh_cfg.resolve_guest(vmid).ok_or_else(|| {
            anyhow::anyhow!("guest {vmid} not configured under [profiles.X.ssh.guests.\"{vmid}\"]")
        })?;

        let session = PtySession::open(
            vmid,
            target,
            self.passphrase.as_deref(),
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
