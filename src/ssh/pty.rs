//! SSH PTY session for guest interactive shells (feature 1a).
//!
//! Lifecycle:
//! 1. Caller resolves a `ResolvedGuestSsh` from config.
//! 2. `PtySession::open(...)` connects, requests a PTY, requests a shell,
//!    spawns a pump task, and returns a handle.
//! 3. The pump task reads bytes from the channel and feeds a shared
//!    `vt100::Parser`. The TUI snapshots the parser to render.
//! 4. The TUI sends user keystrokes through the input mpsc; the pump
//!    forwards them to the channel.
//! 5. On close, the input sender is dropped, the pump exits, the channel
//!    is closed, and the session handle drops the russh `Handle`.
//!
//! Concurrency model: one tokio task per session. No locking on the hot path
//! beyond a `parking_lot::Mutex` (well, `std::sync::Mutex` here to avoid a
//! new dep) around the parser.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use russh::ChannelMsg;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::known_hosts::KnownHosts;
use super::session::{HostKeyVerifier, SshSession};
use crate::config::ResolvedGuestSsh;

/// Snapshot-able view of the parser state. Cheap to clone (just the Arc).
pub type SharedParser = Arc<Mutex<vt100::Parser>>;

/// Active PTY session against a guest. Drop to terminate.
pub struct PtySession {
    pub vmid: u32,
    pub host: String,
    pub user: String,
    parser: SharedParser,
    input_tx: mpsc::UnboundedSender<PtyInput>,
    pump: Option<JoinHandle<()>>,
}

/// Messages sent to the PTY pump task.
#[derive(Debug)]
enum PtyInput {
    /// Bytes to write to the SSH channel (encoded keypresses).
    Bytes(Vec<u8>),
    /// Inform the server of a new terminal size.
    Resize { cols: u16, rows: u16 },
    /// Stop the session and close the channel.
    Close,
}

impl PtySession {
    /// Open a fresh PTY session against a guest. Creates a new SSH connection
    /// (we don't pool guest connections — they're interactive and few).
    pub async fn open(
        vmid: u32,
        target: ResolvedGuestSsh,
        passphrase: Option<&str>,
        known: Arc<tokio::sync::RwLock<KnownHosts>>,
        verifier: Arc<dyn HostKeyVerifier>,
        cols: u16,
        rows: u16,
        scrollback: usize,
    ) -> Result<Self> {
        let host = target.host.clone();
        let user = target.user.clone();

        let session = SshSession::connect(
            target.host,
            target.port,
            target.user,
            &target.key_path,
            passphrase,
            known,
            verifier,
        )
        .await
        .with_context(|| format!("opening SSH to guest {vmid}"))?;

        let mut channel = session
            .open_channel()
            .await
            .context("opening SSH channel for PTY")?;

        channel
            .request_pty(
                true,
                "xterm-256color",
                u32::from(cols),
                u32::from(rows),
                0,
                0,
                &[],
            )
            .await
            .context("requesting PTY")?;
        channel
            .request_shell(true)
            .await
            .context("requesting shell")?;

        let parser = Arc::new(Mutex::new(vt100::Parser::new(rows, cols, scrollback)));
        let (input_tx, mut input_rx) = mpsc::unbounded_channel::<PtyInput>();

        let parser_for_pump = Arc::clone(&parser);
        let pump = tokio::spawn(async move {
            // Keep `session` owned by the pump so the connection stays alive
            // while we're reading from the channel.
            let _session_keepalive = session;
            info!("pty pump started for guest {vmid}");

            loop {
                tokio::select! {
                    msg = channel.wait() => {
                        match msg {
                            Some(ChannelMsg::Data { ref data }) => {
                                let mut p = match parser_for_pump.lock() {
                                    Ok(g) => g,
                                    Err(p) => p.into_inner(),
                                };
                                p.process(data);
                            }
                            Some(ChannelMsg::ExtendedData { ref data, ext }) => {
                                if ext == 1 {
                                    // Stderr from the remote shell — feed it to the
                                    // same parser so users see error output inline.
                                    let mut p = match parser_for_pump.lock() {
                                        Ok(g) => g,
                                        Err(p) => p.into_inner(),
                                    };
                                    p.process(data);
                                }
                            }
                            Some(ChannelMsg::ExitStatus { exit_status }) => {
                                debug!("pty exit status {exit_status}");
                            }
                            Some(ChannelMsg::Close) | None => break,
                            Some(_) => {}
                        }
                    }
                    input = input_rx.recv() => {
                        match input {
                            Some(PtyInput::Bytes(b)) => {
                                if let Err(e) = channel.data(&b[..]).await {
                                    warn!("pty write failed: {e:#}");
                                    break;
                                }
                            }
                            Some(PtyInput::Resize { cols, rows }) => {
                                if let Err(e) = channel
                                    .window_change(u32::from(cols), u32::from(rows), 0, 0)
                                    .await
                                {
                                    warn!("pty window_change failed: {e:#}");
                                }
                                let mut p = match parser_for_pump.lock() {
                                    Ok(g) => g,
                                    Err(p) => p.into_inner(),
                                };
                                p.screen_mut().set_size(rows, cols);
                            }
                            Some(PtyInput::Close) | None => {
                                let _ = channel.close().await;
                                break;
                            }
                        }
                    }
                }
            }

            info!("pty pump exited for guest {vmid}");
        });

        Ok(Self {
            vmid,
            host,
            user,
            parser,
            input_tx,
            pump: Some(pump),
        })
    }

    /// Cheap clone of the parser handle for the renderer.
    #[must_use]
    pub fn parser(&self) -> SharedParser {
        Arc::clone(&self.parser)
    }

    /// Send raw bytes to the remote PTY (encoded keypresses).
    pub fn send_bytes(&self, b: Vec<u8>) {
        if let Err(e) = self.input_tx.send(PtyInput::Bytes(b)) {
            warn!("pty input channel closed: {e}");
        }
    }

    /// Inform the remote PTY of a terminal resize.
    pub fn resize(&self, cols: u16, rows: u16) {
        let _ = self.input_tx.send(PtyInput::Resize { cols, rows });
    }

    /// Returns true once the pump task has exited (remote shell closed,
    /// connection dropped, or close requested).
    pub fn is_finished(&self) -> bool {
        self.pump.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// Request a graceful close. The pump will drain and exit.
    pub fn close(&self) {
        let _ = self.input_tx.send(PtyInput::Close);
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        // Best-effort close. The pump owns the SSH session, dropping the
        // sender alone is enough for `recv()` to return `None` and exit.
        let _ = self.input_tx.send(PtyInput::Close);
        if let Some(h) = self.pump.take() {
            h.abort();
        }
        // (audit) — orphaned remote shell guarantee.
        //
        // After abort the pump's owned `_session_keepalive: SshSession`
        // drops, which drops the inner `russh::client::Handle`. russh's
        // `Handle::Drop` sends `SSH_MSG_DISCONNECT` on the channel; the
        // remote sshd cleans up its child process group, which signals
        // SIGHUP to the controlling shell (bash / sh / etc.). The shell
        // exits, the kernel reaps it. No orphan PIDs accumulate on the
        // PVE node.
        //
        // Worst case (TCP RST race where DISCONNECT doesn't make it):
        // sshd's read returns EOF on the socket within its own
        // `ClientAliveCountMax * ClientAliveInterval` (default ≈ 9 min)
        // and reaps the child anyway. Not as fast as DISCONNECT, but
        // bounded — no permanent zombies.
    }
}

/// Encode a `KeyEvent` into the byte sequence a remote terminal expects.
///
/// Coverage chosen to match what xterm sends for the common keys; we don't
/// emulate every CSI mode (application-keypad, alt-screen flags) — that's
/// the remote shell's job once it gets the bytes.
#[must_use]
pub fn encode_key(key: &crossterm::event::KeyEvent) -> Option<Vec<u8>> {
    use crossterm::event::{KeyCode, KeyModifiers};

    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);

    let mut out: Vec<u8> = Vec::new();

    match key.code {
        KeyCode::Char(c) => {
            if ctrl {
                // Ctrl-A..Ctrl-Z map to 0x01..0x1A. Common controls:
                //   Ctrl-Space → 0x00, Ctrl-? (Ctrl-/) → 0x1F, Ctrl-] → 0x1D
                let upper = c.to_ascii_uppercase();
                let byte = match upper {
                    'A'..='Z' => Some(upper as u8 - b'A' + 1),
                    ' ' => Some(0),
                    '\\' => Some(0x1C),
                    ']' => Some(0x1D),
                    '^' => Some(0x1E),
                    '_' | '?' | '/' => Some(0x1F),
                    _ => None,
                };
                if let Some(b) = byte {
                    if alt {
                        out.push(0x1B);
                    }
                    out.push(b);
                    return Some(out);
                }
            }
            if alt {
                out.push(0x1B);
            }
            // For shifted ASCII, crossterm already gives us the shifted char.
            let _ = shift;
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
        KeyCode::Enter => out.push(b'\r'),
        KeyCode::Tab => out.push(b'\t'),
        KeyCode::BackTab => out.extend_from_slice(b"\x1b[Z"),
        KeyCode::Backspace => out.push(0x7F),
        KeyCode::Esc => out.push(0x1B),
        KeyCode::Left => out.extend_from_slice(b"\x1b[D"),
        KeyCode::Right => out.extend_from_slice(b"\x1b[C"),
        KeyCode::Up => out.extend_from_slice(b"\x1b[A"),
        KeyCode::Down => out.extend_from_slice(b"\x1b[B"),
        KeyCode::Home => out.extend_from_slice(b"\x1b[H"),
        KeyCode::End => out.extend_from_slice(b"\x1b[F"),
        KeyCode::PageUp => out.extend_from_slice(b"\x1b[5~"),
        KeyCode::PageDown => out.extend_from_slice(b"\x1b[6~"),
        KeyCode::Insert => out.extend_from_slice(b"\x1b[2~"),
        KeyCode::Delete => out.extend_from_slice(b"\x1b[3~"),
        KeyCode::F(n) => {
            // xterm function key encoding
            let seq: &[u8] = match n {
                1 => b"\x1bOP",
                2 => b"\x1bOQ",
                3 => b"\x1bOR",
                4 => b"\x1bOS",
                5 => b"\x1b[15~",
                6 => b"\x1b[17~",
                7 => b"\x1b[18~",
                8 => b"\x1b[19~",
                9 => b"\x1b[20~",
                10 => b"\x1b[21~",
                11 => b"\x1b[23~",
                12 => b"\x1b[24~",
                _ => return None,
            };
            out.extend_from_slice(seq);
        }
        _ => return None,
    }

    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn k(code: KeyCode, mods: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, mods)
    }

    #[test]
    fn plain_chars_pass_through() {
        assert_eq!(
            encode_key(&k(KeyCode::Char('a'), KeyModifiers::NONE)),
            Some(vec![b'a'])
        );
        assert_eq!(
            encode_key(&k(KeyCode::Char('Z'), KeyModifiers::SHIFT)),
            Some(vec![b'Z'])
        );
    }

    #[test]
    fn ctrl_letters() {
        assert_eq!(
            encode_key(&k(KeyCode::Char('a'), KeyModifiers::CONTROL)),
            Some(vec![0x01])
        );
        assert_eq!(
            encode_key(&k(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Some(vec![0x03])
        );
        assert_eq!(
            encode_key(&k(KeyCode::Char('z'), KeyModifiers::CONTROL)),
            Some(vec![0x1A])
        );
    }

    #[test]
    fn alt_prefixes_esc() {
        assert_eq!(
            encode_key(&k(KeyCode::Char('a'), KeyModifiers::ALT)),
            Some(vec![0x1B, b'a'])
        );
    }

    #[test]
    fn arrows_and_function_keys() {
        assert_eq!(
            encode_key(&k(KeyCode::Up, KeyModifiers::NONE)).as_deref(),
            Some(b"\x1b[A".as_ref())
        );
        assert_eq!(
            encode_key(&k(KeyCode::F(1), KeyModifiers::NONE)).as_deref(),
            Some(b"\x1bOP".as_ref())
        );
        assert_eq!(
            encode_key(&k(KeyCode::F(12), KeyModifiers::NONE)).as_deref(),
            Some(b"\x1b[24~".as_ref())
        );
    }

    #[test]
    fn enter_and_backspace() {
        assert_eq!(
            encode_key(&k(KeyCode::Enter, KeyModifiers::NONE)),
            Some(vec![b'\r'])
        );
        assert_eq!(
            encode_key(&k(KeyCode::Backspace, KeyModifiers::NONE)),
            Some(vec![0x7F])
        );
    }
}
