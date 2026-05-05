//! Command execution over an SSH channel: capture or stream.
//!
//! Both `exec` and `exec_stream` go through the same russh channel
//! event loop; they differ only in how they handle stdout/stderr lines.

use std::time::Duration;

use anyhow::{Context, Result};
use russh::ChannelMsg;
use tokio::time::timeout;
use tracing::{debug, warn};

use super::session::SshSession;

/// Result of a non-streaming exec.
#[derive(Debug, Clone)]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<u32>,
}

impl ExecResult {
    #[must_use]
    pub fn ok(&self) -> bool {
        self.exit_code == Some(0)
    }
}

/// Per-call options. Defaults are conservative.
#[derive(Debug, Clone)]
pub struct ExecOptions {
    /// Hard timeout for the whole exec. None = no timeout (only use for streaming).
    pub timeout: Option<Duration>,
    /// Cap captured output (per stream) to N bytes to avoid blowing memory.
    /// Default 4 MiB; set to `usize::MAX` to disable.
    pub max_capture_bytes: usize,
}

impl Default for ExecOptions {
    fn default() -> Self {
        Self {
            timeout: Some(Duration::from_mins(1)),
            max_capture_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Streamed stdout/stderr line. Lines are split on `\n` (CR stripped).
#[derive(Debug, Clone)]
pub enum StreamLine {
    Stdout(String),
    Stderr(String),
}

/// Run a command and capture full stdout/stderr.
pub async fn exec(session: &SshSession, command: &str, opts: ExecOptions) -> Result<ExecResult> {
    let fut = exec_inner(
        session,
        command,
        opts.max_capture_bytes,
        None::<fn(StreamLine)>,
    );
    match opts.timeout {
        Some(t) => timeout(t, fut).await.context("ssh exec timed out")?,
        None => fut.await,
    }
}

/// Run a command, invoking `on_line` for each line of output as it arrives.
/// Returns the exit code when the channel closes.
pub async fn exec_stream<F>(
    session: &SshSession,
    command: &str,
    opts: ExecOptions,
    mut on_line: F,
) -> Result<Option<u32>>
where
    F: FnMut(StreamLine) + Send,
{
    let cb = move |line: StreamLine| on_line(line);
    let fut = exec_inner_stream(session, command, opts.max_capture_bytes, cb);
    let res = match opts.timeout {
        Some(t) => timeout(t, fut).await.context("ssh exec_stream timed out")?,
        None => fut.await,
    }?;
    Ok(res.exit_code)
}

async fn exec_inner<F>(
    session: &SshSession,
    command: &str,
    max_capture: usize,
    on_line: Option<F>,
) -> Result<ExecResult>
where
    F: FnMut(StreamLine) + Send,
{
    if let Some(cb) = on_line {
        exec_inner_stream(session, command, max_capture, cb).await
    } else {
        exec_inner_stream(session, command, max_capture, |_| {}).await
    }
}

async fn exec_inner_stream<F>(
    session: &SshSession,
    command: &str,
    max_capture: usize,
    mut on_line: F,
) -> Result<ExecResult>
where
    F: FnMut(StreamLine) + Send,
{
    let mut channel = session.open_channel().await?;
    debug!("ssh exec: {command}");
    channel
        .exec(true, command)
        .await
        .context("requesting exec")?;

    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut stdout_buf = Vec::<u8>::new();
    let mut stderr_buf = Vec::<u8>::new();
    let mut exit_code: Option<u32> = None;

    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { ref data } => {
                push_lines(
                    data,
                    &mut stdout_buf,
                    &mut stdout,
                    max_capture,
                    &mut on_line,
                    true,
                );
            }
            ChannelMsg::ExtendedData { ref data, ext: 1 } => {
                push_lines(
                    data,
                    &mut stderr_buf,
                    &mut stderr,
                    max_capture,
                    &mut on_line,
                    false,
                );
            }
            ChannelMsg::ExitStatus { exit_status } => {
                exit_code = Some(exit_status);
            }
            ChannelMsg::Eof => {
                // Flush whatever's left in the line buffers.
                if !stdout_buf.is_empty() {
                    flush_buf(
                        &mut stdout_buf,
                        &mut stdout,
                        max_capture,
                        &mut on_line,
                        true,
                    );
                }
                if !stderr_buf.is_empty() {
                    flush_buf(
                        &mut stderr_buf,
                        &mut stderr,
                        max_capture,
                        &mut on_line,
                        false,
                    );
                }
            }
            ChannelMsg::Close => break,
            _ => {}
        }
    }

    if exit_code.is_none() {
        warn!("ssh exec '{command}' closed without ExitStatus");
    }

    Ok(ExecResult {
        stdout,
        stderr,
        exit_code,
    })
}

fn push_lines<F>(
    chunk: &[u8],
    line_buf: &mut Vec<u8>,
    capture: &mut String,
    max_capture: usize,
    on_line: &mut F,
    is_stdout: bool,
) where
    F: FnMut(StreamLine),
{
    if capture.len() < max_capture {
        let remaining = max_capture - capture.len();
        let take = chunk.len().min(remaining);
        capture.push_str(&String::from_utf8_lossy(&chunk[..take]));
    }
    line_buf.extend_from_slice(chunk);
    while let Some(pos) = line_buf.iter().position(|b| *b == b'\n') {
        let mut line: Vec<u8> = line_buf.drain(..=pos).collect();
        line.pop(); // \n
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let s = String::from_utf8_lossy(&line).into_owned();
        on_line(if is_stdout {
            StreamLine::Stdout(s)
        } else {
            StreamLine::Stderr(s)
        });
    }
}

fn flush_buf<F>(
    line_buf: &mut Vec<u8>,
    _capture: &mut String,
    _max_capture: usize,
    on_line: &mut F,
    is_stdout: bool,
) where
    F: FnMut(StreamLine),
{
    if line_buf.is_empty() {
        return;
    }
    let mut line = std::mem::take(line_buf);
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    let s = String::from_utf8_lossy(&line).into_owned();
    on_line(if is_stdout {
        StreamLine::Stdout(s)
    } else {
        StreamLine::Stderr(s)
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_splitting_basic() {
        let mut capture = String::new();
        let mut buf = Vec::new();
        let mut lines: Vec<StreamLine> = Vec::new();
        let mut sink = |l: StreamLine| lines.push(l);

        push_lines(
            b"hello\nworld\n",
            &mut buf,
            &mut capture,
            1024,
            &mut sink,
            true,
        );
        assert_eq!(lines.len(), 2);
        assert!(matches!(&lines[0], StreamLine::Stdout(s) if s == "hello"));
        assert!(matches!(&lines[1], StreamLine::Stdout(s) if s == "world"));
        assert_eq!(capture, "hello\nworld\n");
    }

    #[test]
    fn line_splitting_partial() {
        let mut capture = String::new();
        let mut buf = Vec::new();
        let lines = std::cell::RefCell::new(Vec::<StreamLine>::new());
        let mut sink = |l: StreamLine| lines.borrow_mut().push(l);

        push_lines(b"par", &mut buf, &mut capture, 1024, &mut sink, true);
        assert_eq!(lines.borrow().len(), 0);
        push_lines(b"tial\n", &mut buf, &mut capture, 1024, &mut sink, true);
        assert_eq!(lines.borrow().len(), 1);
        let inner = lines.borrow();
        assert!(matches!(&inner[0], StreamLine::Stdout(s) if s == "partial"));
    }

    #[test]
    fn capture_capped() {
        let mut capture = String::new();
        let mut buf = Vec::new();
        let mut sink = |_: StreamLine| {};
        let big = vec![b'a'; 1000];
        push_lines(&big, &mut buf, &mut capture, 100, &mut sink, true);
        assert_eq!(capture.len(), 100);
    }

    #[test]
    fn crlf_stripped() {
        let mut capture = String::new();
        let mut buf = Vec::new();
        let mut lines: Vec<StreamLine> = Vec::new();
        let mut sink = |l: StreamLine| lines.push(l);
        push_lines(b"abc\r\n", &mut buf, &mut capture, 1024, &mut sink, true);
        assert!(matches!(&lines[0], StreamLine::Stdout(s) if s == "abc"));
    }
}
