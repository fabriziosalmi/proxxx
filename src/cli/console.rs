//! Guest console handoffs — VNC ticket, noVNC deep-link, SPICE `.vv`
//! launcher, serial console (WSS termproxy), SSH (system `ssh`
//! subprocess with QGA / lxc-interfaces auto-discovery).

use anyhow::Result;
use clap::ValueEnum;
use serde_json::Value;
use std::sync::Arc;

use crate::cli::common::find_guest;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum SerialKind {
    Qemu,
    Lxc,
}

impl From<SerialKind> for crate::api::types::GuestType {
    fn from(s: SerialKind) -> Self {
        match s {
            SerialKind::Qemu => Self::Qemu,
            SerialKind::Lxc => Self::Lxc,
        }
    }
}

/// Feature #1c — SPICE handoff CLI. Issues spiceproxy ticket, writes
/// `.vv` `ConfigFile`, launches remote-viewer (or system default).
pub async fn execute_spice(
    client: &Arc<crate::api::PxClient>,
    vmid: u32,
    node: &str,
    write_vv: Option<std::path::PathBuf>,
    no_launch: bool,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    let cfg = client.get_spiceproxy(node, vmid).await?;
    // audit: when the user passes `--write-vv <path>` we
    // honour it (they own the path). Without that flag we delegate to
    // the TOCTOU-safe `write_vv_file` which uses tempfile + O_EXCL +
    // 0600 atomically.
    let path = if let Some(p) = write_vv {
        crate::handoff::write_vv_at(&p, &cfg)?;
        p
    } else {
        crate::handoff::write_vv_file(vmid, &cfg)?
    };

    let mut launcher_used: Option<&'static str> = None;
    if !no_launch {
        match crate::handoff::open_spice_vv(&path) {
            Ok(name) => launcher_used = Some(name),
            Err(e) => {
                tracing::warn!("could not auto-launch SPICE viewer: {e:#}");
            }
        }
    }

    Ok((
        serde_json::json!({
            "vmid": vmid,
            "node": node,
            "vv_file": path.to_string_lossy(),
            "host": cfg.host(),
            "launcher": launcher_used,
            "launched": launcher_used.is_some(),
        }),
        0,
    ))
}

/// Feature #1c — noVNC handoff CLI. Builds the deep-link URL and opens
/// it via the system default handler. Authentication is left to the
/// browser's existing `PVEAuthCookie` session.
pub async fn execute_novnc(
    client: &Arc<crate::api::PxClient>,
    config: &crate::config::ProfileConfig,
    vmid: u32,
    node: &str,
    kind_override: Option<SerialKind>,
    no_launch: bool,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    let guest_type = if let Some(k) = kind_override {
        k.into()
    } else {
        let guests = client.get_guests(node).await?;
        let g = guests
            .iter()
            .find(|g| g.vmid == vmid)
            .ok_or_else(|| anyhow::anyhow!("guest {vmid} not on node {node}"))?;
        g.guest_type
    };
    let url = crate::handoff::build_novnc_url(&config.url, node, vmid, guest_type);

    let mut launched = false;
    if !no_launch {
        if let Err(e) = crate::handoff::open_with_default(&url) {
            tracing::warn!("could not auto-launch browser: {e:#}");
        } else {
            launched = true;
        }
    }

    Ok((
        serde_json::json!({
            "vmid": vmid,
            "node": node,
            "type": format!("{guest_type:?}").to_lowercase(),
            "url": url,
            "launched": launched,
            "note": "user must be logged into the Proxmox web UI for the deep-link to work without re-auth"
        }),
        0,
    ))
}

/// Feature #1b — serial console CLI. Issues a termproxy ticket via REST,
/// connects WSS, puts the terminal in raw mode, copies bytes both ways
/// until Ctrl+] then `q`.
///
/// Honest limitations:
/// - Linux/macOS only (crossterm raw mode + signal handling assumes UNIX).
/// - No scrollback (raw passthrough — use `tmux` if you need it).
/// - Exit chord is hardcoded `Ctrl+] q` (telnet-style).
pub async fn execute_serial(
    client: &Arc<crate::api::PxClient>,
    config: &crate::config::ProfileConfig,
    vmid: u32,
    node: &str,
    kind_override: Option<SerialKind>,
    record_path: Option<std::path::PathBuf>,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    // Auto-detect guest type from cluster state if not given.
    let guest_type = if let Some(k) = kind_override {
        k.into()
    } else {
        let guests = client.get_guests(node).await?;
        let g = guests
            .iter()
            .find(|g| g.vmid == vmid)
            .ok_or_else(|| anyhow::anyhow!("guest {vmid} not on node {node}"))?;
        g.guest_type
    };

    // Issue the termproxy ticket — short-lived, must connect immediately.
    let ticket = client.get_termproxy(node, vmid, guest_type).await?;
    let target = crate::wsterm::build_ws_target(
        &config.url,
        node,
        vmid,
        guest_type,
        ticket.port,
        &ticket.ticket,
        &ticket.user,
    );

    // Refresh auth (if needed) BEFORE the WS upgrade — a PAM ticket
    // that's about to expire would 401 the handshake otherwise. Token
    // auth is a no-op refresh.
    let headers = client.auth_headers().await?;
    let mut ws = crate::wsterm::connect(
        &target,
        config.verify_tls,
        client.pinned_verifier(),
        &headers,
    )
    .await?;

    // Put the local terminal in raw mode + alternate screen so the
    // remote shell controls every keystroke. The global panic hook
    // (flight recorder) already restores raw mode on crash; we also do an
    // explicit cleanup at function end. Hold the terminal log gate (`#333`)
    // so `stderr` tracing output is suppressed while the alternate screen is
    // active.
    use anyhow::Context;
    use crossterm::{execute, terminal};
    use std::io::{stdout, Write};

    let term_gate = crate::util::term_gate::acquire();
    terminal::enable_raw_mode().context("enable raw mode")?;
    if let Err(e) = execute!(
        stdout(),
        terminal::EnterAlternateScreen,
        crossterm::cursor::Hide,
    ) {
        let _ = terminal::disable_raw_mode();
        return Err(e).context("enter alt screen");
    }

    let _ = write!(
        stdout(),
        "\x1b[2J\x1b[H[serial console: vmid {vmid} on {node}]  Ctrl+] then 'q' to exit\r\n"
    );
    let _ = stdout().flush();

    // Initial size sync.
    let (cols, rows) = terminal::size().unwrap_or((80, 24));
    let _ = crate::wsterm::send_resize(&mut ws, cols, rows).await;

    // Open the cast recorder upfront so failures are visible before
    // the session starts (rather than half-way through). A failed
    // open prints the error + continues without recording — the
    // session itself is the important thing.
    let mut recorder = if let Some(p) = &record_path {
        match crate::console_record::CastWriter::create(
            p,
            cols,
            rows,
            &format!("proxxx serial vmid={vmid} node={node}"),
        ) {
            Ok(w) => {
                eprintln!("recording → {}", p.display());
                Some(w)
            }
            Err(e) => {
                eprintln!(
                    "warning: could not open recording at {}: {e:#}",
                    p.display()
                );
                None
            }
        }
    } else {
        None
    };

    let exit_code = serial_loop(&mut ws, recorder.as_mut()).await;
    // Final flush before we drop — guarantees the last events made
    // it to disk even if the process is killed before drop fires.
    if let Some(r) = recorder.as_mut() {
        r.flush();
    }

    // Cleanup — best-effort. The panic hook is the safety net for the
    // unhappy path.
    let _ = execute!(
        stdout(),
        terminal::LeaveAlternateScreen,
        crossterm::cursor::Show,
    );
    let _ = terminal::disable_raw_mode();
    drop(term_gate);

    Ok((
        serde_json::json!({
            "vmid": vmid,
            "node": node,
            "type": format!("{guest_type:?}").to_lowercase(),
            "user": ticket.user,
            "exit_code": exit_code,
        }),
        exit_code,
    ))
}

/// `proxxx ssh <vmid>` — interactive SSH session into a guest VM/CT.
///
/// Why exec the system `ssh` rather than russh: the operator's
/// existing keys, `known_hosts`, ssh-agent, and SSH config (Host
/// stanzas, `ProxyJump`, `ControlMaster`) all apply transparently.
/// Re-implementing those features in russh would be incomplete and
/// invisible to muscle memory. The TUI's per-pane PTY uses russh
/// because it embeds the session in a TUI widget; here the operator
/// owns the terminal entirely and `ssh` is the right shape.
///
/// Resolution order:
///   1. `[ssh.guests."<vmid>"]` in config.toml — explicit override
///   2. Auto-discovery via QGA (QEMU) or `/lxc/N/interfaces` (LXC)
///      — uses [ssh].user / [ssh].`key_path` as defaults.
///   3. Friendly error with paste-able TOML if both fail.
pub async fn execute_ssh(
    client: &Arc<crate::api::PxClient>,
    config: &crate::config::ProfileConfig,
    vmid: u32,
    cmd: Option<&str>,
) -> Result<(Value, i32)> {
    let (target, source) = match resolve_guest_target(client, config, vmid).await {
        Ok(found) => found,
        Err(e) => anyhow::bail!(
            "{e:#}\n\
             \n\
             Find the guest's address with:\n\
             proxxx --format json ls guests | jq '.[] | select(.vmid == {vmid})'\n\
             For a QEMU guest whose agent is installed but not running:\n\
             proxxx qga {vmid} net   # exercises the same path"
        ),
    };
    // Last-line-of-defense validation BEFORE we spawn ssh. The config
    // and QGA paths above can each yield a target, but a tampered TOML
    // or a hostile QGA reply could still smuggle a leading `-` or an
    // embedded `@`. Refuse here with a paste-ready diagnostic instead
    // of relying solely on the `--` separator below (CWE-88).
    if let Err(why) = crate::config::validate_ssh_destination(&target.user, &target.host) {
        anyhow::bail!(
            "refusing to ssh: {why}\n\
             source: {source}\n\
             target: user={:?} host={:?}\n\
             Edit [ssh] / [ssh.guests.\"{vmid}\"] in config.toml to fix.",
            target.user,
            target.host,
        );
    }
    // Dim on a terminal only: a pipe, a file or a CI log gets plain text.
    crate::util::color::Line::new()
        .paint(
            format!(
                "[ssh] resolved {}@{}:{} (source: {source})",
                target.user, target.host, target.port
            ),
            Some(crate::util::color::Paint::Dim),
        )
        .eprint();

    // Spawn the system `ssh`. Sharing stdin/stdout/stderr with the
    // parent gives a true terminal handoff — no extra PTY layer, no
    // double key forwarding. The child inherits TERM, LANG, etc.
    //
    // The `--` separator before `user@host` is defense-in-depth against
    // argv injection: a misconfigured/poisoned `host` starting with `-`
    // (e.g. `-oProxyCommand=…`) would otherwise be parsed by ssh as a
    // flag. POSIX `--` ends option processing.
    let mut cmd_builder = std::process::Command::new("ssh");
    cmd_builder
        .arg("-i")
        .arg(&target.key_path)
        .arg("-p")
        .arg(target.port.to_string())
        .arg("--")
        .arg(format!("{}@{}", target.user, target.host));
    if let Some(c) = cmd {
        // The command is passed as a single argv element to `ssh`, which forwards
        // it to the remote login shell. NUL bytes and newlines cannot appear in a
        // legitimate command and would corrupt the remote shell's argument parsing.
        if c.contains('\0') || c.contains('\n') || c.contains('\r') {
            anyhow::bail!("--cmd contains a NUL byte or newline — refusing to forward");
        }
        cmd_builder.arg(c);
    }
    // stdio inherits by default for std::process::Command. Status
    // returns when the child exits — its exit code is what the
    // operator sees from `proxxx ssh ...`.
    let status = cmd_builder.status().map_err(|e| {
        anyhow::anyhow!(
            "spawning ssh failed: {e}\n\
             Verify `ssh` is on PATH (it usually is on macOS / Linux)."
        )
    })?;
    let exit_code = status.code().unwrap_or(1);

    Ok((
        serde_json::json!({
            "vmid": vmid,
            "host": target.host,
            "user": target.user,
            "port": target.port,
            "exit_code": exit_code,
        }),
        exit_code,
    ))
}

/// The SSH target of a guest, resolved the same way by `proxxx ssh` and
/// by the TUI (#545):
///   1. `[ssh.guests."<vmid>"]` of the profile, which always wins;
///   2. auto-discovery: the QEMU guest agent for a VM,
///      `/lxc/{vmid}/interfaces` for a container, with the profile's
///      `[ssh]` user and key.
///
/// The error names the profile's own TOML header and why discovery
/// failed (stopped guest, agent off, no routable address). The second
/// element of the result says which path found the target.
pub async fn resolve_guest_target(
    client: &Arc<crate::api::PxClient>,
    config: &crate::config::ProfileConfig,
    vmid: u32,
) -> Result<(crate::config::ResolvedGuestSsh, &'static str)> {
    let profile = config.profile_name.as_deref();
    let header = crate::config::ssh_guest_table_header(profile, vmid);
    let ssh_cfg = config.ssh.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "no SSH target for guest {vmid}: the profile has no [{ssh}] table. Add one \
             (`proxxx init --interactive` asks for it), for example:\n\
             [{ssh}]\n\
             user = \"root\"\n\
             key_path = \"~/.ssh/id_ed25519\"",
            ssh = crate::config::ssh_table_path(profile)
        )
    })?;
    if let Some(target) = ssh_cfg.resolve_guest(vmid) {
        return Ok((target, "config.toml"));
    }
    match qga_resolve_guest(client, ssh_cfg, vmid).await {
        Ok(target) => Ok((target, "QGA / lxc-interfaces auto-discovery")),
        Err(e) => anyhow::bail!(
            "no SSH target for guest {vmid}: {e:#}. To set one by hand, add to config.toml:\n\
             {header}\n\
             host = \"<guest-ip-or-hostname>\""
        ),
    }
}

/// Resolve a guest's SSH target via auto-discovery — QGA for QEMU,
/// `/lxc/{vmid}/interfaces` for LXC. Used as a fallback by
/// `execute_ssh` when no explicit `[ssh.guests."<vmid>"]` block is
/// present in config.toml.
///
/// Selection: first IPv4 address that is NOT loopback (127.0.0.0/8)
/// AND NOT link-local (169.254.0.0/16). Picks IPv6 only if no IPv4
/// candidate exists — most operators want the v4 by default.
///
/// Diagnostic-rich error: tells the operator WHY discovery failed
/// (no node, agent off, only loopback) so the fallback message in
/// `execute_ssh` doesn't leave them guessing whether the agent
/// needs to be started or the IP just looks weird.
async fn qga_resolve_guest(
    client: &Arc<crate::api::PxClient>,
    ssh_cfg: &crate::config::SshConfig,
    vmid: u32,
) -> Result<crate::config::ResolvedGuestSsh> {
    use crate::api::types::GuestType;
    use crate::api::ProxmoxGateway;

    let guest = crate::cli::common::find_guest_full(client, vmid).await?;
    if guest.status != crate::api::types::GuestStatus::Running {
        anyhow::bail!(
            "guest {vmid} is {} on node {}, and discovery reads the address of a running guest",
            format!("{:?}", guest.status).to_lowercase(),
            guest.node
        );
    }
    let (node, gtype) = (guest.node, guest.guest_type);

    let host = match gtype {
        GuestType::Qemu => {
            let interfaces = client
                .qemu_agent_network_get_interfaces(&node, vmid)
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "QEMU guest-agent query failed (agent off or not installed?): {e:#}"
                    )
                })?;
            pick_first_routable_ipv4_qemu(&interfaces).ok_or_else(|| {
                anyhow::anyhow!(
                    "QGA returned no routable IPv4 for vmid {vmid} \
                     (only loopback / link-local / IPv6 found — guest may be on \
                     a private bridge with no usable address)"
                )
            })?
        }
        GuestType::Lxc => {
            let interfaces = client
                .list_lxc_interfaces(&node, vmid)
                .await
                .map_err(|e| anyhow::anyhow!("LXC interface query failed: {e:#}"))?;
            pick_first_routable_ipv4_lxc(&interfaces).ok_or_else(|| {
                anyhow::anyhow!(
                    "LXC vmid {vmid} has no routable IPv4 \
                     (interfaces query returned only empty / loopback / link-local entries; \
                     a stopped container reports no interfaces)"
                )
            })?
        }
    };

    // Use [ssh] defaults — operator already accepted these in the
    // wizard / their config. This is the same fallback the explicit-
    // config path uses for missing per-guest user/key_path.
    let key_path = ssh_cfg.key_path_resolved().ok_or_else(|| {
        anyhow::anyhow!(
            "[ssh].key_path is not set in config.toml — auto-discovery found \
             host {host} for vmid {vmid} but cannot pick a private key"
        )
    })?;
    Ok(crate::config::ResolvedGuestSsh {
        host,
        port: 22,
        user: ssh_cfg.user.clone(),
        key_path,
    })
}

/// Pick the first routable IPv4 from a QGA interface list. Skips
/// loopback (127.0.0.0/8) and link-local (169.254.0.0/16); pure
/// function so we can pin invariants in unit tests without needing
/// a live cluster.
#[must_use]
pub fn pick_first_routable_ipv4_qemu(
    interfaces: &[crate::api::types::GuestAgentNetworkInterface],
) -> Option<String> {
    for iface in interfaces {
        for ip in &iface.ip_addresses {
            if ip.ip_address_type != "ipv4" {
                continue;
            }
            if is_routable_ipv4(&ip.ip_address) {
                return Some(ip.ip_address.clone());
            }
        }
    }
    None
}

/// Same as `pick_first_routable_ipv4_qemu` but for the LXC `inet`
/// shape (e.g. `"10.0.0.42/24"`) — strip the CIDR before predicate.
#[must_use]
pub fn pick_first_routable_ipv4_lxc(
    interfaces: &[crate::api::types::LxcInterface],
) -> Option<String> {
    for iface in interfaces {
        if iface.inet.is_empty() {
            continue;
        }
        let ip = iface
            .inet
            .split_once('/')
            .map_or(iface.inet.as_str(), |(addr, _cidr)| addr);
        if is_routable_ipv4(ip) {
            return Some(ip.to_string());
        }
    }
    None
}

/// True for IPv4 strings that aren't loopback or link-local. Pure;
/// rejects malformed input by returning false (caller filters with
/// the predicate, not asserts).
fn is_routable_ipv4(s: &str) -> bool {
    let octets: Vec<u8> = s.split('.').filter_map(|p| p.parse::<u8>().ok()).collect();
    if octets.len() != 4 {
        return false;
    }
    if octets[0] == 127 {
        return false; // loopback 127/8
    }
    if octets[0] == 169 && octets[1] == 254 {
        return false; // link-local 169.254/16
    }
    if octets[0] == 0 {
        return false; // 0.0.0.0/8 — never a destination
    }
    true
}

/// Inner loop: keystrokes → WS, WS frames → stdout. Returns exit code.
async fn serial_loop<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    mut recorder: Option<&mut crate::console_record::CastWriter>,
) -> i32
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use crossterm::event::{Event, EventStream, KeyCode, KeyModifiers};
    use futures_util::{SinkExt, StreamExt};
    use std::io::{stdout, Write};
    use tokio_tungstenite::tungstenite::protocol::Message;

    let mut events = EventStream::new();
    // State for the Ctrl+] q exit chord.
    let mut prefix_armed = false;

    loop {
        tokio::select! {
            // Local terminal events.
            evt = events.next() => {
                let Some(Ok(evt)) = evt else { break; };
                match evt {
                    Event::Key(key) => {
                        // Exit chord: Ctrl+] then 'q'.
                        if !prefix_armed
                            && key.modifiers.contains(KeyModifiers::CONTROL)
                            && matches!(key.code, KeyCode::Char(']'))
                        {
                            prefix_armed = true;
                            continue;
                        }
                        if prefix_armed {
                            prefix_armed = false;
                            if matches!(key.code, KeyCode::Char('q')) {
                                let _ = ws.send(Message::Close(None)).await;
                                return 0;
                            }
                            // Not the exit chord — forward Ctrl+] then this key.
                            let _ = crate::wsterm::send_input(ws, &[0x1D]).await;
                        }
                        // Encode + forward + record (if active).
                        if let Some(bytes) = crate::ssh::pty::encode_key(&key) {
                            if let Some(r) = recorder.as_deref_mut() {
                                r.record_input(&bytes);
                            }
                            if crate::wsterm::send_input(ws, &bytes).await.is_err() {
                                return 1;
                            }
                        }
                    }
                    Event::Resize(cols, rows) => {
                        let _ = crate::wsterm::send_resize(ws, cols, rows).await;
                    }
                    _ => {}
                }
            }
            // Remote bytes.
            msg = ws.next() => {
                let Some(msg) = msg else { break; };
                match msg {
                    Ok(Message::Binary(payload)) => {
                        if let Some(bytes) = crate::wsterm::decode_data_frame(&payload) {
                            if let Some(r) = recorder.as_deref_mut() {
                                r.record_output(bytes);
                            }
                            let _ = stdout().write_all(bytes);
                            let _ = stdout().flush();
                        }
                    }
                    Ok(Message::Text(t)) => {
                        if let Some(r) = recorder.as_deref_mut() {
                            r.record_output(t.as_bytes());
                        }
                        let _ = stdout().write_all(t.as_bytes());
                        let _ = stdout().flush();
                    }
                    Ok(Message::Close(_)) => return 0,
                    Ok(_) => {}
                    Err(_) => return 1,
                }
            }
        }
    }
    0
}

/// Hill 2a/2b — guest VNC handoff. Mints a one-shot vncproxy ticket
/// and emits it as JSON. Auto-discovers the owning node + `guest_type`
/// when caller omits `--node`.
pub async fn execute_vnc(
    client: &Arc<crate::api::PxClient>,
    vmid: u32,
    node: Option<String>,
    ws_url: bool,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;

    let (node_name, gt) = if let Some(n) = node {
        // Caller knows the node — but we still need guest_type to
        // route /qemu/ vs /lxc/. One get_guests call is the
        // cheapest way to determine it (filtering one node).
        let guests = client.get_guests(&n).await?;
        let g = guests.iter().find(|g| g.vmid == vmid).ok_or_else(|| {
            crate::api::ApiError::NotFound(format!("vmid {vmid} not on node {n}"))
        })?;
        (n, g.guest_type)
    } else {
        find_guest(client, vmid).await?
    };

    let ticket = client.get_guest_vncproxy(&node_name, vmid, gt).await?;
    let mut out = serde_json::to_value(&ticket)?;
    if ws_url {
        let url = client
            .build_guest_vncwebsocket_url(&node_name, vmid, gt, &ticket)
            .await?;
        if let Some(obj) = out.as_object_mut() {
            obj.insert("ws_url".into(), serde_json::Value::String(url));
        }
    }
    Ok((out, 0))
}

#[cfg(test)]
mod ssh_discovery_tests {
    use super::*;
    use crate::api::types::{GuestAgentIpAddress, GuestAgentNetworkInterface, LxcInterface};

    fn ipv4(addr: &str) -> GuestAgentIpAddress {
        GuestAgentIpAddress {
            ip_address_type: "ipv4".into(),
            ip_address: addr.into(),
            prefix: 24,
        }
    }
    fn ipv6(addr: &str) -> GuestAgentIpAddress {
        GuestAgentIpAddress {
            ip_address_type: "ipv6".into(),
            ip_address: addr.into(),
            prefix: 64,
        }
    }
    fn iface(name: &str, ips: Vec<GuestAgentIpAddress>) -> GuestAgentNetworkInterface {
        GuestAgentNetworkInterface {
            name: name.into(),
            hardware_address: "00:00:00:00:00:00".into(),
            ip_addresses: ips,
        }
    }

    #[test]
    fn qga_picks_first_routable_ipv4_skipping_loopback() {
        let ifaces = vec![
            iface("lo", vec![ipv4("127.0.0.1"), ipv6("::1")]),
            iface(
                "eth0",
                vec![ipv4("169.254.99.1"), ipv4("192.168.1.42"), ipv6("fe80::1")],
            ),
        ];
        assert_eq!(
            pick_first_routable_ipv4_qemu(&ifaces),
            Some("192.168.1.42".to_string())
        );
    }

    #[test]
    fn qga_returns_none_when_only_loopback_and_link_local() {
        // Pre-fix the wizard would have happily picked 127.0.0.1 and
        // tried to ssh into it — auto-discovery must reject and fall
        // back to the explicit-config error message.
        let ifaces = vec![iface("lo", vec![ipv4("127.0.0.1"), ipv4("169.254.99.1")])];
        assert!(pick_first_routable_ipv4_qemu(&ifaces).is_none());
    }

    #[test]
    fn qga_skips_ipv6_only_entries() {
        let ifaces = vec![iface("eth0", vec![ipv6("2001:db8::1")])];
        assert!(pick_first_routable_ipv4_qemu(&ifaces).is_none());
    }

    #[test]
    fn lxc_strips_cidr_and_picks_first_routable() {
        let ifaces = vec![
            LxcInterface {
                name: "lo".into(),
                hwaddr: String::new(),
                inet: "127.0.0.1/8".into(),
                inet6: "::1/128".into(),
            },
            LxcInterface {
                name: "eth0".into(),
                hwaddr: "00:01".into(),
                inet: "10.0.0.42/24".into(),
                inet6: String::new(),
            },
        ];
        assert_eq!(
            pick_first_routable_ipv4_lxc(&ifaces),
            Some("10.0.0.42".to_string())
        );
    }

    #[test]
    fn lxc_skips_empty_inet() {
        // PVE returns "" when the interface has no v4 — must be
        // skipped, not surfaced as a candidate, otherwise the SSH
        // command would be `ssh root@` and fail confusingly.
        let ifaces = vec![LxcInterface {
            name: "eth0".into(),
            hwaddr: "00:01".into(),
            inet: String::new(),
            inet6: "fe80::1/64".into(),
        }];
        assert!(pick_first_routable_ipv4_lxc(&ifaces).is_none());
    }

    #[test]
    fn is_routable_rejects_malformed_strings() {
        assert!(!is_routable_ipv4("not-an-ip"));
        assert!(!is_routable_ipv4("192.168.1"));
        assert!(!is_routable_ipv4(""));
        assert!(!is_routable_ipv4("999.999.999.999"));
        assert!(!is_routable_ipv4("0.0.0.0"));
        assert!(!is_routable_ipv4("127.0.0.1"));
        assert!(!is_routable_ipv4("169.254.0.1"));
        assert!(is_routable_ipv4("10.0.0.1"));
        assert!(is_routable_ipv4("192.168.1.42"));
        assert!(is_routable_ipv4("8.8.8.8"));
    }
}

#[cfg(test)]
mod ssh_target_tests {
    //! #545: the TUI and `proxxx ssh` resolve a guest the same way, and every
    //! failure names the profile's own TOML header and the reason.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::sync::Arc;

    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::resolve_guest_target;
    use crate::api::PxClient;
    use crate::config::{ssh_guest_table_header, ProfileConfig, SshConfig};

    fn ssh(guests_toml: &str) -> SshConfig {
        toml::from_str(&format!(
            "user = \"root\"\nkey_path = \"/nonexistent/id_ed25519\"\n{guests_toml}"
        ))
        .expect("ssh table parses")
    }

    async fn client(
        server: &MockServer,
        ssh: Option<SshConfig>,
        profile: Option<&str>,
    ) -> (Arc<PxClient>, ProfileConfig) {
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
            ssh,
            pbs: None,
            alerts: None,
            mcp_token: None,
            reconcile: None,
            profile_name: profile.map(str::to_string),
        };
        let c = PxClient::new(cfg.clone(), Some("dummy"))
            .await
            .expect("client builds");
        (Arc::new(c), cfg)
    }

    async fn mock(server: &MockServer, p: &str, data: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path(format!("/api2/json{p}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": data })))
            .mount(server)
            .await;
    }

    async fn lab_with_ct200(server: &MockServer, status: &str) {
        mock(
            server,
            "/cluster/resources",
            json!([{"vmid": 200, "type": "lxc", "node": "pve1", "status": status, "name": "ct"}]),
        )
        .await;
        mock(
            server,
            "/nodes/pve1/lxc",
            json!([{"vmid": 200, "status": status, "name": "ct"}]),
        )
        .await;
        mock(server, "/nodes/pve1/qemu", json!([])).await;
        mock(
            server,
            "/nodes/pve1/lxc/200/interfaces",
            json!([
                {"name": "lo", "inet": "127.0.0.1/8", "hwaddr": "00:00:00:00:00:00"},
                {"name": "eth0", "inet": "192.168.0.156/24", "hwaddr": "bc:24:11:4d:f4:ff"}
            ]),
        )
        .await;
    }

    #[tokio::test]
    async fn an_explicit_entry_wins_without_asking_the_cluster() {
        let server = MockServer::start().await;
        let (c, cfg) = client(
            &server,
            Some(ssh("[guests.\"200\"]\nhost = \"10.0.0.9\"\nuser = \"fab\"")),
            Some("lab"),
        )
        .await;
        let (t, source) = resolve_guest_target(&c, &cfg, 200).await.unwrap();
        assert_eq!(
            (t.host.as_str(), t.user.as_str(), t.port),
            ("10.0.0.9", "fab", 22)
        );
        assert_eq!(source, "config.toml");
        assert!(server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty());
    }

    /// The TUI used to refuse this guest: it read only [ssh.guests].
    #[tokio::test]
    async fn a_running_container_without_an_entry_is_discovered() {
        let server = MockServer::start().await;
        lab_with_ct200(&server, "running").await;
        let (c, cfg) = client(&server, Some(ssh("")), Some("lab")).await;
        let (t, source) = resolve_guest_target(&c, &cfg, 200).await.unwrap();
        assert_eq!(
            (t.host.as_str(), t.user.as_str()),
            ("192.168.0.156", "root")
        );
        assert_eq!(source, "QGA / lxc-interfaces auto-discovery");
    }

    #[tokio::test]
    async fn a_stopped_guest_is_named_as_stopped_with_the_profile_header() {
        let server = MockServer::start().await;
        lab_with_ct200(&server, "stopped").await;
        let (c, cfg) = client(&server, Some(ssh("")), Some("lab")).await;
        let err = format!(
            "{:#}",
            resolve_guest_target(&c, &cfg, 200).await.unwrap_err()
        );
        assert!(err.contains("guest 200 is stopped on node pve1"), "{err}");
        assert!(err.contains("[profiles.lab.ssh.guests.\"200\"]"), "{err}");
        assert!(!err.contains("profiles.X"), "{err}");
    }

    #[tokio::test]
    async fn a_profile_without_an_ssh_table_is_told_which_table_to_add() {
        let server = MockServer::start().await;
        let (c, cfg) = client(&server, None, Some("lab")).await;
        let err = format!(
            "{:#}",
            resolve_guest_target(&c, &cfg, 200).await.unwrap_err()
        );
        assert!(err.contains("[profiles.lab.ssh]"), "{err}");
    }

    #[test]
    fn the_header_matches_the_config_shape() {
        assert_eq!(
            ssh_guest_table_header(Some("lab"), 210),
            "[profiles.lab.ssh.guests.\"210\"]"
        );
        assert_eq!(ssh_guest_table_header(None, 210), "[ssh.guests.\"210\"]");
        assert_eq!(
            ssh_guest_table_header(Some("my lab"), 7),
            "[profiles.\"my lab\".ssh.guests.\"7\"]"
        );
        // The header with a quoted name is valid TOML that lands where
        // the profile reads it.
        let doc = format!(
            "{}\nhost = \"10.0.0.7\"\n",
            ssh_guest_table_header(Some("my \"lab\""), 7)
        );
        let v: toml::Value = toml::from_str(&doc).unwrap();
        assert_eq!(
            v["profiles"]["my \"lab\""]["ssh"]["guests"]["7"]["host"].as_str(),
            Some("10.0.0.7")
        );
    }

    #[test]
    fn an_auth_refusal_names_the_key_and_the_fix() {
        let msg = crate::ssh::session::auth_refused_message(
            "root",
            "192.168.0.156",
            22,
            std::path::Path::new("/home/u/.ssh/id_rsa"),
            "SHA256:9eQco89Q2VZfOF",
            &["publickey", "password"],
            false,
        );
        for want in [
            "192.168.0.156:22 refused the key /home/u/.ssh/id_rsa (SHA256:9eQco89Q2VZfOF) for root",
            "root's ~/.ssh/authorized_keys",
            "publickey, password",
        ] {
            assert!(msg.contains(want), "missing {want:?} in {msg}");
        }
        assert!(
            !msg.contains("MethodSet") && !msg.contains("Failure {"),
            "{msg}"
        );
        let partial = crate::ssh::session::auth_refused_message(
            "root",
            "h",
            22,
            std::path::Path::new("/k"),
            "SHA256:x",
            &["password"],
            true,
        );
        assert!(
            partial.contains("accepted the key") && partial.contains("password"),
            "{partial}"
        );
    }
}
