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

    let mut ws = crate::wsterm::connect(&target, config.verify_tls).await?;

    // Put the local terminal in raw mode + alternate screen so the
    // remote shell controls every keystroke. The global panic hook
    // (flight recorder) already restores raw mode on crash; we also do an
    // explicit cleanup at function end.
    use anyhow::Context;
    use crossterm::{execute, terminal};
    use std::io::{stdout, Write};

    terminal::enable_raw_mode().context("enable raw mode")?;
    execute!(
        stdout(),
        terminal::EnterAlternateScreen,
        crossterm::cursor::Hide,
    )
    .context("enter alt screen")?;

    let _ = write!(
        stdout(),
        "\x1b[2J\x1b[H[serial console: vmid {vmid} on {node}]  Ctrl+] then 'q' to exit\r\n"
    );
    let _ = stdout().flush();

    // Initial size sync.
    if let Ok((cols, rows)) = terminal::size() {
        let _ = crate::wsterm::send_resize(&mut ws, cols, rows).await;
    }

    let exit_code = serial_loop(&mut ws).await;

    // Cleanup — best-effort. The panic hook is the safety net for the
    // unhappy path.
    let _ = execute!(
        stdout(),
        terminal::LeaveAlternateScreen,
        crossterm::cursor::Show,
    );
    let _ = terminal::disable_raw_mode();

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
    let ssh_cfg = config.ssh.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "no [ssh] block in config.toml — run `proxxx init --interactive`\n\
             and answer 'y' at the SSH layer step, OR add a minimal block:\n\
             \n\
             [ssh]\n\
             user = \"root\"\n\
             key_path = \"~/.ssh/id_ed25519\"\n\
             \n\
             then add a per-guest target as below."
        )
    })?;
    // 1. Explicit config wins. The operator may have set host:
    // "internal-name.lab" via DNS or pinned a non-default user/port —
    // auto-discovery must not override that.
    let (target, source) = if let Some(t) = ssh_cfg.resolve_guest(vmid) {
        (t, "config.toml")
    } else {
        // 2. Try auto-discovery. The error path collects WHY discovery
        // failed (no agent, link-local only, etc.) so the fallback
        // message is actionable rather than just "not found".
        match qga_resolve_guest(client, ssh_cfg, vmid).await {
            Ok(t) => (t, "QGA / lxc-interfaces auto-discovery"),
            Err(discovery_err) => {
                // 3. Both paths failed — surface paste-able TOML +
                // the discovery diagnostic so the operator knows
                // whether the agent is missing, the IP is link-local
                // only, or PVE rejected the lookup.
                anyhow::bail!(
                    "no [ssh.guests.\"{vmid}\"] entry in config.toml AND auto-\n\
                     discovery failed: {discovery_err}\n\
                     \n\
                     Add an explicit target:\n\
                     \n\
                     [ssh.guests.\"{vmid}\"]\n\
                     host = \"<guest-ip-or-hostname>\"   # e.g. 192.168.1.42\n\
                     # user = \"root\"                    # optional, falls back to [ssh].user\n\
                     # port = 22                          # optional, default 22\n\
                     # key_path = \"~/.ssh/...\"           # optional, falls back to [ssh].key_path\n\
                     \n\
                     You can confirm the guest's IP from PVE with:\n\
                     proxxx --format json ls guests | jq '.[] | select(.vmid == {vmid})'\n\
                     \n\
                     For QEMU guests with the agent installed but not running:\n\
                     proxxx qga {vmid} net   # exercises the same path"
                )
            }
        }
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
    eprintln!(
        "\x1b[2m[ssh] resolved {}@{}:{} (source: {source})\x1b[0m",
        target.user, target.host, target.port
    );

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

    let (node, gtype) = find_guest(client, vmid).await?;

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
                     (interfaces query returned only empty / loopback / link-local entries)"
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
async fn serial_loop<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>) -> i32
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
                        // Encode + forward.
                        if let Some(bytes) = crate::ssh::pty::encode_key(&key) {
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
                            let _ = stdout().write_all(bytes);
                            let _ = stdout().flush();
                        }
                    }
                    Ok(Message::Text(t)) => {
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
    use crate::api::types::GuestType;
    use crate::api::ProxmoxGateway;

    let (node_name, gt) = if let Some(n) = node {
        // Caller knows the node — but we still need guest_type to
        // route /qemu/ vs /lxc/. One get_guests call is the
        // cheapest way to determine it (filtering one node).
        let guests = client.get_guests(&n).await?;
        let g = guests
            .iter()
            .find(|g| g.vmid == vmid)
            .ok_or_else(|| anyhow::anyhow!("vmid {vmid} not on node {n}"))?;
        (n, g.guest_type)
    } else {
        let nodes = client.get_nodes().await?;
        let mut found: Option<(String, GuestType)> = None;
        for n in &nodes {
            if let Ok(guests) = client.get_guests(&n.node).await {
                if let Some(g) = guests.iter().find(|g| g.vmid == vmid) {
                    found = Some((n.node.clone(), g.guest_type));
                    break;
                }
            }
        }
        found.ok_or_else(|| {
            anyhow::anyhow!("vmid {vmid} not found on any node — pass --node X to skip discovery")
        })?
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
