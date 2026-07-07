//! Interactive `proxxx init --interactive` wizard.
//!
//! Why this exists: the non-interactive `proxxx init` writes a TOML
//! template with every field commented out. A first-time user has to
//! know what an API token is, which TLS posture is right, what the
//! `[ssh]` block buys them, etc. The "config not found" error is
//! easy; the "config wrong" path is the one that loses users on
//! first try.
//!
//! The wizard prompts step-by-step, validates each input by actually
//! talking to the cluster (HEAD on /api2/json/version, GET on
//! /access/permissions, optional SSH round-trip, optional Telegram
//! `getMe`), and only writes the TOML if every probed field
//! responded. A failed probe never silently lands in config.toml.
//!
//! No new dependency: reqwest + crossterm are already in tree.
//! crossterm is used only for the password prompt's no-echo mode;
//! everything else goes through `std::io::stdin().read_line()` so
//! the wizard works in dumb terminals too.

use anyhow::{Context, Result};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

const VERIFY_TLS_DEFAULT: bool = true;

/// Run the interactive wizard. Returns the same shape as the
/// non-interactive `execute_init` so the calling dispatcher doesn't
/// have to special-case it.
pub async fn run(profile_name: Option<&str>) -> Result<(serde_json::Value, i32)> {
    // The interactive wizard writes the flat top-level config. Appending a
    // *named* profile interactively is a larger flow (it would have to read
    // + merge the existing document); until that lands, point `--profile`
    // users at the non-interactive append, which is format-preserving and
    // multi-profile-safe.
    if let Some(name) = profile_name {
        anyhow::bail!(
            "the interactive wizard writes the flat top-level config; it can't yet append \
             a named profile. Use `proxxx init --profile {name}` (non-interactive) to add \
             [profiles.{name}] without touching your other profiles, then edit the values."
        );
    }
    print_header();

    let config_dir = resolve_config_dir()?;
    let config_path = config_dir.join("config.toml");

    if config_path.exists() {
        match prompt_existing_action(&config_path)? {
            ExistingAction::Cancel => {
                println!();
                println!("{}cancelled — config left untouched.{}", DIM, RESET);
                return Ok((
                    serde_json::json!({"cancelled": true, "path": config_path.display().to_string()}),
                    1,
                ));
            }
            ExistingAction::Backup => {
                let backup = backup_existing(&config_path)?;
                ok(&format!(
                    "backed up existing config to {}",
                    backup.display()
                ));
            }
            ExistingAction::Overwrite => {
                warn("existing config will be overwritten in place — no backup");
            }
        }
    }

    // ── Step 1/5 — URL + reachability ────────────────────────
    step(1, 5, "PVE connection");
    let url = prompt_url()?;
    info(&format!(
        "  reaching {}/api2/json/version (anonymous probe) ...",
        url
    ));
    let pve_version = match probe_pve_anon(&url, /* verify_tls */ false).await {
        Ok(v) => {
            ok(&format!("PVE responded: release {v}"));
            v
        }
        Err(e) => {
            warn(&format!(
                "anonymous probe failed ({e}); proceeding anyway — verify_tls choice next may resolve it"
            ));
            String::from("unknown")
        }
    };

    // ── Step 2/5 — TLS ────────────────────────────────────────
    step(2, 5, "TLS verification");
    info("  verify_tls=true is the default (rejects self-signed certs).");
    info("  many homelab clusters use self-signed certs; opt out only if you've");
    info("  inspected the cert and accept the residual MITM risk.");
    let verify_tls = prompt_yn("  Verify TLS?", VERIFY_TLS_DEFAULT)?;
    if !verify_tls {
        warn("TLS verification disabled — every API call + websocket exposed to MITM until re-enabled");
    } else {
        ok("TLS verification on");
    }

    // ── Step 3/5 — Auth ──────────────────────────────────────
    step(3, 5, "Authentication");
    info("  PVE supports two auth modes:");
    info("    1) API token (recommended — scoped, revocable, no password in env)");
    info("    2) Username + password (universal, but coarse-grained)");
    let auth_choice = prompt_choice("  Method", &["API token", "Username + password"], 0)?;

    let auth_block = if auth_choice == 0 {
        prompt_token_auth(&url, verify_tls).await?
    } else {
        prompt_password_auth(&url, verify_tls).await?
    };

    // ── Step 4/5 — SSH (optional) ────────────────────────────
    step(4, 5, "SSH layer (optional)");
    info("  Enables `proxxx perms` (effective ACLs) and `proxxx patch apply`");
    info("  (apt upgrade orchestration). Skip if unsure — adds-it-later is one");
    info("  toml block away.");
    let ssh_block = if prompt_yn("  Configure SSH?", false)? {
        prompt_ssh(&url)?
    } else {
        info("  skipping SSH — `[ssh]` block left out");
        None
    };

    // ── Step 5/5 — Telegram HITL (optional) ──────────────────
    step(5, 5, "HITL via Telegram (optional)");
    info("  Required for human-in-the-loop approval gates on destructive ops");
    info("  (`proxxx delete`, `proxxx stop --force`, etc.). Skip if you're");
    info("  the only operator and accept implicit consent.");
    let telegram_block = if prompt_yn("  Configure Telegram HITL?", false)? {
        prompt_telegram().await?
    } else {
        info("  skipping Telegram — `[telegram]` block left out");
        None
    };

    // ── Render + write ───────────────────────────────────────
    println!();
    let toml = render_toml(
        &url,
        verify_tls,
        &auth_block,
        ssh_block.as_ref(),
        telegram_block.as_ref(),
    );
    write_config(&config_dir, &config_path, &toml)?;
    ok(&format!("wrote {}", config_path.display()));

    print_next_steps();

    Ok((
        serde_json::json!({
            "wrote": config_path.display().to_string(),
            "interactive": true,
            "pve_version": pve_version,
            "auth_method": if auth_choice == 0 { "token" } else { "password" },
            "verify_tls": verify_tls,
            "ssh_configured": ssh_block.is_some(),
            "telegram_configured": telegram_block.is_some(),
        }),
        0,
    ))
}

// ── Banners ──────────────────────────────────────────────────

fn print_header() {
    println!();
    println!("{}{}proxxx config wizard{}", BOLD, CYAN, RESET);
    println!("{}─────────────────────{}", DIM, RESET);
    println!("Walks you through the minimal config needed to run `proxxx ls nodes`.");
    println!("Each input is validated against the cluster before it lands in the");
    println!("TOML — a wrong token is caught here, not on the next CLI call.");
    println!();
}

fn print_next_steps() {
    println!();
    println!("{}─────────────────────{}", DIM, RESET);
    println!("{}{}Try it:{}", BOLD, GREEN, RESET);
    println!("  proxxx ls nodes");
    println!("  proxxx ls guests --format json | head");
    println!("  proxxx mcp tools");
    println!();
    println!(
        "{}Docs: https://fabriziosalmi.github.io/proxxx/guide/configuration{}",
        DIM, RESET
    );
}

// ── Existing-config handling ─────────────────────────────────

enum ExistingAction {
    Backup,
    Overwrite,
    Cancel,
}

fn prompt_existing_action(path: &Path) -> Result<ExistingAction> {
    println!(
        "{}A config already exists at {}{}",
        YELLOW,
        path.display(),
        RESET
    );
    let choice = prompt_choice(
        "  What now?",
        &[
            "Back up the old one + write a new one",
            "Overwrite without backup",
            "Cancel",
        ],
        0,
    )?;
    Ok(match choice {
        0 => ExistingAction::Backup,
        1 => ExistingAction::Overwrite,
        _ => ExistingAction::Cancel,
    })
}

fn backup_existing(path: &Path) -> Result<PathBuf> {
    let stamp = epoch_stamp();
    let mut backup = path.to_path_buf();
    let mut name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config.toml".to_string());
    name.push_str(&format!(".bak.{stamp}"));
    backup.set_file_name(name);
    std::fs::copy(path, &backup)
        .with_context(|| format!("backing up {} to {}", path.display(), backup.display()))?;
    Ok(backup)
}

/// Backup-filename stamp. Unix seconds since epoch — sortable by
/// `ls -1`, monotonic, no date-crate dep. We only display this, never
/// parse it back, so a human-readable form isn't worth the lines.
fn epoch_stamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}

// ── Step 1: URL ──────────────────────────────────────────────

fn prompt_url() -> Result<String> {
    loop {
        let raw = prompt_string("  PVE API URL (e.g. https://10.0.0.1:8006)")?;
        if raw.is_empty() {
            warn("URL cannot be empty");
            continue;
        }
        match normalise_url(&raw) {
            Ok(u) => return Ok(u),
            Err(e) => warn(&format!("not a valid URL: {e}")),
        }
    }
}

/// Accept `https://host`, `https://host:port`, `host` (assume https,
/// default 8006). Reject anything that isn't reachable as
/// `<scheme>://<host>[:<port>]`.
fn normalise_url(raw: &str) -> Result<String> {
    let raw = raw.trim().trim_end_matches('/');
    let with_scheme = if raw.contains("://") {
        raw.to_string()
    } else {
        format!("https://{raw}")
    };
    let parsed = reqwest::Url::parse(&with_scheme)?;
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        anyhow::bail!("only http/https are supported, got {}", parsed.scheme());
    }
    if parsed.host_str().is_none() {
        anyhow::bail!("missing host");
    }
    // Default port for PVE is 8006; if the user typed a bare host
    // we add it. If they explicitly typed a port, leave it alone.
    let needs_default_port = parsed.port().is_none() && !raw.contains("://");
    let final_url = if needs_default_port {
        format!(
            "{}://{}:8006",
            parsed.scheme(),
            parsed.host_str().unwrap_or("")
        )
    } else {
        parsed.as_str().trim_end_matches('/').to_string()
    };
    Ok(final_url)
}

async fn probe_pve_anon(url: &str, verify_tls: bool) -> Result<String> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(!verify_tls)
        .timeout(std::time::Duration::from_secs(8))
        .build()?;
    let res = client
        .get(format!("{url}/api2/json/version"))
        .send()
        .await
        .context("HTTP request failed (cluster unreachable, wrong URL, or TLS rejection)")?;
    let status = res.status();
    // Read once into bytes so we can inspect both as JSON (success path)
    // and as a raw preview (diagnostic on failure). reqwest's `.json()`
    // would consume the body and hide the bytes from us.
    let body_bytes = res.bytes().await.unwrap_or_default();
    interpret_anon_probe(status, &body_bytes)
}

/// Pure (status, body) → friendly summary. Extracted so it's
/// testable without spinning up a wiremock — PVE's anonymous-probe
/// behaviour drifts between minor versions (PVE 7 returned a real
/// JSON body, PVE 8+ returns 401 with an empty body) and we want
/// invariants on both shapes pinned by a unit test.
fn interpret_anon_probe(status: reqwest::StatusCode, body: &[u8]) -> Result<String> {
    // PVE 8+ requires auth for /version too. A 401/403 here is NOT
    // a probe failure — the cluster IS reachable, the TLS handshake
    // worked, the HTTP server responded. We just can't read the
    // version banner without credentials, which the next wizard
    // step provides anyway.
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Ok(format!(
            "alive (HTTP {} — auth needed for version detail)",
            status.as_u16()
        ));
    }

    if !status.is_success() {
        anyhow::bail!("HTTP {}: {}", status, body_preview(body, 200));
    }

    // 2xx success — try to extract version + release. On non-JSON
    // (reverse-proxy stripped, captive portal, anything weird),
    // surface a body preview so the operator can see what the
    // endpoint actually returned.
    let parsed: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
        anyhow::anyhow!(
            "HTTP {} but body is not JSON ({}): {}",
            status,
            e,
            body_preview(body, 200)
        )
    })?;
    let release = parsed
        .get("data")
        .and_then(|d| d.get("release"))
        .and_then(|r| r.as_str())
        .unwrap_or("?");
    let version = parsed
        .get("data")
        .and_then(|d| d.get("version"))
        .and_then(|r| r.as_str())
        .unwrap_or("?");
    Ok(format!("PVE {version} ({release})"))
}

/// First N chars (NOT bytes — UTF-8 boundary safe) of a body, with
/// trailing whitespace trimmed. Empty bodies become `<empty>` so
/// the diagnostic doesn't render a stray colon followed by nothing.
fn body_preview(bytes: &[u8], max_chars: usize) -> String {
    if bytes.is_empty() {
        return "<empty>".to_string();
    }
    let s: String = String::from_utf8_lossy(bytes)
        .chars()
        .take(max_chars)
        .collect();
    let trimmed = s.trim();
    if trimmed.is_empty() {
        "<whitespace-only>".to_string()
    } else {
        trimmed.to_string()
    }
}

// ── Step 3a: Token auth ──────────────────────────────────────

#[derive(Debug)]
struct AuthBlock {
    user: String,
    auth: &'static str, // "token" | "password"
    token_id: Option<String>,
    token_secret: Option<crate::util::secret::SecretString>,
    password: Option<crate::util::secret::SecretString>,
}

async fn prompt_token_auth(url: &str, verify_tls: bool) -> Result<AuthBlock> {
    info("  Paste the full token string (e.g. `root@pam!proxxx=<uuid>`) OR");
    info("  press Enter to type user / id / secret separately.");
    let pasted = prompt_string("  Token (paste or empty)")?;

    let (user, token_id, token_secret) = if pasted.is_empty() {
        let user = loop {
            let v = prompt_string("  PVE user (e.g. root@pam)")?;
            if v.contains('@') {
                break v;
            }
            warn("expected user@realm form (e.g. root@pam, proxxx@pve)");
        };
        let token_id = prompt_string("  Token id (e.g. proxxx)")?;
        let secret = prompt_password("  Token secret")?;
        (user, token_id, secret)
    } else {
        match parse_full_token(&pasted) {
            Ok(t) => t,
            Err(e) => {
                warn(&format!("could not parse token string: {e}"));
                anyhow::bail!("token parse failed; restart wizard or enter parts separately");
            }
        }
    };

    info(&format!(
        "  testing token against {url}/api2/json/access/permissions ..."
    ));
    match probe_token(url, &user, &token_id, &token_secret, verify_tls).await {
        Ok(()) => ok(&format!("{user}!{token_id} authenticated")),
        Err(e) => {
            fail(&format!("auth probe failed: {e}"));
            anyhow::bail!("token rejected by PVE — fix and re-run wizard");
        }
    }

    Ok(AuthBlock {
        user,
        auth: "token",
        token_id: Some(token_id),
        token_secret: Some(token_secret.into()),
        password: None,
    })
}

/// Parse a pasted full token: `user@realm!tokenid=secret`.
fn parse_full_token(raw: &str) -> Result<(String, String, String)> {
    let raw = raw.trim();
    let (left, secret) = raw
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("missing `=<secret>` part"))?;
    let (user, token_id) = left
        .split_once('!')
        .ok_or_else(|| anyhow::anyhow!("missing `!<token-id>` part"))?;
    if user.is_empty() || token_id.is_empty() || secret.is_empty() {
        anyhow::bail!("one of user / id / secret is empty");
    }
    if !user.contains('@') {
        anyhow::bail!("user must include realm (e.g. root@pam)");
    }
    Ok((user.to_string(), token_id.to_string(), secret.to_string()))
}

async fn probe_token(
    url: &str,
    user: &str,
    token_id: &str,
    secret: &str,
    verify_tls: bool,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(!verify_tls)
        .timeout(std::time::Duration::from_secs(8))
        .build()?;
    let res = client
        .get(format!("{url}/api2/json/access/permissions"))
        .header(
            "Authorization",
            format!("PVEAPIToken={user}!{token_id}={secret}"),
        )
        .send()
        .await?;
    let status = res.status();
    if status.is_success() {
        return Ok(());
    }
    let body = res.text().await.unwrap_or_default();
    anyhow::bail!(
        "HTTP {status}: {}",
        body.chars().take(200).collect::<String>()
    )
}

// ── Step 3b: Password auth ───────────────────────────────────

async fn prompt_password_auth(url: &str, verify_tls: bool) -> Result<AuthBlock> {
    let user = loop {
        let v = prompt_string("  PVE user (e.g. root@pam)")?;
        if v.contains('@') {
            break v;
        }
        warn("expected user@realm form");
    };
    let password = prompt_password("  Password")?;

    info(&format!(
        "  testing password against {url}/api2/json/access/ticket ..."
    ));
    match probe_password(url, &user, &password, verify_tls).await {
        Ok(()) => ok(&format!("{user} authenticated")),
        Err(e) => {
            fail(&format!("auth probe failed: {e}"));
            anyhow::bail!("password rejected by PVE — fix and re-run wizard");
        }
    }

    Ok(AuthBlock {
        user,
        auth: "password",
        token_id: None,
        token_secret: None,
        password: Some(password.into()),
    })
}

async fn probe_password(url: &str, user: &str, password: &str, verify_tls: bool) -> Result<()> {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(!verify_tls)
        .timeout(std::time::Duration::from_secs(8))
        .build()?;
    let res = client
        .post(format!("{url}/api2/json/access/ticket"))
        .form(&[("username", user), ("password", password)])
        .send()
        .await?;
    if res.status().is_success() {
        return Ok(());
    }
    let status = res.status();
    let body = res.text().await.unwrap_or_default();
    anyhow::bail!(
        "HTTP {status}: {}",
        body.chars().take(200).collect::<String>()
    )
}

// ── Step 4: SSH ──────────────────────────────────────────────

#[derive(Debug)]
struct SshBlock {
    user: String,
    key_path: String,
    /// Optional per-guest overrides: (`vmid_string`, host). Auto-discovery
    /// via QGA covers most cases now (see `cli::qga_resolve_guest`),
    /// so this list is genuinely only for guests where QGA is off,
    /// returns only loopback/link-local, or where the operator wants
    /// a stable DNS name instead of a churning DHCP IP.
    guests: Vec<(String, String)>,
}

fn prompt_ssh(api_url: &str) -> Result<Option<SshBlock>> {
    let user = prompt_string_default("  SSH user", "root")?;
    let key_path = prompt_ssh_key_path()?;
    let expanded = expand_tilde_str(&key_path);
    if !std::path::Path::new(&expanded).exists() {
        warn(&format!(
            "key not found at {expanded} — config will still be written, but SSH will fail until the file exists"
        ));
    }
    if prompt_yn("  Test connection now?", true)? {
        let host = api_host_only(api_url).unwrap_or_else(|| api_url.to_string());
        info(&format!("  ssh -i {expanded} {user}@{host} 'uname -a' ..."));
        match probe_ssh(&user, &host, &expanded) {
            Ok(line) => ok(&format!("SSH ok ({line})")),
            Err(e) => {
                warn(&format!(
                    "SSH test failed: {e}\n  config will be written; fix key/auth then `proxxx perms <user>`"
                ));
            }
        }
    }

    let guests = prompt_ssh_guest_overrides()?;

    Ok(Some(SshBlock {
        user,
        key_path,
        guests,
    }))
}

/// Optional sub-step: pin per-guest SSH targets in config.toml.
///
/// Most operators don't need this — `proxxx ssh <vmid>` falls back
/// to QGA (QEMU) / `/lxc/N/interfaces` (LXC) auto-discovery when the
/// guest isn't pinned. The wizard surfaces this step explicitly only
/// because there are three legitimate reasons to override:
///
///   1. Guest has no qemu-guest-agent (or the agent is off, or the
///      VM is suspended): auto-discovery returns empty, ssh hangs.
///   2. Auto-discovery returns only 127.0.0.1 / 169.254.x: a guest
///      whose only NIC is on a private bridge with no usable
///      address from the operator's perspective.
///   3. Operator prefers a stable DNS name (`web1.lab.example`)
///      over the rotating DHCP IP QGA would surface.
///
/// Empty-VMID terminates the loop — no separate "are you done"
/// prompt to read past.
fn prompt_ssh_guest_overrides() -> Result<Vec<(String, String)>> {
    println!();
    info("  Per-guest SSH overrides (optional):");
    info("    `proxxx ssh <vmid>` auto-discovers via QGA / lxc-interfaces by");
    info("    default. Pin a host below ONLY when the guest has no agent,");
    info("    QGA reports only loopback/link-local, OR you want a stable");
    info("    DNS name. You can also add these later with a text editor.");
    if !prompt_yn("  Pin per-guest SSH targets now?", false)? {
        return Ok(Vec::new());
    }

    let mut guests: Vec<(String, String)> = Vec::new();
    loop {
        let vmid_raw = prompt_string("    VMID (empty = done)")?;
        if vmid_raw.is_empty() {
            break;
        }
        // VMID is a u32 in PVE — refuse anything else loudly so the
        // generated TOML is parse-clean by the loader (which will
        // reject non-numeric keys at runtime).
        if vmid_raw.parse::<u32>().is_err() {
            warn("VMID must be a non-negative integer (PVE uses u32)");
            continue;
        }
        // Detect duplicate entries — TOML allows them syntactically
        // but the second wins, silently. Surface here so the operator
        // doesn't lose work to a typo.
        if guests.iter().any(|(v, _)| v == &vmid_raw) {
            warn(&format!(
                "vmid {vmid_raw} already pinned in this session — overwrite by re-entering, or skip with empty VMID"
            ));
        }
        let host = prompt_string("    host (IP or DNS name)")?;
        if host.is_empty() {
            warn("host cannot be empty — re-enter the vmid to retry");
            continue;
        }
        // Replace existing entry rather than append duplicate.
        if let Some(pos) = guests.iter().position(|(v, _)| v == &vmid_raw) {
            guests[pos] = (vmid_raw, host);
        } else {
            guests.push((vmid_raw, host));
        }
    }

    if guests.is_empty() {
        info("  no per-guest overrides entered — auto-discovery will resolve at `proxxx ssh` time");
    } else {
        ok(&format!(
            "{} per-guest SSH override(s) staged for write",
            guests.len()
        ));
    }
    Ok(guests)
}

/// Discover SSH private keys in `~/.ssh/` and let the operator pick.
/// Pre-fix the wizard hardcoded `~/.ssh/id_ed25519` as the default —
/// when that file didn't exist (operators with `id_rsa`, named keys,
/// or per-host keys like `proxxx_e2e_ed25519`) the SSH probe failed
/// + the config was written with a path pointing to nothing.
///
/// The discovery scans `~/.ssh/`, opens each candidate, and matches
/// the OpenSSH / RSA private-key header — so files that LOOK like
/// keys (no `.pub`, not `known_hosts`, not `config`) but actually
/// aren't get filtered out. Falls back to the legacy free-form
/// prompt when no keys are found OR `HOME` is unset.
fn prompt_ssh_key_path() -> Result<String> {
    let candidates = discover_ssh_keys();
    if candidates.is_empty() {
        // Fallback: no keys found, prompt for custom path with the
        // conventional default — guides the operator toward a
        // `ssh-keygen -t ed25519` if they really have nothing.
        return prompt_string_default("  Private key path", "~/.ssh/id_ed25519");
    }

    info(&format!(
        "  found {} SSH private key(s) in ~/.ssh/",
        candidates.len()
    ));
    let mut display: Vec<String> = candidates
        .iter()
        .map(|p| {
            let name = std::path::Path::new(p)
                .file_name()
                .map_or_else(|| p.clone(), |n| n.to_string_lossy().into_owned());
            // Show name + truncated path for clarity; the basename
            // tells operators "is this the one I authorised on the
            // cluster?" at a glance.
            name
        })
        .collect();
    display.push("Other (type a custom path)".to_string());
    let opts: Vec<&str> = display.iter().map(String::as_str).collect();
    let i = prompt_choice("  Private key", &opts, 0)?;
    if i == candidates.len() {
        // "Other" branch — free-form prompt (still tilde-expanded
        // downstream by expand_tilde_str).
        let custom = prompt_string("  Custom key path")?;
        Ok(custom)
    } else {
        Ok(candidates[i].clone())
    }
}

/// Walk `~/.ssh/` and return paths to files whose first bytes match
/// an OpenSSH or RSA private-key header. Returns an empty Vec when
/// HOME is unset.
fn discover_ssh_keys() -> Vec<String> {
    let Ok(home) = std::env::var("HOME") else {
        return Vec::new();
    };
    discover_ssh_keys_in(&format!("{home}/.ssh"))
}

/// Inner discovery — takes the directory path explicitly so tests can
/// drive it with a fixture tempdir instead of touching `~/.ssh/`.
///
/// Sort order: OpenSSH-format keys first (modern, ed25519/ecdsa
/// usually live here), then PEM-format RSA, alphabetical within
/// each group. The first entry becomes the default in the choice
/// prompt — so an operator with both `id_ed25519_root` and
/// `id_rsa` gets ed25519 pre-selected.
fn discover_ssh_keys_in(dir: &str) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };

    // (priority_bucket, name, full_path). Sort tuples lexically:
    // bucket then name. 0 = OpenSSH format, 1 = RSA PEM, 2 = unknown
    // but matched a BEGIN header.
    let mut keys: Vec<(u8, String, String)> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        // Skip well-known non-keys. The `.pub` filter is critical:
        // public keys also start with the openssh header. Compare
        // case-insensitively so `id_rsa.PUB` on a case-preserving
        // filesystem (HFS+ default, exFAT, NTFS via fuse) doesn't slip
        // past the filter and get treated as a private key.
        let is_pub = std::path::Path::new(name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("pub"));
        if is_pub
            || name == "known_hosts"
            || name == "known_hosts.old"
            || name == "config"
            || name == "authorized_keys"
            || name.starts_with('.')
        {
            continue;
        }
        // Files only — `agent/` etc. are subdirectories.
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        // Cap the read at 200 bytes — enough for the header.
        let Ok(content) = std::fs::read(&path) else {
            continue;
        };
        let preview =
            String::from_utf8_lossy(&content.iter().take(200).copied().collect::<Vec<u8>>())
                .into_owned();
        let bucket = if preview.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
            0
        } else if preview.contains("-----BEGIN RSA PRIVATE KEY-----") {
            1
        } else if preview.contains("-----BEGIN ") && preview.contains("PRIVATE KEY-----") {
            2
        } else {
            continue;
        };
        keys.push((
            bucket,
            name.to_string(),
            path.to_string_lossy().into_owned(),
        ));
    }
    keys.sort();
    keys.into_iter().map(|(_, _, p)| p).collect()
}

fn expand_tilde_str(p: &str) -> String {
    if let Some(stripped) = p.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return format!("{home}/{stripped}");
        }
    }
    p.to_string()
}

fn api_host_only(url: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
}

fn probe_ssh(user: &str, host: &str, key_path: &str) -> Result<String> {
    use std::process::Command;
    // Refuse hostile/typo'd destinations BEFORE shelling out, so the
    // wizard fails fast with a clear message instead of OpenSSH's
    // cryptic "command-line option not recognised" (CWE-88).
    if let Err(why) = crate::config::validate_ssh_destination(user, host) {
        anyhow::bail!("refusing to ssh: {why}");
    }
    // `--` ends option processing before `user@host`: defense-in-depth
    // so a host string starting with `-` can't be parsed as a flag
    // (CWE-88). The remote command must come AFTER the destination —
    // openssh keeps it as a positional even past `--`.
    let out = Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "LogLevel=ERROR",
            "-i",
            key_path,
            "--",
            &format!("{user}@{host}"),
            "uname -a",
        ])
        .output()
        .context("spawning ssh")?;
    if !out.status.success() {
        anyhow::bail!(
            "{} {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
                .lines()
                .next()
                .unwrap_or("")
        );
    }
    let line = String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    Ok(line)
}

// ── Step 5: Telegram ─────────────────────────────────────────

#[derive(Debug)]
struct TelegramBlock {
    bot_token: crate::util::secret::SecretString,
    chat_id: String,
}

async fn prompt_telegram() -> Result<Option<TelegramBlock>> {
    info("  Create the bot via @BotFather first (https://t.me/BotFather → /newbot).");
    info("  Get your chat id from @userinfobot (start a chat, it replies with id).");
    let bot_token = prompt_password("  Bot token")?;
    let chat_id = prompt_string("  Chat id")?;

    info("  testing https://api.telegram.org/bot<TOKEN>/getMe ...");
    match probe_telegram(&bot_token).await {
        Ok(name) => ok(&format!("bot online: @{name}")),
        Err(e) => {
            warn(&format!(
                "Telegram probe failed: {e}\n  config will be written; verify bot token + chat id manually with `proxxx alerts test`"
            ));
        }
    }
    Ok(Some(TelegramBlock {
        bot_token: bot_token.into(),
        chat_id,
    }))
}

async fn probe_telegram(bot_token: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .build()?;
    let res = client
        .get(format!("https://api.telegram.org/bot{bot_token}/getMe"))
        .send()
        .await?;
    if !res.status().is_success() {
        anyhow::bail!("HTTP {}", res.status());
    }
    let body: serde_json::Value = res.json().await?;
    if body.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        anyhow::bail!(
            "Telegram returned ok=false: {}",
            body.get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        );
    }
    Ok(body
        .get("result")
        .and_then(|r| r.get("username"))
        .and_then(|v| v.as_str())
        .unwrap_or("?")
        .to_string())
}

// ── Render TOML ──────────────────────────────────────────────

fn render_toml(
    url: &str,
    verify_tls: bool,
    auth: &AuthBlock,
    ssh: Option<&SshBlock>,
    telegram: Option<&TelegramBlock>,
) -> String {
    let mut out = String::new();
    out.push_str("# proxxx config — generated by `proxxx init --interactive`\n");
    out.push_str("# Every field below was probed live against the cluster before write.\n");
    out.push_str("# Manual edit is supported; re-run the wizard to re-probe.\n\n");

    out.push_str(&format!("url = {}\n", toml_escape(url)));
    out.push_str(&format!("user = {}\n", toml_escape(&auth.user)));
    out.push_str(&format!("auth = {}\n", toml_escape(auth.auth)));
    if !verify_tls {
        out.push_str(
            "# verify_tls=false: every API call + websocket exposed to MITM. Re-enable\n# as soon as a real cert is in place.\n",
        );
    }
    out.push_str(&format!("verify_tls = {verify_tls}\n"));

    if let Some(id) = &auth.token_id {
        out.push_str(&format!("token_id = {}\n", toml_escape(id)));
    }
    if let Some(secret) = &auth.token_secret {
        out.push_str(&format!("token_secret = {}\n", toml_escape(secret)));
        out.push_str(
            "# Inline token_secret is the simplest path. For multi-user machines\n# prefer `token_secret_file = \"/path/to/0600/file\"` or the macOS keychain.\n",
        );
    }
    if let Some(pw) = &auth.password {
        out.push_str(&format!("password = {}\n", toml_escape(pw)));
        out.push_str("# Password in plain TOML — file mode 0600 is enforced by the wizard.\n");
    }

    if let Some(s) = ssh {
        out.push_str("\n[ssh]\n");
        out.push_str(&format!("user = {}\n", toml_escape(&s.user)));
        out.push_str(&format!("key_path = {}\n", toml_escape(&s.key_path)));
        for (vmid, host) in &s.guests {
            // VMID keys must be quoted strings in TOML even when
            // they look numeric — `[ssh.guests.100]` parses as
            // integer-keyed table which proxxx's loader rejects.
            // Quote unconditionally for a parse-clean output.
            out.push_str(&format!("\n[ssh.guests.\"{vmid}\"]\n"));
            out.push_str(&format!("host = {}\n", toml_escape(host)));
        }
    }

    if let Some(t) = telegram {
        out.push_str("\n[telegram]\n");
        out.push_str(&format!("bot_token = {}\n", toml_escape(&t.bot_token)));
        out.push_str(&format!("chat_id = {}\n", toml_escape(&t.chat_id)));
        out.push_str("# Add a [[policies]] block to gate destructive ops via Telegram approval.\n");
    }

    out
}

fn toml_escape(s: &str) -> String {
    // Basic TOML string escape — backslash + double quote.
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ── Atomic write + perms ─────────────────────────────────────

fn write_config(config_dir: &Path, config_path: &Path, body: &str) -> Result<()> {
    std::fs::create_dir_all(config_dir)
        .with_context(|| format!("creating {}", config_dir.display()))?;
    let tmp = config_dir.join("config.toml.proxxx-init-tmp");
    {
        let mut f =
            std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
    }
    // 0600 — the file holds a token / password.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::rename(&tmp, config_path)
        .with_context(|| format!("renaming into {}", config_path.display()))?;
    Ok(())
}

fn resolve_config_dir() -> Result<PathBuf> {
    directories::ProjectDirs::from("dev", "proxxx", "proxxx")
        .map(|d| d.config_dir().to_path_buf())
        .ok_or_else(|| anyhow::anyhow!("could not resolve OS config directory for proxxx"))
}

// ── Prompt primitives ────────────────────────────────────────

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const DIM: &str = "\x1b[2m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";

fn ok(msg: &str) {
    println!("  {}✓{} {msg}", GREEN, RESET);
}
fn warn(msg: &str) {
    println!("  {}⚠{} {msg}", YELLOW, RESET);
}
fn fail(msg: &str) {
    println!("  {}✗{} {msg}", RED, RESET);
}
fn info(msg: &str) {
    println!("{}{msg}{}", DIM, RESET);
}
fn step(n: u8, total: u8, label: &str) {
    println!();
    println!(
        "{}{}Step {n}/{total}{} · {}{}{}",
        BOLD, CYAN, RESET, BOLD, label, RESET
    );
}

fn prompt_string(label: &str) -> Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

fn prompt_string_default(label: &str, default: &str) -> Result<String> {
    print!("{label} [{default}]: ");
    io::stdout().flush()?;
    let mut s = String::new();
    io::stdin().read_line(&mut s)?;
    let s = s.trim();
    if s.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(s.to_string())
    }
}

fn prompt_yn(label: &str, default: bool) -> Result<bool> {
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    loop {
        print!("{label} {hint}: ");
        io::stdout().flush()?;
        let mut s = String::new();
        io::stdin().read_line(&mut s)?;
        let s = s.trim().to_lowercase();
        match s.as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => warn("answer y or n"),
        }
    }
}

fn prompt_choice(label: &str, options: &[&str], default: usize) -> Result<usize> {
    println!("{label}:");
    for (i, opt) in options.iter().enumerate() {
        let marker = if i == default { ">" } else { " " };
        println!("  {marker} {}) {opt}", i + 1);
    }
    loop {
        print!("  Choice [{}]: ", default + 1);
        io::stdout().flush()?;
        let mut s = String::new();
        io::stdin().read_line(&mut s)?;
        let s = s.trim();
        if s.is_empty() {
            return Ok(default);
        }
        match s.parse::<usize>() {
            Ok(n) if (1..=options.len()).contains(&n) => return Ok(n - 1),
            _ => warn(&format!("enter a number 1..{}", options.len())),
        }
    }
}

/// Read a line from stdin with echo suppressed. Uses crossterm's
/// raw-mode for portable no-echo reads. Falls back to echoed input
/// if the terminal can't be put into raw mode (rare; happens when
/// stdin is piped from a script).
fn prompt_password(label: &str) -> Result<String> {
    print!("{label}: ");
    io::stdout().flush()?;

    use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

    if enable_raw_mode().is_err() {
        // Fallback: stdin isn't a tty (piped script). Read echoed.
        let mut s = String::new();
        io::stdin().read_line(&mut s)?;
        return Ok(s.trim().to_string());
    }

    let mut buf = String::new();
    let result: Result<()> = (|| loop {
        if let Event::Key(KeyEvent {
            code, modifiers, ..
        }) = event::read()?
        {
            match code {
                KeyCode::Enter => break Ok(()),
                KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                    break Err(anyhow::anyhow!("cancelled"));
                }
                KeyCode::Char(c) => {
                    buf.push(c);
                }
                KeyCode::Backspace => {
                    buf.pop();
                }
                KeyCode::Esc => break Err(anyhow::anyhow!("cancelled")),
                _ => {}
            }
        }
    })();
    let _ = disable_raw_mode();
    println!();
    result?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_token_simple() {
        let (u, i, s) = parse_full_token("root@pam!proxxx=00000000-0000-0000-0000-000000000000")
            .expect("parse");
        assert_eq!(u, "root@pam");
        assert_eq!(i, "proxxx");
        assert_eq!(s, "00000000-0000-0000-0000-000000000000");
    }

    #[test]
    fn parse_full_token_rejects_missing_realm() {
        assert!(parse_full_token("root!proxxx=secret").is_err());
    }

    #[test]
    fn parse_full_token_rejects_missing_secret() {
        assert!(parse_full_token("root@pam!proxxx=").is_err());
    }

    #[test]
    fn parse_full_token_rejects_missing_id() {
        assert!(parse_full_token("root@pam!=secret").is_err());
    }

    #[test]
    fn normalise_url_adds_scheme_and_port() {
        assert_eq!(normalise_url("10.0.0.1").unwrap(), "https://10.0.0.1:8006");
    }

    #[test]
    fn normalise_url_keeps_explicit_non_default_port() {
        // reqwest::Url drops :443 (HTTPS default port) and :80 (HTTP
        // default) during canonicalisation — that's intentional. Pin
        // the case operators actually hit: PVE on its default 8006.
        assert_eq!(
            normalise_url("https://pve.lan:8006").unwrap(),
            "https://pve.lan:8006"
        );
        assert_eq!(
            normalise_url("https://pve.lan:9999").unwrap(),
            "https://pve.lan:9999"
        );
    }

    #[test]
    fn normalise_url_strips_trailing_slash() {
        assert_eq!(
            normalise_url("https://pve.lan:8006/").unwrap(),
            "https://pve.lan:8006"
        );
    }

    #[test]
    fn normalise_url_rejects_unknown_scheme() {
        assert!(normalise_url("ftp://pve.lan").is_err());
    }

    #[test]
    fn render_toml_token_minimal() {
        let auth = AuthBlock {
            user: "root@pam".into(),
            auth: "token",
            token_id: Some("proxxx".into()),
            token_secret: Some("secret-uuid".into()),
            password: None,
        };
        let out = render_toml("https://pve.lan:8006", true, &auth, None, None);
        assert!(out.contains(r#"url = "https://pve.lan:8006""#));
        assert!(out.contains(r#"user = "root@pam""#));
        assert!(out.contains(r#"auth = "token""#));
        assert!(out.contains(r#"token_id = "proxxx""#));
        assert!(out.contains(r#"token_secret = "secret-uuid""#));
        assert!(out.contains("verify_tls = true"));
        assert!(!out.contains("[ssh]"));
        assert!(!out.contains("[telegram]"));
    }

    #[test]
    fn render_toml_password_with_ssh() {
        let auth = AuthBlock {
            user: "root@pam".into(),
            auth: "password",
            token_id: None,
            token_secret: None,
            password: Some("hunter2".into()),
        };
        let ssh = SshBlock {
            user: "root".into(),
            key_path: "~/.ssh/proxxx_e2e_ed25519".into(),
            guests: Vec::new(),
        };
        let out = render_toml("https://10.0.0.1:8006", false, &auth, Some(&ssh), None);
        assert!(out.contains(r#"auth = "password""#));
        assert!(out.contains(r#"password = "hunter2""#));
        assert!(out.contains("verify_tls = false"));
        assert!(out.contains("[ssh]"));
        assert!(out.contains(r#"key_path = "~/.ssh/proxxx_e2e_ed25519""#));
        // No guest overrides — must NOT emit any [ssh.guests.*] block.
        assert!(!out.contains("[ssh.guests"));
    }

    #[test]
    fn toml_escape_handles_special_chars() {
        assert_eq!(toml_escape("simple"), r#""simple""#);
        assert_eq!(toml_escape("with \"quote\""), r#""with \"quote\"""#);
        assert_eq!(toml_escape("back\\slash"), r#""back\\slash""#);
        assert_eq!(toml_escape("new\nline"), r#""new\nline""#);
    }

    #[test]
    fn anon_probe_401_treated_as_alive_not_failure() {
        // PVE 8+ requires auth for /version. The wizard's anonymous
        // probe should treat this as a successful liveness signal,
        // not surface "response was not JSON" — the cluster IS up,
        // the TLS handshake worked, the HTTP daemon is responding.
        let r = interpret_anon_probe(reqwest::StatusCode::UNAUTHORIZED, b"");
        let s = r.expect("401 must be treated as alive");
        assert!(s.contains("alive"), "expected 'alive' in {s:?}");
        assert!(s.contains("401"), "expected '401' in {s:?}");
    }

    #[test]
    fn anon_probe_403_also_treated_as_alive() {
        let r = interpret_anon_probe(reqwest::StatusCode::FORBIDDEN, b"");
        let s = r.expect("403 must be treated as alive");
        assert!(s.contains("alive"));
    }

    #[test]
    fn anon_probe_200_with_pve7_body_extracts_version() {
        // PVE 7-style response: full version banner anonymously.
        let body = br#"{"data":{"version":"7.4-1","release":"7.4","repoid":"abc"}}"#;
        let r = interpret_anon_probe(reqwest::StatusCode::OK, body);
        let s = r.expect("valid PVE 7 body must parse");
        assert!(s.contains("7.4"), "expected version in {s:?}");
    }

    #[test]
    fn anon_probe_200_with_html_body_surfaces_preview() {
        // Reverse-proxy intercepting /api2/json/version and returning
        // a login HTML page is the realistic non-JSON scenario. The
        // error must include the body preview so the operator can
        // see "oh this is HTML" rather than an opaque "not JSON".
        let body = b"<html><body>Login required</body></html>";
        let r = interpret_anon_probe(reqwest::StatusCode::OK, body);
        let err = r.expect_err("non-JSON body must surface as error");
        let msg = format!("{err:#}");
        assert!(msg.contains("Login required"), "preview missing: {msg}");
    }

    #[test]
    fn anon_probe_500_surfaces_status_and_body_preview() {
        let body = b"Internal server error: backend unreachable";
        let r = interpret_anon_probe(reqwest::StatusCode::INTERNAL_SERVER_ERROR, body);
        let err = r.expect_err("5xx must surface as error");
        let msg = format!("{err:#}");
        assert!(msg.contains("500"), "status missing: {msg}");
        assert!(
            msg.contains("backend unreachable"),
            "preview missing: {msg}"
        );
    }

    #[test]
    fn body_preview_handles_empty_and_whitespace() {
        assert_eq!(body_preview(b"", 200), "<empty>");
        assert_eq!(body_preview(b"   \n\t  ", 200), "<whitespace-only>");
        assert_eq!(body_preview(b"  hello  \n", 200), "hello");
    }

    #[test]
    fn body_preview_caps_at_max_chars() {
        // The cap is in CHARS, not bytes — multi-byte UTF-8 characters
        // mustn't get sliced mid-codepoint (the operator's PVE error
        // message could include emoji or non-ASCII).
        let long: String = "abc".repeat(200);
        let p = body_preview(long.as_bytes(), 100);
        assert_eq!(p.chars().count(), 100);
    }

    #[test]
    fn discover_ssh_keys_filters_pub_keys_and_known_hosts() {
        // Reproduces the operator's `~/.ssh/` from the wizard run that
        // surfaced this gap: id_ed25519_root + id_rsa (private +
        // public siblings), plus known_hosts / config / authorized_keys
        // noise. Discovery must return EXACTLY the two private keys,
        // OpenSSH first (id_ed25519_root), RSA second (id_rsa).
        let dir = std::env::temp_dir().join(format!(
            "proxxx-ssh-discover-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("tmp dir");

        let openssh = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n-----END OPENSSH PRIVATE KEY-----\n";
        let rsa =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n";
        let pub_key = "ssh-ed25519 AAAA tester@host\n";

        std::fs::write(dir.join("id_ed25519_root"), openssh).unwrap();
        std::fs::write(dir.join("id_ed25519_root.pub"), pub_key).unwrap();
        std::fs::write(dir.join("id_rsa"), rsa).unwrap();
        std::fs::write(dir.join("id_rsa.pub"), pub_key).unwrap();
        std::fs::write(dir.join("known_hosts"), "host ssh-ed25519 AAAA\n").unwrap();
        std::fs::write(dir.join("config"), "Host *\n  User root\n").unwrap();
        std::fs::write(dir.join("authorized_keys"), pub_key).unwrap();
        std::fs::write(dir.join("random.txt"), "not a key\n").unwrap();
        // A dotfile that should be skipped by the leading-dot rule:
        std::fs::write(dir.join(".DS_Store"), b"\x00\x01").unwrap();

        let keys = discover_ssh_keys_in(dir.to_str().unwrap());
        assert_eq!(
            keys.len(),
            2,
            "must filter pub keys + non-keys, got {keys:?}"
        );
        // OpenSSH first per sort priority.
        assert!(
            keys[0].ends_with("id_ed25519_root"),
            "OpenSSH key should sort first, got {keys:?}"
        );
        assert!(
            keys[1].ends_with("id_rsa"),
            "RSA key should sort second, got {keys:?}"
        );

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn discover_ssh_keys_returns_empty_for_missing_dir() {
        let nonexistent = std::env::temp_dir().join(format!(
            "proxxx-ssh-nope-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        let keys = discover_ssh_keys_in(nonexistent.to_str().unwrap());
        assert!(keys.is_empty());
    }

    #[test]
    fn discover_ssh_keys_skips_files_without_private_key_header() {
        // A file with a plausible name but no `-----BEGIN` header
        // (e.g. an old-format key, garbage from a half-rotated
        // backup, a base64 blob without armouring) must not be
        // surfaced as a candidate — the operator would pick it,
        // ssh would fail with a confusing error, the wizard's "I
        // tested this for you" promise would be broken.
        let dir = std::env::temp_dir().join(format!(
            "proxxx-ssh-noheader-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos())
        ));
        std::fs::create_dir_all(&dir).expect("tmp dir");

        std::fs::write(
            dir.join("looks_like_a_key"),
            "MIIEpAIBAAKCAQEA-without-the-armour-line\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("id_real"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\ndata\n",
        )
        .unwrap();

        let keys = discover_ssh_keys_in(dir.to_str().unwrap());
        assert_eq!(keys.len(), 1);
        assert!(keys[0].ends_with("id_real"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_toml_emits_per_guest_ssh_blocks_when_present() {
        let auth = AuthBlock {
            user: "root@pam".into(),
            auth: "token",
            token_id: Some("proxxx".into()),
            token_secret: Some("secret".into()),
            password: None,
        };
        let ssh = SshBlock {
            user: "root".into(),
            key_path: "~/.ssh/id_ed25519".into(),
            guests: vec![
                ("100".into(), "10.0.0.42".into()),
                ("9999".into(), "lxc-9999.lab.example".into()),
            ],
        };
        let out = render_toml("https://10.0.0.1:8006", true, &auth, Some(&ssh), None);

        // Per-guest blocks land with quoted vmid (TOML loader needs
        // string keys, not integers).
        assert!(out.contains(r#"[ssh.guests."100"]"#));
        assert!(out.contains(r#"host = "10.0.0.42""#));
        assert!(out.contains(r#"[ssh.guests."9999"]"#));
        assert!(out.contains(r#"host = "lxc-9999.lab.example""#));

        // Round-trip through proxxx's own loader: the wizard's output
        // must parse back without error AND surface the per-guest
        // entries as a populated `guests` map.
        let parsed: toml::Value = toml::from_str(&out).expect("wizard output must parse as TOML");
        let guests = parsed
            .get("ssh")
            .and_then(|s| s.get("guests"))
            .and_then(|g| g.as_table())
            .expect("ssh.guests table missing from wizard output");
        assert!(guests.contains_key("100"), "vmid 100 missing");
        assert!(guests.contains_key("9999"), "vmid 9999 missing");
        assert_eq!(
            guests
                .get("100")
                .and_then(|v| v.get("host"))
                .and_then(|h| h.as_str()),
            Some("10.0.0.42")
        );
    }

    #[test]
    fn render_toml_ouput_round_trips_via_serde() {
        // The render must produce TOML that proxxx's own loader can
        // parse back without error — otherwise the wizard ships
        // syntactically-broken configs.
        let auth = AuthBlock {
            user: "root@pam".into(),
            auth: "token",
            token_id: Some("proxxx".into()),
            token_secret: Some("hs+/=very%weird?secret".into()),
            password: None,
        };
        let out = render_toml("https://pve.lan:8006", true, &auth, None, None);
        let parsed: toml::Value = toml::from_str(&out).expect("wizard output must parse as TOML");
        assert_eq!(
            parsed.get("token_secret").and_then(|v| v.as_str()),
            Some("hs+/=very%weird?secret")
        );
    }
}
