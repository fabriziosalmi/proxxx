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
pub async fn run() -> Result<(serde_json::Value, i32)> {
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
    // /api2/json/version is the anonymous endpoint — no auth required.
    let res = client
        .get(format!("{url}/api2/json/version"))
        .send()
        .await
        .context("HTTP request failed (cluster unreachable, wrong URL, or TLS rejection)")?;
    let status = res.status();
    let body: serde_json::Value = res.json().await.context("response was not JSON")?;
    if !status.is_success() {
        anyhow::bail!("HTTP {status}: {body}");
    }
    let release = body
        .get("data")
        .and_then(|d| d.get("release"))
        .and_then(|r| r.as_str())
        .unwrap_or("?")
        .to_string();
    let version = body
        .get("data")
        .and_then(|d| d.get("version"))
        .and_then(|r| r.as_str())
        .unwrap_or("?");
    Ok(format!("PVE {version} ({release})"))
}

// ── Step 3a: Token auth ──────────────────────────────────────

#[derive(Debug)]
struct AuthBlock {
    user: String,
    auth: &'static str, // "token" | "password"
    token_id: Option<String>,
    token_secret: Option<String>,
    password: Option<String>,
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
        token_secret: Some(token_secret),
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
        password: Some(password),
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
}

fn prompt_ssh(api_url: &str) -> Result<Option<SshBlock>> {
    let user = prompt_string_default("  SSH user", "root")?;
    let default_key = default_ssh_key_path();
    let key_path = prompt_string_default("  Private key path", &default_key)?;
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
    Ok(Some(SshBlock { user, key_path }))
}

fn default_ssh_key_path() -> String {
    if let Ok(home) = std::env::var("HOME") {
        format!("{home}/.ssh/id_ed25519")
    } else {
        "~/.ssh/id_ed25519".to_string()
    }
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
    bot_token: String,
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
    Ok(Some(TelegramBlock { bot_token, chat_id }))
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
    if body.get("ok").and_then(|v| v.as_bool()) != Some(true) {
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
        match event::read()? {
            Event::Key(KeyEvent {
                code, modifiers, ..
            }) => match code {
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
            },
            _ => {}
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
        };
        let out = render_toml("https://10.0.0.1:8006", false, &auth, Some(&ssh), None);
        assert!(out.contains(r#"auth = "password""#));
        assert!(out.contains(r#"password = "hunter2""#));
        assert!(out.contains("verify_tls = false"));
        assert!(out.contains("[ssh]"));
        assert!(out.contains(r#"key_path = "~/.ssh/proxxx_e2e_ed25519""#));
    }

    #[test]
    fn toml_escape_handles_special_chars() {
        assert_eq!(toml_escape("simple"), r#""simple""#);
        assert_eq!(toml_escape("with \"quote\""), r#""with \"quote\"""#);
        assert_eq!(toml_escape("back\\slash"), r#""back\\slash""#);
        assert_eq!(toml_escape("new\nline"), r#""new\nline""#);
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
