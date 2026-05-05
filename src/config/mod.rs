use anyhow::Result;
use serde::Deserialize;

/// Profile configuration loaded from TOML
#[derive(Debug, Clone, Deserialize)]
pub struct ProfileConfig {
    pub url: String,
    pub user: String,
    #[serde(default = "default_auth")]
    pub auth: String,
    pub token_id: Option<String>,
    pub token_secret: Option<String>,
    pub token_secret_file: Option<String>,
    pub password: Option<String>,
    #[serde(default)]
    pub verify_tls: bool,
    pub rate_limit: Option<u32>,
    pub policies: Option<Vec<crate::hitl::policy::Policy>>,
    pub telegram: Option<TelegramConfig>,
    pub ssh: Option<SshConfig>,
    pub pbs: Option<PbsConfig>,
    /// Alert rules (feature #8). Empty/missing = no alerting.
    pub alerts: Option<Vec<AlertRuleConfig>>,
}

/// One alert rule, declared in TOML.
///
/// Honest scope: `when` is a CLOSED ENUM of 3 predicates, not a free-form
/// DSL. The draconian review explicitly called out an expression parser
/// as scope creep — closed enum keeps the surface area small and the
/// behaviour predictable across releases.
///
/// Example:
/// ```toml
/// [[alerts]]
/// name = "node_down"
/// when = "node_offline"
/// for_secs = 120
/// severity = "critical"
/// route = ["telegram", "ntfy:proxxx-prod", "webhook:https://hooks.example/notify"]
/// dedup_secs = 600
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct AlertRuleConfig {
    pub name: String,
    /// One of `"node_offline" | "storage_above" | "replication_failing"`.
    /// Unknown values cause the engine to skip the rule with a warn log.
    pub when: String,
    /// For `node_offline`: minimum seconds offline before firing.
    /// Default 60.
    #[serde(default = "default_for_secs")]
    pub for_secs: u64,
    /// For `storage_above`: trigger threshold (% used). Default 90.
    #[serde(default = "default_storage_threshold")]
    pub threshold_percent: u8,
    /// Optional storage filter for `storage_above` — if set, the rule
    /// only fires for that storage name. Empty = all storages.
    #[serde(default)]
    pub storage: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    /// One or more route specs. Format: `"telegram"` or `"ntfy:<topic>"`
    /// or `"webhook:<url>"`. Unrecognised prefixes log a warning and
    /// skip — they don't fail the rule.
    pub route: Vec<String>,
    /// Suppression window in seconds — after firing, don't re-fire the
    /// same (rule, target) pair until this elapses. Default 300.
    #[serde(default = "default_dedup_secs")]
    pub dedup_secs: u64,
}

const fn default_for_secs() -> u64 {
    60
}
const fn default_storage_threshold() -> u8 {
    90
}
fn default_severity() -> String {
    "warning".to_string()
}
const fn default_dedup_secs() -> u64 {
    300
}

/// Proxmox Backup Server connection (feature #3). Separate from the main
/// `[profiles.X]` block because PBS is a different server with its own
/// auth tokens and TLS surface — coupling them would break in any setup
/// where PBS lives behind a different proxy or VPN.
///
/// Auth is token-only. PBS supports password but pinning a long-lived
/// token is the right pattern for headless tools like proxxx.
#[derive(Debug, Clone, Deserialize)]
pub struct PbsConfig {
    /// PBS API base URL, e.g. `"https://pbs.lan:8007"`.
    pub url: String,
    /// PBS user@realm, e.g. `"proxxx@pbs"`.
    pub user: String,
    /// API token id (the part after `!` in PBS speak), e.g. `"reader"`.
    pub token_id: String,
    /// Token secret. Resolution order matches `PROXXX_PBS_TOKEN_SECRET`
    /// env, then `token_secret_file`, then OS keychain.
    pub token_secret: Option<String>,
    pub token_secret_file: Option<String>,
    /// TLS verification. Default true — PBS in homelabs often uses
    /// self-signed certs but we never silently disable verification.
    #[serde(default = "default_verify_tls_pbs")]
    pub verify_tls: bool,
    /// Optional API rate limit (req/s). Default 10.
    pub rate_limit: Option<u32>,
}

const fn default_verify_tls_pbs() -> bool {
    true
}

/// (Gemini wave-3 audit) — keychain access wrapper.
///
/// `keyring::Entry::get_password()` is **synchronous** and can block
/// for tens of seconds on Linux (Secret Service / GNOME Keyring may
/// pop a GUI unlock dialog and wait for the user to type a password).
/// Calling it directly inside a tokio async context blocks the runtime
/// thread it's scheduled on, starving every other future.
///
/// `tokio::task::spawn_blocking` runs the closure on the dedicated
/// blocking thread pool (default 512 threads) — the async runtime
/// stays responsive. The `.await` here yields just like any other
/// async call, returning the result when the blocking thread
/// completes.
#[cfg(feature = "keychain")]
async fn keyring_get(
    service: &'static str,
    item: &'static str,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
    tokio::task::spawn_blocking(move || -> anyhow::Result<zeroize::Zeroizing<String>> {
        let entry = keyring::Entry::new(service, item)?;
        Ok(zeroize::Zeroizing::new(entry.get_password()?))
    })
    .await
    .map_err(|e| anyhow::anyhow!("keychain spawn_blocking join error: {e}"))?
}

/// .10 (audit) — bounded env var read for secrets.
///
/// `std::env::var(name)` returns the entire value as a `String` with
/// no upper bound. A local attacker who can set `PROXXX_TOKEN_SECRET`
/// to a 4 GiB blob would OOM proxxx at startup before any validation
/// can refuse the value. We cap at 64 KiB — comfortably above any
/// real PVE/PBS token (~80 chars), real Proxmox passwords, real
/// Telegram bot tokens (~46 chars). Anything bigger is hostile or
/// corrupted.
const ENV_SECRET_MAX_BYTES: usize = 64 * 1024;

fn env_var_secret(name: &str) -> Option<zeroize::Zeroizing<String>> {
    let raw = std::env::var(name).ok()?;
    if raw.len() > ENV_SECRET_MAX_BYTES {
        tracing::warn!(
            "env var {name} is {} bytes — exceeds {ENV_SECRET_MAX_BYTES} cap, refusing",
            raw.len()
        );
        return None;
    }
    if raw.is_empty() {
        return None;
    }
    Some(zeroize::Zeroizing::new(raw))
}

impl PbsConfig {
    /// Resolve the token secret using the same hierarchy as the main
    /// Proxmox API: CLI override → env → file → keychain.
    ///
    /// Async because the keychain branch must run via
    /// `spawn_blocking` (audit) — see `keyring_get`.
    pub async fn resolve_token_secret(
        &self,
        cli_secret: Option<&str>,
    ) -> Result<zeroize::Zeroizing<String>> {
        if let Some(s) = cli_secret {
            if !s.is_empty() {
                return Ok(zeroize::Zeroizing::new(s.to_string()));
            }
        }
        if let Some(val) = env_var_secret("PROXXX_PBS_TOKEN_SECRET") {
            return Ok(val);
        }
        if let Some(ref s) = self.token_secret {
            if !s.is_empty() {
                return Ok(zeroize::Zeroizing::new(s.clone()));
            }
        }
        if let Some(ref file_path) = self.token_secret_file {
            let path = std::path::Path::new(file_path);
            if path.exists() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::metadata(path) {
                        let mode = meta.permissions().mode();
                        if mode & 0o077 != 0 {
                            anyhow::bail!(
                                "Security Error: pbs.token_secret_file '{}' has unsafe permissions {:o}. Must be 0600.",
                                file_path,
                                mode & 0o777,
                            );
                        }
                    }
                }
                if let Ok(content) = std::fs::read_to_string(path) {
                    let s = content.trim().to_string();
                    if !s.is_empty() {
                        return Ok(zeroize::Zeroizing::new(s));
                    }
                }
            }
        }
        #[cfg(feature = "keychain")]
        {
            if let Ok(val) = keyring_get("proxxx", "pbs_token_secret").await {
                return Ok(val);
            }
        }
        anyhow::bail!("PBS token secret not found. Check CLI flag, PROXXX_PBS_TOKEN_SECRET, token_secret_file, or keychain.")
    }
}

/// Telegram bot credentials. Used by the HITL daemon and the alert
/// notifier to send messages and listen for callback approvals.
///
/// Phase 5.13 — `bot_token` was previously plaintext-only. Bot tokens
/// are long-lived bearer credentials: an attacker holding one can
/// impersonate the operator on the approval channel (forge "approve"
/// callbacks against the HITL daemon). We now resolve the token via
/// the same hierarchy as PVE/PBS: CLI override → env → file → keychain.
/// Inline `bot_token = "…"` in the TOML still works for lab setups
/// but is the lowest-priority source.
#[derive(Debug, Clone, Deserialize)]
pub struct TelegramConfig {
    /// Inline plaintext token. Kept for lab setups; not recommended for
    /// prod — prefer `bot_token_file` (chmod 600) or the OS keychain.
    pub bot_token: Option<String>,
    /// Path to a file containing the bot token (only the token, no
    /// surrounding JSON). Must be `0600` permissions on Unix; proxxx
    /// refuses to read it otherwise.
    pub bot_token_file: Option<String>,
    /// Destination chat / channel id. Negative for groups & channels,
    /// positive for direct chats with the bot user.
    pub chat_id: String,
}

impl TelegramConfig {
    /// Resolve the bot token using the standard hierarchy:
    /// 1. `PROXXX_TELEGRAM_BOT_TOKEN` env var (capped at 64 KiB)
    /// 2. `bot_token_file` (with 0600 permission check on Unix)
    /// 3. Inline `bot_token` field
    /// 4. OS keychain entry `proxxx / telegram_bot_token`
    ///
    /// Async so the keychain branch can run via `spawn_blocking`
    /// (audit) — keyring calls block on Linux.
    ///
    /// Returns `Zeroizing<String>` so the heap bytes are wiped on
    /// drop, matching the PVE/PBS pattern (audit).
    pub async fn resolve_bot_token(&self) -> Result<zeroize::Zeroizing<String>> {
        if let Some(val) = env_var_secret("PROXXX_TELEGRAM_BOT_TOKEN") {
            return Ok(val);
        }
        if let Some(ref file_path) = self.bot_token_file {
            let path = std::path::Path::new(file_path);
            if path.exists() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::metadata(path) {
                        let mode = meta.permissions().mode();
                        if mode & 0o077 != 0 {
                            anyhow::bail!(
                                "Security Error: telegram.bot_token_file '{}' has unsafe permissions {:o}. Must be 0600.",
                                file_path,
                                mode & 0o777,
                            );
                        }
                    }
                }
                if let Ok(content) = std::fs::read_to_string(path) {
                    let s = content.trim().to_string();
                    if !s.is_empty() {
                        return Ok(zeroize::Zeroizing::new(s));
                    }
                }
            }
        }
        if let Some(ref s) = self.bot_token {
            if !s.is_empty() {
                return Ok(zeroize::Zeroizing::new(s.clone()));
            }
        }
        #[cfg(feature = "keychain")]
        {
            if let Ok(val) = keyring_get("proxxx", "telegram_bot_token").await {
                return Ok(val);
            }
        }
        anyhow::bail!(
            "Telegram bot token not found. Check PROXXX_TELEGRAM_BOT_TOKEN env, \
             telegram.bot_token_file, inline telegram.bot_token, or keychain entry \
             proxxx/telegram_bot_token."
        )
    }
}

/// SSH layer config (SSH layer). Optional per-profile.
///
/// Auth is key-based only. Password is intentionally unsupported —
/// a Proxmox node with password-only SSH is a security smell we won't enable.
#[derive(Debug, Clone, Deserialize)]
pub struct SshConfig {
    /// SSH user on the Proxmox node (default: "root")
    #[serde(default = "default_ssh_user")]
    pub user: String,

    /// Path to private key (e.g. "~/.`ssh/proxxx_homelab`"). Tilde-expanded.
    pub key_path: Option<String>,

    /// Per-node hostname/IP override. Key = node name, value = host:port form.
    /// If absent, the node name itself is used as host (port 22).
    #[serde(default)]
    pub hosts: std::collections::HashMap<String, String>,

    /// `known_hosts` file path. Defaults to $`XDG_CONFIG_HOME/proxxx/known_hosts`.
    /// Intentionally separate from ~/.`ssh/known_hosts` to avoid contamination.
    pub known_hosts: Option<String>,

    /// "tofu" | "strict" | "off". Default: "tofu".
    #[serde(default = "default_strict_host_check")]
    pub strict_host_key_checking: String,

    /// Hard cap on concurrent SSH operations per profile. Default 8.
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: u32,

    /// Connection idle timeout in seconds (default 300).
    #[serde(default = "default_idle_timeout")]
    pub idle_timeout_secs: u64,

    /// Per-command timeout in seconds (default 60). Streaming ops override per-call.
    #[serde(default = "default_exec_timeout")]
    pub exec_timeout_secs: u64,

    /// Per-guest SSH connection targets (feature 1a).
    /// Keys are the VMID as a string (TOML doesn't support integer table keys).
    #[serde(default)]
    pub guests: std::collections::HashMap<String, GuestSshTarget>,
}

/// Connection details for `SSHing` into a guest (not the Proxmox node).
/// All fields fall back to the parent `SshConfig` when omitted.
#[derive(Debug, Clone, Deserialize)]
pub struct GuestSshTarget {
    /// Guest hostname or IP. Required (we don't yet auto-discover via agent).
    pub host: String,
    /// Optional port override (default 22).
    pub port: Option<u16>,
    /// Optional user override (default: parent SshConfig.user).
    pub user: Option<String>,
    /// Optional key override (default: parent `SshConfig.key_path`).
    pub key_path: Option<String>,
}

fn default_ssh_user() -> String {
    "root".to_string()
}
fn default_strict_host_check() -> String {
    "tofu".to_string()
}
const fn default_max_concurrent() -> u32 {
    8
}
const fn default_idle_timeout() -> u64 {
    300
}
const fn default_exec_timeout() -> u64 {
    60
}

/// Fully-resolved guest SSH target: every field plugged in.
#[derive(Debug, Clone)]
pub struct ResolvedGuestSsh {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub key_path: std::path::PathBuf,
}

impl SshConfig {
    /// Look up a guest's connection target by VMID, applying parent fallbacks.
    /// Returns `None` if the guest isn't configured AND there's no auto-discovery
    /// configured (auto-discovery via qemu-guest-agent is a future enhancement).
    #[must_use]
    pub fn resolve_guest(&self, vmid: u32) -> Option<ResolvedGuestSsh> {
        let key = vmid.to_string();
        let target = self.guests.get(&key)?;
        let user = target.user.clone().unwrap_or_else(|| self.user.clone());
        let key_path = match target.key_path.as_ref() {
            Some(p) => expand_tilde(p),
            None => self.key_path_resolved()?,
        };
        Some(ResolvedGuestSsh {
            host: target.host.clone(),
            port: target.port.unwrap_or(22),
            user,
            key_path,
        })
    }

    /// Resolve host:port for a given node name. Falls back to node:22.
    #[must_use]
    pub fn resolve_host(&self, node: &str) -> (String, u16) {
        if let Some(spec) = self.hosts.get(node) {
            if let Some((h, p)) = spec.rsplit_once(':') {
                if let Ok(port) = p.parse::<u16>() {
                    return (h.to_string(), port);
                }
            }
            return (spec.clone(), 22);
        }
        (node.to_string(), 22)
    }

    /// Resolve `known_hosts` path with default + tilde expansion.
    #[must_use]
    pub fn known_hosts_path(&self) -> std::path::PathBuf {
        if let Some(ref p) = self.known_hosts {
            return expand_tilde(p);
        }
        let dir = directories::ProjectDirs::from("dev", "proxxx", "proxxx").map_or_else(
            || std::path::PathBuf::from("/tmp/proxxx"),
            |d| d.config_dir().to_path_buf(),
        );
        dir.join("known_hosts")
    }

    /// Resolve private key path with tilde expansion.
    #[must_use]
    pub fn key_path_resolved(&self) -> Option<std::path::PathBuf> {
        self.key_path.as_ref().map(|p| expand_tilde(p))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyPolicy {
    Tofu,
    Strict,
    Off,
}

impl HostKeyPolicy {
    /// Parse a string policy tolerantly. Default fallback: Tofu.
    ///
    /// Intentionally NOT `impl FromStr` — the std trait returns
    /// `Result<Self, Err>` which doesn't fit our infallible
    /// "tolerate unknown → Tofu" semantics. The tolerance is the
    /// load-bearing behaviour (a typo'd config shouldn't crash
    /// proxxx, just default to the safer policy).
    #[allow(clippy::should_implement_trait)]
    #[must_use]
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "strict" => Self::Strict,
            "off" => Self::Off,
            _ => Self::Tofu,
        }
    }
}

fn expand_tilde(p: &str) -> std::path::PathBuf {
    if let Some(stripped) = p.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return std::path::PathBuf::from(home).join(stripped);
        }
    }
    std::path::PathBuf::from(p)
}

fn default_auth() -> String {
    "token".to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthType {
    Token,
    Password,
}

impl ProfileConfig {
    #[must_use]
    pub fn auth_method(&self) -> AuthType {
        if self.auth == "password" {
            AuthType::Password
        } else {
            AuthType::Token
        }
    }

    pub async fn resolve_token_secret(
        &self,
        cli_secret: Option<&str>,
    ) -> Result<zeroize::Zeroizing<String>> {
        // 1. CLI Flag
        if let Some(secret) = cli_secret {
            if !secret.is_empty() {
                return Ok(zeroize::Zeroizing::new(secret.to_string()));
            }
        }

        // 2. Environment variable (— 64 KiB cap)
        if let Some(val) = env_var_secret("PROXXX_TOKEN_SECRET") {
            return Ok(val);
        }

        // 3. Inline `token_secret = "..."` in the config file.
        //
        // Bug fix from live cluster test: this branch was missing
        // entirely — the field was advertised in `docs/config.example.toml`
        // and accepted by serde, but the resolver only consulted CLI /
        // env / file / keychain, so users who put the secret directly
        // in config.toml got "Token secret not found" with no hint.
        // PbsConfig already had the equivalent branch; this aligns
        // the two resolvers.
        if let Some(ref s) = self.token_secret {
            if !s.is_empty() {
                return Ok(zeroize::Zeroizing::new(s.clone()));
            }
        }

        // 4. Secure File
        if let Some(ref file_path) = self.token_secret_file {
            let path = std::path::Path::new(file_path);
            if path.exists() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = std::fs::metadata(path) {
                        let mode = meta.permissions().mode();
                        if mode & 0o077 != 0 {
                            anyhow::bail!("Security Error: token_secret_file '{}' has unsafe permissions {:o}. Must be 0600 or stricter.", file_path, mode & 0o777);
                        }
                    }
                }

                if let Ok(content) = std::fs::read_to_string(path) {
                    let secret = content.trim().to_string();
                    if !secret.is_empty() {
                        return Ok(zeroize::Zeroizing::new(secret));
                    }
                }
            } else {
                anyhow::bail!("token_secret_file '{file_path}' not found");
            }
        }

        // 5. OS Keychain (if feature enabled) — blocking
        // call wrapped in spawn_blocking via `keyring_get`.
        #[cfg(feature = "keychain")]
        {
            if let Ok(val) = keyring_get("proxxx", "token_secret").await {
                return Ok(val);
            }
        }

        anyhow::bail!("Token secret not found. Check CLI args, PROXXX_TOKEN_SECRET, inline `token_secret =` in config.toml, token_secret_file, or keychain.")
    }

    /// Resolve password from config, keychain, or env var. Async
    /// because the keychain branch goes through `spawn_blocking`
    /// (audit).
    pub async fn resolve_password(&self) -> Result<zeroize::Zeroizing<String>> {
        if let Some(ref pw) = self.password {
            if !pw.is_empty() {
                return Ok(zeroize::Zeroizing::new(pw.clone()));
            }
        }

        // — bounded env var read for the PVE password.
        if let Some(val) = env_var_secret("PROXXX_PASSWORD") {
            return Ok(val);
        }

        #[cfg(feature = "keychain")]
        {
            if let Ok(val) = keyring_get("proxxx", "password").await {
                return Ok(val);
            }
        }

        anyhow::bail!("Password not found. Set it via config, PROXXX_PASSWORD env var, or `proxxx auth login`")
    }
}

/// Load configuration from TOML file
pub fn load_config(_profile_name: Option<&str>) -> Result<ProfileConfig> {
    let config_dir = directories::ProjectDirs::from("dev", "proxxx", "proxxx")
        .map(|d| d.config_dir().to_path_buf())
        .unwrap_or_else(|| {
            let mut p = dirs_fallback();
            p.push(".config/proxxx");
            p
        });

    let config_path = config_dir.join("config.toml");

    if !config_path.exists() {
        anyhow::bail!(
            "Config not found at {}. Run `proxxx init` to create one.",
            config_path.display()
        );
    }

    let content = std::fs::read_to_string(&config_path)?;
    let config: ProfileConfig = toml::from_str(&content)?;
    Ok(config)
}

fn dirs_fallback() -> std::path::PathBuf {
    std::env::var("HOME").map_or_else(
        |_| std::path::PathBuf::from("/tmp"),
        std::path::PathBuf::from,
    )
}
