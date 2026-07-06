pub mod watcher;
pub use watcher::ConfigHandle;

use anyhow::{Context, Result};
use serde::Deserialize;

/// Profile configuration loaded from TOML
#[derive(Debug, Clone, Deserialize)]
pub struct ProfileConfig {
    pub url: String,
    pub user: String,
    #[serde(default = "default_auth")]
    pub auth: String,
    pub token_id: Option<String>,
    pub token_secret: Option<zeroize::Zeroizing<String>>,
    pub token_secret_file: Option<String>,
    pub password: Option<zeroize::Zeroizing<String>>,
    #[serde(default)]
    pub verify_tls: bool,
    /// Phase 13 audit fix: opt-in TLS pinning. Set to `"tofu"` (case
    /// insensitive) to snapshot the cluster's leaf cert on first connect
    /// and refuse any subsequent cert that doesn't match. When unset
    /// (the default), behaviour is unchanged — `verify_tls` alone
    /// controls trust. The cert is persisted at
    /// `<config_dir>/known_certs/<profile>.der`; delete the file to
    /// re-trust on the next connect.
    #[serde(default)]
    pub tls_pin_mode: Option<String>,
    /// Declarative, always-on write lock for this profile. When `true`,
    /// proxxx refuses EVERY mutation (POST/PUT/DELETE) on this profile
    /// before the request leaves the process; reads (GET) are unaffected.
    /// Independent of — and complementary to — a read-only PVE API token:
    /// the token is server-enforced, this is client-enforced, and either
    /// alone blocks writes. Unlike `incident freeze` (a runtime lock you
    /// have to remember to set and can `thaw`), this lives with the
    /// profile in config and is version-controllable. Default `false`.
    #[serde(default)]
    pub read_only: bool,
    pub rate_limit: Option<u32>,
    pub policies: Option<Vec<crate::hitl::policy::Policy>>,
    pub telegram: Option<TelegramConfig>,
    pub ssh: Option<SshConfig>,
    pub pbs: Option<PbsConfig>,
    /// Alert rules (feature #8). Empty/missing = no alerting.
    pub alerts: Option<Vec<AlertRuleConfig>>,
    /// Bearer token for the MCP HTTP transport. When set, all POST /mcp and
    /// GET /mcp requests must carry `Authorization: Bearer <token>`. Leave
    /// unset (the default) to run the HTTP server without auth — only do this
    /// on a trusted network or behind a reverse proxy that enforces auth.
    pub mcp_token: Option<zeroize::Zeroizing<String>>,

    /// Continuous-reconciliation (`reconcile watch`) config. When present,
    /// `proxxx daemon serve` runs a 4th pillar that periodically diffs the
    /// declared `source` against live state and reports drift (detect-only).
    /// Absent = no reconcile loop.
    pub reconcile: Option<ReconcileConfig>,

    /// The profile name this config was loaded under (`None` for the flat /
    /// default top-level config). Not part of the TOML — `load_config` stamps
    /// it after deserialising so the rest of the code (notably the per-profile
    /// incident freeze) can attribute a client to its cluster. `#[serde(skip)]`
    /// keeps it out of the wire format entirely.
    #[serde(skip)]
    pub profile_name: Option<String>,
}

/// Continuous-reconciliation config (`[profiles.X.reconcile]`). Drives the
/// `reconcile watch` daemon pillar; same source semantics as the one-shot
/// `reconcile run`. Detect-only by default; `auto_converge = true` opts the
/// daemon into the converge (write) half — see [`ReconcileConfig::auto_converge`].
#[derive(Debug, Clone, Deserialize)]
pub struct ReconcileConfig {
    /// Desired-state source: a local file, a local directory, or a git URL
    /// (shallow-cloned each tick).
    pub source: String,
    /// State file path within a directory / git-repo source. The output of
    /// `proxxx state export`. Default `state.toml`.
    #[serde(default = "default_reconcile_path")]
    pub path: String,
    /// Poll interval in seconds (floored at 30 by the loop). Default 300.
    #[serde(default = "default_reconcile_interval")]
    pub interval_secs: u64,

    /// Opt-in to Layer 3 auto-converge: when `true`, after detecting drift each
    /// tick the daemon runs the converge (apply) core to mutate the live cluster
    /// toward the declared state. **Default `false`** — the watch stays strictly
    /// detect-only unless this is explicitly set. The unmanned converge always
    /// runs with `force = false`, so a Severe-risk change (see
    /// [`crate::state::preflight`]) is never auto-applied — it raises a "needs
    /// human review" alert and mutates nothing.
    #[serde(default)]
    pub auto_converge: bool,

    /// When auto-converging, also execute `Delete` changes (maps to
    /// [`crate::state::apply::ApplyOptions::prune`]). **Default `false`** — deletes
    /// are previewed as `Skipped { PrunePolicy }` but not executed, matching
    /// `state apply` without `--prune`. Enable only against a desired-state repo
    /// with branch protection / atomic pushes: a half-pushed tree could otherwise
    /// present spurious deletes (the bulk-change Severe gate is the backstop).
    #[serde(default)]
    pub converge_prune: bool,

    /// Per-family whitelist for the **unmanned** daemon converge. Empty/absent
    /// = every family (current behaviour). When set, the unmanned auto-converge
    /// only touches these state families (matched against `Change::resource`,
    /// e.g. `"pool"`, `"acl"`, `"storage"`); high-blast-radius families left off
    /// the list stay human-only — graduated trust. The manual `reconcile
    /// converge` command is NOT restricted. Only ever narrows the blast radius.
    #[serde(default)]
    pub allowed_families: Option<Vec<String>>,

    /// Hard cap on the number of changes the **unmanned** daemon will apply in a
    /// single tick (counted AFTER `allowed_families` filtering), regardless of
    /// severity. Absent = no cap (current behaviour). Above the cap the daemon
    /// refuses and raises a "needs human review (too many changes)" alert
    /// instead of applying. Complements the Severe bulk-change circuit-breaker
    /// (which only trips on Severe-tier floods) by also catching a flood of
    /// Warning-tier changes — e.g. 40 deletes from a partial git revert.
    #[serde(default)]
    pub max_unmanned_changes: Option<u32>,
}

fn default_reconcile_path() -> String {
    "state.toml".to_string()
}

const fn default_reconcile_interval() -> u64 {
    300
}

/// Refusal returned by the API write helpers when the active profile is
/// configured `read_only = true`. Carried via `anyhow` so callers `?`
/// through it unchanged; `main.rs` downcasts to map the exit code. Shares
/// the "mutation refused by a local lock" exit code (8) with the incident
/// freeze — both mean "proxxx declined to write before touching PVE".
#[derive(Debug, thiserror::Error)]
#[error(
    "refusing mutation on {path} — profile '{profile}' is configured read-only \
     (read_only = true). Remove the flag from this profile in config.toml to \
     allow writes (or point it at a writable profile)."
)]
pub struct ReadOnlyRefusal {
    pub profile: String,
    pub path: String,
}

impl ReadOnlyRefusal {
    /// Process exit code — matches the "mutation refused by a local lock"
    /// contract shared with `incident freeze` (docs/reference/exit-codes.md).
    pub const EXIT_CODE: i32 = 8;
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
    pub token_secret: Option<zeroize::Zeroizing<String>>,
    pub token_secret_file: Option<String>,
    /// TLS verification. Default true — PBS in homelabs often uses
    /// self-signed certs but we never silently disable verification.
    #[serde(default = "default_verify_tls_pbs")]
    pub verify_tls: bool,
    /// SHA-256 certificate fingerprint of the PBS server, e.g.
    /// `"AB:CD:…:23"`. Needed by `proxmox-backup-client` (the restore
    /// shell-out) to trust a self-signed PBS cert: the client has no
    /// "insecure" switch — it verifies against the system trust store
    /// OR an explicit `PBS_FINGERPRINT`. Without it, restore against a
    /// self-signed PBS fails with "certificate fingerprint was not
    /// confirmed". Get it from the PBS UI (Certificates) or
    /// `proxmox-backup-manager cert info`.
    #[serde(default)]
    pub fingerprint: Option<String>,
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

/// Ordered keychain item names to try for a secret: the per-profile item
/// `<profile>/<item>` first, then the flat `<item>` as a back-compat fallback.
///
/// Two keychain-backed profiles used to collide on the same flat key (both read
/// `proxxx/token_secret`), so profile B silently resolved profile A's cluster
/// credential — a cross-cluster isolation gap. Namespacing per profile closes
/// it; the flat fallback keeps keys stored before this change working. Pure so
/// the ordering is unit-tested without touching the OS keychain.
#[must_use]
fn keyring_candidates(item: &str, profile: Option<&str>) -> Vec<String> {
    let mut names = Vec::with_capacity(2);
    if let Some(p) = profile {
        names.push(format!("{p}/{item}"));
    }
    names.push(item.to_string());
    names
}

/// Resolve a keychain secret, per-profile-first with a flat fallback (see
/// [`keyring_candidates`]). The primary cluster credentials (`token_secret`,
/// `password`) route through here; the shared/secondary bot-token + PBS-token
/// keychain entries stay flat by design (see ACCEPTED-RISKS AR-8).
#[cfg(feature = "keychain")]
async fn keyring_get_scoped(
    item: &str,
    profile: Option<&str>,
) -> anyhow::Result<zeroize::Zeroizing<String>> {
    let candidates = keyring_candidates(item, profile);
    tokio::task::spawn_blocking(move || -> anyhow::Result<zeroize::Zeroizing<String>> {
        let mut last: Option<keyring::Error> = None;
        for name in &candidates {
            match keyring::Entry::new("proxxx", name).and_then(|e| e.get_password()) {
                Ok(v) => return Ok(zeroize::Zeroizing::new(v)),
                Err(e) => last = Some(e),
            }
        }
        Err(anyhow::anyhow!(
            "keychain: no entry among {candidates:?}: {last:?}"
        ))
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
                return Ok(s.clone());
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

/// Reject SSH user/host strings that would be parsed by `ssh(1)` as
/// flags or that would smuggle a different destination through the
/// `user@host` positional. Defense-in-depth even with `--`: the
/// `--`-separator stops flag parsing in the binary, but a leading `-`
/// in `host` or `@` in `user` still indicates a config that's been
/// tampered with or fat-fingered, and "ssh -- -oProxyCommand=…" is
/// unsafe on shells that auto-complete around `--` (CWE-88).
///
/// Returns `Err(reason)` so callers can surface an actionable message.
pub fn validate_ssh_destination(user: &str, host: &str) -> std::result::Result<(), String> {
    if user.is_empty() {
        return Err("ssh user is empty".into());
    }
    if host.is_empty() {
        return Err("ssh host is empty".into());
    }
    // Leading `-` would be parsed as a flag if the destination ever
    // ends up before `--` (e.g. via a future call site that forgets
    // the separator). Refuse at the source.
    if user.starts_with('-') {
        return Err(format!("ssh user starts with '-': {user:?}"));
    }
    if host.starts_with('-') {
        return Err(format!("ssh host starts with '-': {host:?}"));
    }
    // `@` in the user collapses `user@host` parsing — ssh keeps the
    // last `@` as the separator, so `user="a@b", host="c"` becomes
    // destination `b@c` and silently changes target.
    if user.contains('@') {
        return Err(format!("ssh user contains '@': {user:?}"));
    }
    // Whitespace and NUL would survive into argv but break shell
    // composition for the few internal callers that quote into
    // log/diagnostic strings.
    let bad = |c: char| c.is_whitespace() || c == '\0';
    if user.contains(bad) {
        return Err(format!("ssh user contains whitespace/NUL: {user:?}"));
    }
    if host.contains(bad) {
        return Err(format!("ssh host contains whitespace/NUL: {host:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod ssh_validation_tests {
    use super::validate_ssh_destination;

    #[test]
    fn accepts_normal_destination() {
        assert!(validate_ssh_destination("root", "10.0.0.1").is_ok());
        assert!(validate_ssh_destination("ops", "pve.lab").is_ok());
    }

    #[test]
    fn rejects_leading_dash_host() {
        assert!(validate_ssh_destination("root", "-oProxyCommand=evil").is_err());
    }

    #[test]
    fn rejects_leading_dash_user() {
        assert!(validate_ssh_destination("-l", "host").is_err());
    }

    #[test]
    fn rejects_at_in_user() {
        assert!(validate_ssh_destination("user@other", "host").is_err());
    }

    #[test]
    fn rejects_whitespace_or_nul() {
        assert!(validate_ssh_destination("ro ot", "h").is_err());
        assert!(validate_ssh_destination("root", "h\0ost").is_err());
    }

    #[test]
    fn rejects_empty() {
        assert!(validate_ssh_destination("", "host").is_err());
        assert!(validate_ssh_destination("user", "").is_err());
    }
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
                return Ok(s.clone());
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
            if let Ok(val) = keyring_get_scoped("token_secret", self.profile_name.as_deref()).await
            {
                return Ok(val);
            }
        }

        anyhow::bail!("Token secret not found. Check CLI args, PROXXX_TOKEN_SECRET, inline `token_secret =` in config.toml, token_secret_file, or keychain.")
    }

    /// Resolve password from env, config, or keychain. Async because
    /// the keychain branch goes through `spawn_blocking` (audit).
    ///
    /// Resolution order — env > inline config > keychain — matches
    /// `resolve_token_secret` so operators get the SAME precedence
    /// rules regardless of which auth method their profile uses. The
    /// pre-Phase 18 order put inline-config first, which made
    /// `PROXXX_PASSWORD` silently unreachable on any profile that
    /// also had `password =` in `config.toml`. That broke
    /// credential rotation at runtime (the documented escape hatch)
    /// AND broke the `beta_bad_token_surfaces_401_cleanly` E2E test
    /// on password-auth configs.
    pub async fn resolve_password(&self) -> Result<zeroize::Zeroizing<String>> {
        // Env beats inline — matches the token-secret hierarchy and
        // the long-standing "env always wins" promise in the docs.
        if let Some(val) = env_var_secret("PROXXX_PASSWORD") {
            return Ok(val);
        }

        if let Some(ref pw) = self.password {
            if !pw.is_empty() {
                return Ok(pw.clone());
            }
        }

        #[cfg(feature = "keychain")]
        {
            if let Ok(val) = keyring_get_scoped("password", self.profile_name.as_deref()).await {
                return Ok(val);
            }
        }

        anyhow::bail!("Password not found. Set it via PROXXX_PASSWORD env var, inline `password =` in config.toml, or `proxxx auth login`")
    }
}

/// Phase 15 audit fix: typed errors for the config-load path.
///
/// `docs/reference/exit-codes.md` has documented exit code `3` for
/// "Configuration error" since v0.1.10, but every config-load failure
/// (file missing, IO error, malformed TOML, missing required field)
/// was an opaque `anyhow::Error` that landed in main.rs's catch-all
/// → exit `1`. Scripts written against the contract (`case $? in 3) ...`)
/// silently never matched. Same wiring pattern as `ApiError::exit_code`
/// (v0.1.15) and `PreflightRefusal::EXIT_CODE` (v0.1.13):
///
///   1. Construct typed `ConfigError` at the failure site.
///   2. Carry through anyhow via `From<ConfigError> for anyhow::Error`
///      (free — `thiserror::Error` blanket impls `std::error::Error`).
///   3. main.rs chain-walker downcasts to `ConfigError` and maps to 3.
///
/// All three variants currently map to the same exit code, so a single
/// associated constant keeps the chain walker trivial (no per-variant
/// branch). Splitting later is a SemVer-compatible additive change as
/// long as 3 remains in the set.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// `config.toml` does not exist at the expected path. First-run
    /// case — the operator hasn't run `proxxx init` yet.
    #[error("Config not found at {path}. Run `proxxx init` to create one.")]
    NotFound { path: std::path::PathBuf },

    /// The file exists but couldn't be read — permission denied, EIO,
    /// disk gone. Distinct from `NotFound` because the fix is different
    /// (chmod / unmount diagnostics, not `proxxx init`).
    #[error("Failed to read config at {path}")]
    Io {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The file was read but TOML parsing failed: syntax error, type
    /// mismatch (`url = 8006` instead of `"…"`), or a required field
    /// is missing (the toml crate surfaces both as the same error
    /// type — `toml::de::Error` carries line/col info in `Display`).
    #[error("Invalid TOML in {path}")]
    Toml {
        path: std::path::PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

impl ConfigError {
    /// Process exit code for any `ConfigError` variant — matches the
    /// `3` slot in [`docs/reference/exit-codes.md`](../../docs/reference/exit-codes.md).
    pub const EXIT_CODE: i32 = 3;
}

/// Resolve the config.toml path. The `PROXXX_CONFIG` env var overrides
/// the OS-default location — used by integration tests for a hermetic
/// config (mirrors the `PROXXX_FREEZE_PATH` override on the freeze lock)
/// and handy for operators juggling several config files.
fn config_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PROXXX_CONFIG") {
        if !p.is_empty() {
            return std::path::PathBuf::from(p);
        }
    }
    let config_dir = directories::ProjectDirs::from("dev", "proxxx", "proxxx")
        .map(|d| d.config_dir().to_path_buf())
        .unwrap_or_else(|| {
            let mut p = dirs_fallback();
            p.push(".config/proxxx");
            p
        });
    config_dir.join("config.toml")
}

/// Public accessor for the resolved config path — `proxxx init` and the
/// wizard write here, so they must agree with `load_config` on the
/// location (including the `PROXXX_CONFIG` override).
#[must_use]
pub fn resolved_config_path() -> std::path::PathBuf {
    config_path()
}

/// Directory holding per-profile secret files: `<config_dir>/secrets/`.
/// Honors the `PROXXX_CONFIG` override (its parent is the config dir).
#[must_use]
pub fn secrets_dir() -> std::path::PathBuf {
    let mut dir = resolved_config_path()
        .parent()
        .map_or_else(dirs_fallback, std::path::Path::to_path_buf);
    dir.push("secrets");
    dir
}

/// Canonical path for a profile's token-secret file:
/// `<config_dir>/secrets/<profile>.token`. Point a profile's
/// `token_secret_file = "..."` here so [`Config::resolve_token_secret`]
/// (which enforces 0600) reads it back.
#[must_use]
pub fn token_secret_path(profile: &str) -> std::path::PathBuf {
    secrets_dir().join(format!("{profile}.token"))
}

/// Write a profile's token secret to [`token_secret_path`] with `0600`
/// perms on Unix, atomically (temp file + rename; perms set BEFORE the
/// rename so the secret is never briefly group/world-readable). Returns
/// the path so the caller can record it as `token_secret_file`. The
/// companion reader is [`Config::resolve_token_secret`], which refuses
/// anything looser than 0600.
pub fn write_token_secret(profile: &str, secret: &str) -> Result<std::path::PathBuf> {
    write_secret_file(&token_secret_path(profile), secret)
}

/// Inner writer, split out so tests can exercise the atomic-write + 0600
/// mechanics against an explicit path without touching the global
/// `PROXXX_CONFIG`-derived location.
fn write_secret_file(path: &std::path::Path, secret: &str) -> Result<std::path::PathBuf> {
    let dir = path
        .parent()
        .context("token-secret path has no parent directory")?;
    std::fs::create_dir_all(dir)
        .with_context(|| format!("creating secrets dir {}", dir.display()))?;
    let tmp = path.with_extension("token.tmp");
    std::fs::write(&tmp, secret.as_bytes())
        .with_context(|| format!("writing {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting 0600 on {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(path.to_path_buf())
}

/// Load configuration from TOML file. Errors carry a typed
/// [`ConfigError`] through anyhow so main.rs can map them to exit
/// code `3` ("Configuration error") instead of the generic `1`.
///
/// When `profile_name` is `None` the flat top-level keys are used
/// (backwards-compatible with configs that pre-date named profiles).
/// When `profile_name` is `Some("x")` the `[profiles.x]` table is
/// used; if it does not exist an error is returned listing the known
/// profile names so the user knows what to pass to `--profile`.
pub fn load_config(profile_name: Option<&str>) -> Result<ProfileConfig> {
    let config_path = config_path();

    if !config_path.exists() {
        return Err(ConfigError::NotFound { path: config_path }.into());
    }

    let content = std::fs::read_to_string(&config_path).map_err(|source| ConfigError::Io {
        path: config_path.clone(),
        source,
    })?;

    let raw: toml::Value = toml::from_str(&content).map_err(|source| ConfigError::Toml {
        path: config_path.clone(),
        source,
    })?;

    // Resolve which profile to load when none was passed on the CLI:
    //   1. an explicit `--profile` always wins (the `Some` arm below);
    //   2. else a top-level `default = "name"` key in config.toml;
    //   3. else, if the config is profile-only (no flat `url`) and has
    //      exactly ONE profile, transparently use it;
    //   4. else fall back to the flat top-level config.
    // (3)+(2) turn the opaque "missing field `url`" into a usable default
    // for the common single-profile case, and (see below) a profile-only
    // config with several profiles and no default yields an actionable
    // "use --profile X" error instead of the serde message.
    let effective: Option<String> = profile_name.map(str::to_string).or_else(|| {
        raw.get("default")
            .and_then(toml::Value::as_str)
            .map(str::to_string)
            .or_else(|| {
                let flat = raw.get("url").is_some();
                if flat {
                    return None;
                }
                let names = profile_names(&raw);
                (names.len() == 1).then(|| names[0].clone())
            })
    });

    let profile_value: toml::Value = if let Some(name) = effective.as_deref() {
        raw.get("profiles")
            .and_then(|p| p.get(name))
            .cloned()
            .ok_or_else(|| {
                let known = profile_names(&raw);
                let known_str = if known.is_empty() {
                    "(none defined)".to_string()
                } else {
                    known.join(", ")
                };
                anyhow::anyhow!(
                    "Profile '{}' not found in config. Known profiles: {}",
                    name,
                    known_str,
                )
            })?
    } else {
        // No profile resolved. If the config is profile-only (no flat
        // `url`/`user`) emit an actionable error listing the profiles —
        // instead of the opaque serde "missing field `url`" — so the user
        // knows to pass `--profile <name>` (or `proxxx fleet`), or set a
        // top-level `default = "name"`.
        let flat_present = raw.get("url").is_some() || raw.get("user").is_some();
        if !flat_present {
            let names = profile_names(&raw);
            if !names.is_empty() {
                anyhow::bail!(
                    "no default profile and this config has no flat top-level connection. \
                     Available profiles: {}. Re-run with `--profile <name>` (e.g. \
                     `proxxx --profile {} ls nodes`), aggregate all of them read-only with \
                     `proxxx fleet`, or set a top-level `default = \"<name>\"` in config.toml.",
                    names.join(", "),
                    names[0],
                );
            }
        }
        // Flat top-level config (backwards compat). Strip the [profiles]
        // table before deserializing so unknown-field errors don't fire
        // on parsers that use deny_unknown_fields in the future.
        let mut v = raw;
        if let Some(t) = v.as_table_mut() {
            t.remove("profiles");
        }
        v
    };

    let mut cfg: ProfileConfig = profile_value.try_into().map_err(|e| {
        anyhow::anyhow!(
            "Failed to parse{} profile from {}: {}",
            effective
                .as_deref()
                .map_or(String::new(), |n| format!(" '{n}'")),
            config_path.display(),
            e,
        )
    })?;
    // Stamp the resolved profile name so a client built from this config
    // knows which cluster it talks to (used by the per-profile incident
    // freeze). `None` for the flat/default config — that client respects
    // only the global lock. Note this is `effective`, not the raw CLI arg,
    // so a `default = "x"` key or single-profile auto-default is attributed.
    cfg.profile_name = effective;
    Ok(cfg)
}

/// Sorted names of the `[profiles.*]` tables in a parsed config.
fn profile_names(raw: &toml::Value) -> Vec<String> {
    raw.get("profiles")
        .and_then(toml::Value::as_table)
        .map(|t| {
            let mut v: Vec<String> = t.keys().cloned().collect();
            v.sort();
            v
        })
        .unwrap_or_default()
}

/// Return the names of all named profiles in the config file.
/// The flat top-level config (backwards-compat default) is not included.
pub fn list_profiles() -> Result<Vec<String>> {
    let path = config_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    let content = std::fs::read_to_string(&path)?;
    let raw: toml::Value = toml::from_str(&content)?;
    let names = raw
        .get("profiles")
        .and_then(|p| p.as_table())
        .map(|t| {
            let mut v: Vec<String> = t.keys().cloned().collect();
            v.sort();
            v
        })
        .unwrap_or_default();
    Ok(names)
}

fn dirs_fallback() -> std::path::PathBuf {
    std::env::var("HOME").map_or_else(
        |_| std::path::PathBuf::from("/tmp"),
        std::path::PathBuf::from,
    )
}

#[cfg(test)]
mod read_only_tests {
    use super::*;

    #[test]
    fn read_only_defaults_false_when_absent() {
        // A minimal profile with no `read_only` key must deserialize
        // with the flag off — existing configs keep writing.
        let cfg: ProfileConfig =
            toml::from_str("url = \"https://x:8006\"\nuser = \"root@pam\"\n").unwrap();
        assert!(!cfg.read_only);
    }

    #[test]
    fn read_only_true_parses() {
        let cfg: ProfileConfig =
            toml::from_str("url = \"https://x:8006\"\nuser = \"root@pam\"\nread_only = true\n")
                .unwrap();
        assert!(cfg.read_only);
    }

    #[test]
    fn read_only_refusal_exit_code_is_eight() {
        // Shares exit 8 with the incident freeze ("mutation refused by a
        // local lock"). Locked here so a future edit can't silently drift
        // the documented contract.
        assert_eq!(ReadOnlyRefusal::EXIT_CODE, 8);
    }

    #[test]
    fn read_only_refusal_message_is_actionable() {
        let e = ReadOnlyRefusal {
            profile: "prod".into(),
            path: "/nodes/pve1/qemu/100/status/start".into(),
        };
        let msg = format!("{e}");
        assert!(msg.contains("read-only"), "got: {msg}");
        assert!(msg.contains("prod"), "names the profile: {msg}");
    }
}

#[cfg(test)]
mod reconcile_config_tests {
    use super::*;

    #[test]
    fn reconcile_absent_is_none() {
        let cfg: ProfileConfig =
            toml::from_str("url = \"https://x:8006\"\nuser = \"root@pam\"\n").unwrap();
        assert!(cfg.reconcile.is_none());
    }

    #[test]
    fn reconcile_section_parses_with_defaults() {
        let cfg: ProfileConfig = toml::from_str(
            "url = \"https://x:8006\"\nuser = \"root@pam\"\n\
             [reconcile]\nsource = \"https://github.com/o/r.git\"\n",
        )
        .unwrap();
        let rec = cfg.reconcile.expect("reconcile section present");
        assert_eq!(rec.source, "https://github.com/o/r.git");
        assert_eq!(rec.path, "state.toml"); // default
        assert_eq!(rec.interval_secs, 300); // default

        // Layer 3 is opt-in: both converge knobs default OFF so an existing
        // detect-only `[reconcile]` section keeps mutating nothing.
        assert!(!rec.auto_converge, "auto_converge must default false");
        assert!(!rec.converge_prune, "converge_prune must default false");
    }

    #[test]
    fn reconcile_overrides_take_effect() {
        let cfg: ProfileConfig = toml::from_str(
            "url = \"https://x:8006\"\nuser = \"root@pam\"\n\
             [reconcile]\nsource = \"/etc/proxxx/state.toml\"\n\
             path = \"clusters/prod.toml\"\ninterval_secs = 60\n",
        )
        .unwrap();
        let rec = cfg.reconcile.unwrap();
        assert_eq!(rec.path, "clusters/prod.toml");
        assert_eq!(rec.interval_secs, 60);
    }

    #[test]
    fn reconcile_auto_converge_opt_in() {
        // Layer 3: the converge knobs are explicit opt-ins; once set they
        // must round-trip so the daemon can read them.
        let cfg: ProfileConfig = toml::from_str(
            "url = \"https://x:8006\"\nuser = \"root@pam\"\n\
             [reconcile]\nsource = \"https://github.com/o/r.git\"\n\
             auto_converge = true\nconverge_prune = true\n",
        )
        .unwrap();
        let rec = cfg.reconcile.unwrap();
        assert!(rec.auto_converge);
        assert!(rec.converge_prune);
    }

    #[test]
    fn keyring_candidates_are_profile_first_then_flat() {
        // A named profile tries `<profile>/<item>` first, then the flat item
        // (back-compat) — so two keychain-backed profiles no longer collide.
        assert_eq!(
            keyring_candidates("token_secret", Some("prod")),
            vec!["prod/token_secret".to_string(), "token_secret".to_string()],
        );
        // No profile (flat/default config) → only the flat key, unchanged.
        assert_eq!(
            keyring_candidates("password", None),
            vec!["password".to_string()],
        );
    }
}

#[cfg(test)]
mod config_error_tests {
    use super::*;

    /// All variants must be downcastable from an `anyhow::Error` chain.
    /// This is what `main.rs::typed_exit` does on the boundary; if the
    /// downcast breaks (e.g. someone wraps via `anyhow!("…: {e}")`
    /// which is a string, not a source) main.rs falls back to exit 1
    /// and the contract regresses silently.
    #[test]
    fn config_error_variants_carry_through_anyhow_chain() {
        let path = std::path::PathBuf::from("/nonexistent/config.toml");

        let not_found: anyhow::Error = ConfigError::NotFound { path: path.clone() }.into();
        assert!(
            not_found
                .chain()
                .any(|c| c.downcast_ref::<ConfigError>().is_some()),
            "NotFound should be downcast-recoverable from the anyhow chain"
        );

        let io: anyhow::Error = ConfigError::Io {
            path: path.clone(),
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        }
        .into();
        assert!(io.chain().any(|c| matches!(
            c.downcast_ref::<ConfigError>(),
            Some(ConfigError::Io { .. })
        )));

        // Build a real toml::de::Error so the Toml variant is exercised
        // end-to-end — synthesising one by hand is unstable across
        // toml crate versions, so go through the parser.
        let toml_err = toml::from_str::<toml::Value>("url = 8006\nuser =").unwrap_err();
        let toml: anyhow::Error = ConfigError::Toml {
            path,
            source: toml_err,
        }
        .into();
        assert!(toml.chain().any(|c| matches!(
            c.downcast_ref::<ConfigError>(),
            Some(ConfigError::Toml { .. })
        )));
    }

    /// The fixed exit code is documented in
    /// `docs/reference/exit-codes.md` as part of the public CLI
    /// contract. Lock it here so a typo in a future audit doesn't
    /// silently change the value scripts depend on.
    #[test]
    fn config_error_exit_code_is_three() {
        assert_eq!(ConfigError::EXIT_CODE, 3);
    }

    /// `load_config` of a path that doesn't exist must surface a
    /// `NotFound` variant — main.rs's chain walker depends on this
    /// shape. We can't easily override the resolved `config_dir` from
    /// inside the test (it uses `directories::ProjectDirs`), so this
    /// only exercises the variant-construction path, not the path
    /// resolution. Path resolution belongs to a higher-level
    /// integration test (`tests/cli_init_integration.rs` covers it).
    #[test]
    fn config_error_not_found_renders_actionable_message() {
        let path = std::path::PathBuf::from("/var/empty/config.toml");
        let e = ConfigError::NotFound { path };
        let msg = format!("{e}");
        assert!(msg.contains("Run `proxxx init`"), "got: {msg}");
        assert!(msg.contains("/var/empty/config.toml"));
    }
}

#[cfg(test)]
mod secret_file_tests {
    use super::*;

    #[test]
    fn token_secret_path_uses_secrets_subdir_and_profile() {
        let p = token_secret_path("pve");
        assert!(
            p.ends_with("secrets/pve.token"),
            "unexpected path: {}",
            p.display()
        );
    }

    #[test]
    fn write_secret_file_round_trips_with_0600_and_no_temp_left() {
        let dir = std::env::temp_dir().join(format!("proxxx-secret-test-{}", std::process::id()));
        let path = dir.join("pve.token");
        let written = write_secret_file(&path, "s3cr3t-token-value").expect("write secret");
        assert_eq!(written, path);
        assert_eq!(
            std::fs::read_to_string(&path).expect("read back"),
            "s3cr3t-token-value"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "secret file must be 0600");
        }
        assert!(
            !path.with_extension("token.tmp").exists(),
            "temp file leaked"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
