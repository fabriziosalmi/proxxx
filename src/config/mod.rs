pub mod watcher;
pub use watcher::ConfigHandle;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::util::path::expand_tilde;
use crate::util::secret::SecretString;

/// Profile configuration loaded from TOML
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfig {
    pub url: String,
    pub user: String,
    #[serde(default = "default_auth")]
    pub auth: String,
    pub token_id: Option<String>,
    pub token_secret: Option<SecretString>,
    pub token_secret_file: Option<String>,
    pub password: Option<SecretString>,
    /// Validate the cluster's TLS certificate. **Defaults to `true`**
    /// since v0.13.4 (audit 2026-09-09, #251): omitting the key used to
    /// mean `false`, so a minimal config silently accepted any
    /// certificate — including one presented by whoever sat between
    /// proxxx and the cluster, who then received the API token.
    ///
    /// Proxmox ships a self-signed certificate, so a fresh cluster needs
    /// either `verify_tls = false` (deliberate, and what `proxxx doctor`
    /// will flag as "ok for homelab, not for production") or
    /// `tls_pin_mode = "tofu"` to pin the leaf on first connect.
    ///
    /// The PBS block has defaulted to `true` all along; this aligns the
    /// two.
    #[serde(default = "default_verify_tls")]
    pub verify_tls: bool,
    /// Phase 13 / #320: opt-in TLS pinning. Set to `"tofu"` (case
    /// insensitive) to snapshot the cluster's leaf cert on first connect
    /// and refuse any subsequent cert that doesn't match via
    /// [`crate::api::tls_pin::PinnedLeafVerifier`]. When unset (the
    /// default), behaviour is unchanged — `verify_tls` alone controls
    /// trust. The cert is persisted at
    /// `<config_dir>/known_certs/<host>_<port>.der`; delete the file to
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
    pub mcp_token: Option<SecretString>,

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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct AlertRuleConfig {
    pub name: String,
    /// One of `"node_offline" | "storage_above" | "replication_failing"`.
    /// Unknown values cause the engine to skip the rule with a warn log.
    /// `trigger` is accepted as an alias: it is the name the documentation
    /// uses, so both spellings parse.
    #[serde(alias = "trigger")]
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
#[serde(deny_unknown_fields)]
pub struct PbsConfig {
    /// PBS API base URL, e.g. `"https://pbs.lan:8007"`.
    pub url: String,
    /// PBS user@realm, e.g. `"proxxx@pbs"`.
    pub user: String,
    /// API token id (the part after `!` in PBS speak), e.g. `"reader"`.
    pub token_id: String,
    /// Token secret. Resolution order matches `PROXXX_PBS_TOKEN_SECRET`
    /// env, then `token_secret_file`, then OS keychain.
    pub token_secret: Option<SecretString>,
    pub token_secret_file: Option<String>,
    /// TLS verification. Default true — PBS in homelabs often uses
    /// self-signed certs but we never silently disable verification.
    #[serde(default = "default_verify_tls_pbs")]
    pub verify_tls: bool,
    /// SHA-256 certificate fingerprint of the PBS server, e.g.
    /// `"AB:CD:…:23"`. When set, both [`crate::pbs::PbsClient`] (`#414`)
    /// and the `proxmox-backup-client` restore shell-out pin the server's
    /// leaf certificate via this fingerprint (allowing `verify_tls = true`
    /// against a self-signed PBS certificate). Get it from the PBS UI
    /// (Certificates) or `proxmox-backup-manager cert info`.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Optional API rate limit (req/s). Default 10.
    pub rate_limit: Option<u32>,
    /// Resolved profile name stamped by [`load_config_from_path`] (`None` for
    /// flat top-level config). Used to scope keychain lookups to
    /// `<profile>/pbs_token_secret` before falling back to `pbs_token_secret`.
    #[serde(skip)]
    pub profile_name: Option<String>,
}

const fn default_verify_tls_pbs() -> bool {
    true
}

/// See [`ProfileConfig::verify_tls`]. Separate from the PBS default only
/// because serde needs a path per field.
const fn default_verify_tls() -> bool {
    true
}

/// Compiled-in OS keychain store descriptor (`#319`, `#332`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeychainStoreInfo {
    /// `true` iff a persistent OS keychain store (`UntilDelete`) is compiled in.
    pub compiled: bool,
    /// Store identifier (`"macos-keychain"` or `"none"`).
    pub store: &'static str,
}

/// Report whether a real persistent OS keychain store is compiled into this
/// binary (`#319`, `#332`).
///
/// Queries `keyring::default::default_credential_builder().persistence()` on
/// macOS rather than relying on `cfg!` alone: `UntilDelete` indicates the
/// real macOS Security.framework keychain (`apple-native`), whereas
/// `EntryOnly` indicates `keyring`'s in-memory mock fallback.
// Non-macOS builds omit the runtime `keyring::default` query, making the body const-eligible on Linux only.
#[cfg_attr(
    not(all(feature = "keychain", target_os = "macos")),
    allow(clippy::missing_const_for_fn)
)]
#[must_use]
pub fn keychain_store_info() -> KeychainStoreInfo {
    #[cfg(all(feature = "keychain", target_os = "macos"))]
    {
        if matches!(
            keyring::default::default_credential_builder().persistence(),
            keyring::credential::CredentialPersistence::UntilDelete
        ) {
            return KeychainStoreInfo {
                compiled: true,
                store: "macos-keychain",
            };
        }
    }
    KeychainStoreInfo {
        compiled: false,
        store: "none",
    }
}

/// Outcome of querying a single `(service, account)` entry in the keychain (`#329`).
#[cfg(any(test, all(feature = "keychain", target_os = "macos")))]
#[cfg_attr(not(all(feature = "keychain", target_os = "macos")), allow(dead_code))]
#[derive(Debug, Clone)]
enum KeychainEntryOutcome {
    /// Entry found with a non-empty secret.
    Found(SecretString),
    /// Entry does not exist in the keychain.
    NotFound,
    /// Entry exists in the keychain but its value is empty.
    Empty,
    /// Access to the keychain item was denied (locked keychain or ACL refusal).
    AccessDenied(String),
    /// Other platform / store failure (never contains a secret value).
    Error(String),
}

#[cfg(any(test, all(feature = "keychain", target_os = "macos")))]
impl KeychainEntryOutcome {
    fn diagnostic_reason(&self) -> String {
        match self {
            Self::Found(_) => "found".to_string(),
            Self::NotFound => "not found".to_string(),
            Self::Empty => "empty".to_string(),
            Self::AccessDenied(msg) => {
                if msg.is_empty() {
                    "access denied".to_string()
                } else {
                    format!("access denied: {msg}")
                }
            }
            Self::Error(msg) => format!("error: {msg}"),
        }
    }
}

/// Test-only in-memory keychain override (`#319`, `#329`).
///
/// Compiled only under `#[cfg(test)]` so the release library API never exposes
/// an override hook and production lookups never acquire a global lock.
#[cfg(test)]
#[derive(Debug, Clone)]
enum TestKeychainMode {
    /// Simulate a compiled-in store backed by an in-memory map of
    /// `(service, account) -> KeychainEntryOutcome`.
    Entries(std::collections::HashMap<(String, String), KeychainEntryOutcome>),
    /// Simulate a build with no keychain store compiled in (Linux /
    /// `--no-default-features`).
    NoStoreCompiled,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct TestKeychainState {
    mode: Option<TestKeychainMode>,
    consult_count: usize,
}

#[cfg(test)]
static TEST_KEYCHAIN_STATE: std::sync::LazyLock<std::sync::RwLock<TestKeychainState>> =
    std::sync::LazyLock::new(|| std::sync::RwLock::new(TestKeychainState::default()));

/// RAII guard that installs a [`TestKeychainMode`] for the duration of a unit
/// test and restores the default state on drop. Serialise tests that construct
/// this guard with `#[serial_test::serial]`.
#[cfg(test)]
#[derive(Debug)]
struct TestKeychainGuard;

#[cfg(test)]
impl TestKeychainGuard {
    /// Install a [`TestKeychainMode`] and reset the consultation counter to `0`.
    #[must_use]
    fn install(mode: TestKeychainMode) -> Self {
        let mut guard = TEST_KEYCHAIN_STATE
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.mode = Some(mode);
        guard.consult_count = 0;
        Self
    }

    /// Number of times the underlying store was consulted while this guard was active.
    // Takes `&self` so callers must still hold the active `TestKeychainGuard` when reading the counter.
    #[allow(clippy::unused_self)]
    #[must_use]
    fn consult_count(&self) -> usize {
        let guard = TEST_KEYCHAIN_STATE
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.consult_count
    }
}

#[cfg(test)]
impl Drop for TestKeychainGuard {
    fn drop(&mut self) {
        let mut guard = TEST_KEYCHAIN_STATE
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.mode = None;
        guard.consult_count = 0;
    }
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
pub fn keyring_candidates(item: &str, profile: Option<&str>) -> Vec<String> {
    let mut names = Vec::with_capacity(2);
    if let Some(p) = profile {
        if !p.is_empty() {
            names.push(format!("{p}/{item}"));
        }
    }
    names.push(item.to_string());
    names
}

// Non-macOS non-test builds have no keychain store and never construct `Found`.
#[cfg_attr(
    not(any(test, all(feature = "keychain", target_os = "macos"))),
    allow(dead_code)
)]
enum KeychainLookupOutcome {
    Found(SecretString),
    Unavailable { summary: String },
}

#[cfg(all(feature = "keychain", target_os = "macos"))]
fn classify_keyring_error(err: &keyring::Error) -> KeychainEntryOutcome {
    match err {
        keyring::Error::NoEntry => KeychainEntryOutcome::NotFound,
        keyring::Error::NoStorageAccess(inner) => {
            KeychainEntryOutcome::AccessDenied(inner.to_string())
        }
        keyring::Error::PlatformFailure(inner) => {
            let msg = inner.to_string();
            let lower = msg.to_ascii_lowercase();
            if lower.contains("auth")
                || lower.contains("denied")
                || lower.contains("interaction is not allowed")
                || lower.contains("-25308")
                || lower.contains("-128")
            {
                KeychainEntryOutcome::AccessDenied(msg)
            } else {
                KeychainEntryOutcome::Error(msg)
            }
        }
        other => KeychainEntryOutcome::Error(other.to_string()),
    }
}

#[cfg(test)]
fn keyring_query_test_mode(
    service: &str,
    candidates: &[String],
    mode: TestKeychainMode,
) -> KeychainLookupOutcome {
    match mode {
        TestKeychainMode::NoStoreCompiled => KeychainLookupOutcome::Unavailable {
            summary: format!(
                "keychain (service `{service}`, accounts [{}]: no keychain store in this build)",
                candidates.join(", ")
            ),
        },
        TestKeychainMode::Entries(map) => {
            let mut per_account = Vec::with_capacity(candidates.len());
            for name in candidates {
                {
                    let mut guard = TEST_KEYCHAIN_STATE
                        .write()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    guard.consult_count += 1;
                }
                let outcome = map
                    .get(&(service.to_string(), name.clone()))
                    .cloned()
                    .unwrap_or(KeychainEntryOutcome::NotFound);
                if let KeychainEntryOutcome::Found(secret) = outcome {
                    if !secret.is_empty() {
                        return KeychainLookupOutcome::Found(secret);
                    }
                    per_account.push(format!("`{name}` (empty)"));
                } else {
                    per_account.push(format!("`{name}` ({})", outcome.diagnostic_reason()));
                }
            }
            KeychainLookupOutcome::Unavailable {
                summary: format!(
                    "keychain (service `{service}`, accounts [{}])",
                    per_account.join(", ")
                ),
            }
        }
    }
}

/// Resolve a keychain secret under service `"proxxx"`, trying
/// `<profile>/<item>` first and then flat `<item>` (`#319`, `#329`).
///
/// On failure, returns a formatted diagnostic naming service `"proxxx"`, every
/// account queried in order, and why each account did not yield a secret
/// (`not found`, `access denied`, or `no keychain store in this build`).
// Non-macOS builds omit the `spawn_blocking(...).await` keychain lookup.
#[cfg_attr(
    not(all(feature = "keychain", target_os = "macos")),
    allow(clippy::unused_async)
)]
async fn keyring_query_scoped(item: &str, profile: Option<&str>) -> KeychainLookupOutcome {
    const SERVICE: &str = "proxxx";
    let candidates = keyring_candidates(item, profile);

    #[cfg(test)]
    {
        let test_mode = {
            let guard = TEST_KEYCHAIN_STATE
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.mode.clone()
        };

        if let Some(mode) = test_mode {
            return keyring_query_test_mode(SERVICE, &candidates, mode);
        }
    }

    if !keychain_store_info().compiled {
        let accounts_list = candidates.join(", ");
        return KeychainLookupOutcome::Unavailable {
            summary: format!(
                "keychain (service `{SERVICE}`, accounts [{accounts_list}]: no keychain store in this build)"
            ),
        };
    }

    #[cfg(all(feature = "keychain", target_os = "macos"))]
    {
        let candidates_for_task = candidates.clone();
        let res = tokio::task::spawn_blocking(move || -> KeychainLookupOutcome {
            let mut per_account = Vec::with_capacity(candidates_for_task.len());
            for name in &candidates_for_task {
                let outcome = match keyring::Entry::new(SERVICE, name) {
                    Ok(entry) => match entry.get_password() {
                        Ok(pw) if pw.is_empty() => KeychainEntryOutcome::Empty,
                        Ok(pw) => KeychainEntryOutcome::Found(SecretString::new(pw)),
                        Err(ref e) => classify_keyring_error(e),
                    },
                    Err(ref e) => classify_keyring_error(e),
                };
                if let KeychainEntryOutcome::Found(secret) = outcome {
                    return KeychainLookupOutcome::Found(secret);
                }
                per_account.push(format!("`{name}` ({})", outcome.diagnostic_reason()));
            }
            KeychainLookupOutcome::Unavailable {
                summary: format!(
                    "keychain (service `{SERVICE}`, accounts [{}])",
                    per_account.join(", ")
                ),
            }
        })
        .await;

        match res {
            Ok(outcome) => outcome,
            Err(join_err) => KeychainLookupOutcome::Unavailable {
                summary: format!(
                    "keychain (service `{SERVICE}`, accounts [{}]: join error: {join_err})",
                    candidates.join(", ")
                ),
            },
        }
    }

    #[cfg(not(all(feature = "keychain", target_os = "macos")))]
    {
        let accounts_list = candidates.join(", ");
        KeychainLookupOutcome::Unavailable {
            summary: format!(
                "keychain (service `{SERVICE}`, accounts [{accounts_list}]: no keychain store in this build)"
            ),
        }
    }
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

fn env_var_secret_checked(name: &str) -> std::result::Result<SecretString, &'static str> {
    match std::env::var(name) {
        Err(std::env::VarError::NotPresent) => Err("unset"),
        Err(std::env::VarError::NotUnicode(_)) => Err("invalid UTF-8"),
        Ok(raw) => {
            if raw.len() > ENV_SECRET_MAX_BYTES {
                tracing::warn!(
                    "env var {name} is {} bytes — exceeds {ENV_SECRET_MAX_BYTES} cap, refusing",
                    raw.len()
                );
                return Err("exceeds 64 KiB cap");
            }
            if raw.is_empty() {
                return Err("empty");
            }
            Ok(SecretString::new(raw))
        }
    }
}

#[cfg(test)]
fn env_var_secret(name: &str) -> Option<SecretString> {
    env_var_secret_checked(name).ok()
}

enum SecretFileCheck {
    Loaded(SecretString),
    NotConfigured {
        diagnostic: String,
    },
    Failed {
        diagnostic: String,
        security_header: Option<String>,
        blocks_fallback: bool,
    },
}

fn check_secret_file(field_name: &str, raw_path: Option<&str>) -> SecretFileCheck {
    let Some(file_path) = raw_path else {
        return SecretFileCheck::NotConfigured {
            diagnostic: format!("{field_name} (not configured)"),
        };
    };
    let expanded = expand_tilde(file_path);
    let path = expanded.as_path();
    let expanded_str = path.display().to_string();
    if !path.exists() {
        return SecretFileCheck::Failed {
            diagnostic: format!("{field_name} '{file_path}' (expanded: '{expanded_str}': missing)"),
            security_header: None,
            blocks_fallback: true,
        };
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                let header = format!(
                    "Security Error: {field_name} '{file_path}' ({expanded_str}) has unsafe permissions {mode:04o}. Must be 0600 or stricter."
                );
                return SecretFileCheck::Failed {
                    diagnostic: format!(
                        "{field_name} '{file_path}' (expanded: '{expanded_str}': bad permissions {mode:04o} — unsafe permissions, must be 0600 or stricter)"
                    ),
                    security_header: Some(header),
                    blocks_fallback: true,
                };
            }
        }
    }

    match std::fs::read_to_string(path) {
        Ok(content) => {
            let trimmed = content.trim();
            if trimmed.is_empty() {
                SecretFileCheck::Failed {
                    diagnostic: format!(
                        "{field_name} '{file_path}' (expanded: '{expanded_str}': empty)"
                    ),
                    security_header: None,
                    blocks_fallback: false,
                }
            } else {
                SecretFileCheck::Loaded(SecretString::new(trimmed.to_string()))
            }
        }
        Err(e) => SecretFileCheck::Failed {
            diagnostic: format!(
                "{field_name} '{file_path}' (expanded: '{expanded_str}': read error: {e})"
            ),
            security_header: None,
            blocks_fallback: true,
        },
    }
}

fn format_sources_tried_error(
    headline: &str,
    security_header: Option<&str>,
    tried: &[String],
) -> anyhow::Error {
    let mut numbered = String::new();
    for (idx, item) in tried.iter().enumerate() {
        if idx > 0 {
            numbered.push_str("; ");
        }
        let _ = std::fmt::Write::write_fmt(&mut numbered, format_args!("{}. {item}", idx + 1));
    }
    if let Some(sec) = security_header {
        anyhow::anyhow!("{sec} {headline}. Sources tried in order: {numbered}")
    } else {
        anyhow::anyhow!("{headline}. Sources tried in order: {numbered}")
    }
}

impl PbsConfig {
    /// Resolve the token secret using the same hierarchy as the main
    /// Proxmox API: CLI override → env → inline → file → keychain (`#319`, `#329`).
    ///
    /// Async because the keychain branch runs via `spawn_blocking`.
    pub async fn resolve_token_secret(&self, cli_secret: Option<&str>) -> Result<SecretString> {
        let mut tried: Vec<String> = Vec::with_capacity(5);

        // 1. CLI flag
        match cli_secret {
            Some(s) if !s.is_empty() => return Ok(SecretString::from(s)),
            Some(_) => tried.push("CLI flag --pbs-token-secret (empty)".to_string()),
            None => tried.push("CLI flag --pbs-token-secret (not given)".to_string()),
        }

        // 2. Env var
        match env_var_secret_checked("PROXXX_PBS_TOKEN_SECRET") {
            Ok(val) => return Ok(val),
            Err(reason) => tried.push(format!("env var PROXXX_PBS_TOKEN_SECRET ({reason})")),
        }

        // 3. Inline key
        match self.token_secret {
            Some(ref s) if !s.is_empty() => return Ok(s.clone()),
            Some(_) => tried.push("inline pbs.token_secret (empty)".to_string()),
            None => tried.push("inline pbs.token_secret (absent)".to_string()),
        }

        // 4. Secret file
        let mut blocks_fallback = false;
        match check_secret_file("pbs.token_secret_file", self.token_secret_file.as_deref()) {
            SecretFileCheck::Loaded(secret) => return Ok(secret),
            SecretFileCheck::NotConfigured { diagnostic } => tried.push(diagnostic),
            SecretFileCheck::Failed {
                diagnostic,
                security_header: Some(sec),
                blocks_fallback: _,
            } => {
                tried.push(diagnostic);
                return Err(format_sources_tried_error(
                    "PBS token secret not found",
                    Some(&sec),
                    &tried,
                ));
            }
            SecretFileCheck::Failed {
                diagnostic,
                security_header: None,
                blocks_fallback: blocks,
            } => {
                tried.push(diagnostic);
                blocks_fallback = blocks;
            }
        }

        // 5. Keychain (`<profile>/pbs_token_secret`, then `pbs_token_secret`)
        match keyring_query_scoped("pbs_token_secret", self.profile_name.as_deref()).await {
            KeychainLookupOutcome::Found(val) if !blocks_fallback => return Ok(val),
            KeychainLookupOutcome::Found(_) => {
                let candidates =
                    keyring_candidates("pbs_token_secret", self.profile_name.as_deref());
                tried.push(format!(
                    "keychain (service `proxxx`, accounts [{}]: ignored because pbs.token_secret_file failed)",
                    candidates.join(", ")
                ));
            }
            KeychainLookupOutcome::Unavailable { summary } => tried.push(summary),
        }

        Err(format_sources_tried_error(
            "PBS token secret not found",
            None,
            &tried,
        ))
    }

    /// Build a [`crate::api::tls_pin::PinnedLeafVerifier`] when
    /// `fingerprint = "..."` is configured (`#414`).
    ///
    /// # Errors
    /// Returns an error if `fingerprint` is set to a malformed SHA-256 value.
    pub fn pinned_verifier(
        &self,
    ) -> Result<Option<std::sync::Arc<crate::api::tls_pin::PinnedLeafVerifier>>> {
        let Some(ref fp) = self.fingerprint else {
            return Ok(None);
        };
        let digest = crate::api::tls_pin::parse_sha256_fingerprint(fp)?;
        Ok(Some(std::sync::Arc::new(
            crate::api::tls_pin::PinnedLeafVerifier::from_fingerprint(digest),
        )))
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
#[serde(deny_unknown_fields)]
pub struct TelegramConfig {
    /// Inline plaintext token. Kept for lab setups; not recommended for
    /// prod — prefer `bot_token_file` (chmod 600) or the OS keychain.
    /// `SecretString`: redacted in `Debug`, zeroized on drop — this field
    /// was a plain `String` until v0.13.2, the only unwiped credential.
    pub bot_token: Option<SecretString>,
    /// Path to a file containing the bot token (only the token, no
    /// surrounding JSON). Must be `0600` permissions on Unix; proxxx
    /// refuses to read it otherwise.
    pub bot_token_file: Option<String>,
    /// Destination chat / channel id. Negative for groups & channels,
    /// positive for direct chats with the bot user.
    pub chat_id: String,
    /// Telegram numeric user ids allowed to approve or deny a HITL
    /// request. **Required for the HITL daemon to act on any callback.**
    ///
    /// The callback HMAC proves proxxx minted the keyboard; it does not
    /// establish who pressed the button. Without this list every member
    /// of `chat_id` — including anyone added to the group later — could
    /// approve a destructive operation, which then executes with the
    /// daemon's full PVE credentials (audit 2026-09-09, #249).
    ///
    /// Numeric ids only: a Telegram `username` is mutable and can be
    /// reassigned after release, so an allowlist keyed on handles is
    /// forgeable. Get yours by messaging `@userinfobot`.
    ///
    /// Absent or empty ⇒ the daemon refuses every callback and tells the
    /// operator to configure it. This is fail-closed by design.
    #[serde(default)]
    pub allowed_approvers: Option<Vec<i64>>,
    /// Resolved profile name stamped by [`load_config_from_path`] (`None` for
    /// flat top-level config). Used to scope keychain lookups to
    /// `<profile>/telegram_bot_token` before falling back to `telegram_bot_token`.
    #[serde(skip)]
    pub profile_name: Option<String>,
}

impl TelegramConfig {
    /// Resolve the bot token using the standard hierarchy (`#319`, `#329`):
    /// 1. `PROXXX_TELEGRAM_BOT_TOKEN` env var (capped at 64 KiB)
    /// 2. `bot_token_file` (with 0600 permission check on Unix)
    /// 3. Inline `bot_token` field
    /// 4. OS keychain entry (`<profile>/telegram_bot_token`, then `telegram_bot_token`)
    ///
    /// Returns [`SecretString`] so the heap bytes are wiped on drop and
    /// any `{:?}` prints `[REDACTED]`, matching the PVE/PBS pattern.
    pub async fn resolve_bot_token(&self) -> Result<SecretString> {
        let mut tried: Vec<String> = Vec::with_capacity(4);

        // 1. Env var
        match env_var_secret_checked("PROXXX_TELEGRAM_BOT_TOKEN") {
            Ok(val) => return Ok(val),
            Err(reason) => tried.push(format!("env var PROXXX_TELEGRAM_BOT_TOKEN ({reason})")),
        }

        // 2. Secret file
        let mut blocks_fallback = false;
        match check_secret_file("telegram.bot_token_file", self.bot_token_file.as_deref()) {
            SecretFileCheck::Loaded(secret) => return Ok(secret),
            SecretFileCheck::NotConfigured { diagnostic } => tried.push(diagnostic),
            SecretFileCheck::Failed {
                diagnostic,
                security_header: Some(sec),
                blocks_fallback: _,
            } => {
                tried.push(diagnostic);
                return Err(format_sources_tried_error(
                    "Telegram bot token not found",
                    Some(&sec),
                    &tried,
                ));
            }
            SecretFileCheck::Failed {
                diagnostic,
                security_header: None,
                blocks_fallback: blocks,
            } => {
                tried.push(diagnostic);
                blocks_fallback = blocks;
            }
        }

        // 3. Inline key
        match self.bot_token {
            Some(ref s) if !s.is_empty() && !blocks_fallback => return Ok(s.clone()),
            Some(ref s) if !s.is_empty() => {
                tried.push(
                    "inline telegram.bot_token (ignored because telegram.bot_token_file failed)"
                        .to_string(),
                );
            }
            Some(_) => tried.push("inline telegram.bot_token (empty)".to_string()),
            None => tried.push("inline telegram.bot_token (absent)".to_string()),
        }

        // 4. Keychain (`<profile>/telegram_bot_token`, then `telegram_bot_token`)
        match keyring_query_scoped("telegram_bot_token", self.profile_name.as_deref()).await {
            KeychainLookupOutcome::Found(val) if !blocks_fallback => return Ok(val),
            KeychainLookupOutcome::Found(_) => {
                let candidates =
                    keyring_candidates("telegram_bot_token", self.profile_name.as_deref());
                tried.push(format!(
                    "keychain (service `proxxx`, accounts [{}]: ignored because telegram.bot_token_file failed)",
                    candidates.join(", ")
                ));
            }
            KeychainLookupOutcome::Unavailable { summary } => tried.push(summary),
        }

        Err(format_sources_tried_error(
            "Telegram bot token not found",
            None,
            &tried,
        ))
    }
}

/// SSH layer config (SSH layer). Optional per-profile.
///
/// Auth is key-based only. Password is intentionally unsupported —
/// a Proxmox node with password-only SSH is a security smell we won't enable.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshConfig {
    /// SSH user on the Proxmox node (default: "root")
    #[serde(default = "default_ssh_user")]
    pub user: String,

    /// Path to private key (e.g. "~/.`ssh/proxxx_homelab`"). Tilde-expanded.
    pub key_path: Option<String>,

    /// Per-node hostname/IP override. Key = node name, value = `host:port` or `host` form.
    /// When omitted for a node, `proxxx` falls back to the host in the profile's `url`
    /// (port 22) ONLY if that node is the one answering the API (`/cluster/status`
    /// `local = true`, or the single node of a standalone install) and verifies the
    /// remote hostname before running any command (`#328`). Every non-API node of a
    /// cluster requires an explicit entry here.
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
#[serde(deny_unknown_fields)]
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

/// Source of a resolved Proxmox VE node SSH target (`#328`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshHostSource {
    /// Explicit entry in `[ssh].hosts` (`hosts = { <node> = "<host>:<port>" }`).
    ExplicitHosts,
    /// Fallback to the host in the profile's `url` (port 22) because `node`
    /// is the node answering the API (`/cluster/status` `local = true`, or
    /// the single node of a standalone install).
    ApiUrlFallback,
    /// Pre-`#328` fallback to `(node.to_string(), 22)` (DNS / `/etc/hosts`
    /// resolution by node name) for non-API cluster nodes or when
    /// `/cluster/status` is unavailable.
    NodeNameFallback,
}

/// Resolved SSH connection target for a Proxmox VE node (`#328`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNodeSsh {
    pub host: String,
    pub port: u16,
    pub source: SshHostSource,
}

/// Extract the bare host (IPv4, unbracketed IPv6 literal, or DNS name) from an
/// API `url` (`#328`).
///
/// Unbrackets IPv6 literals (e.g. `https://[::1]:8006` -> `"::1"`) so the
/// returned string can be passed directly to `(host.as_str(), port)` socket
/// resolution.
#[must_use]
pub fn extract_url_host(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let raw = parsed.host_str()?.trim();
    let stripped = raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(raw);
    if stripped.is_empty() {
        None
    } else {
        Some(stripped.to_string())
    }
}

/// Parse an `[ssh].hosts` value (`"<host>:<port>"`, `"<host>"`, `"[<ipv6>]:<port>"`,
/// or `"[<ipv6>]"`) into `(host, port)`, defaulting the port to `22` (`#328`).
#[must_use]
pub fn parse_ssh_host_spec(spec: &str) -> (String, u16) {
    if let Some(rest) = spec.strip_prefix('[') {
        if let Some((ipv6, port_str)) = rest.split_once("]:") {
            if let Ok(port) = port_str.parse::<u16>() {
                return (ipv6.to_string(), port);
            }
        }
        if let Some(ipv6) = rest.strip_suffix(']') {
            return (ipv6.to_string(), 22);
        }
    }
    if spec.bytes().filter(|&b| b == b':').count() > 1 {
        return (spec.to_string(), 22);
    }
    if let Some((h, p)) = spec.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return (h.to_string(), port);
        }
    }
    (spec.to_string(), 22)
}

/// Determine the node answering the API from `/cluster/status` entries (`#328`):
/// 1. The node entry with `local = true`, or
/// 2. The single node entry of a standalone install (no `type == "cluster"` entry
///    and exactly one node entry).
#[must_use]
pub fn api_local_node_from_status(
    entries: &[crate::api::types::ClusterStatusEntry],
) -> Option<String> {
    let node_entries: Vec<&crate::api::types::ClusterStatusEntry> = entries
        .iter()
        .filter(|e| e.entry_type != "cluster" && !e.name.is_empty())
        .collect();

    if let Some(local_entry) = node_entries.iter().find(|e| e.local) {
        return Some(local_entry.name.clone());
    }

    let has_cluster_entry = entries.iter().any(|e| e.entry_type == "cluster");
    if !has_cluster_entry && node_entries.len() == 1 {
        return Some(node_entries[0].name.clone());
    }

    None
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

    /// Look up an explicit `[ssh].hosts` entry for `node` (`#328`).
    ///
    /// Returns `Some((host, port))` when `hosts[node]` is configured, or `None`
    /// when no explicit entry exists for `node`.
    #[must_use]
    pub fn resolve_explicit_host(&self, node: &str) -> Option<(String, u16)> {
        self.hosts.get(node).map(|spec| parse_ssh_host_spec(spec))
    }

    /// Resolve the SSH `(host, port, source)` target for `node` (`#328`).
    ///
    /// Resolution order:
    /// 1. `self.hosts[node]` (always wins, no `/cluster/status` lookup needed).
    /// 2. The host from `api_url` on port `22`, **only if** `node` is the node
    ///    answering the API (`api_local_node == Some(node)`).
    /// 3. `(node.to_string(), 22)` (`SshHostSource::NodeNameFallback`, pre-`#328`
    ///    behaviour) for every other node or when `/cluster/status` is
    ///    unavailable.
    #[must_use]
    pub fn resolve_host(
        &self,
        node: &str,
        api_url: Option<&str>,
        api_local_node: Option<&str>,
    ) -> ResolvedNodeSsh {
        if let Some((host, port)) = self.resolve_explicit_host(node) {
            return ResolvedNodeSsh {
                host,
                port,
                source: SshHostSource::ExplicitHosts,
            };
        }

        if api_local_node.is_some_and(|local| local == node) {
            if let Some(url_host) = api_url.and_then(extract_url_host) {
                return ResolvedNodeSsh {
                    host: url_host,
                    port: 22,
                    source: SshHostSource::ApiUrlFallback,
                };
            }
        }

        ResolvedNodeSsh {
            host: node.to_string(),
            port: 22,
            source: SshHostSource::NodeNameFallback,
        }
    }

    /// Convenience wrapper around [`Self::resolve_host`] that extracts the
    /// API-local node from `/cluster/status` entries (`#328`).
    #[must_use]
    pub fn resolve_host_with_status(
        &self,
        node: &str,
        api_url: &str,
        cluster_status: &[crate::api::types::ClusterStatusEntry],
    ) -> ResolvedNodeSsh {
        let local_node = api_local_node_from_status(cluster_status);
        self.resolve_host(node, Some(api_url), local_node.as_deref())
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

    /// Reject values for enum-like string keys that are neither of the
    /// documented options (audit 2026-09-09, #255).
    ///
    /// `auth_method()` above maps anything that is not exactly
    /// `"password"` to token auth, so `auth = "Password"` or a typo
    /// silently switched authentication mode: the operator supplied a
    /// password, got token auth, and the secret chain then either failed
    /// with a message that never mentioned `auth`, or picked up a
    /// `PROXXX_TOKEN_SECRET` left over from another profile and
    /// authenticated as a different identity.
    ///
    /// Validated at load rather than in `auth_method` so the failure
    /// names the key and its accepted values, once, before anything
    /// tries to connect.
    ///
    /// # Errors
    /// When a key holds a value outside its documented set.
    /// Warn when a lower-precedence secret source is shadowed by a
    /// higher one (audit 2026-09-09, #257).
    ///
    /// The resolution order is inline-then-file, and both the README and
    /// the configuration reference stated the opposite until v0.13.4. An
    /// operator following the production checklist's advice to move a
    /// secret into a `0600` file, without deleting the inline value,
    /// therefore kept using the inline one: the file was never read, and
    /// rotating it had no effect.
    ///
    /// The order itself is left alone — changing it would silently swap
    /// which credential a live deployment authenticates with, which is a
    /// worse failure than the one being fixed. Instead the shadowing is
    /// made visible at load.
    pub fn warn_on_shadowed_secret_sources(&self) {
        let inline_set = |s: &Option<crate::util::secret::SecretString>| {
            s.as_ref().is_some_and(|v| !v.expose().trim().is_empty())
        };
        if inline_set(&self.token_secret) && self.token_secret_file.is_some() {
            tracing::warn!(
                "config: both `token_secret` (inline) and `token_secret_file` are set. \
                 Inline wins — the file is NOT read, and rotating it will have no \
                 effect. Delete the inline value to use the file."
            );
        }
        if let Some(pbs) = &self.pbs {
            if inline_set(&pbs.token_secret) && pbs.token_secret_file.is_some() {
                tracing::warn!(
                    "config: both `pbs.token_secret` (inline) and \
                     `pbs.token_secret_file` are set. Inline wins — the file is NOT \
                     read. Delete the inline value to use the file."
                );
            }
        }
        if let Some(tg) = &self.telegram {
            if inline_set(&tg.bot_token) && tg.bot_token_file.is_some() {
                tracing::warn!(
                    "config: both `telegram.bot_token` (inline) and \
                     `telegram.bot_token_file` are set. Inline wins — the file is \
                     NOT read. Delete the inline value to use the file."
                );
            }
        }
    }

    pub fn validate_enum_like_fields(&self) -> Result<()> {
        const AUTH_VALUES: &[&str] = &["token", "password"];
        if !AUTH_VALUES.contains(&self.auth.as_str()) {
            return Err(ConfigError::InvalidValue(format!(
                "config key `auth` is {:?}, which is not a recognised value. \
                 Accepted: {}. Note the comparison is case-sensitive.",
                self.auth,
                AUTH_VALUES.join(" | ")
            ))
            .into());
        }
        if let Some(mode) = self.tls_pin_mode.as_deref() {
            if !mode.trim().is_empty() && !mode.eq_ignore_ascii_case("tofu") {
                return Err(ConfigError::InvalidValue(format!(
                    "config key `tls_pin_mode` is {mode:?}, which is not a recognised \
                     value. Accepted: \"tofu\" (case-insensitive), or omit the key \
                     entirely for no pinning. Refusing rather than silently running \
                     unpinned — you set this key because the default trust posture \
                     was not enough."
                ))
                .into());
            }
        }
        if let Some(ref pbs) = self.pbs {
            pbs.pinned_verifier()
                .map_err(|e| ConfigError::InvalidValue(e.to_string()))?;
        }
        Ok(())
    }

    pub async fn resolve_token_secret(&self, cli_secret: Option<&str>) -> Result<SecretString> {
        let mut tried: Vec<String> = Vec::with_capacity(5);

        // 1. CLI Flag
        match cli_secret {
            Some(secret) if !secret.is_empty() => return Ok(SecretString::from(secret)),
            Some(_) => tried.push("CLI flag --token-secret (empty)".to_string()),
            None => tried.push("CLI flag --token-secret (not given)".to_string()),
        }

        // 2. Environment variable (— 64 KiB cap)
        match env_var_secret_checked("PROXXX_TOKEN_SECRET") {
            Ok(val) => return Ok(val),
            Err(reason) => tried.push(format!("env var PROXXX_TOKEN_SECRET ({reason})")),
        }

        // 3. Inline `token_secret = "..."` in the config file.
        match self.token_secret {
            Some(ref s) if !s.is_empty() => return Ok(s.clone()),
            Some(_) => tried.push("inline token_secret (empty)".to_string()),
            None => tried.push("inline token_secret (absent)".to_string()),
        }

        // 4. Secure File
        let mut blocks_fallback = false;
        match check_secret_file("token_secret_file", self.token_secret_file.as_deref()) {
            SecretFileCheck::Loaded(secret) => return Ok(secret),
            SecretFileCheck::NotConfigured { diagnostic } => tried.push(diagnostic),
            SecretFileCheck::Failed {
                diagnostic,
                security_header: Some(sec),
                blocks_fallback: _,
            } => {
                tried.push(diagnostic);
                return Err(format_sources_tried_error(
                    "Token secret not found",
                    Some(&sec),
                    &tried,
                ));
            }
            SecretFileCheck::Failed {
                diagnostic,
                security_header: None,
                blocks_fallback: blocks,
            } => {
                tried.push(diagnostic);
                blocks_fallback = blocks;
            }
        }

        // 5. OS Keychain (`<profile>/token_secret`, then `token_secret`)
        match keyring_query_scoped("token_secret", self.profile_name.as_deref()).await {
            KeychainLookupOutcome::Found(val) if !blocks_fallback => return Ok(val),
            KeychainLookupOutcome::Found(_) => {
                let candidates = keyring_candidates("token_secret", self.profile_name.as_deref());
                tried.push(format!(
                    "keychain (service `proxxx`, accounts [{}]: ignored because token_secret_file failed)",
                    candidates.join(", ")
                ));
            }
            KeychainLookupOutcome::Unavailable { summary } => tried.push(summary),
        }

        Err(format_sources_tried_error(
            "Token secret not found",
            None,
            &tried,
        ))
    }

    /// Resolve password from env, config, or keychain (`#319`, `#329`).
    ///
    /// Resolution order — env > inline config > keychain — matches
    /// `resolve_token_secret` so operators get the SAME precedence
    /// rules regardless of which auth method their profile uses.
    pub async fn resolve_password(&self) -> Result<SecretString> {
        let mut tried: Vec<String> = Vec::with_capacity(3);

        // 1. Environment variable
        match env_var_secret_checked("PROXXX_PASSWORD") {
            Ok(val) => return Ok(val),
            Err(reason) => tried.push(format!("env var PROXXX_PASSWORD ({reason})")),
        }

        // 2. Inline `password = "..."`
        match self.password {
            Some(ref pw) if !pw.is_empty() => return Ok(pw.clone()),
            Some(_) => tried.push("inline password (empty)".to_string()),
            None => tried.push("inline password (absent)".to_string()),
        }

        // 3. OS Keychain (`<profile>/password`, then `password`)
        match keyring_query_scoped("password", self.profile_name.as_deref()).await {
            KeychainLookupOutcome::Found(val) => return Ok(val),
            KeychainLookupOutcome::Unavailable { summary } => tried.push(summary),
        }

        Err(format_sources_tried_error(
            "Password not found",
            None,
            &tried,
        ))
    }

    /// Resolved profile label (`#346`, Decision 1): returns the effective
    /// profile name (`--profile <name>`, top-level `default = "<name>"`, or
    /// the sole `[profiles.<name>]` entry), falling back to `"default"` ONLY
    /// for a flat top-level config (no `[profiles]` table selected).
    #[must_use]
    pub fn profile_label(&self) -> &str {
        match self.profile_name.as_deref() {
            Some(name) if !name.is_empty() => name,
            _ => "default",
        }
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

    /// The requested `--profile <name>` (or `default = "<name>"`) does
    /// not exist under `[profiles]` in `config.toml`.
    #[error("Profile '{profile}' not found in config. Known profiles: {known}")]
    UnknownProfile { profile: String, known: String },

    /// Multi-profile `config.toml` with no flat top-level `url`/`user`,
    /// no `default = "<name>"`, and no `--profile <name>` passed.
    #[error(
        "no default profile and this config has no flat top-level connection. \
         Available profiles: {available}. Re-run with `--profile <name>` (e.g. \
         `proxxx --profile {example} ls nodes`), aggregate all of them read-only with \
         `proxxx fleet`, or set a top-level `default = \"<name>\"` in config.toml."
    )]
    NoDefaultProfile { available: String, example: String },

    /// Deserializing the `[defaults]` table into [`DefaultsConfigSchema`]
    /// failed — e.g. an unknown field or a type mismatch inside `[defaults]`.
    #[error("Failed to parse [defaults] from {path}: {source}")]
    DefaultsParse {
        path: std::path::PathBuf,
        #[source]
        source: toml::de::Error,
    },

    /// Deserializing the selected profile table (or flat config) into
    /// [`ProfileConfig`] failed — e.g. a required field (`url`, `user`)
    /// is missing or has the wrong type.
    #[error(
        "Failed to parse{} profile from {path}: {source}",
        profile.as_deref().map_or_else(String::new, |n| format!(" '{n}'"))
    )]
    ProfileParse {
        profile: Option<String>,
        path: std::path::PathBuf,
        #[source]
        source: toml::de::Error,
    },

    /// A configuration field holds a value outside its documented set
    /// (e.g. `auth` or `tls_pin_mode`).
    #[error("{0}")]
    InvalidValue(String),

    /// `proxxx pbs ...` was invoked on a profile that has no PBS table.
    #[error(
        "no [{}] block configured — add url, user, token_id, token_secret(_file)",
        profile.as_deref().map_or_else(|| "pbs".to_string(), |p| format!("profiles.{p}.pbs"))
    )]
    MissingPbsConfig { profile: Option<String> },

    /// `state apply` or `reconcile converge` was invoked with a declared
    /// state file whose `[meta] profile` differs from the resolved target
    /// profile (`#346`, Decision 3), without `--allow-profile-mismatch`.
    #[error(
        "refusing to apply state from `{source_desc}`: [meta] declares profile '{declared}', \
         but the active target profile is '{target}'. Pass `--profile {declared}` to target \
         that cluster, or `--allow-profile-mismatch` if applying across profiles is intentional."
    )]
    ProfileMismatch {
        source_desc: String,
        declared: String,
        target: String,
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
    // #268 — see util::durable.
    crate::util::durable::rename_durable(&tmp, path)
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
    load_config_from_path(&config_path, profile_name)
}

/// Schema used strictly to validate the top-level `[defaults]` table (`#331`).
///
/// Every non-secret, non-`url` field from [`ProfileConfig`] is optional here so
/// `[defaults]` can provide any subset of shared keys. `#[serde(deny_unknown_fields)]`
/// guarantees that an unknown key in `[defaults]` or in one of its sub-tables
/// (`[defaults.ssh]`, `[defaults.pbs]`, `[defaults.telegram]`, `[defaults.reconcile]`,
/// `[[defaults.policies]]`, `[[defaults.alerts]]`) is caught before merging and
/// reported via [`ConfigError::DefaultsParse`] naming `[defaults]` directly.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DefaultsConfigSchema {
    #[allow(dead_code)]
    user: Option<String>,
    auth: Option<String>,
    #[allow(dead_code)]
    token_id: Option<String>,
    #[allow(dead_code)]
    verify_tls: Option<bool>,
    tls_pin_mode: Option<String>,
    #[allow(dead_code)]
    read_only: Option<bool>,
    #[allow(dead_code)]
    rate_limit: Option<u32>,
    #[allow(dead_code)]
    policies: Option<Vec<crate::hitl::policy::Policy>>,
    #[allow(dead_code)]
    telegram: Option<DefaultsTelegramSchema>,
    #[allow(dead_code)]
    ssh: Option<SshConfig>,
    pbs: Option<DefaultsPbsSchema>,
    #[allow(dead_code)]
    alerts: Option<Vec<AlertRuleConfig>>,
    #[allow(dead_code)]
    reconcile: Option<DefaultsReconcileSchema>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DefaultsTelegramSchema {
    #[allow(dead_code)]
    chat_id: Option<String>,
    #[allow(dead_code)]
    allowed_approvers: Option<Vec<i64>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DefaultsPbsSchema {
    #[allow(dead_code)]
    url: Option<String>,
    #[allow(dead_code)]
    user: Option<String>,
    #[allow(dead_code)]
    token_id: Option<String>,
    #[allow(dead_code)]
    verify_tls: Option<bool>,
    fingerprint: Option<String>,
    #[allow(dead_code)]
    rate_limit: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DefaultsReconcileSchema {
    #[allow(dead_code)]
    source: Option<String>,
    #[allow(dead_code)]
    path: Option<String>,
    #[allow(dead_code)]
    interval_secs: Option<u64>,
    #[allow(dead_code)]
    auto_converge: Option<bool>,
    #[allow(dead_code)]
    converge_prune: Option<bool>,
    #[allow(dead_code)]
    allowed_families: Option<Vec<String>>,
    #[allow(dead_code)]
    max_unmanned_changes: Option<u32>,
}

/// Validate the top-level `[defaults]` table (`#331`):
/// 1. `defaults` must be a TOML table.
/// 2. `url` is forbidden in `[defaults]` (each profile has its own endpoint).
/// 3. Secret keys (`token_secret`, `token_secret_file`, `password`, `mcp_token`,
///    plus `pbs.token_secret`, `pbs.token_secret_file`, `telegram.bot_token`,
///    `telegram.bot_token_file`) are forbidden in `[defaults]` so a single
///    credential is not silently shared across every node.
/// 4. Unknown keys and type mismatches are rejected via [`DefaultsConfigSchema`]
///    and wrapped in [`ConfigError::DefaultsParse`] naming `[defaults]`.
fn validate_defaults_value<'a>(
    defaults_val: &'a toml::Value,
    config_path: &std::path::Path,
) -> Result<&'a toml::map::Map<String, toml::Value>> {
    let Some(table) = defaults_val.as_table() else {
        return Err(ConfigError::InvalidValue(format!(
            "config key `defaults` in {} must be a `[defaults]` table, not a scalar or array",
            config_path.display()
        ))
        .into());
    };

    if table.contains_key("url") {
        return Err(ConfigError::InvalidValue(format!(
            "`url` is not allowed in `[defaults]` ({}): each profile under `[profiles.<name>]` \
             must declare its own cluster `url`",
            config_path.display()
        ))
        .into());
    }

    const TOP_LEVEL_SECRET_KEYS: &[&str] =
        &["token_secret", "token_secret_file", "password", "mcp_token"];
    for &secret_key in TOP_LEVEL_SECRET_KEYS {
        if table.contains_key(secret_key) {
            return Err(ConfigError::InvalidValue(format!(
                "secret key `{secret_key}` is not allowed in `[defaults]` ({}): credentials must \
                 be configured per-profile under `[profiles.<name>]`, via `PROXXX_*` environment \
                 variables, or in the OS keychain so one secret is not silently shared across every node",
                config_path.display()
            ))
            .into());
        }
    }

    if let Some(pbs_table) = table.get("pbs").and_then(toml::Value::as_table) {
        for &secret_key in &["token_secret", "token_secret_file"] {
            if pbs_table.contains_key(secret_key) {
                return Err(ConfigError::InvalidValue(format!(
                    "secret key `pbs.{secret_key}` is not allowed in `[defaults]` ({}): credentials \
                     must be configured per-profile under `[profiles.<name>.pbs]`, via \
                     `PROXXX_PBS_TOKEN_SECRET`, or in the OS keychain",
                    config_path.display()
                ))
                .into());
            }
        }
    }

    if let Some(tg_table) = table.get("telegram").and_then(toml::Value::as_table) {
        for &secret_key in &["bot_token", "bot_token_file"] {
            if tg_table.contains_key(secret_key) {
                return Err(ConfigError::InvalidValue(format!(
                    "secret key `telegram.{secret_key}` is not allowed in `[defaults]` ({}): \
                     credentials must be configured per-profile under `[profiles.<name>.telegram]`, \
                     via `PROXXX_TELEGRAM_BOT_TOKEN`, or in the OS keychain",
                    config_path.display()
                ))
                .into());
            }
        }
    }

    let parsed: DefaultsConfigSchema =
        defaults_val
            .clone()
            .try_into()
            .map_err(|source| ConfigError::DefaultsParse {
                path: config_path.to_path_buf(),
                source,
            })?;

    if let Some(ref auth) = parsed.auth {
        const AUTH_VALUES: &[&str] = &["token", "password"];
        if !AUTH_VALUES.contains(&auth.as_str()) {
            return Err(ConfigError::InvalidValue(format!(
                "`[defaults]` key `auth` is {auth:?}, which is not a recognised value. \
                 Accepted: {}. Note the comparison is case-sensitive.",
                AUTH_VALUES.join(" | ")
            ))
            .into());
        }
    }

    if let Some(ref mode) = parsed.tls_pin_mode {
        if !mode.trim().is_empty() && !mode.eq_ignore_ascii_case("tofu") {
            return Err(ConfigError::InvalidValue(format!(
                "`[defaults]` key `tls_pin_mode` is {mode:?}, which is not a recognised value. \
                 Accepted: \"tofu\" (case-insensitive), or omit the key entirely for no pinning."
            ))
            .into());
        }
    }

    if let Some(ref pbs) = parsed.pbs {
        if let Some(ref fp) = pbs.fingerprint {
            if !fp.trim().is_empty() {
                crate::api::tls_pin::parse_sha256_fingerprint(fp).map_err(|e| {
                    ConfigError::InvalidValue(format!(
                        "invalid `[defaults.pbs]` fingerprint {fp:?}: {e}"
                    ))
                })?;
            }
        }
    }

    Ok(table)
}

/// Merge `[defaults]` into a single `[profiles.<name>]` table (`#331`, Decision A1):
/// - A key set in the profile always wins.
/// - Sub-tables (`[ssh]`, `[pbs]`, `[telegram]`, `[reconcile]`) merge **one level
///   deep**: missing keys in `[profiles.<name>.<sub>]` are filled from
///   `[defaults.<sub>]`, while any nested table inside `<sub>` (such as
///   `ssh.hosts` or `ssh.guests`) is taken whole from the profile if present,
///   else from defaults (no recursive map merge).
/// - Arrays (`policies`, `alerts`) are NOT merged: a profile's array replaces
///   the default array wholesale.
fn merge_defaults_into_profile(
    defaults: &toml::map::Map<String, toml::Value>,
    profile: &mut toml::map::Map<String, toml::Value>,
) {
    for (key, default_val) in defaults {
        match profile.get_mut(key) {
            None => {
                profile.insert(key.clone(), default_val.clone());
            }
            Some(toml::Value::Table(profile_subtable)) => {
                if let toml::Value::Table(default_subtable) = default_val {
                    for (subkey, default_subval) in default_subtable {
                        if !profile_subtable.contains_key(subkey) {
                            profile_subtable.insert(subkey.clone(), default_subval.clone());
                        }
                    }
                }
            }
            Some(_) => {
                // Scalar, array (`policies`, `alerts`), or non-table value in
                // the profile always wins over `[defaults]`.
            }
        }
    }
}

pub fn load_config_from_path(
    config_path: &std::path::Path,
    profile_name: Option<&str>,
) -> Result<ProfileConfig> {
    if !config_path.exists() {
        return Err(ConfigError::NotFound {
            path: config_path.to_path_buf(),
        }
        .into());
    }

    let content = std::fs::read_to_string(config_path).map_err(|source| ConfigError::Io {
        path: config_path.to_path_buf(),
        source,
    })?;

    let raw: toml::Value = toml::from_str(&content).map_err(|source| ConfigError::Toml {
        path: config_path.to_path_buf(),
        source,
    })?;

    // Validate `[defaults]` up front (before profile resolution) so forbidden
    // keys (`url`, secrets) or unknown keys inside `[defaults]` fail with a
    // `ConfigError` naming `[defaults]` regardless of which profile is active.
    let defaults_table: Option<toml::map::Map<String, toml::Value>> =
        if let Some(defaults_val) = raw.get("defaults") {
            Some(validate_defaults_value(defaults_val, config_path)?.clone())
        } else {
            None
        };

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
        let mut pval = raw
            .get("profiles")
            .and_then(|p| p.get(name))
            .cloned()
            .ok_or_else(|| {
                let known = profile_names(&raw);
                let known_str = if known.is_empty() {
                    "(none defined)".to_string()
                } else {
                    known.join(", ")
                };
                ConfigError::UnknownProfile {
                    profile: name.to_string(),
                    known: known_str,
                }
            })?;
        if let (Some(ref defaults), Some(profile_map)) = (&defaults_table, pval.as_table_mut()) {
            merge_defaults_into_profile(defaults, profile_map);
        }
        pval
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
                return Err(ConfigError::NoDefaultProfile {
                    available: names.join(", "),
                    example: names[0].clone(),
                }
                .into());
            }
        }
        // Flat top-level config (backwards compat). Strip the [profiles]
        // and [defaults] tables before deserializing so unknown-field errors
        // don't fire on ProfileConfig (`#[serde(deny_unknown_fields)]`).
        // `[defaults]` was already schema-validated above; emit a warning so
        // an operator with a flat config knows `[defaults]` only applies to
        // `[profiles.<name>]` entries.
        let mut v = raw;
        if let Some(t) = v.as_table_mut() {
            t.remove("profiles");
            if t.remove("defaults").is_some() {
                tracing::warn!(
                    "config: `[defaults]` table in {} is ignored because no `[profiles.<name>]` \
                     profile is active (flat top-level config mode)",
                    config_path.display()
                );
            }
        }
        v
    };

    let mut cfg: ProfileConfig =
        profile_value
            .try_into()
            .map_err(|source| ConfigError::ProfileParse {
                profile: effective.clone(),
                path: config_path.to_path_buf(),
                source,
            })?;
    // Stamp the resolved profile name so a client built from this config
    // knows which cluster it talks to (used by the per-profile incident
    // freeze). `None` for the flat/default config — that client respects
    // only the global lock. Note this is `effective`, not the raw CLI arg,
    // so a `default = "x"` key or single-profile auto-default is attributed.
    cfg.profile_name = effective;
    if let Some(ref mut pbs) = cfg.pbs {
        pbs.profile_name.clone_from(&cfg.profile_name);
    }
    if let Some(ref mut tg) = cfg.telegram {
        tg.profile_name.clone_from(&cfg.profile_name);
    }
    cfg.validate_enum_like_fields()?;
    cfg.warn_on_shadowed_secret_sources();
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
    let content = std::fs::read_to_string(&path).map_err(|source| ConfigError::Io {
        path: path.clone(),
        source,
    })?;
    let raw: toml::Value = toml::from_str(&content).map_err(|source| ConfigError::Toml {
        path: path.clone(),
        source,
    })?;
    if let Some(defaults_val) = raw.get("defaults") {
        validate_defaults_value(defaults_val, &path)?;
    }
    Ok(profile_names(&raw))
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
mod unknown_field_tests {
    use super::ProfileConfig;

    #[test]
    fn rejects_stale_ssh_key_name() {
        let err = toml::from_str::<ProfileConfig>(
            r#"
url = "https://pve.example:8006"
user = "root@pam"

[ssh]
key = "~/.ssh/id_ed25519"
"#,
        )
        .expect_err("the stale key name must not be silently ignored");

        let message = err.to_string();
        assert!(
            message.contains("unknown field `key`") || message.contains("unknown field 'key'"),
            "expected an actionable unknown-field error, got: {message}"
        );
    }

    #[test]
    fn rejects_unknown_key_in_policy() {
        let err = toml::from_str::<ProfileConfig>(
            r#"
url = "https://pve.example:8006"
user = "root@pam"

[[policies]]
action = "delete"
target = "*"
channel = "telegram"
require = 2
requires = 3
"#,
        )
        .expect_err("a misspelled policy key must not be silently ignored");

        let message = err.to_string();
        assert!(
            message.contains("unknown field `requires`"),
            "expected an actionable unknown-field error, got: {message}"
        );
    }

    #[test]
    fn accepts_documented_ssh_key_path() {
        let config = toml::from_str::<ProfileConfig>(
            r#"
url = "https://pve.example:8006"
user = "root@pam"

[ssh]
key_path = "~/.ssh/id_ed25519"
"#,
        )
        .expect("the documented key_path field must parse");

        assert_eq!(
            config.ssh.and_then(|ssh| ssh.key_path),
            Some("~/.ssh/id_ed25519".to_string())
        );
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

    fn write_temp_config(tag: &str, body: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "proxxx-cfg-err-test-{}-{tag}.toml",
            std::process::id()
        ));
        std::fs::write(&path, body).expect("write temp config");
        path
    }

    #[test]
    fn unknown_profile_downcasts_to_config_error() {
        let path = write_temp_config(
            "unknown-profile",
            "[profiles.prod]\nurl = \"https://pve.example:8006\"\nuser = \"root@pam\"\n",
        );
        let err = load_config_from_path(&path, Some("typo")).expect_err("unknown profile");
        let _ = std::fs::remove_file(&path);
        assert!(
            err.chain()
                .any(|c| c.downcast_ref::<ConfigError>().is_some()),
            "unknown profile error must downcast to ConfigError (exit 3), got: {err:#}"
        );
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Profile 'typo' not found in config") && msg.contains("prod"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn no_default_profile_downcasts_to_config_error() {
        let path = write_temp_config(
            "no-default",
            "[profiles.alpha]\nurl = \"https://a:8006\"\nuser = \"root@pam\"\n\
             [profiles.beta]\nurl = \"https://b:8006\"\nuser = \"root@pam\"\n",
        );
        let err = load_config_from_path(&path, None).expect_err("no default profile");
        let _ = std::fs::remove_file(&path);
        assert!(
            err.chain()
                .any(|c| c.downcast_ref::<ConfigError>().is_some()),
            "no-default-profile error must downcast to ConfigError (exit 3), got: {err:#}"
        );
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no default profile") && msg.contains("alpha, beta"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn missing_required_field_downcasts_to_config_error() {
        let path = write_temp_config(
            "missing-field",
            "[profiles.incomplete]\nurl = \"https://pve.example:8006\"\n",
        );
        let err =
            load_config_from_path(&path, Some("incomplete")).expect_err("missing required field");
        let _ = std::fs::remove_file(&path);
        assert!(
            err.chain()
                .any(|c| c.downcast_ref::<ConfigError>().is_some()),
            "missing required field error must downcast to ConfigError (exit 3), got: {err:#}"
        );
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Failed to parse 'incomplete' profile") && msg.contains("user"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn validate_enum_like_fields_downcasts_to_config_error() {
        let path = write_temp_config(
            "bad-auth",
            "[profiles.prod]\nurl = \"https://pve.example:8006\"\nuser = \"root@pam\"\nauth = \"Password\"\n",
        );
        let err = load_config_from_path(&path, Some("prod")).expect_err("invalid auth enum");
        let _ = std::fs::remove_file(&path);
        assert!(
            err.chain()
                .any(|c| c.downcast_ref::<ConfigError>().is_some()),
            "validate_enum_like_fields auth error must downcast to ConfigError (exit 3), got: {err:#}"
        );

        let path_tls = write_temp_config(
            "bad-tls-pin",
            "[profiles.prod]\nurl = \"https://pve.example:8006\"\nuser = \"root@pam\"\ntls_pin_mode = \"invalid\"\n",
        );
        let err_tls =
            load_config_from_path(&path_tls, Some("prod")).expect_err("invalid tls_pin_mode");
        let _ = std::fs::remove_file(&path_tls);
        assert!(
            err_tls
                .chain()
                .any(|c| c.downcast_ref::<ConfigError>().is_some()),
            "validate_enum_like_fields tls_pin_mode error must downcast to ConfigError (exit 3), got: {err_tls:#}"
        );
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

// Executable proof for security-invariants row 14 (Injection · env-var
// secrets capped at ENV_SECRET_MAX_BYTES to prevent OOM via ENV). The
// matrix previously cited only the constant. Env vars are process-global
// and integration tests run in parallel, so each test uses a UNIQUE name
// to avoid cross-test races.
#[cfg(test)]
mod env_secret_cap_tests {
    use super::{env_var_secret, ENV_SECRET_MAX_BYTES};

    #[test]
    fn over_cap_is_refused() {
        let name = "PROXXX_TEST_ENV_CAP_OVER";
        let oversized = "x".repeat(ENV_SECRET_MAX_BYTES + 1);
        std::env::set_var(name, &oversized);
        assert!(
            env_var_secret(name).is_none(),
            "a value one byte over the cap must be refused (OOM guard)"
        );
        std::env::remove_var(name);
    }

    #[test]
    fn at_cap_is_accepted() {
        let name = "PROXXX_TEST_ENV_CAP_AT";
        let at_cap = "y".repeat(ENV_SECRET_MAX_BYTES);
        std::env::set_var(name, &at_cap);
        let got = env_var_secret(name).expect("a value exactly at the cap must be accepted");
        assert_eq!(got.expose().len(), ENV_SECRET_MAX_BYTES);
        std::env::remove_var(name);
    }

    #[test]
    fn empty_is_none() {
        let name = "PROXXX_TEST_ENV_CAP_EMPTY";
        std::env::set_var(name, "");
        assert!(
            env_var_secret(name).is_none(),
            "an empty env var must resolve to None, not an empty secret"
        );
        std::env::remove_var(name);
    }

    #[test]
    fn normal_value_round_trips() {
        let name = "PROXXX_TEST_ENV_CAP_OK";
        std::env::set_var(name, "a-normal-token-value");
        let got = env_var_secret(name).expect("a normal-sized value resolves");
        assert_eq!(got.expose(), "a-normal-token-value");
        std::env::remove_var(name);
    }
}

#[cfg(test)]
mod tls_default_tests {
    use super::ProfileConfig;

    /// #251 — a profile that omits `verify_tls` must validate the
    /// cluster certificate. Before v0.13.4 the bare `#[serde(default)]`
    /// on a bool made omission mean "accept any certificate", so a
    /// minimal config silently trusted whatever cert it was handed.
    #[test]
    fn verify_tls_defaults_to_true_when_omitted() {
        let toml = r#"
url = "https://pve.example:8006"
user = "root@pam"
token_id = "proxxx"
"#;
        let cfg: ProfileConfig = toml::from_str(toml).expect("parses");
        assert!(
            cfg.verify_tls,
            "omitting verify_tls must not disable certificate validation"
        );
    }

    /// The opt-out still works — it just has to be stated.
    #[test]
    fn verify_tls_false_is_still_honoured() {
        let toml = r#"
url = "https://pve.example:8006"
user = "root@pam"
verify_tls = false
"#;
        let cfg: ProfileConfig = toml::from_str(toml).expect("parses");
        assert!(!cfg.verify_tls);
    }
}

#[cfg(test)]
mod enum_like_validation_tests {
    use super::ProfileConfig;

    fn parse(toml_src: &str) -> ProfileConfig {
        toml::from_str(toml_src).expect("parses")
    }

    const BASE: &str = r#"
url = "https://pve.example:8006"
user = "root@pam"
"#;

    /// #255 — `auth_method()` maps anything that is not exactly
    /// "password" to token auth, so a typo silently switched mode. The
    /// value is now rejected at load, naming the key.
    #[test]
    fn unrecognised_auth_value_is_refused() {
        for bad in ["Password", "pasword", "tokne", "PAM", ""] {
            let cfg = parse(&format!("{BASE}auth = \"{bad}\"\n"));
            let err = cfg
                .validate_enum_like_fields()
                .expect_err("must refuse {bad:?}");
            let msg = format!("{err}");
            assert!(
                msg.contains("auth") && msg.contains("token | password"),
                "the error must name the key and its accepted values, got: {msg}"
            );
        }
    }

    #[test]
    fn documented_auth_values_are_accepted() {
        for good in ["token", "password"] {
            let cfg = parse(&format!("{BASE}auth = \"{good}\"\n"));
            cfg.validate_enum_like_fields()
                .unwrap_or_else(|e| panic!("{good} must be accepted: {e}"));
        }
        // Omitted entirely -> serde default, which must also be valid.
        parse(BASE)
            .validate_enum_like_fields()
            .expect("the default auth value must itself be valid");
    }

    /// #255 — a misspelled `tls_pin_mode` used to warn (to a log file
    /// nobody reads) and run unpinned. The operator set the key because
    /// the default trust posture was not enough.
    #[test]
    fn unrecognised_tls_pin_mode_is_refused() {
        for bad in ["TOFU ", "pin", "tofu2", "on"] {
            let cfg = parse(&format!("{BASE}tls_pin_mode = \"{bad}\"\n"));
            assert!(
                cfg.validate_enum_like_fields().is_err(),
                "must refuse tls_pin_mode = {bad:?}"
            );
        }
    }

    #[test]
    fn tofu_is_accepted_case_insensitively_and_absence_is_fine() {
        for good in ["tofu", "TOFU", "ToFu"] {
            let cfg = parse(&format!("{BASE}tls_pin_mode = \"{good}\"\n"));
            cfg.validate_enum_like_fields()
                .unwrap_or_else(|e| panic!("{good} must be accepted: {e}"));
        }
        parse(BASE)
            .validate_enum_like_fields()
            .expect("omitting tls_pin_mode means no pinning, which is valid");
    }
}

#[cfg(test)]
mod keychain_and_secret_resolution_tests {
    use super::*;
    use crate::cli::doctor::check_keychain_for_store;
    use std::collections::HashMap;

    fn clear_secret_env_vars() {
        std::env::remove_var("PROXXX_TOKEN_SECRET");
        std::env::remove_var("PROXXX_PASSWORD");
        std::env::remove_var("PROXXX_PBS_TOKEN_SECRET");
        std::env::remove_var("PROXXX_TELEGRAM_BOT_TOKEN");
    }

    /// Test 1 (`#319`, macOS-only): the compiled default credential builder
    /// reports `CredentialPersistence::UntilDelete` (real macOS Security.framework
    /// store via `apple-native`), not `EntryOnly` (keyring's in-memory mock).
    #[cfg(all(feature = "keychain", target_os = "macos"))]
    #[test]
    fn macos_default_credential_builder_reports_persistent_store() {
        assert!(
            matches!(
                keyring::default::default_credential_builder().persistence(),
                keyring::credential::CredentialPersistence::UntilDelete
            ),
            "macOS build must wire keyring with apple-native (UntilDelete persistence), not the EntryOnly mock store"
        );
        let info = keychain_store_info();
        assert!(info.compiled, "keychain_store_info().compiled must be true");
        assert_eq!(info.store, "macos-keychain");
    }

    /// Test 5 (Linux / non-macOS native check): when not built on macOS with
    /// `keychain`, `keychain_store_info()` reports `compiled: false, store: "none"`.
    #[cfg(not(all(feature = "keychain", target_os = "macos")))]
    #[test]
    fn non_macos_keychain_store_info_reports_none() {
        let info = keychain_store_info();
        assert!(!info.compiled);
        assert_eq!(info.store, "none");
    }

    /// Test 2 (`#319` + consistent keychain account names):
    /// With an injected keychain (`TestKeychainGuard`), `load_config_from_path`
    /// stamps `profile_name` on `ProfileConfig`, `PbsConfig`, and `TelegramConfig`,
    /// and all four resolvers (`token_secret`, `password`, `pbs_token_secret`,
    /// `telegram_bot_token`) resolve `<profile>/<item>` first, then fall back to
    /// the flat `<item>` name.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_2_injected_keychain_resolves_profile_scoped_then_flat_names() {
        clear_secret_env_vars();

        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg_path = tmp.path().join("config.toml");
        std::fs::write(
            &cfg_path,
            r#"
default = "pve-test"

[profiles.pve-test]
url = "https://127.0.0.1:8006"
user = "root@pam"
token_id = "proxxx"

[profiles.pve-test.pbs]
url = "https://127.0.0.1:8007"
user = "backup@pbs"
token_id = "reader"

[profiles.pve-test.telegram]
chat_id = "12345"
"#,
        )
        .expect("write config.toml");

        let cfg = load_config_from_path(&cfg_path, None).expect("load config");
        assert_eq!(cfg.profile_name.as_deref(), Some("pve-test"));
        assert_eq!(
            cfg.pbs.as_ref().unwrap().profile_name.as_deref(),
            Some("pve-test")
        );
        assert_eq!(
            cfg.telegram.as_ref().unwrap().profile_name.as_deref(),
            Some("pve-test")
        );

        // 2a. Both `<profile>/<item>` and flat `<item>` present -> `<profile>/<item>` wins.
        let mut scoped_and_flat = HashMap::new();
        for (item, scoped_val, flat_val) in [
            ("token_secret", "pve-scoped-val", "pve-flat-val"),
            ("password", "pw-scoped-val", "pw-flat-val"),
            ("pbs_token_secret", "pbs-scoped-val", "pbs-flat-val"),
            ("telegram_bot_token", "tg-scoped-val", "tg-flat-val"),
        ] {
            scoped_and_flat.insert(
                ("proxxx".to_string(), format!("pve-test/{item}")),
                KeychainEntryOutcome::Found(SecretString::from(scoped_val)),
            );
            scoped_and_flat.insert(
                ("proxxx".to_string(), item.to_string()),
                KeychainEntryOutcome::Found(SecretString::from(flat_val)),
            );
        }
        {
            let guard = TestKeychainGuard::install(TestKeychainMode::Entries(scoped_and_flat));
            assert_eq!(
                cfg.resolve_token_secret(None).await.unwrap().expose(),
                "pve-scoped-val"
            );
            assert_eq!(
                cfg.resolve_password().await.unwrap().expose(),
                "pw-scoped-val"
            );
            assert_eq!(
                cfg.pbs
                    .as_ref()
                    .unwrap()
                    .resolve_token_secret(None)
                    .await
                    .unwrap()
                    .expose(),
                "pbs-scoped-val"
            );
            assert_eq!(
                cfg.telegram
                    .as_ref()
                    .unwrap()
                    .resolve_bot_token()
                    .await
                    .unwrap()
                    .expose(),
                "tg-scoped-val"
            );
            assert_eq!(
                guard.consult_count(),
                4,
                "each resolver must stop after the first hit on <profile>/<item>"
            );
        }

        // 2b. Only flat `<item>` present -> falls back to flat `<item>`.
        let mut flat_only = HashMap::new();
        for (item, flat_val) in [
            ("token_secret", "pve-flat-only"),
            ("password", "pw-flat-only"),
            ("pbs_token_secret", "pbs-flat-only"),
            ("telegram_bot_token", "tg-flat-only"),
        ] {
            flat_only.insert(
                ("proxxx".to_string(), item.to_string()),
                KeychainEntryOutcome::Found(SecretString::from(flat_val)),
            );
        }
        {
            let guard = TestKeychainGuard::install(TestKeychainMode::Entries(flat_only));
            assert_eq!(
                cfg.resolve_token_secret(None).await.unwrap().expose(),
                "pve-flat-only"
            );
            assert_eq!(
                cfg.resolve_password().await.unwrap().expose(),
                "pw-flat-only"
            );
            assert_eq!(
                cfg.pbs
                    .as_ref()
                    .unwrap()
                    .resolve_token_secret(None)
                    .await
                    .unwrap()
                    .expose(),
                "pbs-flat-only"
            );
            assert_eq!(
                cfg.telegram
                    .as_ref()
                    .unwrap()
                    .resolve_bot_token()
                    .await
                    .unwrap()
                    .expose(),
                "tg-flat-only"
            );
            assert_eq!(
                guard.consult_count(),
                8,
                "each resolver queries <profile>/<item> (miss) then <item> (hit)"
            );
        }
    }

    /// Test 3a (`#329`):
    /// With no source available, `ProfileConfig::resolve_token_secret`,
    /// `ProfileConfig::resolve_password`, `PbsConfig::resolve_token_secret`, and
    /// `TelegramConfig::resolve_bot_token` list every source tried in order,
    /// name every keychain account queried, and never print any secret value
    /// (verified with canary secrets in a decoy profile's keychain accounts).
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_3a_secret_not_found_lists_all_sources_in_order_and_leaks_no_canary() {
        clear_secret_env_vars();

        let canary_pve = "CANARY-PVE-SECRET-329-DO-NOT-PRINT";
        let canary_pw = "CANARY-PW-SECRET-329-DO-NOT-PRINT";
        let canary_pbs = "CANARY-PBS-SECRET-329-DO-NOT-PRINT";
        let canary_tg = "CANARY-TG-SECRET-329-DO-NOT-PRINT";

        let mut decoy_entries = HashMap::new();
        decoy_entries.insert(
            (
                "proxxx".to_string(),
                "other-profile/token_secret".to_string(),
            ),
            KeychainEntryOutcome::Found(SecretString::from(canary_pve)),
        );
        decoy_entries.insert(
            ("proxxx".to_string(), "other-profile/password".to_string()),
            KeychainEntryOutcome::Found(SecretString::from(canary_pw)),
        );
        decoy_entries.insert(
            (
                "proxxx".to_string(),
                "other-profile/pbs_token_secret".to_string(),
            ),
            KeychainEntryOutcome::Found(SecretString::from(canary_pbs)),
        );
        decoy_entries.insert(
            (
                "proxxx".to_string(),
                "other-profile/telegram_bot_token".to_string(),
            ),
            KeychainEntryOutcome::Found(SecretString::from(canary_tg)),
        );
        let _guard = TestKeychainGuard::install(TestKeychainMode::Entries(decoy_entries));

        let mut cfg: ProfileConfig = toml::from_str(
            r#"
url = "https://127.0.0.1:8006"
user = "root@pam"
token_id = "proxxx"

[pbs]
url = "https://127.0.0.1:8007"
user = "backup@pbs"
token_id = "reader"

[telegram]
chat_id = "12345"
"#,
        )
        .expect("parse profile");
        cfg.profile_name = Some("pve-test".to_string());
        cfg.pbs.as_mut().unwrap().profile_name = Some("pve-test".to_string());
        cfg.telegram.as_mut().unwrap().profile_name = Some("pve-test".to_string());

        // 1. PVE token_secret
        let pve_msg = format!("{:#}", cfg.resolve_token_secret(None).await.unwrap_err());
        let i_cli = pve_msg
            .find("1. CLI flag --token-secret (not given)")
            .expect(&pve_msg);
        let i_env = pve_msg
            .find("2. env var PROXXX_TOKEN_SECRET (unset)")
            .expect(&pve_msg);
        let i_inl = pve_msg
            .find("3. inline token_secret (absent)")
            .expect(&pve_msg);
        let i_fil = pve_msg
            .find("4. token_secret_file (not configured)")
            .expect(&pve_msg);
        let i_kc = pve_msg
            .find("5. keychain (service `proxxx`, accounts [`pve-test/token_secret` (not found), `token_secret` (not found)])")
            .expect(&pve_msg);
        assert!(i_cli < i_env && i_env < i_inl && i_inl < i_fil && i_fil < i_kc);
        assert!(!pve_msg.contains(canary_pve) && !pve_msg.contains("CANARY-"));

        // 2. PVE password
        let pw_msg = format!("{:#}", cfg.resolve_password().await.unwrap_err());
        assert!(
            pw_msg.contains("1. env var PROXXX_PASSWORD (unset)"),
            "{pw_msg}"
        );
        assert!(pw_msg.contains("2. inline password (absent)"), "{pw_msg}");
        assert!(
            pw_msg.contains("3. keychain (service `proxxx`, accounts [`pve-test/password` (not found), `password` (not found)])"),
            "{pw_msg}"
        );
        assert!(!pw_msg.contains(canary_pw) && !pw_msg.contains("CANARY-"));

        // 3. PBS token_secret
        let pbs_msg = format!(
            "{:#}",
            cfg.pbs
                .as_ref()
                .unwrap()
                .resolve_token_secret(None)
                .await
                .unwrap_err()
        );
        assert!(
            pbs_msg.contains("1. CLI flag --pbs-token-secret (not given)"),
            "{pbs_msg}"
        );
        assert!(
            pbs_msg.contains("2. env var PROXXX_PBS_TOKEN_SECRET (unset)"),
            "{pbs_msg}"
        );
        assert!(
            pbs_msg.contains("3. inline pbs.token_secret (absent)"),
            "{pbs_msg}"
        );
        assert!(
            pbs_msg.contains("4. pbs.token_secret_file (not configured)"),
            "{pbs_msg}"
        );
        assert!(
            pbs_msg.contains("5. keychain (service `proxxx`, accounts [`pve-test/pbs_token_secret` (not found), `pbs_token_secret` (not found)])"),
            "{pbs_msg}"
        );
        assert!(!pbs_msg.contains(canary_pbs) && !pbs_msg.contains("CANARY-"));

        // 4. Telegram bot_token
        let tg_msg = format!(
            "{:#}",
            cfg.telegram
                .as_ref()
                .unwrap()
                .resolve_bot_token()
                .await
                .unwrap_err()
        );
        assert!(
            tg_msg.contains("1. env var PROXXX_TELEGRAM_BOT_TOKEN (unset)"),
            "{tg_msg}"
        );
        assert!(
            tg_msg.contains("2. telegram.bot_token_file (not configured)"),
            "{tg_msg}"
        );
        assert!(
            tg_msg.contains("3. inline telegram.bot_token (absent)"),
            "{tg_msg}"
        );
        assert!(
            tg_msg.contains("4. keychain (service `proxxx`, accounts [`pve-test/telegram_bot_token` (not found), `telegram_bot_token` (not found)])"),
            "{tg_msg}"
        );
        assert!(!tg_msg.contains(canary_tg) && !tg_msg.contains("CANARY-"));
    }

    /// Test 3b (`#329`):
    /// Exercises `token_secret_file` diagnostics (`missing`, `bad permissions`,
    /// `empty`) and keychain `access denied` without leaking any file content.
    #[cfg(unix)]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_3b_secret_file_states_and_keychain_access_denied_diagnostics() {
        use std::os::unix::fs::PermissionsExt;

        clear_secret_env_vars();
        let tmp = tempfile::tempdir().expect("tempdir");

        let mut entries = HashMap::new();
        entries.insert(
            ("proxxx".to_string(), "pve-test/token_secret".to_string()),
            KeychainEntryOutcome::AccessDenied("User interaction is not allowed".to_string()),
        );
        let _guard = TestKeychainGuard::install(TestKeychainMode::Entries(entries));

        // 1. Missing file
        let missing_path = tmp.path().join("missing.token");
        let mut cfg: ProfileConfig = toml::from_str(&format!(
            "url = \"https://127.0.0.1:8006\"\nuser = \"root@pam\"\ntoken_secret_file = \"{}\"\n",
            missing_path.display()
        ))
        .unwrap();
        cfg.profile_name = Some("pve-test".to_string());
        let msg_missing = format!("{:#}", cfg.resolve_token_secret(None).await.unwrap_err());
        assert!(
            msg_missing.contains(": missing)")
                && msg_missing.contains(
                    "`pve-test/token_secret` (access denied: User interaction is not allowed)"
                )
                && msg_missing.contains("`token_secret` (not found)"),
            "unexpected missing-file diagnostic: {msg_missing}"
        );

        // 2. Bad permissions (0644) with a canary secret inside the file
        let lax_path = tmp.path().join("lax.token");
        let file_canary = "CANARY-LAX-FILE-SECRET-329";
        std::fs::write(&lax_path, file_canary).unwrap();
        std::fs::set_permissions(&lax_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        cfg.token_secret_file = Some(lax_path.display().to_string());
        let msg_lax = format!("{:#}", cfg.resolve_token_secret(None).await.unwrap_err());
        assert!(
            msg_lax.contains("bad permissions 0644") && msg_lax.contains("Must be 0600"),
            "unexpected bad-permissions diagnostic: {msg_lax}"
        );
        assert!(
            !msg_lax.contains(file_canary),
            "bad-permissions error must never print file contents: {msg_lax}"
        );

        // 3. Empty file (0600)
        let empty_path = tmp.path().join("empty.token");
        std::fs::write(&empty_path, "   \n").unwrap();
        std::fs::set_permissions(&empty_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        cfg.token_secret_file = Some(empty_path.display().to_string());
        let msg_empty = format!("{:#}", cfg.resolve_token_secret(None).await.unwrap_err());
        assert!(
            msg_empty.contains(": empty)")
                && msg_empty.contains(
                    "`pve-test/token_secret` (access denied: User interaction is not allowed)"
                )
                && msg_empty.contains("`token_secret` (not found)"),
            "unexpected empty-file diagnostic: {msg_empty}"
        );
    }

    /// Test 5 (`#319`, `#329`, `#332` Linux / no-store behaviour):
    /// - `check_keychain_for_store` with `compiled: false, store: "none"` reports
    ///   `warn` with `"no keychain store in this build (Linux): use token_secret_file or env"`.
    /// - When no store is compiled in (`TestKeychainMode::NoStoreCompiled`), none
    ///   of the four secret resolvers ever consults a store (`consult_count() == 0`)
    ///   and each reports `"no keychain store in this build"`.
    #[tokio::test]
    #[serial_test::serial]
    async fn test_5_linux_no_store_doctor_warn_and_resolvers_never_consult_store() {
        clear_secret_env_vars();

        let linux_check = check_keychain_for_store(
            KeychainStoreInfo {
                compiled: false,
                store: "none",
            },
            "Linux",
        );
        assert_eq!(linux_check["check"], "keychain");
        assert_eq!(linux_check["status"], "warn");
        assert_eq!(
            linux_check["message"],
            "no keychain store in this build (Linux): use token_secret_file or env"
        );

        let guard = TestKeychainGuard::install(TestKeychainMode::NoStoreCompiled);
        let mut cfg: ProfileConfig = toml::from_str(
            r#"
url = "https://127.0.0.1:8006"
user = "root@pam"
token_id = "proxxx"

[pbs]
url = "https://127.0.0.1:8007"
user = "backup@pbs"
token_id = "reader"

[telegram]
chat_id = "12345"
"#,
        )
        .expect("parse profile");
        cfg.profile_name = Some("pve-test".to_string());
        cfg.pbs.as_mut().unwrap().profile_name = Some("pve-test".to_string());
        cfg.telegram.as_mut().unwrap().profile_name = Some("pve-test".to_string());

        let pve_err = format!("{:#}", cfg.resolve_token_secret(None).await.unwrap_err());
        let pw_err = format!("{:#}", cfg.resolve_password().await.unwrap_err());
        let pbs_err = format!(
            "{:#}",
            cfg.pbs
                .as_ref()
                .unwrap()
                .resolve_token_secret(None)
                .await
                .unwrap_err()
        );
        let tg_err = format!(
            "{:#}",
            cfg.telegram
                .as_ref()
                .unwrap()
                .resolve_bot_token()
                .await
                .unwrap_err()
        );

        assert_eq!(
            guard.consult_count(),
            0,
            "resolver must never consult a keychain store when no store is compiled in"
        );
        for msg in [&pve_err, &pw_err, &pbs_err, &tg_err] {
            assert!(
                msg.contains("no keychain store in this build"),
                "expected 'no keychain store in this build', got: {msg}"
            );
        }
    }
}

#[cfg(test)]
mod defaults_merge_tests {
    use super::*;

    fn write_cfg(dir: &tempfile::TempDir, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.path().join(name);
        std::fs::write(&p, body).expect("write test config");
        p
    }

    /// Test 1 (`#331`): Two profiles sharing `user`, `token_id`, `verify_tls`
    /// and `[ssh] key_path`/`user` from `[defaults]`; each resolves its own
    /// `url`, the shared values, and its own `profile_label()`.
    #[test]
    fn test_1_two_profiles_share_defaults_scalars_and_ssh() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg_path = write_cfg(
            &tmp,
            "config.toml",
            r#"
default = "pve1"

[defaults]
user = "root@pam"
token_id = "proxxx"
verify_tls = false

[defaults.ssh]
user = "ops"
key_path = "~/.ssh/proxxx_ed25519"

[profiles.pve1]
url = "https://pve1.lan:8006"

[profiles.pve2]
url = "https://pve2.lan:8006"
"#,
        );

        let p1 = load_config_from_path(&cfg_path, Some("pve1")).expect("load pve1");
        assert_eq!(p1.url, "https://pve1.lan:8006");
        assert_eq!(p1.user, "root@pam");
        assert_eq!(p1.token_id.as_deref(), Some("proxxx"));
        assert!(!p1.verify_tls);
        assert_eq!(p1.profile_label(), "pve1");
        let p1_ssh = p1.ssh.as_ref().expect("pve1 ssh from defaults");
        assert_eq!(p1_ssh.user, "ops");
        assert_eq!(p1_ssh.key_path.as_deref(), Some("~/.ssh/proxxx_ed25519"));

        let p2 = load_config_from_path(&cfg_path, Some("pve2")).expect("load pve2");
        assert_eq!(p2.url, "https://pve2.lan:8006");
        assert_eq!(p2.user, "root@pam");
        assert_eq!(p2.token_id.as_deref(), Some("proxxx"));
        assert!(!p2.verify_tls);
        assert_eq!(p2.profile_label(), "pve2");
        let p2_ssh = p2.ssh.as_ref().expect("pve2 ssh from defaults");
        assert_eq!(p2_ssh.user, "ops");
        assert_eq!(p2_ssh.key_path.as_deref(), Some("~/.ssh/proxxx_ed25519"));

        // Default resolution (`profile_name = None`) selects `default = "pve1"`
        // and merges `[defaults]` identically.
        let p_default = load_config_from_path(&cfg_path, None).expect("load default profile");
        assert_eq!(p_default.url, "https://pve1.lan:8006");
        assert_eq!(p_default.profile_label(), "pve1");
    }

    /// Test 2 (`#331`): Precedence: a profile value beats the default, both for
    /// a top-level scalar (`user`, `verify_tls`, `rate_limit`) and for a key
    /// inside `[ssh]` (`user`, `key_path`).
    #[test]
    fn test_2_profile_values_beat_defaults_for_scalars_and_ssh_keys() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg_path = write_cfg(
            &tmp,
            "config.toml",
            r#"
[defaults]
user = "root@pam"
token_id = "shared-token"
verify_tls = false
rate_limit = 10

[defaults.ssh]
user = "root"
key_path = "~/.ssh/default_ed25519"
exec_timeout_secs = 60

[profiles.pve1]
url = "https://pve1.lan:8006"
user = "audit@pve"
verify_tls = true

[profiles.pve1.ssh]
user = "admin"
"#,
        );

        let p1 = load_config_from_path(&cfg_path, Some("pve1")).expect("load pve1");
        assert_eq!(p1.url, "https://pve1.lan:8006");
        assert_eq!(p1.user, "audit@pve", "profile scalar must beat [defaults]");
        assert!(p1.verify_tls, "profile verify_tls must beat [defaults]");
        assert_eq!(
            p1.token_id.as_deref(),
            Some("shared-token"),
            "unset scalar falls back to [defaults]"
        );
        assert_eq!(p1.rate_limit, Some(10));

        let ssh = p1.ssh.expect("merged ssh");
        assert_eq!(
            ssh.user, "admin",
            "profile [ssh].user must beat [defaults.ssh].user"
        );
        assert_eq!(
            ssh.key_path.as_deref(),
            Some("~/.ssh/default_ed25519"),
            "unset [ssh].key_path falls back to [defaults.ssh].key_path"
        );
        assert_eq!(ssh.exec_timeout_secs, 60);
    }

    /// Test 3 (`#331`): One-level table merge:
    /// - `[defaults.ssh] key_path` + `[profiles.X.ssh] hosts = {...}` -> both present.
    /// - `hosts` in both `[defaults.ssh]` and `[profiles.Y.ssh]` -> the profile's
    ///   `hosts` map wins whole (no recursive merge of nested maps).
    #[test]
    fn test_3_one_level_table_merge_and_nested_map_replacement() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg_path = write_cfg(
            &tmp,
            "config.toml",
            r#"
[defaults]
user = "root@pam"
token_id = "proxxx"

[defaults.ssh]
key_path = "~/.ssh/proxxx_ed25519"
hosts = { defaultnode = "10.0.0.99" }

[profiles.pve1]
url = "https://pve1.lan:8006"
[profiles.pve1.ssh]
user = "ops"

[profiles.pve2]
url = "https://pve2.lan:8006"
[profiles.pve2.ssh]
hosts = { pve2 = "10.0.0.2:2222" }
"#,
        );

        // pve1 omits `hosts` in `[profiles.pve1.ssh]`: inherits both `key_path`
        // and the `hosts` table whole from `[defaults.ssh]`.
        let p1 = load_config_from_path(&cfg_path, Some("pve1")).expect("load pve1");
        let ssh1 = p1.ssh.expect("pve1 ssh");
        assert_eq!(ssh1.user, "ops");
        assert_eq!(ssh1.key_path.as_deref(), Some("~/.ssh/proxxx_ed25519"));
        assert_eq!(ssh1.hosts.len(), 1);
        assert_eq!(
            ssh1.hosts.get("defaultnode").map(String::as_str),
            Some("10.0.0.99")
        );

        // pve2 sets `hosts` in `[profiles.pve2.ssh]`: keeps `key_path` from
        // `[defaults.ssh]`, and its `hosts` map replaces the default `hosts`
        // map wholesale (`defaultnode` is NOT merged in).
        let p2 = load_config_from_path(&cfg_path, Some("pve2")).expect("load pve2");
        let ssh2 = p2.ssh.expect("pve2 ssh");
        assert_eq!(ssh2.key_path.as_deref(), Some("~/.ssh/proxxx_ed25519"));
        assert_eq!(ssh2.hosts.len(), 1, "profile hosts map must win whole");
        assert_eq!(
            ssh2.hosts.get("pve2").map(String::as_str),
            Some("10.0.0.2:2222")
        );
        assert!(!ssh2.hosts.contains_key("defaultnode"));
    }

    /// Test 4 (`#331`): Arrays replace: `[[defaults.policies]]` +
    /// `[[profiles.X.policies]]` -> only the profile's array is kept (not concatenated).
    /// When a profile omits `policies` (or `alerts`), it inherits `[defaults]`'s array.
    #[test]
    fn test_4_arrays_replace_rather_than_append() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg_path = write_cfg(
            &tmp,
            "config.toml",
            r#"
[defaults]
user = "root@pam"
token_id = "proxxx"

[[defaults.policies]]
action = "delete"
target = "*"
channel = "telegram"
require = 1

[[defaults.alerts]]
name = "default_node_down"
when = "node_offline"
route = ["telegram"]

[profiles.inherits]
url = "https://pve1.lan:8006"

[profiles.overrides]
url = "https://pve2.lan:8006"

[[profiles.overrides.policies]]
action = "*"
target = "tag:prod"
channel = "telegram"
require = 2

[[profiles.overrides.alerts]]
name = "prod_storage_full"
when = "storage_above"
threshold_percent = 85
route = ["telegram"]
"#,
        );

        let inherited = load_config_from_path(&cfg_path, Some("inherits")).expect("inherits");
        let inh_pol = inherited.policies.expect("inherited policies");
        assert_eq!(inh_pol.len(), 1);
        assert_eq!(inh_pol[0].action, "delete");
        assert_eq!(inh_pol[0].require, 1);
        let inh_alerts = inherited.alerts.expect("inherited alerts");
        assert_eq!(inh_alerts.len(), 1);
        assert_eq!(inh_alerts[0].name, "default_node_down");

        let overridden = load_config_from_path(&cfg_path, Some("overrides")).expect("overrides");
        let ov_pol = overridden.policies.expect("overridden policies");
        assert_eq!(
            ov_pol.len(),
            1,
            "profile policies must replace default array"
        );
        assert_eq!(ov_pol[0].action, "*");
        assert_eq!(ov_pol[0].target, "tag:prod");
        assert_eq!(ov_pol[0].require, 2);

        let ov_alerts = overridden.alerts.expect("overridden alerts");
        assert_eq!(
            ov_alerts.len(),
            1,
            "profile alerts must replace default array"
        );
        assert_eq!(ov_alerts[0].name, "prod_storage_full");
    }

    /// Test 5 (`#331` unit level): Refusals for `url`, secrets, and unknown keys
    /// in `[defaults]`, all downcasting to `ConfigError` (`EXIT_CODE == 3`) and
    /// naming `defaults`.
    #[test]
    fn test_5_refusals_for_url_secrets_and_unknown_keys_in_defaults() {
        let tmp = tempfile::tempdir().expect("tempdir");

        let cases: &[(&str, &str, &str)] = &[
            (
                "url-in-defaults.toml",
                "[defaults]\nurl = \"https://pve1.lan:8006\"\nuser = \"root@pam\"\n\n[profiles.pve1]\nurl = \"https://pve1.lan:8006\"\n",
                "url",
            ),
            (
                "token-secret-in-defaults.toml",
                "[defaults]\nuser = \"root@pam\"\ntoken_secret = \"super-secret\"\n\n[profiles.pve1]\nurl = \"https://pve1.lan:8006\"\n",
                "token_secret",
            ),
            (
                "token-secret-file-in-defaults.toml",
                "[defaults]\nuser = \"root@pam\"\ntoken_secret_file = \"/etc/proxxx/tok\"\n\n[profiles.pve1]\nurl = \"https://pve1.lan:8006\"\n",
                "token_secret_file",
            ),
            (
                "password-in-defaults.toml",
                "[defaults]\nuser = \"root@pam\"\npassword = \"hunter2\"\n\n[profiles.pve1]\nurl = \"https://pve1.lan:8006\"\n",
                "password",
            ),
            (
                "mcp-token-in-defaults.toml",
                "[defaults]\nuser = \"root@pam\"\nmcp_token = \"bearer-xyz\"\n\n[profiles.pve1]\nurl = \"https://pve1.lan:8006\"\n",
                "mcp_token",
            ),
            (
                "pbs-secret-in-defaults.toml",
                "[defaults]\nuser = \"root@pam\"\n[defaults.pbs]\ntoken_secret = \"pbs-sec\"\n\n[profiles.pve1]\nurl = \"https://pve1.lan:8006\"\n",
                "pbs.token_secret",
            ),
            (
                "telegram-secret-in-defaults.toml",
                "[defaults]\nuser = \"root@pam\"\n[defaults.telegram]\nbot_token = \"tg-sec\"\n\n[profiles.pve1]\nurl = \"https://pve1.lan:8006\"\n",
                "telegram.bot_token",
            ),
            (
                "unknown-key-in-defaults.toml",
                "[defaults]\nuser = \"root@pam\"\nverfiy_tls = false\n\n[profiles.pve1]\nurl = \"https://pve1.lan:8006\"\n",
                "verfiy_tls",
            ),
            (
                "unknown-ssh-key-in-defaults.toml",
                "[defaults]\nuser = \"root@pam\"\n[defaults.ssh]\nkey = \"~/.ssh/id_ed25519\"\n\n[profiles.pve1]\nurl = \"https://pve1.lan:8006\"\n",
                "unknown field `key`",
            ),
        ];

        for &(filename, body, expected_needle) in cases {
            let path = write_cfg(&tmp, filename, body);
            let err = load_config_from_path(&path, Some("pve1"))
                .expect_err(&format!("{filename} must be rejected"));
            let cfg_err = err
                .chain()
                .find_map(|c| c.downcast_ref::<ConfigError>())
                .unwrap_or_else(|| panic!("{filename} must downcast to ConfigError: {err:#}"));
            assert_eq!(ConfigError::EXIT_CODE, 3);
            let msg = format!("{cfg_err}");
            assert!(
                msg.contains("defaults"),
                "{filename}: error message must name `defaults`, got: {msg}"
            );
            assert!(
                msg.contains(expected_needle),
                "{filename}: error message must contain `{expected_needle}`, got: {msg}"
            );
        }
    }

    #[test]
    fn flat_config_strips_valid_defaults_and_preserves_default_profile_label() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg_path = write_cfg(
            &tmp,
            "flat.toml",
            r#"
url = "https://pve-flat.lan:8006"
user = "root@pam"

[defaults]
verify_tls = false
"#,
        );

        let cfg = load_config_from_path(&cfg_path, None).expect("flat config loads");
        assert_eq!(cfg.url, "https://pve-flat.lan:8006");
        // Flat config ignores `[defaults]` (with a warning) rather than failing
        // on `deny_unknown_fields`, so `verify_tls` keeps its struct default (`true`).
        assert!(cfg.verify_tls);
        assert_eq!(cfg.profile_label(), "default");
    }
}
