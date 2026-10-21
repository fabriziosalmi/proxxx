//! `proxxx token bootstrap` — mint and store a Proxmox VE API token over SSH
//! without ever exposing the token secret to the terminal, logs, or audit trail (`#330`).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, info};
use zeroize::Zeroize;

use crate::api::ProxmoxGateway;
use crate::config::{HostKeyPolicy, ProfileConfig};
use crate::ssh::{ExecOptions, SshGateway, SshPool};
use crate::util::path::expand_tilde;
use crate::util::secret::SecretString;

/// CLI flags for `proxxx [--profile X] token bootstrap` (`#330`).
#[derive(Debug, Clone, Args)]
pub struct TokenBootstrapArgs {
    /// Proxmox user@realm to own the token (default: `user` from the profile).
    #[arg(long)]
    pub userid: Option<String>,
    /// API token identifier (default: `token_id` from the profile).
    #[arg(long)]
    pub tokenid: Option<String>,
    /// PVE role to grant on `--acl-path` via `pveum acl modify`.
    #[arg(long, default_value = "PVEAuditor")]
    pub role: String,
    /// PVE ACL path to grant `--role` on via `pveum acl modify`.
    #[arg(long = "acl-path", default_value = "/")]
    pub acl_path: String,
    /// Explicit SSH target `<host[:port]>` (default: host from the profile's `url` on port 22).
    #[arg(long = "ssh-host", value_name = "HOST[:PORT]")]
    pub ssh_host: Option<String>,
    /// Explicit file path to write the `0600` token secret to (overrides profile / keychain default).
    #[arg(long = "secret-file", value_name = "PATH")]
    pub secret_file: Option<PathBuf>,
    /// If the token or secret already exists, remove and recreate the token and overwrite the stored secret.
    #[arg(long)]
    pub rotate: bool,
    /// Required confirmation flag (`token bootstrap` mutates PVE tokens and ACLs over SSH).
    #[arg(long)]
    pub yes: bool,
}

/// Destination selected to persist the newly minted token secret (`#330`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretStoreTarget {
    /// Write to a `0600` file (parent directory created with `0700`, atomic rename).
    File(PathBuf),
    /// Store in the OS keychain under service `"proxxx"`, account `<profile>/<item>`.
    Keychain { profile: String, item: String },
}

/// Location where the secret was persisted (`#330`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoredSecretLocation {
    File(PathBuf),
    Keychain { service: String, account: String },
}

impl StoredSecretLocation {
    #[must_use]
    pub const fn store_kind(&self) -> &'static str {
        match self {
            Self::File(_) => "file",
            Self::Keychain { .. } => "macos-keychain",
        }
    }

    #[must_use]
    pub fn target_description(&self) -> String {
        match self {
            Self::File(path) => path.display().to_string(),
            Self::Keychain { service, account } => format!("{service}:{account}"),
        }
    }

    /// Read the secret back from the exact store location just written (`#330` Rev. 42 F1).
    ///
    /// Proves the write-then-read round-trip (including `0600` permission check on
    /// files) and yields the exact secret to pass as `cli_secret` to [`crate::api::PxClient::new`]
    /// so `PROXXX_TOKEN_SECRET` or inline config can never shadow it during verification.
    pub async fn read_back(&self) -> Result<SecretString> {
        match self {
            Self::File(path) => crate::config::read_secret_file_checked(path),
            Self::Keychain { service, account } => {
                crate::config::read_keychain_secret_checked(service, account).await
            }
        }
    }
}

/// Abstraction over persisting the bootstrapped token secret so unit tests can
/// exercise the full bootstrap flow and rollback behaviour without touching the
/// real OS keychain or user config directory (`#330`).
#[async_trait::async_trait]
pub trait BootstrapSecretStore: Send + Sync {
    /// Whether this binary has a persistent OS keychain compiled in.
    fn has_compiled_keychain(&self) -> bool;

    /// Persist `secret` into `target`. When `allow_overwrite` is `false`, must
    /// refuse if the target file or keychain entry already exists.
    async fn store(
        &self,
        target: &SecretStoreTarget,
        secret: &SecretString,
        allow_overwrite: bool,
    ) -> Result<StoredSecretLocation>;
}

/// Production [`BootstrapSecretStore`] backed by `0600` files and the macOS Keychain.
pub struct RealBootstrapSecretStore;

#[async_trait::async_trait]
impl BootstrapSecretStore for RealBootstrapSecretStore {
    fn has_compiled_keychain(&self) -> bool {
        crate::config::keychain_store_info().compiled
    }

    async fn store(
        &self,
        target: &SecretStoreTarget,
        secret: &SecretString,
        allow_overwrite: bool,
    ) -> Result<StoredSecretLocation> {
        match target {
            SecretStoreTarget::File(path) => {
                let written = crate::config::write_secret_file_checked(
                    path,
                    secret.expose(),
                    allow_overwrite,
                )?;
                Ok(StoredSecretLocation::File(written))
            }
            SecretStoreTarget::Keychain { profile, item } => {
                let (service, account) = crate::config::store_keychain_secret_checked(
                    profile,
                    item,
                    secret,
                    allow_overwrite,
                )
                .await?;
                Ok(StoredSecretLocation::Keychain { service, account })
            }
        }
    }
}

/// Outcome of verifying the newly bootstrapped token against the Proxmox REST API (`#330`).
#[derive(Debug, Clone, Serialize)]
pub struct BootstrapVerifyReport {
    pub ok: bool,
    pub version: Option<String>,
    pub release: Option<String>,
    pub nodes_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Abstraction over the post-bootstrap REST API verification (`GET /version` and `GET /nodes`).
#[async_trait::async_trait]
pub trait BootstrapVerifier: Send + Sync {
    async fn verify(
        &self,
        config: &ProfileConfig,
        userid: &str,
        tokenid: &str,
        stored: &StoredSecretLocation,
    ) -> BootstrapVerifyReport;
}

/// Production [`BootstrapVerifier`] that builds a [`crate::api::PxClient`] from the profile
/// and the newly stored secret, then runs `GET /version` and `GET /nodes`.
pub struct RealBootstrapVerifier;

#[async_trait::async_trait]
impl BootstrapVerifier for RealBootstrapVerifier {
    async fn verify(
        &self,
        config: &ProfileConfig,
        userid: &str,
        tokenid: &str,
        stored: &StoredSecretLocation,
    ) -> BootstrapVerifyReport {
        let round_tripped = match stored.read_back().await {
            Ok(s) => s,
            Err(e) => {
                return BootstrapVerifyReport {
                    ok: false,
                    version: None,
                    release: None,
                    nodes_count: None,
                    error: Some(format!("reading back stored secret failed: {e:#}")),
                };
            }
        };

        let mut verify_cfg = config.clone();
        verify_cfg.auth = "token".to_string();
        verify_cfg.user = userid.to_string();
        verify_cfg.token_id = Some(tokenid.to_string());
        verify_cfg.token_secret = None;
        verify_cfg.token_secret_file = None;

        // Pass the round-tripped secret explicitly as `cli_secret` (highest precedence
        // in `ProfileConfig::resolve_token_secret`) so `PROXXX_TOKEN_SECRET` in the
        // process environment can never shadow or substitute the secret being verified.
        let client = match crate::api::PxClient::new(verify_cfg, Some(round_tripped.expose())).await
        {
            Ok(c) => c,
            Err(e) => {
                return BootstrapVerifyReport {
                    ok: false,
                    version: None,
                    release: None,
                    nodes_count: None,
                    error: Some(format!("building API client failed: {e:#}")),
                };
            }
        };

        let ver_val = match client.get_api_version().await {
            Ok(v) => v,
            Err(e) => {
                return BootstrapVerifyReport {
                    ok: false,
                    version: None,
                    release: None,
                    nodes_count: None,
                    error: Some(format!("GET /version failed: {e:#}")),
                };
            }
        };
        let version = (!ver_val.version.is_empty()).then_some(ver_val.version);
        let release = (!ver_val.release.is_empty()).then_some(ver_val.release);

        match client.get_nodes().await {
            Ok(nodes) => BootstrapVerifyReport {
                ok: true,
                version,
                release,
                nodes_count: Some(nodes.len()),
                error: None,
            },
            Err(e) => BootstrapVerifyReport {
                ok: false,
                version,
                release,
                nodes_count: None,
                error: Some(format!("GET /nodes failed: {e:#}")),
            },
        }
    }
}

#[derive(Deserialize)]
struct PveumTokenListEntry {
    tokenid: String,
}

#[derive(Deserialize)]
struct PveumTokenAddResponse {
    value: SecretString,
}

/// Select where `token bootstrap` will store the new secret (`#330`):
/// 1. Explicit `--secret-file <path>` flag (tilde-expanded).
/// 2. `token_secret_file` on the profile, if set (tilde-expanded).
/// 3. macOS keychain `<profile>/token_secret` (service `proxxx`) when compiled in.
/// 4. `<config_dir>/secrets/<profile>.token`.
#[must_use]
pub fn select_secret_store_target(
    config: &ProfileConfig,
    args: &TokenBootstrapArgs,
    has_compiled_keychain: bool,
) -> SecretStoreTarget {
    if let Some(ref explicit_path) = args.secret_file {
        return SecretStoreTarget::File(expand_tilde(&explicit_path.to_string_lossy()));
    }
    if let Some(ref cfg_path) = config.token_secret_file {
        let trimmed = cfg_path.trim();
        if !trimmed.is_empty() {
            return SecretStoreTarget::File(expand_tilde(trimmed));
        }
    }
    let profile_label = config.profile_label().to_string();
    if has_compiled_keychain {
        return SecretStoreTarget::Keychain {
            profile: profile_label,
            item: "token_secret".to_string(),
        };
    }
    SecretStoreTarget::File(crate::config::token_secret_path(&profile_label))
}

/// Resolve the `(host, port)` SSH endpoint for `token bootstrap` (`#330`).
///
/// Uses `--ssh-host <host[:port]>` when passed, otherwise extracts the host from
/// the profile's `url` (port 22). No `/cluster/status` call and no remote
/// `hostname` check are performed because no API token exists yet.
pub fn resolve_bootstrap_ssh_endpoint(
    config: &ProfileConfig,
    ssh_host_override: Option<&str>,
) -> Result<(String, u16)> {
    if let Some(spec) = ssh_host_override.map(str::trim).filter(|s| !s.is_empty()) {
        return Ok(crate::config::parse_ssh_host_spec(spec));
    }
    let host = crate::config::extract_url_host(&config.url).ok_or_else(|| {
        anyhow::anyhow!(
            "cannot extract SSH host from profile url {:?}; pass `--ssh-host <host[:port]>`",
            config.url
        )
    })?;
    Ok((host, 22))
}

fn format_host_port_spec(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn validate_identifier(name: &str, value: &str, require_realm: bool) -> Result<()> {
    if value.is_empty() {
        anyhow::bail!("{name} must not be empty");
    }
    if require_realm && !value.contains('@') {
        anyhow::bail!("{name} {value:?} must include a realm (e.g. `root@pam` or `ops@pve`)");
    }
    if value.starts_with('-') {
        anyhow::bail!("{name} {value:?} must not start with '-'");
    }
    if value.chars().any(|c| {
        c.is_control()
            || c.is_whitespace()
            || matches!(c, '`' | '$' | ';' | '&' | '|' | '\'' | '"' | '\\' | '!')
    }) {
        anyhow::bail!("{name} contains forbidden shell or control characters — refusing");
    }
    Ok(())
}

fn validate_acl_path(path: &str) -> Result<()> {
    if !path.starts_with('/') {
        anyhow::bail!("--acl-path {path:?} must start with '/' (e.g. `/` or `/vms/100`)");
    }
    if path.chars().any(|c| {
        c.is_control()
            || c.is_whitespace()
            || matches!(c, '`' | '$' | ';' | '&' | '|' | '\'' | '"' | '\\')
    }) {
        anyhow::bail!("--acl-path contains forbidden shell or control characters — refusing");
    }
    Ok(())
}

/// Quote a single shell argument when needed; bare when strictly `[A-Za-z0-9@._/-]+`.
fn quote_arg(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '_' | '-' | '.' | '/'))
    {
        return s.to_string();
    }
    quote_single(s)
}

/// Always wrap `s` in single quotes (`'...'`), escaping internal `'` as `'\''`.
/// Used for `--tokens '<user>!<tokenid>'` so `!` is never interpreted by history
/// expansion or the remote shell (`#330`).
fn quote_single(s: &str) -> String {
    let escaped = s.replace('\'', "'\\''");
    format!("'{escaped}'")
}

/// Parse `pveum user token list <user> --output-format json` stdout and zeroize
/// the raw buffer immediately. Never echoes `stdout` on parse errors (`#330`).
fn parse_token_list_stdout(raw_stdout: &mut String) -> Result<Vec<PveumTokenListEntry>> {
    let res = serde_json::from_str::<Vec<PveumTokenListEntry>>(raw_stdout);
    raw_stdout.zeroize();
    res.map_err(|e| {
        anyhow::anyhow!(
            "failed to parse JSON from `pveum user token list` (line {}, column {}) — \
             raw stdout suppressed",
            e.line(),
            e.column()
        )
    })
}

/// Parse `pveum user token add <user> <tokenid> --privsep 1 --output-format json`
/// stdout straight into a [`SecretString`] and zeroize the raw buffer immediately.
/// Never echoes `stdout` on parse errors (`#330`).
fn parse_token_add_stdout(raw_stdout: &mut String) -> Result<SecretString> {
    let res = serde_json::from_str::<PveumTokenAddResponse>(raw_stdout);
    raw_stdout.zeroize();
    let parsed = res.map_err(|e| {
        anyhow::anyhow!(
            "failed to parse JSON from `pveum user token add` (line {}, column {}) — \
             raw stdout suppressed to protect token secret",
            e.line(),
            e.column()
        )
    })?;
    if parsed.value.expose().trim().is_empty() {
        anyhow::bail!("`pveum user token add` returned an empty token secret value");
    }
    Ok(parsed.value)
}

async fn exec_pveum<G: SshGateway + ?Sized>(
    ssh: &G,
    node: &str,
    cmd: &str,
) -> Result<crate::ssh::ExecResult> {
    debug!(node = %node, command = %cmd, "token bootstrap ssh exec");
    ssh.exec(node, cmd, ExecOptions::default()).await
}

async fn rollback_created_token<G: SshGateway + ?Sized>(
    ssh: &G,
    node: &str,
    remove_cmd: &str,
    userid: &str,
    tokenid: &str,
) -> std::result::Result<(), String> {
    match exec_pveum(ssh, node, remove_cmd).await {
        Ok(mut res) => {
            let ok = res.ok();
            let exit_code = res.exit_code;
            let stderr_msg: String = res.stderr.trim().chars().take(200).collect();
            res.stdout.zeroize();
            res.stderr.zeroize();
            if ok {
                info!(
                    node = %node,
                    userid = %userid,
                    tokenid = %tokenid,
                    "rolled back newly created PVE token after post-creation failure"
                );
                Ok(())
            } else {
                Err(format!(
                    "rollback `pveum user token remove` exited {exit_code:?}: {stderr_msg}"
                ))
            }
        }
        Err(e) => Err(format!("rollback `pveum user token remove` failed: {e:#}")),
    }
}

/// Testable core of `proxxx token bootstrap` (`#330`), generic over [`SshGateway`],
/// [`BootstrapSecretStore`], and [`BootstrapVerifier`].
#[allow(clippy::too_many_lines)]
pub async fn bootstrap_token_with<G, S, V>(
    config: &ProfileConfig,
    args: &TokenBootstrapArgs,
    ssh_node: &str,
    ssh: &G,
    secret_store: &S,
    verifier: &V,
    audit_dir: Option<&Path>,
) -> Result<(Value, i32)>
where
    G: SshGateway + ?Sized,
    S: BootstrapSecretStore + ?Sized,
    V: BootstrapVerifier + ?Sized,
{
    let profile_label = config.profile_label().to_string();

    // 1. Refuse `read_only = true` profiles (exit code 8) and require `--yes`
    //    before running any SSH command.
    if config.read_only {
        return Err(crate::config::ReadOnlyRefusal {
            profile: profile_label,
            path: "SSH token bootstrap".to_string(),
        }
        .into());
    }
    crate::cli::common::require_yes(args.yes, "token bootstrap")?;

    let userid = args
        .userid
        .as_deref()
        .unwrap_or(&config.user)
        .trim()
        .to_string();
    let tokenid = args
        .tokenid
        .as_deref()
        .or(config.token_id.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no `token_id` configured on profile '{profile_label}' — pass `--tokenid <id>` \
                 or set `token_id` in config.toml"
            )
        })?
        .to_string();
    let role = args.role.trim().to_string();
    let acl_path = args.acl_path.trim().to_string();

    validate_identifier("userid", &userid, true)?;
    validate_identifier("tokenid", &tokenid, false)?;
    validate_identifier("role", &role, false)?;
    validate_acl_path(&acl_path)?;

    let q_user = quote_arg(&userid);
    let q_token = quote_arg(&tokenid);
    let q_role = quote_arg(&role);
    let q_path = quote_arg(&acl_path);
    let q_full_token = quote_single(&format!("{userid}!{tokenid}"));

    let list_cmd = format!("pveum user token list {q_user} --output-format json");
    let remove_cmd = format!("pveum user token remove {q_user} {q_token}");
    let add_cmd =
        format!("pveum user token add {q_user} {q_token} --privsep 1 --output-format json");
    let acl_cmd = format!("pveum acl modify {q_path} --tokens {q_full_token} --roles {q_role}");

    // 3. Pre-check over SSH: `pveum user token list <user> --output-format json`.
    let mut list_res = exec_pveum(ssh, ssh_node, &list_cmd)
        .await
        .with_context(|| format!("running `pveum user token list` on {ssh_node}"))?;
    if !list_res.ok() {
        let code = list_res.exit_code;
        let stderr_msg: String = list_res.stderr.trim().chars().take(300).collect();
        list_res.stdout.zeroize();
        list_res.stderr.zeroize();
        anyhow::bail!("`pveum user token list` on {ssh_node} exited {code:?}: {stderr_msg}");
    }
    list_res.stderr.zeroize();
    let existing_tokens = parse_token_list_stdout(&mut list_res.stdout)?;
    let full_token_id = format!("{userid}!{tokenid}");
    let token_exists = existing_tokens
        .iter()
        .any(|t| t.tokenid == tokenid || t.tokenid == full_token_id);

    if token_exists && !args.rotate {
        anyhow::bail!(
            "token '{full_token_id}' already exists on node '{ssh_node}'; pass `--rotate` \
             to remove and recreate it (note: rotating invalidates the previous token secret)"
        );
    }

    // 10. Audit write-ahead entry before mutating tokens on PVE (never contains the secret).
    let rotate_str = if args.rotate { "true" } else { "false" };
    let audit_params = [
        ("user", userid.as_str()),
        ("tokenid", tokenid.as_str()),
        ("role", role.as_str()),
        ("path", acl_path.as_str()),
        ("node", ssh_node),
        ("rotate", rotate_str),
    ];
    let audit_ctx = crate::audit::MutationAuditCtx::write_ahead_custom_at(
        "SSH token bootstrap",
        Some(ssh_node),
        None,
        &audit_params,
        &profile_label,
        audit_dir,
    )?;

    let mut rotated = false;
    if token_exists && args.rotate {
        info!(
            node = %ssh_node,
            token = %full_token_id,
            "rotating existing PVE API token (--rotate): removing previous token; old secret stops working immediately"
        );
        let mut rm_res = match exec_pveum(ssh, ssh_node, &remove_cmd).await {
            Ok(r) => r,
            Err(e) => {
                audit_ctx.record_outcome("error remove_transport");
                return Err(e.context(format!(
                    "removing existing token '{full_token_id}' on {ssh_node} (--rotate)"
                )));
            }
        };
        let rm_ok = rm_res.ok();
        let rm_code = rm_res.exit_code;
        let rm_stderr: String = rm_res.stderr.trim().chars().take(300).collect();
        rm_res.stdout.zeroize();
        rm_res.stderr.zeroize();
        if !rm_ok {
            audit_ctx.record_outcome(&format!("error remove_{}", rm_code.unwrap_or(1)));
            anyhow::bail!(
                "`pveum user token remove` for '{full_token_id}' on {ssh_node} exited {rm_code:?}: {rm_stderr}"
            );
        }
        rotated = true;
    }

    // 4. Create token: `pveum user token add <user> <tokenid> --privsep 1 --output-format json`.
    let mut add_res = match exec_pveum(ssh, ssh_node, &add_cmd).await {
        Ok(r) => r,
        Err(e) => {
            audit_ctx.record_outcome("error add_transport");
            return Err(e.context(format!(
                "running `pveum user token add` for '{full_token_id}' on {ssh_node}"
            )));
        }
    };
    let add_ok = add_res.ok();
    let add_code = add_res.exit_code;
    let add_stderr: String = add_res.stderr.trim().chars().take(300).collect();
    add_res.stderr.zeroize();
    if !add_ok {
        add_res.stdout.zeroize();
        audit_ctx.record_outcome(&format!("error add_{}", add_code.unwrap_or(1)));
        anyhow::bail!(
            "`pveum user token add` for '{full_token_id}' on {ssh_node} exited {add_code:?}: {add_stderr}"
        );
    }

    let mut secret = match parse_token_add_stdout(&mut add_res.stdout) {
        Ok(s) => s,
        Err(parse_err) => {
            let _ = rollback_created_token(ssh, ssh_node, &remove_cmd, &userid, &tokenid).await;
            audit_ctx.record_outcome("error add_parse_rolled_back");
            return Err(parse_err);
        }
    };

    // 5. Grant ACL: `pveum acl modify <acl-path> --tokens '<user>!<tokenid>' --roles <role>`.
    let acl_outcome = exec_pveum(ssh, ssh_node, &acl_cmd).await;
    match acl_outcome {
        Ok(mut acl_res) => {
            let acl_ok = acl_res.ok();
            let acl_code = acl_res.exit_code;
            let acl_stderr: String = acl_res.stderr.trim().chars().take(300).collect();
            acl_res.stdout.zeroize();
            acl_res.stderr.zeroize();
            if !acl_ok {
                secret.zeroize();
                let rb =
                    rollback_created_token(ssh, ssh_node, &remove_cmd, &userid, &tokenid).await;
                audit_ctx.record_outcome("error acl_rolled_back");
                return match rb {
                    Ok(()) => Err(anyhow::anyhow!(
                        "`pveum acl modify` on {ssh_node} exited {acl_code:?}: {acl_stderr} \
                         (rolled back newly created token '{full_token_id}')"
                    )),
                    Err(rb_err) => Err(anyhow::anyhow!(
                        "`pveum acl modify` on {ssh_node} exited {acl_code:?}: {acl_stderr}; \
                         additionally, rollback failed: {rb_err}"
                    )),
                };
            }
        }
        Err(acl_err) => {
            secret.zeroize();
            let rb = rollback_created_token(ssh, ssh_node, &remove_cmd, &userid, &tokenid).await;
            audit_ctx.record_outcome("error acl_rolled_back");
            return match rb {
                Ok(()) => Err(acl_err.context(format!(
                    "`pveum acl modify` failed on {ssh_node} (rolled back newly created token '{full_token_id}')"
                ))),
                Err(rb_err) => Err(acl_err.context(format!(
                    "`pveum acl modify` failed on {ssh_node}; additionally, rollback failed: {rb_err}"
                ))),
            };
        }
    }

    // 6 & 7. Store secret BEFORE reporting success; roll back on store failure.
    let store_target =
        select_secret_store_target(config, args, secret_store.has_compiled_keychain());
    let store_res = secret_store
        .store(&store_target, &secret, args.rotate)
        .await;
    secret.zeroize();

    let stored = match store_res {
        Ok(loc) => loc,
        Err(store_err) => {
            let rb = rollback_created_token(ssh, ssh_node, &remove_cmd, &userid, &tokenid).await;
            audit_ctx.record_outcome("error store_rolled_back");
            return match rb {
                Ok(()) => Err(store_err.context(format!(
                    "failed to store token secret locally; rolled back newly created token \
                     '{full_token_id}' on {ssh_node} (secret was discarded and never printed)"
                ))),
                Err(rb_err) => Err(store_err.context(format!(
                    "failed to store token secret locally, and rollback of '{full_token_id}' \
                     on {ssh_node} also failed ({rb_err}); secret was discarded and never printed"
                ))),
            };
        }
    };

    // 8. Verify with `PxClient`: `GET /version` + `GET /nodes`.
    let verify_report = verifier.verify(config, &userid, &tokenid, &stored).await;
    let exit_code = i32::from(!verify_report.ok);

    // 10. Audit outcome after completion (never contains the secret).
    let outcome_label = if verify_report.ok {
        "ok 0"
    } else {
        "ok 0 (verify_failed)"
    };
    audit_ctx.record_outcome(outcome_label);

    // 9. Print the TOML lines the operator needs (do NOT edit config.toml).
    let toml_lines = match &stored {
        StoredSecretLocation::File(path) => vec![
            format!("token_id = {tokenid:?}"),
            format!("token_secret_file = {:?}", path.display().to_string()),
        ],
        StoredSecretLocation::Keychain { .. } => vec![format!("token_id = {tokenid:?}")],
    };
    let toml_snippet = toml_lines.join("\n");

    let mut out = serde_json::json!({
        "profile": profile_label,
        "node": ssh_node,
        "userid": userid,
        "tokenid": tokenid,
        "full_tokenid": full_token_id,
        "role": role,
        "acl_path": acl_path,
        "rotated": rotated,
        "secret_store": stored.store_kind(),
        "secret_target": stored.target_description(),
        "verify": verify_report,
        "toml_lines": toml_lines,
        "toml_snippet": toml_snippet,
        "status": if verify_report.ok { "bootstrapped" } else { "verify_failed" },
    });
    if rotated {
        out["notice"] = Value::String(format!(
            "existing token '{full_token_id}' was removed and recreated (--rotate); \
             the previous token secret no longer works"
        ));
    }
    if let StoredSecretLocation::File(path) = &stored {
        out["token_secret_file"] = Value::String(path.display().to_string());
    }

    Ok((out, exit_code))
}

/// Entrypoint called by [`crate::cli::execute`] before constructing `PxClient` (`#330`).
pub async fn execute_token_bootstrap(
    config: &ProfileConfig,
    args: &TokenBootstrapArgs,
) -> Result<(Value, i32)> {
    let profile_label = config.profile_label().to_string();
    if config.read_only {
        return Err(crate::config::ReadOnlyRefusal {
            profile: profile_label,
            path: "SSH token bootstrap".to_string(),
        }
        .into());
    }
    crate::cli::common::require_yes(args.yes, "token bootstrap")?;

    let mut ssh_cfg = config.ssh.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "[profiles.{profile_label}.ssh] (or [defaults.ssh]) is not configured — \
             `proxxx token bootstrap` connects over SSH to run `pveum`"
        )
    })?;

    if HostKeyPolicy::from_str(&ssh_cfg.strict_host_key_checking) == HostKeyPolicy::Off {
        anyhow::bail!(
            "refusing `token bootstrap` with `ssh.strict_host_key_checking = \"off\"` — \
             host key verification (\"tofu\" or \"strict\") is mandatory when minting API tokens over SSH"
        );
    }

    let (host, port) = resolve_bootstrap_ssh_endpoint(config, args.ssh_host.as_deref())?;
    crate::config::validate_ssh_destination(&ssh_cfg.user, &host)
        .map_err(|e| anyhow::anyhow!("invalid SSH target for `token bootstrap`: {e}"))?;

    let host_port_spec = format_host_port_spec(&host, port);
    let ssh_node = if port == 22 {
        host.clone()
    } else {
        host_port_spec.clone()
    };
    // Pin the resolved `(host, port)` as an explicit host entry on the pool so
    // `SshPool` connects directly without calling `/cluster/status` or running
    // the fallback `hostname` node-name check (no working API token exists yet).
    ssh_cfg.hosts.insert(ssh_node.clone(), host_port_spec);

    let pool = SshPool::new(ssh_cfg, None)?;
    let store = RealBootstrapSecretStore;
    let verifier = RealBootstrapVerifier;
    bootstrap_token_with(config, args, &ssh_node, &pool, &store, &verifier, None).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use crate::ssh::ExecResult;

    struct FakeSsh {
        responses: Mutex<VecDeque<ExecResult>>,
        recorded: Mutex<Vec<(String, String)>>,
    }

    impl FakeSsh {
        fn new(responses: Vec<ExecResult>) -> Self {
            Self {
                responses: Mutex::new(VecDeque::from(responses)),
                recorded: Mutex::new(Vec::new()),
            }
        }

        fn commands(&self) -> Vec<String> {
            self.recorded
                .lock()
                .unwrap()
                .iter()
                .map(|(_, cmd)| cmd.clone())
                .collect()
        }
    }

    #[async_trait::async_trait]
    impl SshGateway for FakeSsh {
        async fn exec(&self, node: &str, command: &str, _opts: ExecOptions) -> Result<ExecResult> {
            self.recorded
                .lock()
                .unwrap()
                .push((node.to_string(), command.to_string()));
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("unexpected SSH command: {command}"))
        }
    }

    struct FakeStore {
        compiled_keychain: bool,
        fail_with: Option<String>,
    }

    impl FakeStore {
        fn file_backed() -> Self {
            Self {
                compiled_keychain: false,
                fail_with: None,
            }
        }

        fn failing(msg: &str) -> Self {
            Self {
                compiled_keychain: false,
                fail_with: Some(msg.to_string()),
            }
        }
    }

    #[async_trait::async_trait]
    impl BootstrapSecretStore for FakeStore {
        fn has_compiled_keychain(&self) -> bool {
            self.compiled_keychain
        }

        async fn store(
            &self,
            target: &SecretStoreTarget,
            secret: &SecretString,
            allow_overwrite: bool,
        ) -> Result<StoredSecretLocation> {
            if let Some(ref msg) = self.fail_with {
                anyhow::bail!("{msg}");
            }
            RealBootstrapSecretStore
                .store(target, secret, allow_overwrite)
                .await
        }
    }

    struct FakeVerifier {
        report: BootstrapVerifyReport,
    }

    impl FakeVerifier {
        fn ok() -> Self {
            Self {
                report: BootstrapVerifyReport {
                    ok: true,
                    version: Some("9.0.3".to_string()),
                    release: Some("9.0".to_string()),
                    nodes_count: Some(1),
                    error: None,
                },
            }
        }
    }

    #[async_trait::async_trait]
    impl BootstrapVerifier for FakeVerifier {
        async fn verify(
            &self,
            _config: &ProfileConfig,
            _userid: &str,
            _tokenid: &str,
            _stored: &StoredSecretLocation,
        ) -> BootstrapVerifyReport {
            self.report.clone()
        }
    }

    #[derive(Clone, Default)]
    struct SharedLogBuffer(Arc<Mutex<Vec<u8>>>);

    impl SharedLogBuffer {
        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for SharedLogWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SharedLogBuffer {
        type Writer = SharedLogWriter;

        fn make_writer(&'a self) -> Self::Writer {
            SharedLogWriter(Arc::clone(&self.0))
        }
    }

    fn sample_profile(read_only: bool) -> ProfileConfig {
        ProfileConfig {
            url: "https://10.10.10.181:8006".to_string(),
            user: "root@pam".to_string(),
            auth: "token".to_string(),
            token_id: Some("proxxx-boot".to_string()),
            token_secret: None,
            token_secret_file: None,
            password: None,
            verify_tls: false,
            tls_pin_mode: None,
            read_only,
            rate_limit: None,
            policies: None,
            telegram: None,
            ssh: None,
            pbs: None,
            alerts: None,
            mcp_token: None,
            reconcile: None,
            profile_name: Some("pve1".to_string()),
        }
    }

    fn default_args(secret_file: PathBuf) -> TokenBootstrapArgs {
        TokenBootstrapArgs {
            userid: None,
            tokenid: None,
            role: "PVEAuditor".to_string(),
            acl_path: "/".to_string(),
            ssh_host: None,
            secret_file: Some(secret_file),
            rotate: false,
            yes: true,
        }
    }

    fn ok_exec(stdout: &str) -> ExecResult {
        ExecResult {
            stdout: stdout.to_string(),
            stderr: String::new(),
            exit_code: Some(0),
        }
    }

    fn assert_audit_entries_have_no_canary(audit_dir: &Path, canary: &str) {
        let logger = crate::audit::AuditLogger::open_in(audit_dir).unwrap();
        let (verified_ok, verified_fail) = logger.verify().unwrap();
        assert_eq!((verified_ok, verified_fail), (2, 0));
        let entries = logger.query(10, None).unwrap();
        assert_eq!(entries.len(), 2, "expected sent + outcome audit entries");
        let entries_json = serde_json::to_string(&entries).unwrap();
        assert!(
            !entries_json.contains(canary),
            "audit entries must never contain the canary secret: {entries_json}"
        );
        // `query` returns rows in DESC order (newest first: index 0 is outcome, index 1 is sent).
        let outcome_entry = &entries[0];
        let sent_entry = &entries[1];
        assert_eq!(sent_entry.action, "SSH token bootstrap");
        assert_eq!(sent_entry.result, "sent");
        assert_eq!(sent_entry.node.as_deref(), Some("10.10.10.181"));
        let sent_params: Value =
            serde_json::from_str(sent_entry.params_json.as_deref().unwrap()).unwrap();
        assert_eq!(sent_params["profile"], "pve1");
        assert_eq!(sent_params["user"], "root@pam");
        assert_eq!(sent_params["tokenid"], "proxxx-boot");
        assert_eq!(sent_params["role"], "PVEAuditor");
        assert_eq!(sent_params["path"], "/");
        assert_eq!(sent_params["node"], "10.10.10.181");
        assert_eq!(outcome_entry.action, "SSH token bootstrap");
        assert_eq!(outcome_entry.result, "ok 0");
    }

    /// Test 1: Happy path with a fake gateway returning a canary `value`:
    /// the stored file has the canary and mode `0600` (and parent dir `0700`);
    /// the command output, the captured tracing output (at DEBUG level), and
    /// the audit entries contain no canary.
    #[tokio::test]
    async fn test_1_happy_path_stores_0600_and_never_leaks_canary() {
        const CANARY: &str = "CANARY-SECRET-9f8e7d6c-5b4a-3210-fedc-ba9876543210";

        let tmp = tempfile::tempdir().unwrap();
        let secret_dir = tmp.path().join("nested_secrets");
        let secret_file = secret_dir.join("pve1.token");
        let audit_dir = tmp.path().join("audit");

        let ssh = FakeSsh::new(vec![
            ok_exec(r#"[{"tokenid":"other-token","privsep":1}]"#),
            ok_exec(&format!(
                r#"{{"full-tokenid":"root@pam!proxxx-boot","info":{{"privsep":"1"}},"value":"{CANARY}"}}"#
            )),
            ok_exec(""),
        ]);
        let store = FakeStore::file_backed();
        let verifier = FakeVerifier::ok();
        let cfg = sample_profile(false);
        let args = default_args(secret_file.clone());

        let log_buf = SharedLogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(log_buf.clone())
            .with_ansi(false)
            .finish();
        // tracing-core treats a process with a single registered dispatcher
        // as "just one": a callsite first hit on another test's thread then
        // takes that thread's (empty) default, caches a global "never", and
        // the `debug!` below is dropped (19-31 failures in 300 runs). A
        // second, permanent dispatcher keeps every registration asking all
        // live dispatchers, including this test's scoped one.
        static KEEP_REGISTRY_MULTI: std::sync::OnceLock<tracing::Dispatch> =
            std::sync::OnceLock::new();
        KEEP_REGISTRY_MULTI
            .get_or_init(|| tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()));
        let _guard = tracing::subscriber::set_default(subscriber);

        let (out, exit_code) = bootstrap_token_with(
            &cfg,
            &args,
            "10.10.10.181",
            &ssh,
            &store,
            &verifier,
            Some(&audit_dir),
        )
        .await
        .expect("happy-path bootstrap must succeed");

        assert_eq!(exit_code, 0);
        assert_eq!(out["status"], "bootstrapped");
        assert_eq!(out["verify"]["ok"], true);
        assert_eq!(out["token_secret_file"], secret_file.display().to_string());

        // Stored file contains the canary and has mode 0600; parent dir has 0700.
        let stored_bytes = std::fs::read_to_string(&secret_file).unwrap();
        assert_eq!(stored_bytes, CANARY);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_mode = std::fs::metadata(&secret_file)
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                file_mode, 0o600,
                "secret file must be created with mode 0600"
            );
            let dir_mode = std::fs::metadata(&secret_dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                dir_mode, 0o700,
                "parent secrets dir must be created with mode 0700"
            );
        }

        // Command output (JSON and pretty string) must not contain the canary.
        let out_str = serde_json::to_string_pretty(&out).unwrap();
        assert!(
            !out_str.contains(CANARY),
            "command output must never contain the canary secret: {out_str}"
        );
        let snippet = out["toml_snippet"].as_str().unwrap();
        assert!(
            snippet.contains("token_id = \"proxxx-boot\""),
            "output must include the TOML token_id line: {snippet}"
        );
        assert!(
            snippet.contains("token_secret_file = "),
            "output must include the TOML token_secret_file line: {snippet}"
        );

        // Tracing output captured at DEBUG level must contain the command name
        // (proving debug capture is active) and NEVER contain the canary.
        let logs = log_buf.text();
        assert!(
            logs.contains("pveum user token add"),
            "debug logs must record the pveum command (got: {logs})"
        );
        assert!(
            !logs.contains(CANARY),
            "tracing logs must never contain the canary secret: {logs}"
        );

        assert_audit_entries_have_no_canary(&audit_dir, CANARY);
    }

    /// Test 2: Existing token without `--rotate` -> refused, no `add` command sent;
    /// with `--rotate` -> `remove` then `add`, in that order.
    #[tokio::test]
    async fn test_2_existing_token_refuses_without_rotate_and_removes_then_adds_with_rotate() {
        let tmp = tempfile::tempdir().unwrap();
        let secret_file = tmp.path().join("pve1.token");
        let audit_dir = tmp.path().join("audit");
        let cfg = sample_profile(false);
        let store = FakeStore::file_backed();
        let verifier = FakeVerifier::ok();

        // Without --rotate: refused after `token list`, no `add` or `remove` sent.
        let ssh_no_rotate =
            FakeSsh::new(vec![ok_exec(r#"[{"tokenid":"proxxx-boot","privsep":1}]"#)]);
        let args_no_rotate = default_args(secret_file.clone());
        let err = bootstrap_token_with(
            &cfg,
            &args_no_rotate,
            "10.10.10.181",
            &ssh_no_rotate,
            &store,
            &verifier,
            Some(&audit_dir),
        )
        .await
        .expect_err("existing token without --rotate must be refused");
        assert!(
            err.to_string().contains("--rotate"),
            "error must advise passing --rotate, got: {err}"
        );
        assert_eq!(
            ssh_no_rotate.commands(),
            vec!["pveum user token list root@pam --output-format json"],
            "no add or remove command may be sent when refusing without --rotate"
        );

        // Pre-populate the secret file so `--rotate` also exercises overwriting it.
        std::fs::write(&secret_file, "old-secret").unwrap();

        // With --rotate: `list` -> `remove` -> `add` -> `acl modify`, in that exact order.
        let ssh_rotate = FakeSsh::new(vec![
            ok_exec(r#"[{"tokenid":"proxxx-boot","privsep":1}]"#),
            ok_exec(""),
            ok_exec(r#"{"value":"rotated-secret-value"}"#),
            ok_exec(""),
        ]);
        let mut args_rotate = default_args(secret_file.clone());
        args_rotate.rotate = true;
        let (out, exit_code) = bootstrap_token_with(
            &cfg,
            &args_rotate,
            "10.10.10.181",
            &ssh_rotate,
            &store,
            &verifier,
            Some(&audit_dir),
        )
        .await
        .expect("existing token with --rotate must succeed");

        assert_eq!(exit_code, 0);
        assert_eq!(out["rotated"], true);
        assert!(
            out["notice"]
                .as_str()
                .unwrap_or_default()
                .contains("previous token secret no longer works"),
            "rotation output must warn that the old secret stops working: {out}"
        );
        assert_eq!(
            ssh_rotate.commands(),
            vec![
                "pveum user token list root@pam --output-format json",
                "pveum user token remove root@pam proxxx-boot",
                "pveum user token add root@pam proxxx-boot --privsep 1 --output-format json",
                "pveum acl modify / --tokens 'root@pam!proxxx-boot' --roles PVEAuditor",
            ]
        );
        assert_eq!(
            std::fs::read_to_string(&secret_file).unwrap(),
            "rotated-secret-value"
        );
    }

    /// Test 3: Store failure -> rollback `remove` is sent; no canary anywhere in the error.
    #[tokio::test]
    async fn test_3_store_failure_triggers_rollback_remove_without_leaking_canary() {
        const CANARY: &str = "CANARY-ROLLBACK-00112233-4455-6677-8899-aabbccddeeff";

        let tmp = tempfile::tempdir().unwrap();
        let secret_file = tmp.path().join("pve1.token");
        let audit_dir = tmp.path().join("audit");
        let cfg = sample_profile(false);
        let args = default_args(secret_file);

        let ssh = FakeSsh::new(vec![
            ok_exec("[]"),
            ok_exec(&format!(r#"{{"value":"{CANARY}"}}"#)),
            ok_exec(""),
            ok_exec(""),
        ]);
        let store = FakeStore::failing("simulated disk full / permission denied on secret store");
        let verifier = FakeVerifier::ok();

        let err = bootstrap_token_with(
            &cfg,
            &args,
            "10.10.10.181",
            &ssh,
            &store,
            &verifier,
            Some(&audit_dir),
        )
        .await
        .expect_err("store failure must fail the bootstrap command");

        assert_eq!(
            ssh.commands(),
            vec![
                "pveum user token list root@pam --output-format json",
                "pveum user token add root@pam proxxx-boot --privsep 1 --output-format json",
                "pveum acl modify / --tokens 'root@pam!proxxx-boot' --roles PVEAuditor",
                "pveum user token remove root@pam proxxx-boot",
            ],
            "rollback `pveum user token remove` must be sent when storing fails"
        );

        let err_display = format!("{err:#}");
        let err_debug = format!("{err:?}");
        assert!(
            err_display.contains("rolled back newly created token"),
            "error must report that the token was rolled back, got: {err_display}"
        );
        assert!(
            !err_display.contains(CANARY) && !err_debug.contains(CANARY),
            "error must never contain the canary secret: {err_display}"
        );

        let logger = crate::audit::AuditLogger::open_in(&audit_dir).unwrap();
        let entries = logger.query(10, None).unwrap();
        let entries_json = serde_json::to_string(&entries).unwrap();
        assert!(
            !entries_json.contains(CANARY),
            "audit log must never contain the canary secret on rollback: {entries_json}"
        );
    }

    /// Test 4: `read_only` profile -> refused before any SSH command;
    /// missing `--yes` -> refused before any SSH command.
    #[tokio::test]
    async fn test_4_read_only_profile_and_missing_yes_refuse_before_any_ssh() {
        let tmp = tempfile::tempdir().unwrap();
        let secret_file = tmp.path().join("pve1.token");
        let audit_dir = tmp.path().join("audit");
        let store = FakeStore::file_backed();
        let verifier = FakeVerifier::ok();

        // Case A: read_only = true profile
        let ssh_ro = FakeSsh::new(vec![]);
        let read_only_cfg = sample_profile(true);
        let args = default_args(secret_file.clone());
        let ro_err = bootstrap_token_with(
            &read_only_cfg,
            &args,
            "10.10.10.181",
            &ssh_ro,
            &store,
            &verifier,
            Some(&audit_dir),
        )
        .await
        .expect_err("read_only profile must refuse token bootstrap");
        assert!(
            ro_err
                .downcast_ref::<crate::config::ReadOnlyRefusal>()
                .is_some(),
            "must return typed ReadOnlyRefusal (exit code 8), got: {ro_err:#}"
        );
        assert!(
            ssh_ro.commands().is_empty(),
            "no SSH command may run on a read_only profile"
        );

        // Case B: missing --yes
        let ssh_no_yes = FakeSsh::new(vec![]);
        let writable_cfg = sample_profile(false);
        let mut args_no_yes = default_args(secret_file);
        args_no_yes.yes = false;
        let yes_err = bootstrap_token_with(
            &writable_cfg,
            &args_no_yes,
            "10.10.10.181",
            &ssh_no_yes,
            &store,
            &verifier,
            Some(&audit_dir),
        )
        .await
        .expect_err("missing --yes must refuse token bootstrap");
        assert!(
            yes_err.to_string().contains("--yes"),
            "error must mention --yes, got: {yes_err}"
        );
        assert!(
            ssh_no_yes.commands().is_empty(),
            "no SSH command may run when --yes is missing"
        );
    }

    /// Test 5: ACL command uses `--tokens '<user>!<tokenid>'` and the chosen role/path
    /// (argument quoting tested, including a user with `@`).
    #[tokio::test]
    async fn test_5_acl_command_quotes_user_with_at_and_uses_chosen_role_and_path() {
        let tmp = tempfile::tempdir().unwrap();
        let secret_file = tmp.path().join("pve1.token");
        let audit_dir = tmp.path().join("audit");
        let cfg = sample_profile(false);
        let store = FakeStore::file_backed();
        let verifier = FakeVerifier::ok();

        let ssh = FakeSsh::new(vec![
            ok_exec("[]"),
            ok_exec(r#"{"value":"acl-test-secret"}"#),
            ok_exec(""),
        ]);

        let args = TokenBootstrapArgs {
            userid: Some("ops.bot-1@pve".to_string()),
            tokenid: Some("ci_runner-2".to_string()),
            role: "PVEVMUser".to_string(),
            acl_path: "/vms/100".to_string(),
            ssh_host: None,
            secret_file: Some(secret_file),
            rotate: false,
            yes: true,
        };

        let (out, exit_code) = bootstrap_token_with(
            &cfg,
            &args,
            "10.10.10.181",
            &ssh,
            &store,
            &verifier,
            Some(&audit_dir),
        )
        .await
        .expect("bootstrap with custom user/token/role/path must succeed");

        assert_eq!(exit_code, 0);
        assert_eq!(out["userid"], "ops.bot-1@pve");
        assert_eq!(out["tokenid"], "ci_runner-2");
        assert_eq!(out["role"], "PVEVMUser");
        assert_eq!(out["acl_path"], "/vms/100");
        assert_eq!(
            ssh.commands(),
            vec![
                "pveum user token list ops.bot-1@pve --output-format json",
                "pveum user token add ops.bot-1@pve ci_runner-2 --privsep 1 --output-format json",
                "pveum acl modify /vms/100 --tokens 'ops.bot-1@pve!ci_runner-2' --roles PVEVMUser",
            ]
        );
    }

    /// Test 6: Malformed `pveum` JSON -> error without echoing `stdout`.
    #[tokio::test]
    async fn test_6_malformed_pveum_json_errors_without_echoing_stdout() {
        const RAW_STDOUT_CANARY: &str = "UNPARSABLE-PVEUM-STDOUT-CANARY-77889900";

        let tmp = tempfile::tempdir().unwrap();
        let secret_file = tmp.path().join("pve1.token");
        let audit_dir = tmp.path().join("audit");
        let cfg = sample_profile(false);
        let store = FakeStore::file_backed();
        let verifier = FakeVerifier::ok();

        // Case A: malformed JSON from `pveum user token list`
        let ssh_bad_list = FakeSsh::new(vec![ok_exec(&format!(
            "not-json-at-all: {RAW_STDOUT_CANARY}"
        ))]);
        let args = default_args(secret_file.clone());
        let err_list = bootstrap_token_with(
            &cfg,
            &args,
            "10.10.10.181",
            &ssh_bad_list,
            &store,
            &verifier,
            Some(&audit_dir),
        )
        .await
        .expect_err("malformed token list JSON must fail");
        let list_err_str = format!("{err_list:#} {err_list:?}");
        assert!(
            !list_err_str.contains(RAW_STDOUT_CANARY),
            "malformed list JSON error must never echo stdout: {list_err_str}"
        );

        // Case B: malformed JSON from `pveum user token add` (also triggers rollback remove)
        let ssh_bad_add = FakeSsh::new(vec![
            ok_exec("[]"),
            ok_exec(&format!("{{\"value\": \"{RAW_STDOUT_CANARY}\" truncated")),
            ok_exec(""),
        ]);
        let err_add = bootstrap_token_with(
            &cfg,
            &args,
            "10.10.10.181",
            &ssh_bad_add,
            &store,
            &verifier,
            Some(&audit_dir),
        )
        .await
        .expect_err("malformed token add JSON must fail");
        let add_err_str = format!("{err_add:#} {err_add:?}");
        assert!(
            !add_err_str.contains(RAW_STDOUT_CANARY),
            "malformed add JSON error must never echo stdout: {add_err_str}"
        );
        assert_eq!(
            ssh_bad_add.commands().last().map(String::as_str),
            Some("pveum user token remove root@pam proxxx-boot"),
            "malformed add output after exit 0 must still attempt rollback remove"
        );
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, val: &str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, val);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(ref prev) = self.previous {
                std::env::set_var(self.key, prev);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    /// Test 7 (Rev. 42 F1): `RealBootstrapVerifier` reads back the secret from the store
    /// just written and passes it explicitly as highest-precedence `cli_secret`, so a
    /// stale or unrelated `PROXXX_TOKEN_SECRET` in the environment cannot shadow it.
    #[tokio::test]
    #[serial_test::serial]
    async fn test_7_real_verifier_reads_stored_secret_ignoring_env_var() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const STORED_CANARY: &str = "STORED-SECRET-11223344-5566-7788-99aa-bbccddeeff00";
        const WRONG_ENV_SECRET: &str = "WRONG-ENV-SECRET-deadbeef-0000-1111-2222-333344445555";

        let server = MockServer::start().await;
        let expected_auth = format!("PVEAPIToken=root@pam!proxxx-boot={STORED_CANARY}");

        Mock::given(method("GET"))
            .and(path("/api2/json/version"))
            .and(header("Authorization", expected_auth.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "version": "9.1.1",
                    "release": "9.1",
                    "repoid": "a1b2c3d4"
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api2/json/nodes"))
            .and(header("Authorization", expected_auth.as_str()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [
                    {
                        "node": "pve-test-1",
                        "status": "online",
                        "cpu": 0.05,
                        "maxcpu": 8,
                        "mem": 1024,
                        "maxmem": 8192,
                        "uptime": 3600
                    }
                ]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let _env_guard = EnvVarGuard::set("PROXXX_TOKEN_SECRET", WRONG_ENV_SECRET);

        let tmp = tempfile::tempdir().unwrap();
        let secret_file = tmp.path().join("pve1.token");
        let audit_dir = tmp.path().join("audit");

        let mut cfg = sample_profile(false);
        cfg.url = server.uri();
        let args = default_args(secret_file.clone());

        let ssh = FakeSsh::new(vec![
            ok_exec("[]"),
            ok_exec(&format!(r#"{{"value":"{STORED_CANARY}"}}"#)),
            ok_exec(""),
        ]);

        let (out, exit_code) = bootstrap_token_with(
            &cfg,
            &args,
            "10.10.10.181",
            &ssh,
            &RealBootstrapSecretStore,
            &RealBootstrapVerifier,
            Some(&audit_dir),
        )
        .await
        .expect("bootstrap with RealBootstrapVerifier must succeed");

        assert_eq!(
            exit_code, 0,
            "verify must succeed using the stored secret despite PROXXX_TOKEN_SECRET: {out}"
        );
        assert_eq!(out["verify"]["ok"], true);
        assert_eq!(out["verify"]["version"], "9.1.1");
        assert_eq!(out["verify"]["release"], "9.1");
        assert_eq!(out["verify"]["nodes_count"], 1);
    }
}
