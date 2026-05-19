//! Access control surface: ACL/users/groups/roles/realms/TFA browse + CRUD,
//! API token CRUD, and the effective-permissions shell-out (`proxxx perms`).

use anyhow::Result;
use clap::Subcommand;
use serde_json::Value;
use std::sync::Arc;

#[derive(Debug, Subcommand)]
pub enum AccessCommand {
    /// List ACL entries.
    Acl {
        /// Filter to a specific path (substring match).
        #[arg(long)]
        path: Option<String>,
    },
    /// List users.
    Users,
    /// List groups.
    Groups,
    /// List roles (with their privileges).
    Roles,
    /// List authentication realms (PAM/PVE/AD/LDAP/OIDC).
    Realms,
    /// List TFA entries for a user.
    Tfa { userid: String },
    /// Create a user. `userid` must include the realm
    /// (e.g. `alice@pve`, `svc@pam`).
    #[command(name = "user-create")]
    UserCreate {
        userid: String,
        /// Required for `@pve` realm; ignored for `@pam` (the OS owns that).
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        firstname: Option<String>,
        #[arg(long)]
        lastname: Option<String>,
        /// Comma-separated group ids the user joins on creation.
        #[arg(long)]
        groups: Option<String>,
        /// Disable on creation (default: enabled).
        #[arg(long)]
        disabled: bool,
        /// Account expiry as Unix timestamp; omit for never.
        #[arg(long)]
        expire: Option<u64>,
    },
    /// Modify an existing user. Only the fields you pass are changed.
    #[command(name = "user-update")]
    UserUpdate {
        userid: String,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        firstname: Option<String>,
        #[arg(long)]
        lastname: Option<String>,
        /// Comma-separated group ids to REPLACE the user's membership.
        #[arg(long)]
        groups: Option<String>,
        /// Enable the user.
        #[arg(long, conflicts_with = "disable")]
        enable: bool,
        /// Disable the user.
        #[arg(long, conflicts_with = "enable")]
        disable: bool,
        #[arg(long)]
        expire: Option<u64>,
    },
    /// Delete a user. PVE refuses if the user owns API tokens —
    /// revoke those first via `proxxx token revoke`.
    #[command(name = "user-delete")]
    UserDelete {
        userid: String,
        #[arg(long)]
        yes: bool,
    },
    /// Create a group.
    #[command(name = "group-create")]
    GroupCreate {
        groupid: String,
        #[arg(long)]
        comment: Option<String>,
    },
    /// Delete a group. PVE refuses if any user is still a member —
    /// remove members first via `proxxx access user-update --groups <new-csv>`.
    #[command(name = "group-delete")]
    GroupDelete {
        groupid: String,
        #[arg(long)]
        yes: bool,
    },
    /// Grant a role to a user/group/token on a path.
    #[command(name = "acl-set")]
    AclSet {
        /// PVE permission path (e.g. `/`, `/vms/100`, `/storage/local`).
        path: String,
        /// Role to grant (e.g. `PVEAuditor`, `PVEAdmin`, `Administrator`).
        #[arg(long)]
        role: String,
        /// Grant to this user (mutually exclusive with --group / --token).
        #[arg(long, conflicts_with_all = ["group", "token"])]
        user: Option<String>,
        /// Grant to this group.
        #[arg(long, conflicts_with_all = ["user", "token"])]
        group: Option<String>,
        /// Grant to this API token (`<userid>!<tokenid>`).
        #[arg(long, conflicts_with_all = ["user", "group"])]
        token: Option<String>,
        /// Disable propagation to child paths (default: propagate).
        #[arg(long)]
        no_propagate: bool,
    },
    /// Revoke a role from a user/group/token on a path.
    #[command(name = "acl-unset")]
    AclUnset {
        path: String,
        #[arg(long)]
        role: String,
        #[arg(long, conflicts_with_all = ["group", "token"])]
        user: Option<String>,
        #[arg(long, conflicts_with_all = ["user", "token"])]
        group: Option<String>,
        #[arg(long, conflicts_with_all = ["user", "group"])]
        token: Option<String>,
        /// Required: confirms this destructive op.
        #[arg(long)]
        yes: bool,
    },
    /// Effective permissions tree for a user (or self) on a path
    /// (or all paths). Hits `/access/permissions` directly — no SSH
    /// dependency, unlike the `proxxx perms` shellout.
    Permissions {
        /// User id (e.g. `alice@pve`). Default: current ticket's user.
        #[arg(long)]
        userid: Option<String>,
        /// ACL path (e.g. `/pool/dev`, `/storage/local`). Default: all.
        #[arg(long)]
        path: Option<String>,
    },
    /// Change a user's password. Requires either being the user
    /// themselves, or `Realm.AllocateUser` on `/access/{realm}`
    /// (typically root@pam).
    Password {
        userid: String,
        /// New password. Use shell history care — passes via `PUT` body.
        #[arg(long)]
        password: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// List tokens for a user.
    List { userid: String },
    /// Create a new token. The secret is printed ONCE — capture it,
    /// proxxx can't recover it later.
    Create {
        userid: String,
        tokenid: String,
        /// Privilege separation (recommended: leave default = true).
        #[arg(long, default_value_t = true)]
        privsep: bool,
        /// Expire timestamp (Unix seconds). Omit for never.
        #[arg(long)]
        expire: Option<u64>,
        #[arg(long)]
        comment: Option<String>,
    },
    /// Revoke a token. Required: `--yes`.
    Revoke {
        userid: String,
        tokenid: String,
        #[arg(long)]
        yes: bool,
    },
}

/// Feature #10 — read-only access browse.
pub async fn execute_access(
    client: &Arc<crate::api::PxClient>,
    action: AccessCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        AccessCommand::Acl { path } => {
            let mut acl = client.list_acl().await?;
            if let Some(p) = path {
                acl.retain(|e| e.path.contains(&p));
            }
            Ok((serde_json::to_value(acl)?, 0))
        }
        AccessCommand::Users => {
            let users = client.list_users().await?;
            Ok((serde_json::to_value(users)?, 0))
        }
        AccessCommand::Groups => {
            let groups = client.list_groups().await?;
            Ok((serde_json::to_value(groups)?, 0))
        }
        AccessCommand::Roles => {
            let roles = client.list_roles().await?;
            Ok((serde_json::to_value(roles)?, 0))
        }
        AccessCommand::Realms => {
            let realms = client.list_realms().await?;
            Ok((serde_json::to_value(realms)?, 0))
        }
        AccessCommand::Tfa { userid } => {
            let tfa = client.list_tfa(&userid).await?;
            Ok((serde_json::to_value(tfa)?, 0))
        }
        AccessCommand::UserCreate {
            userid,
            password,
            comment,
            email,
            firstname,
            lastname,
            groups,
            disabled,
            expire,
        } => {
            // `enable` semantic: PVE default is enabled. We pass
            // `enable=0` only when `--disabled` was set so the field
            // doesn't appear otherwise.
            let enable = if disabled { Some(false) } else { None };
            client
                .create_user(
                    &userid,
                    password.as_deref(),
                    comment.as_deref(),
                    email.as_deref(),
                    firstname.as_deref(),
                    lastname.as_deref(),
                    enable,
                    expire,
                    groups.as_deref(),
                )
                .await?;
            Ok((
                serde_json::json!({
                    "userid": userid,
                    "status": "created",
                    "groups": groups,
                    "enabled": !disabled,
                }),
                0,
            ))
        }
        AccessCommand::UserUpdate {
            userid,
            comment,
            email,
            firstname,
            lastname,
            groups,
            enable,
            disable,
            expire,
        } => {
            // `--enable` and `--disable` are clap-conflicting; if
            // neither is set, leave the field unchanged.
            let enable_param = if enable {
                Some(true)
            } else if disable {
                Some(false)
            } else {
                None
            };
            client
                .update_user(
                    &userid,
                    comment.as_deref(),
                    email.as_deref(),
                    firstname.as_deref(),
                    lastname.as_deref(),
                    enable_param,
                    expire,
                    groups.as_deref(),
                )
                .await?;
            Ok((
                serde_json::json!({
                    "userid": userid,
                    "status": "updated",
                }),
                0,
            ))
        }
        AccessCommand::UserDelete { userid, yes } => {
            if !yes {
                anyhow::bail!("`access user-delete` is destructive — re-run with --yes");
            }
            client.delete_user(&userid).await?;
            Ok((
                serde_json::json!({"userid": userid, "status": "deleted"}),
                0,
            ))
        }
        AccessCommand::GroupCreate { groupid, comment } => {
            client.create_group(&groupid, comment.as_deref()).await?;
            Ok((
                serde_json::json!({"groupid": groupid, "status": "created"}),
                0,
            ))
        }
        AccessCommand::GroupDelete { groupid, yes } => {
            if !yes {
                anyhow::bail!("`access group-delete` is destructive — re-run with --yes");
            }
            client.delete_group(&groupid).await?;
            Ok((
                serde_json::json!({"groupid": groupid, "status": "deleted"}),
                0,
            ))
        }
        AccessCommand::AclSet {
            path,
            role,
            user,
            group,
            token,
            no_propagate,
        } => {
            if user.is_none() && group.is_none() && token.is_none() {
                anyhow::bail!(
                    "`access acl-set` requires exactly one of --user, --group, or --token"
                );
            }
            client
                .modify_acl(
                    &path,
                    &role,
                    user.as_deref(),
                    group.as_deref(),
                    token.as_deref(),
                    !no_propagate,
                    false,
                )
                .await?;
            Ok((
                serde_json::json!({
                    "path": path,
                    "role": role,
                    "user": user,
                    "group": group,
                    "token": token,
                    "propagate": !no_propagate,
                    "status": "granted",
                }),
                0,
            ))
        }
        AccessCommand::AclUnset {
            path,
            role,
            user,
            group,
            token,
            yes,
        } => {
            if !yes {
                anyhow::bail!("`access acl-unset` is destructive — re-run with --yes");
            }
            if user.is_none() && group.is_none() && token.is_none() {
                anyhow::bail!(
                    "`access acl-unset` requires exactly one of --user, --group, or --token"
                );
            }
            client
                .modify_acl(
                    &path,
                    &role,
                    user.as_deref(),
                    group.as_deref(),
                    token.as_deref(),
                    true,
                    true,
                )
                .await?;
            Ok((
                serde_json::json!({
                    "path": path,
                    "role": role,
                    "user": user,
                    "group": group,
                    "token": token,
                    "status": "revoked",
                }),
                0,
            ))
        }
        AccessCommand::Permissions { userid, path } => {
            let perms = client
                .get_access_permissions(userid.as_deref(), path.as_deref())
                .await?;
            Ok((
                serde_json::json!({
                    "userid": userid, "path": path, "permissions": perms,
                }),
                0,
            ))
        }
        AccessCommand::Password { userid, password } => {
            client.change_user_password(&userid, &password).await?;
            Ok((serde_json::json!({"userid": userid, "changed": true}), 0))
        }
    }
}

/// Feature #10 — token CRUD.
pub async fn execute_token(
    client: &Arc<crate::api::PxClient>,
    action: TokenCommand,
) -> Result<(Value, i32)> {
    use crate::api::ProxmoxGateway;
    match action {
        TokenCommand::List { userid } => {
            let tokens = client.list_user_tokens(&userid).await?;
            Ok((serde_json::to_value(tokens)?, 0))
        }
        TokenCommand::Create {
            userid,
            tokenid,
            privsep,
            expire,
            comment,
        } => {
            let tok = client
                .create_token(&userid, &tokenid, privsep, expire, comment.as_deref())
                .await?;
            // The secret in `value` is shown ONCE. Highlight that fact
            // both in the JSON and in plain output via a banner.
            Ok((
                serde_json::json!({
                    "userid": userid,
                    "tokenid": tokenid,
                    "privsep": tok.privsep,
                    "expire": tok.expire,
                    "comment": tok.comment,
                    "value": tok.value,
                    "warning": "the token `value` is the secret and is shown ONCE — capture it now"
                }),
                0,
            ))
        }
        TokenCommand::Revoke {
            userid,
            tokenid,
            yes,
        } => {
            if !yes {
                anyhow::bail!("token revoke is destructive — re-run with --yes");
            }
            client.revoke_token(&userid, &tokenid).await?;
            Ok((
                serde_json::json!({
                    "userid": userid,
                    "tokenid": tokenid,
                    "status": "revoked"
                }),
                0,
            ))
        }
    }
}

/// Feature #10 — effective permissions via SSH shell-out (Option A).
pub async fn execute_perms(
    config: &crate::config::ProfileConfig,
    userid: &str,
    path_filter: Option<&str>,
    node: &str,
) -> Result<(Value, i32)> {
    use crate::ssh::{ExecOptions, SshPool};

    let ssh_cfg = config.ssh.clone().ok_or_else(|| {
        anyhow::anyhow!("[profiles.X.ssh] not configured — `proxxx perms` shells out via SSH")
    })?;
    let pool = SshPool::new(ssh_cfg, None)?;
    // Build the command. We pass userid through unchanged — pveum quotes
    // it server-side. We DO defend against shell-injection by refusing
    // any userid that contains shell metachars.
    // (Gemini audit) — defence in depth, three layers:
    //  1. Refuse-list of obvious shell metachars (early-out for the
    //     common attack patterns; produces a clearer error than a
    //     downstream pveum failure).
    //  2. `shell_quote`: wraps the value in single quotes and escapes
    //     internal `'` as `'\''`. Inside `'…'` bash does NOT interpret
    //     ANY metachar — backticks, $(), $VAR, `\` are all literal.
    //     The only escape is another `'`, which we handle. This is
    //     mathematically injection-proof at the shell layer.
    //  3. `--` separator before `{userid}`: even if pveum's argparser
    //     accepts flags after positionals, the `--` sentinel forces it
    //     to treat everything that follows as positional. This blocks
    //     argument-injection vectors like `--config-file=/etc/passwd`.
    if userid
        .chars()
        .any(|c| matches!(c, '`' | '$' | ';' | '&' | '|' | '\n' | '\r'))
    {
        anyhow::bail!("userid contains shell metacharacters — refusing");
    }
    let cmd = format!("pveum user permissions -- {}", shell_quote(userid));
    let res = pool.exec(node, &cmd, ExecOptions::default()).await?;
    if !res.ok() {
        anyhow::bail!(
            "pveum exited {:?}: {}",
            res.exit_code,
            res.stderr.trim().chars().take(500).collect::<String>()
        );
    }

    let mut perms = crate::access::parse_user_permissions(userid, &res.stdout);
    if let Some(p) = path_filter {
        perms.paths.retain(|x| x.path.contains(p));
    }
    // Render to JSON manually — `EffectivePermissions` isn't Serialize
    // (pure logic crate), so we shape it inline for the CLI.
    let json = serde_json::json!({
        "userid": perms.userid,
        "paths": perms.paths.iter().map(|pp| {
            serde_json::json!({
                "path": pp.path,
                "privileges": pp.privileges.iter().map(|(n, prop)| {
                    serde_json::json!({ "name": n, "propagate": prop })
                }).collect::<Vec<_>>()
            })
        }).collect::<Vec<_>>()
    });
    Ok((json, 0))
}

fn shell_quote(s: &str) -> String {
    // Empty input MUST quote as `''`. The bare path's `chars().all(…)`
    // predicate is vacuously true on empty, but emitting bare empty
    // means bash word-splitting silently drops the argument entirely
    // — so e.g. `pveum user permissions -- {shell_quote("")}` ends up
    // as `pveum user permissions --` with NO user argument, and
    // pveum prints help instead of erroring out on a missing user.
    // Pinned by the `shell_quote_round_trips_via_bash_dequote`
    // proptest, which failed on the empty-string shrink.
    if s.is_empty() {
        return "''".to_string();
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '!' | '_' | '-' | '.'))
    {
        return s.to_string();
    }
    let escaped = s.replace('\'', "'\\''");
    format!("'{escaped}'")
}

#[cfg(test)]
mod shell_quote_tests {
    use super::shell_quote;

    /// (Gemini audit) — single-quote wrapping is mathematically
    /// injection-proof. Inside single quotes, bash interprets nothing
    /// except another single quote (which we escape via the
    /// close-escape-reopen idiom `'\''`).
    #[test]
    fn ascii_userid_passes_through_unquoted() {
        // Bare-ASCII userids are safe to pass through; the test pins
        // the optimisation so a refactor doesn't regress it.
        assert_eq!(shell_quote("root@pam"), "root@pam");
        assert_eq!(shell_quote("svc-readonly"), "svc-readonly");
    }

    #[test]
    fn embedded_single_quote_is_escaped() {
        // The textbook tricky input: a value containing a single quote.
        // Output must produce a literal `'` after shell parsing.
        assert_eq!(shell_quote("o'reilly"), "'o'\\''reilly'");
    }

    #[test]
    fn metachars_become_literal_inside_single_quotes() {
        // Inside `'…'` bash does NOT interpret $, `, \, ;, |, &, (, )
        // — they all become literal.
        assert_eq!(shell_quote("$(rm -rf /)"), "'$(rm -rf /)'");
        assert_eq!(shell_quote("`whoami`"), "'`whoami`'");
        assert_eq!(shell_quote("a;b|c&d"), "'a;b|c&d'");
        assert_eq!(shell_quote("a\\b\"c"), "'a\\b\"c'");
    }

    #[test]
    fn injection_attempt_from_audit_becomes_inert_literal() {
        // Gemini's exact attack string, re-shell-parsed:
        //   input: test'; touch /tmp/pwned; '
        //   shell_quote → 'test'\''; touch /tmp/pwned; '\'''
        // Bash parses that as a single concatenated literal:
        //   'test' + \' + '; touch /tmp/pwned; ' + \' + ''
        // = test'; touch /tmp/pwned; '
        // pveum then sees a single argument with the metachars inert.
        let q = shell_quote("test'; touch /tmp/pwned; '");
        // Closure invariants: starts with a single quote, ends with one,
        // and every embedded `'` is closed before being escaped.
        assert!(q.starts_with('\''));
        assert!(q.ends_with('\''));
        // The escaped form `'\''` must appear for each input `'`.
        assert_eq!(q.matches("'\\''").count(), 2);
        // No raw shell-active sequence outside of quotes survives.
        assert!(!q.contains(";'") || q.contains("'\\''"));
    }
}

/// Property tests on `shell_quote` — the function defends shell-out
/// to `pveum` against a hostile userid (Audit phase 5.13). The unit
/// tests above pin specific known-attack payloads. These proptests
/// pin the structural contract for ANY UTF-8 input: the output must
/// either be bare-safe or fully single-quoted with every internal
/// `'` properly escape-sequenced, AND a faithful bash-style single-
/// quote unquoter must round-trip the output back to the input.
///
/// Why this matters: a single regression that accidentally let the
/// "bare-safe" branch accept a `;` or `$` character would open an
/// injection hole that bypasses every existing example test (none
/// of them check the universe of unsafe chars). proptest's 256
/// random cases cover the universe.
#[cfg(test)]
mod shell_quote_proptests {
    use super::shell_quote;
    use proptest::prelude::*;

    /// Parse a `shell_quote` OUTPUT back into the original input,
    /// emulating the subset of bash word-splitting that
    /// `shell_quote` is designed to be safe under. Supports two
    /// shapes only:
    ///   * bare-safe path: input == output, output is alphanumeric +
    ///     @!_-.
    ///   * single-quoted path: `'…'` with embedded `'\''` escapes.
    ///
    /// Returns `None` if the output doesn't match the expected shape
    /// (which itself is a test failure — the safety contract is
    /// "output IS one of these two shapes").
    fn bash_dequote(out: &str) -> Option<String> {
        if out.is_empty() {
            return None;
        }
        // Bare path — no quotes anywhere.
        if !out.contains('\'') {
            let all_safe = out
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '!' | '_' | '-' | '.'));
            return if all_safe {
                Some(out.to_string())
            } else {
                None
            };
        }
        // Quoted path — must start and end with `'`.
        if !out.starts_with('\'') || !out.ends_with('\'') {
            return None;
        }
        // Iterate the inner content, expanding `'\''` → `'`.
        let bytes = out.as_bytes();
        let mut decoded = String::new();
        let mut i = 1;
        let end = bytes.len() - 1; // exclude trailing `'`
        while i < end {
            if bytes[i] == b'\'' {
                // Inside the outer `'…'` region, the only legal `'` is
                // the start of a `'\''` close-escape-reopen sequence.
                if i + 3 < bytes.len()
                    && bytes[i + 1] == b'\\'
                    && bytes[i + 2] == b'\''
                    && bytes[i + 3] == b'\''
                {
                    decoded.push('\'');
                    i += 4;
                } else {
                    // Bare `'` mid-string OR end-of-quoted-region — both
                    // indicate the safety contract was broken.
                    return None;
                }
            } else {
                // Multi-byte UTF-8 safe: push the byte. We accumulate
                // bytes then reinterpret as UTF-8 at the end below.
                decoded.push(bytes[i] as char);
                i += 1;
            }
        }
        // Reconstruct any UTF-8 from raw bytes if the input had non-ASCII.
        // `decoded` was built byte-by-byte via `bytes[i] as char` which
        // is only valid for ASCII (< 0x80). For non-ASCII fast-path,
        // re-extract from the original slice.
        if decoded.chars().any(|c| (c as u32) >= 0x80) || decoded.contains('\u{00}') {
            // Fall back to byte-slice → str conversion.
            let inner = &out[1..out.len() - 1];
            let mut s = String::new();
            let mut rest = inner;
            while let Some(idx) = rest.find("'\\''") {
                s.push_str(&rest[..idx]);
                s.push('\'');
                rest = &rest[idx + 4..];
            }
            s.push_str(rest);
            return Some(s);
        }
        Some(decoded)
    }

    proptest! {
        /// Round-trip: ANY input that goes through `shell_quote` must
        /// be recoverable by the bash dequoter. This is the security
        /// contract: bash with `--` argument splitting receives
        /// EXACTLY the input as a single argv element, no expansion.
        #[test]
        fn shell_quote_round_trips_via_bash_dequote(s in any::<String>()) {
            let quoted = shell_quote(&s);
            let recovered = bash_dequote(&quoted);
            prop_assert_eq!(
                recovered.as_deref(),
                Some(s.as_str()),
                "shell_quote({:?}) = {:?} did not round-trip via bash_dequote (got {:?})",
                s, quoted, recovered
            );
        }

        /// Bare path correctness: input is returned unchanged IF AND
        /// ONLY IF it consists entirely of the safe-char set
        /// alphanumeric + `@!_-.`. Any deviation must trigger the
        /// quoted path.
        #[test]
        fn bare_path_used_iff_safe_chars(s in any::<String>()) {
            let safe = !s.is_empty()
                && s.chars().all(|c| {
                    c.is_ascii_alphanumeric() || matches!(c, '@' | '!' | '_' | '-' | '.')
                });
            let q = shell_quote(&s);
            if safe {
                prop_assert_eq!(&q, &s, "safe input {:?} should pass through bare", s);
            } else {
                // For non-safe input (including empty), the function
                // must produce a quoted form — i.e. start with `'`.
                prop_assert!(
                    q.starts_with('\''),
                    "unsafe input {:?} produced bare output {:?}",
                    s, q
                );
            }
        }

        /// Deterministic: same input always produces the same output.
        /// Pins against any future refactor that introduces randomness
        /// (e.g. variable-length padding) which would break shell
        /// equivalence proofs that build on `shell_quote`'s output.
        #[test]
        fn deterministic(s in any::<String>()) {
            prop_assert_eq!(shell_quote(&s), shell_quote(&s));
        }

        /// No raw shell metachar outside the protective quoting. The
        /// dangerous bash metachars (`;`, `|`, `&`, `$`, `` ` ``, `(`,
        /// `)`, `<`, `>`, newline) must NEVER appear in the bare
        /// (unquoted) output — that's the entire point of the safe-
        /// char allowlist. If any of them are in the input, the
        /// output must use the quoted form.
        #[test]
        fn metachars_never_appear_bare(s in any::<String>()) {
            let q = shell_quote(&s);
            // If the output is the bare form (no leading quote), then
            // it contains NO metachar — by construction of the allowlist.
            if !q.starts_with('\'') {
                for mc in &[';', '|', '&', '$', '`', '(', ')', '<', '>', '\n', '\r', ' ', '\t', '*', '?', '[', ']', '{', '}', '#', '~', '!', '\\', '"', '/'] {
                    if matches!(*mc, '@' | '!' | '_' | '-' | '.') {
                        continue; // these ARE in the allowlist
                    }
                    prop_assert!(
                        !q.contains(*mc),
                        "metachar {:?} survived bare in output {:?} for input {:?}",
                        mc, q, s
                    );
                }
            }
        }
    }
}
