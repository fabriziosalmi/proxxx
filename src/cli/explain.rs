//! `proxxx explain <error-id>` — bundled error knowledge base.
//!
//! Every typed error variant proxxx can emit has one entry in
//! [`ENTRIES`] below. Each entry carries the *cause*, a numbered
//! list of *fixes*, *commands* operators can run to diagnose, and
//! *references* (forum threads / PVE wiki). Bundled means it ships
//! with the binary — no network needed.
//!
//! Output picks itself from `--format`:
//!   text (default)  → plain-text rendering with sigil-marked sections
//!   md              → raw markdown
//!   json            → structured `{id, title, cause, fixes,
//!                     commands, references}` for LLM agents
//!
//! ## Adding a new entry
//!
//! 1. Add the typed error in `src/api/error.rs` (or wherever).
//! 2. Append a new [`ExplainEntry`] to [`ENTRIES`] below — keep the
//!    `id` snake-case and stable (it's user-typed at the CLI).
//! 3. Update `pre-commit/01-feature-coverage.md` if you're tracking
//!    coverage of typed-error explanations.
//!
//! ## What's deferred (per #72 "optional")
//!
//! `--apply-fix <N>` — turning the Nth fix into an actual proxxx
//! command invocation that flows through pre-flight + audit. Needs
//! a structured "machine-fix" shape next to the human-readable fix
//! strings, plus a dispatch table back into the CLI. Left as a
//! follow-up issue once the knowledge base proves useful.

use anyhow::{Context, Result};
use clap::Subcommand;
use serde::Serialize;
use serde_json::Value;

/// One entry in the bundled knowledge base. `'static` everywhere so
/// the table is a true compile-time constant — zero runtime cost on
/// every other command path.
#[derive(Debug, Clone, Serialize)]
pub struct ExplainEntry {
    /// Stable kebab-case identifier the user types: `proxxx explain
    /// <id>`. Also used to derive the `id` field in JSON output.
    pub id: &'static str,
    /// One-line title, capitalised, no trailing period.
    pub title: &'static str,
    /// 1-3 sentence explanation of what causes this error. No fix
    /// hints here — those live in `fixes`.
    pub cause: &'static str,
    /// Numbered fixes in priority order. Each is a short imperative
    /// sentence ("Re-run `proxxx auth login`."). Concrete enough
    /// that an operator (or LLM agent) can act on it without further
    /// research.
    pub fixes: &'static [&'static str],
    /// Diagnostic commands. Format: free-form text including
    /// language-fenced code is fine, but each entry should be one
    /// distinct command or short sequence.
    pub commands: &'static [&'static str],
    /// External references: URLs, PVE wiki anchors, forum threads.
    /// Empty array if none.
    pub references: &'static [&'static str],
}

/// The bundled knowledge base. **Order matters** — entries are
/// displayed in declaration order when `proxxx explain` is run
/// without an argument (the catalog listing).
///
/// Every typed error variant in `api::error::ApiError`,
/// `config::ConfigError`, and `app::preflight::PreflightRefusal`
/// gets an entry. See [`entries_cover_every_typed_error`] in the
/// test module for the enforcement.
pub const ENTRIES: &[ExplainEntry] = &[
    ExplainEntry {
        id: "unauthorized",
        title: "Proxmox rejected our credentials (401)",
        cause: "PVE returned HTTP 401. Common causes: API token revoked or expired, password changed since proxxx was configured, PAM ticket expired after a long sleep/suspend, or wrong realm (`@pam` vs `@pve`).",
        fixes: &[
            "Re-run `proxxx auth login` to refresh the ticket.",
            "Check the token in the PVE web UI (Datacenter → API Tokens) — make sure it exists, isn't expired, and has the privileges your operations need.",
            "Verify the user/realm in `config.toml` matches the token's owner: `user = \"root@pam\"` not `\"root@pve\"`.",
            "If using `auth = \"token\"`, confirm `token_id` matches the token name exactly (case-sensitive).",
        ],
        commands: &[
            "proxxx auth show              # check what proxxx thinks the auth is",
            "proxxx auth login             # interactive re-auth",
            "curl -k https://<pve>:8006/api2/json/access/ticket  # raw probe",
        ],
        references: &[
            "https://pve.proxmox.com/wiki/Proxmox_VE_API#Authentication",
            "https://pve.proxmox.com/wiki/User_Management#pveum_tokens",
        ],
    },
    ExplainEntry {
        id: "forbidden",
        title: "Proxmox refused — insufficient privileges (403)",
        cause: "Credentials are valid but the API token / user doesn't have the privilege for this operation. Common with restricted tokens that skip the `Privilege Separation` checkbox.",
        fixes: &[
            "Grant the missing privilege via Datacenter → Permissions → Add → API Token Permission, scoping it to the right path (`/`, `/vms/<id>`, `/storage/<name>`).",
            "If the token has `Privilege Separation` enabled, the token only gets a SUBSET of its user's privileges — uncheck it temporarily to test, then re-enable with explicit ACL grants.",
            "For pool-scoped operations, add the token to a permission rule on the pool path: `/pool/<name>`.",
        ],
        commands: &[
            "proxxx ls acl                    # list ACL grants",
            "proxxx state export --resource acl > acl.toml   # snapshot for review",
        ],
        references: &[
            "https://pve.proxmox.com/wiki/User_Management#_permissions",
            "https://pve.proxmox.com/pve-docs/api-viewer/index.html  # which roles cover which endpoints",
        ],
    },
    ExplainEntry {
        id: "not-found",
        title: "Proxmox resource not found (404)",
        cause: "The named guest, node, storage, pool, or task UPID doesn't exist on this cluster. Either a typo, the resource was deleted since the operator's last view, or proxxx is pointed at the wrong cluster (multi-cluster mismatch).",
        fixes: &[
            "Re-run `proxxx ls <kind>` to see what actually exists.",
            "Check `proxxx --profile <name>` matches the cluster you intended — common after pivoting between profiles.",
            "For VMID lookups: PVE allows the same VMID across clusters; double-check you're on the right one with `proxxx ls nodes`.",
        ],
        commands: &[
            "proxxx ls guests --node <node>      # list every guest on a node",
            "proxxx ls storage                   # list every storage",
            "proxxx tasks --node <node>          # recent task UPIDs",
        ],
        references: &[],
    },
    ExplainEntry {
        id: "rate-limited",
        title: "Proxmox transient failure after retries (429 / 5xx)",
        cause: "PVE returned 429, 502, 503, or 504 repeatedly within proxxx's retry budget. Usually a sign the cluster is genuinely overloaded — `pvestatd` slow, `pveproxy` saturated, or a storage backend hanging upstream of pveproxy.",
        fixes: &[
            "Wait a minute and retry — most transient overloads clear themselves.",
            "Check `pvestatd` health on each node: `systemctl status pvestatd`. A wedged pvestatd makes every API call slow.",
            "Look for hanging NFS / Ceph mounts — `mount | grep nfs` and `dmesg | tail` on each node.",
            "If symptoms persist, bump `rate_limit` in `config.toml` down to give pveproxy more headroom.",
        ],
        commands: &[
            "proxxx logs tail --service pvestatd --since '5 minutes ago'",
            "proxxx logs tail --service pveproxy --grep 'overload' --since '15 minutes ago'",
        ],
        references: &[
            "https://pve.proxmox.com/wiki/High_Availability#ha_manager_status",
        ],
    },
    ExplainEntry {
        id: "storage-hang",
        title: "Proxmox storage/upstream hang (595)",
        cause: "Status 595 is Proxmox-specific: `pveproxy` timed out waiting on an upstream — `pvestatd`, NFS, Ceph, or a storage daemon. The cluster is degraded; the API surface is partially unavailable.",
        fixes: &[
            "Identify the hanging upstream — usually a wedged NFS mount or a stalled Ceph OSD.",
            "On each node: `mount | grep nfs && dmesg | tail -50` to spot frozen mounts.",
            "For Ceph: `ceph -s` from any monitor; look for `slow ops` or `degraded objects`.",
            "Force-unmount the hung mount only after confirming no in-flight VM I/O depends on it: `umount -l /mnt/path`.",
        ],
        commands: &[
            "proxxx logs tail --service pveproxy --grep '595' --since '15 minutes ago'",
            "proxxx ls nodes                     # confirm which node went silent",
        ],
        references: &[
            "https://forum.proxmox.com/threads/595-network-connect-timeout-error.119427/",
        ],
    },
    ExplainEntry {
        id: "transport",
        title: "Network / TLS / connection failure",
        cause: "Couldn't even talk to PVE: DNS failure, TLS handshake failure, connection refused, or proxxx's TCP socket timeout. Includes self-signed cert rejections when `verify_tls = true`.",
        fixes: &[
            "Verify reachability: `curl -k https://<pve>:8006/api2/json/version` from the same host running proxxx.",
            "If `verify_tls = true` and the cert is self-signed, either install the cert into the system trust store or set `verify_tls = false` (MITM risk).",
            "For DNS issues, try replacing the hostname in `url = …` with a literal IP.",
            "Check intermediate firewalls / VPN — port 8006 must be reachable from your machine to every PVE node you talk to.",
        ],
        commands: &[
            "curl -kv https://<pve>:8006/api2/json/version  # verbose probe",
            "openssl s_client -connect <pve>:8006 -showcerts < /dev/null",
            "proxxx doctor                                   # built-in connectivity diagnostics",
        ],
        references: &[],
    },
    ExplainEntry {
        id: "payload-too-large",
        title: "Response body exceeds size limit",
        cause: "PVE returned >32 MiB in a single response. Almost always a misbehaving endpoint (huge task log dump, runaway query) rather than legitimate data. proxxx refuses to parse to avoid memory blow-up.",
        fixes: &[
            "Narrow the query — for `tasks` use `--limit`, for log views use a `--since` window.",
            "If a particular endpoint is genuinely returning megabytes of valid data, file a proxxx issue with the endpoint + cluster size — the 32 MiB cap can be raised with justification.",
        ],
        commands: &[
            "proxxx tasks --limit 50                  # bounded task list",
            "proxxx logs tail --since '5 minutes ago' --no-follow",
        ],
        references: &[],
    },
    ExplainEntry {
        id: "parse",
        title: "JSON parse error from PVE response",
        cause: "PVE returned `Content-Type: application/json` but the body wasn't valid JSON, OR the JSON shape doesn't match what proxxx expected for that endpoint. Schema drift between PVE versions is the usual cause.",
        fixes: &[
            "Check the PVE version: `proxxx doctor` reports it. If you're on a new major (e.g. 9.x post-9.1), some endpoints changed shape.",
            "Open a proxxx issue with the failing endpoint path and PVE version — schema drift is fixable in the model layer.",
            "As a workaround, query the raw API: `proxxx api <method> <path>`.",
        ],
        commands: &[
            "proxxx doctor                                  # PVE version + reachability",
            "proxxx api GET /nodes/<node>/status            # raw bypass of the typed model",
        ],
        references: &[],
    },
    ExplainEntry {
        id: "other",
        title: "Uncategorized HTTP status from PVE",
        cause: "PVE returned a status code proxxx doesn't have a dedicated handler for. Body is included in the error message for diagnosis.",
        fixes: &[
            "Read the body — PVE usually puts a human-readable message there.",
            "Check the PVE web UI for the same operation; if it fails identically, the issue is server-side.",
            "File a proxxx issue if the status looks like one proxxx should categorize (e.g. recurring 5xx that isn't in the retry set).",
        ],
        commands: &["proxxx logs tail --service pveproxy --since '5 minutes ago'"],
        references: &[],
    },
    ExplainEntry {
        id: "config-not-found",
        title: "Config file missing",
        cause: "proxxx looked for `config.toml` at the platform-default location and didn't find it. First-run state, or the file was deleted/moved.",
        fixes: &[
            "Run `proxxx init --interactive` — the wizard probes the cluster live and writes a working config.",
            "If you have a config elsewhere, set `PROXXX_CONFIG` to its path, or move it to the default location (printed in the error message).",
        ],
        commands: &[
            "proxxx init --interactive            # guided setup",
            "ls -la ~/Library/Application\\ Support/dev.proxxx.proxxx/   # macOS",
            "ls -la ~/.config/proxxx/             # Linux",
        ],
        references: &[],
    },
    ExplainEntry {
        id: "config-io",
        title: "Failed to read config file",
        cause: "The file exists at the expected path but reading it failed — usually file permissions (the wizard enforces 0600), occasionally a wedged filesystem.",
        fixes: &[
            "Check ownership: `ls -la <path>` — the file should be owned by you.",
            "If permissions look wrong: `chmod 0600 <path>` (matches what the wizard sets).",
            "If the filesystem is shared (NFS / autofs) and slow, try the local copy.",
        ],
        commands: &["stat <config-path>"],
        references: &[],
    },
    ExplainEntry {
        id: "config-toml",
        title: "Invalid TOML in config file",
        cause: "The config exists and is readable but isn't valid TOML — usually a syntax error from a hand-edit, or a stray BOM after copying from a non-Unix editor.",
        fixes: &[
            "Locate the line in the error message and check for unbalanced quotes, missing `=`, or stray bytes.",
            "Validate the file with a TOML linter: `taplo lint <path>` or paste into https://toml-lint.com/.",
            "If unsure, regenerate from scratch: `proxxx init --interactive` (back up the existing file first).",
        ],
        commands: &[
            "taplo lint <config-path>             # if taplo is installed",
            "file <config-path>                   # check for BOM / encoding",
        ],
        references: &["https://toml.io/en/"],
    },
    ExplainEntry {
        id: "freeze-refusal",
        title: "Incident lockdown active — mutations refused",
        cause: "proxxx's freeze lock is active. Every POST/PUT/DELETE refuses immediately, exits 8, and tells the operator why. Reads still work — investigators need observation.",
        fixes: &[
            "If the freeze is intentional (live incident), wait for the TTL to expire or coordinate with the operator who froze.",
            "If the freeze is stale (forgotten, no TTL, false alarm), thaw it: `proxxx incident thaw --reason '<text>'`.",
            "Always pair `freeze` with `--ttl <duration>` — a forgotten freeze with no TTL is the operational nightmare we're trying to avoid.",
            "Check the audit log for who froze and why: every freeze/thaw is recorded under the `incident.*` action prefix.",
        ],
        commands: &[
            "proxxx incident status",
            "proxxx incident thaw --reason '<text>'",
            "proxxx audit export --limit 20 | grep incident",
        ],
        references: &["docs/reference/exit-codes.md"],
    },
    ExplainEntry {
        id: "preflight-refusal",
        title: "Pre-flight refused: SEVERE risk without --allow-risk",
        cause: "proxxx's pre-flight risk checks rated the requested operation `Severe` (e.g. deleting a guest with active TCP listeners, migrating with local disks while heavily loaded). The default policy is to refuse rather than execute — exit code 6.",
        fixes: &[
            "Read the risk list printed above the error. Each line tells you what specifically tripped the gate.",
            "If the risk is acceptable, re-run with `--allow-risk` to bypass. You own the consequence.",
            "If the risk is NOT acceptable, fix the underlying state first — e.g. drain the guest's connections, evacuate the node, schedule a maintenance window.",
        ],
        commands: &[
            "proxxx preflight <op> <vmid>         # show the risk assessment without acting",
            "proxxx exec <vmid> -- ss -tln        # see what's listening before stopping",
        ],
        references: &["docs/reference/exit-codes.md"],
    },
];

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum ExplainFormat {
    /// Plain text with sigil-marked sections (default).
    Text,
    /// Raw markdown.
    Md,
    /// Structured JSON object. LLM-friendly.
    Json,
}

/// Arguments for `proxxx explain`. Unlike most CLI commands, this is
/// flat (no subcommand) — `proxxx explain unauthorized` reads more
/// naturally than `proxxx explain lookup unauthorized`.
#[derive(Debug, clap::Args)]
pub struct ExplainArgs {
    /// Error ID (kebab-case). Run `proxxx explain` with no args for
    /// the full catalog.
    ///
    /// Examples:
    ///   proxxx explain                       # catalog
    ///   proxxx explain unauthorized
    ///   proxxx explain storage-hang
    ///   proxxx explain rate-limited --output json | jq .fixes
    pub id: Option<String>,

    /// Output format. Text (default) for humans, markdown for piping
    /// into a doc tool, json for LLM agents.
    #[arg(long, value_enum, default_value_t = ExplainFormat::Text)]
    pub output: ExplainFormat,
}

/// Type alias kept for the dispatch table — `Command::Explain {
/// action: ExplainCommand }` is the existing pattern in `cli/mod.rs`.
pub type ExplainCommand = ExplainArgs;

// Suppress the unused-import lint on `Subcommand` — the file used to
// expose a `#[derive(Subcommand)]` enum; we now use `Args` directly
// but keep the import for the case where future subcommands return.
#[allow(unused_imports)]
use Subcommand as _Subcommand;

/// Execute `proxxx explain …`. Returns `Value::Null` so the standard
/// print pipeline is skipped — we write directly to stdout.
pub fn execute_explain(args: ExplainArgs) -> Result<(Value, i32)> {
    // No id → print the catalog and exit 0.
    let Some(id) = args.id else {
        print_catalog(args.output);
        return Ok((Value::Null, 0));
    };
    let entry = lookup(&id).with_context(|| {
        format!("no explain entry for `{id}` — try `proxxx explain` with no args for the catalog")
    })?;
    match args.output {
        ExplainFormat::Text => print_text(entry),
        ExplainFormat::Md => print_markdown(entry),
        ExplainFormat::Json => print_json(entry)?,
    }
    Ok((Value::Null, 0))
}

/// Find an entry by its `id`. Case-insensitive on lookup so
/// `Unauthorized` works as well as `unauthorized`.
#[must_use]
pub fn lookup(id: &str) -> Option<&'static ExplainEntry> {
    let lower = id.to_ascii_lowercase();
    ENTRIES.iter().find(|e| e.id == lower)
}

fn print_catalog(output: ExplainFormat) {
    if matches!(output, ExplainFormat::Json) {
        // For JSON, emit a flat array of `{id, title}` so pipeline
        // consumers can grep without re-parsing.
        let cat: Vec<serde_json::Value> = ENTRIES
            .iter()
            .map(|e| serde_json::json!({"id": e.id, "title": e.title}))
            .collect();
        match serde_json::to_string_pretty(&cat) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("explain catalog json: {e}"),
        }
    } else {
        println!("Known error IDs (run `proxxx explain <id>` for full details):\n");
        // Compute column width once so titles align.
        let max_id = ENTRIES.iter().map(|e| e.id.len()).max().unwrap_or(8);
        for e in ENTRIES {
            println!(
                "  {id:<width$}   {title}",
                id = e.id,
                width = max_id,
                title = e.title
            );
        }
    }
}

fn print_text(e: &ExplainEntry) {
    println!("# {} ({})\n", e.title, e.id);
    println!("Cause:");
    println!("  {}", wrap_indent(e.cause, "  "));
    if !e.fixes.is_empty() {
        println!("\nFixes:");
        for (i, fix) in e.fixes.iter().enumerate() {
            println!("  {n}. {fix}", n = i + 1);
        }
    }
    if !e.commands.is_empty() {
        println!("\nDiagnostic commands:");
        for c in e.commands {
            println!("  $ {c}");
        }
    }
    if !e.references.is_empty() {
        println!("\nReferences:");
        for r in e.references {
            println!("  - {r}");
        }
    }
}

fn print_markdown(e: &ExplainEntry) {
    println!("# {} (`{}`)\n", e.title, e.id);
    println!("## Cause\n\n{}\n", e.cause);
    if !e.fixes.is_empty() {
        println!("## Fixes\n");
        for (i, fix) in e.fixes.iter().enumerate() {
            println!("{n}. {fix}", n = i + 1);
        }
        println!();
    }
    if !e.commands.is_empty() {
        println!("## Diagnostic commands\n\n```bash");
        for c in e.commands {
            println!("{c}");
        }
        println!("```\n");
    }
    if !e.references.is_empty() {
        println!("## References\n");
        for r in e.references {
            println!("- {r}");
        }
        println!();
    }
}

fn print_json(e: &ExplainEntry) -> Result<()> {
    let s = serde_json::to_string_pretty(e)?;
    println!("{s}");
    Ok(())
}

/// Soft-wrap a single string into a multi-line indented block. We
/// keep this simple — split on whitespace, accumulate ≤ 76 chars per
/// line, prepend the indent to each continuation line. Good enough
/// for the cause-paragraph, the only place it's used.
fn wrap_indent(text: &str, continuation_indent: &str) -> String {
    let mut out = String::new();
    let mut line_len = 0_usize;
    for word in text.split_whitespace() {
        // Account for the leading space between words.
        let needed = if line_len == 0 {
            word.len()
        } else {
            word.len() + 1
        };
        if line_len + needed > 76 {
            out.push('\n');
            out.push_str(continuation_indent);
            line_len = 0;
        }
        if line_len > 0 {
            out.push(' ');
            line_len += 1;
        }
        out.push_str(word);
        line_len += word.len();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_entry_has_required_fields() {
        for e in ENTRIES {
            assert!(!e.id.is_empty(), "empty id");
            assert!(
                e.id.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
                "id `{}` must be kebab-case",
                e.id
            );
            assert!(!e.title.is_empty(), "empty title for {}", e.id);
            assert!(!e.cause.is_empty(), "empty cause for {}", e.id);
            assert!(!e.fixes.is_empty(), "no fixes for {}", e.id);
        }
    }

    #[test]
    fn ids_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for e in ENTRIES {
            assert!(seen.insert(e.id), "duplicate id {}", e.id);
        }
    }

    #[test]
    fn lookup_is_case_insensitive() {
        assert!(lookup("unauthorized").is_some());
        assert!(lookup("Unauthorized").is_some());
        assert!(lookup("UNAUTHORIZED").is_some());
        assert!(lookup("not-a-real-error").is_none());
    }

    /// Every typed error variant in the codebase that can reach an
    /// operator's terminal should have a knowledge-base entry. This
    /// test pins the expected IDs and fails if the table drifts.
    /// Update the list when adding new typed errors.
    #[test]
    fn entries_cover_every_typed_error() {
        let expected: &[&str] = &[
            // ApiError variants (src/api/error.rs):
            "unauthorized",
            "forbidden",
            "not-found",
            "rate-limited",
            "storage-hang",
            "transport",
            "payload-too-large",
            "parse",
            "other",
            // ConfigError variants (src/config/mod.rs):
            "config-not-found",
            "config-io",
            "config-toml",
            // Preflight refusal (src/app/preflight.rs):
            "preflight-refusal",
            // Incident lockdown (src/incident/mod.rs):
            "freeze-refusal",
        ];
        for id in expected {
            assert!(
                lookup(id).is_some(),
                "missing explain entry for typed error: {id}",
            );
        }
    }

    #[test]
    fn json_serializes_to_canonical_shape() {
        let e = lookup("unauthorized").unwrap();
        let s = serde_json::to_string(e).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["id"], "unauthorized");
        assert!(v["fixes"].is_array());
        assert!(!v["fixes"].as_array().unwrap().is_empty());
        // The shape is what LLM agents will key off of, so pin all
        // the field names explicitly.
        for key in &["id", "title", "cause", "fixes", "commands", "references"] {
            assert!(
                v.get(key).is_some(),
                "missing field `{key}` in serialized entry",
            );
        }
    }

    #[test]
    fn wrap_indent_respects_width() {
        let long = "word ".repeat(40);
        let wrapped = wrap_indent(long.trim(), "    ");
        // Should have inserted at least one newline.
        assert!(wrapped.contains('\n'), "expected wrap, got: {wrapped:?}");
        // Continuation lines should start with the indent.
        for line in wrapped.lines().skip(1) {
            assert!(
                line.starts_with("    "),
                "continuation line missing indent: {line:?}",
            );
        }
    }
}
