//! `proxxx state {export}` — read live cluster state into TOML (or
//! JSON).
//!
//! v1 ships export only, pools only. Subsequent commands (`diff`,
//! `apply`) and resource families (acl, storage, firewall-cluster,
//! backup-jobs, notifications) land in follow-up PRs tracked by epic
//! [#74](https://github.com/fabriziosalmi/proxxx/issues/74).

use anyhow::{Context, Result};
use clap::{Subcommand, ValueEnum};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;

use crate::api::PxClient;
use crate::state;

/// Local output-format choice for `state export`. Independent of the
/// global `--format` flag because TOML isn't part of `OutputFormat` —
/// `state export` is the only command that emits TOML, so the format
/// surface stays here rather than bleeding into the global enum.
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum ExportFormat {
    /// TOML (default). The canonical format for the `GitOps` workflow
    /// — diff-stable byte-for-byte across runs against an unchanged
    /// cluster.
    #[default]
    Toml,
    /// JSON (pretty). For piping into `jq` / programmatic consumers.
    Json,
}

#[derive(Debug, Subcommand)]
pub enum StateCommand {
    /// Export the cluster's mutable state.
    ///
    /// Supported resources: `pools`, `acl`, `all` (every supported
    /// family). More (storage, firewall-cluster, backup-jobs,
    /// notifications) land per the ladder in epic #74.
    ///
    /// The resulting document is byte-stable across runs against an
    /// unchanged cluster — every collection is sorted by its identity
    /// field on the way out — so a `git diff` after a re-export only
    /// shows actual cluster drift, never serialisation noise.
    ///
    /// Examples:
    ///   proxxx state export                                 # default: pools, TOML to stdout
    ///   proxxx state export > state.toml                    # capture to file
    ///   proxxx state export --output json | jq '.pools[0]'  # programmatic
    Export {
        /// Resource family to export. Valid: `pools`, `acl`, `all`.
        /// More families coming — see issue #74.
        #[arg(long, default_value = "pools")]
        resource: String,

        /// Output format for the exported document. TOML (default)
        /// is the canonical disk format for the `GitOps` workflow;
        /// JSON is for piping into `jq` and other programmatic
        /// consumers. Distinct from the global `--format` flag,
        /// which controls how proxxx's normal table/json/plain
        /// output is rendered — state export bypasses that pipeline
        /// and writes the document directly to stdout.
        #[arg(long, value_enum, default_value_t = ExportFormat::Toml)]
        output: ExportFormat,
    },

    /// Compare a declared cluster state file against the live
    /// cluster. Read-only: never mutates. Prints a human-readable
    /// per-change summary by default; `--output json` emits a
    /// structured array of `Change` objects for tooling.
    ///
    /// Exit code:
    ///   0 — live state already matches declared (no changes)
    ///   2 — changes exist (the apply layer would have work to do)
    ///   1 — error (file unreadable, PVE unreachable, etc.)
    ///
    /// CI-friendly: a `state diff` step in a pipeline can gate a
    /// merge on "declared state matches live", catching drift before
    /// it accumulates.
    Diff {
        /// Path to the declared state TOML file. Typically the
        /// output of an earlier `proxxx state export`, possibly
        /// hand-edited.
        declared: PathBuf,

        /// Output format. Default: human-readable per-change line.
        #[arg(long, value_enum, default_value_t = DiffFormat::Text)]
        output: DiffFormat,
    },
}

/// Local output-format choice for `state diff`. Like `ExportFormat`,
/// this is independent of the global `--format` flag because TOML
/// isn't a meaningful diff format (the diff IS a sequence of
/// changes, not a TOML document).
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum DiffFormat {
    /// Human-readable: one `<sigil> <resource>: <identity>` line per
    /// change. `+` = create, `~` = update, `-` = delete (matches
    /// `diff(1)` convention).
    #[default]
    Text,
    /// JSON array of `Change` objects with full before/after values.
    /// For pipeline consumption.
    Json,
}

/// Execute a `proxxx state …` invocation.
///
/// Export prints the document directly to stdout in the requested
/// format and returns `Value::Null` to skip the standard print
/// pipeline — the document IS the output, re-serialising it through
/// `format::print` would either escape the TOML's newlines or wrap
/// the JSON in an additional outer layer.
pub async fn execute_state(
    client: &Arc<PxClient>,
    profile: Option<&str>,
    action: StateCommand,
) -> Result<(Value, i32)> {
    match action {
        StateCommand::Export { resource, output } => {
            let resources = state::export::Resource::parse(&resource)?;
            let profile_label = profile.unwrap_or("default");
            let exported =
                state::export::export_state(client.as_ref(), &resources, profile_label).await?;

            match output {
                ExportFormat::Toml => {
                    let s = toml::to_string_pretty(&exported)?;
                    print!("{s}");
                    if !s.ends_with('\n') {
                        println!();
                    }
                }
                ExportFormat::Json => {
                    let s = serde_json::to_string_pretty(&exported)?;
                    println!("{s}");
                }
            }
            Ok((Value::Null, 0))
        }

        StateCommand::Diff { declared, output } => {
            // Read the declared file.
            let toml_str = std::fs::read_to_string(&declared)
                .with_context(|| format!("reading declared state from {}", declared.display()))?;
            let declared_state: state::model::ClusterState = toml::from_str(&toml_str)
                .with_context(|| {
                    format!(
                        "parsing TOML at {} — is it the output of `proxxx state export`?",
                        declared.display()
                    )
                })?;

            // Export live across every supported family — diff
            // ignores anything that's not in BOTH declared and live,
            // so over-fetching is cheap and correct.
            let profile_label = profile.unwrap_or("default");
            let live_state = state::export::export_state(
                client.as_ref(),
                &[
                    state::export::Resource::Pools,
                    state::export::Resource::Acl,
                    state::export::Resource::Storage,
                ],
                profile_label,
            )
            .await?;

            let changes = state::diff::diff(&declared_state, &live_state);

            match output {
                DiffFormat::Text => {
                    if changes.is_empty() {
                        println!("(no changes — live state matches declared)");
                    } else {
                        for c in &changes {
                            println!("{}", state::diff::summary_line(c));
                        }
                    }
                }
                DiffFormat::Json => {
                    let json = serde_json::to_string_pretty(&changes)?;
                    println!("{json}");
                }
            }

            // Exit code: 0 = no changes, 2 = changes exist (apply
            // would do something), 1 = error (handled by `?`).
            // 2 is the convention for "diff exists" — matches
            // `diff(1)` and modern CI pipelines.
            let exit = i32::from(!changes.is_empty()) * 2;
            Ok((Value::Null, exit))
        }
    }
}
