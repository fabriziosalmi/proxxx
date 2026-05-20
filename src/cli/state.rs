//! `proxxx state {export,diff,apply}` — read live cluster state into
//! TOML / JSON, diff a declared file against live, and converge live
//! toward declared.
//!
//! Resource families covered today: pools, ACL grants, cluster
//! storage definitions. Cluster firewall, backup jobs, notifications,
//! and HA groups land in follow-up PRs tracked by epic
//! [#74](https://github.com/fabriziosalmi/proxxx/issues/74). Pre-flight
//! risk gates + HITL approval per destructive change are tracked
//! separately and will wrap the apply dispatch without changing it.

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

    /// Converge live cluster state toward the declared state file.
    ///
    /// Reads the declared TOML, computes the diff against live, then
    /// dispatches each change to PVE. Returns one outcome row per
    /// change: `applied`, `skipped` (with reason), or `failed`.
    ///
    /// Safety model:
    ///   --dry-run             — never mutates; every change reports
    ///                           as `skipped (dry_run)`. Always safe.
    ///   (no --prune)          — `delete` changes report as `skipped
    ///                           (prune_policy)`. Default behaviour.
    ///   --prune               — actually delete resources absent from
    ///                           the declared file.
    ///   (default)             — fail-fast: first failure halts the
    ///                           apply; remainder reports as `skipped
    ///                           (aborted_by_prior)`.
    ///   --continue-on-error   — keep going past failures.
    ///
    /// Exit code:
    ///   0 — all changes applied or skipped without failure
    ///   2 — at least one change failed
    ///   1 — error (file unreadable, PVE unreachable, etc.)
    ///
    /// Pre-flight risk gates fire BEFORE any PVE call. Severe
    /// risks (deleting a non-empty pool, removing a root-equivalent
    /// ACL grant, deleting a shared storage, very large change
    /// batches) refuse the apply unless `--allow-risk` is set. Exit
    /// code 6 ("Pre-flight risk refused") matches the per-guest
    /// pre-flight contract.
    ///
    /// `--interactive` adds a Human-In-The-Loop step: each Severe
    /// change prompts `[y/N]` on stdin. Use for one-off manual
    /// applies; not for scripted pipelines (use `--allow-risk`).
    ///
    /// Always run `--dry-run` first, then `--prune` only when
    /// you've reviewed the diff.
    ///
    /// Examples:
    ///   proxxx state apply state.toml --dry-run                       # preview
    ///   proxxx state apply state.toml                                  # apply, no deletes
    ///   proxxx state apply state.toml --prune                          # apply + delete drift
    ///   proxxx state apply state.toml --prune --interactive            # prompt per Severe
    ///   proxxx state apply state.toml --prune --allow-risk             # bypass gate (CI)
    Apply {
        /// Path to the declared state TOML file.
        declared: PathBuf,

        /// Preview only — never mutates. Every change reports as
        /// `skipped (dry_run)`. Recommended for the first run on any
        /// declared state file.
        #[arg(long)]
        dry_run: bool,

        /// Required to execute `delete` changes. Without this, deletes
        /// report as `skipped (prune_policy)`. Treat as a safety
        /// interlock — opt in deliberately.
        #[arg(long)]
        prune: bool,

        /// Don't halt on the first failure. Each change is attempted
        /// in order regardless of prior failures. Useful for
        /// "best-effort" cluster sweeps; risky if changes have
        /// ordering dependencies.
        #[arg(long)]
        continue_on_error: bool,

        /// Override the pre-flight Severe-risk gate. Without this,
        /// any Severe risk (non-empty pool delete, root-role ACL
        /// delete, shared storage delete, batch ≥ 50 changes) refuses
        /// the apply with exit code 6. Pass `--allow-risk` only when
        /// the operator has explicitly reviewed the diff.
        #[arg(long)]
        allow_risk: bool,

        /// Prompt `[y/N]` on stdin for every Severe-risk change.
        /// Mutually informative with `--allow-risk`: --allow-risk
        /// bypasses the gate silently; --interactive lets the
        /// operator approve case-by-case. Don't use in CI pipelines
        /// — there's no stdin.
        #[arg(long)]
        interactive: bool,

        /// Output format. Default: human-readable per-change line.
        #[arg(long, value_enum, default_value_t = ApplyOutputFormat::Text)]
        output: ApplyOutputFormat,
    },
}

/// Local output-format choice for `state apply`. Same rationale as
/// `ExportFormat`/`DiffFormat` — TOML is not a meaningful apply
/// output (the apply IS a sequence of outcomes, not a TOML
/// document).
#[derive(Debug, Clone, Copy, ValueEnum, Default)]
pub enum ApplyOutputFormat {
    /// Human-readable: one `<sigil> <resource>: <identity> — <status>`
    /// line per outcome.
    #[default]
    Text,
    /// JSON array of `ApplyOutcome` objects with full change + result.
    /// For pipeline consumption / audit.
    Json,
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

        StateCommand::Apply {
            declared,
            dry_run,
            prune,
            continue_on_error,
            allow_risk,
            interactive,
            output,
        } => {
            let toml_str = std::fs::read_to_string(&declared)
                .with_context(|| format!("reading declared state from {}", declared.display()))?;
            let declared_state: state::model::ClusterState = toml::from_str(&toml_str)
                .with_context(|| {
                    format!(
                        "parsing TOML at {} — is it the output of `proxxx state export`?",
                        declared.display()
                    )
                })?;

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

            let mut changes = state::diff::diff(&declared_state, &live_state);

            // Pre-flight risk gate. Dry-run skips the gate (the
            // operator is exploring, not committing) — every other
            // path goes through enforce_state_preflight, which
            // prints the risk list and may refuse with
            // PreflightRefusal (exit 6).
            if !dry_run {
                state::preflight::enforce_state_preflight(&changes, &live_state, allow_risk)?;
            }

            // Interactive HITL: per-Severe-change stdin prompt.
            // Filtered before dispatch so a rejected change becomes
            // an explicit operator-skipped outcome.
            if interactive && !dry_run {
                changes = interactive_hitl_filter(&changes, &live_state);
            }

            let opts = state::apply::ApplyOptions {
                dry_run,
                prune,
                continue_on_error,
            };
            let outcomes = state::apply::apply(client.as_ref(), changes, opts).await;

            match output {
                ApplyOutputFormat::Text => {
                    if outcomes.is_empty() {
                        println!("(no changes — live state matches declared)");
                    } else {
                        for o in &outcomes {
                            println!("{}", apply_summary_line(o));
                        }
                    }
                }
                ApplyOutputFormat::Json => {
                    let json = serde_json::to_string_pretty(&outcomes)?;
                    println!("{json}");
                }
            }

            // Exit code: 2 if any outcome failed, else 0. 1 is
            // reserved for hard errors (file unreadable, PVE
            // unreachable) — those flow through `?` above.
            let any_failed = outcomes
                .iter()
                .any(|o| matches!(o.result, state::apply::ApplyResult::Failed { .. }));
            let exit = i32::from(any_failed) * 2;
            Ok((Value::Null, exit))
        }
    }
}

/// Interactive HITL filter: prompt `[y/N]` for every change whose
/// pre-flight risk is Severe; return only the approved subset.
///
/// Notice/Warning-tier changes pass through unchanged — the gate
/// fires only on Severe so the operator isn't drowned in prompts
/// for routine drift convergence.
///
/// On EOF / unreadable stdin we treat the answer as "no" (refuse).
/// That matches the spirit of HITL: silence = no consent.
fn interactive_hitl_filter(
    changes: &[state::diff::Change],
    live_state: &state::model::ClusterState,
) -> Vec<state::diff::Change> {
    use std::io::{BufRead, Write};

    let mut approved: Vec<state::diff::Change> = Vec::with_capacity(changes.len());
    let stdin = std::io::stdin();

    for change in changes {
        // Re-assess this single change to know its severity tier.
        // The full-list assess() runs cluster-wide checks (bulk
        // count) that we don't want to repeat per change; for the
        // per-change prompt we only care about the per-change
        // risks.
        let risks = state::preflight::assess(std::slice::from_ref(change), live_state);
        let max = risks
            .iter()
            .map(state::preflight::StateRisk::level)
            .max()
            .unwrap_or(crate::app::preflight::RiskLevel::Notice);

        if max != crate::app::preflight::RiskLevel::Severe {
            approved.push(change.clone());
            continue;
        }

        let summary = state::diff::summary_line(change);
        eprintln!("\nSEVERE change pending:");
        eprintln!("  {summary}");
        for r in &risks {
            if matches!(r.level(), crate::app::preflight::RiskLevel::Severe) {
                eprintln!("  reason: {}", r.describe());
            }
        }
        {
            let mut out = std::io::stdout().lock();
            let _ = write!(out, "Approve? [y/N] ");
            let _ = out.flush();
        }

        let mut line = String::new();
        let mut handle = stdin.lock();
        let answer = match handle.read_line(&mut line) {
            Ok(0) => false, // EOF
            Ok(_) => matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes"),
            Err(_) => false,
        };
        if answer {
            eprintln!("  → approved");
            approved.push(change.clone());
        } else {
            eprintln!("  → rejected (skipped)");
        }
    }
    approved
}

/// Render one apply outcome as a single human-readable line.
///
/// Format: `<sigil> <resource>: <identity> — <status>`, with sigils
/// matching `state::diff::summary_line` so the eye can correlate a
/// diff line with the apply line that acted on it. The trailing
/// status word is the discriminant of [`state::apply::ApplyResult`]
/// — `applied` / `skipped (<reason>)` / `failed: <error>`.
fn apply_summary_line(o: &state::apply::ApplyOutcome) -> String {
    let diff_line = state::diff::summary_line(&o.change);
    match &o.result {
        state::apply::ApplyResult::Applied => format!("{diff_line} — applied"),
        state::apply::ApplyResult::Skipped { reason } => {
            let r = match reason {
                state::apply::SkipReason::DryRun => "dry_run",
                state::apply::SkipReason::PrunePolicy => "prune_policy",
                state::apply::SkipReason::AbortedByPrior => "aborted_by_prior",
            };
            format!("{diff_line} — skipped ({r})")
        }
        state::apply::ApplyResult::Failed { error } => format!("{diff_line} — failed: {error}"),
    }
}
