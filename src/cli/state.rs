//! `proxxx state {export}` — read live cluster state into TOML (or
//! JSON).
//!
//! v1 ships export only, pools only. Subsequent commands (`diff`,
//! `apply`) and resource families (acl, storage, firewall-cluster,
//! backup-jobs, notifications) land in follow-up PRs tracked by epic
//! [#74](https://github.com/fabriziosalmi/proxxx/issues/74).

use anyhow::Result;
use clap::{Subcommand, ValueEnum};
use serde_json::Value;
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
    /// v1 supports `--resource pools` only. More resource families
    /// (acl, storage, firewall-cluster, backup-jobs, notifications)
    /// land per the ladder in epic #74.
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
        /// Resource family to export. Valid in v1: `pools`. More
        /// coming — see issue #74.
        #[arg(long, default_value = "pools")]
        resource: String,

        /// Output format for the exported document. TOML (default)
        /// is the canonical disk format for the GitOps workflow;
        /// JSON is for piping into `jq` and other programmatic
        /// consumers. Distinct from the global `--format` flag,
        /// which controls how proxxx's normal table/json/plain
        /// output is rendered — state export bypasses that pipeline
        /// and writes the document directly to stdout.
        #[arg(long, value_enum, default_value_t = ExportFormat::Toml)]
        output: ExportFormat,
    },
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
            let r = state::export::Resource::parse(&resource)?;
            let profile_label = profile.unwrap_or("default");
            let exported =
                state::export::export_state(client.as_ref(), &[r], profile_label).await?;

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
    }
}
