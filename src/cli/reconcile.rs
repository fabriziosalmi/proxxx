//! Continuous reconciliation — the `GitOps` controller, layer 1.
//!
//! `proxxx reconcile run` is the one-shot, CI-gateable drift check. It
//! resolves a *desired-state source* (a local file, a local directory,
//! or a git repo), exports live cluster state across every state family,
//! diffs the two, and prints a structured drift report. The exit code
//! follows the `diff(1)` / CI convention: **0 = in sync, 2 = drift**
//! (1 is reserved for errors, surfaced via `?`).
//!
//! It is strictly **read-only** — detection only. No mutation, and no
//! audit-log write: the HMAC audit chain records *mutations*, and a
//! drift check changes nothing. Auto-converge (which mutates, and so
//! does audit) is a later layer. The `reconcile watch` daemon pillar (see
//! [`crate::cli::daemon`]) calls this same `compute_drift` core on a timer
//! and fans drift out to logs + Telegram (Prometheus metrics / MCP events
//! follow). Every change here composes over the stable
//! `state::{export,diff}` surfaces.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Subcommand;
use serde_json::Value;

use crate::api::PxClient;
use crate::state;
use crate::state::diff::{Change, ChangeKind};

#[derive(Debug, Subcommand)]
pub enum ReconcileCommand {
    /// One-shot drift check: diff a desired-state source against the
    /// live cluster. Exit 0 = in sync, 2 = drift detected (CI-gateable).
    Run {
        /// Desired-state source: a local file, a local directory, or a
        /// git URL (`https://…`, `git@…`, `ssh://…`, `git://…`, or any
        /// `*.git`). Git sources are shallow-cloned to a temp dir, read,
        /// then discarded.
        #[arg(long)]
        source: String,

        /// State file path *within* a directory or git-repo source (the
        /// output of `proxxx state export`). Ignored when `--source`
        /// points directly at a file.
        #[arg(long, default_value = "state.toml")]
        path: PathBuf,

        /// Emit the full drift report as JSON instead of a text summary.
        #[arg(long)]
        json: bool,
    },
}

pub async fn execute_reconcile(
    client: &Arc<PxClient>,
    profile: Option<&str>,
    action: ReconcileCommand,
) -> Result<(Value, i32)> {
    match action {
        ReconcileCommand::Run { source, path, json } => {
            run(client, profile, &source, &path, json).await
        }
    }
}

async fn run(
    client: &Arc<PxClient>,
    profile: Option<&str>,
    source: &str,
    path: &Path,
    json: bool,
) -> Result<(Value, i32)> {
    let profile_label = profile.unwrap_or("default");
    let changes = compute_drift(client.as_ref(), profile_label, source, path).await?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report_json(source, profile_label, &changes))?
        );
    } else {
        print_text(source, profile_label, &changes);
    }

    // 0 = in sync, 2 = drift (diff(1) / CI convention; 1 = error via `?`).
    let exit = i32::from(!changes.is_empty()) * 2;
    Ok((Value::Null, exit))
}

/// Core drift computation, shared by the one-shot CLI (`reconcile run`) and
/// the `reconcile watch` daemon pillar: resolve + read the desired-state
/// source, export live state across every family, and diff. Read-only.
pub(crate) async fn compute_drift(
    client: &PxClient,
    profile: &str,
    source: &str,
    path: &Path,
) -> Result<Vec<Change>> {
    let toml_str = load_desired_toml(source, path).await?;
    let declared: state::model::ClusterState = toml::from_str(&toml_str).with_context(|| {
        format!(
            "parsing desired state from `{source}` — is it the output of `proxxx state export`?"
        )
    })?;

    // `Resource::all()` is the single source of truth, so a newly-added
    // family is never silently omitted (which would diff as perpetual creates).
    let live =
        state::export::export_state(client, &state::export::Resource::all(), profile).await?;

    Ok(state::diff::diff(&declared, &live))
}

/// One-line human summary of drift, for daemon logs + Telegram alerts.
/// `"in sync"` when empty; otherwise a per-family tally.
pub(crate) fn drift_summary(changes: &[Change]) -> String {
    if changes.is_empty() {
        return "in sync".to_string();
    }
    let families = by_family(changes);
    let per: Vec<String> = families
        .iter()
        .map(|(fam, d)| {
            let mut parts = Vec::new();
            if d.create > 0 {
                parts.push(format!("{} create", d.create));
            }
            if d.update > 0 {
                parts.push(format!("{} update", d.update));
            }
            if d.delete > 0 {
                parts.push(format!("{} delete", d.delete));
            }
            format!("{fam}: {}", parts.join(", "))
        })
        .collect();
    format!(
        "{} change(s) across {} famil{} — {}",
        changes.len(),
        families.len(),
        if families.len() == 1 { "y" } else { "ies" },
        per.join("; ")
    )
}

/// Per-family drift counts (create + update + delete summed per family), for
/// the daemon's shared drift-state store. Stable order via `by_family`.
pub(crate) fn family_counts(changes: &[Change]) -> Vec<(String, u32)> {
    by_family(changes)
        .into_iter()
        .map(|(fam, d)| (fam, (d.create + d.update + d.delete) as u32))
        .collect()
}

/// True when `source` should be treated as a git remote (cloned) rather
/// than a filesystem path.
//
// `.git` is compared case-sensitively on purpose: git remote URLs are
// case-sensitive and the `.git` suffix convention is lowercase, so a
// case-insensitive compare would be wrong, not safer.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn is_git_source(source: &str) -> bool {
    source.starts_with("https://")
        || source.starts_with("http://")
        || source.starts_with("git@")
        || source.starts_with("ssh://")
        || source.starts_with("git://")
        || source.ends_with(".git")
}

/// Resolve a non-git source to the state file: a directory gets `path`
/// joined onto it; anything else (a file) is used as-is, so
/// `--source ./state.toml` works without `--path`.
fn resolve_local(source: &str, path: &Path) -> PathBuf {
    let p = PathBuf::from(source);
    if p.is_dir() {
        p.join(path)
    } else {
        p
    }
}

/// Resolve the desired-state source to its TOML contents. A git source is
/// shallow-cloned to a temp dir, read, and the clone discarded; a local
/// directory has `path` joined onto it; a local file is read directly.
/// The clone lives exactly as long as the read.
async fn load_desired_toml(source: &str, path: &Path) -> Result<String> {
    if is_git_source(source) {
        let tmp = clone_git_source(source).await?;
        read_state_file(&tmp.path().join(path))
    } else {
        read_state_file(&resolve_local(source, path))
    }
}

fn read_state_file(file: &Path) -> Result<String> {
    std::fs::read_to_string(file)
        .with_context(|| format!("reading desired state from {}", file.display()))
}

/// Shallow-clone `url` into a fresh temp dir via the system `git`. The
/// returned `TempDir` owns the clone and removes it on drop. Shelling
/// out keeps proxxx's single-static-binary shape — no git library dep.
async fn clone_git_source(url: &str) -> Result<tempfile::TempDir> {
    let tmp = tempfile::TempDir::new().context("creating temp dir for git clone")?;
    let output = tokio::process::Command::new("git")
        .args(["clone", "--depth", "1", "--quiet"])
        .arg(url)
        .arg(tmp.path())
        .output()
        .await
        .context("running `git clone` — is git installed and on PATH?")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git clone of `{url}` failed: {}", stderr.trim());
    }
    Ok(tmp)
}

/// Per-family drift tally.
#[derive(Debug, Default, PartialEq, Eq, serde::Serialize)]
struct FamilyDrift {
    create: usize,
    update: usize,
    delete: usize,
}

/// Group changes by state family (the `resource` discriminant), tallying
/// each `ChangeKind`. Deterministic order via `BTreeMap`.
fn by_family(changes: &[Change]) -> BTreeMap<String, FamilyDrift> {
    let mut map: BTreeMap<String, FamilyDrift> = BTreeMap::new();
    for c in changes {
        let entry = map.entry(c.resource.to_string()).or_default();
        match c.kind {
            ChangeKind::Create => entry.create += 1,
            ChangeKind::Update => entry.update += 1,
            ChangeKind::Delete => entry.delete += 1,
        }
    }
    map
}

/// JSON drift report: a summary envelope plus the raw changes, so JSON
/// consumers get both the at-a-glance tally and full per-resource detail.
fn report_json(source: &str, profile: &str, changes: &[Change]) -> Value {
    let by_fam = serde_json::to_value(by_family(changes)).unwrap_or_default();
    let detail = serde_json::to_value(changes).unwrap_or_default();
    serde_json::json!({
        "source": source,
        "profile": profile,
        "in_sync": changes.is_empty(),
        "total_changes": changes.len(),
        "by_family": by_fam,
        "changes": detail,
    })
}

fn print_text(source: &str, profile: &str, changes: &[Change]) {
    println!("reconcile — source {source} (profile {profile})");
    println!();
    if changes.is_empty() {
        println!("  ✓ IN SYNC — live matches desired (0 changes)");
        return;
    }
    let families = by_family(changes);
    println!(
        "  ✗ DRIFT — {} change(s) across {} famil{}",
        changes.len(),
        families.len(),
        if families.len() == 1 { "y" } else { "ies" }
    );
    for (fam, d) in &families {
        let mut parts = Vec::new();
        if d.create > 0 {
            parts.push(format!("{} create", d.create));
        }
        if d.update > 0 {
            parts.push(format!("{} update", d.update));
        }
        if d.delete > 0 {
            parts.push(format!("{} delete", d.delete));
        }
        println!("     {fam:<22} {}", parts.join(", "));
    }
    println!();
    for c in changes {
        println!("  {}", state::diff::summary_line(c));
    }
    println!();
    println!("  → run `proxxx state apply` to converge, or `proxxx state diff` for full detail");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch(kind: ChangeKind, resource: &'static str, id: &str) -> Change {
        Change {
            kind,
            resource,
            identity: id.to_string(),
            before: None,
            after: None,
        }
    }

    #[test]
    fn git_sources_are_detected() {
        for s in [
            "https://github.com/o/r",
            "http://x/y",
            "git@github.com:o/r.git",
            "ssh://git@h/r",
            "git://h/r",
            "/local/repo.git",
            "x.git",
        ] {
            assert!(is_git_source(s), "{s} should be detected as git");
        }
        for s in [
            "/etc/proxxx/state.toml",
            "./state.toml",
            "state.toml",
            "/tmp/cluster",
            "../desired",
        ] {
            assert!(!is_git_source(s), "{s} should be treated as local");
        }
    }

    #[test]
    fn resolve_local_file_is_used_as_is_dir_gets_path_joined() {
        // A file path is returned verbatim (ignores --path).
        let file = tempfile::NamedTempFile::new().unwrap();
        let p = file.path().to_path_buf();
        assert_eq!(
            resolve_local(p.to_str().unwrap(), Path::new("state.toml")),
            p
        );

        // A directory gets the state-file path joined onto it.
        let dir = tempfile::TempDir::new().unwrap();
        let got = resolve_local(dir.path().to_str().unwrap(), Path::new("state.toml"));
        assert_eq!(got, dir.path().join("state.toml"));
    }

    #[test]
    fn by_family_tallies_each_kind() {
        let changes = vec![
            ch(ChangeKind::Create, "pool", "a"),
            ch(ChangeKind::Create, "pool", "b"),
            ch(ChangeKind::Update, "pool", "c"),
            ch(ChangeKind::Delete, "storage", "d"),
        ];
        let fam = by_family(&changes);
        assert_eq!(fam.len(), 2);
        assert_eq!(
            fam["pool"],
            FamilyDrift {
                create: 2,
                update: 1,
                delete: 0
            }
        );
        assert_eq!(
            fam["storage"],
            FamilyDrift {
                create: 0,
                update: 0,
                delete: 1
            }
        );
    }

    #[test]
    fn report_json_shape_in_sync_and_drift() {
        let in_sync = report_json("src", "prof", &[]);
        assert_eq!(in_sync["in_sync"], serde_json::json!(true));
        assert_eq!(in_sync["total_changes"], serde_json::json!(0));
        assert_eq!(in_sync["source"], serde_json::json!("src"));
        assert_eq!(in_sync["profile"], serde_json::json!("prof"));

        let changes = vec![
            ch(ChangeKind::Create, "pool", "a"),
            ch(ChangeKind::Update, "pool", "b"),
        ];
        let drift = report_json("git://x", "prod", &changes);
        assert_eq!(drift["in_sync"], serde_json::json!(false));
        assert_eq!(drift["total_changes"], serde_json::json!(2));
        assert_eq!(drift["by_family"]["pool"]["create"], serde_json::json!(1));
        assert_eq!(drift["by_family"]["pool"]["update"], serde_json::json!(1));
        assert!(drift["changes"].is_array());
        assert_eq!(drift["changes"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn drift_summary_reads_clean_and_grouped() {
        assert_eq!(drift_summary(&[]), "in sync");

        let changes = vec![
            ch(ChangeKind::Create, "pool", "a"),
            ch(ChangeKind::Update, "pool", "b"),
            ch(ChangeKind::Delete, "storage", "c"),
        ];
        let s = drift_summary(&changes);
        assert!(s.starts_with("3 change(s) across 2 families"), "{s}");
        assert!(s.contains("pool: 1 create, 1 update"), "{s}");
        assert!(s.contains("storage: 1 delete"), "{s}");
    }

    #[test]
    fn family_counts_sums_kinds_per_family() {
        let changes = vec![
            ch(ChangeKind::Create, "pool", "a"),
            ch(ChangeKind::Update, "pool", "b"),
            ch(ChangeKind::Delete, "storage", "c"),
        ];
        // pool: create + update = 2; storage: delete = 1; sorted by family.
        assert_eq!(
            family_counts(&changes),
            vec![("pool".to_string(), 2), ("storage".to_string(), 1)]
        );
    }
}
