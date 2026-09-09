//! Layer 3 — converge live cluster state toward declared (the WRITE half of
//! continuous reconciliation).
//!
//! `reconcile run` / `reconcile watch` DETECT drift (read-only). This module is
//! the mutation half: **detect → pre-flight gate → apply → audit**. It is shared
//! by the `reconcile converge` CLI command (operator / CI push-mode) and the
//! daemon's opt-in `auto_converge` loop (unmanned, always `force = false`).
//!
//! ## Safety
//!
//! The pre-flight risk gate ([`enforce_state_preflight`]) is the *same* one
//! `state apply` uses: if any change is Severe and `force` is false, the **whole
//! batch** is refused with a typed [`crate::app::preflight::PreflightRefusal`]
//! (mapped to exit 6 on the CLI; surfaced as a "needs human review" alert on the
//! daemon). The unmanned loop always passes `force = false`, so a Severe drift is
//! never auto-applied — only a present operator can override it with
//! `--allow-risk`. The bulk-change gate (Severe at ≥ 50 changes) is the
//! circuit-breaker against a catastrophic mass-drift (e.g. an emptied
//! desired-state repo diffing to "delete everything").

use std::path::Path;

use anyhow::Result;

use crate::api::PxClient;
use crate::state::apply::{apply, ApplyOptions, ApplyOutcome, ApplyResult, StateWriteView};
use crate::state::diff::Change;
use crate::state::model::ClusterState;
use crate::state::preflight::enforce_state_preflight;

/// What a converge run decided and did. Lets the daemon branch on the outcome
/// (applied / partial / refused) without re-deriving it from `outcomes`.
#[derive(Debug)]
pub struct ConvergeReport {
    /// One row per change attempted (empty when already in sync).
    pub outcomes: Vec<ApplyOutcome>,
    /// Total drift detected this run (`== outcomes.len()`).
    pub total_changes: usize,
    pub applied: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl ConvergeReport {
    /// Already in sync — nothing to do.
    const fn in_sync() -> Self {
        Self {
            outcomes: Vec::new(),
            total_changes: 0,
            applied: 0,
            failed: 0,
            skipped: 0,
        }
    }

    /// Tally a finished apply run.
    fn from_outcomes(outcomes: Vec<ApplyOutcome>) -> Self {
        let (mut applied, mut failed, mut skipped) = (0usize, 0usize, 0usize);
        for o in &outcomes {
            match o.result {
                ApplyResult::Applied => applied += 1,
                ApplyResult::Failed { .. } => failed += 1,
                ApplyResult::Skipped { .. } => skipped += 1,
            }
        }
        Self {
            total_changes: outcomes.len(),
            applied,
            failed,
            skipped,
            outcomes,
        }
    }

    /// True if any change failed to apply.
    #[must_use]
    pub const fn any_failed(&self) -> bool {
        self.failed > 0
    }

    /// True if at least one change actually hit PVE (applied or failed) — i.e.
    /// this run mutated (or attempted to mutate) the cluster. Drives the audit
    /// write: a dry-run or a fully-skipped run records nothing.
    #[must_use]
    pub const fn dispatched(&self) -> bool {
        self.applied > 0 || self.failed > 0
    }

    /// CLI exit code: mirrors `state apply` — 2 if any change Failed, else 0.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        i32::from(self.any_failed()) * 2
    }

    /// One-line `result` field for the audit entry / daemon logs.
    #[must_use]
    pub fn audit_result(&self) -> String {
        format!(
            "applied {} / failed {} / skipped {}",
            self.applied, self.failed, self.skipped
        )
    }
}

/// Converge core: resolve drift from `source`, then mutate the live cluster
/// toward it. The daemon's `auto_converge` loop calls this directly (always with
/// `force = false`). Strictly read-only when `opts.dry_run` is set.
///
/// A pre-flight refusal propagates as `Err(PreflightRefusal)` so the CLI maps
/// exit 6 and the daemon can downcast it into the "needs human review" branch.
pub async fn converge(
    client: &PxClient,
    profile: &str,
    source: &str,
    path: &Path,
    opts: ApplyOptions,
    force: bool,
    audit_user: &str,
) -> Result<ConvergeReport> {
    let (changes, live) =
        crate::cli::reconcile::compute_drift_with_live(client, profile, source, path).await?;
    converge_with_changes(
        client, profile, source, changes, &live, opts, force, audit_user,
    )
    .await
}

/// Converge a pre-resolved change set. The CLI's `--interactive` path calls this
/// after filtering `changes` against stdin, so the interactive prompt never
/// reaches the daemon — the core has no stdin access. `live` is needed for the
/// pre-flight risk assessment (some risks read live state, not just the change).
#[allow(clippy::too_many_arguments)]
pub async fn converge_with_changes<C: StateWriteView + ?Sized>(
    client: &C,
    profile: &str,
    source: &str,
    changes: Vec<Change>,
    live: &ClusterState,
    opts: ApplyOptions,
    force: bool,
    audit_user: &str,
) -> Result<ConvergeReport> {
    // Pre-flight risk gate — only when actually mutating (dry-run is
    // exploration). Atomic: a single Severe change refuses the whole batch
    // unless `force`. Propagates as Err(PreflightRefusal) → exit 6 on the CLI /
    // "needs human review" on the daemon. (Gating an empty set is a no-op.)
    if !opts.dry_run {
        enforce_state_preflight(&changes, live, force)?;
    }
    Ok(apply_and_audit(
        client,
        profile,
        source,
        changes,
        opts,
        audit_user,
        "reconcile_converge",
    )
    .await)
}

/// Apply a **pre-gated** change set and write ONE HMAC audit entry per dispatched
/// run. Does NOT run the pre-flight gate itself — the caller is responsible for
/// gating. Shared by every state-mutating path so each gets a tamper-evident
/// trail: `reconcile converge` / the unmanned daemon reach it via
/// [`converge_with_changes`] (which gates first) and the CLI `--interactive`
/// path calls it directly after gating+filtering; `state apply` calls it with
/// `action = "state_apply"`. `action` is the audit verb recorded.
#[allow(clippy::too_many_arguments)]
pub async fn apply_and_audit<C: StateWriteView + ?Sized>(
    client: &C,
    profile: &str,
    source: &str,
    changes: Vec<Change>,
    opts: ApplyOptions,
    audit_user: &str,
    action: &str,
) -> ConvergeReport {
    if changes.is_empty() {
        return ConvergeReport::in_sync();
    }

    // Capture the summary before `apply` consumes `changes` (for the audit entry).
    let summary = crate::cli::reconcile::drift_summary(&changes);
    let total = changes.len();

    // Audit 2026-09-09 (#265) — leave a record even if we never come back.
    //
    // The completion entry below is written after `apply` returns. When
    // the daemon aborts a component mid-converge, this future is dropped
    // at whatever await it was sitting on: changes already dispatched
    // have been applied by PVE and stand, and the entry that would have
    // described them never runs. An operator restarting the daemon found
    // a partially converged cluster with nothing in the log.
    //
    // A Drop guard is the fix rather than a cancellation token, because
    // Drop runs on abort too — a token only helps at points we
    // explicitly check, and the abort lands wherever it lands.
    //
    // On the normal path the guard is disarmed and the usual completion
    // entry is written instead, so the log gains nothing in the case
    // that already worked.
    let mut guard = InterruptedRunGuard {
        armed: !opts.dry_run,
        action: action.to_string(),
        user: audit_user.to_string(),
        profile: profile.to_string(),
        source: source.to_string(),
        summary: summary.clone(),
        total,
    };

    let outcomes = apply(client, changes, opts).await;
    let report = ConvergeReport::from_outcomes(outcomes);
    guard.armed = false;

    // One audit entry per run that actually dispatched (not a dry-run, and
    // something hit PVE). Best-effort — a logging failure never fails the apply.
    if !opts.dry_run && report.dispatched() {
        write_apply_audit(action, audit_user, profile, source, &summary, &report);
    }

    report
}

/// Writes an `<action>_interrupted` audit entry if the run it guards
/// never reached its completion write (audit 2026-09-09, #265).
///
/// Disarmed as soon as `apply` returns, so it fires only when the future
/// was dropped mid-flight — in practice, a daemon component abort during
/// shutdown. The entry records what the run intended to do; the changes
/// that actually landed are recoverable from PVE's own task log, and the
/// point here is that an investigator learns the run happened at all.
struct InterruptedRunGuard {
    armed: bool,
    action: String,
    user: String,
    profile: String,
    source: String,
    summary: String,
    total: usize,
}

impl Drop for InterruptedRunGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let action = format!("{}_interrupted", self.action);
        let params = converge_audit_params(&self.profile, &self.source, &self.summary, self.total);
        let write = (|| -> Result<()> {
            let mut logger = crate::audit::AuditLogger::open()?;
            logger.log(
                &action,
                &self.user,
                None,
                None,
                Some(&params),
                "INTERRUPTED",
            )
        })();
        match write {
            Ok(()) => tracing::error!(
                "{action}: converge was interrupted mid-apply — changes already \
                 dispatched to PVE stand. Recorded in the audit log; reconcile \
                 again to establish the current state."
            ),
            Err(e) => tracing::error!(
                "{action}: converge was interrupted mid-apply AND the audit write \
                 failed ({e:#}) — the cluster may have been partially changed with \
                 no record. Reconcile to establish the current state."
            ),
        }
    }
}

/// Build the `params_json` payload for the converge audit entry. Split out so
/// its shape is unit-testable without touching the real audit DB (the
/// `AuditLogger::open` glue below is exercised by the live e2e instead).
fn converge_audit_params(profile: &str, source: &str, summary: &str, total: usize) -> String {
    serde_json::json!({
        "profile": profile,
        "source": source,
        "summary": summary,
        "total": total,
    })
    .to_string()
}

/// Append one HMAC-chained audit entry for an apply run (`action` = the verb,
/// e.g. `reconcile_converge` or `state_apply`). Best-effort: state mutations
/// aren't otherwise on the (guest-centric) audit chain, and especially an
/// *unmanned* mutation deserves a tamper-evident trail. A failure here is logged
/// and swallowed — the PVE mutation already happened; failing the run because we
/// couldn't *log* it would be worse.
fn write_apply_audit(
    action: &str,
    user: &str,
    profile: &str,
    source: &str,
    summary: &str,
    report: &ConvergeReport,
) {
    let params = converge_audit_params(profile, source, summary, report.total_changes);
    let write = (|| -> Result<()> {
        let mut logger = crate::audit::AuditLogger::open()?;
        logger.log(
            action,
            user,
            None,
            None,
            Some(&params),
            &report.audit_result(),
        )
    })();
    if let Err(e) = write {
        tracing::warn!("{action}: audit write failed (non-fatal): {e:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::apply::SkipReason;
    use crate::state::diff::ChangeKind;
    use crate::state::model::PoolDecl;
    use crate::state::test_support::RecordingClient;

    fn ch(kind: ChangeKind, resource: &'static str, id: &str) -> Change {
        Change {
            kind,
            resource,
            identity: id.to_string(),
            before: None,
            after: None,
        }
    }

    fn outcome(result: ApplyResult) -> ApplyOutcome {
        ApplyOutcome {
            change: ch(ChangeKind::Create, "pool", "x"),
            result,
        }
    }

    /// Live state holding one non-empty pool — a Delete against it is Severe
    /// (`PoolDeleteNonEmpty`), the cheapest way to trip the pre-flight gate.
    fn live_with_nonempty_pool(poolid: &str) -> ClusterState {
        ClusterState {
            pools: vec![PoolDecl {
                poolid: poolid.to_string(),
                comment: String::new(),
                members: vec!["qemu/100".to_string()],
            }],
            ..Default::default()
        }
    }

    #[test]
    fn report_from_outcomes_tallies_and_derives() {
        let report = ConvergeReport::from_outcomes(vec![
            outcome(ApplyResult::Applied),
            outcome(ApplyResult::Applied),
            outcome(ApplyResult::Failed {
                error: "boom".into(),
            }),
            outcome(ApplyResult::Skipped {
                reason: SkipReason::PrunePolicy,
            }),
        ]);
        assert_eq!(report.total_changes, 4);
        assert_eq!(report.applied, 2);
        assert_eq!(report.failed, 1);
        assert_eq!(report.skipped, 1);
        assert!(report.any_failed());
        assert!(report.dispatched());
        assert_eq!(report.exit_code(), 2); // any failed → 2
        assert_eq!(report.audit_result(), "applied 2 / failed 1 / skipped 1");
    }

    #[test]
    fn report_all_skipped_is_not_dispatched_exit_zero() {
        let report = ConvergeReport::from_outcomes(vec![outcome(ApplyResult::Skipped {
            reason: SkipReason::DryRun,
        })]);
        assert!(!report.any_failed());
        assert!(!report.dispatched()); // nothing hit PVE → no audit
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn converge_audit_params_carries_context() {
        let p = converge_audit_params("prod", "git://x", "3 change(s) across …", 3);
        let v: serde_json::Value = serde_json::from_str(&p).unwrap();
        assert_eq!(v["profile"], "prod");
        assert_eq!(v["source"], "git://x");
        assert_eq!(v["total"], 3);
        assert!(v["summary"].as_str().unwrap().contains("change"));
    }

    #[tokio::test]
    async fn empty_changes_is_in_sync() {
        let c = RecordingClient::default();
        let live = ClusterState::default();
        let report = converge_with_changes(
            &c,
            "p",
            "src",
            vec![],
            &live,
            ApplyOptions::default(),
            false,
            "u",
        )
        .await
        .unwrap();
        assert_eq!(report.total_changes, 0);
        assert!(!report.dispatched());
        assert!(c.lines().await.is_empty(), "no PVE call when in sync");
    }

    #[tokio::test]
    async fn dry_run_skips_all_and_does_not_dispatch() {
        let c = RecordingClient::default();
        let live = ClusterState::default();
        let changes = vec![ch(ChangeKind::Create, "pool", "p1")];
        let opts = ApplyOptions {
            dry_run: true,
            ..ApplyOptions::default()
        };
        let report = converge_with_changes(&c, "p", "src", changes, &live, opts, false, "u")
            .await
            .unwrap();
        assert_eq!(report.skipped, 1);
        assert!(!report.dispatched());
        assert!(c.lines().await.is_empty(), "dry-run issues no PVE call");
    }

    #[tokio::test]
    async fn severe_change_refuses_before_apply() {
        // Deleting a non-empty pool is Severe; force=false must refuse the whole
        // batch BEFORE any write. prune=true ⇒ if the gate hadn't fired, the
        // delete WOULD dispatch — so an empty log proves the gate stopped it.
        let c = RecordingClient::default();
        let live = live_with_nonempty_pool("prod");
        let changes = vec![ch(ChangeKind::Delete, "pool", "prod")];
        let opts = ApplyOptions {
            prune: true,
            ..ApplyOptions::default()
        };
        let err = converge_with_changes(&c, "p", "src", changes, &live, opts, false, "u")
            .await
            .expect_err("severe change must refuse");
        assert!(
            err.downcast_ref::<crate::app::preflight::PreflightRefusal>()
                .is_some(),
            "must be a typed PreflightRefusal (→ exit 6)"
        );
        assert!(
            c.lines().await.is_empty(),
            "refused batch must not issue any PVE call"
        );
    }

    #[tokio::test]
    async fn force_overrides_severe_gate() {
        // Same Severe delete, but force=true bypasses the gate. prune=false holds
        // the delete back by prune policy (so no real dispatch/audit in this unit
        // test) — the point is that the gate no longer refuses with force.
        let c = RecordingClient::default();
        let live = live_with_nonempty_pool("prod");
        let changes = vec![ch(ChangeKind::Delete, "pool", "prod")];
        let opts = ApplyOptions {
            prune: false,
            ..ApplyOptions::default()
        };
        let report = converge_with_changes(&c, "p", "src", changes, &live, opts, true, "u")
            .await
            .expect("force overrides the Severe gate");
        assert_eq!(report.skipped, 1); // held by prune policy, not the gate
        assert!(!report.dispatched());
        assert!(c.lines().await.is_empty());
    }
}

#[cfg(test)]
mod interrupted_run_tests {
    use super::{ApplyOptions, InterruptedRunGuard};

    fn guard(armed: bool) -> InterruptedRunGuard {
        InterruptedRunGuard {
            armed,
            action: "reconcile_converge".to_string(),
            user: "tester@host".to_string(),
            profile: "prod".to_string(),
            source: "/tmp/state.toml".to_string(),
            summary: "3 changes".to_string(),
            total: 3,
        }
    }

    /// #265 — the guard must be disarmed on the normal path, so a run
    /// that completes writes only its completion entry.
    #[test]
    fn a_completed_run_does_not_leave_an_interrupted_entry() {
        let mut g = guard(true);
        g.armed = false; // what `apply_and_audit` does when apply returns
        drop(g); // must not attempt an audit write
    }

    /// A dry run never dispatches, so there is nothing to record even if
    /// it is interrupted.
    #[test]
    fn a_dry_run_arms_nothing() {
        let opts = ApplyOptions {
            dry_run: true,
            ..Default::default()
        };
        assert!(opts.dry_run, "sanity: this is the dry-run case");
        let g = guard(!opts.dry_run);
        assert!(!g.armed, "a dry run must not arm the interrupted-run guard");
        drop(g);
    }

    /// The guard is armed for a real run — this is the state in which a
    /// mid-flight drop produces the record.
    #[test]
    fn a_real_run_arms_the_guard() {
        let opts = ApplyOptions::default();
        let g = guard(!opts.dry_run);
        assert!(g.armed);
        // Deliberately not dropped while armed here: Drop opens the real
        // audit DB, which belongs to the live e2e rather than a unit test.
        std::mem::forget(g);
    }
}
