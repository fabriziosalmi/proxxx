// HITL Policy Engine — which operations require approval
// First matching policy wins. No match = immediate execution.
//
// THREAT MODEL (SPOF 5.1, Category 5 audit) — tag-based policies are
// OPERATIONAL guardrails, NOT a security boundary. proxxx is a CLIENT
// to PVE; PVE owns the source of truth for guest tags. Any other API
// client (web UI, `qm set --tags`, raw curl) can mutate tags out-of-
// band; proxxx will then see the new tags on its next refresh and the
// HITL match will not fire. There is no fix at this layer for that
// attack — the only correct enforcement is PVE-side ACL restricting
// who can mutate tags AND who can call destructive operations.
//
// What proxxx provides instead:
// 1. `secure_mode` (CLI `--secure` flag) — tag-INDEPENDENT gate that
//    forces HITL approval on every destructive op regardless of tags.
//    This is the right knob for prod-grade infrastructure.
// 2. Tag-change observability — `app::audit_tag_changes` logs at WARN
//    when a guest's tag set differs between two consecutive snapshots,
//    so an out-of-band mutation leaves a forensic trail in the proxxx
//    log even when it bypasses HITL.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    pub action: String,  // "delete" | "stop" | "migrate" | "*"
    pub target: String,  // "*" | "100" | "tag:prod"
    pub channel: String, // "telegram" | "teams" | "all"
    pub require: u8,     // approvals needed
}

#[derive(Debug, Clone)]
pub enum Decision {
    Approved {
        by: String,
        via: String,
        elapsed_ms: u64,
    },
    Denied {
        by: String,
        via: String,
    },
    Timeout {
        after_ms: u64,
    },
    Skipped, // no matching policy → proceed immediately
}

/// Check if an action+target matches any policy
#[must_use]
pub fn check_policies<'a>(
    policies: &'a [Policy],
    action: &str,
    target: &str,
    tags: &[&str],
) -> Option<&'a Policy> {
    policies.iter().find(|p| {
        let action_match = p.action == "*" || p.action == action;
        let target_match = p.target == "*"
            || p.target == target
            || (p.target.starts_with("tag:")
                && tags.contains(&p.target.trim_start_matches("tag:")));
        action_match && target_match
    })
}
