//! Drift-proofs: documentation claims that MUST track the code.
//!
//! The v0.13.0 release flipped `create_snapshot` and `suspend_guest` to
//! `destructive: true` and the docs kept saying "8 flagged destructive"
//! for a month; `THREAT_MODEL.md` described the pre-v0.13 fail-open MCP
//! posture ("4 destructive tools go through HITL") until 2026-07-07.
//! These tests recompute the numbers from the real registry so the next
//! registry change turns doc drift into a red CI instead of a stale claim.

use std::fs;
use std::path::Path;

use proxxx::mcp::tools::TOOLS;

// Test-only helper: a missing repo file must abort the test with the path
// in the message; the crate-wide `clippy::panic = deny` targets production
// code and has no built-in exemption for non-`#[test]` helper fns.
#[allow(clippy::panic)]
fn repo_file(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

#[test]
fn threat_model_destructive_count_matches_registry() {
    let total = TOOLS.len();
    let destructive = TOOLS.iter().filter(|t| t.destructive).count();
    let doc = repo_file("THREAT_MODEL.md");

    // The registry-size claim ("Compile-time fixed, 25 tools") must match.
    assert!(
        doc.contains(&format!("{total} tools")),
        "THREAT_MODEL.md no longer states the registry size ({total} tools) — \
         the registry changed; update the doc"
    );

    // The fail-closed row must state the real destructive count
    // ("10 of the 25 tools are flagged `destructive: true`").
    assert!(
        doc.contains(&format!("{destructive} of the {total} tools are flagged")),
        "THREAT_MODEL.md destructive-tool count is out of sync with the \
         registry (real count: {destructive} of {total}) — update the \
         fail-closed row in attack surface 5"
    );

    // Every destructive tool must be named in the doc, so a flipped flag
    // (the exact drift v0.13.0 introduced) is caught by name, not just count.
    for tool in TOOLS.iter().filter(|t| t.destructive) {
        assert!(
            doc.contains(&format!("`{}`", tool.name)),
            "destructive tool `{}` is not named in THREAT_MODEL.md's \
             fail-closed row",
            tool.name
        );
    }

    // The pre-v0.13 fail-open sentence must never come back.
    assert!(
        !doc.contains("go through the same HITL approval channel"),
        "THREAT_MODEL.md resurrected the pre-v0.13 fail-open wording — \
         MCP destructive dispatch is fail-closed (src/mcp/dispatch.rs)"
    );
}
