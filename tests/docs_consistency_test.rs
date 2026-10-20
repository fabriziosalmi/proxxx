#![allow(clippy::expect_used, clippy::panic)]
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

fn collect_markdown_files(dir: &Path, acc: &mut Vec<std::path::PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_markdown_files(&path, acc);
            } else if path.extension().and_then(|s| s.to_str()) == Some("md") {
                acc.push(path);
            }
        }
    }
}

#[test]
fn documented_toml_blocks_have_no_unknown_fields() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut md_files = Vec::new();
    collect_markdown_files(&root.join("docs"), &mut md_files);
    md_files.push(root.join("README.md"));

    let dir = tempfile::tempdir().expect("temp dir for config checks");

    for file_path in md_files {
        let content = fs::read_to_string(&file_path)
            .unwrap_or_else(|e| panic!("cannot read {}: {e}", file_path.display()));
        let rel = file_path.strip_prefix(root).unwrap_or(&file_path);

        let lines: Vec<&str> = content.lines().collect();
        let mut idx = 0;
        while idx < lines.len() {
            if lines[idx].trim().starts_with("```toml") {
                let start_line = idx + 1;
                idx += 1;
                let mut block_lines = Vec::new();
                while idx < lines.len() && !lines[idx].trim().starts_with("```") {
                    block_lines.push(lines[idx]);
                    idx += 1;
                }
                let block = block_lines.join("\n");

                // Skip state.toml examples
                if block.contains("state.toml")
                    || block.contains("[[vms]]")
                    || block.contains("[[containers]]")
                {
                    continue;
                }

                let test_content = if !block.contains("url") && !block.contains("[profiles") {
                    format!("url = \"https://127.0.0.1:8006\"\nuser = \"root@pam\"\n{block}")
                } else {
                    block.clone()
                };

                let tmp_cfg = dir.path().join(format!("test_{start_line}.toml"));
                fs::write(&tmp_cfg, &test_content).expect("write temp config");

                if let Err(err) = proxxx::config::load_config_from_path(&tmp_cfg, None) {
                    let err_msg = format!("{err:?}");
                    assert!(
                        !err_msg.contains("unknown field"),
                        "Documentation error in {}:{}: found unknown field in TOML block:\n{err_msg}\nBlock:\n{block}",
                        rel.display(),
                        start_line
                    );
                }
                let _ = fs::remove_file(&tmp_cfg);
            }
            idx += 1;
        }
    }
}
