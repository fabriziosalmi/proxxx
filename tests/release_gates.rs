#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #381: a tag is published only after the tagged commit passes CI, and
//! every cargo command that resolves dependencies is pinned to Cargo.lock.
//! These are text checks on the workflow files, so a change that drops the
//! gate or a `--locked` fails here instead of on the next release.

use std::path::Path;

fn workflow(name: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".github/workflows")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
}

/// The lines of the job `job` (from its `  job:` key to the next job key).
fn job<'a>(text: &'a str, job: &str) -> Vec<&'a str> {
    let key = format!("  {job}:");
    let mut lines = text.lines().skip_while(|l| *l != key);
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("job `{job}` not found"));
    std::iter::once(first)
        .chain(lines.take_while(|l| {
            // A new job key: exactly two spaces of indent, then a name.
            !(l.starts_with("  ") && !l.starts_with("   ") && l.trim_end().ends_with(':'))
        }))
        .collect()
}

#[test]
fn the_release_build_needs_the_ci_gate() {
    let rel = workflow("release.yml");
    let gate = job(&rel, "gate");
    assert!(
        gate.iter()
            .any(|l| l.trim() == "uses: ./.github/workflows/ci.yml"),
        "release.yml job `gate` must call ci.yml"
    );
    let build = job(&rel, "build");
    assert!(
        build.iter().any(|l| l.trim() == "needs: gate"),
        "release.yml job `build` must need `gate`, or a red commit can be published"
    );
    let ci = workflow("ci.yml");
    assert!(
        ci.lines().any(|l| l.trim() == "workflow_call:"),
        "ci.yml must be callable (`on: workflow_call`) for the release gate"
    );
}

/// `cargo build|test|clippy|run|llvm-cov` and `cross build` re-resolve a stale
/// lock unless given `--locked`. `cargo install` pins its own lock
/// separately; `cargo deb --no-build` and `cargo cyclonedx` read the lock that
/// the gate's `--locked` build has already proven current for this commit.
#[test]
fn every_cargo_command_that_resolves_dependencies_uses_locked() {
    let mut missing = Vec::new();
    for name in ["ci.yml", "release.yml", "cloudimg-repin.yml", "codeql.yml"] {
        for (i, line) in workflow(name).lines().enumerate() {
            let code = line.split(" #").next().unwrap().trim();
            if code.starts_with('#') {
                continue;
            }
            let resolves = [
                "cargo build",
                "cargo test",
                "cargo clippy",
                "cargo run",
                "cargo llvm-cov --",
                "cross build",
            ]
            .iter()
            .any(|c| code.contains(c));
            let resolves = resolves || code.ends_with("cargo llvm-cov");
            if resolves && !code.contains("--locked") {
                missing.push(format!("{name}:{}: {code}", i + 1));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "cargo commands without --locked:\n{}",
        missing.join("\n")
    );
}
