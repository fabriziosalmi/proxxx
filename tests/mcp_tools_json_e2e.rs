#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #385: `mcp tools --json` was a no-op: the output followed `--format`, so
//! the default printed the table form and `--format json` wrapped the
//! registry in a one-element array.

fn run(args: &[&str]) -> std::process::Output {
    let dir = tempfile::tempdir().unwrap();
    std::process::Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .args(args)
        .env("PROXXX_CONFIG", dir.path().join("missing.toml"))
        .env("PROXXX_AUDIT_DIR", dir.path().join("audit"))
        .output()
        .unwrap()
}

#[test]
fn json_prints_the_registry_document_as_is() {
    for args in [
        &["mcp", "tools", "--json"][..],
        &["--format", "json", "mcp", "tools"],
    ] {
        let out = run(args);
        assert_eq!(out.status.code(), Some(0), "{args:?}");
        let v: serde_json::Value = serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("{args:?}: not JSON: {e}"));
        assert!(v["tools"].is_array(), "{args:?}: {v}");
    }
    let out = run(&["mcp", "tools", "--checksum", "--json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["checksum"].is_string(), "{v}");
}

#[test]
fn without_json_the_global_format_decides() {
    let out = run(&["mcp", "tools"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("KEY\tVALUE\n"), "{text}");
}
