#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! #437: human-readable CLI output goes through `outln!` / `out!`, which
//! remove control sequences from interpolated cluster strings. Machine
//! output (JSON, TOML documents) keeps `println!` with a `// raw-output:`
//! note. The guard below fails when a new bare `println!` / `print!`
//! appears under `src/cli`; the e2e test prints a cluster string that
//! carries an OSC 52 clipboard-write sequence.

use std::path::Path;

use serde_json::json;
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// `init_wizard.rs` prints its own ANSI colours, which `outln!` would
/// strip; it sanitizes each interpolated value with its `safe()` helper.
const ALLOWED_FILES: &[&str] = &["init_wizard.rs"];

fn is_bare_print(line: &str) -> bool {
    let code = line.split("//").next().unwrap_or("");
    ["println!(", "print!("].iter().any(|m| {
        code.match_indices(m).any(|(i, _)| {
            i == 0 || {
                let prev = code.as_bytes()[i - 1];
                !(prev.is_ascii_alphanumeric() || prev == b'_' || prev == b':')
            }
        })
    })
}

#[test]
fn every_cli_print_is_sanitized_or_marked_raw() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/cli");
    let mut bad = Vec::new();
    let mut files: Vec<_> = walk(&dir);
    files.sort();
    for f in files {
        let name = f.file_name().unwrap().to_string_lossy().to_string();
        if ALLOWED_FILES.contains(&name.as_str()) {
            let text = std::fs::read_to_string(&f).unwrap();
            assert!(
                text.contains("fn safe("),
                "{name} is allowed only while it sanitizes"
            );
            continue;
        }
        let text = std::fs::read_to_string(&f).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for (i, l) in lines.iter().enumerate() {
            if !is_bare_print(l) {
                continue;
            }
            let marked = l.contains("// raw-output:")
                || i.checked_sub(1)
                    .is_some_and(|p| lines[p].trim_start().starts_with("// raw-output:"));
            if !marked {
                bad.push(format!("{}:{}: {}", f.display(), i + 1, l.trim()));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "use crate::outln!/crate::out! for human-readable output, or mark machine \
         output with `// raw-output: <why>` on the line above:\n{}",
        bad.join("\n")
    );
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    out
}

/// A pool id carrying an OSC 52 sequence (terminal clipboard write)
/// reaches `state diff` text output. It used to be printed as is.
#[tokio::test]
async fn state_diff_text_strips_a_control_sequence_from_a_resource_name() {
    let server = MockServer::start().await;
    let evil = "tenant\u{1b}]52;c;aGk=\u{7}-a";
    Mock::given(method("GET"))
        .and(path("/api2/json/version"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"data": {"version": "9.1.1", "release": "9.1", "repoid": "x"}}),
            ),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api2/json/cluster/firewall/options"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {}})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api2/json/pools"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": [{"poolid": evil}]})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_regex("^/api2/json/pools/.+"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data": {"poolid": evil, "comment": "", "members": []}})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;

    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("config.toml");
    std::fs::write(
        &cfg,
        format!(
            "default = \"lab\"\n\n[profiles.lab]\nurl = \"{}\"\nuser = \"root@pam\"\n\
             token_id = \"x\"\ntoken_secret = \"00000000-0000-0000-0000-000000000000\"\n\
             verify_tls = false\n",
            server.uri()
        ),
    )
    .unwrap();
    let declared = dir.path().join("state.toml");
    std::fs::write(&declared, "pools = []\n").unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_proxxx"))
        .args(["state", "diff", declared.to_str().unwrap()])
        .env("PROXXX_CONFIG", &cfg)
        .env("PROXXX_AUDIT_DIR", dir.path().join("audit"))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(
        out.status.code(),
        Some(2),
        "{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("- pool: tenant"), "{stdout:?}");
    assert!(
        !stdout.contains('\u{1b}') && !stdout.contains('\u{7}'),
        "a control sequence reached stdout: {stdout:?}"
    );
}
