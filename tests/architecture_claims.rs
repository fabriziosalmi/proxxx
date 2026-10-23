#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
//! The structural claims in `ARCHITECTURE.md`, checked against the source
//! (#296). A claim that fails here is either stale prose or a regression;
//! fix whichever is wrong, in the same change.
//!
//! The commands in the process table are checked in `src/main.rs`, which
//! owns the top-level parser.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    std::fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn doc() -> String {
    read("ARCHITECTURE.md")
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Source lines that are not comments.
fn code_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with("//"))
}

fn rel(path: &Path) -> String {
    path.strip_prefix(root())
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/")
}

/// The files of module `segs` (`["hitl", "daemon"]`): its `.rs` file and,
/// when it is a directory, every file below it (items are often defined
/// in a submodule and re-exported).
fn module_files(segs: &[&str]) -> Vec<PathBuf> {
    let base = root().join("src").join(segs.join("/"));
    let mut out = Vec::new();
    let file = base.with_extension("rs");
    if file.is_file() {
        out.push(file);
    }
    if base.is_dir() {
        rust_files(&base, &mut out);
    }
    out
}

const fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Whether `name` is defined in `text`: an item (`fn`, `struct`, ...), an
/// enum variant, or a field.
fn defines(text: &str, name: &str) -> bool {
    for kw in [
        "fn ", "struct ", "enum ", "trait ", "const ", "static ", "type ", "mod ",
    ] {
        let needle = format!("{kw}{name}");
        let mut from = 0;
        while let Some(i) = text[from..].find(&needle) {
            let end = from + i + needle.len();
            if !text[end..].starts_with(is_ident_char) {
                return true;
            }
            from = end;
        }
    }
    text.lines().any(|l| {
        let t = l.trim_start().trim_start_matches("pub ");
        t.strip_prefix(name)
            .is_some_and(|rest| rest.starts_with([' ', '{', '(', ',', ':']) || rest.is_empty())
    })
}

/// Every `module::path::Item` the page names, in prose or in a diagram,
/// resolves to a definition in that module's source.
#[test]
fn every_module_path_the_page_names_exists() {
    let doc = doc();
    let top: BTreeSet<String> = std::fs::read_dir(root().join("src"))
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            p.file_stem().unwrap().to_string_lossy().into_owned()
        })
        .collect();

    let mut checked = 0;
    let mut missing = Vec::new();
    for token in doc.split(|c: char| !(is_ident_char(c) || c == ':')) {
        let token = token.trim_matches(':');
        if !token.contains("::") {
            continue;
        }
        let segs: Vec<&str> = token.split("::").collect();
        if !top.contains(segs[0]) {
            continue; // an external crate (`tokio::...`) or a type path.
        }
        let split = (1..=segs.len())
            .rev()
            .find(|&i| !module_files(&segs[..i]).is_empty())
            .unwrap_or_else(|| panic!("`{token}`: no module {}", segs[0]));
        let files = module_files(&segs[..split]);
        let text: String = files
            .iter()
            .map(|f| std::fs::read_to_string(f).unwrap())
            .collect();
        for item in &segs[split..] {
            if !defines(&text, item) {
                missing.push(format!(
                    "`{token}`: `{item}` is not defined in {}",
                    segs[..split].join("::")
                ));
            }
        }
        checked += 1;
    }
    assert!(
        checked >= 20,
        "only {checked} module paths found; the scan is broken"
    );
    assert!(missing.is_empty(), "{}", missing.join("\n"));
}

/// Names the page uses without a module path, and where they live.
#[test]
fn the_unqualified_names_the_page_uses_exist() {
    let doc = doc();
    for (name, file, item) in [
        (
            "enforce_cli_secure_mode",
            "src/cli/mod.rs",
            "enforce_cli_secure_mode",
        ),
        ("execute_delete", "src/cli/mod.rs", "execute_delete"),
        (
            "dispatch_side_effect",
            "src/tui/mod.rs",
            "dispatch_side_effect",
        ),
        (
            "PxClient::guard_read_only",
            "src/api/client.rs",
            "guard_read_only",
        ),
        (
            "PxClient::delete_guest",
            "src/api/client.rs",
            "delete_guest",
        ),
        ("PxClient::delete ", "src/api/client.rs", "delete"),
        (
            "Action::EnqueueBatchOperation",
            "src/app.rs",
            "EnqueueBatchOperation",
        ),
        ("Action::ExecuteQueue", "src/app.rs", "ExecuteQueue"),
        ("SideEffect::ExecuteQueue", "src/app.rs", "ExecuteQueue"),
        ("AppState.op_queue", "src/app.rs", "op_queue"),
    ] {
        assert!(
            doc.contains(name),
            "the page no longer names `{name}`; drop it here"
        );
        assert!(
            defines(&read(file), item),
            "`{name}` is not defined in {file}"
        );
    }
}

#[test]
fn every_linked_path_exists() {
    let doc = doc();
    let mut checked = 0;
    for part in doc.split("](").skip(1) {
        let target = &part[..part.find(')').unwrap()];
        if target.contains("://") || target.starts_with('#') {
            continue;
        }
        assert!(root().join(target).exists(), "broken link: {target}");
        checked += 1;
    }
    assert!(checked >= 20, "only {checked} links found");
}

/// "`app.rs` ... no `.await` and no file, network or process I/O".
#[test]
fn the_reducer_does_no_io() {
    let src = read("src/app.rs");
    for (n, line) in code_lines(&src) {
        for banned in [
            ".await",
            "std::fs",
            "tokio::",
            "reqwest",
            "std::net",
            "std::process",
        ] {
            assert!(
                !line.contains(banned),
                "src/app.rs:{}: `{banned}` in the reducer: {line}",
                n + 1
            );
        }
    }
}

/// "`AppState` is used only by the TUI".
#[test]
fn app_state_is_used_only_by_the_tui() {
    let allowed = ["src/app.rs", "src/app/queue.rs", "src/app/search.rs"];
    let mut files = Vec::new();
    rust_files(&root().join("src"), &mut files);
    let mut outside = Vec::new();
    for f in files {
        let r = rel(&f);
        if r.starts_with("src/tui/") || allowed.contains(&r.as_str()) {
            continue;
        }
        let text = std::fs::read_to_string(&f).unwrap();
        for (n, line) in code_lines(&text) {
            let uses = line.match_indices("AppState").any(|(i, _)| {
                !line[..i].ends_with(is_ident_char)
                    && !line[i + "AppState".len()..].starts_with(is_ident_char)
            });
            if uses {
                outside.push(format!("{r}:{}", n + 1));
            }
        }
    }
    assert!(
        outside.is_empty(),
        "AppState used outside the TUI: {outside:?}"
    );
}

/// "Every mutating HTTP request `PxClient` sends is built in one of four
/// places ... Each runs, in this order": read-only guard, freeze check,
/// write-ahead audit, then the request.
#[test]
fn every_mutating_request_runs_the_gateway_gates_in_order() {
    let mut files = Vec::new();
    rust_files(&root().join("src/api"), &mut files);
    let mut sites = 0;
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for (n, line) in code_lines(&text) {
            let mutating = ["http.post(", "http.put(", "http.delete(", "http.patch("]
                .iter()
                .any(|m| line.contains(m));
            if !mutating {
                continue;
            }
            sites += 1;
            let start = (0..=n)
                .rev()
                .find(|&i| {
                    lines[i].trim_start().starts_with("async fn ")
                        || lines[i].trim_start().starts_with("pub async fn ")
                        || lines[i].trim_start().starts_with("pub(crate) async fn ")
                })
                .unwrap_or_else(|| panic!("{}:{}: no enclosing async fn", rel(&f), n + 1));
            let body = lines[start..=n].join("\n");
            let at = |needle: &str| {
                body.find(needle).unwrap_or_else(|| {
                    panic!(
                        "{}:{}: `{needle}` missing before the request",
                        rel(&f),
                        n + 1
                    )
                })
            };
            let (ro, frozen, audit) = (
                at("guard_read_only("),
                at("check_not_frozen_for("),
                at("write_ahead_at("),
            );
            assert!(
                ro < frozen && frozen < audit,
                "{}:{}: gates out of order",
                rel(&f),
                n + 1
            );
        }
    }
    assert_eq!(
        sites, 4,
        "the page says four places build a mutating request"
    );
}

/// The MCP column and the execution check (#507): the MCP gate runs the
/// deep preflight on the listed tools, and the HITL daemon runs `assess`
/// on the live guest before an approved operation.
#[test]
fn mcp_and_the_hitl_daemon_run_the_risk_preflight() {
    let dispatch = read("src/mcp/dispatch.rs");
    let code = code_lines(&dispatch)
        .map(|(_, l)| l)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        code.contains("assess_deep_with("),
        "the MCP gate runs assess_deep"
    );
    for tool in [
        "stop_guest",
        "restart_guest",
        "delete_guest",
        "migrate_guest",
    ] {
        assert!(
            code.contains(&format!("\"{tool}\" => Some(Op::")),
            "the MCP preflight covers {tool}"
        );
    }
    let daemon = read("src/hitl/daemon.rs");
    assert!(
        code_lines(&daemon).any(|(_, l)| l.contains("crate::app::preflight::assess(")),
        "the HITL daemon checks the live guest before executing"
    );
}

/// The CLI approval cell: these five commands go through the policy
/// path, which asks for Telegram approval on a matching policy.
#[test]
fn the_cli_queues_these_commands_for_approval() {
    let cli = read("src/cli/mod.rs");
    let lines: Vec<&str> = cli.lines().collect();
    let mut ops = BTreeSet::new();
    for (n, line) in code_lines(&cli) {
        if !line.contains("execute_batch_op_with_policy(") {
            continue;
        }
        let window = lines[n..(n + 4).min(lines.len())].join(" ");
        let i = window.find("BatchOp::").expect("a BatchOp argument");
        ops.insert(
            window[i + 9..]
                .chars()
                .take_while(|c| is_ident_char(*c))
                .collect::<String>(),
        );
    }
    let want: BTreeSet<String> = ["Restart", "Resume", "Start", "Stop", "Suspend"]
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(ops, want);
    let common = read("src/cli/common.rs");
    assert!(common.contains("crate::hitl::policy::check_policies(policies, action_str"));
}

/// The TUI column: palette actions refuse a locked or HA-managed guest.
#[test]
fn tui_palette_actions_refuse_locked_and_ha_guests() {
    let app = read("src/app.rs");
    for op in ["stop", "restart", "delete", "snapshot"] {
        assert!(
            app.contains(&format!("guest_block_reason(state, vmid, \"{op}\")")),
            "{op} is checked by guest_block_reason"
        );
    }
    let block = &app[app.find("fn guest_block_reason").unwrap()..];
    let body = &block[..block.find("\n}\n").unwrap()];
    assert!(body.contains("is_locked()") && body.contains("is_ha_managed()"));
}

/// The CLI column: `assess_deep` on exactly these operations.
#[test]
fn the_cli_runs_the_deep_preflight_on_the_listed_operations() {
    let mut files = Vec::new();
    rust_files(&root().join("src/cli"), &mut files);
    let mut ops = BTreeSet::new();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for (n, line) in code_lines(&text) {
            let call = line.contains("enforce_preflight(")
                || line.contains("enforce_preflight_with_notes(");
            if !call || line.contains("fn enforce_preflight") || rel(&f).ends_with("common.rs") {
                continue;
            }
            let window = lines[n..(n + 8).min(lines.len())].join(" ");
            let i = window
                .find("Op::")
                .unwrap_or_else(|| panic!("{}:{}: preflight call without an Op", rel(&f), n + 1));
            let op: String = window[i + 4..]
                .chars()
                .take_while(|c| is_ident_char(*c))
                .collect();
            ops.insert(op);
        }
    }
    let want: BTreeSet<String> = [
        "Delete",
        "Migrate",
        "MoveDisk",
        "ResizeDisk",
        "Restart",
        "Stop",
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    assert_eq!(ops, want);
    let common = read("src/cli/common.rs");
    assert!(
        common.contains("assess_deep("),
        "the CLI preflight is assess_deep"
    );
}

/// The TUI column: the cheap `assess`, only for queued operations.
#[test]
fn the_tui_runs_the_cheap_preflight_only_in_the_queue() {
    let tui = read("src/tui/mod.rs");
    assert!(
        !code_lines(&tui).any(|(_, l)| l.contains("assess_deep")),
        "the page says the TUI runs no deep checks"
    );
    let calls: Vec<usize> = tui
        .match_indices("preflight::assess(")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(calls.len(), 1, "one preflight call site in the TUI");
    let queue_arm = tui.find("SideEffect::ExecuteQueue").expect("the queue arm");
    assert!(
        calls[0] > queue_arm,
        "the preflight call is in the queue arm"
    );
}

#[test]
fn the_mcp_line_cap_is_16_mib() {
    assert!(
        read("src/mcp/server.rs").contains("const MAX_RPC_LINE_BYTES: usize = 16 * 1024 * 1024;")
    );
    assert!(doc().contains("16 MiB cap, mcp::server::MAX_RPC_LINE_BYTES"));
}

#[test]
fn the_release_profile_is_the_one_described() {
    let cargo: toml::Value = toml::from_str(&read("Cargo.toml")).unwrap();
    let release = &cargo["profile"]["release"];
    assert_eq!(release["lto"].as_bool(), Some(true));
    assert_eq!(release["codegen-units"].as_integer(), Some(1));
    assert_eq!(release["strip"].as_bool(), Some(true));
    assert_eq!(release["opt-level"].as_str(), Some("z"));
    let doc = doc();
    for claim in [
        "`lto = true`",
        "`codegen-units = 1`",
        "`strip = true`",
        "`opt-level = \"z\"`",
    ] {
        assert!(doc.contains(claim), "{claim}");
    }
    let gate = read("scripts/gate.sh");
    assert!(gate.contains("cargo clippy --release"));
    assert!(gate.contains("cargo test --release"));
}
