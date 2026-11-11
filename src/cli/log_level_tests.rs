//! Which stderr level a command gets when `RUST_LOG` is unset.

use clap::Parser;

use super::{is_long_running, stderr_log_directive, Command};

#[derive(Parser)]
struct Probe {
    #[command(subcommand)]
    cmd: Command,
}

fn parse(args: &[&str]) -> Command {
    let command_line = std::iter::once("proxxx").chain(args.iter().copied());
    match Probe::try_parse_from(command_line) {
        Ok(p) => p.cmd,
        Err(e) => panic!("{args:?} does not parse: {e}"),
    }
}

const DAEMONS: &[&[&str]] = &[
    &["daemon", "serve"],
    &["hitl", "serve"],
    &["mcp", "serve"],
    &["mcp", "serve-http"],
    &["alerts", "watch"],
];

const ONE_SHOT: &[&[&str]] = &[
    &["ls", "nodes"],
    &["describe"],
    &["alerts", "eval"],
    &["mcp", "tools"],
    &["schedule", "run-due"],
];

#[test]
fn daemons_are_long_running_and_one_shot_commands_are_not() {
    for args in DAEMONS {
        assert!(
            is_long_running(&parse(args)),
            "{args:?} must be long-running"
        );
    }
    for args in ONE_SHOT {
        assert!(!is_long_running(&parse(args)), "{args:?} must be one-shot");
    }
}

#[test]
fn a_one_shot_command_at_a_terminal_prints_only_warnings() {
    for args in ONE_SHOT {
        assert_eq!(
            stderr_log_directive(&parse(args), true),
            "proxxx=warn",
            "{args:?}"
        );
    }
}

/// #270: journald, cron mail and CI captures are not terminals; they keep
/// the full `info` trail, as do daemons run in the foreground.
#[test]
fn daemons_and_non_terminal_stderr_keep_info() {
    for args in ONE_SHOT {
        assert_eq!(
            stderr_log_directive(&parse(args), false),
            "proxxx=info",
            "{args:?}"
        );
    }
    for args in DAEMONS {
        assert_eq!(
            stderr_log_directive(&parse(args), true),
            "proxxx=info",
            "{args:?}"
        );
        assert_eq!(
            stderr_log_directive(&parse(args), false),
            "proxxx=info",
            "{args:?}"
        );
    }
}
