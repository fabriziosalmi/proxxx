//! Argument rules applied to the whole command tree.

use clap::builder::NonEmptyStringValueParser;
use clap::{Arg, Command};

/// Make every positional string argument refuse an empty value (#363).
///
/// An identifier passed as `""` built paths such as `/pools/` or
/// `/access/users//token`: some hit the list endpoint and printed a
/// fabricated empty object with exit 0 (`pool show ""`, `backup-jobs show
/// ""`), others failed with a misleading parse or PVE error. Positional
/// strings are identifiers (pool, job, storage, group, user ids, ...), so
/// an empty one is a usage error (exit 2) before any request. A trailing
/// argument list (a command to run inside a guest, for example) is left
/// alone: an empty word can be meant there. Options are left alone too:
/// `--comment ""` clears a comment.
#[must_use]
pub fn reject_empty_positionals(cmd: Command) -> Command {
    cmd.mut_args(non_empty_if_positional_string)
        .mut_subcommands(reject_empty_positionals)
}

fn non_empty_if_positional_string(arg: Arg) -> Arg {
    let is_string =
        arg.get_value_parser().type_id() == clap::builder::ValueParser::string().type_id();
    if arg.is_positional() && is_string && !arg.is_trailing_var_arg_set() && !arg.is_last_set() {
        arg.value_parser(NonEmptyStringValueParser::new())
    } else {
        arg
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd() -> Command {
        reject_empty_positionals(
            Command::new("t").subcommand(
                Command::new("pool").subcommand(
                    Command::new("show")
                        .arg(Arg::new("poolid").required(true))
                        .arg(Arg::new("comment").long("comment"))
                        .arg(
                            Arg::new("vmid")
                                .long("vmid")
                                .value_parser(clap::value_parser!(u32)),
                        ),
                ),
            ),
        )
    }

    #[test]
    fn an_empty_positional_is_a_usage_error() {
        let err = cmd()
            .try_get_matches_from(["t", "pool", "show", ""])
            .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidValue);
        assert!(cmd()
            .try_get_matches_from(["t", "pool", "show", "tenant-a"])
            .is_ok());
    }

    #[test]
    fn options_may_still_be_empty() {
        assert!(cmd()
            .try_get_matches_from(["t", "pool", "show", "p", "--comment", ""])
            .is_ok());
    }

    #[test]
    fn a_trailing_word_list_may_hold_an_empty_word() {
        let c = reject_empty_positionals(
            Command::new("exec")
                .arg(Arg::new("vmid").required(true))
                .arg(
                    Arg::new("cmd")
                        .num_args(1..)
                        .trailing_var_arg(true)
                        .allow_hyphen_values(true),
                ),
        );
        assert!(c
            .try_get_matches_from(["exec", "100", "printf", ""])
            .is_ok());
    }
}
