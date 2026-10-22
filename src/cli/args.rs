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

/// Give every subcommand a `Usage:` line that parses. clap writes a
/// parent's required positionals into its child's usage (`qga <VMID>
/// net`) but builds the grandchild's from the child's plain name, so
/// `firewall-guest <VMID> alias list` printed as `firewall-guest alias
/// list` (audit #385). clap recomputes names while parsing, so the fix is
/// an `override_usage`, set only where an ancestor above the parent has
/// required positionals.
#[must_use]
pub fn usage_with_parent_positionals(cmd: Command) -> Command {
    let root = cmd.get_name().to_string();
    let mut built = cmd.bin_name(root.clone());
    built.build();
    let prefix = with_positionals(&built, &root);
    built.mut_subcommands(|sub| fix_usage(sub, &prefix, false))
}

/// `path` followed by the `<NAME>` of each required positional of `cmd`.
fn with_positionals(cmd: &Command, path: &str) -> String {
    let mut out = path.to_string();
    for arg in cmd.get_positionals().filter(|a| a.is_required_set()) {
        let name = arg
            .get_value_names()
            .and_then(|v| v.first())
            .map_or_else(|| arg.get_id().as_str().to_uppercase(), ToString::to_string);
        out.push_str(&format!(" <{name}>"));
    }
    out
}

/// `prefix` is the full path to `sub`'s parent with every ancestor's
/// required positionals; `lossy` says whether clap's own path for `sub`
/// has lost some of them.
fn fix_usage(sub: Command, prefix: &str, lossy: bool) -> Command {
    let name = sub.get_name().to_string();
    let path = format!("{prefix} {name}");
    let mut sub = sub;
    if lossy {
        // clap's rendering of this command's own arguments, after its
        // (incomplete) path.
        let rendered = sub.clone().render_usage().to_string();
        let marker = format!(" {name}");
        if let Some(i) = rendered.rfind(&marker) {
            let tail = &rendered[i + marker.len()..];
            sub = sub.override_usage(format!("{path}{tail}"));
        }
    }
    let child_prefix = with_positionals(&sub, &path);
    // A child's clap path keeps this command's positionals but none above.
    let child_lossy = lossy || prefix.contains(" <");
    sub.mut_subcommands(|c| fix_usage(c, &child_prefix, child_lossy))
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

    #[test]
    fn a_nested_usage_line_carries_every_ancestor_positional() {
        let cmd = usage_with_parent_positionals(
            Command::new("t").subcommand(
                Command::new("fw")
                    .arg(Arg::new("vmid").required(true))
                    .subcommand(Command::new("alias").subcommand(Command::new("list"))),
            ),
        );
        let err = cmd
            .try_get_matches_from(["t", "fw", "100", "alias", "list", "--help"])
            .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        assert!(
            err.to_string().contains("Usage: t fw <VMID> alias list"),
            "{err}"
        );
    }

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
