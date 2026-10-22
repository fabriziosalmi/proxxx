//! Help text checked against the clap tree it documents (audit #385).

use clap::Subcommand as _;

fn cli() -> clap::Command {
    let mut cmd = super::Command::augment_subcommands(clap::Command::new("proxxx"));
    cmd.build();
    cmd
}

/// `init` had no description and `profiles --help` opened with the `init`
/// text: the doc comment sat above the wrong variant. Top level only:
/// several nested subcommands have no description yet.
#[test]
fn every_top_level_command_has_a_description() {
    let cli = cli();
    let missing: Vec<&str> = cli
        .get_subcommands()
        .filter(|s| s.get_name() != "help")
        .filter(|s| s.get_about().is_none() && s.get_long_about().is_none())
        .map(clap::Command::get_name)
        .collect();
    assert!(
        missing.is_empty(),
        "commands without a description: {missing:?}"
    );
}

#[test]
fn profiles_and_init_describe_themselves() {
    let cli = cli();
    let about = |name: &str| {
        cli.find_subcommand(name)
            .and_then(clap::Command::get_about)
            .map(ToString::to_string)
            .unwrap_or_default()
    };
    assert!(
        about("profiles").starts_with("List named profiles"),
        "{}",
        about("profiles")
    );
    assert!(
        about("init").starts_with("Bootstrap a `config.toml`"),
        "{}",
        about("init")
    );
}

fn possible_values(path: &[&str], arg: &str) -> Vec<String> {
    let cli = cli();
    let mut cmd = &cli;
    for name in path {
        cmd = cmd.find_subcommand(name).expect("subcommand exists");
    }
    let values = cmd
        .get_arguments()
        .find(|a| a.get_id() == arg)
        .expect("argument exists")
        .get_possible_values()
        .iter()
        .map(|v| v.get_name().to_string())
        .collect();
    values
}

/// Values measured against PVE 9.1.1: `/feature` takes snapshot, clone
/// and copy; `/cluster/resources?type=` takes vm, storage, node and sdn,
/// and pool and network are filtered by proxxx.
#[test]
fn enumerated_arguments_offer_only_what_pve_accepts() {
    assert_eq!(
        possible_values(&["feature"], "feature"),
        ["snapshot", "clone", "copy"]
    );
    assert_eq!(
        possible_values(&["cluster-resources"], "kind"),
        ["vm", "storage", "node", "sdn", "pool", "network"]
    );
}

#[test]
fn search_matches_and_reports_the_labels_ls_prints() {
    use crate::api::types::{Guest, GuestStatus, GuestType};
    let vm = Guest {
        vmid: 8888,
        name: "debian".into(),
        node: "pve1".into(),
        status: GuestStatus::Stopped,
        guest_type: GuestType::Qemu,
        ..Guest::default()
    };
    // `0` is in no visible field of this guest; the guest type used to be
    // in the haystack as the number 0.
    assert!(super::search_rows(&[], std::slice::from_ref(&vm), &[], "0", 20).is_empty());
    let rows = super::search_rows(&[], &[vm], &[], "qemu", 20);
    assert_eq!(rows[0]["status"], "stopped");
    assert_eq!(rows[0]["type"], "qemu");
}

fn placeholders(cmd: &clap::Command) -> Vec<String> {
    cmd.get_positionals()
        .filter(|a| a.is_required_set())
        .map(|a| {
            let name = a
                .get_value_names()
                .and_then(|v| v.first())
                .map_or_else(|| a.get_id().as_str().to_uppercase(), ToString::to_string);
            format!("<{name}>")
        })
        .collect()
}

fn check_usage(cmd: &clap::Command, inherited: &[String], bad: &mut Vec<String>) {
    for sub in cmd.get_subcommands().filter(|s| s.get_name() != "help") {
        let usage = sub.clone().render_usage().to_string();
        let lost: Vec<&String> = inherited.iter().filter(|p| !usage.contains(*p)).collect();
        if !lost.is_empty() {
            bad.push(format!("{usage}  (missing {lost:?})"));
        }
        let mut next = inherited.to_vec();
        next.extend(placeholders(sub));
        check_usage(sub, &next, bad);
    }
}

/// `firewall-guest alias list` printed its usage without `<VMID>`.
#[test]
fn every_usage_line_carries_its_ancestors_positionals() {
    let cmd = super::args::usage_with_parent_positionals(cli());
    let mut bad = Vec::new();
    check_usage(&cmd, &[], &mut bad);
    assert!(
        bad.is_empty(),
        "usage lines that do not parse:\n{}",
        bad.join("\n")
    );
    let err = cmd
        .try_get_matches_from(["proxxx", "firewall-guest", "100", "alias", "list", "--help"])
        .unwrap_err();
    assert!(
        err.to_string()
            .contains("Usage: proxxx firewall-guest <VMID> alias list"),
        "{err}"
    );
}
