//! Help text checked against the clap tree it documents (audit #385).

use clap::Subcommand as _;

fn cli() -> clap::Command {
    let mut cmd = super::Command::augment_subcommands(clap::Command::new("proxxx"));
    cmd.build();
    cmd
}

fn undescribed<'a>(cmd: &'a clap::Command, path: &mut Vec<&'a str>, out: &mut Vec<String>) {
    for sub in cmd.get_subcommands() {
        if sub.get_name() == "help" {
            continue;
        }
        path.push(sub.get_name());
        if sub.get_about().is_none() && sub.get_long_about().is_none() {
            out.push(path.join(" "));
        }
        undescribed(sub, path, out);
        path.pop();
    }
}

/// Every subcommand at every level has a description (#494: 64 nested
/// ones had none, so `--help` listed them blank). `init` lost its own and
/// `profiles --help` opened with the `init` text when a doc comment sat
/// above the wrong variant (#385).
#[test]
fn every_subcommand_has_a_description() {
    let mut missing = Vec::new();
    undescribed(&cli(), &mut Vec::new(), &mut missing);
    assert!(
        missing.is_empty(),
        "subcommands without a description: {missing:?}"
    );
}

/// #494: arguments PVE 9.1 requires on these calls (each measured: a 400
/// "property is missing and it is not optional") are required here too,
/// and the metric-server `--comment`, which PVE does not accept at all,
/// is gone.
#[test]
fn arguments_pve_requires_are_required() {
    let cmd = super::args::usage_with_parent_positionals(cli());
    // (command line, refused by the parser)
    let cases = [
        ("node-system pve1 dns set --dns1 1.1.1.1", true),
        ("node-system pve1 dns set --search lan --dns1 1.1.1.1", false),
        ("firewall-cluster alias update a --comment x", true),
        ("firewall-cluster alias update a --cidr 10.0.0.1", false),
        ("firewall-guest 100 alias update a --comment x", true),
        ("firewall-guest 100 alias update a --cidr 10.0.0.1", false),
        ("cluster-mapping usb update m --description x", true),
        ("cluster-mapping usb update m --map node=pve1,id=1234:5678", false),
        ("metric-servers update influx --disable true", true),
        ("metric-servers update influx --server h --port 8086", false),
        ("metric-servers create --id i --server-type influxdb --server h --port 8086 --comment x", true),
        ("metric-servers create --id i --server-type influxdb --server h --port 8086", false),
    ];
    for (line, refused) in cases {
        let argv = std::iter::once("proxxx").chain(line.split_whitespace());
        let got = cmd.clone().try_get_matches_from(argv).is_err();
        assert_eq!(got, refused, "`{line}`: refused={got}, expected {refused}");
    }
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
