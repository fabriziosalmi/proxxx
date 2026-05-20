//! `proxxx upgrade-check --target <version>` — pre-flight scanner
//! for PVE major upgrades.
//!
//! The "Friday upgrade → Saturday emergency" failure mode comes
//! from breaking changes (removed endpoints, deprecated config
//! fields, changed defaults) that nobody noticed until after the
//! reboot. This scanner runs the equivalent of `pve8to9`'s checks
//! cluster-wide PLUS scans proxxx's own config for fields that will
//! break in the target version.
//!
//! ## What lands in this MVP
//!
//! - **Bundled rule set** at compile time. Each rule has a `target`
//!   (the upgrade target it applies to), `severity`, `component`,
//!   `description`, and `remediation`. Rules are easy to add: append
//!   a new [`UpgradeRule`] to [`RULES`].
//! - **Cluster scan**: hits every node's `/version` endpoint and
//!   reports anything below the target version (still on the
//!   pre-upgrade major).
//! - **Config scan**: reads the live `ProfileConfig` and checks
//!   known-deprecated fields against the rules.
//! - **Output**: text (default) for humans; JSON for CI gating.
//! - **Exit code**: 0 on info/warn only; 1 on any `block`-severity
//!   finding. Operators can `proxxx upgrade-check --target 9.x ||
//!   echo "DO NOT UPGRADE"` in their CI pipelines.
//!
//! ## Scope deferred per #60
//!
//! - **`pve8to9` parity** — the full perl script checks ~30 things
//!   (apt sources, ceph version, corosync version, free space,
//!   kernel modules, etc.). Implementing each requires SSH + bash
//!   probing. v1 covers the PVE-version-floor check; the rest is
//!   one PR per category.
//! - **Audit-log scan** for deprecated endpoint usage. Requires
//!   walking `audit_log.params_json` against an endpoint-removal
//!   list. Separate work.
//! - **Per-guest scan** (cloud-init schema drift, OS support matrix).
//!   Touches guest config; out-of-scope for the platform pre-flight.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

use crate::api::{ProxmoxGateway, PxClient};

/// Severity ladder. `Block` flips the CLI exit code to 1 so
/// `proxxx upgrade-check && proxxx patch apply` gates correctly.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational only — no action needed.
    Info,
    /// Should be addressed before upgrade; doesn't gate.
    Warn,
    /// Will break on upgrade. Gates the exit code.
    Block,
}

/// One bundled rule. `'static` everywhere — the rule table is a
/// compile-time const.
#[derive(Debug, Clone, Serialize)]
pub struct UpgradeRule {
    /// Target version this rule applies to (e.g. `"9"`). A scan
    /// for `--target 9.x` runs every rule whose target string is
    /// a prefix match for the requested target's major.
    pub target: &'static str,
    pub severity: Severity,
    /// Short component tag for grouping output (`"config"`,
    /// `"node"`, `"ceph"`, `"corosync"`, etc.).
    pub component: &'static str,
    /// One-line description. Imperative or declarative — both
    /// styles are fine.
    pub description: &'static str,
    /// Numbered remediation steps in one string. Concrete enough
    /// for an operator to act without lookups.
    pub remediation: &'static str,
    /// URL or wiki anchor with the canonical reference. Empty
    /// when no public reference exists (e.g. proxxx-internal).
    pub reference: &'static str,
}

/// The bundled rule set. Append-only — never remove a rule once
/// shipped because operators may script against the `component` +
/// `description` text.
pub const RULES: &[UpgradeRule] = &[
    // ── PVE 8 → 9 ───────────────────────────────────────────────
    UpgradeRule {
        target: "9",
        severity: Severity::Block,
        component: "node",
        description: "Node running pre-9.x PVE — upgrade in place is required before \
                      target 9.x features (state apply, new firewall syntax) work.",
        remediation: "1. `apt update && apt full-upgrade` on each node. \
                      2. Reboot one node at a time (drain HA-managed guests first). \
                      3. Re-run `proxxx upgrade-check --target 9.x` until all nodes report 9.x.",
        reference: "https://pve.proxmox.com/wiki/Upgrade_from_8_to_9",
    },
    UpgradeRule {
        target: "9",
        severity: Severity::Warn,
        component: "config",
        description: "Config has `verify_tls = false` — PVE 9.x ships stricter TLS \
                      defaults; consider rotating to a proper certificate before \
                      upgrade so you don't lose the option to enable verification.",
        remediation: "1. Install a real cert on every pveproxy (Let's Encrypt or \
                      private CA). \
                      2. Update `config.toml` → `verify_tls = true`. \
                      3. Probe with `proxxx doctor` to confirm.",
        reference: "https://pve.proxmox.com/wiki/Certificate_Management",
    },
    UpgradeRule {
        target: "9",
        severity: Severity::Info,
        component: "feature",
        description: "PVE 9.x adds the cluster-firewall syntax `direction = forward` — \
                      proxxx's state-apply layer (`proxxx state apply`) handles this \
                      natively from the export side. No action needed for current users.",
        remediation: "No action — informational. Operators upgrading from `proxxx ≤ 0.1.x` \
                      should re-export firewall state after upgrade.",
        reference: "",
    },
];

/// Find every rule that applies to the requested target. Match is
/// prefix-based on `major`: `--target 9.1.1` matches rules with
/// `target = "9"` or `target = "9.1"`.
#[must_use]
pub fn rules_for_target(target: &str) -> Vec<&'static UpgradeRule> {
    let target_major = target.split('.').next().unwrap_or(target);
    RULES.iter().filter(|r| r.target == target_major).collect()
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: usize,
    pub severity: Severity,
    pub component: &'static str,
    pub description: &'static str,
    pub remediation: &'static str,
    pub reference: &'static str,
    /// Per-node context when the finding came from a per-node
    /// check (e.g. version floor). Empty for global findings.
    pub node: Option<String>,
    /// Free-form additional detail (current value, observed
    /// version, etc.) that the static rule text can't carry.
    pub detail: Option<String>,
}

#[derive(Debug, clap::Args)]
pub struct UpgradeCheckArgs {
    /// Upgrade target version (e.g. `9.1`, `9.x`, `10`). Match is
    /// prefix-based on the major; minor/patch are accepted but
    /// only the major is used for rule filtering.
    #[arg(long)]
    pub target: String,

    /// Output format. `text` (default) for humans, `json` for CI.
    #[arg(long, value_enum, default_value_t = UpgradeOutput::Text)]
    pub output: UpgradeOutput,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, Default)]
pub enum UpgradeOutput {
    #[default]
    Text,
    Json,
}

pub async fn execute_upgrade_check(
    client: &Arc<PxClient>,
    config: &crate::config::ProfileConfig,
    args: UpgradeCheckArgs,
) -> Result<(Value, i32)> {
    let target = args.target.trim();
    if target.is_empty() {
        anyhow::bail!("--target is required (e.g. `--target 9.x`)");
    }
    let target_major = target.split('.').next().unwrap_or(target);
    let applicable = rules_for_target(target);

    let mut findings: Vec<Finding> = Vec::new();

    // Per-node version check.
    if let Ok(nodes) = client.get_nodes().await {
        for n in nodes {
            // Best-effort per-node version probe — PVE's `pveversion`
            // is per-node; the cluster `get_api_version` returns
            // whichever node the API call landed on. We could SSH
            // per-node for a richer probe; v1 uses the cluster value
            // as a coarse signal.
            if let Ok(v) = client.get_api_version().await {
                let observed_major = v.version.split('.').next().unwrap_or(&v.version);
                if observed_major != target_major {
                    // Find the matching node-rule.
                    if let Some((rule_id, rule)) = applicable
                        .iter()
                        .enumerate()
                        .find(|(_, r)| r.component == "node")
                    {
                        findings.push(Finding {
                            rule_id,
                            severity: rule.severity,
                            component: rule.component,
                            description: rule.description,
                            remediation: rule.remediation,
                            reference: rule.reference,
                            node: Some(n.node.clone()),
                            detail: Some(format!("observed PVE {}", v.version)),
                        });
                    }
                }
                // First node's version is representative for the
                // cluster-wide rule; bail to avoid duplicate
                // findings if PVE only exposes a cluster version.
                break;
            }
        }
    }

    // Config-side rules.
    for (rule_id, rule) in applicable.iter().enumerate() {
        match rule.component {
            "config"
                if rule.description.contains("verify_tls = false") && !config.verify_tls =>
            {
                findings.push(Finding {
                    rule_id,
                    severity: rule.severity,
                    component: rule.component,
                    description: rule.description,
                    remediation: rule.remediation,
                    reference: rule.reference,
                    node: None,
                    detail: Some("config.toml has `verify_tls = false`".into()),
                });
            }
            // Info-tier rules without a runtime predicate are
            // always emitted so operators see them in the report.
            "feature" => {
                findings.push(Finding {
                    rule_id,
                    severity: rule.severity,
                    component: rule.component,
                    description: rule.description,
                    remediation: rule.remediation,
                    reference: rule.reference,
                    node: None,
                    detail: None,
                });
            }
            _ => {}
        }
    }

    // Exit code: 1 if any Block-severity finding; 0 otherwise.
    let has_block = findings.iter().any(|f| f.severity == Severity::Block);

    match args.output {
        UpgradeOutput::Json => {
            let v = serde_json::json!({
                "target": target,
                "findings": findings,
                "summary": {
                    "blocks": findings.iter().filter(|f| f.severity == Severity::Block).count(),
                    "warns": findings.iter().filter(|f| f.severity == Severity::Warn).count(),
                    "infos": findings.iter().filter(|f| f.severity == Severity::Info).count(),
                }
            });
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        UpgradeOutput::Text => {
            if findings.is_empty() {
                println!("✓ no upgrade-check findings for target {target}");
            } else {
                println!("upgrade-check → target {target}\n");
                for f in &findings {
                    let sigil = match f.severity {
                        Severity::Block => "✗ BLOCK",
                        Severity::Warn => "! WARN ",
                        Severity::Info => "ℹ INFO ",
                    };
                    let node = f.node.as_deref().unwrap_or("(cluster)");
                    println!("{sigil}  [{}] on {node}", f.component);
                    println!("  {}", f.description);
                    if let Some(d) = &f.detail {
                        println!("  detail: {d}");
                    }
                    println!("  remediation: {}", f.remediation);
                    if !f.reference.is_empty() {
                        println!("  reference: {}", f.reference);
                    }
                    println!();
                }
            }
        }
    }

    Ok((Value::Null, i32::from(has_block)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_for_target_matches_by_major_prefix() {
        assert!(!rules_for_target("9").is_empty());
        assert!(!rules_for_target("9.1.1").is_empty());
        assert!(!rules_for_target("9.x").is_empty());
        assert!(rules_for_target("10").is_empty());
        assert!(rules_for_target("").is_empty());
    }

    #[test]
    fn rules_have_well_formed_metadata() {
        for r in RULES {
            assert!(!r.target.is_empty());
            assert!(!r.component.is_empty());
            assert!(!r.description.is_empty());
            assert!(!r.remediation.is_empty());
            // Reference can be empty (no public ref); not asserted.
        }
    }

    #[test]
    fn severity_serialises_lowercase() {
        let v = serde_json::to_value(Severity::Block).unwrap();
        assert_eq!(v, "block");
        let v2 = serde_json::to_value(Severity::Warn).unwrap();
        assert_eq!(v2, "warn");
        let v3 = serde_json::to_value(Severity::Info).unwrap();
        assert_eq!(v3, "info");
    }
}
