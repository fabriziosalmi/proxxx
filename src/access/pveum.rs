//! Parser for `pveum user permissions <userid>` output.
//!
//! Why a parser at all: `pveum` doesn't have a JSON output flag in PVE
//! 7/8 for the `user permissions` subcommand — it prints a human table.
//! We accept that table verbatim and parse it into a strict struct so
//! the rest of proxxx can reason about the result.
//!
//! Sample output (PVE 8):
//! ```text
//! Permissions for user 'oncall@pve' on /:
//!     VM.Audit (1)
//!     Datastore.Audit (1)
//!
//! Permissions for user 'oncall@pve' on /vms/100:
//!     VM.PowerMgmt (1)
//! ```
//!
//! `(1)` is `propagate=true`, `(0)` is propagate=false. We capture both
//! the privilege list per path AND the propagate flag per privilege.
//!
//! Strategy: stateful line scanner. Headers reset the current path, body
//! lines are appended. Anything we don't recognise is logged + skipped
//! rather than failing — this preserves forward-compat if Proxmox ever
//! adds extra trailing lines.

use std::collections::BTreeMap;

/// One privilege the user holds on a path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPerms {
    /// Path the privileges apply to, e.g. `"/"`, `"/vms/100"`.
    pub path: String,
    /// `(privilege_name, propagate)` pairs. Sorted by name for stable
    /// output. `propagate=true` means children inherit.
    pub privileges: Vec<(String, bool)>,
}

/// Full effective permissions snapshot for one user.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EffectivePermissions {
    pub userid: String,
    pub paths: Vec<PathPerms>,
}

/// Parse the output of `pveum user permissions <userid>`. The userid
/// must be passed in separately because the output sometimes wraps it
/// in single quotes and we don't want to chase escape rules.
#[must_use]
pub fn parse_user_permissions(userid: &str, output: &str) -> EffectivePermissions {
    let mut by_path: BTreeMap<String, Vec<(String, bool)>> = BTreeMap::new();
    let mut current_path: Option<String> = None;

    for raw in output.lines() {
        let line = raw.trim_end();
        // Header: `Permissions for user 'X' on /path:` (also accepts
        // `for token 'X'` for completeness).
        if let Some(rest) = line
            .trim_start()
            .strip_prefix("Permissions for user ")
            .or_else(|| line.trim_start().strip_prefix("Permissions for token "))
        {
            // rest = "'oncall@pve' on /vms/100:"
            // Strip trailing colon if present.
            let cleaned = rest.trim_end_matches(':');
            // Find " on " separator.
            if let Some(idx) = cleaned.find(" on ") {
                let path = cleaned[idx + 4..].trim().to_string();
                current_path = Some(path.clone());
                by_path.entry(path).or_default();
            }
            continue;
        }

        // Body line: `    Privilege.Name (propagate-flag)`.
        // Skip empty / non-indented.
        if !raw.starts_with(' ') && !raw.starts_with('\t') {
            // End-of-section: clear current path, but keep the entry
            // we already inserted in by_path.
            current_path = None;
            continue;
        }
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some(path) = current_path.as_ref() else {
            // Body line without a header — malformed, skip.
            continue;
        };
        // Parse "Name (0)" or "Name (1)".
        let (name, propagate) = match parse_priv_line(trimmed) {
            Some(t) => t,
            None => continue,
        };
        by_path
            .entry(path.clone())
            .or_default()
            .push((name, propagate));
    }

    let mut paths: Vec<PathPerms> = by_path
        .into_iter()
        .map(|(path, mut privs)| {
            privs.sort_by(|a, b| a.0.cmp(&b.0));
            privs.dedup_by(|a, b| a.0 == b.0);
            PathPerms {
                path,
                privileges: privs,
            }
        })
        .collect();
    paths.sort_by(|a, b| a.path.cmp(&b.path));

    EffectivePermissions {
        userid: userid.to_string(),
        paths,
    }
}

fn parse_priv_line(line: &str) -> Option<(String, bool)> {
    // Expected: `Name.Suffix (0)` or `Name.Suffix (1)`.
    let lparen = line.rfind('(')?;
    let rparen = line.rfind(')')?;
    if rparen < lparen {
        return None;
    }
    let name = line[..lparen].trim().to_string();
    if name.is_empty() {
        return None;
    }
    let flag = line[lparen + 1..rparen].trim();
    let propagate = match flag {
        "1" => true,
        "0" => false,
        _ => return None,
    };
    Some((name, propagate))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PVE8: &str = "\
Permissions for user 'oncall@pve' on /:
    VM.Audit (1)
    Datastore.Audit (1)

Permissions for user 'oncall@pve' on /vms/100:
    VM.PowerMgmt (1)
    VM.Audit (0)
";

    #[test]
    fn parses_pve8_sample() {
        let p = parse_user_permissions("oncall@pve", SAMPLE_PVE8);
        assert_eq!(p.userid, "oncall@pve");
        assert_eq!(p.paths.len(), 2);
        // Paths are sorted alphabetically.
        assert_eq!(p.paths[0].path, "/");
        assert_eq!(p.paths[1].path, "/vms/100");
        // Root has 2 privileges, sorted by name.
        let root = &p.paths[0];
        assert_eq!(root.privileges.len(), 2);
        assert_eq!(root.privileges[0].0, "Datastore.Audit");
        assert!(root.privileges[0].1);
        assert_eq!(root.privileges[1].0, "VM.Audit");
        // VM-100 path: VM.Audit propagate=false.
        let vm = &p.paths[1];
        let vm_audit = vm
            .privileges
            .iter()
            .find(|(n, _)| n == "VM.Audit")
            .expect("VM.Audit on vms/100");
        assert!(!vm_audit.1, "propagate=0 must round-trip as false");
    }

    #[test]
    fn empty_output_yields_empty_struct() {
        let p = parse_user_permissions("nobody@pve", "");
        assert_eq!(p.userid, "nobody@pve");
        assert!(p.paths.is_empty());
    }

    #[test]
    fn handles_token_header_form() {
        let out = "Permissions for token 'svc@pve!ci' on /:\n    VM.Allocate (1)\n";
        let p = parse_user_permissions("svc@pve!ci", out);
        assert_eq!(p.paths.len(), 1);
        assert_eq!(p.paths[0].privileges.len(), 1);
        assert_eq!(p.paths[0].privileges[0].0, "VM.Allocate");
    }

    #[test]
    fn malformed_lines_skipped_not_panic() {
        // Body lines MUST be indented per pveum's output format.
        // Explicit \n separation here so leading spaces survive.
        let out = "Permissions for user 'x@pve' on /:\n    garbage line without parens\n    nope (xyz)\n    VM.Audit (1)\n";
        let p = parse_user_permissions("x@pve", out);
        assert_eq!(p.paths.len(), 1);
        assert_eq!(p.paths[0].privileges.len(), 1);
        assert_eq!(p.paths[0].privileges[0].0, "VM.Audit");
    }

    #[test]
    fn duplicate_privileges_deduped() {
        let out = "Permissions for user 'x@pve' on /:\n    VM.Audit (1)\n    VM.Audit (1)\n";
        let p = parse_user_permissions("x@pve", out);
        assert_eq!(p.paths.len(), 1);
        assert_eq!(p.paths[0].privileges.len(), 1);
    }

    #[test]
    fn body_without_header_ignored() {
        // No "Permissions for user" preamble — body lines must be
        // dropped silently rather than panicking on missing path.
        let out = "    VM.Audit (1)\n    Datastore.Allocate (0)\n";
        let p = parse_user_permissions("ghost@pve", out);
        assert!(p.paths.is_empty());
    }

    #[test]
    fn paths_with_special_chars_preserved() {
        let out = "Permissions for user 'a@pve' on /storage/local-zfs:\n    Datastore.AllocateSpace (1)\n";
        let p = parse_user_permissions("a@pve", out);
        assert_eq!(p.paths[0].path, "/storage/local-zfs");
    }
}
