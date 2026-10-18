//! Parser for `pveum user permissions --output-format json -- <userid>` output.
//!
//! `proxxx perms` shells out to `pveum user permissions --output-format json`
//! over SSH so Proxmox's `pve-access-control` remains the single authority for
//! effective privilege evaluation.
//!
//! Expected JSON shape (PVE 7/8/9):
//! ```json
//! {
//!   "/": { "Datastore.Audit": 1, "VM.Audit": 1 },
//!   "/vms/100": { "VM.PowerMgmt": 1, "VM.Audit": 0 }
//! }
//! ```
//! Outer keys are ACL paths; inner keys are privilege names; values are the
//! integer propagate flag (`1` = `true`, `0` = `false`). An empty object `{}`
//! parses to an empty `paths` list (`execute_perms` then queries
//! `GET /access/users/{userid}` to distinguish an existing user with no
//! privileges from a user that does not exist). Non-JSON output or JSON of any
//! other shape is rejected with an error carrying up to the first 200
//! characters of stdout.

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

/// Parse the output of `pveum user permissions --output-format json -- <userid>`.
///
/// # Errors
///
/// Returns an error (including up to the first 200 characters of `output`)
/// if `output` is not a valid JSON object mapping ACL paths to `{privilege: 0|1}`
/// maps.
pub fn parse_user_permissions(userid: &str, output: &str) -> anyhow::Result<EffectivePermissions> {
    let raw: BTreeMap<String, BTreeMap<String, u8>> =
        serde_json::from_str(output).map_err(|e| {
            let snippet: String = output.chars().take(200).collect();
            anyhow::anyhow!(
                "failed to parse `pveum user permissions` JSON output for {userid}: {e} (stdout: {snippet:?})"
            )
        })?;

    let mut paths = Vec::with_capacity(raw.len());
    for (path, priv_map) in raw {
        let mut privileges = Vec::with_capacity(priv_map.len());
        for (priv_name, flag) in priv_map {
            let propagate = match flag {
                1 => true,
                0 => false,
                other => {
                    let snippet: String = output.chars().take(200).collect();
                    anyhow::bail!(
                        "invalid propagate flag {other} for privilege {priv_name:?} on {path:?} in `pveum user permissions` output (stdout: {snippet:?})"
                    );
                }
            };
            privileges.push((priv_name, propagate));
        }
        privileges.sort_by(|a, b| a.0.cmp(&b.0));
        paths.push(PathPerms { path, privileges });
    }
    paths.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(EffectivePermissions {
        userid: userid.to_string(),
        paths,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUDITOR_PVE9_JSON: &str = concat!(
        r#"{"/":{"Datastore.Audit":1,"Mapping.Audit":1,"Pool.Audit":1,"SDN.Audit":1,"Sys.Audit":1,"VM.Audit":1,"VM.GuestAgent.Audit":1},"#,
        r#""/access":{"Datastore.Audit":1,"Mapping.Audit":1,"Pool.Audit":1,"SDN.Audit":1,"Sys.Audit":1,"VM.Audit":1,"VM.GuestAgent.Audit":1},"#,
        r#""/access/groups":{"Datastore.Audit":1,"Mapping.Audit":1,"Pool.Audit":1,"SDN.Audit":1,"Sys.Audit":1,"VM.Audit":1,"VM.GuestAgent.Audit":1},"#,
        r#""/nodes":{"Datastore.Audit":1,"Mapping.Audit":1,"Pool.Audit":1,"SDN.Audit":1,"Sys.Audit":1,"VM.Audit":1,"VM.GuestAgent.Audit":1},"#,
        r#""/pool":{"Datastore.Audit":1,"Mapping.Audit":1,"Pool.Audit":1,"SDN.Audit":1,"Sys.Audit":1,"VM.Audit":1,"VM.GuestAgent.Audit":1},"#,
        r#""/sdn":{"Datastore.Audit":1,"Mapping.Audit":1,"Pool.Audit":1,"SDN.Audit":1,"Sys.Audit":1,"VM.Audit":1,"VM.GuestAgent.Audit":1},"#,
        r#""/storage":{"Datastore.Audit":1,"Mapping.Audit":1,"Pool.Audit":1,"SDN.Audit":1,"Sys.Audit":1,"VM.Audit":1,"VM.GuestAgent.Audit":1},"#,
        r#""/vms":{"Datastore.Audit":1,"Mapping.Audit":1,"Pool.Audit":1,"SDN.Audit":1,"Sys.Audit":1,"VM.Audit":1,"VM.GuestAgent.Audit":1},"#,
        r#""/vms/8888":{"Datastore.Audit":1,"Mapping.Audit":1,"Pool.Audit":1,"SDN.Audit":1,"Sys.Audit":1,"VM.Audit":1,"VM.GuestAgent.Audit":1}}"#
    );

    const SAMPLE_PVE8_TEXT: &str = "\
Permissions for user 'oncall@pve' on /:
    VM.Audit (1)
    Datastore.Audit (1)

Permissions for user 'oncall@pve' on /vms/100:
    VM.PowerMgmt (1)
    VM.Audit (0)
";

    const PVE9_BOX_TABLE: &str = "\
┌────────────────┬─────────────────────┬───────────┐
│ ACL path       │ Permissions         │ Propagate │
╞════════════════╪═════════════════════╪═══════════╡
│ /              │ Datastore.Audit     │         1 │
│                │ VM.Audit            │         1 │
└────────────────┴─────────────────────┴───────────┘
";

    /// Required test 1 (#347): full 9-path, 7-privilege JSON captured on PVE 9.1.1
    /// for `auditor@pve`.
    #[test]
    fn parses_pve9_auditor_json() {
        let p = parse_user_permissions("auditor@pve", AUDITOR_PVE9_JSON)
            .expect("PVE 9.1.1 JSON must parse");
        assert_eq!(p.userid, "auditor@pve");
        assert_eq!(p.paths.len(), 9);

        let expected_paths = [
            "/",
            "/access",
            "/access/groups",
            "/nodes",
            "/pool",
            "/sdn",
            "/storage",
            "/vms",
            "/vms/8888",
        ];
        let expected_privs = [
            "Datastore.Audit",
            "Mapping.Audit",
            "Pool.Audit",
            "SDN.Audit",
            "Sys.Audit",
            "VM.Audit",
            "VM.GuestAgent.Audit",
        ];

        for (pp, expected_path) in p.paths.iter().zip(expected_paths.iter()) {
            assert_eq!(pp.path, *expected_path);
            assert_eq!(pp.privileges.len(), 7);
            for ((name, propagate), expected_priv) in
                pp.privileges.iter().zip(expected_privs.iter())
            {
                assert_eq!(name, *expected_priv);
                assert!(
                    *propagate,
                    "propagate must be true for {name} on {expected_path}"
                );
            }
        }

        // Single-path sample (`--path /vms/8888`) from PVE 9.1.1 lab capture.
        let single = r#"{"/vms/8888":{"Datastore.Audit":1,"Mapping.Audit":1,"Pool.Audit":1,"SDN.Audit":1,"Sys.Audit":1,"VM.Audit":1,"VM.GuestAgent.Audit":1}}"#;
        let ps =
            parse_user_permissions("auditor@pve", single).expect("single-path JSON must parse");
        assert_eq!(ps.paths.len(), 1);
        assert_eq!(ps.paths[0].path, "/vms/8888");
        assert_eq!(ps.paths[0].privileges.len(), 7);
    }

    /// Required test 2 (#347): `{}` yields an empty path set; invalid JSON,
    /// empty stdout, PVE 9 box-drawn tables, and legacy PVE 7/8 text output
    /// all return `Err` with the first 200 chars of stdout.
    #[test]
    fn empty_json_object_and_invalid_or_table_outputs() {
        let empty = parse_user_permissions("nosuch@pve", "{}").expect("{} is valid empty JSON");
        assert_eq!(empty.userid, "nosuch@pve");
        assert_eq!(empty.paths, Vec::new());

        let empty_nl =
            parse_user_permissions("nosuch@pve", "{}\n").expect("{}\\n is valid empty JSON");
        assert_eq!(empty_nl.paths, Vec::new());

        let table_err = parse_user_permissions("auditor@pve", PVE9_BOX_TABLE)
            .expect_err("PVE 9 box-drawn table without --output-format json must fail");
        let msg = table_err.to_string();
        assert!(
            msg.contains("ACL path"),
            "error must include stdout snippet, got: {msg}"
        );

        let text_err = parse_user_permissions("oncall@pve", SAMPLE_PVE8_TEXT)
            .expect_err("legacy PVE 7/8 text table must fail");
        assert!(text_err.to_string().contains("Permissions for user"));

        let invalid_err =
            parse_user_permissions("oncall@pve", "not valid json").expect_err("invalid JSON fails");
        assert!(invalid_err.to_string().contains("not valid json"));
    }

    #[test]
    fn multi_path_propagate_zero_and_sorting_round_trip() {
        let json = r#"{"/vms/100":{"VM.PowerMgmt":1,"VM.Audit":0},"/":{"VM.Audit":1,"Datastore.Audit":1}}"#;
        let p = parse_user_permissions("oncall@pve", json).expect("valid JSON");
        assert_eq!(p.userid, "oncall@pve");
        assert_eq!(p.paths.len(), 2);
        assert_eq!(p.paths[0].path, "/");
        assert_eq!(p.paths[1].path, "/vms/100");
        assert_eq!(
            p.paths[0].privileges,
            vec![
                ("Datastore.Audit".to_string(), true),
                ("VM.Audit".to_string(), true),
            ]
        );
        assert_eq!(
            p.paths[1].privileges,
            vec![
                ("VM.Audit".to_string(), false),
                ("VM.PowerMgmt".to_string(), true),
            ]
        );
    }

    #[test]
    fn empty_stdout_is_rejected_as_err() {
        assert!(parse_user_permissions("nobody@pve", "").is_err());
        assert!(parse_user_permissions("nobody@pve", "   \n").is_err());
    }

    #[test]
    fn handles_token_userid() {
        let out = r#"{"/":{"VM.Allocate":1}}"#;
        let p = parse_user_permissions("svc@pve!ci", out).expect("valid token JSON");
        assert_eq!(p.userid, "svc@pve!ci");
        assert_eq!(p.paths.len(), 1);
        assert_eq!(
            p.paths[0].privileges,
            vec![("VM.Allocate".to_string(), true)]
        );
    }

    #[test]
    fn invalid_propagate_flag_is_rejected() {
        let out = r#"{"/":{"VM.Audit":2}}"#;
        let err = parse_user_permissions("x@pve", out)
            .expect_err("propagate flag outside 0|1 must be rejected");
        assert!(err.to_string().contains("VM.Audit"));
    }

    #[test]
    fn wrong_json_shape_is_rejected() {
        assert!(parse_user_permissions("x@pve", "[]").is_err());
        assert!(parse_user_permissions("x@pve", r#"{"/":["VM.Audit"]}"#).is_err());
    }

    #[test]
    fn error_message_caps_stdout_preview_at_200_chars() {
        let long_stdout = format!("PREFIX_{}", "x".repeat(300));
        let err = parse_user_permissions("ghost@pve", &long_stdout)
            .expect_err("non-JSON stdout must fail");
        let msg = err.to_string();
        let expected_prefix: String = long_stdout.chars().take(200).collect();
        assert!(msg.contains(&expected_prefix));
        assert!(!msg.contains(&long_stdout));
    }

    #[test]
    fn paths_with_special_chars_preserved() {
        let out = r#"{"/storage/local-zfs":{"Datastore.AllocateSpace":1}}"#;
        let p = parse_user_permissions("a@pve", out).expect("valid JSON");
        assert_eq!(p.paths[0].path, "/storage/local-zfs");
        assert_eq!(
            p.paths[0].privileges,
            vec![("Datastore.AllocateSpace".to_string(), true)]
        );
    }
}
