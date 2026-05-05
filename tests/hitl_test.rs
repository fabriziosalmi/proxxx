#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
// Unit tests for the HITL policy engine

#[cfg(test)]
mod tests {
    use proxxx::hitl::policy::*;

    fn test_policies() -> Vec<Policy> {
        vec![
            Policy {
                action: "delete".into(),
                target: "*".into(),
                channel: "telegram".into(),
                require: 1,
            },
            Policy {
                action: "stop".into(),
                target: "tag:prod".into(),
                channel: "telegram".into(),
                require: 1,
            },
            Policy {
                action: "migrate".into(),
                target: "*".into(),
                channel: "all".into(),
                require: 1,
            },
        ]
    }

    #[test]
    fn test_delete_matches_any_target() {
        let policies = test_policies();
        let result = check_policies(&policies, "delete", "100", &[]);
        assert!(result.is_some());
        assert_eq!(result.map(|p| p.action.as_str()), Some("delete"));
    }

    #[test]
    fn test_stop_requires_prod_tag() {
        let policies = test_policies();

        // Without prod tag — no match (delete would match first for *, but stop specifically needs tag:prod)
        let result = check_policies(&policies, "stop", "100", &["dev"]);
        assert!(result.is_none());

        // With prod tag — matches
        let result = check_policies(&policies, "stop", "100", &["prod", "web"]);
        assert!(result.is_some());
        assert_eq!(result.map(|p| p.action.as_str()), Some("stop"));
    }

    #[test]
    fn test_migrate_matches_all() {
        let policies = test_policies();
        let result = check_policies(&policies, "migrate", "200", &[]);
        assert!(result.is_some());
        assert_eq!(result.map(|p| p.channel.as_str()), Some("all"));
    }

    #[test]
    fn test_start_has_no_policy() {
        let policies = test_policies();
        let result = check_policies(&policies, "start", "100", &["prod"]);
        assert!(result.is_none()); // start is not gated
    }

    #[test]
    fn test_wildcard_action_matches_everything() {
        let policies = vec![Policy {
            action: "*".into(),
            target: "tag:critical".into(),
            channel: "teams".into(),
            require: 2,
        }];

        let result = check_policies(&policies, "restart", "999", &["critical"]);
        assert!(result.is_some());
        assert_eq!(result.map(|p| p.require), Some(2));
    }

    #[test]
    fn test_specific_vmid_target() {
        let policies = vec![Policy {
            action: "stop".into(),
            target: "100".into(),
            channel: "telegram".into(),
            require: 1,
        }];

        // VM 100 — matches
        let result = check_policies(&policies, "stop", "100", &[]);
        assert!(result.is_some());

        // VM 200 — no match
        let result = check_policies(&policies, "stop", "200", &[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_first_matching_policy_wins() {
        let policies = vec![
            Policy {
                action: "stop".into(),
                target: "100".into(),
                channel: "telegram".into(),
                require: 1,
            },
            Policy {
                action: "stop".into(),
                target: "*".into(),
                channel: "teams".into(),
                require: 2,
            },
        ];

        // VM 100 should match the first (telegram, require=1), not the second
        let result = check_policies(&policies, "stop", "100", &[]);
        assert!(result.is_some());
        assert_eq!(result.map(|p| p.channel.as_str()), Some("telegram"));
        assert_eq!(result.map(|p| p.require), Some(1));
    }

    #[test]
    fn test_empty_policies_always_skips() {
        let policies: Vec<Policy> = vec![];
        let result = check_policies(&policies, "delete", "100", &["prod"]);
        assert!(result.is_none());
    }
}
