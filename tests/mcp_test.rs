#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
// Unit tests for the MCP deterministic tool registry
// Verifies compile-time const properties and checksum stability.

#[cfg(test)]
mod tests {
    use proxxx::mcp::tools::*;

    #[test]
    fn test_registry_has_expected_tool_count() {
        // If someone adds a tool, this test forces them to update the count
        assert_eq!(
            TOOLS.len(),
            10,
            "Tool count changed! Update this test if intentional."
        );
    }

    #[test]
    fn test_all_tools_have_names() {
        for tool in TOOLS {
            assert!(!tool.name.is_empty(), "Tool has empty name");
            assert!(
                !tool.description.is_empty(),
                "Tool {} has empty description",
                tool.name
            );
        }
    }

    #[test]
    fn test_destructive_tools_are_flagged() {
        let destructive_names: Vec<&str> = TOOLS
            .iter()
            .filter(|t| t.destructive)
            .map(|t| t.name)
            .collect();

        // These MUST be destructive — if any is missing, HITL gate is bypassed
        assert!(
            destructive_names.contains(&"stop_guest"),
            "stop_guest must be destructive"
        );
        assert!(
            destructive_names.contains(&"delete_guest"),
            "delete_guest must be destructive"
        );
        assert!(
            destructive_names.contains(&"restart_guest"),
            "restart_guest must be destructive"
        );
        assert!(
            destructive_names.contains(&"delete_snapshot"),
            "delete_snapshot must be destructive"
        );
    }

    #[test]
    fn test_read_only_tools_are_not_destructive() {
        let safe_names = [
            "list_nodes",
            "list_guests",
            "get_guest_status",
            "get_storage_pools",
        ];
        for name in &safe_names {
            let tool = TOOLS.iter().find(|t| t.name == *name);
            assert!(tool.is_some(), "Tool {name} not found");
            assert!(
                !tool.is_none_or(|t| t.destructive),
                "Read-only tool {name} should NOT be destructive"
            );
        }
    }

    #[test]
    fn test_no_duplicate_tool_names() {
        let mut names: Vec<&str> = TOOLS.iter().map(|t| t.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), TOOLS.len(), "Duplicate tool names detected!");
    }

    #[test]
    fn test_required_params_on_destructive_tools() {
        // All destructive tools MUST require at least one parameter (the target)
        for tool in TOOLS.iter().filter(|t| t.destructive) {
            let has_required = tool.params.iter().any(|p| p.required);
            assert!(
                has_required,
                "Destructive tool {} has no required params — dangerous!",
                tool.name
            );
        }
    }

    #[test]
    fn test_registry_json_is_valid() {
        let json = registry_json();
        assert!(json.get("tools").is_some());
        let tools = json["tools"].as_array();
        assert!(tools.is_some());
        assert_eq!(tools.map_or(0, std::vec::Vec::len), TOOLS.len());
    }

    #[test]
    fn test_checksum_is_deterministic() {
        let hash1 = registry_checksum();
        let hash2 = registry_checksum();
        assert_eq!(hash1, hash2, "Checksum must be deterministic across calls");
        assert!(!hash1.is_empty());
        assert_eq!(hash1.len(), 16, "Checksum should be 16 hex chars");
    }

    #[test]
    fn test_tool_actions_are_unique() {
        let mut actions: Vec<String> = TOOLS.iter().map(|t| format!("{:?}", t.action)).collect();
        actions.sort();
        let len_before = actions.len();
        actions.dedup();
        assert_eq!(actions.len(), len_before, "Duplicate ToolActions found!");
    }
}
