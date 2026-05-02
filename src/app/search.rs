use crate::app::AppState;
use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher};

#[derive(Debug, Clone)]
pub enum SearchItem {
    Node {
        name: String,
        status: String,
    },
    Guest {
        vmid: u32,
        name: String,
        node: String,
        status: String,
        type_str: String,
    },
    Storage {
        pool: String,
        type_str: String,
    },
    Command {
        action: crate::app::Action,
        desc: String,
    },
}

impl SearchItem {
    #[must_use]
    pub fn search_text(&self) -> String {
        match self {
            Self::Node { name, .. } => format!("node {name}"),
            Self::Guest {
                vmid, name, node, ..
            } => format!("{vmid} {name} {node}"),
            Self::Storage { pool, .. } => format!("storage {pool}"),
            Self::Command { desc, .. } => format!("> {desc}"),
        }
    }
}

#[must_use]
pub fn build_index(state: &AppState) -> Vec<SearchItem> {
    let mut items = Vec::new();

    for node in &state.nodes {
        items.push(SearchItem::Node {
            name: node.node.clone(),
            status: format!("{:?}", node.status),
        });
    }

    for guest in &state.guests {
        items.push(SearchItem::Guest {
            vmid: guest.vmid,
            name: guest.name.clone(),
            node: guest.node.clone(),
            status: format!("{:?}", guest.status),
            type_str: format!("{:?}", guest.guest_type),
        });
    }

    for storage in &state.storage {
        items.push(SearchItem::Storage {
            pool: storage.storage.clone(),
            type_str: storage.storage_type.clone(),
        });
    }

    // Views
    items.push(SearchItem::Command {
        action: crate::app::Action::SwitchView(crate::app::View::Dashboard),
        desc: "View: Dashboard".to_string(),
    });
    items.push(SearchItem::Command {
        action: crate::app::Action::SwitchView(crate::app::View::NodeList),
        desc: "View: Nodes".to_string(),
    });
    items.push(SearchItem::Command {
        action: crate::app::Action::SwitchView(crate::app::View::GuestList),
        desc: "View: Guests".to_string(),
    });
    items.push(SearchItem::Command {
        action: crate::app::Action::SwitchView(crate::app::View::StorageList),
        desc: "View: Storage".to_string(),
    });
    items.push(SearchItem::Command {
        action: crate::app::Action::SwitchView(crate::app::View::Heatmap),
        desc: "View: Hotspot Heatmap".to_string(),
    });
    items.push(SearchItem::Command {
        action: crate::app::Action::SwitchView(crate::app::View::BackupBoard),
        desc: "View: Backup Health Board".to_string(),
    });
    items.push(SearchItem::Command {
        action: crate::app::Action::EnterTimeline,
        desc: "View: Audit Timeline".to_string(),
    });
    items.push(SearchItem::Command {
        action: crate::app::Action::SwitchView(crate::app::View::OperationQueue),
        desc: "View: Operation Queue".to_string(),
    });
    items.push(SearchItem::Command {
        action: crate::app::Action::SwitchView(crate::app::View::ApprovalQueue),
        desc: "View: Approval Queue".to_string(),
    });

    // Guest operations
    for guest in &state.guests {
        items.push(SearchItem::Command {
            action: crate::app::Action::StartGuest { vmid: guest.vmid },
            desc: format!("Start VM/CT {} ({})", guest.vmid, guest.name),
        });
        items.push(SearchItem::Command {
            action: crate::app::Action::StopGuest {
                vmid: guest.vmid,
                force: false,
            },
            desc: format!("Stop VM/CT {} ({})", guest.vmid, guest.name),
        });
        items.push(SearchItem::Command {
            action: crate::app::Action::RestartGuest { vmid: guest.vmid },
            desc: format!("Restart VM/CT {} ({})", guest.vmid, guest.name),
        });
        items.push(SearchItem::Command {
            action: crate::app::Action::DeleteGuest { vmid: guest.vmid },
            desc: format!("Delete VM/CT {} ({})", guest.vmid, guest.name),
        });
    }

    // Node operations
    for node in &state.nodes {
        items.push(SearchItem::Command {
            action: crate::app::Action::EvacuateNode {
                node: node.node.clone(),
            },
            desc: format!("Evacuate Node {}", node.node),
        });
    }

    items
}

#[must_use]
pub fn get_search_results(state: &AppState) -> Vec<(u32, SearchItem)> {
    let all_items = build_index(state);
    let mut results: Vec<(u32, SearchItem)> = Vec::new();
    let query = &state.search_query;

    if query.is_empty() {
        for item in all_items {
            results.push((0, item));
        }
    } else {
        let mut matcher = Matcher::new(Config::DEFAULT);
        let pattern = Pattern::parse(query, CaseMatching::Ignore, Normalization::Smart);
        let mut buf = Vec::new();
        for item in all_items {
            let haystack_str = item.search_text();
            let haystack = nucleo_matcher::Utf32Str::new(&haystack_str, &mut buf);
            if let Some(score) = pattern.score(haystack, &mut matcher) {
                results.push((score, item));
            }
        }
        results.sort_by(|a, b| b.0.cmp(&a.0)); // descending
    }
    results
}
