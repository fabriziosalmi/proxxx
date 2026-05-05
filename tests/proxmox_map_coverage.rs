#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::missing_errors_doc,
    clippy::too_many_lines
)]
//! Phase 4 — Proxmox API surface coverage gate.
//!
//! Reads `tests/fixtures/proxmox_map.json` (the curated catalogue of every
//! PVE REST endpoint we care about) and `src/api/client.rs` (proxxx's
//! actual API surface), then computes:
//!
//! - **Covered**: endpoints in the map that proxxx calls.
//! - **Uncovered**: endpoints in the map that proxxx does NOT call —
//!   either out-of-scope (Ceph, SDN, ACME, `OpenID` …) or genuine gaps.
//! - **Undocumented**: paths in `client.rs` that don't appear in the
//!   map. This catches drift in the OPPOSITE direction: proxxx wired
//!   to an endpoint we forgot to register, or PVE renamed a path and
//!   the map is stale.
//!
//! The output is a deterministic text report compared against a
//! checked-in snapshot via `insta::assert_snapshot!`. The gate fails
//! when the report changes — which means either:
//!
//! 1. proxxx grew a new API call → review + accept the new line.
//! 2. proxxx LOST coverage (regression) → investigate why.
//! 3. The map was updated (PVE upgrade) → accept the new uncovered
//!    entries, OR wire them up.
//!
//! Accept changes via `cargo insta review` after sanity-checking the
//! diff.
//!
//! ## Why static analysis vs live cluster polling
//!
//! The map analyzer runs in `cargo test` — no cluster, no network. It
//! catches coverage drift at commit time, not at deploy time. The
//! tradeoff: it can't tell you whether your code's path string actually
//! works against PVE (that's what the live mutation suite is for).
//! Static + live form a bracket: this test guards "did we wire it",
//! the live tests guard "does the wire actually carry traffic".
//!
//! ## Path normalization
//!
//! Both sides are reduced to a "skeleton" form — every `{anything}`
//! placeholder collapses to `*`. So `/nodes/{node}/qemu/{vmid}/start`
//! and `/nodes/{}/qemu/{}/start` (positional Rust placeholder) match
//! identically. The `{kind}` placeholder used by proxxx's QEMU/LXC
//! dispatch is expanded into both flavours so it matches both map
//! entries.

use std::collections::{BTreeMap, BTreeSet};

const MAP_JSON: &str = include_str!("fixtures/proxmox_map.json");
const CLIENT_RS: &str = include_str!("../src/api/client.rs");

/// One leaf endpoint from the map.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct MapEntry {
    /// Dotted path through the JSON tree, e.g.
    /// `cluster.ha.resources` — used as the human-readable name.
    name: String,
    /// HTTP method(s), e.g. `GET|POST|PUT|DELETE`.
    methods: String,
    /// Path with PVE-style placeholders (`{node}`, `{vmid}`).
    path: String,
}

impl MapEntry {
    fn skeleton(&self) -> String {
        skeleton_of(&self.path)
    }
}

/// Walk the nested JSON structure, emitting one `MapEntry` per leaf.
/// A leaf is an object with both `method` and `path` string fields.
fn parse_map_entries() -> Vec<MapEntry> {
    let json: serde_json::Value =
        serde_json::from_str(MAP_JSON).expect("proxmox_map.json is valid JSON");
    let mut out = Vec::new();
    walk_map(&json, String::new(), &mut out);
    out.sort();
    out
}

fn walk_map(v: &serde_json::Value, dotted: String, out: &mut Vec<MapEntry>) {
    let Some(obj) = v.as_object() else {
        return;
    };
    // Leaf check: object containing both a `method` string AND a `path`
    // string. Some intermediate nodes have `desc` but not both.
    let m = obj.get("method").and_then(|x| x.as_str());
    let p = obj.get("path").and_then(|x| x.as_str());
    if let (Some(method), Some(path)) = (m, p) {
        out.push(MapEntry {
            name: dotted,
            methods: method.to_string(),
            path: path.to_string(),
        });
        return;
    }
    for (key, child) in obj {
        let next = if dotted.is_empty() {
            key.clone()
        } else {
            format!("{dotted}.{key}")
        };
        walk_map(child, next, out);
    }
}

/// Reduce a path template to its structural skeleton: every `{…}` →
/// `*`. Used for cross-form matching between map (named placeholders)
/// and client (positional `{}` or named).
fn skeleton_of(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    let mut depth = 0;
    for c in p.chars() {
        match c {
            '{' => {
                if depth == 0 {
                    out.push('*');
                }
                depth += 1;
            }
            '}' if depth > 0 => {
                depth -= 1;
            }
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    // Strip optional leading `/api2/json` (proxxx adds it; map omits).
    out.trim_start_matches("/api2/json").to_string()
}

/// One path the client touches. The skeleton + raw form so reports can
/// show both.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
struct ClientPath {
    raw: String,
    skeleton: String,
}

/// Variable names proxxx uses for the QEMU/LXC dispatch — they all
/// carry the runtime value `"qemu"` or `"lxc"` and represent BOTH
/// endpoints from the map's perspective.
const KIND_PLACEHOLDERS: &[&str] = &["{kind}", "{type_str}"];

/// Extract every API path string the client constructs. Heuristic:
/// scan source for string literals starting with `/nodes`, `/cluster`,
/// `/access`, `/storage`, `/pools`, `/version`. Also handles
/// `/api2/json/...` prefixed forms (used by the multipart upload site
/// and the disk-resize site).
fn parse_client_paths() -> Vec<ClientPath> {
    let mut paths = BTreeSet::new();
    for s in extract_string_literals(CLIENT_RS) {
        if !is_pve_path(&s) {
            continue;
        }
        // QEMU/LXC dispatch: expand `{kind}` / `{type_str}` into both
        // `qemu` and `lxc` so each variant matches its map entry
        // independently.
        let kind_present = KIND_PLACEHOLDERS.iter().any(|k| s.contains(k));
        if kind_present {
            for kind in ["qemu", "lxc"] {
                let mut expanded = s.clone();
                for placeholder in KIND_PLACEHOLDERS {
                    expanded = expanded.replace(placeholder, kind);
                }
                let skel = skeleton_of(&expanded);
                paths.insert(ClientPath {
                    raw: expanded,
                    skeleton: skel,
                });
            }
        } else {
            let skel = skeleton_of(&s);
            paths.insert(ClientPath {
                raw: s,
                skeleton: skel,
            });
        }
    }
    // Strip query strings — `/agent/exec-status?pid=...` becomes
    // `/agent/exec-status`, matching the map.
    paths
        .into_iter()
        .map(|mut p| {
            if let Some(q) = p.skeleton.find('?') {
                p.skeleton.truncate(q);
            }
            if let Some(q) = p.raw.find('?') {
                p.raw.truncate(q);
            }
            p
        })
        .collect()
}

/// True for path templates that are likely PVE API endpoints (not
/// docstrings, error messages, or filesystem paths).
fn is_pve_path(s: &str) -> bool {
    // Strip /api2/json prefix when checking the first segment.
    let p = s.trim_start_matches("/api2/json");
    matches!(
        p.split('/').nth(1),
        Some("nodes" | "cluster" | "access" | "storage" | "pools" | "version")
    )
}

/// Extract every `"…"` string literal from Rust source. Handles
/// escaped quotes via `\"` and skips `//` line comments. Doesn't
/// distinguish raw strings (treats `r"foo"` as `foo` plus the `r`
/// outside, which is fine for our purpose — we only look at content).
fn extract_string_literals(src: &str) -> Vec<String> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let b = bytes[i];
        // Line comment.
        if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Block comment.
        if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = i.saturating_add(2);
            continue;
        }
        if b == b'"' {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() {
                if bytes[j] == b'\\' {
                    j += 2;
                    continue;
                }
                if bytes[j] == b'"' {
                    break;
                }
                j += 1;
            }
            if j <= bytes.len() && j >= start {
                if let Ok(s) = std::str::from_utf8(&bytes[start..j]) {
                    out.push(s.to_string());
                }
            }
            i = j + 1;
            continue;
        }
        i += 1;
    }
    out
}

/// PVE REST convention: a map entry like
/// `/access/groups [GET|POST|PUT|DELETE]` actually denotes a *family*
/// of routes — the collection at `/access/groups` AND the per-item
/// singleton at `/access/groups/{groupid}`. The collection serves
/// `GET` (list) and `POST` (create); the singleton serves
/// `PUT`/`DELETE`. proxxx splits these into separate path strings
/// (`get("/access/groups")` vs `delete("/access/groups/{}")`), so the
/// matcher must canonicalize both directions:
///
/// - Map ends without `*` and has PUT/DELETE → also accept `…/*`
///   (singleton form).
/// - Map ends with `*` and has GET or POST → also accept the parent
///   path (collection form).
///
/// This collapses the map's "one entry, many verbs" shorthand into the
/// concrete path skeletons proxxx actually emits.
fn map_skeletons_with_singleton_expansion(map: &[MapEntry]) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for e in map {
        let skel = e.skeleton();
        out.insert(skel.clone());
        let has_mutation = e.methods.contains("PUT") || e.methods.contains("DELETE");
        let has_collection_verb = e.methods.contains("GET") || e.methods.contains("POST");
        let ends_with_id = skel.ends_with('*');
        if has_mutation && !ends_with_id {
            out.insert(format!("{skel}/*"));
        }
        if has_collection_verb && ends_with_id {
            // Strip the trailing `/*` to get the parent collection.
            if let Some(parent) = skel.strip_suffix("/*") {
                out.insert(parent.to_string());
            }
        }
    }
    out
}

/// Compute coverage relative to map entries (one entry may have
/// multiple methods listed; we count it as one endpoint).
fn build_report() -> String {
    let map = parse_map_entries();
    let client = parse_client_paths();

    let client_skeletons: BTreeSet<&str> = client.iter().map(|c| c.skeleton.as_str()).collect();
    let expanded_map_skels = map_skeletons_with_singleton_expansion(&map);

    let mut covered = Vec::new();
    let mut uncovered = Vec::new();
    for entry in &map {
        let skel = entry.skeleton();
        // An entry is covered if any of: (a) the exact skeleton appears
        // in client paths, (b) the implicit singleton form does, or
        // (c) the implicit collection (parent) form does.
        let singleton = format!("{skel}/*");
        let collection = skel.strip_suffix("/*").map(str::to_string);
        let hit = client_skeletons.contains(skel.as_str())
            || client_skeletons.contains(singleton.as_str())
            || collection
                .as_deref()
                .is_some_and(|c| client_skeletons.contains(c));
        if hit {
            covered.push(entry);
        } else {
            uncovered.push(entry);
        }
    }

    let mut undocumented: Vec<&ClientPath> = client
        .iter()
        .filter(|c| !expanded_map_skels.contains(&c.skeleton))
        .collect();
    undocumented.sort();

    // Group uncovered by top-level category for readability.
    let mut by_category: BTreeMap<&str, Vec<&MapEntry>> = BTreeMap::new();
    for e in &uncovered {
        let cat = e.name.split('.').next().unwrap_or("misc");
        by_category.entry(cat).or_default().push(e);
    }

    let pct = if map.is_empty() {
        0
    } else {
        100 * covered.len() / map.len()
    };

    let mut out = String::new();
    out.push_str("# proxxx API surface coverage\n\n");
    out.push_str(&format!("Map endpoints      : {}\n", map.len()));
    out.push_str(&format!(
        "Covered            : {} ({pct}%)\n",
        covered.len()
    ));
    out.push_str(&format!("Uncovered          : {}\n", uncovered.len()));
    out.push_str(&format!("Undocumented (drift): {}\n\n", undocumented.len()));

    out.push_str("## Covered endpoints\n\n");
    for c in &covered {
        out.push_str(&format!("- {} `{}` [{}]\n", c.name, c.path, c.methods));
    }

    out.push_str("\n## Uncovered endpoints (by category)\n\n");
    for (cat, entries) in &by_category {
        out.push_str(&format!("### {cat}\n\n"));
        for e in entries {
            out.push_str(&format!("- {} `{}` [{}]\n", e.name, e.path, e.methods));
        }
        out.push('\n');
    }

    out.push_str("## Undocumented client paths (in code, not in map)\n\n");
    if undocumented.is_empty() {
        out.push_str("(none — every client path matches a map entry)\n");
    } else {
        for u in &undocumented {
            out.push_str(&format!("- `{}`\n", u.skeleton));
        }
    }

    out
}

#[test]
fn proxmox_map_coverage_snapshot() {
    let report = build_report();
    insta::assert_snapshot!(report);
}

// ── Self-tests for the analyzer machinery ─────────────────────────────

#[test]
fn skeleton_collapses_named_and_positional_placeholders() {
    assert_eq!(
        skeleton_of("/nodes/{node}/qemu/{vmid}/status/start"),
        "/nodes/*/qemu/*/status/start"
    );
    assert_eq!(
        skeleton_of("/access/users/{}/token/{}"),
        "/access/users/*/token/*"
    );
    // Mixed.
    assert_eq!(
        skeleton_of("/nodes/{node}/qemu/{}/config"),
        "/nodes/*/qemu/*/config"
    );
}

#[test]
fn skeleton_strips_api2_json_prefix() {
    assert_eq!(
        skeleton_of("/api2/json/cluster/resources"),
        "/cluster/resources"
    );
}

#[test]
fn map_parser_finds_known_endpoints() {
    let map = parse_map_entries();
    // Spot checks — these are stable PVE endpoints in the curated map.
    let paths: BTreeSet<_> = map.iter().map(|e| e.path.as_str()).collect();
    assert!(
        paths.contains("/cluster/resources"),
        "cluster.resources missing"
    );
    assert!(
        paths.contains("/nodes/{node}/qemu/{vmid}/status/start"),
        "qemu start missing"
    );
    assert!(paths.contains("/access/acl"), "access.acl missing");
}

#[test]
fn client_parser_finds_known_paths() {
    let client = parse_client_paths();
    let skels: BTreeSet<&str> = client.iter().map(|c| c.skeleton.as_str()).collect();
    assert!(
        skels.contains("/nodes/*/qemu/*/status/start"),
        "qemu start dispatch missing — got {skels:?}"
    );
    assert!(skels.contains("/access/acl"), "access acl missing");
}

#[test]
fn extractor_skips_line_comments() {
    let src = r#"
        // "/this/is/a/comment/with/quotes/inside"
        let real = "/cluster/resources";
    "#;
    let lits = extract_string_literals(src);
    assert!(lits.iter().any(|s| s == "/cluster/resources"));
    assert!(
        !lits
            .iter()
            .any(|s| s == "/this/is/a/comment/with/quotes/inside"),
        "line comments must be stripped"
    );
}

#[test]
fn is_pve_path_filters_non_api_strings() {
    assert!(is_pve_path("/nodes/foo"));
    assert!(is_pve_path("/cluster/resources"));
    assert!(is_pve_path("/api2/json/cluster/status"));
    assert!(!is_pve_path("/tmp/file.txt"));
    assert!(!is_pve_path("hello world"));
    assert!(!is_pve_path("/etc/passwd"));
}
