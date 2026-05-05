# Benchmark fixtures

Static input payloads loaded once before `criterion` starts the timer.
Generated deterministically (seed-free, just index-based) so the
benches are reproducible across runs.

The fixtures themselves are NOT committed if they're large — instead,
`benches/common/mod.rs` exposes generator functions that produce the
in-memory data on demand. This keeps the repo small and avoids
shipping multi-MB binary blobs.

## Coverage
- `guests_payload(n)` — synthetic JSON for `n` Proxmox guests,
  schema-faithful to `api::types::Guest`. Used by
  `benches/serde_parse.rs` to measure pure parser cost.
- `snapshot_chain(depth)` — flat snapshot list with a linear parent
  chain `depth` long. Used by `benches/snaptree_assemble.rs`.
- `haystack(n)` — `n` synthetic guest names with tag/node tokens.
  Used by `benches/fuzzy_search.rs`.
