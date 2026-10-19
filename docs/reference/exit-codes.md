# Exit codes

Stable contract within a major version. Use these in CI / scripts
instead of grepping stderr.

| Exit | Meaning | When |
| :--- | :--- | :--- |
| `0` | Success | Operation completed |
| `1` | Generic failure | Catch-all; check stderr for the message |
| `2` | Usage error / diff present | clap rejected the arguments **OR** a read-only check found drift (`state diff`, `reconcile run`) **OR** a mutation had a failed change (`state apply`, `reconcile converge`) |
| `3` | Configuration error | TOML invalid, required field missing, profile not found, no default profile, invalid enum-like setting, `proxxx pbs` without a `[pbs]` / `[profiles.<name>.pbs]` section, or `state apply` / `reconcile converge` when `[meta] profile` mismatches the resolved target profile without `--allow-profile-mismatch` |
| `4` | Authentication / authorization | `Unauthorized` (401) or `Forbidden` (403) — see [errors](/reference/errors) |
| `5` | Resource not found | `NotFound` (404) — guest, node, snapshot, etc., a VMID absent from `GET /cluster/resources?type=vm`, or `proxxx find <vmid>` when no profile owns the VMID. A guest listed in `/cluster/resources?type=vm` whose hosting node is offline or unreachable does **not** exit `5` (exits `1`, or `7` on transient `RateLimited` / `StorageHang`), so teardown scripts never treat an unreachable node as "already gone". |
| `6` | Pre-flight risk refused | A `SEVERE` risk surfaced and `--allow-risk` was not passed. Fires from per-guest pre-flight (running guest, etc.) and state-apply / `reconcile converge` pre-flight (non-empty pool delete, root-role ACL delete, shared-storage delete, batch ≥ 50). The unmanned daemon `auto_converge` always runs as if `--allow-risk` were absent, so a Severe drift is left for a human (no exit code — it alerts + skips). |
| `7` | Cluster transient | `RateLimited` / `StorageHang` / persistent retries exhausted |
| `8` | Mutation refused by a local lock | A mutation was refused by a proxxx-side lock before reaching PVE. Either `proxxx incident freeze` is in effect (run `proxxx incident thaw` first, or wait for the TTL), or the active profile is configured `read_only = true` (point at a writable profile, or remove the flag from `config.toml`). |

## Handling in shell

```bash
if proxxx delete 100 --yes; then
    echo "deleted"
else
    case $? in
        4) echo "auth — refresh the token" ;;
        5) echo "already gone — idempotent OK" ;;
        6) echo "pre-flight refused — re-run with --allow-risk if intentional" ;;
        7) echo "cluster busy — retry later" ;;
        *) echo "other failure" ;;
    esac
fi
```

## Handling in CI

GitHub Actions workflow, treating `5` as success on teardown:

```yaml
- name: Teardown test guest
  continue-on-error: false
  run: |
    set +e
    proxxx delete "${{ env.TEST_VMID }}" --yes
    rc=$?
    set -e
    if [ "$rc" -ne 0 ] && [ "$rc" -ne 5 ]; then
        exit "$rc"
    fi
```

## How exit codes are mapped from `ApiError`

```
ApiError::Unauthorized    → 4
ApiError::Forbidden       → 4
ApiError::NotFound        → 5
ApiError::RateLimited     → 7
ApiError::StorageHang     → 7
ApiError::PayloadTooLarge → 1
ApiError::Transport       → 1   (network — generic; retry strategy belongs to caller)
ApiError::Parse           → 1   (PVE returned non-JSON or unknown shape)
ApiError::Other           → 1   (uncategorised HTTP status)
```

The wiring lives in `main.rs` — the CLI error path walks the anyhow
chain via `Error::chain().find_map(downcast_ref::<ApiError>)` and
calls `ApiError::exit_code()`. Non-API anyhow errors (or `ApiError`
variants not in the table) fall through to `1`.

Guest lookups (`cli::common::find_guest` and `find_guest_full`) treat
`GET /cluster/resources?type=vm` (backed by `pmxcfs` `/etc/pve/.vmlist`)
as the authoritative cluster inventory. A VMID is surfaced as
`ApiError::NotFound` (`guest <vmid> not found in cluster`, exit `5`)
only when it is absent from `/cluster/resources?type=vm`. When a guest
is listed in `/cluster/resources` (even with status `"unknown"` while
its node is offline) and the per-node status query fails, the error
names the node and its cluster status and preserves the underlying
error chain (`1`, or `7` when the node returned `RateLimited` or
`StorageHang`), never `5`. When `/cluster/resources` itself is
unavailable and a per-node walk is used as fallback, any node query
error aborts the lookup with a summary of node failures rather than
reporting the guest as missing.

Pre-flight refusal is surfaced as a typed `app::preflight::PreflightRefusal`
error carried via anyhow; the same chain walker maps it to `6`.

Configuration errors are typed via `config::ConfigError` with nine
variants: `NotFound` (no `config.toml`), `Io` (read failure once the
file exists), `Toml` (invalid TOML syntax), `UnknownProfile` (requested
`--profile` not in `[profiles]`),
`NoDefaultProfile` (multi-profile config without `default` or
`--profile`), `ProfileParse` (missing required field or invalid type in
a profile block), `InvalidValue` (unsupported enum-like setting in
`validate_enum_like_fields`), `MissingPbsConfig` (`proxxx pbs`
invoked when the active profile has no `[pbs]` /
`[profiles.<name>.pbs]` block), and `ProfileMismatch` (`state apply` or
`reconcile converge` invoked with a state file whose `[meta] profile`
differs from the resolved target profile without
`--allow-profile-mismatch`). All nine map to exit `3` per the
`Configuration error` slot above. Splitting individual variants to
distinct codes later is an additive (minor) bump as long as `3` stays
in the set.

## Stability

- Adding a new exit code is a minor bump (additive).
- Repurposing an existing code is a major bump.
- Behavioural changes within an existing code (e.g. moving timeout
  from `7` to `1`) are a major bump.

This contract is what scripts depend on. Don't break it without a
SemVer signal.
