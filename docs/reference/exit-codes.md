# Exit codes

Stable contract within a major version. Use these in CI / scripts
instead of grepping stderr.

| Exit | Meaning | When |
| :--- | :--- | :--- |
| `0` | Success | Operation completed |
| `1` | Generic failure | Catch-all; check stderr for the message |
| `2` | Usage error | clap rejected the arguments |
| `3` | Configuration error | TOML invalid, required field missing, profile not found |
| `4` | Authentication / authorization | `Unauthorized` (401) or `Forbidden` (403) — see [errors](/reference/errors) |
| `5` | Resource not found | `NotFound` (404) — guest, node, snapshot, etc. |
| `6` | Pre-flight risk refused | A `SEVERE` risk surfaced and `--allow-risk` was not passed |
| `7` | Cluster transient | `RateLimited` / `StorageHang` / persistent retries exhausted |

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
ApiError::Unauthorized  → 4
ApiError::Forbidden     → 4
ApiError::NotFound      → 5
ApiError::RateLimited   → 7
ApiError::StorageHang   → 7
ApiError::PayloadTooLarge → 1
ApiError::Transport     → 1   (network — generic; retry strategy belongs to caller)
ApiError::Schema        → 1   (PVE returned non-JSON or unknown shape)
```

Pre-flight refusal and configuration errors are caught before the API
layer, so they map directly to `6` and `3` respectively.

## Stability

- Adding a new exit code is a minor bump (additive).
- Repurposing an existing code is a major bump.
- Behavioural changes within an existing code (e.g. moving timeout
  from `7` to `1`) are a major bump.

This contract is what scripts depend on. Don't break it without a
SemVer signal.
