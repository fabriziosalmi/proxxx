# Live cluster harness

Bash harnesses that exercise the `proxxx` release binary against a real
Proxmox VE cluster (and PBS instance). Separate from the cargo
integration tests in `tests/*.rs` — these talk to actual hardware.

## Files

| File | Tracked | Purpose |
|---|---|---|
| `test_run.sh` | yes | Read-only probes — `ls nodes/guests/storage`, `replication`, `access`, `iso`, `search`, `patch plan`, format contracts. |
| `test_mutation.sh` | yes | Full LXC lifecycle on VMID 9999: create → start → snapshot → stop → delete, with RAII `trap EXIT` teardown. |
| `test_env.md` | **gitignored** | Cluster URL, token id, token secret. **Local-only — never commit.** |
| `*.log`, `*_errors.log`, `*_summary.md` | gitignored | Run artifacts; regenerated each invocation. |

## Running

The scripts are location-independent — they resolve the repo root via
`git rev-parse` and find the release binary at `target/release/proxxx`.
Run from any cwd:

```sh
# from repo root
./tests/live/test_run.sh

# or from anywhere — same result
cd /tmp && ~/Documents/git/proxxx/tests/live/test_run.sh
```

### Override knobs

| Env var | Default | When to set |
|---|---|---|
| `BIN` | `<repo>/target/release/proxxx` | Test a debug build or an installed binary. |
| `LOG_DIR` | this directory | Redirect `*.log` to a CI artifact dir. |

Example:

```sh
LOG_DIR=/tmp/proxxx-ci BIN=./target/debug/proxxx ./tests/live/test_run.sh
```

## Cluster prerequisites

- Token must be reachable from the host running the harness (no firewall
  in the way).
- For `test_mutation.sh`, the token needs `VM.Allocate` +
  `Datastore.AllocateSpace` (or simply `Administrator` at `/`):
  ```sh
  ssh root@<node> 'pveum acl modify / --tokens "root@pam!proxxx" --roles Administrator'
  ```
- proxxx must be configured to point at the cluster. On macOS, the
  config lives at:
  ```
  ~/Library/Application Support/dev.proxxx.proxxx/config.toml
  ```

## Exit codes

- `test_run.sh` exits with the failure count (0 = all green).
- `test_mutation.sh` exits 0 on a clean lifecycle, 1 on early-stage
  abort. The `trap EXIT` cleanup runs regardless — VMID 9999 is never
  leaked even if a step panics.
