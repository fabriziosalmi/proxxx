# Live cluster harness

Bash harnesses that exercise the `proxxx` release binary against a real
Proxmox VE cluster (and PBS instance). Separate from the cargo
integration tests in `tests/*.rs` — these talk to actual hardware.

## Files

| File | Tracked | Purpose |
|---|---|---|
| `test_run.sh` | yes | Read-only probes — `ls nodes/guests/storage`, `replication`, `access`, `iso`, `search`, `patch plan`, format contracts. |
| `test_mutation.sh` | yes | Full LXC lifecycle on VMID 9999: create → start → snapshot → stop → delete, with RAII `trap EXIT` teardown. |
| `test_env.md` | **gitignored** | Free-form notes (cluster topology, manual-only steps). |
| `env.local` | **gitignored** | Cluster URL + PVE token for `test_mutation.sh`. **Sourced by the script; copy from `env.local.example` and fill.** |
| `env.local.example` | yes | Template showing required env-var names. |
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

### First-time setup for `test_mutation.sh`

The mutation harness needs a PVE token to set up + tear down the
test LXC. Both the URL and the token come from `env.local`, which is
gitignored.

```sh
cp tests/live/env.local.example tests/live/env.local
$EDITOR tests/live/env.local         # paste your PVE URL + token
./tests/live/test_mutation.sh        # script sources env.local automatically
```

A missing or empty env var fails the script LOUDLY at the top:

```
./tests/live/test_mutation.sh: line 38: PROXXX_E2E_PVE_TOKEN: env PROXXX_E2E_PVE_TOKEN not set …
```

### Why `env.local` and not `test_env.md`

An earlier revision of `test_mutation.sh` had the PVE token inline.
That token leaked to public git history (rotated + revoked when
discovered, but the leaked value lives in the rebased history
forever). The `env.local` pattern is the structural fix — the
sourced file is gitignored AND the script's `:?` guards refuse to
run with an empty token, so a clean checkout can't accidentally
no-op against the wrong cluster either.

### Override knobs

| Env var | Default | When to set |
|---|---|---|
| `BIN` | `<repo>/target/release/proxxx` | Test a debug build or an installed binary. |
| `LOG_DIR` | this directory | Redirect `*.log` to a CI artifact dir. |
| `PROXXX_E2E_ENV_FILE` | `tests/live/env.local` | Read env from a different path (CI runners with a secrets store). |

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
