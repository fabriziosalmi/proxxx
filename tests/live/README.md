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

## The LAN e2e box, and why the live tier is not on GitHub

`cargo test --all-targets` skips every `#[ignore]`d test and never invokes
the harnesses in this directory, so the highest-consequence behaviour in
the project — real guest mutations, RBAC across three token identities,
PBS backup and restore, the Severe delete gate actually refusing — has no
automated gate. A regression in any of it merges green.

The obvious fix is a GitHub Actions job on a self-hosted runner. We
deliberately do not do that:

- proxxx is a **public** repo. A self-hosted runner attached to it can be
  named by a fork's own workflow file (`runs-on: [self-hosted, <label>]`),
  so the fork-PR approval policy becomes the only thing standing between
  an outside contributor and code execution on the runner.
- The live tier needs **real cluster credentials**. Putting them in
  repository secrets means a live PVE token lives on GitHub, and any job
  that runs on the runner can read it.
- Bridging a hosted runner to the cluster (VPN, tunnel, port-forward) is
  worse still: it hands an inbound path to the LAN.

So the live tier runs on a LAN-only box that is **not** a GitHub runner,
and the credentials never leave the LAN:

```sh
# read-only suites against the current HEAD
tests/live/remote_run.sh

# a specific ref
tests/live/remote_run.sh v0.14.0

# the mutating suites (creates and destroys real guests)
tests/live/remote_run.sh --mutations
```

The box is an unprivileged LXC on the local hypervisor; `remote_run.sh`
reaches it over the LAN via `pct exec`, with no inbound tunnel and
nothing exposed to the internet. Override `PROXXX_LIVE_HYPERVISOR` and
`PROXXX_LIVE_CTID` to point it elsewhere.

Each run writes `tests/live/records/live-tier-<sha>.md` — ref, host,
timestamps, whether the mutating suites ran, and the per-suite
`test result:` lines. Committing that record is what keeps "the live tier
passed for this commit" from resting on memory. The records carry no
credentials.

Credentials on the box live in a root-owned `0640` env file readable by
the build user only; it is a copy of your `env.local` and is never
committed, uploaded, or sent to GitHub.
