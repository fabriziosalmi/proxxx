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
| `battery.sh` | yes | Pre-tag battery: every suite below in order, one summary line each, with an inventory before and after. **Mutating.** See [Pre-tag battery](#pre-tag-battery). |
| `inventory.sh` | yes | Read-only snapshot of 17 configuration endpoints (GET only), normalized so an unchanged cluster compares equal. |
| `lib.sh` | yes | Sourced by the scripts: loads the env file, accepts the token with or without `root@pam!`, gives the binary a private config built from the same URL and token as the curl calls (plus its own audit, log and cache directories), and provides `run_timeout` for macOS. |
| `env.local` | **gitignored** | Cluster URL + PVE token for `test_mutation.sh`. **Sourced by the script; copy from `env.local.example` and fill.** |
| `env.local.example` | yes | Template showing required env-var names. |
| `*.log`, `*_errors.log`, `*_summary.md`, `battery-out/` | gitignored | Run artifacts; regenerated each invocation. |

## Running

The scripts are location-independent — they resolve the repo root via
`git rev-parse` and find the release binary at `target/release/proxxx`.
The binary never reads your own proxxx config: `lib.sh` writes a private
one from `PROXXX_E2E_PVE_URL` and `PROXXX_E2E_PVE_TOKEN`, so the probes
reach the same cluster as the script's `curl` calls and your config file
is never rewritten (#479). `test_fleet_readonly.sh` is the exception: it
reads every profile of your config, read-only, by design.
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

## Pre-tag battery

Before a release tag, run every live suite against the lab and check that
the suites left the cluster as they found it:

```sh
tests/live/battery.sh                 # suites + inventory before and after
tests/live/battery.sh --no-inventory  # suites only
```

**It mutates the cluster**: `test_mutation.sh`, the state and reconcile
suites and the cargo e2e suites create, change and delete guests and
settings. Point it at a lab, never at production.

In order it runs `test_run.sh`, `test_mutation.sh`,
`test_state_mappings.sh`, `test_state_ha_rules.sh`,
`test_reconcile_converge.sh`, `setup_demo.sh --check`, and the cargo live
suites `feature_coverage_live`, `ssh_live`, `e2e_beta` and `e2e_alpha`
(with `PROXXX_E2E_ENABLE`, `PROXXX_E2E_FEATURE_COVERAGE_ENABLE` and
`PROXXX_E2E_ALLOW_DELETE` set to 1). Without `BIN` it builds the release
binary first. Each suite writes `LOG_DIR/<suite>.log` (default
`tests/live/battery-out/`), and `summary.txt` gets one line per suite:

```
test_run                     rc=11    16s  pass=76 fail=11
cargo_e2e_alpha              rc=0     41s  pass=1 fail=0 skipped=0
```

`skipped` counts the cargo suites' env-gated early returns
(`[e2e] PROXXX_E2E_ENABLE != 1 — skipping`), which cargo reports as
passed: a suite with `skipped` above 0 did not exercise the cluster. `test_run.sh` exits with its failure count,
so a node that is offline shows up there. The battery exits with the
number of suites that exited non-zero, plus one when the inventory
differs.

`inventory.sh <outdir>` is the snapshot on its own: one JSON file per
endpoint (`cluster/resources`, pools, storage, HA, mappings, firewall,
users, groups, ACLs, backup and replication jobs, notification matchers).
It drops what moves while nothing changes (resource metrics, every
`digest`) and sorts lists and storage `content`, so
`diff -r before after` is empty for an unchanged cluster. It sends GET
requests only, through `lib.sh`, and passes the token to curl on stdin,
out of the process listing.

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
