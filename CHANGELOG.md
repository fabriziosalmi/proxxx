# Changelog

All notable changes are documented here. The project follows this
SemVer contract:

- TUI layout changes are NOT covered (minor).
- CLI commands + exit codes are strictly SemVer.
- `--format json` output is additive-only (removing/renaming fields →
  major bump).
- Config schema is backwards compatible.
- MCP tool registry is append-only.
- **Rust library API** — the crate is linked by the proxima desktop UI.
  The supported surface (`api`, `config`, `app::preflight`,
  `state::model`) is additive within a minor; everything else is an
  implementation detail. Enumerated in `src/lib.rs`.

## [Unreleased]

### Security

- **An SSH client key below the NIST minimum through 2030 is refused before proxxx connects (#485).** proxxx used any key the configuration named: a 1024-bit RSA key loaded and signed (measured). It now refuses an RSA key under 2048 bits and any DSA key, naming the file and pointing to `ssh-keygen -t ed25519`. Ed25519, ECDSA and RSA of 2048 bits or more are unchanged. **Breaking** for a setup that uses such a key. **Migration:** create an Ed25519 key (`ssh-keygen -t ed25519`), install its public key on the nodes and point `key_path` at it.
- **The operator name in the audit log is looked up with the reentrant `getpwuid_r` (#476).** `getpwuid` returns a pointer into one static buffer shared by every thread, and the lookup runs from the audit hooks inside the multi-threaded runtime, so two concurrent lookups made the copy a data race (undefined behaviour) on the value sealed into the audit actor. The lookup now uses a buffer of its own, grown on `ERANGE`; a test keeps the non-reentrant passwd and group calls out of `src/`.

### Fixed

- **A TUI refresh costs N+4 requests instead of 3N+3, and leaves offline nodes alone (#493).** Every 5 s cycle listed qemu, lxc and storage on every node, offline ones included; against the default 10 requests/s it saturated around 16 nodes, and since #491 each offline node also cost a `/nodes` lookup per failed request (measured on the lab, 3 nodes with 1 offline: 15 requests per cycle). Guests now come from one `/cluster/resources` call and storage from the online nodes only (6 per cycle on the same lab; saturation moves to about 46 nodes). Guest status in the dashboard can trail the node by a few seconds (measured 3-5 s, pvestatd's cycle); the checks before a mutation still read the node itself. Storage stays per node because `/cluster/resources` has no exact `avail` (it overstated free space on a `dir` storage by its 5% root reserve). If `/cluster/resources` fails, the nodes are walked as before. An offline node keeps its last-known guests, marked stale; on a first load its guests are shown as PVE reports them.
- **`iso list` / `iso download` and `cloud-img download` point at images that exist (#492).** On 2026-10-22, 4 of the 6 bundled ISO-library URLs answered 404 (Ubuntu 22.04 and 24.04, Fedora 41, Rocky 9; measured), because mirrors delete old builds and the weekly re-pin covered only `cloudimg.rs`. Both registries are re-pinned from the official manifests (two of them checked by downloading the image and hashing it). Ubuntu now comes from `releases/<codename>/release-YYYYMMDD/`, which Ubuntu keeps since GA, and the end-of-life Fedora 41 from the permanent Fedora archive. `scripts/repin-cloudimg.py` now re-pins `iso_library.rs` too, refreshes the ISO view snapshot in the same bump, and the weekly workflow fails when a pinned URL stops answering (`--check-urls`). This supersedes the pending bot PR #244.
- **A node name outside the cluster is "not found" (exit 5), and an offline member says it is offline (#383).** PVE answers a request for a node it cannot route with the same HTTP 500 "hostname lookup failed" for a typo and for an offline member (measured on PVE 9.1.1), and proxxx passed it on with exit 1. proxxx now asks `/nodes` which one it is. `ha preview --node <name>` refuses a name that is not a member instead of printing a preview in which nothing is affected (it exited 0). **Breaking** for a script that tests the exit code: a mistyped `--node` now exits 5.
- **`find`, MCP and the HITL daemon no longer report a guest on an offline node as missing (#383).** The lookup walked online nodes only, so such a guest came back "not found" and `find <vmid>` exited 5, the code a teardown script reads as "already gone". It is now an error naming the offline node (exit 1), as `docs/reference/exit-codes.md` already stated.
- **`patch changelog --package <unknown>` fails with exit 5 (#383).** PVE returns apt's error text with HTTP 200 and a trailing `RC: 100`; proxxx printed it as the changelog and exited 0. Any other non-zero `RC` is an error with apt's message.
- **`audit export --export-format csv` prints CSV (#383).** It printed a JSON object holding the CSV text, with fields unquoted, so a comma in a result message shifted the later columns. Fields are now quoted per RFC 4180. **Breaking** for a consumer that parsed the JSON wrapper: read the output as CSV.
- **`ct interfaces` on a stopped container returns an empty list (#383).** PVE answers `{"data": null}` (measured), which proxxx reported as schema drift.
- **`gpu-inspect` reports the IOMMU as enabled only when IOMMU groups exist (#383).** Any dmesg line mentioning the IOMMU counted, including "DMAR: IOMMU disabled". The PCI class name keeps its first word ("VGA compatible controller", not "compatible controller"), and the vendor:device pair is read from the last hex `[xxxx:yyyy]` bracket even when the device name has brackets.
- **`play-cast` accepts asciicast v2 files without `title` or `timestamp` (#383).** Both are optional in the format.
- **`events stream` no longer grows without bound (#383).** The map of seen tasks kept every task it had ever seen; it now holds the tasks of the latest poll.
- **`ls <kind> --all-profiles` and `find <vmid>` report a panicked profile query under its profile name (#383),** instead of under a generic "unknown" label.
- **TUI queue (#383):** ops queued in the same microsecond no longer share an id; an op that was running when proxxx exited comes back as "interrupted, outcome unknown" with a pointer to the task log, instead of staying Running forever (it was never re-dispatched, and still is not); a queued op finds its guest through `/cluster/resources` instead of walking every node, and reports a failed lookup as itself instead of "Node not found"; saving the queue no longer holds key handling while SQLite is busy.
- **`state export` help no longer claims byte-stable output (#383).** Two exports of an unchanged cluster differ in `meta.exported_at`; the help, README and docs now say so.
- **Hints and `explain` no longer point at commands that do not exist (#385).** `explain unauthorized` recommended `proxxx auth login` / `auth show`, `explain parse` recommended `proxxx api GET`, `explain preflight-refusal` recommended `proxxx preflight`, and the parse-error hint suggested `proxxx -vvv`; none of them exist. They now point at `proxxx init --interactive`, `proxxx doctor`, `pvesh get` on a node and `RUST_LOG=proxxx=debug`. A test checks every cited `proxxx` command against the real command tree.
- **The 403 hint distinguishes a root-only endpoint (#385).** PVE reserves some endpoints, such as `/cluster/backup-info` (`backup-jobs info`), to the root@pam user itself and refuses every API token, root@pam's included (measured on PVE 9.1.1); the hint said to fix the ACL. The generic 403 hint now gives the full `proxxx perms <user> --node <node>` form.
- **PVE "does not exist" errors get a not-found hint (#385),** and the generic hint for other PVE errors no longer refers to an `Other { status }` field that is never shown.
- **`qga` on a container points at commands that work on one (#385):** `ct interfaces`, `serial --node` and `ssh`, not `exec`, which is QEMU only too.
- **Help text matches the commands (#385).** `init` has its description back and `profiles --help` no longer opens with the `init` text; `node-system syslog` says it pages from the oldest line and points at `journal --lastentries` for the newest; third-level usage lines carry their ancestors' positionals (`firewall-guest <VMID> alias list`).
- **`feature --feature` takes `snapshot`, `clone` or `copy`, and `cluster-resources --kind` takes `vm`, `storage`, `node`, `sdn`, `pool` or `network` (#385).** Both were free text; PVE 9 refuses `migrate` and `replicate` for features, and `pool` and `network` as a resource filter (measured). `pool` and `network` are now filtered by proxxx.
- **`watch` validates its request before waiting (#385).** `-u status=banana` waited out the full timeout; an unsupported target, key or value is now an error at once. `--since` takes s, m, h, d and w (`1d` was read as one hour) and refuses anything else. The help no longer offers a task UPID as a target.
- **`search` matches and reports the labels `ls` prints (#385).** `search 0` matched every QEMU VM through the guest type's hidden number; JSON rows now say `"stopped"` / `"qemu"` instead of `"Stopped"` / `"Qemu"`. **Breaking** for a consumer that compared those values.
- **`--format table` renders objects as tables (#385).** An object prints as `KEY<TAB>VALUE` rows plus one table per array of objects (`config`, `incident status`, `ha preview`); a nested object in a row expands into columns, so `find` and `ls --all-profiles` no longer print a JSON blob in a `DATA` column; the columns are the union of the rows' keys. `--format plain` is unchanged: one compact JSON value per line.
- **`mcp tools --json` prints the registry as is (#385).** The flag was ignored, so the default printed the table form and `--format json` wrapped the registry in a one-element array.
- **`accounting --include-unassigned` labels guests without a tag `(none)`, as it does guests without a pool (#385).** It used `(no-tag)`. **Breaking** for a consumer keyed on `(no-tag)`.
- **`metrics` labels a guest by its real type and refuses series that do not exist (#385).** `metrics vm` on a container printed "VM" (PVE serves the RRD under either path); `--field loadavg` or `iowait` on a guest, `diskread`/`diskwrite` on a node and anything but `used`/`total` on a storage returned all nulls with exit 0 and are now errors. `metrics node --field used|total` reads the root filesystem, as its help says, instead of returning nulls.

## [0.15.0] - 2026-10-22

Headline: **the second audit backlog, closed.** This release is mostly
security and correctness fixes. Several of them change what a v0.14.0
config, script or library consumer sees; they are listed first, each with
its migration. Read them before upgrading an unattended deployment
(daemon, cron job, CI gate, MCP server).

### Breaking (config, CLI flags and exit codes, JSON output, library API)

**Configurations that no longer load (exit 3)**

- **Unknown keys are refused in every TOML section, including `[[policies]]` (#326).** v0.14.0 ignored them (measured: a flat config with `verfy_tls = false` loaded and ran). **Migration:** run any command once; the error names the key. Fix the spelling or remove the key. `[[alerts]]` now accepts `trigger` as an alias of `when`.
- **A profile-only config with a top-level section that no profile reads is refused (#440).** With `[profiles.<name>]` tables and no top-level `url`, a top-level `[[alerts]]`, `[telegram]`, `[ssh]`, `[pbs]` or `[[policies]]` used to be dropped silently (measured: a top-level `[[alerts]]` next to `[profiles.lab]` loaded). **Migration:** move the section to `[defaults.*]` (shared) or `[profiles.<name>.*]`. Configs that also have a top-level `url` are unchanged.
- **`ssh.strict_host_key_checking` is validated, and `"yes"` now means strict (#375).** Accepted: `tofu`, `strict`, `off`, and the OpenSSH spellings `accept-new` (tofu), `yes` (strict), `no` (off). Any other value used to mean TOFU (measured: `"ask"` loaded); it is now refused. A config with `"yes"` used to trust a new node's key on first use and now refuses a node that is not already in `known_hosts`. The `/tmp/proxxx` fallback for `known_hosts` is gone. **Migration:** write `tofu` if you relied on trust on first use; set an explicit `known_hosts` path where the per-user config directory cannot be resolved.
- **`pbs.fingerprint` is enforced (#414).** v0.14.0 parsed and ignored it (measured: `fingerprint = "not-a-fingerprint"` loaded). A malformed value is now refused at load; a well-formed but stale value fails the TLS handshake, and the pin takes precedence over `verify_tls = false`. **Migration:** set it to the current SHA-256 fingerprint of the PBS certificate (`proxmox-backup-manager cert info`), or remove the key.

**Mutations that are now refused**

- **Every PVE mutation and SSH `patch apply` needs a writable, verifiable audit log (#344).** Before any `POST`, `PUT` or `DELETE` leaves the process, proxxx verifies the HMAC chain in `audit.db` and writes a write-ahead row; if the database or key cannot be opened, verified or written, the mutation is refused with exit 8. This applies to the CLI, the TUI, `daemon serve` and the MCP server. An existing chain that v0.14.0 broke with concurrent writers (#368) refuses every mutation. **Migration:** before upgrading, run `proxxx audit verify` as each user that runs proxxx (CLI, daemon, MCP); make sure the audit directory is writable for that user (`PROXXX_AUDIT_DIR`, `PROXXX_AUDIT_KEY`); if verify reports tampered or unverifiable rows, archive `audit.db` and `audit.key` before the upgrade so a new chain starts.
- **`--secure` is enforced on the CLI (#338, #399).** v0.14.0 accepted `--secure` on the CLI and ignored it, so `proxxx --secure delete 100 --yes` ran. Every destructive CLI command (the 64 actions in `hitl::DESTRUCTIVE_ACTIONS`: stop, delete, migrate, `node stopall`, `snapshot delete`, `pool delete`, `state apply`, `reconcile converge`, `patch apply`, `pbs restore`, `ssh <vmid> --cmd`, and the others listed in the Security section) now exits 8 under `--secure` before any API call, and `schedule run-due` passes `--secure` to the jobs it starts. **Migration:** drop `--secure` from scripts and schedules that must run destructive commands unattended; keep it where refusal is the point.
- **`node stopall` and `node suspendall` require `--yes` (#399).** Without it they exit 1 before any request. **Migration:** add `--yes`.
- **`--token-secret` / `--token-secret-file` are refused by fan-out commands (#374).** `ls <kind> --all-profiles`, `find` and `fleet` exit 3 when the flag is given (measured: v0.14.0 accepted it and sent the secret to every profile). **Migration:** give each profile its own secret (`token_secret_file`, environment variable or keychain) and drop the flag from fan-out calls.
- **`state apply`, `reconcile converge` and the daemon's `auto_converge` refuse a state file whose `[meta] profile` differs from the resolved profile (#346).** Exit 3; `state diff`, `reconcile run` and `reconcile watch` only warn. v0.14.0 wrote `profile = "default"` on every export made without `--profile`, also when a named profile was selected through `default = "<name>"` or a single `[profiles.<name>]`, so those files now mismatch. The daemon never overrides the check. **Migration:** set `[meta] profile` to the profile name (or re-export with v0.15.0); on the CLI, `--allow-profile-mismatch` overrides.
- **A state file that declares no resource family is refused by `state diff`, `state apply` and `reconcile` (#371).** Exit 1 for an empty, comment-only or `[meta]`-only file, which used to report "no changes" with exit 0. **Migration:** declare the families the file manages, e.g. `pools = []`. `state export` now writes empty families that way.
- **`state apply --dry-run` and `reconcile converge --dry-run` run the pre-flight gate (#369).** A rehearsal can now exit 6 where it exited 0. **Migration:** treat exit 6 from a dry-run as "the real run would be refused". Without `--prune`, skipped deletes no longer trip the gate.
- **A storage update refuses a change to an immutable field (#370).** A declared change to `type`, `path`, `export`, `datastore`, `vgname` or `thinpool` used to be reported as Applied without effect, on every tick; it is now an error before any request. **Migration:** align the declared value with the cluster, or recreate the storage.
- **`mcp serve-http` checks `Host` and `Origin` on every route (#342).** On a non-loopback bind only `<bind>:<port>` and each `--allowed-host` value are accepted, so a `0.0.0.0` bind answers 403 to clients that use the machine's name or address; on a loopback bind only `127.0.0.1`, `localhost` and `[::1]` are accepted, which refuses a reverse proxy that forwards the public `Host`. A cross-origin `Origin` is refused. **Migration:** add `--allowed-host <name[:port]>` for every name clients use.
- **HITL approval requests expire after 120 s, and keyboards minted before the upgrade are refused (#341).** v0.14.0 kept no expiry. Requests now live in `<config_dir>/hitl_pending.db`, shared by the sender and the daemon. **Migration:** approve within two minutes, or request again; re-request anything pending at upgrade time.

**Exit codes**

- **A batch operation waiting for approval exits 9, not 3 (#360).** When the approval request cannot be sent (no `[telegram]`, or Telegram refused it), the guest is reported as an error and the batch exits 2. **Migration:** treat 9 as "pending approval"; 3 now only means a configuration error.
- **Configuration errors exit 3, not 1 (#359):** unknown `--profile`, no default profile, missing required fields, invalid enum-like values, `proxxx pbs ...` without a PBS block (measured: an unknown profile exited 1 on v0.14.0). **Migration:** treat 3 as a configuration error.
- **A VMID absent from the cluster exits 5, not 1 (#358)**, for guest-targeted commands, `metrics vm|ct`, `watch -t vm-<id>`, `snapshot` and `console vnc`. An unreachable node still exits 1 (or 7). **Migration:** treat 5 as "guest does not exist".
- **`ls <kind> --all-profiles` exits 1 when any profile fails, and `find <vmid>` exits 1 when a profile failed (#322).** Both exited 0 (measured with one unreachable profile). `find` exits 5 only when every profile answered and none owns the VMID. **Migration:** treat 1 as partial output; the rows are still printed.
- **`upgrade-check` no longer passes when it could not check (#355).** A node that cannot be read gives `indeterminate` and exit 1, a target with no checks (e.g. `banana`, `10`) is a usage error (exit 2), and every node's version is checked, so a node behind the target is a block finding. **Migration:** use `--target 9`; treat 1 as "not proven ready".
- **`heatmap` exits 1 when a node does not answer (#353)**, and each row now times the node itself. v0.14.0 always exited 0.
- **`anomaly` exits 1 when a node is skipped (offline or too little RRD history), and judges each node against its own history (#356).** It used to exit 1 only on an anomaly, computed across the nodes of one snapshot. New `--min-cpu-delta` (10) and `--min-mem-delta` (5) defaults gate what counts. **Migration:** read `skipped` in the JSON before alerting on exit 1.
- **`logs tail` exits 1 when a node fails, and reports the failure on stderr instead of as a log record (#364).** The `[ssh error]` records no longer appear on stdout (JSON or text). **Migration:** check the exit code and stderr instead of parsing error records.
- **`perms <user>` exits 5 for a user that does not exist (#347)**, instead of printing `paths: []` with exit 0.

**Changed defaults and behaviour**

- **`logs tail --no-follow` without `--since` prints the last 200 lines per node (#392).** It used to print the whole journal. **Migration:** pass `--since` or the new `--lines N` to choose the window.
- **Mutating requests are not retried after a timeout, a `502`, a `504` or a `503` without `Retry-After` (#348).** They used to be retried up to 4 times, which could run the change twice. The command now fails (exit 1 for a timeout, 7 for the status codes) and says PVE may have run it. **Migration:** after such a failure, check `proxxx tasks` or the PVE task log before retrying.
- **The global `--format json` now applies to commands with their own output flag (#362):** `explain`, `describe`, `cloud-img list`, `schedule list`, `backup-verify`, `heatmap`, `anomaly`, `upgrade-check`, `accounting`, `import`, `gpu-inspect`, `state export|diff|apply`, `reconcile run|converge`, `mcp tools`. They printed text. **Migration:** a wrapper that always passes `--format json` and wants text must pass the command's own flag (`--output`, `--print`, `--json`), which still wins.
- **The default data directory is narrowed to `0700` on every start, and the log directory is created `0700` (#384).** It is also the default audit directory (on macOS the same directory holds the config). A log shipper running as another user loses read access, and proxxx fails to start if it cannot narrow a directory it does not own. **Migration:** run log readers as the same user, or point `PROXXX_LOG_DIR` at a directory you manage (a directory set there is created `0700` but not narrowed).
- **Node-level SSH reaches the API node through the profile `url` host when `ssh.hosts` has no entry for it (#328).** Host keys are recorded per connection host, so under `strict` a `known_hosts` entry made for the node name does not cover the URL host. **Migration:** add `hosts = { <node> = "<node>:22" }` under `[ssh]` to keep the previous target, or record the URL host's key.

**CLI flags**

- **`node-system <node> journal`: `--service` is removed and `--since` / `--until` take UNIX epoch seconds (#351).** PVE's journal endpoint has no unit filter (use `syslog --service`) and accepts only epoch seconds. In v0.14.0 every call failed on PVE 9.1.1 (gzip body).
- **`watch -t storage-<id>` refuses a node-local storage present on several nodes (#352).** It used to watch whichever node's row came first. **Migration:** use `storage-<id>@<node>`.

**JSON output**

- **`ha status` has the shape PVE returns (#350):** `manager_status` (`master_node`, `node_status`, `service_status`), `lrm_status` per node and `quorum` replace the top-level `master`, `mode` and `node_status`, which v0.14.0 always printed empty. A response without `manager_status` is now a parse error.
- **Option `get` commands omit keys PVE did not return (#349):** `firewall-cluster options get`, `firewall-guest <vmid> options get` and `cluster-config get` used to print unset keys as `false`, `0` or `""`. `registered-tags` and `tag-style` are passed through as PVE sends them, `allowed-tags` and `policy_forward` are new, and `acme plugin list` reads the real `validation-delay`. **Migration:** treat a missing key as "PVE default" (for example `jq '.ebtables // true'`).
- **`backup-verify --output json` (#357):** a `missing` row no longer carries `age_days` (it was `0.0`), the new status `unknown` has no `age_days`, and a node that could not be read gives one `unknown` row without `vmid`.
- **Fatal errors under `--format json-envelope` are wrapped in the envelope (#361):** `{"proxxx": "<version>", "data": [ ... ]}` instead of a bare array (measured on v0.14.0). Under both JSON formats `error` now carries the whole cause chain, and `causes` and `exit_code` are added.

**Rust library API (`api`, `config`, `state::model`)**

- **Type and signature changes for library consumers:** `ClusterOptions`, `FirewallOptions`, `GuestFirewallOptions` and `state::model::FirewallOptionsDecl` fields become `Option<_>`; `AcmePlugin::validation_delay` is `Option<u32>`; `HaManagerStatus` is reshaped (see `ha status`); `StoragePool` gains a public `node` field; `ProxmoxGateway` gains the required methods `get_node_version` and `get_user`; `api::tls_pin::pinned_cert_path` and `load_pinned_cert` are removed; `ApiError::actionable_hint` is no longer `const`; `SshConfig::resolve_host` takes the API URL and local node and returns `ResolvedNodeSsh`; `SshConfig::known_hosts_path` returns `Result`; `ConfigError` gains variants (`UnknownProfile`, `NoDefaultProfile`, `ProfileParse`, `InvalidValue`, `MissingPbsConfig`, `ProfileMismatch`, `DefaultsParse`, ...); `PbsConfig` and `TelegramConfig` gain `profile_name`. **Migration:** rebuild proxima against v0.15.0 and adjust; implementors of `ProxmoxGateway` must add the two methods.

### Security

- **Six smaller security fixes (#384).** `mcp serve-http` takes its bearer token from `--token-file` or `PROXXX_MCP_TOKEN`, so it no longer has to sit in the process listing; the file wins over `--token`, which wins over the variable, which wins over `mcp_token`. An open SSE stream re-checks its token before every event and every 15 s and ends once a `SIGHUP` reload has rotated it out; it used to keep receiving events. An MCP integer parameter outside 0 to 4294967295 is refused; it was narrowed with `as u32`, so `guest_id` 4294967396 acted on VMID 100 and HITL policies matched the wrapped id. A PBS datastore name is percent-encoded as one path segment, and PBS requests pass the same relative-segment check as PVE ones; `../` in a name used to reach other API paths. A webhook URL is logged and reported as scheme, host and port only, since hosted webhooks keep their secret in the path; it was logged at info on every alert. `audit.db` is created `0600` (an older, wider one is narrowed on open), and the log directory is created `0700`, with the default data directory narrowed on start: it is also the default audit directory, and `main` created it `0755` before the audit layer could create it `0700`. The panic message names the real log file instead of a fixed `~/.local/share/proxxx (proxxx.log)`.
- **Release builds are pinned, checked and signed end to end (#384).** The aarch64 musl build pins the cross image by digest in a new `Cross.toml` (the `0.2.5` tag alone is mutable, and the image holds the linker that builds the released binary). A tag whose version differs from `Cargo.toml` fails before any build, so tarballs named `proxxx-X` can no longer report version Y. The CycloneDX SBOM is signed with the same keyless cosign bundle as the tarballs. `--version` and the startup log line name the commit a release was built from (`proxxx X.Y.Z (commit <12 hex>)`), and the release job checks it on the targets it can run. The RUSTSEC-2023-0071 rationale in `.cargo/audit.toml`, `deny.toml` and `THREAT_MODEL.md` names the current path (russh 0.64.1 to rsa 0.10.0-rc.18, directly and through ssh-key 0.7.0-rc.11) instead of rc.16 through a forked crate.
- **`--format table` and `--format plain` no longer pass terminal control sequences from API strings (#365).** Table, the default CLI format, printed every string as received, so a value such as a PBS snapshot comment or a user comment synced from LDAP could carry escape sequences that move the cursor, retitle the terminal or write the clipboard (OSC 52). Every cell and header now has its control characters removed, and a tab, newline or carriage return inside a value is printed as `\t`, `\n` or `\r` so it cannot split the row a script reads. Plain output and the pretty JSON that table prints for a single object drop DEL and C1 controls (JSON already escapes the rest). The shared display filter, also used by the TUI, now removes the C1 controls U+0080 to U+009F as well: some terminals read U+009B as CSI and U+009D as OSC. Output with no control characters is unchanged.
- **A tag publishes nothing unless the tagged commit passes CI, and every build is pinned to `Cargo.lock` (#381).** `release.yml` assumed the tagged commit had already passed CI, so a tag on a red commit, or on one with a fresh advisory, still produced signed artefacts and a Homebrew bump. Its first job now calls `ci.yml` (tests, clippy, fmt, cargo audit, cargo deny, secret scan, musl build) on the tagged commit, and the build matrix needs it. No cargo command passed `--locked`, so a stale lock was re-resolved on the runner and the shipped binary could contain crates that audit, deny and the SBOM never saw; every `cargo build`, `test`, `clippy`, `llvm-cov` and `cross build` in the workflows now uses `--locked`. `tests/release_gates.rs` fails if the gate or a `--locked` is dropped.
- **The CLI token secret is no longer sent to other clusters or to PBS (#374).** `--token-secret` / `--token-secret-file` hold one profile's secret, but `ls --all-profiles`, `find` and `fleet` passed it to every profile, the TUI kept it after an in-app profile switch, and the `delete` pre-flight passed it to the PBS client. Fan-out commands now refuse the flag (exit 3); after a TUI profile switch the next profile resolves its own secret; the PBS client in the `delete` pre-flight resolves its own secret (`proxxx pbs ...` commands still use the flag). When PBS is configured but its client cannot be built, the pre-flight reports the PBS backup check as skipped instead of silently leaving PBS out. The docs no longer mention a `--pbs-token-secret` flag that does not exist.
- **Private files are never written with wider permissions first (#376).** The HMAC key, `config.toml` from `init` and the wizard, `schedules.toml`, the freeze lock and console recordings were written with the default umask and only then chmod-ed to 0600, so another local user watching the directory could open the file in between and keep the descriptor. All of them, plus token secret files and TLS pins, now go through one helper that creates the parent directory 0700 if missing, writes a temp file that is 0600 from the first byte, fsyncs it and renames it durably; TLS pins and console recordings were also not fsync-ed before. A guard test fails if a write-then-chmod comes back.
- **An unrecognised `ssh.strict_host_key_checking` value no longer degrades to TOFU (#375).** Any value other than `tofu`, `strict` or `off` used to mean "trust on first use", so the OpenSSH spelling `"yes"` trusted the first key presented and a man-in-the-middle on a new or reinstalled node was pinned. The value is now validated at config load (exit 3 with the accepted list); the OpenSSH spellings are accepted as aliases (`accept-new` = tofu, `yes` = strict, `no` = off), and an unknown value seen at runtime fails safe to strict. The `known_hosts` file no longer falls back to the shared `/tmp/proxxx` when the per-user config directory cannot be resolved: proxxx asks for an explicit `known_hosts` path instead, and the TUI checks host keys strictly.

- **Exhaustive CLI `--secure` destructive-command classification, `--secure` forwarding in `schedule run-due`, and `--yes` confirmation on `node stopall` / `node suspendall` (#399).**
  `src/cli/mod.rs::cli_hitl_action` previously matched only 9 top-level variants (`start`, `stop`, `restart`, `delete`, `migrate`, `exec`, `disk move`, `disk resize`, `snapshot create`) and fell back to `_ => None`, `src/hitl/mod.rs::DESTRUCTIVE_ACTIONS` listed only the 7 TUI `SideEffect` action names (`stop`, `delete`, `restart`, `migrate`, `exec`, `move_disk`, `resize_disk`), and `src/cli/schedule.rs::run_due` spawned scheduled child commands without forwarding `--secure`. As a result, destructive CLI commands outside those 7 — including `node stopall`, `node suspendall`, `snapshot delete`, `template`, `task-stop`, `backup --mode stop|suspend`, `patch apply`, `state apply`, `reconcile converge`, `storage delete`, `storage-defs update` / `delete`, `pool delete`, `pool remove-members`, `access user-update` / `user-delete` / `group-delete` / `acl-unset` / `password`, `token revoke` / `token bootstrap --rotate`, `firewall-cluster` / `firewall-guest` deletions and policy/alias/ipset updates (`options set`, `alias update`, `ipset add-cidr`), `cluster-mapping` deletions, `cluster-bootstrap` node/qdevice changes (`nodes add` / `remove`, `qdevice setup` / `update` / `delete`, `join join`), `node-system` cert/subscription deletion, `notifications` / `metric-servers` / `backup-jobs` / `acme` / `ha` / `schedule` deletions, `vm raw-set`, `vm sendkey`, `vm unlink`, `ct raw-set`, `qga write`, `pbs restore`, and non-interactive `ssh <vmid> --cmd` — bypassed the `--secure` gate, as did any destructive command invoked via `proxxx --secure schedule run-due`. `DESTRUCTIVE_ACTIONS` now documents the canonical classification rule (an action is destructive if it is irreversible, removes data or a resource, or interrupts availability) and lists all 64 destructive action names, `cli_hitl_action` matches exhaustively on `Command` and every mutating nested subcommand enum without any `_ =>` wildcard (so adding a new CLI subcommand fails to compile until classified), `schedule::run_due` forwards `--secure` to every spawned child process when the parent runs under `--secure`, and `node stopall` and `node suspendall` (`src/cli/node.rs`) now require `--yes` via `cli::common::require_yes` before invoking the gateway.

- **TLS TOFU (`tls_pin_mode = "tofu"`) and PBS `pbs.fingerprint` now enforce true SHA-256 leaf-certificate pinning via a custom `rustls` `PinnedLeafVerifier` across REST, WebSocket serial console (`wsterm`), `PbsClient`, and `doctor` probes (#320, #414).**
  `PxClient` previously loaded `<config_dir>/known_certs/<host>_<port>.der` via `reqwest::Certificate::from_der` and passed it to `ClientBuilder::add_root_certificate`, which WebPKI treats as a CA trust anchor (failing with `InvalidCertValidity` / `UnknownIssuer` / `NotValidForName` against Proxmox VE's default `pve-root-ca.pem` → `pve-ssl.pem` non-CA leaf or IP URLs), while `PbsConfig.fingerprint` (`#414`) was deserialized and silently ignored by `PbsClient::new`. `src/api/tls_pin.rs` now provides `PinnedLeafVerifier` implementing `rustls::client::danger::ServerCertVerifier`: `verify_server_cert` compares `SHA-256(end_entity DER)` against the pinned 32-byte digest in constant time (`subtle::ConstantTimeEq`), and `verify_tls12_signature` / `verify_tls13_signature` verify the handshake `CertificateVerify` signature via `rustls::crypto::verify_tls12_signature` / `verify_tls13_signature` backed by `ring`'s `signature_verification_algorithms`. On mismatch, the handshake fails immediately without retry (`src/api/transport.rs::is_retryable_error` now excludes TLS/certificate errors) and reports both pinned and presented SHA-256 fingerprints, the `<config_dir>/known_certs/<host>_<port>.der` path, and instructions to verify out of band before deleting the file to re-trust. `PxClient`, `wsterm::connect` (`src/cli/console.rs`), `PbsClient::new`, and `doctor`'s anonymous version probes all honour the pinned verifier via `use_preconfigured_tls`, and malformed `pbs.fingerprint` values are rejected at config load (`ConfigError::InvalidValue`, exit code 3).

- **`proxxx doctor` no longer prints the plaintext Telegram bot token on transport or proxy failures (#410).**
  `src/cli/doctor.rs` previously constructed `https://api.telegram.org/bot{token}/getMe` directly and formatted any `reqwest::Error` with `{e}`, whose `Display` implementation appends `for url (https://api.telegram.org/bot<token>/getMe)`. `doctor` now routes its Telegram check through `TelegramGateway::new_for_probe` and `TelegramGateway::get_me`, which strip the request URL via `reqwest::Error::without_url()` and redact both the configured token and secret patterns via `panic_hook::scrub_secrets`, ensuring no `doctor` stdout or stderr output (JSON or table) contains the bot token on any path.

- **The MCP HTTP server (`proxxx mcp serve-http`) now enforces fail-closed `Host` and `Origin` validation on every route before Bearer auth (#342) and keeps `--token` across `SIGHUP` config reloads (#343).**
  `src/mcp/http_server.rs` previously accepted any `Host` and `Origin` header on `POST /mcp`, `GET /mcp` (SSE), and `GET /health`, leaving loopback listeners open to browser DNS-rebinding attacks, and `src/cli/mod.rs` wrote the `--token` CLI argument directly into the reloadable `ProfileConfig` (`cfg.mcp_token = Some(...)`) so a `SIGHUP` config reload from a file without `mcp_token` overwrote the CLI token (dropping authentication on loopback or locking out all callers with `401` on an exposed bind). A router-wide `require_allowed_host_and_origin` layer now runs before `require_authorized` on every route: missing or empty `Host` headers return `400 Bad Request`; `Host` must match one of the allowed authorities (`127.0.0.1:<port>`, `localhost:<port>`, and `[::1]:<port>` on loopback binds, or `<bind>:<port>` plus each repeatable `--allowed-host <host[:port]>` entry on exposed binds) or is refused with `403 Forbidden` naming the rejected host; if an `Origin` header is present it must be `http://` or `https://` followed by an allowed authority or is refused with `403 Forbidden` (requests without `Origin` remain allowed and no CORS headers are emitted). For `#343`, the CLI `--token` is no longer written into `ProfileConfig`: it is stored as `cli_token: Option<SecretString>` in `McpState` at startup and takes precedence over the reloadable `config.mcp_token`, so `SIGHUP` reloads can still rotate `mcp_token` from disk when `--token` was not given but can never clear or replace a CLI-supplied token.

- **Every PVE REST mutation and SSH `patch apply` now writes a fail-closed write-ahead `"sent"` entry and a post-call outcome entry to the HMAC-chained `audit.db` (#344).**
  `src/audit/mod.rs` previously called `AuditLogger::log()` only from `incident freeze`, `incident thaw`, and `state apply`, leaving guest lifecycle operations (`start`, `stop`, `shutdown`, `restart`, `suspend`, `resume`, `delete`, `clone`, `migrate`), snapshots, disk move/resize, firewall changes, user/role/ACL/token mutations, ISO downloads, and SSH `patch apply` unaudited despite documentation claiming every mutation was recorded. `PxClient::post`, `PxClient::put`, `PxClient::delete`, `PxClient::upload_to_storage` (with `PxClient::resize_disk` routed through `PxClient::put`), and `app::patch::Orchestrator::run_upgrade` now pass through a mandatory write-ahead audit gate (`MutationAuditCtx::write_ahead` / `write_ahead_custom` and `record_outcome`) backed by a process-wide lazy `AuditLogger` with a 5-second SQLite `busy_timeout`. Before any mutation leaves the process, the gate verifies the existing HMAC chain and appends a `"sent"` row (`action` = `"<METHOD> <path>"` or `"SSH patch apply"`, `user` = authenticated PVE user or SSH user, `node`/`vmid` parsed from `/nodes/{node}/(qemu|lxc|openvz)/{vmid}/...`, and `params_json` with secret keys matching `password|secret|token|ticket|key|cookie` replaced by `"[REDACTED]"` and non-secret values scrubbed via `panic_hook::scrub_secrets`), then appends a second row with the outcome (`"ok <status>"`, `"error <status>"`, `"ok 0"`, `"error <code>"`, or `"error transport: <kind>"`). If opening, verifying, or writing `audit.db` or `audit.key` fails, the mutation is refused before any network call with `AuditWriteRefusal` (exit code 8).

- **The HITL daemon now executes all 15 policy-gated CLI and MCP operations from persisted `params_json` with live Guest Binding and strict parameter decoding (#340).**
  `src/hitl/daemon.rs::execute_approved_action` previously implemented only
  `stop`, `delete`, `restart`, and `start`, dropped stored parameters such as
  `force`, `timeout_secs`, `snapname`, `newid`, and `target_node`, re-resolved
  `(node, guest_type)` from the live cluster by `vmid` alone without checking
  the approved row, and marked every other policy-gated operation (`shutdown`,
  `stop_guest`, `restart_guest`, `delete_guest`, `create_snapshot`,
  `delete_snapshot`, `suspend_guest`, `clone_guest`, `migrate_guest`,
  `create_guest`, `clone_with_cloudinit`) as `Unknown HITL action`. The daemon
  now decodes each row into an exhaustive `ApprovedOp` enum across all 5 CLI
  batch operations and 10 destructive MCP tools (`#[serde(deny_unknown_fields)]`
  plus `Shape::Name` validation on path-bearing fields), verifies Guest Binding
  against `get_cluster_resources()` before execution (existing guests must still
  reside on `(row.node, row.guest_type)` and target VMIDs for `create_guest` /
  `clone_guest` / `clone_with_cloudinit` must still be free), calls the shared
  `cli::common::exec_cli_batch_op` and `mcp::dispatch::exec_*` executors with
  the exact stored parameters, and records the returned UPID or identifier in
  `hitl_pending_requests.upid`.

- **HITL pending approvals are now persisted in `<config_dir>/hitl_pending.db` with 64-bit random request IDs and a 120-second TTL (#341).**
  CLI and MCP policy intercepts previously constructed a deterministic
  `{action}:{vmid}` transaction ID while `src/hitl/pending.rs` kept the consumed
  set only in process memory with no `issued_at` or `expires_at`, allowing an
  old approval button to replay after a daemon restart and causing a second
  legitimate request for the same `(action, vmid)` within a single daemon
  session to be rejected as stale. Senders and the HITL daemon now share
  `<config_dir>/hitl_pending.db` (SQLite, `0600` in a `0700` parent directory
  alongside `telegram_hmac.key`, with 7-day retention pruning of terminal rows
  on open), storing `id` (16 lowercase hex chars from `getrandom`), `action`,
  `vmid`, `node`, `guest_type` (`qemu`/`lxc`), `params_json`, `require`,
  `issued_at`, `expires_at` (120 s default TTL), `status` (`pending`,
  `approved`, `denied`, `expired`, `executed`, `failed`), `approvers_json`, and
  `error`. Telegram inline keyboards now emit `approve:<id>:<hmac16>` (41 bytes)
  and `deny:<id>:<hmac16>` (38 bytes), leaving 23 bytes of headroom under
  Telegram's 64-byte `callback_data` cap regardless of action length, and
  legacy 3/4-segment buttons are refused with a prompt to request again.

- **CLI `--secure` now refuses destructive commands with exit code 8 instead of silently ignoring the flag (CLI-surface behaviour change, #338).**
  `src/cli/mod.rs::execute` previously accepted `--secure` as an unused
  `_secure: bool` parameter while `--help` and `docs/integrations/hitl.md`
  advertised `proxxx --secure delete 100 --yes` as requiring Telegram 2FA,
  causing destructive CLI commands under `--secure` to execute immediately
  without human approval. Both the TUI and the CLI now consult the shared
  `hitl::DESTRUCTIVE_ACTIONS` set (`stop`, `delete`, `restart`, `migrate`,
  `exec`, `move_disk`, `resize_disk`), and `cli::enforce_cli_secure_mode`
  refuses any destructive CLI command before any API call with
  `hitl::SecureModeRefusal` (exit code 8, in the same local-lock refusal
  family as `read_only` and `incident freeze`), while non-destructive CLI
  commands continue to run normally.

- **All mutating TUI side effects and queued batch operations now pass through the HITL gate (#339).**
  `src/tui/mod.rs` previously called `check_hitl` only inside the `StartGuest`,
  `StopGuest`, and `RestartGuest` arms of `dispatch_side_effect`, leaving
  `DeleteGuest`, `MigrateGuest`, `ExecuteGuestCommand`, `CreateSnapshot`,
  `DownloadIso`, `MoveDisk`, `ResizeDisk`, and `ExecuteQueue` ungated even when
  `--secure` was enabled or a matching `[[policies]]` rule was configured.
  `tui::hitl_action` now exhaustively classifies every `SideEffect` variant
  with no wildcard arm so new variants fail to compile until classified, a
  single `check_hitl` gate runs before the `match effect` dispatch for all
  mutating variants (`start`, `stop`, `restart`, `delete`, `snapshot`,
  `migrate`, `exec`, `download_iso`, `move_disk`, `resize_disk`), and
  `ExecuteQueue` gates each queued operation individually while preserving
  write-ahead persistence and immediate dispatch for non-gated operations.

- **Unified HITL Telegram callback verification and quorum enforcement across the daemon and TUI (#336, #337).**
  `TelegramGateway::request_approval` mints approve callbacks with a trailing
  `:r<require>` quorum segment (`approve:<txn_id>:r<require>:<hmac>`), while
  `src/tui/mod.rs` previously split only at the first `:` after stripping the
  HMAC tag, leaving `:r<require>` attached to `txn_id` so every TUI approval
  looked up a non-existent pending key and timed out (#336). In addition, the
  TUI poller verified only the HMAC tag and skipped the originating `chat.id`
  check, the `allowed_approvers` allowlist, and `require > 1` quorum counting
  (#337). Both the daemon and the TUI now validate callbacks through
  `hitl::daemon::verify_callback` and `parse_callback_payload` (HMAC tag,
  `chat.id`, fail-closed `allowed_approvers`, and `<decision>:<txn_id>[:r<digits>]`
  with backward compatibility for 3-segment keyboards), enforce `require`
  distinct approver votes via `PendingApprovals`, and answer the Telegram
  callback with `Approved` or `Denied` only after a matching pending entry is
  resolved (or `Expired or unknown request` when none matches).
- **The panic hook scrubs `PVEAPIToken=` headers before writing to stderr and the log file (#377).**
  `src/util/panic_hook.rs` redacted `PVEAuthCookie=`, `PBSAPIToken=`,
  `tokenid=`, `password=`, `token_secret=`, `csrfpreventiontoken=`,
  `vncticket=`, and `Authorization: Bearer `, but omitted `PVEAPIToken=`,
  the `Authorization` header format sent on PVE API requests
  (`PVEAPIToken=<user>!<tokenid>=<uuid>`). Adding `"PVEAPIToken="` to
  `KEY_VALUE_MARKERS` masks the entire `<user>!<tokenid>=<uuid>` value run
  with `[REDACTED]` (case-insensitively).
- **Upgraded `russh` from `0.62.5` to `0.64.1` (#315).** Closes five GitHub
  Security Advisories against `russh`: `GHSA-47hw-gvq5-r2gm` (high, client-side
  channel-scoped `Handler` callbacks firing for channel IDs the client never
  opened), `GHSA-w3jg-pjxf-73p4` (medium, missing X25519 low-order point
  validation in hybrid ML-KEM key exchange), `GHSA-35g8-35p8-c8fw` (medium,
  unbounded memory growth via `CHANNEL_OPEN` flood during a stalled rekey),
  `GHSA-p8qx-h547-fjw9` (low, strict-kex enforcement before initial KEX
  completion), and `GHSA-g6xm-f9xp-qq35` (low, server/agent handling).
  `SshHandler::check_server_key` now adapts to `PublicKeyOrCertificate` while
  keeping `host_key_certificates` empty (plain `Ed25519` keys only) and
  rejecting public-key serialization failures instead of falling back to an
  empty key blob.

- **The docs workflow moved off the self-hosted runner.** `docs.yml`
  declared `runs-on: [self-hosted, Linux, X64]` — labels that name no
  particular machine, so the job matched *any* self-hosted runner
  attached to the repo. It builds on `pull_request`, and proxxx is
  public, so a fork PR touching `docs/**` could execute on whichever
  runner happened to be registered. Both jobs now run on
  `ubuntu-latest`; `npm ci` + `npx vitepress build` never needed a
  private host, and the deploy job additionally holds the `github-pages`
  credential.

- **Live-cluster credentials now live outside the working tree.** The
  `tests/live/*.sh` harnesses resolve `~/.config/proxxx/live-env` before
  the gitignored in-repo `env.local` (`PROXXX_E2E_ENV_FILE` still
  overrides both). A real PVE token inside a checkout is one `git add -f`
  or one world-readable clone away from leaking, and the in-repo copy was
  mode 0644 in practice.

### Changed

- **Configuration typos now fail loudly (#326).** All TOML configuration
  sections reject unknown keys; configs that contain unknown keys now fail
  to load; previously the keys were ignored. Stale documentation examples
  (such as `[ssh].key`, `threshold`, and `password_file`) have been corrected
  and are now drift-proofed in CI. In `[[alerts]]` rules, `trigger` is now
  accepted as an alias of `when`: the documented examples used `trigger`
  and previously failed to load with a missing `when` field. `[[policies]]`
  entries also reject unknown keys; the HITL policy examples in the docs
  used fields that do not exist (`require_approval`, `timeout_secs`,
  `when = {...}`, `require = "telegram"`) and now show the real schema
  (`action`, `target`, `channel`, `require`), and `telegram.chat_id` is
  shown as a string, which is what the loader requires.

- **The live tier moved off GitHub Actions and onto a LAN-only box.**
  v0.14.0 added `.github/workflows/live-tier.yml`, a `workflow_dispatch`
  job on a self-hosted runner, to close the audit finding that the
  `#[ignore]`d suites and the `tests/live/` harnesses never ran. That
  shape was wrong for a **public** repo on two counts, and both are
  removed rather than mitigated:

  - A self-hosted runner attached to a public repo can be named by a
    fork's own workflow file (`runs-on: [self-hosted, <label>]`), so the
    fork-PR approval policy was the only control between an outside
    contributor and code execution on the runner.
  - The job read `PROXXX_E2E_PVE_URL` / `_TOKEN` / `_NODE` from
    repository secrets, which would have put a live PVE token on GitHub
    — readable by any job that runs on the runner.

  The runner has been unregistered. The live tier now runs on a LAN-only
  machine that is not a GitHub runner, driven by the maintainer with
  `tests/live/remote_run.sh`; credentials never leave the LAN and there
  is no inbound path from GitHub. Each run writes
  `tests/live/records/live-tier-<sha>.md`, so "the live tier passed for
  this commit" is still recorded rather than remembered.

  GitHub Actions keeps everything that does not need the cluster: the
  full hosted test suite, the script gates, and the signed release
  pipeline.

- **CLI flag renames on `audit export`, `events stream`, and `import` (#345).**
  Three subcommands previously declared a local `--format` argument whose
  clap id collided with the top-level global `--format <OutputFormat>`,
  causing clap to panic on downcast (`Mismatch between definition and access of 'format'`).
  - `proxxx audit export`: `--format` is now `--export-format <json|csv>` (default `json`, validated as a `ValueEnum`).
  - `proxxx events stream`: the local `--format` flag is removed; output now follows the global `--format` (`json` and `json-envelope` emit NDJSON, `table` and `plain` emit text).
  - `proxxx import`: `--format` is now `--source-format <raw|qcow2|vmdk|vdi|vhdx|vhd>` (validated as a `ValueEnum`).

### Added

- **Fuzz targets for the code that reads untrusted input.** `fuzz/` adds four cargo-fuzz targets with invariants: MCP path-segment shapes, terminal sanitization, guest spec parsing (print/parse stability) and PVE response deserialization. `.github/workflows/fuzz.yml` runs them weekly, on demand and on PRs that touch `fuzz/`, on a pinned nightly. Each ran for 60 s (about 185,000 to 212,000 inputs) with no finding, and each found a bug injected on purpose (`/` accepted by `Shape::Name`, C1 controls kept by `sanitize_display`) within that minute. This also gives the OpenSSF Scorecard Fuzzing check something to detect.

- **Per-metric TUI usage colour thresholds and critical `!` marker across Nodes, Guests, Fleet, and Dashboard views (#334).**
  `src/tui/theme.rs` now defines `UsageMetric` (`Cpu`, `Memory`, `Disk`), `UsageLevel` (`Ok`, `Elevated`, `High`, `Critical`), `USAGE_THRESHOLDS`, and the pure classifier `usage_level(metric, percent) -> UsageLevel` (plus `Theme::usage_span`), mapping CPU (`>= 60 %` Elevated, `>= 80 %` High, `>= 95 %` Critical) and Memory / Disk / storage (`>= 70 %` Elevated, `>= 80 %` High, `>= 90 %` Critical) to `Theme::SUCCESS` (green), `Theme::WARNING` (yellow), `Theme::ORANGE` (`Rgb(249, 115, 22)`), and `Theme::DANGER` (red, with a trailing `!` marker such as `96%!` or `1.8T/1.9T!`), all verified to have at least 4.5:1 WCAG contrast against `Theme::BG`. Applied to the Nodes table (`src/tui/views/nodes.rs`), Guests table and detail `Resources` panel (`src/tui/views/guests.rs`), Fleet cluster summary (`mem` and `storage` `used/total` cells while leaving the `cpu` core-count cell uncoloured) and Fleet guest table (`src/tui/fleet/view.rs`), and the Dashboard gauges and node cards (`src/tui/views/dashboard.rs`, replacing the old `Theme::gauge_color` 50 % / 80 % cut-offs so all views share the same thresholds). Cells with `max == 0` or missing data render with the default style and no `!` marker.

- **`proxxx token bootstrap` subcommand for zero-terminal-exposure API token onboarding over SSH (#330).**
  `proxxx [--profile X] token bootstrap [--userid <user>] [--tokenid <id>] [--role PVEAuditor] [--acl-path /] [--ssh-host <host[:port]>] [--secret-file <path>] [--rotate] --yes` (`src/cli/token_bootstrap.rs`, wired before `PxClient::new` in `src/cli/mod.rs`) loads the target profile (with `[defaults]` merged), refuses `read_only = true` profiles (`ReadOnlyRefusal`, exit code 8) and missing `--yes` before opening SSH, and connects over `SshPool` to `--ssh-host <host[:port]>` or the profile `url` host on port 22 under the profile's `known_hosts` policy (`tofu` / `strict`; `"off"` is refused; no `/cluster/status` or `hostname` check is run since no API token exists yet). Over SSH it checks `pveum user token list <user> --output-format json` (refusing an existing `<tokenid>` unless `--rotate` removes and recreates it), runs `pveum user token add <user> <tokenid> --privsep 1 --output-format json` and parses `value` directly into a `SecretString` while immediately zeroizing the raw `stdout`/`stderr` buffers and suppressing raw `stdout` on parse errors, grants `--role` on `--acl-path` via `pveum acl modify <acl-path> --tokens '<user>!<tokenid>' --roles <role>`, and persists the secret to `--secret-file <path>` -> `config.token_secret_file` -> macOS Keychain (`proxxx` / `<profile>/token_secret`, when compiled in) -> `<config_dir>/secrets/<profile>.token` (`config::write_secret_file_checked` opens the temp file with mode `0600` from the first byte inside a `0700` parent directory and renames atomically via `rename_durable`, refusing to overwrite an existing file or keychain entry without `--rotate`). If ACL assignment or secret storage fails after token creation, `token bootstrap` rolls back the token via `pveum user token remove <user> <tokenid>` and never prints the secret; on success it verifies the stored credential with `PxClient` (`GET /version` and `GET /nodes`), records write-ahead `"sent"` and outcome entries in `audit.db` (`user`, `tokenid`, `role`, `path`, `node`, never `value`), and returns the `token_id` / `token_secret_file` TOML lines without modifying `config.toml`.

- **Top-level `[defaults]` configuration table for sharing non-secret settings across named profiles (#331).**
  `load_config_from_path` (`src/config/mod.rs`) now supports an optional top-level `[defaults]` table that is validated and merged into the selected `[profiles.<name>]` entry on the `toml::Value` level before deserializing into `ProfileConfig`, so every profile reader (single-profile CLI/TUI, `--all-profiles` fan-out, `proxxx fleet`, `proxxx doctor`, and `SIGHUP` MCP reloads) observes the same merged configuration while preserving `[profiles.<name>]` as `ProfileConfig::profile_label()`. Merge rules are deterministic: any key set in the profile wins over `[defaults]`; sub-tables (`[defaults.ssh]`, `[defaults.pbs]`, `[defaults.telegram]`, `[defaults.reconcile]`) merge one level deep into `[profiles.<name>.<sub>]` while nested maps inside a sub-table (`ssh.hosts`, `ssh.guests`) are taken whole from the profile if present or else from `[defaults]`; and arrays (`[[defaults.policies]]`, `[[defaults.alerts]]`) are replaced wholesale when a profile defines its own array. Validation refuses `url` and all secret keys (`token_secret`, `token_secret_file`, `password`, `mcp_token`, `pbs.token_secret`, `pbs.token_secret_file`, `telegram.bot_token`, `telegram.bot_token_file`) in `[defaults]` with `ConfigError::InvalidValue` (exit code 3), enforces `#[serde(deny_unknown_fields)]` via `DefaultsConfigSchema` / `ConfigError::DefaultsParse` (exit code 3) naming `[defaults]`, and strips `[defaults]` with a warning when loading a flat top-level config with no active `[profiles.<name>]`.

- **`proxxx version --json` and `proxxx doctor` now report compiled Cargo features and the OS keychain credential store (#332).**
  `proxxx version --json` (`src/cli/mod.rs::build_version_payload`) adds two additive fields: `"features"` (array of active Cargo feature names, e.g. `["keychain"]`) and `"keychain": {"compiled": bool, "store": "macos-keychain" | "none"}`, derived from `config::keychain_store_info()` by inspecting `keyring::default::default_credential_builder().persistence()` (`UntilDelete` vs `EntryOnly`) rather than guessing from `cfg!`. `proxxx doctor` (`src/cli/doctor.rs`) adds a `"keychain"` check (without reading any secret) that reports `ok` (`"OS keychain store compiled in (macos-keychain)"`) when a persistent store is compiled in and `warn` (`"no keychain store in this build (Linux): use token_secret_file or env"`) otherwise.

### Fixed

- **An audit opener that loses the race to create the key uses the winner's key instead of refusing to start (#482).** On a fresh audit directory, an opener that found no key and then waited for the database lock could see rows that another opener had signed in the meantime, and refused with "refusing to start a forged chain" although the key was on disk. The v0.15.0 release run hit it in CI (8 writers, the loser counted 120 rows). Rows next to a key that now exists are read with that key; rows with no key at all are still refused.
- **An audit write waits up to 30 s for another writer's lock instead of 5 s (#468).** Each append is a rollback-journal transaction with an fsync, and SQLite's busy handler is not fair: with 8 concurrent writers on Linux one connection could wait more than 5 s, which failed the audit concurrency tests on CI (1 of 20 idle runs, 4 of 20 under load) and, since #406, refuses a mutation whose write-ahead row cannot be written. At 30 s the same runs failed 0 of 20 and 0 of 20.
- **The TUI shows a failed action on screen instead of only in the log file (#380).** A start, stop, restart, snapshot, delete, migrate, guest command, disk move or disk resize that the API refused was written with `error!` to the log file and nothing else, so the operator had to guess from the guest status. Each failure now also reaches the red status-line banner, naming the action, the guest and the error (for example `start 200 failed: ...`); so do a failed task-log fetch and a migrate refused because the guest type is unknown. Actions run through the operation queue already recorded their outcome in the queue view.
- **`logs tail --no-follow` without `--since` shows the last 200 lines per node instead of the whole journal (#392).** The command asked journalctl for everything when no window was given: measured on a PVE 9.1.1 test node, `logs tail --node pve-test-1 --no-follow` printed 337,252 lines. A new `--lines N` (`journalctl --lines N`) bounds any run, and a non-follow run with neither `--since` nor `--lines` now defaults to 200 lines per node. A follow is unchanged unless `--lines` is given. The `--since` help no longer claims there is no history without it, which was true only in follow mode.
- **The HITL guide, the error reference and the production checklist describe what the code does (#382).** Checked against the code: the HITL guide's test step ran `proxxx delete 100 --yes` as if a `delete` policy intercepted it, but CLI `delete` and the other single-guest destructive commands never consult policies (they run with `--yes`; `--secure` refuses them); the guide now lists which names a policy matches on each surface (CLI batch verbs, TUI actions, MCP tool names) and tests with `stop`. The `[telegram]` example lacked `allowed_approvers`, without which every callback is refused. The audit section quoted log lines that are never written; it now says where each record is (HMAC audit log, `hitl_pending.db`, the daemon log, the Telegram chat). The error reference listed TUI modals and toasts that do not exist; it now lists the banners the TUI shows. The production checklist's rollback read a `cache_path` key `doctor` does not output, so it deleted nothing, named the cache `cache.db` (it is `<profile>_state.db`), and its backup table left out `known_certs/`, `known_hosts`, `secrets/` and `schedules.toml`. The CLI reference now lists `daemon serve --no-reconcile` / `--no-converge`, and a code comment no longer claims every write goes through the HITL gate.
- **A batch operation that needs approval exits 9 only when an approval request was actually sent (#360).** It exited 3, the configuration-error code, and reported `pending_hitl` even when no request existed: with no `[telegram]` section it made up a transaction id (measured with a mock cluster: `{"status": "pending_hitl", "txn_id": "f1261c11ca2ff210"}`, exit 3, nothing recorded), and when the Telegram send failed it only logged the error and left the request pending forever. Now a guest whose approval request cannot be sent is reported as an error ("the operation was not run"), the pending row is closed, and the batch exits 2; a request that was sent exits 9, a new documented code. A failure on another guest still wins (exit 2).
- **The global `--format json` gives JSON for commands that have their own output flag (#362).** `explain`, `describe`, `cloud-img list`, `schedule list`, `backup-verify`, `heatmap`, `anomaly`, `upgrade-check`, `accounting`, `import`, `gpu-inspect`, `state export|diff|apply`, `reconcile run|converge` and `mcp tools` ignored it and printed text with exit 0, so `proxxx --format json describe | jq` failed (measured on a PVE 9.1.1 test cluster for nine of them). Under `--format json` or `json-envelope` they now print JSON unless their own flag (`--output`, `--print`, `--json`) is given on the command line, which still wins. A test runs thirteen of them with `--format json` and parses the output.
- **A destructive MCP call is reported as pending only when its approval request was sent (#458).** With no `[telegram]` section the MCP dispatch made up a transaction id and told the agent "Action intercepted by HITL policy ... Transaction: <id>", although nothing was recorded or sent; a test pinned that as the intended outcome. When Telegram was configured, the send result was ignored (`let _ = ...`), so a failed send also read as pending. Now the call is refused (`isError`) with the reason when there is no channel, when the gateway cannot be set up, or when the send fails; in the last case the recorded request is closed as failed. The channel is checked before any PVE call. The CLI batch path had the same flaw (#360).
- **`logs tail` no longer drops journal lines (#449).** Each node's SSH callback forwarded lines with `try_send` into a 32-slot merge channel and dropped the line when it was full; a `--no-follow` window arrives in one burst. Measured on a PVE 9.1.1 test cluster, one hour from two nodes: 29 to 151 lines of about 800 were dropped per run, so four runs over the same fixed window printed 657, 733, 764 and 549 of its lines. The callback now waits for room (`block_in_place` + `blocking_send` on the CLI's multi-thread runtime), which holds the SSH stream back instead; four runs now print the same 810 lines (identical hash). Memory stays bounded by the channel. On a current-thread runtime, where blocking is not allowed, a dropped line is counted and reported on stderr.
- **The fleet view keeps one connection per cluster instead of logging in again every 10 s (#379).** Each poll cycle built a new client per profile: a password profile logged in again each cycle (360 ticket logins an hour per cluster in the PVE auth log), a new TLS pool was set up, and the "Connected to ..." line was logged each time; `/nodes` was also read three times per cycle. Clients are now built once per profile and reused (the client renews its own ticket), a cycle that fails drops the profile's client so the next one reconnects, and `/nodes` is read once per cycle. Measured with a mock cluster over three cycles: 1 login and 3 `/nodes` reads, against 3 and 9 before.
- **An empty identifier is a usage error (exit 2) before any request (#363).** An id passed as `""` built paths such as `/pools/` and `/access/users//token`. Measured on a PVE 9.1.1 test cluster: `pool show ""` and `backup-jobs show ""` printed a fabricated all-empty object with exit 0, `firewall-cluster group rules ""` and `ipset cidrs ""` printed `(no results)` with exit 0, and `storage-defs show ""`, `acme plugin show ""` and `token list ""` failed with a misleading parse or PVE 500 error. Every positional string argument (the 78 identifiers in the command tree: pool, job, storage, group, user and token ids, node names, ACL paths, ...) now refuses an empty value at parsing. Options are unchanged (`--comment ""` still clears a comment), and so is the trailing command of `exec`.
- **`upgrade-check` reads every node's version and does not pass when it could not check (#355).** It read `/version` once, which answers for the node serving the API call, so a cluster with that node on 9.x and another on 8.x passed `--target 9`; a target with no rules (`banana`, `10`) reported "no findings" with exit 0; and a version probe that failed was skipped. Measured on a PVE 9.1.1 test cluster with one node offline: `--target banana`, `--target 10` and `--target 9` all exited 0. Now each node is read through `/nodes/{node}/version` and a node behind the target is a block finding; a node that cannot be read makes the result `indeterminate` (exit 1, listed in the JSON `indeterminate` array); a target with no checks is a usage error (exit 2) naming the supported targets.
- **`heatmap` times each node and reports a down node as `down` (#353).** Every row timed `/version`, which the configured node answers, so all rows measured the same node and a node that was down showed green. Measured on a PVE 9.1.1 test cluster with `pve-test-3` offline: `pve-test-3 /version 1.8 green Ok`. Each row now times `/nodes/{node}/time`, which the node itself answers; a node that does not answer is `down` with the error, and the command exits 1.
- **`tasks --limit N` returns the N newest tasks (#354).** `/cluster/tasks` comes grouped by node, not by time, and proxxx truncated it as received. Measured on a PVE 9.1.1 test cluster: `tasks --limit 5` returned five tasks from `pve-test-2` while the five newest alternate between the two nodes. The client now sorts the list newest first (the TUI task view uses the same call). `/cluster/tasks` holds 50 tasks on PVE 9.1, so a larger `--limit` now prints a note on stderr pointing to `--node`, instead of returning fewer rows without a word.
- **Storage rows carry their node, and `describe`, `watch` and `ls storage` stop mixing nodes up (#352).** `/nodes/{node}/storage` rows have no node, and proxxx kept none, so a node-local storage present on two nodes gave two indistinguishable rows. Measured on a PVE 9.1.1 test cluster: `describe` printed `local` and `local-lvm` as `(shared)` (both are node-local; `shared` was inferred from the node count) with `local-lvm` at 25.9 %, the first node's value; `ls storage` printed two `local-lvm` rows with no node and left out the offline node's pools without a note; `watch -t storage-local-lvm` judged whichever node's row came first. Now every row has `node`; `describe` uses PVE's `shared` flag and sums usage across nodes for node-local storage (`local-lvm 13.0% on 2 nodes (local)`); `ls storage` notes the nodes it skipped; `watch` takes `storage-<id>@<node>` and refuses an ambiguous node-local target instead of picking a node, and reports a pool of size 0 instead of never matching.
- **`ha status` reports the HA manager state PVE returns (#350).** The type expected top-level `master` / `mode` / `node_status` with every field defaulted; PVE nests the CRM state under `manager_status` and adds `lrm_status` and `quorum`, so the real response parsed as empty. Measured on a PVE 9.1.1 test cluster: `ha status` printed `{"master": "", "mode": "", "node_status": {}}` with exit 0 while the CRM master was `pve-test-1`. It now prints `manager_status` (`master_node`, `node_status`, `service_status`), `lrm_status` per node and `quorum`. `manager_status` is required, so a response without it is a parse error instead of an empty success. The TUI HA console shows the master node and its LRM mode.
- **`node-system <node> journal` works, and its flags match the API (#351).** PVE sends the journal gzip-compressed even though proxxx does not ask for it, and the HTTP client is built without decompression, so the compressed bytes reached the JSON parser: on a PVE 9.1.1 test cluster every call failed with "response parse error ... expected value at line 1 column 1" (measured: `content-encoding: gzip`, body starting `1f 8b`). Response bodies marked gzip are now decompressed for every endpoint, under the same 32 MiB limit as uncompressed bodies, using the `flate2` already in the dependency tree. `--since` / `--until` take UNIX epoch seconds, as PVE requires (the help promised relative times PVE rejects), and `--service` is gone: PVE's journal endpoint has no unit filter and answered 400; `syslog --service` filters by unit.
- **`anomaly` judges each node against its own history, so it can fire on a small cluster (#356).** It computed a z-score across the nodes of one snapshot; n values cannot score above sqrt(n-1), so the default threshold of 3 needed at least 10 nodes (3 nodes: at most 1.41, measured on a PVE 9.1.1 test cluster), and an offline node joined the population as cpu 0 / mem 0. The module doc described an RRD baseline the code did not have. Each online node's current CPU and memory are now compared with its own RRD day history. Because an idle node's history barely moves (a CPU change from 2.5 % to 4.8 % scored z = 5 on the test cluster), an anomaly also needs a change of at least `--min-cpu-delta` (default 10 points) or `--min-mem-delta` (default 5 points); these defaults are a judgement call. Offline nodes and nodes with too little history are listed as skipped, and exit 1 when any node was skipped.
- **The TUI keeps the guests of a node whose fetch fails, marked stale, and does not cache an incomplete cycle (#378).** Each refresh replaced the guest list with the guests of the nodes that answered, so one transient error on a node made its guests vanish from the dashboard and the guest table, and the truncated list was saved to the state cache that seeds the next start. Guests of a failed node now stay at their last-known values; the guest view names the stale nodes in its title and marks their rows (`pve2?`). A cycle in which any node's guest or storage fetch failed is not written to the cache. The storage list still loses a failed node's pools for that cycle, since storage entries carry no node.
- **A profile-only config with a top-level section that no profile reads is refused (#440).** With `[profiles.<name>]` tables and no top-level `url`, a profile is built from `[profiles.<name>]` and `[defaults]` only, so a top-level `[[alerts]]`, `[telegram]`, `[ssh]`, `[pbs]`, `[[policies]]` or misspelled key was dropped without a word: `alerts watch` reported "no [[alerts]] rules configured" while the file had rules, and `verfy_tls = false` loaded where a flat config rejects it. Loading now fails with exit 3, naming the keys and where to move them (`[defaults.*]` or `[profiles.<name>.*]`). A config that also has a top-level `url` (a flat profile next to named ones) is unchanged. The configuration docs, which showed these sections at the top level only, now say where they go in each layout.
- **`backup-verify` reports `unknown` when it cannot check, instead of `missing` (#357).** A backup storage that could not be read was skipped, so the guests whose backups live there were reported "no backup found" with an age of 0, and a node whose guest list failed was left out without a word. Measured on a PVE 9.1.1 test cluster with an unreachable PBS storage and an offline node: two guests `missing`, the node absent. They now come out as `unknown`, naming the storage or node error, with no age; exit 1 as before. Only backup-capable storages are read, once per node instead of once per guest.
- **`logs tail` exits 1 when a node fails, and reports the failure on stderr instead of as a log line (#364).** An unknown node, an offline node and a `--since` value journalctl rejects all ended with exit 0, the error printed as one more log record (`{"timestamp": "", "node": "nosuch", "text": "[ssh error] ..."}` in JSON). Measured on a PVE 9.1.1 test cluster: each of these now exits 1 with `logs tail: node <n> failed: ...` on stderr and no error record on stdout; with one node of three down, the other two nodes' lines are printed and the exit is 1, as `ls --all-profiles` does for a failed profile. Remote stderr also goes to stderr. Stopping a follow with Ctrl-C ends the per-node streams instead of waiting for them.
- **Human-readable CLI output removes control sequences from cluster strings (#437).** #365 covered `--format table` and `plain`; about 150 direct `println!` / `print!` calls under `src/cli` (`describe`, `logs tail`, `state diff` / `apply`, `reconcile`, `events`, `explain`, and others) still printed interpolated cluster strings as they came. Measured: a pool id carrying an OSC 52 clipboard-write sequence reached `state diff` output unchanged. These calls now go through `outln!` / `out!`, which remove control characters line by line and keep line breaks and tabs. JSON and TOML documents printed for machines are unchanged, since removing characters would change the data; the `init` wizard keeps its colours and sanitizes the values it interpolates. A test fails when a new bare `println!` appears under `src/cli`.
- **Node, storage, role and realm lists come back in a stable order (#438).** PVE returns `/nodes`, `/nodes/{node}/storage`, `/storage`, `/access/roles` and `/access/domains` in no stable order, and proxxx printed them as received. Measured on a PVE 9.1.1 test cluster, four runs in a row: `access roles`, `access realms`, `ls nodes`, `ls storage` and `storage-defs list` changed row order between calls, so a script diffing two runs saw changes that did not happen. The client now sorts these lists by their identity (`node`, `storage`, `roleid`, `realm`), which also steadies the TUI and MCP views built on them; six runs of each are identical. Lists that were stable over the same runs (`access users`, `access acl`, `ls guests`, `tasks`, which is newest first by design) are unchanged.
- **`get` commands no longer invent values for option keys PVE did not return, and a firewall-options converge no longer turns ebtables off (#349).** PVE returns only the keys that are set (an untouched cluster's firewall options are just `{"digest": ...}`), and proxxx printed every absent key as `false`, `0` or `""`. Measured on a PVE 9.1.1 test cluster: `firewall-cluster options get` showed `ebtables: false` (PVE default on), `firewall-guest <vmid> options get` showed `macfilter: false` and `ndp: false` (both on by default), and `cluster-config get` showed `max_workers: 0` and dropped `allowed-tags`. These option types now hold `Option` values and leave unset keys out of the output; `acme plugin list` reads `validation-delay` (it read `validation_delay`, so the value was always 0). The state model had the same flaw with a worse effect: an unset `ebtables` was exported as `false` and left out of the file, and every firewall-options update sent `ebtables=0`, so a converge that changed a policy also turned L2 filtering off. `[firewall_options]` keys are now optional: export writes only the keys PVE returned, the diff compares only the keys the file sets, and apply sends only those. Older state files load unchanged, with keys they do not mention left unmanaged.
- **`daemon serve` runs without `[[alerts]]` or `[telegram]` (#372).** The alerts and HITL components refuse to run without their section, and the supervisor treats a component that exits as a failure, so a config without either (for example the unmanned `auto_converge` setup in the README) made the daemon exit 1 at startup and stopped schedule and reconcile with it; under systemd it restarted in a loop. alerts and HITL now start only when configured, as reconcile already did, and the startup message names the components not started and why. With nothing to run (`--no-schedule` and no optional section) the daemon refuses to start and lists the reasons. Adding a section later needs a restart, not a `SIGHUP`.
- **A storage update sends what changed and converges (#370).** The update sent `content`, `nodes`, `disable`, `fingerprint` and `username` whatever the diff said, never `shared`, `pool` or `server`, and never `delete=`. Measured on the previous code: turning `shared` on sent `content`, `nodes` and `disable=0` and reported Applied; clearing `nodes` sent neither `nodes` nor `delete`; changing `path` reported Applied. Each of these was re-applied on every reconcile tick. The update now sends exactly the fields that differ, clears emptied fields and turned-off flags through `delete=`, and refuses a change to `type`, `path`, `export`, `datastore`, `vgname` or `thinpool` (which `PUT /storage/{storage}` does not accept on PVE 9.1) with a "recreate the storage" error before any request. `content` and `nodes` are compared as sets, so a declared value in another order than PVE's is no longer drift.
- **SIGTERM and Ctrl-C stop long-running commands whenever they arrive (#366).** Each wait installed its own signal listener, and a listener only sees signals sent after it exists; once the first one was installed the default terminate action was gone, so a signal that arrived while nothing was listening was dropped. `alerts watch` listened only while fetching a snapshot and ignored SIGTERM and Ctrl-C during the sleep between ticks (measured: still running 8 s after the signal, every time); `systemctl stop` waited for SIGKILL and the final dedup flush never ran. One listener per process now sets a shutdown flag that every wait sees, including one that starts later; the tick sleep of `alerts watch` ends on it. `mcp serve-http` ended its graceful shutdown only when every client disconnected, so a connected SSE client (`GET /mcp`) kept the process alive; SSE streams now end on shutdown, and open requests get 10 s before the server exits anyway. `daemon serve` counted a component that stopped because of the signal as a component failure and could exit 1 on a clean stop; it now waits up to 5 s for its components to finish and exits 0.
- **`state diff`, `state apply` and `reconcile` refuse a state file that declares no resource family (#371), and `state export` declares the families it exported even when they are empty.** An empty file, a comment-only file or one with only `[meta]` manages nothing, so `state diff` printed "no changes" and exited 0: a truncated or emptied file passed a CI drift gate. Such a file is now refused with a message that says how to declare a family. `state export --resource pools` on a cluster without pools wrote only `[meta]`, so the file did not manage pools and a pool created afterwards was never reported (measured: `state diff` said "no changes" with exit 0 after a pool appeared). Exported families with no members are now written as `key = []` (TOML; JSON output is unchanged), and the diff reports the new pool with exit 2. Files with members are written byte for byte as before. A hand-written or older exported file with only `[meta]` must gain a family line, e.g. `pools = []`.
- **The state pre-flight gate and the unmanned change cap count only the changes that will run (#369).** Without `--prune` (or with `converge_prune` off) apply skips every delete, but the gate assessed them anyway: one undeclared non-empty pool made every `auto_converge` tick refuse with "needs human review", so nothing was applied, and `state apply` without `--prune` exited 6 for a delete it would not perform, which pushed operators to `--allow-risk` and disabled the gate for the changes that did run. Skipped deletes also counted toward the batch size and toward `max_unmanned_changes`. The gate now assesses, and the cap counts, only what apply would send; the interactive prompt no longer asks about a delete that will be skipped. `--dry-run` now runs the gate too (on `state apply` and `reconcile converge`), so the rehearsal exits 6 where the real run would instead of 0.
- **Two threads creating the same private file no longer share a temp file.** The audit key (`audit.key.<pid>-<nanos>.tmp`) and every file written through the private-write helper (`.<name>.<pid>.tmp`: HMAC key, config from `init`, `schedules.toml`, TLS pins, freeze lock, token secret files) used temp names that are not unique inside one process. Two threads creating the audit key at the same moment failed with `File exists` (59 of 300 runs of the concurrent first-use test); two threads writing the same file through the helper made one remove the other's temp file and fail (300 of 300 runs of the new 16-thread test). Temp names now carry a process-wide counter. A tracing capture test that lost its debug line in 31 of 300 runs (tracing-core caches a callsite as disabled when only one dispatcher is registered) now keeps a second dispatcher registered; both tests pass 300 of 300.
- **`read_only` and `[reconcile]` follow a `SIGHUP` reload (#373).** The client checked a copy of `read_only` taken at startup and the reconcile loop took its settings by value, so setting `read_only = true` or `auto_converge = false` and sending `SIGHUP` (the obvious emergency brake) did not stop writes. Long-running commands now attach their reloadable config to the client, which reads `read_only` from it before every write, and the reconcile loop re-reads `[reconcile]` and `read_only` on every tick. `rate_limit` is restart-only, contrary to what the watcher's comment said; the reload log line now names the settings that need a restart.
- **`cargo test` no longer writes into the developer's real cache and data directories (#386), and the startup line names the real log file (#420).** The HITL queue tests created `hitl_e2e_queue_test_state.db` and `hitl_e2e_unclassified_queue_test_state.db` in `~/Library/Caches/proxxx` (`~/.cache/proxxx` on Linux), and every e2e test that spawns the binary appended to the real `proxxx.<date>.log`. The state cache now honours `PROXXX_CACHE_DIR` and the log files `PROXXX_LOG_DIR`, and `.cargo/config.toml` points both into `target/` for every process cargo starts. Tests fail if that wiring is lost, and CI fails the build when a test run leaves anything in the user cache, data or config directory. The audit rows signed with the real key were already closed by #406, but a `doctor` test still opened the real `audit.db` and `audit.key` (on a fresh Linux home it created both); it now uses a temp audit directory. Over the whole suite, a before/after snapshot of the real directories on macOS and the new CI check on Linux both show nothing written. The startup line used to name `proxxx.log.<date>`, a file that never exists; it now names `proxxx.<date>.log`, derived from the same prefix and suffix the appender uses.
- **Concurrent audit writers no longer break the chain (#368).** Reading the previous MAC and inserting the new row now run in one `BEGIN IMMEDIATE` transaction, so two writers on the same `audit.db` (the daemon and a CLI process, or two CLI processes) cannot chain onto the same predecessor. Measured before the fix: 8 writers with their own connection, 50 appends each, broke the chain in 5 of 5 runs. A writer that cannot take the lock within the 5 s busy timeout, or cannot read the previous MAC, fails instead of starting a new segment; because the write-ahead record is fail-closed, that refuses the mutation it guards.
- **`audit rotate-key` is all-or-nothing (#367).** It used to rename the primary key away before relabelling the rows, so a locked database left the history unverifiable. Rotation now takes the write lock first, writes the retired copy (0600), relabels the rows and installs the new primary inside the transaction, and commits; any failure leaves the primary key byte-identical and removes the retired copy. Retired keys are now resolved beside the key of the logger that opened the database, so a log in an explicit directory verifies its rotated rows.
- **Several proxxx processes starting at once on a fresh audit directory no longer delete the audit key.** On first use a process checked for the key, another one created it and signed rows with it, and the first then saw those rows, concluded the chain was forged and removed the key, leaving every row unverifiable. Measured with 40 parallel CLI writers on an empty directory: on the previous code `audit verify` reported `tampered`. The rows-without-key check now runs before any key exists, the key is published atomically (temp file + `hard_link`, so readers never see a partial key) and a process that loses the race uses the winner's key; nothing deletes a key any more.

- **Mutating PVE requests (`POST`, `PUT`, `DELETE`) are no longer retried after request timeouts, `502`, `504`, or `503` without `Retry-After`, preventing duplicate execution (#348).**
  `PxClient::send_with_retry` (`src/api/client.rs`) previously shared a single retry policy across `get`, `post`, `put`, and `delete`, retrying `is_retryable_status` (`503`, `429`, `502`, `504`) and `is_retryable_error` (`e.is_timeout() || e.is_connect()`) up to 4 times. A slow `vzdump`/`clone`/firewall `POST` that exceeded the 30 s timeout or received a reverse-proxy `502`/`504` while PVE continued processing was sent again, producing duplicate tasks or spurious `"already exists"` errors. `send_with_retry` now takes an explicit `RequestIdempotency` (`Idempotent` for `GET`, `Mutation` for `POST`/`PUT`/`DELETE`): `GET` keeps its existing retry policy unchanged, whereas `POST`, `PUT`, and `DELETE` retry **only** when the request provably was not processed by PVE — (a) a connect error that is neither a timeout nor a TLS/certificate failure (`is_connect() && !is_timeout() && !is_tls_or_cert_error(e)`), (b) HTTP `429`, or (c) HTTP `503` **with** a `Retry-After` header (in addition to reactive `401` re-auth). When a mutation fails on a timeout (`ApiError::Transport`, exit code `1`) or `502`/`504`/`503` without `Retry-After` (`ApiError::RateLimited`, exit code `7`), the error message and `ApiError::actionable_hint` explicitly state that PVE may still have executed the mutation and advise checking `proxxx tasks` or the PVE task log before retrying, while keeping the write-ahead `"sent"` audit entry written once per logical mutation.

- **Node-level SSH (`proxxx perms`, `proxxx gpu inspect`, `proxxx logs tail`, and `proxxx patch apply`) now falls back to the profile `url` host on port `22` for the API-answering node with remote `hostname` verification, while keeping `<node>:22` with an actionable `hosts` hint for other cluster members (#328).**
  `SshConfig::resolve_host` (`src/config/mod.rs`) previously fell back directly to `(node.to_string(), 22)` whenever `ssh.hosts` had no entry for `node`, causing standalone installs whose PVE node name (e.g. `pve` or `opti7`) is not resolvable in client DNS to fail with `failed to lookup address information`. `SshConfig::resolve_host_with_status` and `SshPool` (`src/ssh/mod.rs`) now enforce a three-step resolution order: (1) an explicit `ssh.hosts[node]` entry (`SshHostSource::ExplicitHosts`) always wins without querying `/cluster/status` (supporting IPv4, bracketed IPv6 `[::1]:2222`, and DNS names, defaulting to port `22`); (2) when `ssh.hosts[node]` is absent, `SshPool` queries `/cluster/status` at most once per pool (`tokio::sync::OnceCell`) and falls back to the host parsed from the profile's `url` on port `22` (`SshHostSource::ApiUrlFallback`) **only** if `node` is the node answering the API (`type == "node"` with `local == 1`, or the sole node of a standalone install); (3) for every other node of a cluster — or if `/cluster/status` fails or no API gateway is attached (logged at `debug!`) — `SshPool` falls back to `(node.to_string(), 22)` (`SshHostSource::NodeNameFallback`) without an identity check, and if that connection fails with a name-lookup error, the error adds `hosts = { <node> = "<ip>:22" }`. On sessions opened via the profile `url` fallback (`SshHostSource::ApiUrlFallback`), `SshPool` runs `hostname` before the first command and refuses the connection if the remote short hostname does not match `node` (guarding against a profile `url` that points at a VIP or load balancer). All four `SshPool::new` call sites (`cli::access::execute_perms`, `cli::gpu_passthrough::execute_gpu_inspect`, `cli::logs::execute_logs`, and `cli::patch::execute`) now wire the profile `url` and API gateway into the pool.

- **macOS Keychain integration now links the persistent `apple-native` Security.framework store instead of `keyring`'s in-memory mock store, Linux builds omit the mock store entirely, and PBS/Telegram keychain lookups now try `<profile>/<item>` before flat `<item>` (#319).**
  `Cargo.toml` previously declared `keyring = { version = "3", optional = true }` with no platform backend feature, causing `keyring 3` to compile its `EntryOnly` in-memory mock credential builder on every platform so `keyring_get` / `keyring_get_scoped` could never read an OS keychain item. `keyring` is now declared under `[target.'cfg(target_os = "macos")'.dependencies]` with `features = ["apple-native"]` (keeping `keychain = ["dep:keyring"]` in `default` so `--no-default-features` remains accepted everywhere while Linux musl/gnu builds do not pull `keyring` or D-Bus and never silently query a mock store). In addition, `PbsConfig` and `TelegramConfig` now carry the resolved `profile_name` stamped by `load_config_from_path` and query `<profile>/pbs_token_secret` (then `pbs_token_secret`) and `<profile>/telegram_bot_token` (then `telegram_bot_token`), matching PVE's `<profile>/token_secret` and `<profile>/password` account precedence.

- **Missing-secret errors across PVE (`token_secret`, `password`), PBS (`pbs.token_secret`), and Telegram (`telegram.bot_token`) now list every source consulted in order and why each did not yield a secret (#329).**
  `ProfileConfig::resolve_token_secret`, `ProfileConfig::resolve_password`, `PbsConfig::resolve_token_secret`, and `TelegramConfig::resolve_bot_token` (`src/config/mod.rs`) previously returned a generic static hint when no secret was found. They now record the non-secret outcome of each source actually consulted in precedence order — CLI flag (`not given` or `empty`), environment variable (`unset`, `empty`, `exceeds 64 KiB cap`, or `invalid UTF-8`), inline TOML key (`absent` or `empty`), secret file (`not configured`, or the user-written and tilde-expanded path with `missing`, `bad permissions`, `empty`, or `read error`), and keychain (service `proxxx`, every account queried in order such as `pve-test/token_secret` and `token_secret`, and each account's result: `not found`, `empty`, `access denied`, or `no keychain store in this build`) — while preserving exit code `1` and never including any secret value.

- **Full-screen subcommands (`proxxx fleet`, drill-in `tui::run`, and `proxxx serial`) now suppress `stderr` `tracing` log lines while the alternate screen is active (#333).**
  `src/main.rs` previously checked `cli.command.is_none()` at startup and kept an unconditional `stderr` `tracing` layer enabled for every CLI subcommand, causing `INFO proxxx::api::client: Connected to ...` and background poll diagnostics to draw directly over `proxxx fleet`, its drill-in single-profile TUI, and `proxxx serial`'s raw-mode alternate screen. A depth-counted runtime gate (`util::term_gate::TermGate` + `GatedStderrMakeWriter`) now wraps the `stderr` `tracing` layer while leaving the rotating file layer untouched: `TerminalGuard::install` (`src/tui/terminal_guard.rs`), the `proxxx fleet` drill-in loop (`src/main.rs`), and `execute_serial` (`src/cli/console.rs`) acquire an RAII `TermGateGuard` before entering raw mode / `EnterAlternateScreen` and release it after `LeaveAlternateScreen` (or on early `?` return / unwinding panic), so CLI commands that never enter a full-screen view keep logging to `stderr` while full-screen views write logs only to the rotating file.

- **`proxxx doctor` now probes PVE 8+/9 connectivity and authentication through `PxClient`, validates Telegram `getMe` responses (`2xx` and `"ok": true`), and probes PBS through `PbsClient` (#321, #411).**
  `src/cli/doctor.rs` previously called an unauthenticated `probe_url` helper on `/api2/json/version` and decoded the body as JSON: because PVE 8+/9 and PBS return HTTP `401` to anonymous `/version` requests, JSON decoding failed, `connectivity` was reported as `fail`, and the `auth` check was skipped (`#321`). In addition, `probe_url` treated any JSON body as success, so an invalid Telegram bot token returning `401 {"ok":false,"description":"Unauthorized"}` was reported as `ok` (`#411`), and the PBS probe hardcoded `skip_tls = true` regardless of `pbs.verify_tls`. `doctor` now deletes `probe_url` and: (1) builds `PxClient::new(cfg.clone(), None).map(PxClient::with_single_attempt)` and calls `get_api_version()` + `get_nodes()` (reporting `connectivity` `ok` with `PVE reachable, version <v>` and `auth` `ok` on valid credentials; `connectivity` `ok` with `PVE reachable (HTTP 401|403)` and `auth` `fail` when matched against typed `ApiError::Unauthorized | Forbidden`; `connectivity` `fail` and `auth` `warn` `skipped` on transport/TLS errors; and when `PxClient::new` itself fails, `auth` `fail` `client init failed: ...` paired with `init_wizard::send_anon_version_probe` treating any HTTP response as reachable without decoding the body); (2) calls `TelegramGateway::get_me` and reports `ok` only when HTTP `2xx` **and** `"ok": true` in the `getMe` payload, otherwise `warn` with the HTTP status code and Telegram's `"description"`; and (3) probes PBS via `PbsClient::new(pbs.clone(), None)` + `version()` (honouring `pbs.verify_tls` and the three-way `ok` / reachable with rejected credentials / unreachable mapping under `Warn` severity).

- **Cross-profile fan-out (`ls <kind> --all-profiles` and `find <vmid>`) now exits `1` when any profile fails (#322), and `token_secret_file` (PVE and PBS) plus `doctor`'s `ssh_key` check now expand `~` via a single shared helper (#324, #325).**
  `src/cli/mod.rs` previously returned exit code `0` unconditionally from `ls <nodes|guests|storage> --all-profiles` even when every profile failed with a `ProfileRowPayload::Error` row, and `find <vmid>` checked only `rows.is_empty()` while `fanout_find_vmid` labelled error rows as `"(unknown)"` instead of the failing profile's name. `ls --all-profiles` now exits `1` whenever any row is an error row (still printing all data and error rows in both table and JSON modes) and `0` when all profiles succeed; `find <vmid>` preserves each failing profile's name on error rows, exits `5` (`NotFound`) only when every profile answered without error and none owns the VMID, and exits `1` (including the error rows) when any profile failed. For `#324` and `#325`, the three duplicate tilde helpers (`src/config/mod.rs::expand_tilde`, `src/cli/vm.rs::expand_tilde`, and `src/cli/init_wizard.rs::expand_tilde_str`) are consolidated into `proxxx::util::path::expand_tilde` / `expand_tilde_with_home`, which expands `"~"` and `"~/..."` while leaving `"/abs"`, `"rel"`, and `"~user"` untouched, and is now wired into `ProfileConfig::resolve_token_secret`, `PbsConfig::resolve_token_secret`, `TelegramConfig::resolve_bot_token`, `SshConfig`, `CloudInitProfile::from_toml_file`, `init --interactive`, and `proxxx doctor`'s `ssh_key` check, with diagnostic and error messages preserving both the user-written `~/...` path and the expanded path.

- **Cache paths, `state export`, audit logs, metrics, and MCP notifications now use the resolved profile name instead of falling back to literal `"default"` when `--profile` is omitted, and `state apply` / `reconcile converge` refuse profile mismatches (#346).**
  `load_config` already populated `ProfileConfig::profile_name` from `--profile`, `default = "<name>"`, or a single `[profiles.<name>]` section, but ten downstream call sites (`app::cache::get_db_path`, `cli::state::execute_state`, `cli::reconcile::execute_reconcile`, `cli::daemon::reconcile_loop`, `cli::monitoring::execute_alerts`, `cli::watch::execute_watch`, `cli::execute` `Replay`, `tui::run` / `app::update` timeline actions, `audit::redact_params_json`, `metrics::render_metrics`, and `mcp::notifications::spawn_reconcile_watcher`) took the raw CLI `--profile` `Option<&str>` and fell back on `.unwrap_or("default")`. Every call site now goes through the single `ProfileConfig::profile_label(&self) -> &str` accessor, which returns `"default"` only for a flat top-level `config.toml` with no `[profiles]` section. Note: existing `default_state.db` cache files written when a named profile was selected via `default = "<name>"` (without `--profile`) are no longer read for that profile and are automatically rebuilt under `<profile>_state.db`. In addition, `ClusterState::check_profile_match` now compares a declared state file's `[meta] profile` against the resolved target profile: `state diff`, `reconcile run`, and `reconcile watch` emit a warning to stderr on mismatch, while `state apply` and `reconcile converge` refuse before contacting PVE with `ConfigError::ProfileMismatch` (exit code 3) unless `--allow-profile-mismatch` is passed.

- **`proxxx perms` parses JSON output on PVE 9 and rejects unknown users with exit 5** (#347).
  `execute_perms` now invokes `pveum user permissions --output-format json -- <userid>`
  and deserializes the `{path: {privilege: 0|1}}` map with `serde_json` instead of
  the legacy PVE 7/8 text scanner, which silently returned `paths: []` on PVE 9's
  box-drawn table. Non-JSON output is rejected as an error with the first 200
  characters of stdout, and user existence is verified via `GET /access/users/{userid}`
  so an unknown user returns a typed `ApiError::NotFound` (exit code 5) while an
  existing user with no privileges returns `paths: []` (exit code 0).

- **Guest-targeted CLI commands now exit `5` (`NotFound`) when a VMID is absent from the cluster (#358).**
  `cli::common::find_guest` and `find_guest_full` (plus `metrics vm|ct`,
  `watch -t vm-<id>`, `snapshot`, and `console vnc`) previously returned
  untyped `anyhow!` errors when a guest could not be found, falling
  through to generic exit `1`. They now treat
  `GET /cluster/resources?type=vm` (`pmxcfs` `/etc/pve/.vmlist`) as
  authoritative and return `ApiError::NotFound` (`guest <vmid> not found
  in cluster`, exit `5`) only when the VMID is absent from the cluster
  resource list. When a VMID is present in `/cluster/resources` (even
  with status `"unknown"` while its hosting node is offline) and the
  node cannot be queried, the error names the node and its cluster
  status and exits `1` (or `7` if the underlying failure is transient
  `RateLimited` / `StorageHang`), so teardown scripts never mistake an
  unreachable node for an already-deleted guest.
- **Configuration errors now consistently exit `3` (`ConfigError`) (#359).**
  Unknown `--profile`, missing `default` in a
  multi-profile config, missing required fields or profile parse errors,
  invalid enum-like values in `validate_enum_like_fields`, and invoking
  `proxxx pbs ...` without a PBS configuration block now return typed
  `ConfigError` variants (`UnknownProfile`, `NoDefaultProfile`,
  `ProfileParse`, `InvalidValue`, `MissingPbsConfig`) instead of plain
  `anyhow!` strings, exiting `3` per the documented exit-code contract.
  `MissingPbsConfig` also names the active profile section
  (`[profiles.<name>.pbs]`, or `[pbs]` for flat configs) instead of the
  literal placeholder `[profiles.X.pbs]`.

- **JSON fatal errors now include the full error chain, `causes`, `exit_code`, and respect `--format json-envelope` (#361).**
  Fatal CLI errors under `--format json` and `--format json-envelope`
  previously emitted `[{"error": e.to_string(), "status": "fatal_error"}]`,
  dropping every wrapped cause and ignoring the `json-envelope` wrapper.
  `util::format::render_fatal_error` now formats `error` with `{e:#}`
  (matching text mode), adds `causes` (one string per element of
  `e.chain()`, outermost first) and `exit_code` (the integer passed to
  `std::process::exit`) as additive keys alongside `status` and optional
  `hint`, and reuses `util::format::render_json_output` so
  `--format json-envelope` wraps the error array in
  `{"proxxx": "<version>", "data": [...]}`.
- **`ApiError::Transport` now preserves the underlying `reqwest` source chain (#323).**
  `reqwest::Error`'s `Display` implementation prints only the top-level
  summary (`error sending request for url (...)`) and omits its
  `std::error::Error::source()` chain, hiding TLS certificate, DNS, and
  OS-level TCP connection causes (`Connection refused`, timeouts).
  `ApiError::from_transport` and `ApiError::format_error_chain` now walk
  the full `.source()` chain when constructing `ApiError::Transport` and
  logging retry warnings across PVE and PBS clients.

## [0.14.0] — 2026-09-09

Headline: **the 2026-09-09 audit backlog, closed.** A 20-category audit
of `32e10020` produced 72 verified findings; the 36 with a concrete,
bounded fix are all in this release. Several are behavioural breaks and
are listed first — read those before upgrading an unattended deployment.

### ⚠️ Breaking (behavioural — no schema or CLI contract change)

- **The HITL daemon refuses every callback without `allowed_approvers`.**
  The callback HMAC proved proxxx minted the approval keyboard; it never
  established who pressed the button, so any member of `chat_id` —
  including someone added to the group later — could approve a
  destructive operation, which then ran with the daemon's full PVE
  credentials. **Migration:** add the approving Telegram numeric user ids
  to the profile's `[telegram]` section (`@userinfobot` gives you one).
  Usernames are deliberately not accepted: a handle can be released and
  re-registered by someone else. Absent or empty is treated as "refuse
  everything" rather than "allow anyone", matching the posture v0.13.0
  took for destructive MCP tools with no matching policy.
- **`verify_tls` now defaults to `true`.** Omitting the key used to mean
  `false`, so a minimal config silently accepted any certificate —
  including one presented by whoever sat between proxxx and the cluster,
  who then received the API token. **Migration:** Proxmox ships a
  self-signed certificate, so a homelab needs an explicit
  `verify_tls = false` or, better, `tls_pin_mode = "tofu"`. The `[pbs]`
  block has defaulted to `true` all along; this aligns the two.
- **An unrecognised `auth` or `tls_pin_mode` value no longer starts.**
  Both were matched rather than validated: `auth` fell through to token
  auth for anything that was not exactly `"password"`, and a misspelled
  `tls_pin_mode` warned into a log file and ran unpinned. Both are now
  rejected at load with the key and its accepted values named.
- **`Policy.require` is enforced.** It was never compared against
  anything — `require = 3` was satisfied by one press while the CLI
  printed "requires 3 approval(s)". Approvals are now counted as a set of
  distinct approver ids. **Migration:** none if you used `require = 1`;
  otherwise the quorum now actually applies.

### Security

- **Approver authentication and quorum for HITL** (#249, #250). The
  quorum rides in the signed callback payload as a fourth segment, so a
  keyboard minted by an older proxxx still parses and means one approver.
- **An unreadable freeze lock now refuses the operation** (#252). Any
  read or parse error mapped to "not frozen", so a torn write, a
  truncated copy or a full disk silently disarmed the cluster-wide write
  kill-switch at exactly the moment it was being relied on. Only a
  *missing* file means thawed; a file that exists and cannot be read is
  unknown state, and for a kill-switch unknown means stopped.
- **Caller-supplied path segments are percent-encoded** (#253), across
  all 111 path-building sites, plus a traversal guard at the transport
  that applies to every request regardless of which of the 234 gateway
  methods built the path.
- **MCP string parameters carry a shape** (#254), enforced in the
  dispatcher and published as a JSON Schema `pattern` in `tools/list`.
  Not added to `registry_json`, so `registry_checksum()` — the contract
  fingerprint callers pin — is unchanged.
- **The audit actor is anchored on `getuid()`** (#256), not `$USER`,
  which the calling process controls. A disagreement between the two is
  recorded as unverified rather than silently believed.
- **MCP HTTP authorization is a router layer** (#258), not a per-handler
  call; `/health` is exempted explicitly rather than by omission.
- **`--token-secret-file`** (#283), so the credential need not appear in
  the process listing, shell history or CI logs.
- **The audit HMAC key can be rotated without invalidating history**
  (#281). Each row records the key that signed it, retired keys are
  archived beside the primary, and `proxxx audit rotate-key` does the
  swap. Previously rotating meant starting a new chain — so the correct
  response to a host compromise destroyed the evidence. `proxxx doctor`
  now verifies the chain rather than reporting OK when the DB merely
  opened, which is what the README already claimed.
- **Secret resolution order corrected in the docs** (#257) — they said
  file-then-inline; the code does inline-then-file. An operator moving a
  secret into a `0600` file without deleting the inline value kept using
  the inline one. proxxx now warns when both are set.

### Fixed

- **`state`: a family the document never mentions is left alone** (#259).
  It was indistinguishable from one declared empty, and an empty declared
  family means "delete every live member" — so a dropped or mistyped
  section header destroyed that family under `--prune`.
- **All declaration structs reject unknown fields** (#262), so a
  misspelled key is a parse error rather than a silently-defaulted one.
- **Duplicate identities within a family are refused** (#261); they were
  silently discarded by the diff's `HashMap`.
- **The state document carries `meta.schema_version`** (#263); a document
  newer than the binary understands is refused rather than reinterpreted.
- **`get_guest_status` stamps `guest_type` and `node`** (#260). Every
  container came back labelled as a QEMU VM on node `""`, and the MCP
  tool serialised that verbatim. A 403 on the QEMU probe now surfaces
  instead of falling through to an LXC 404 that names the wrong cause.
- **The daemon supervises its components** (#264). Nothing polled the
  handles, so a panicked pillar left the process alive and exiting zero —
  and `Restart=on-failure` never fired. An unexpected exit now stops the
  rest and exits non-zero.
- **An interrupted converge leaves an audit record** (#265), via a Drop
  guard, which runs on abort where a cancellation token would not.
- **A per-node listing failure is no longer reported as "Guest not
  found"** (#266); it is reported as indeterminate, naming the
  unreachable nodes.
- **Atomic writes fsync the parent directory** (#268), so the rename that
  puts a file in place survives a power loss.
- **`describe` says which sections it could not read** (#278) instead of
  rendering a 403 as "this cluster has no users".

### Observability

- **Log records reach stderr as well as the rotating file** outside the
  TUI (#270), so `journalctl` is no longer empty for a daemon. `RUST_LOG`
  is honoured; the default level drops to `info`.
- **`proxxx_daemon_component_up` and `…_last_tick_timestamp`** (#271), so
  a stopped pillar is visible to monitoring rather than looking like a
  quiet one.

### Performance

- **Guest lookup is one request** (#276) via `/cluster/resources`, not
  1 + 2N. It runs before almost every per-vmid command and at seventeen
  MCP dispatch sites.
- **The TUI refresh adapts** (#277): it sleeps the remainder of its
  target period rather than a flat 5 s on top of the cycle, warns on
  screen when it cannot keep up, and bounds its per-node fan-out.

### CI and verification

- **`cargo clippy` runs with `-D warnings`** (#272). The curated
  pedantic/nursery configuration was decorative; the tree turned out to be
  clean at that level, so there is no backlog.
- **ruff, shellcheck and gitleaks gates** (#274) — 10 shell and 2 Python
  files shipped unchecked, including the script that rewrites Rust source
  and opens supply-chain PRs.
- **A coverage job and an on-demand live-tier workflow** (#275), the
  latter recording its result against a commit SHA.
- **npm is watched by Dependabot and gated by `npm audit`** (#280), and
  `cargo-audit`, `cargo-deny` and `cargo-cyclonedx` are version-pinned —
  the tools deciding whether the build passes its security gate were
  fetched unpinned on every run.
- **Two tests that could not fail now can** (#273). One asserted on two
  local variables while named for lock detection; it passed with lock
  detection deleted.

### Packaging

- **Release tarballs are reproducible** (#279): `--sort=name`,
  `--mtime=@SOURCE_DATE_EPOCH`, normalised ownership and `gzip -n`. The
  published `.sha256` now attests to the source rather than to one CI run.

### Contract

- **The Rust library API is a declared surface** (#284), enumerated in
  `src/lib.rs` and named in the SemVer contract above. It is linked by
  the proxima desktop UI and previously had no policy at all.
- **`--format json-envelope`** wraps the payload in
  `{"proxxx": "<version>", "data": …}` for consumers that must work
  against several versions at once. `--format json` is unchanged.

### Documentation

- **ARCHITECTURE.md describes this system** (#282). Its diagram put all
  three callers behind `app::reducer`, which is TUI-only, and called all
  of `app/` zero-I/O, which is true only of `app.rs`.
- **The production checklist gains upgrade, rollback and backup**
  (#269), including which files must survive a host rebuild and that the
  cache DB refuses to open under an older binary.
- **The shipped systemd unit no longer claims** that replay protection
  survives a restart (#267) — it does not, and the unit's own
  `Restart=on-failure` makes those restarts routine.

### Dependencies

- `der` 0.8.0 → 0.8.2 and `wnaf` 0.14.0 → 0.14.1, both yanked upstream
  and reached transitively through russh. Landed separately in #245
  while this branch was open — noted here because it is what took
  `cargo deny check` green again for this release.

### Also in this release

- **The TUI-typed SSH passphrase redacts `Debug` as a type property.** `Action::SshPassphraseInput` and `SideEffect::SetSshPassphraseAndOpen` carried the typed passphrase as a plain `String` inside `Debug`-derived enums — no site logs actions today and the op queue persists through the closed `PersistedOp` set, so nothing leaked, but the invariant since v0.13.2 is that redaction never depends on call-site discipline. Both now carry `SecretString` (`{:?}` → `[REDACTED]`, proven by test), the submit path moves the input buffer into the wrapper via `mem::take` so the plaintext is zeroized instead of surviving in a freed allocation, and `ssh_handler.set_passphrase` accepts the wrapper end-to-end. Flagged while triaging CodeQL's new Rust queries (alert #45).

## [0.13.3] — 2026-08-29

Patch: supply-chain catch-up (the scheduled audit had been red since 2026-08-25) plus docs-site SEO. No CLI / config / MCP contract change; config stays backward compatible.

### Security

- **Supply-chain audit green again.** Three findings had accumulated in the lockfile: `h2` 0.4.15 → 0.4.19 (RUSTSEC-2026-0258, unbounded empty DATA frames), `lru` 0.18.0 → 0.18.3 (RUSTSEC-2026-0253, unsound `LruCache::pop`, transitive via ratatui-core), and `chacha20` 0.10.0 → 0.10.2 (yanked release, transitive via russh). Lockfile-only; `cargo audit --deny warnings` and `cargo deny check` both pass again.
- **`russh` 0.62.1 → 0.62.5**, closing four GHSA advisories against the SSH layer (GHSA-m65r-rprj-r5rg, GHSA-g9hv-x236-4qp3, GHSA-cqjc-rmpq-xprq, GHSA-5xvq-cp9x-6p6r).
- **CodeQL triage.** The codeql-action bump enabled newer Rust queries; all 19 new findings were triaged with written dispositions rather than blanket-dismissed. The one with substance — a claimed passphrase-to-disk flow through the operation queue — is infeasible (the queue persists through the closed `PersistedOp` enum, which cannot carry a raw `Action`), with a follow-up tracked to make the passphrase-bearing variant redact its `Debug` as a type property.

### Dependencies

- `tokio` 1.52.3 → 1.53.1, `tokio-util` 0.7.18 → 0.7.19, `tokio-stream` 0.1.18 → 0.1.19.
- Patch-and-minor group (12 crates): `serde`, `serde_json`, `clap`, `clap_complete`, `toml_edit`, `anyhow`, `thiserror`, `async-trait`, `rusqlite`, `futures-util`, `rustls`, `libc`.
- `postcss` (docs tooling, dev-only) → 8.5.26 (GHSA-r28c-9q8g-f849 high + GHSA-fxqj-rqcc-2cmp).
- GitHub Actions patch-and-minor group (8 actions, incl. `github/codeql-action`).

### Docs

- **The docs site is now crawlable and shareable**: `sitemap.xml` (vitepress `sitemap` with the `/proxxx/` base baked into the hostname — base-less route paths would otherwise emit URLs that 404 on GH Pages), `robots.txt`, and OpenGraph/Twitter cards. `og:url` is derived per page via `transformPageData` — crawlers treat it as canonical, so a single global value would have advertised every subpage as the homepage.
- Privacy notice linked in the site footer + a meta-CSP on the built site (production builds only — the dev server's HMR websocket needs a laxer `connect-src`).

### Internal

- Cloud-image registry re-pinned to the latest dated upstream builds (Ubuntu noble 20260814, Debian trixie 20260819-2575) with refreshed checksums.
- Live-harness `url-info` probe un-rotted: `jammy/current/SHA256SUMS` instead of a dated snapshot Ubuntu has since pruned — the probe now tests proxxx, not Ubuntu's retention policy.
- Live E2E temp-dir leak fixed in the reconcile test; CI branch protection no longer requires branches to be up to date (the auto-merge limbo fix).

## [0.13.2] — 2026-07-07

Patch: secret-hygiene hardening (redaction as a type property, closing a latent log-leak class the v0.13.1 `WsTarget` fix only covered for one type), plus two untested security-relevant paths now proven. No CLI / config / MCP contract change; config stays backward compatible.

### Security

- **Credential redaction is now a type property, not call-site discipline.** A new `SecretString` (redacting `Debug` → `[REDACTED]`, no `Display`, no `Serialize`, zeroize-on-drop) backs every credential field — PVE/PBS token secrets, password, `mcp_token`, `AuthMethod` token/ticket/CSRF, `TelegramConfig.bot_token` (previously a plain unwiped `String`), `PbsClient.auth_header`, SSH passphrases, init-wizard blocks. `Zeroizing<String>` delegates `Debug` to its inner `String`, so a derived `{:?}` on any config/auth struct previously printed live secrets — the same leak class the v0.13.1 `WsTarget` fix closed for one type, now closed at the type level everywhere.
- **Telegram bot token no longer reachable in the persistent log.** The Bot API embeds the token in the request URL; reqwest's error `Display` appends `for url (…)`, and the HITL long-poll / alert paths log those errors — so a transport blip wrote the live token to the 14-day file log. Every Telegram request now scrubs the URL from its errors (`Error::without_url`) before they can reach a `tracing` event. Found by an adversarial-review pass; proven by a hermetic connection-refused test.
- **Console / token wire types redact `Debug`.** `VncTicket`, `TermproxyTicket`, `SpiceConfig.password` and `ApiToken.value` keep `Serialize` (they ride the wire / `--json` output by design) but their live-credential fields are now hand-redacted in `Debug`, so a future `{:?}` log can't leak them.
- **SIGHUP config hot-reload proven (AR-1 dependency).** The `mcp_token`-rotation path AR-1 relies on had zero tests. `reload_once` is extracted and unit-tested (a successful reload swaps `mcp_token` / `policies` / `rate_limit`; a failed parse keeps last-known-good), plus a real-signal end-to-end test (`PROXXX_CONFIG` tempfile + `libc::raise(SIGHUP)`).
- **Env-var secret 64 KiB cap proven.** The `ENV_SECRET_MAX_BYTES` OOM guard, previously matrix-cited by constant only, now has executable proofs (over-cap refused, at-cap accepted, empty → None).

### Dependencies

- `crossbeam-epoch` 0.9.18 → 0.9.20 (RUSTSEC-2026-0204, transitive; not triggerable via proxxx's usage — the daily supply-chain sweep caught it).
- `vite` (docs tooling, dev-only) → ≥ 7.3.5 (GHSA-fx2h-pf6j-xcff high + GHSA-v6wh-96g9-6wx3).
- `github/codeql-action` v4.36.2 → v4.36.3 (CI).

### Docs

- `THREAT_MODEL.md` refreshed to v0.13.x reality: MCP dispatch is fail-closed (10 destructive tools, refuse-without-policy), keychain per-profile scoping, cache-at-rest perms, and vncticket redaction added; a new `tests/docs_consistency_test.rs` fails CI if the destructive-tool count drifts from the registry again.
- Corrected the stale "8 flagged destructive" → 10 across the README / asset captions (the MCP demo SVG re-rendered) and "8 of the 10 state families" in the mutation-harness wording. Test counts refreshed to the actual `cargo test` totals (745 lib + 478 integration).

### Internal

- Security-invariants matrix: new rows for the redacting-`Debug` and SIGHUP-reload invariants; row 1 (zeroize-on-drop) reworded to its honest compile-time-type-property scope.

## [0.13.1] — 2026-07-06

Patch: security hardening of the residual "yellow" doubts + dependency bumps. No CLI / config / MCP contract change; keychain resolution stays backward compatible.

### Security

- **Console session tickets no longer leak into logs.** The `vncticket` was logged in cleartext on every console attach; it is now redacted at every log/error site, `WsTarget`'s `Debug` redacts it, and the panic-hook scrubber knows `vncticket=`. The intentional `vnc --ws-url` output is unchanged — that is the feature (signed [ACCEPTED-RISKS](pre-commit/ACCEPTED-RISKS.md) AR-7).
- **Cache-at-rest is owner-protected.** The per-profile SQLite cache dir is created `0700` and the DB plus its `-wal`/`-shm` sidecars `0600` on unix (AR-8).
- **Keychain per-profile isolation.** OS-keychain lookups for `token_secret` / `password` now try the profile-scoped item `<profile>/<item>` before the flat name, so two keychain-backed profiles no longer resolve the *same* secret. Opt-in and backward compatible via a flat fallback (AR-9).
- **State export verified secret-free** (no modelled secret field; field-whitelist, no serde-flatten). Issue #178's elide-on-export convention is the signed gate before any secret-bearing state family; free-text fields (`comment`/`notes`) still pass through verbatim (AR-10).

### Dependencies

- `russh` 0.61.2 → 0.62.1 (SSH). The rsa-sha2-512 client-auth fix from v0.13.0 was re-verified against a live PVE 9.1.1 cluster on the new version.
- `clap_complete` 4.6.5 → 4.6.7; grouped GitHub Actions bumps.

### Internal

- The live E2E harness is turnkey — `run_proxxx` synthesizes the CLI config from the E2E env, and `e2e_beta` is self-contained (no VMID collision with `e2e_alpha`). No change to the shipped binary.

## [0.13.0] — 2026-07-05

Headline: **Fail-closed by default.** The four declared security-invariant gaps are closed and hardened under adversarial review, and the whole surface was exercised against a live PVE 9.1.1 cluster (which turned up two real bugs, both fixed). No CLI-command, exit-code, `--format json`, or MCP-registry *contract* change — but several runtime **defaults are now stricter**, so read the migration notes.

### ⚠️ Breaking (behavioural — no schema/contract change)

- **Destructive MCP tools now require a policy.** A destructive tool invoked over MCP with **no matching `[[policies]]` entry is REFUSED** (typed `isError`; the PVE gateway is never reached). Previously such a call executed inline. The MCP transport is network-reachable, so this closes the path where an unauthenticated caller could drive a destructive op. **Migration:** add a matching `[[policies]]` entry (which routes the op through HITL approval) for any destructive MCP tool you rely on.
- **`suspend_guest` and `create_snapshot` are now destructive** (policy-gated over MCP): the first pauses a running VM (availability impact), the second is an unbounded storage write. `start_guest` / `resume_guest` stay inline. **Migration:** as above — add a policy if an agent needs them.
- **`mcp serve-http` refuses to expose an unauthenticated endpoint.** It will not start on a non-loopback bind (e.g. `0.0.0.0`) unless `mcp_token` is set. **Migration:** set `mcp_token` (or `--token`), bind `127.0.0.1`, or pass the new `--insecure-bind` to override consciously. An empty/whitespace token counts as absent (fail-closed).
- **Unmanned `converge_prune` holds deletes without a cap.** With `auto_converge = true` and `converge_prune = true` but **no `max_unmanned_changes`**, the daemon now converges creates/updates but **holds all deletes** (a 10–49 delete flood is below the Severe ≥50 breaker and would otherwise auto-apply unmanned). **Migration:** set a *small* `max_unmanned_changes` to re-enable unmanned prune (size it to the smallest count a legit tick applies — a large cap re-opens the band).

### Security

- **MCP dispatch is fail-closed and stays that way (#192, #194).** Destructive tools with no governing policy are refused; the deny is uniform across all 10 destructive tools (registry-contract + parametrized dispatch tests). The HTTP bind preflight and a per-request token gate are **SIGHUP-safe** — clearing (or emptying) `mcp_token` at runtime on an exposed server can no longer silently drop auth.
- **Audit key custody hardened (#192, #194).** A group/world-readable `audit.key` is refused on load (unix); the check **fails closed** on a stat error and fstat's the open fd (no TOCTOU / symlink-swap); the audit data dir is created `0700`. `PROXXX_AUDIT_KEY` relocates the key off the DB volume. `proxxx audit verify` exits non-zero on any tamper.
- **Unmanned converge blast radius bounded (#192).** Adversarial tests prove a mass-delete cannot auto-apply; the fail-closed prune guard is above.
- **Operation-queue crash recovery is idempotent (#193).** A write-ahead persist records intent before any PVE call, so a crash mid-op can't turn into a double-execute of a non-idempotent op on restart.
- Signed residual risks are catalogued in [`pre-commit/ACCEPTED-RISKS.md`](pre-commit/ACCEPTED-RISKS.md) (AR-1…AR-6).

### Fixed

- **RSA SSH client keys work against a modern sshd (#195).** russh signed RSA keys with the deprecated `ssh-rsa` (SHA-1), which OpenSSH sshd (PVE 9 / Debian 13) rejects — so RSA keys were unusable for the console / `exec` / log-fanout even though the same key works over the OpenSSH client. Now pins `rsa-sha2-512` for RSA keys. Surfaced by the live E2E run.
- **A 401 now names the status (#195).** `ApiError::Unauthorized` renders as *"Proxmox rejected our credentials (HTTP 401 Unauthorized): …"* — recognizable/greppable as an auth failure.

### Added

- **`--insecure-bind`** flag on `mcp serve-http` — the explicit, conscious opt-out of the non-loopback-without-auth refusal.
- **`PROXXX_AUDIT_KEY`** env var — relocate the audit HMAC key onto a separate volume/trust domain (complements the existing `PROXXX_AUDIT_DIR`).

### CI / Supply chain

- Least-privilege `automerge` workflow token (top-level → job-level write; OpenSSF Scorecard Token-Permissions) and concurrency guards on `ci` / `codeql` (#196).

## [0.12.0] — 2026-07-01

Headline: **Security hardening — tamper-evident audit that now covers WHO/WHAT, tested destructive-confirmation gates, and guardrails on the unmanned converge.** No CLI / config / MCP contract change; an existing `audit.db` migrates in place.

### Added

- **Unmanned auto-converge guardrails (#171).** Two opt-in restrictions on the
  daemon's Layer-3 `auto_converge` — both only ever *narrow* the unmanned blast
  radius, default = exact current behaviour. `[reconcile] allowed_families =
  ["pool", "acl"]` limits which state families the unmanned daemon may
  auto-apply (graduated trust — keep storage / HA / firewall human-only); the
  manual `reconcile converge` stays unrestricted. `[reconcile]
  max_unmanned_changes = 20` caps changes-per-tick (after family filtering),
  refusing with a "needs human review" alert above the cap — catching a
  Warning-tier flood (e.g. a partial git revert) that the Severe bulk-change
  circuit-breaker (≥50) would miss. Pure, unit-tested filter + cap; documented
  under `[profiles.<name>.reconcile]`.

### Security

- **Audit HMAC chain now binds WHO and WHAT (#173).** The chain was
  `HMAC(key, prev || ts || action || vmid || result)` — `user`, `node`, and
  `params_json` were stored but left *outside* the MAC, so a local attacker
  with write access to `audit.db` could rewrite the actor or the parameters
  of a logged action without breaking the chain (and for `state_apply` /
  `reconcile_converge` entries the meaningful "what" lives in `params_json`).
  A new **v2** format folds those columns in: `HMAC(key, "v2" || prev || ts ||
  action || user || vmid || node || params_json || result)`. A `chain_version`
  column lets `audit verify` recompute each row under its own format, so an
  existing `audit.db` migrates transparently and its rows keep verifying as
  v1. `THREAT_MODEL.md` updated; proptests pin the extended coverage and the
  v1↔v2 migration contract.

### Changed

- **Destructive-confirmation gates centralised and tested (#172).** The ~30
  copy-pasted `if !yes { bail!(…) }` checks across the CLI now route through a
  single, unit-tested `require_yes(yes, what)` chokepoint. A behavioural test
  net drives the real command handlers with `--yes` absent against a
  dead-endpoint client and asserts they refuse *before* any API call — so a
  silently-dropped safety gate now turns CI red instead of passing unnoticed.

## [0.11.0] — 2026-06-26

Headline: **Consumer-driven gateway + helpers — the gaps the proxima desktop UI hit, closed.** A batch of additive library-API surface driven by real proxima usage: role-management write methods, a shared-storage flag, and three helpers proxima had reimplemented. **No CLI / MCP / config contract change** (one additive `--format json` field on storage status); these let proxima drop hand-rolled workarounds and route through proxxx's rate-limiter, TLS pinning, and auth instead.

### Added (library API — `ProxmoxGateway`)

- **Role CRUD** — `create_role(roleid, privs)` (`POST /access/roles`), `update_role(roleid, privs, append)` (`PUT /access/roles/{roleid}`; `append` toggles replace-vs-extend of the privilege set), and `delete_role(roleid)` (`DELETE`). Completes the access-control write surface — `create/update/delete_user`, `modify_acl`, and token create/revoke already shipped, so realms are now the only read-only access family left. Built-in roles and ACL-referenced roles are refused PVE-side.

### Added (library API — helpers)

- **`wsterm::humanize_error(raw)` / `humanize_error_hint(raw)`** — map raw termproxy / websocket / vncproxy failures (LXC-console attach, connection-reset, TLS-handshake, ticket-rejection, timeout) to sysadmin-facing hints. proxxx generates these errors, so proxxx decorates them — one mapping shared across CLI, TUI, and embedding consumers instead of each re-deriving it.
- **`config::write_token_secret(profile, secret)` + `config::token_secret_path(profile)` / `config::secrets_dir()`** — an atomic, `0600` writer for a profile's token-secret file (`<config_dir>/secrets/<profile>.token`, honoring `PROXXX_CONFIG`), completing the read/write symmetry with `resolve_token_secret` (which already enforced `0600` on read). Perms are set before the rename so the secret is never briefly world-readable.
- **`handoff::token_page_url(api_base)`** — deep-link builder into the PVE web-UI API-token panel, alongside the existing `build_novnc_url` (host:port extraction is now shared between them). The PVE-version-specific `#v1:…` route lives in proxxx so consumers don't hard-code it.

### Added (`--format json`, additive)

- **`shared` on storage status** (`StoragePool`) — surfaces PVE's per-node `shared` flag (NFS/Ceph/PBS = `1`) from `/nodes/{node}/storage` and `/cluster/resources`, so consumers dedup cluster-wide pools exactly instead of guessing from identical per-node usage totals.

All changes are additive (no breaking CLI/JSON/config/MCP change). 13 new unit tests: storage `shared` deserialization (present + absent), role `POST`/`PUT`(`append=1`)/`DELETE` wire-paths, the five humanize patterns + passthrough, the token-secret `0600` round-trip + path convention, and the token-page URL builder.

## [0.10.0] — 2026-06-25

Headline: **PCI + USB passthrough-as-code — cluster resource mappings (`/cluster/mapping`) are now a writable GitOps state family.** Declare which physical GPU / NIC / USB device a guest may bind to, version it in git, and converge it like any other state. New `--resource` tokens `mappings` / `mappings-pci` / `mappings-usb` join the loop as the **ninth and tenth** state families. This is the epic-#74 economic pattern applied to a PVE surface that already shipped full CRUD — no new HTTP, all the leverage.

### Added (GitOps state family — cluster resource mappings)

- **`mappings-pci`** (`/cluster/mapping/pci`) and **`mappings-usb`** (`/cluster/mapping/usb`), plus the **`mappings`** umbrella selector — full `state export` → `diff` → `apply` lifecycle. A mapping declares an `id`, an optional `description`, and a `map` list (one `node=<n>,path=<addr>,id=<vendor:device>` entry per node the device lives on); PCI mappings additionally carry `mdev` (mediated-device / vGPU). `map` is emitted as repeated form keys (PVE's array shape) and is byte-stable on round-trip.
- **Pre-flight: a mapping delete is `Severe`** (`MappingPciDelete` / `MappingUsbDelete`), unconditionally — proxxx does not model which guests reference a mapping (`hostpciN: mapping=<id>` / `usbN: mapping=<id>`), so it cannot prove the safe case. A guest bound to a deleted mapping loses its device on next start and hard-fails migration; the gate refuses unmanned (the `auto_converge` daemon alerts for human review) and requires `--allow-risk` from a present operator.
- **Rule-type-aware param builders** keep the PCI-only `mdev` field from ever leaking into a USB mapping (the field-leak lesson from epic #74's HA rules).

Validated end-to-end against a live PVE 9.1.1 cluster (`tests/live/test_state_mappings.sh`, 7/7): create → export round-trip → `mdev`-leak guard → update → Severe-delete gate (exit 6, mappings intact) → operator override → in-sync. 3 new unit tests (the `mdev` leak guard + both Severe-delete assertions); the full suite is 1159 tests.

## [0.9.2] — 2026-06-25

Headline: **Three additive `ProxmoxGateway` methods for the proxima desktop UI — ZFS pool detail, guest serial-device pre-flight, and guest disk-IO rate.** Library-API additions only — **no CLI / MCP / config change** (the user-facing contract is untouched). They let the proxima UI drop three direct-`reqwest` workarounds and route through proxxx's rate-limiter, TLS pinning, and auth-refresh instead.

### Added (library API — `ProxmoxGateway`)

- **`get_node_zfs_detail(node, name)`** — `GET /nodes/{node}/disks/zfs/{name}`: the per-pool `scan` line (scrub progress / last-scrub epoch / error counters) plus the vdev tree, flattened depth-first from PVE's nested shape into `Vec<ZfsVdev>` (`read`/`write`/`cksum` coerced defensively from PVE's number-or-string).
- **`guest_serial_devices(node, vmid, kind)`** — the `serial0..3` devices configured on a QEMU guest (empty for LXC, which uses `/dev/console` via `lxc-console`). Lets a console pre-flight refuse to open a `termproxy` session that would attach to nothing (no `serial0: socket` → a permanently black terminal).
- **`guest_disk_io_rate(node, vmid, kind)`** — best-effort read/write bytes-per-second for a guest, from the most recent RRD point. **Verified live:** PVE's RRD already stores `diskread`/`diskwrite` as a *rate* (an idle guest reads 0 while its cumulative `/cluster/resources` counter is non-zero), so this is the latest sample, not a counter delta. `read_iops`/`write_iops` are `None` (PVE guest RRD carries no per-op counts).

New types: `ZfsPoolDetail`, `ZfsVdev`, `SerialDevice`, `DiskIoRate` (all in `proxxx::api::types`). 2 new unit tests (ZFS tree flatten + number-or-string coercion).

## [0.9.1] — 2026-06-25

Headline: **Hardening patch — `state apply` now leaves an audit trail, and the audit chain's key handling is tightened.** A code-health / security pass after the v0.9.0 GitOps-controller release. No CLI-contract changes (commands, exit codes, and `--format json` shapes are unchanged); the tamper-evident trail and a handful of robustness edges get firmer.

### Security

- **`state apply` now writes an HMAC audit entry**, closing the asymmetry where only the unmanned `reconcile converge` left a tamper-evident trail while the operator-driven `state apply` — issuing the *identical* mutations through the same `apply()` code — recorded nothing. Both now log one entry per dispatched run (`state_apply` / `reconcile_converge`) through the shared `apply_and_audit` core.
- **The audit key is length-validated.** A truncated or empty `audit.key` (e.g. an interrupted first write) is now rejected with an actionable error instead of silently degrading to a forgeable all-zeros HMAC key; the zeroed-key fallback in `compute_hmac` is removed. `last_chain_hmac` now distinguishes an empty log (correct) from a real read error (which warns).
- **`mcp_token` is held as `Zeroizing<String>`**, matching every other config secret.

### Fixed

- **QGA `network-get-interfaces` no longer swallows a malformed payload** into an empty interface list (indistinguishable from a guest that genuinely has none) — a deserialize failure now surfaces as a typed `Parse` error. Both call sites (`vm qga net`, console IP discovery) already handle it.
- **QGA `guest-exec` builds its command argv as proper JSON** (`serde_json::json!`) instead of hand-rolled `"`-only escaping, so a command containing backslashes / newlines / tabs is no longer malformed.
- **The Telegram HTTP client sets a 30 s request timeout** so `send` / `edit` / `approve` can't hang forever on a wedged connection (the long-poll keeps its own longer per-request timeout).

### Deferred (tracked)

- Folding `user` + `params_json` into the audit chain ([#173](https://github.com/fabriziosalmi/proxxx/issues/173) — needs a chain-format version so existing DBs still verify) and a test net for the destructive `--yes` gates ([#172](https://github.com/fabriziosalmi/proxxx/issues/172) — a focused refactor). New GitOps state families + node-level ZFS pool create are v0.10.0 feature work (a patch can't add CLI surface).

## [0.9.0] — 2026-06-25

Headline: **The GitOps controller, complete — `reconcile {run,converge}` + an unmanned drift-watch that self-heals.** Continuous reconciliation closes end to end: drift *detection* (Layers 1–2 — `reconcile run`, the `watch` daemon pillar, drift → Prometheus + MCP) and drift *convergence* (Layer 3 — `reconcile converge` + the opt-in unmanned `auto_converge` daemon) ship together, making "GitOps for Proxmox" a first-class workflow: `git push` → production converges, behind the same Severe-risk pre-flight gate that guards `state apply` — which the unmanned loop **never** overrides. Also the first release built + distributed through the new signed Debian `.deb` packages and the Homebrew tap.

### Added

- **`reconcile converge` + unmanned `auto_converge` — the GitOps controller's WRITE half (continuous reconciliation, Layer 3).** Closes the loop: detection (Layers 1–2) now has a converge counterpart that mutates live state toward the declared source. Two surfaces over one shared core (`state::converge`):
  - **`proxxx reconcile converge --source <file|dir|git>`** — the operator / CI push-mode. Resolves drift exactly like `reconcile run`, then applies it through the **same pre-flight safety gate as `state apply`** (atomic refuse-on-any-Severe). Mirrors `state apply`'s flags (`--dry-run`, `--prune`, `--continue-on-error`, `--allow-risk`, `--interactive`) and exit-code contract (0 ok / 2 any-Failed / **6** Severe refusal / **8** read-only or freeze lock). Drop it in CI to make `git push` converge production.
  - **Unmanned `auto_converge` (daemon).** Opt-in via `[profiles.X.reconcile] auto_converge = true` (+ `converge_prune` to allow deletes). The `reconcile watch` pillar, after detecting drift each tick, converges it — **always `force = false`, so a Severe-risk drift is NEVER auto-applied**: it raises a `🛑 needs human review (Severe)` alert and mutates nothing (the bulk-change gate — Severe at ≥ 50 changes — is the circuit-breaker against a catastrophic mass-drift, e.g. an emptied repo diffing to "delete everything"). A deliberate write-lock (`read_only` / incident freeze) skips the tick **quietly** (no alert storm); detection + metrics keep running. New `--no-converge` daemon flag and `PROXXX_NO_CONVERGE` env kill-switch. Each dispatched converge writes one HMAC-chained **`reconcile_converge` audit entry** (state mutations weren't otherwise on the guest-centric audit chain — an unmanned mutation especially earns a tamper-evident trail) and re-persists drift-state so the next Prometheus scrape reflects convergence immediately. New `PROXXX_AUDIT_DIR` override (hermetic tests / relocating the trail onto a dedicated volume). 9 new unit tests + a `tests/live/test_reconcile_converge.sh` e2e (drift → dry-run → prune round-trip → in-sync → audit, plus an opt-in Severe-gate case). **Layer 3 completes the GitOps-for-Proxmox controller.**
- **`proxxx reconcile run` — GitOps drift detection (continuous reconciliation, layer 1).** A one-shot, CI-gateable drift check: resolve a desired-state *source* (a local file, a local directory, or a git repo — shallow-cloned via the system `git`, **no new dependency**), export live cluster state across every state family, diff, and print a structured **per-family drift report** (`--json` for the full machine-readable envelope). Exit code follows the `diff(1)` / CI convention: **0 = in sync, 2 = drift** — drop it in a pipeline to fail the build when production drifts from git, or point it at a teammate's fat-fingered cluster to see what moved. Strictly **read-only**: detection only, no mutation, no audit-log write (the HMAC chain records mutations; a drift check changes nothing). This is the foundation the `reconcile watch` daemon pillar calls on a timer. Composes entirely over the stable `state::{export,diff}` surfaces; 4 new unit tests.
- **`reconcile watch` — the GitOps drift watch as the daemon's 4th pillar (continuous reconciliation, layer 2).** Opt-in via a `[profiles.X.reconcile]` config section (`source`, `path` = `state.toml`, `interval_secs` = 300); `proxxx daemon serve` then runs a 4th `tokio` task — alongside alerts / HITL / schedule, under the same unified shutdown — that recomputes drift on the interval via the shared `compute_drift` core. **Detect-only**: drift is logged at WARN and, when the profile has Telegram configured, pushed as an alert (`⚠️ proxxx reconcile — drift on <profile>` + a per-family summary). A failing tick (git fetch / cluster unreachable) is logged and the loop continues; a transient error never kills the watch. New `--no-reconcile` flag force-disables it. Prometheus `proxxx_drift_resources{family,profile}` metrics + MCP `cluster-event` fan-out are intentionally deferred to a follow-up — both run in separate processes (`metrics serve` / `mcp serve`) and need a shared drift-state store; logs + Telegram are the in-process channels and ship now. 4 new tests (config defaults/overrides + drift summary).
- **Reconcile drift → Prometheus metrics (continuous reconciliation, layer 2b).** The `reconcile watch` loop now persists its latest result to a shared per-profile `SQLite` drift-state store (a new schema-v3 migration; WAL mode → readers never block the writer), so the separate `metrics serve` process can surface it. `proxxx metrics` now emits, once a watch has reported: `proxxx_reconcile_in_sync{profile}` (1/0), `proxxx_reconcile_drift_total{profile}`, `proxxx_reconcile_last_check_timestamp{profile}` (so `now − this` is your staleness alert), and `proxxx_drift_resources{family,profile}` (per-family breakdown). Absent until the first check — no phantom zero series. Still strictly detect-only; the metrics path reads the store, the daemon writes it, no new mutation surface. The matching MCP `cluster-event` fan-out (the second cross-process consumer of the same store) follows in layer 2b-ii. 2 new tests (drift-state round-trip + per-family tally).
- **Reconcile drift → MCP `cluster-event` notifications (continuous reconciliation, layer 2b-ii — completes the drift fan-out).** Both MCP transports (`mcp serve` stdio + HTTP/SSE) now spawn a `reconcile` watcher alongside the existing task/incident watchers: it polls the shared drift-state store every 5 s and emits a `notifications/cluster-event` with `kind: "reconciliation"` (`event: "drifted" | "in_sync"`, `profile`, `drift_total`, `summary`) on a sync↔drift transition or a fresh drift result — quiet otherwise, silent until the watch first reports. This is the AI-agent-facing channel: an assistant subscribed to the MCP stream now learns the moment production drifts from git, tying the GitOps cuneo to the AI angle. Append-only notification variant (the pinned tool-registry surface SHA is unaffected). 2 new tests (variant serialization + the publish-decision logic). With this, drift now reaches **all three** channels — logs, Telegram, Prometheus, and MCP — and Layer 2 of the GitOps controller is complete (auto-converge remains a deliberately separate, gated layer).

### Packaging

- **Debian `.deb` packages — signed, attached to every release.** `cargo deb` now builds a `.deb` for **amd64** and **arm64** as part of the release workflow, alongside the tarballs. Because the binary is static-musl, the package declares **no runtime dependencies** — `sudo apt install ./proxxx_X.Y.Z-1_amd64.deb` drops it straight onto a Proxmox VE node (Debian) with no glibc/lib resolution. Each `.deb` ships its own SHA-256 and the same keyless **sigstore cosign bundle** as the tarball, so it carries the identical supply-chain guarantee. (A hosted apt repository is a separate follow-up; for now the `.deb` is a release asset, verifiable offline.)
- **Homebrew tap — `brew install fabriziosalmi/proxxx/proxxx`.** A new [`fabriziosalmi/homebrew-proxxx`](https://github.com/fabriziosalmi/homebrew-proxxx) tap installs the pre-built static binary on macOS (Apple Silicon) and Linux (x86_64 / aarch64). The formula's version + per-target SHA-256 are bumped automatically on each release by a new `bump-homebrew` job in the release workflow (requires a `HOMEBREW_TAP_TOKEN` repo secret with write access to the tap). Verified end-to-end against the v0.8.5 release: `brew install` → `proxxx --version` → `proxxx 0.8.5`.

## [0.8.5] — 2026-06-24

Headline: **Supply-chain refresh — clears RUSTSEC-2026-0185 and drains the dependency backlog.** Maintenance release. The daily `cargo audit` gate (a *required* status check) went red on 2026-06-23 when RUSTSEC-2026-0185 landed against `quinn-proto`; with branch protection in `strict` mode this transitively blocked **every** pending dependency PR from merging (each merge must re-run the now-failing audit). A `cargo update` refresh clears the advisory, drops the yanked `crypto-bigint`, and folds in the queued Dependabot bumps in one motion. No source changes — the test suite is unchanged.

### Security

- **RUSTSEC-2026-0185 (`quinn-proto`) cleared** — "remote memory exhaustion from unbounded out-of-order stream reassembly", `quinn-proto 0.11.14 → 0.11.15`. Note: `quinn-proto` is a transitive **lockfile-only** entry, not present in proxxx's active build graph (`cargo tree -i quinn-proto --target all` is empty), so no shipped binary was ever vulnerable — but `cargo audit` scans `Cargo.lock`, and the gate was correctly red.
- **Yanked `crypto-bigint 0.7.3 → 0.7.5`** (pulled transitively via the `russh` → `rsa` / `crypto-primes` RustCrypto stack).

### Changed

- **Dependency refresh** (supersedes the queued Dependabot PRs #153–#156, #160): `russh 0.61.1 → 0.61.2`, `ratatui 0.30.0 → 0.30.2`, `rusqlite 0.39.0 → 0.40.1`, `toml_edit 0.22 → 0.25.12`, plus the patch-and-minor group (`getrandom 0.4.3`, `zeroize 1.9.0`, `insta 1.48.0`, `serial_test 3.5.0`) and a broader in-range `cargo update`.

### Docs

- **Corrected an "Honest non-goals" entry the product had outgrown.** The README claimed "No multi-cluster aggregation in the TUI", but the read-only `proxxx fleet` view (v0.8.0+) does exactly that. Reworded to the real boundary: no multi-cluster *writes* from one TUI — `fleet` aggregates strictly read-only and drills into a single-profile TUI to act.

## [0.8.4] — 2026-05-30

Headline: **PBS on Proxmox Backup Server 4.x — `pbs datastores` no longer crashes, and `pbs restore` works against a self-signed PBS.** Patch release closing the #140 backup/restore coverage gap. A live end-to-end run against a real PBS 4.2 (homelab `pve-pbs` + datastore `test-store`) immediately caught two real bugs that the mocked unit tests missed — the recurring "live e2e catches what mocks can't" lesson. Both are fixed and verified through proxxx: a full `backup → list → restore` round-trip of a throwaway alpine LXC restored 313 files (incl. `/etc/alpine-release`) on the PBS host via `proxxx pbs restore`.

### Fixed

- **PBS datastore/snapshot listing crashed on `null` string fields.** PBS 4.x returns an explicit JSON `null` (not an absent key) for an unset datastore `comment` — and likewise for a snapshot's `owner`/`comment` and an archive's `crypt-mode`. `#[serde(default)]` only covers a *missing* key, so `proxxx pbs datastores` aborted with `Fatal Error: response parse error from /admin/datastore: invalid type: null, expected a string`. These fields now map `null` → default via a `null_to_default` deserializer. Caught by live e2e against PBS 4.2 (the #140 coverage work).

### Added

- **`pbs.fingerprint` config field** — SHA-256 cert fingerprint for the PBS server, passed to `proxmox-backup-client` as `PBS_FINGERPRINT` so `proxxx pbs restore` can trust a self-signed PBS cert. Without it, restore against the typical homelab self-signed PBS failed with `certificate fingerprint was not confirmed` (the client has no "insecure" switch). Also fixes a latent bug: the old code set `PBS_FINGERPRINT=""` under `verify_tls = false`, which does **not** disable verification — restore still failed. Now an empty/unset fingerprint is simply not passed.
- **`tests/live/test_pbs_backup_restore.sh`** — profile-based PBS backup → list → restore → verify live e2e (RAII snapshot-forget), closing the #140 coverage gap. See `tests/live/env.local.example` for the one-time setup (incl. the PBS privilege-separation ACL gotcha: the *user* needs a datastore ACL, not just the token).

## [0.8.3] — 2026-05-30

Headline: **Fleet view search + sort — now actually shipped.** Correction release: the fleet guest-pane search (`/`) and sort (`s`) were described in the v0.8.1 notes but the code did not make it onto `main` for that tag (the feature branch was never merged before the release was cut; v0.8.1/v0.8.2 binaries do **not** contain it). This release lands the real implementation.

### Added — fleet search (`/`) + sort (`s`)

- **`/` search** — filters the aggregated guest pane case-insensitively across cluster / name / vmid / node / tags. `Enter` applies, `Esc` cancels; in normal mode `Esc` clears an active filter before quitting. A search line shows only while typing or when a filter is active.
- **`s` sort** — cycles the guest order `cluster → vmid → name → status → cpu↓ → mem↓` (cpu/mem descending to surface the busy guests). Ties always break on `(profile, vmid)` so order stays deterministic. The guest-pane title + footer reflect the active match and sort.
- Pure view-state on `FleetState` — the fleet view remains strictly read-only. 9 new fleet unit tests (filter across each field, case-insensitivity, empty/no-match, sort cycle + wrap, ordering, search-input key semantics) + render snapshot + `docs/reference/tui.md`.

> Note: the `## [0.8.1]` entry below describes this same feature; it was premature — the feature is genuinely in **0.8.3**.

## [0.8.2] — 2026-05-30

Headline: **Multi-cluster setup UX.** Now that multi-profile is first-class (`proxxx fleet`, `--all-profiles`, per-profile `read_only`), `proxxx init` catches up: add a cluster without hand-editing TOML or clobbering your other profiles, and get a helpful error — not a serde dump — when a profile-only config has no default.

### Added — `proxxx init --profile <name>` (append) + smarter profile-only config loading (#142)

- **`proxxx init --profile <name>`** now **appends** a `[profiles.<name>]` block to the existing `config.toml`, preserving every other profile, comment, and formatting (format-preserving via `toml_edit`). Creates the file if absent; refuses to overwrite a same-named profile without `--force` (other profiles are always preserved). This is the multi-cluster setup path: `proxxx init --profile prod` then `proxxx init --profile lab`, … — bare `proxxx init` still writes the flat starter template. (The interactive wizard still writes the flat config; `--interactive --profile` points you at the non-interactive append.)
- **Smarter `load_config` when no profile is selected.** A profile-only config (no flat top-level `url`) now: (1) honors a top-level `default = "<name>"` key; (2) auto-uses the sole profile when exactly one is defined; (3) otherwise fails with an **actionable** error listing the available profiles and suggesting `--profile <name>` / `proxxx fleet` — instead of the opaque serde `missing field \`url\``. An explicit `--profile` always wins; flat configs are unchanged.
- **New `PROXXX_CONFIG` env override** for the config path (mirrors `PROXXX_FREEZE_PATH`) — enables hermetic tests and operators juggling multiple config files.
- Tested: 10 integration tests (`tests/init_multiprofile_test.rs`) covering append/create/duplicate-refuse, single-profile auto-default, `default` key, multi-profile actionable error, explicit-profile-wins, and flat-config backward-compat.

## [0.8.1] — 2026-05-30

Headline: **Fleet view scales — search + sort.** Follow-up to the v0.8.0 fleet view: with dozens–hundreds of guests across many clusters, the flat overview needed a way to find things. `/` opens a search box that filters the aggregated guest pane case-insensitively across cluster / name / vmid / node / tags (`Enter` applies, `Esc` cancels; in normal mode `Esc` clears an active filter before quitting). `s` cycles the sort: cluster → vmid → name → status → cpu↓ → mem↓ (cpu/mem descending to surface the busy guests). Ties always break on `(profile, vmid)` so order stays deterministic. All new state is pure view-state on `FleetState` — the fleet view remains strictly read-only, no new mutation surface.

### Added — fleet search (`/`) + sort (`s`)

- **`/` search** — filters the guest pane across cluster / name / vmid / node / tags, case-insensitive. A search line appears only while typing or when a filter is active; the guest-pane title and footer reflect the active match + sort.
- **`s` sort** — cycles `cluster → vmid → name → status → cpu↓ → mem↓`.
- Tested: 9 new fleet unit tests (filter across each field, case-insensitivity, empty + no-match, sort cycle + wrap, vmid/mem ordering, and the search-input key semantics — `Esc` cancels, `Enter` keeps the filter and is *not* read as drill-in, normal-mode `Esc` clears-then-quits). Snapshot + `docs/reference/tui.md` updated.

## [0.8.0] — 2026-05-30

Headline: **Multi-Proxmox, safely.** Two features that make proxxx pleasant *and* safe across a whole fleet of Proxmox at once. `proxxx fleet` aggregates every configured `[profiles.NAME]` — clusters and standalone hosts, mixed — into a single, strictly read-only TUI, closing the long-standing "one cluster at a time" gap. And `read_only = true` declaratively locks a profile against **all** mutations client-side, designed to pair with a `PVEAuditor` PVE token: the token is server-enforced (403), `read_only` is client-enforced (proxxx never sends the write) — belt-and-suspenders for the production clusters you only ever observe. Both shipped backward-compatible (no change to existing config, CLI JSON, or the cache schema) and verified live against a real homelab (read-only on production, full read+write on the test cluster + PBS), including an end-to-end proof that a `read_only` production profile refuses a write before the request leaves the process while reads keep working.

### Added — `read_only = true` per-profile declarative write lock

- **New per-profile config flag `read_only = true`** makes proxxx refuse **every** mutation (POST/PUT/DELETE) on that profile, **before the request leaves the process**. Reads (GET) are unaffected. Enforced at the single API write chokepoint (`src/api/client.rs`), alongside the existing incident-freeze check, so it covers the CLI, the TUI, and MCP uniformly — there is no write path that skips it.
- **Why, vs the alternatives:** unlike `[[policies]]` (which only *request* approval) and `proxxx incident freeze` (a runtime lock you must remember to set and can `thaw`), `read_only` is **declarative** — it lives with the profile in `config.toml`, is version-controllable, and is always on. Designed to pair with a read-only PVE API token (`PVEAuditor` role): the token is **server-enforced** (PVE returns 403), `read_only` is **client-enforced** (proxxx never sends the write) — either alone blocks writes; together they're belt-and-suspenders for production clusters you only ever observe. The intended setup: production hosts get a `PVEAuditor` token **and** `read_only = true`; the one writable test cluster gets neither.
- Refusal surfaces a typed `ReadOnlyRefusal` error → **exit code 8** (the same "mutation refused by a local lock" family as the incident freeze). Backward-compatible: the flag defaults to `false` (`#[serde(default)]`), so existing configs are unchanged.
- Documented in `development/config.example.toml`. Tested: config deserialize (default-off + explicit-on), exit-code/message pins, and a wiremock integration test proving a `read_only` profile refuses a write **without the request reaching the server** (`.expect(0)`) while GETs still succeed.

### Added — `proxxx fleet`: read-only multi-cluster fleet view

- **New CLI subcommand `proxxx fleet`** launches a full-screen, **strictly read-only** TUI that aggregates nodes, guests, and storage across **every** configured `[profiles.NAME]` — clusters and standalone hosts, mixed — into one screen. Closes the long-standing "one cluster at a time in the TUI" gap: a homelab with N Proxmox endpoints is now viewable from a single pane without profile-switching.
- **Read-only by construction, not by convention.** The fleet view runs in its own dedicated runner (`src/tui/fleet/`) that is a stripped-down mirror of `tui::run`: it wires **no** `SideEffect` channel, **no** HITL coordinator, **no** SSH handler, **no** op-queue, and **no** cache writes, and its keymap is navigation-only (`q`/`Esc`, `↑↓`/`jk`, `Tab`) — there is no code path from a keystroke to a mutation. It reuses the proven multi-profile read fan-out from `proxxx ls --all-profiles` (one fresh `PxClient` per profile; per-cluster failures degrade gracefully to a `DOWN` row and never abort the others).
- **Attribution by containment, zero contract change.** Each cluster's `Node`/`Guest`/`StoragePool` live in a per-profile bucket that owns the profile name — the domain structs are **unmodified**, so the `--format json` CLI shape and the SQLite cache schema are byte-identical. No change to `AppState`, the single-profile TUI loop, or any existing command. `proxxx fleet` ignores `--profile` (it aggregates all of them); `--secure` is irrelevant (no writes exist).
- The screen shows a per-cluster summary (reachable/down + error, node count, running/stopped guests, aggregate CPU cores, memory used/total, and storage used/total de-duplicated across nodes) plus an aggregated guest table; `↑↓` selects a cluster, `Tab` toggles the guest pane between the selected cluster and the whole fleet, and **`Enter` drills into the selected cluster** — opening its full single-profile TUI (nodes/guests/detail), returning to the fleet on quit. An unreachable cluster retains its last-known data (flagged stale) instead of flickering empty.
- Tests: 11 reducer/aggregation unit tests, a wiremock multi-server integration test (real `PxClient` fan-out + graceful one-cluster-down degradation + shared-VMID attribution), a render snapshot, and a read-only live verification script (`tests/live/test_fleet_readonly.sh`).

## [0.7.4] — 2026-05-28

Headline: **WebSocket handshake auth headers + release-notes line-wrap fix.** Two small focused threads landed since v0.7.3, neither user-facing on the CLI surface but both important on the operational surface. The WS auth headers PR (#135) plumbs PVE authentication into the WebSocket termproxy handshake — proxxx's `serial <vmid>` console previously relied solely on the URL-embedded ticket that PVE happens to accept; this release also sends the proper `Authorization` / `Cookie` headers as belt-and-suspenders, opens the door for future WS endpoints (vncproxy, spiceproxy) that don't embed the ticket in the URL, and refreshes any about-to-expire PAM ticket before the handshake (the existing `ensure_auth()` is now called before exposing the cookie — a long-idle session no longer fails on the WS upgrade). The release-notes line-wrap fix (#134, already shipped on main, retroactively backfilled across v0.6.1 through v0.7.3 release pages) makes future tags render flat paragraphs on the GitHub release page; the `release.yml` extractor now runs the awk-extracted CHANGELOG section through a small Python paragraph-unwrap that preserves list items, headings, blockquotes, tables, and fenced code blocks.

### Added — `AuthMethod::headers()` + `PxClient::auth_headers()`

- **`AuthMethod::headers()`** (`src/api/auth.rs`) returns the raw header pairs the WS handshake needs:
  - Token auth → one `Authorization: PVEAPIToken=<user>!<id>=<secret>`
  - Password auth → one `Cookie: PVEAuthCookie=<ticket>`
  The CSRF prevention token is **deliberately omitted** — PVE requires it only on state-changing HTTP requests, never on the WebSocket upgrade. A regression test pins the omission so a future contributor doesn't "helpfully" add it.

- **`PxClient::auth_headers() -> Result<Vec<(String, String)>>`** (`src/api/client.rs`) wraps the above and **calls the existing `ensure_auth()` first** — so an idle PAM session about to expire gets refreshed before we expose the cookie. Token auth is a no-op refresh (token secrets don't have a TTL on the PVE side).

- **`wsterm::connect()`** (`src/wsterm/mod.rs`) now takes `headers: &[(String, String)]` and injects them into the tungstenite request before handshake. Empty slice = no headers (the existing in-tree callers either pass `&[]` for no creds or `client.auth_headers().await?` for authenticated WS).

- **`execute_serial`** in `src/cli/console.rs` wires `client.auth_headers().await?` into the `wsterm::connect` call. Comment in-source explains why the refresh-before-WS matters.

### Fixed — release-notes line-wrap rendering

- **`release.yml` "Compose release notes" step** (PR #134, already on main pre-v0.7.4) now pipes the awk-extracted CHANGELOG section through a small Python paragraph-unwrap. GitHub's release-page renderer treats single newlines inside paragraphs as **hard line breaks** (visible as `<br>`-style splits), NOT as the soft-wrap-becomes-space behaviour of standard GFM. Without post-processing, every release page from v0.6.1 onward was rendering with visible mid-sentence breaks. The unwrap preserves list items (`- / * / + / N. / N)`), headings (`#`), blockquotes (`>`), tables (`|`), indented continuations, and fenced code blocks. Idempotent on already-flat input. **Backfilled in-place across v0.6.1 – v0.7.3** (6 release pages, 142 paragraph-internal newlines unwrapped) via `gh release edit --notes-file` before #134 merged.

### Tests

- **+3 lib unit tests** for `AuthMethod`:
  - `token_headers_emit_pveapi_authorization` — pins exact `PVEAPIToken=<user>!<id>=<secret>` shape
  - `password_headers_emit_pveauthcookie_only` — pins cookie shape + CSRF-non-leak
  - `token_headers_handle_special_chars_in_user_and_token_id` — delimiter robustness for `@` / `-` / digits
- Lib total: 643 → **646**.

### Carved out of this release (deliberate scope discipline)

The starting WIP for #135 contained two unrelated changes that I split out:
- A `PxClient::get_node_zfs_detail()` method (no caller in-tree yet) — belongs in a focused ZFS-detail PR when there's an operator-facing entry point for it.
- A `fn config_path() → pub fn config_path()` visibility flip — unused by anything else in the WIP. Belongs with whatever future feature actually needs cross-module access to the config path.

Neither carve-out was destructive; both are trivially re-applied in their own PR when scope is clear.

### Lessons saved to l0-memory

Six durable lessons from this multi-sprint session went into l0-memory (`repo:proxxx` scope) — searchable via FTS:
- `pve-api-immutability-means-echo-not-omit` — the v0.7.0 → v0.7.1 type-on-PUT trap
- `live-e2e-essential-for-state-families` — mocked tests can't catch wire-contract bugs
- `inter-family-ordering-state-apply` — cross-family dependency ordering + 404-tolerant deletes (v0.7.3)
- `config-url-drift-false-alarm` — the v0.7.1 → v0.7.2 PAM-auth phantom debug
- `state-family-implementation-checklist` — 19-step recipe for adding a new state family
- `release-notes-line-wrap-rendering` — the v0.7.4 line-wrap fix lesson

## [0.7.3] — 2026-05-28

Headline: **Epic [#74](https://github.com/fabriziosalmi/proxxx/issues/74)
epilogue — HA resources ship as the seventh state family at 7/6.** The
HA-rules family in v0.7.0 closed epic #74 at 6/6 writable GitOps
families but left an asymmetry: declaring an HA rule still required
the operator to pre-register the referenced resource SIDs via raw curl
to `/cluster/ha/resources`. v0.7.3 adds the resources family as the
self-contained epilogue, making the GitOps loop fully round-trippable
through `proxxx state {export,diff,apply}` end-to-end with no raw-API
side channels. `tests/live/test_state_ha_rules.sh` now declares
resources + rules in a single TOML and runs the full lifecycle as one
self-contained sequence — **7/7 PASS, 0 FAIL** against PVE 9.1.1.

### Added — HA resources state family

- **`proxxx state --resource ha-resources`** — full CRUD via
  `/cluster/ha/resources` (PVE 9+). Identity is `sid` (`vm:<vmid>` or
  `ct:<vmid>`). Fields: `state` (`started` | `enabled` | `stopped` |
  `disabled` | `ignored`), `max_restart`, `max_relocate`, `failback`,
  `auto_rebalance`, `comment`. `type` (`vm`/`ct`) is auto-derived from
  the SID prefix and never set in TOML. `group` is **never sent** —
  PVE 9 rejects with `invalid parameter 'group': ha groups have been
  migrated to rules`.
- **Inter-family dependency handled**: `Resource::all()` orders
  `HaResources` BEFORE `HaRules` so creates flow naturally
  (resources-then-rules; rules reference resource SIDs). On the
  delete side, PVE's `purge=1` default on resource DELETE
  auto-removes the SID from referencing rules; the rule-delete apply
  path is now **404-tolerant** to keep the cleanup idempotent. A
  dedicated `diff_emits_ha_resources_changes_before_ha_rules` test +
  the `resource_all_includes_every_variant` assertion pin the
  ordering invariant.
- **Preflight tiers**:
  - `HaResourceDelete` → **Severe**. Removes a VM/CT from HA
    management (CRM stops restarting/relocating it) AND auto-purges
    referencing rules. Operator-perceived behaviour shift is a step
    change; refuses without `--allow-risk`.
  - `HaResourceStateChange` → **Warning** when going from
    `started`/`enabled` to `disabled`/`ignored`/`stopped` (CRM
    enforcement stops). Re-enabling (the reverse direction) is
    additive and risk-free, deliberately not flagged.

### Discovered live (fix shipped this commit)

- **PVE 9.1.1's `/cluster/ha/resources` schema rejects `auto-rebalance`**
  outright with HTTP 400 `"property is not defined in schema and the
  schema does not allow additional properties"`. The field exists in
  `pve-ha-manager.git` HEAD but hasn't yet shipped in the 9.1.x
  stable line. Fix: `ha_resource_params` emits both `failback` and
  `auto-rebalance` ONLY when explicitly opt-out (`false`); when at
  PVE's server-side default (`true`), they're skipped on the wire. On
  PVE 9.2+ where the field lands, an explicit `failback = false` or
  `auto_rebalance = false` in TOML will still cleanly opt out (the
  test `ha_resource_create_emits_failback_only_when_explicitly_false`
  pins this contract).

### Changed — test infrastructure

- **`tests/live/test_state_ha_rules.sh`** — pre-step ⓪ (raw-API
  resource registration) is GONE. The test TOML now declares
  `[[ha_resources]]` alongside `[[ha_rules]]` and the apply runs as
  one operation. Step 1 expects 4 `— applied` lines (2 resources +
  2 rules). Step 6 expects 4 `— applied` deletes with preflight
  firing SEVERE on each resource + Warning on each rule. Defensive
  raw-API cleanup loop in `trap EXIT` stays as a belt-and-braces
  safety net in case the proxxx apply itself fails mid-run.
- **`pre-commit/01-feature-coverage.md`** — new row for the HA
  resources family, with all the live-caught findings inlined.
  The HA-rules row's "Discovered live #2" (raw-API pre-registration
  workaround) is updated to point at v0.7.3's resolution.

### Tests

- **+12 lib unit tests** (3 diff, 5 apply, 4 preflight). Lib total:
  631 → 643.
- **Cross-family invariant test**: `Resource::all()` now asserts
  `HaResources` is positioned BEFORE `HaRules` so a future re-order
  breaks the build, not the live cluster.
- **Live e2e**: 7/7 PASS against PVE 9.1.1 (homelab 192.168.0.122).

## [0.7.2] — 2026-05-28

Headline: **Corrigendum to v0.7.1 — the "PAM-auth POST limitation" was a
false alarm.** Docs-only patch release; zero code change. Sprint 2 set out
to investigate the scope of a "PAM-authenticated `state apply` POST fails
where API-token POST succeeds" limitation flagged in v0.7.1's CHANGELOG.
A deliberate matrix test — pools, firewall aliases, backup-jobs,
notification matchers, and HA rules, all POST'd via `proxxx state apply`
under PAM auth on the test cluster — came back **5/5 `applied`**. PAM auth
is not broken on any state family.

The original v0.7.1 finding was caused by **config-URL drift between
sessions**, not by an auth-flavor bug: while Sprint 1.A was running the
live HA-rules tests, the operator's default `config.toml` pointed at one
cluster (`192.168.0.120`) while `tests/live/env.local`'s API token
addressed a different cluster (`192.168.0.122`). The "cannot use
unmanaged resource(s) ct:7777" error was correct from the
`config.toml`-cluster's perspective — `ct:7777` had been registered as
an HA resource on the env.local-cluster via raw curl, but never on the
config-cluster which proxxx was actually hitting. Apples-to-oranges in
disguise, not a PVE worker-cache quirk and not a proxxx serialisation
bug.

### Changed — docs retracted

- **`CHANGELOG.md` [0.7.1]**: leaves the historical section unchanged
  (commit history immutable), but the v0.7.1 GitHub release page body is
  backfilled in-place via `gh release edit` with the "PAM-auth POST
  limitation" paragraph replaced by a retraction pointer to this v0.7.2
  entry. Operator-facing surface stays accurate.
- **`pre-commit/01-feature-coverage.md` HA-rules row**: the "Discovered
  live #3 (known limitation, not yet fixed)" paragraph is retracted with
  a note explaining the Sprint 2 matrix outcome + the root cause
  (config-URL drift). "Discovered live #1" (the real type-on-PUT bug
  fixed in v0.7.1) and "Discovered live #2" (HA resources need
  pre-registration before rule creates — real PVE behaviour) are
  unchanged.
- **`tests/live/test_state_ha_rules.sh`**: the auth-note header paragraph
  is rewritten — the temporary token-auth config swap stays as a
  defensive fixture-isolation measure (consistent known-good auth flavor
  for the test), but the framing as a "PAM bug workaround" is corrected.

### Lesson

The Sprint 1.A live-test discovery uncovered a real bug (the v0.7.1
`type`-on-PUT fix) but also a false alarm. The false alarm survived to a
shipped release because the in-the-moment debugging conflated two
variables: the in-tree `tests/live/env.local` had a different URL than
the operator's macOS-default `config.toml`. Future live-mutation scripts
should explicitly **assert the cluster URL is the same across both
ends** — either log it from each side, or use only one source of truth
(env.local) for the duration of the test. The Sprint 2 matrix script
captures this discipline (single source of URL, no implicit fallback to
the operator's default config).

## [0.7.1] — 2026-05-28

Headline: **HA-rules PUT bug fix (caught by new live e2e) + `api/types.rs`
modularised by PVE category.** Patch release closing the v0.7.0 verification
debt: the new HA-rules state family from v0.7.0 had a real bug that mocked
unit tests didn't catch — `ha_rule_params` omitted the `type` field from
PUT requests, based on a mis-reading of pve-ha-manager.git's `Rules.pm`
comment that the field is "immutable on PUT" (PVE-API parlance for "value
cannot CHANGE between current state and request" — NOT "omit the field").
Live PVE 9.1.1 rejects PUT `/cluster/ha/rules/{rule}` with HTTP 400
`{"errors":{"type":"property is missing"}}` when absent. v0.7.1 always
emits `type` on both POST and PUT; the actual immutability guard stays in
`apply_ha_rule_update` (a type *change* between before/after still surfaces
an actionable "delete + re-create" error before the gateway call). Caught
by a new self-contained live mutation script (`tests/live/
test_state_ha_rules.sh`) that runs the full GitOps lifecycle for both rule
types against PVE 9.1.x — create node-affinity + resource-affinity, flip
`strict=true` (SEVERE preflight refuses without `--allow-risk`),
`--allow-risk` succeeds (the fix-verification step), `state export`
round-trips `strict = true` persisted, restore baseline via `--prune
--allow-risk`. 8/8 PASS, 0 FAIL with RAII cleanup. Alongside the fix:
`src/api/types.rs` (which had grown to 3 511 LOC / 96 types over many
feature PRs — the cliff point for adding new wire types had become "find
the right neighborhood in the 3.5K file") split into 16 per-category
submodules under `src/api/types/`. Pure mechanical refactor — every `pub
struct` / `pub enum` moved verbatim with doc comments, derive attrs, body,
and `impl` blocks; the 3 deserialize helpers promoted to `pub(crate) fn`
in `mod.rs`. Public API surface byte-identical (every
`crate::api::types::Foo` callsite still resolves via `pub use X::*;`
re-exports). 631 lib + ~1078 all-targets tests green pre+post, zero
behaviour change.

### Fixed — HA-rule PUT contract

- **`type` field now emitted on PUT `/cluster/ha/rules/{rule}`.**
  v0.7.0 omitted it under the wrong reading of "immutable on PUT" — PVE
  9.1.x rejects the omission with HTTP 400. `ha_rule_params` always
  sends `type` now; the unit-test regression
  (`ha_rule_update_clears_emptied_fields_via_repeated_delete_keys`)
  asserts the field IS present + matches `before.rule_type`. The
  pre-existing type-change rejection (live PVE error wrapped in an
  actionable `"delete + re-create"` bail) still runs at the apply layer
  before any gateway call.

### Added — live HA-rules e2e harness

- **`tests/live/test_state_ha_rules.sh`** — full GitOps mutation
  lifecycle for HA rules against a real PVE 9.1.x cluster. Two rule
  types, strict-flip preflight, `--allow-risk` override, `--prune`
  restore, RAII via `trap EXIT`. Forces token auth via a temporary
  `config.toml` swap (see "known limitation" below).
- Coverage matrix `pre-commit/01-feature-coverage.md` updated: rows
  55+56 (Read HA topology) promoted ⚠️ → ✅; new dedicated row for the
  HA-rules state family inserted after row 124, with the three
  live-discovered findings inlined.

### Changed — `api/types.rs` modularised

- **`src/api/types.rs` (3 511 LOC, 96 types) → `src/api/types/` (16 submodules).**
  Per-category split: `task` · `node` · `node_hw` · `guest` ·
  `guest_agent` · `storage` · `cluster` · `pool` · `firewall` · `ha` ·
  `notifications` · `access` · `acme` · `backup` · `console` ·
  `replication`. Smallest module is `pool.rs` (34 LOC, 3 small structs);
  largest is `guest.rs` (790 LOC — QEMU/LXC config soup with the
  `QemuNetSpec` / `QemuDiskSpec` parsers). `mod.rs` is 150 LOC of
  re-exports + 3 shared `pub(crate)` deserialize helpers
  (`deserialize_u32_from_str_or_num`, `deserialize_u64_from_str_or_num`,
  `deserialize_bool_from_int`).
- **Public API surface byte-identical.** Every consumer of
  `crate::api::types::Foo` (and the test files using
  `use proxxx::api::types::*`) resolves through the `pub use X::*;`
  re-exports. Zero caller changes anywhere else in the tree.

### Known limitations (documented, not fixed in this release)

- **PVE rejects HA-rule creates referencing SIDs not registered as HA
  resources** — `cannot use unmanaged resource(s) <sid>`. The live test
  script pre-registers via the raw `/cluster/ha/resources` API.
  proxxx doesn't yet manage HA *resources* as a state family — natural
  follow-up to epic #74 (which closed at 6/6 writable families with
  v0.7.0; HA resources would make it 7/6, an epic #74 epilogue).
- **PAM-authenticated `state apply` POST to `/cluster/ha/rules` fails
  where API-token POST succeeds** with byte-identical params. Direct
  curl with PAM headers reproduces, so it's not a proxxx serialisation
  issue — likely a PVE-side worker-cache or session-context quirk; not
  introduced by v0.7.0. The live test forces token auth via a
  temporary config swap. Investigation tracked separately.

## [0.7.0] — 2026-05-28

Headline: **HA-rules closes epic [#74](https://github.com/fabriziosalmi/proxxx/issues/74) at 6/6 +
`russh` ZIP-bomb security bump + release-notes extractor fix.** Minor bump because HA rules is
the sixth (and final) writable GitOps state family — `proxxx state {export,diff,apply}` now
covers pools, ACL, storage, backup jobs, cluster firewall, notification matchers, AND HA
placement rules (`node-affinity` + `resource-affinity` under `/cluster/ha/rules`, PVE 9+),
with full preflight risk tiering. The original deferral reason ("PVE 9 has no write gateway
for HA rules") is gone — `pve-ha-manager.git src/PVE/API2/HA/Rules.pm` exposes the full
CRUD surface today (POST + PUT + DELETE under `Sys.Console`); proxxx now uses it.
Alongside the family: `russh 0.60.3 → 0.61.1` absorbs **GHSA-wwx6-x28x-8259** (a malicious SSH
peer could craft a ZIP-bomb-style packet under compression negotiation to OOM the client
process), the release-notes extractor in `release.yml` now picks the per-version CHANGELOG
section instead of `[Unreleased]` (the v0.6.1 / v0.6.2 release pages shipped with
`_no entries yet._` as their body; backfilled to the actual content as part of this release),
and routine dependabot drains: `serde_json 1.0.150`, `codeql-action 4.36.0`, Ubuntu 24.04
cloud-image re-pinned (build 20260518).

### Added — HA placement rules state family (epic #74 close)

- **`proxxx state --resource ha-rules`** — full CRUD via `/cluster/ha/rules` (PVE 9+).
  Two PVE-side rule types are modelled today and both round-trip through export → diff →
  apply unchanged:
  - **`node-affinity`** — pin an HA resource set to a node set, optionally with
    `node:priority` notation (`pve1:5,pve2`), optionally `strict` (no fallback to other
    nodes). Replaces what PVE-8 HA *groups* did. Strict-flip on an Update is preflight-
    Severe (CRM can force-migrate constrained guests within seconds).
  - **`resource-affinity`** — `positive` collocates the set on one node, `negative`
    keeps them on different nodes (anti-affinity / spread). No `nodes` field; placement
    is computed relative to the set itself.
  - Common fields across both: `rule` (identity), `type` (immutable on PUT —
    type-change is caught upstream with an actionable `"delete + re-create"` error
    instead of PVE's cryptic message), `resources` (sorted `Vec<String>` of SIDs on
    disk for TOML readability + diff-stable set equality), `disable`, `comment`.
  - Update path applies the matcher lesson: empty fields are cleared via repeated
    `delete=<key>` params (never CSV — PVE rejects CSV on per-rule endpoints).
  - Preflight: `HaRuleDelete` is Warning (resources fall back to global HA defaults;
    no outage, just constraint loss). `HaRuleStrictChange` on a `node-affinity` rule
    is Severe — flipping `strict` can cascade into a fleet-wide forced migration as
    soon as the CRM tick.
  - +12 unit tests across `diff` / `apply` / `preflight` covering CRUD dispatch, leak
    checks (no field bleed across plugin types), type-change rejection, strict-flip
    preflight detection. `Resource::all()` now guards seven variants — adding a family
    here is the durable single-source-of-truth lesson from v0.5.0.

### Security

- **`russh 0.60.3 → 0.61.1` — GHSA-wwx6-x28x-8259.** When compression is negotiated, a
  malicious SSH peer could craft a "ZIP-bomb" packet that bypassed the maximum-packet-size
  check and forced the receiver to OOM. proxxx uses `russh` for guest SSH consoles + the
  PBS / SSH worker pool, so a compromised PVE node or a hostile guest could have exploited
  this against the proxxx client process. Russh 0.61.1 closes it. The 0.61 series also adds
  zero-copy `*_bytes` write APIs (not yet adopted by proxxx — performance follow-up).

### Changed — dependencies + CI

- **`serde_json 1.0.149 → 1.0.150`** (patch-and-minor dependabot group). Tightens
  non-string enum-object-key rejection on deserialize.
- **`github/codeql-action 4.35.5 → 4.36.0`** (CI action only).
- **Cloud-image registry re-pinned**: Ubuntu 24.04 noble → build 20260518 + fresh SHA-256
  (automated weekly cron, single registry-entry change, validated by the
  `cargo test --release --lib cloudimg` invariants).

### Fixed — release-notes extractor

- **`release.yml` "Compose release notes" step now prefers the per-version
  `## [X.Y.Z]` CHANGELOG section** over `[Unreleased]`. The repo's bump convention
  adds a new versioned section while leaving `[Unreleased]` with a `_no entries yet._`
  placeholder; every release page from v0.6.1 onward was shipping with that
  placeholder as the rendered body. The new extractor uses `awk -v v="$VERSION"`
  to match the literal version-stamped header, falling back to `[Unreleased]`
  for the pre-bump-commit window and to a CHANGELOG.md link if both are empty.
  The v0.6.1 and v0.6.2 release pages have been backfilled in-place to the
  proper content as part of this release.

### Out of scope (deferred)

- **HA resources** (`/cluster/ha/resources`) — which guests are HA-managed (vs. *how*
  they're placed). The read path is wired (`list_ha_resources`); a separate state family
  for the write path is a follow-up.
- **Legacy `/cluster/ha/groups`** — PVE 9 migrated this to `/cluster/ha/rules`. proxxx
  targets PVE 9.x; no compat shim shipped.
- **Live e2e for HA-rules** against the homelab cluster — pending; schema validated
  against `pve-ha-manager.git` HEAD, unit + integration suites green offline (~1078 / 1078).

## [0.6.2] — 2026-05-28

Headline: **Module shape — lift HTTP transport and the watch dispatch out
of the two largest monolithic files, behind a green audit gate.** Pure
housekeeping patch release: zero behaviour change, zero public-surface
change, no CLI/JSON contract movement. The retry/backoff state machine
and the bounded-response reader move from `src/api/client.rs` into a new
`src/api/transport.rs` (10 helpers, all `pub(super)`, ~149 lines lifted);
doc comments, audit-trail rationales (SPOF 2.2, Gemini wave-3, the
blocking-threshold derivation) and byte-for-byte semantics survive the
move unchanged. The 173-line `Command::Watch` arm in `src/cli/mod.rs`
becomes a four-function module at `src/cli/watch.rs` (`execute_watch`
dispatch + `watch_until` / `watch_since` + per-target probes); `proxxx
watch --help` and the emitted JSON shapes (`condition_met`, the `diff`
array) are byte-identical pre and post. The scheduled supply-chain audit
cron is unblocked by transitively bumping `aes 0.9.0 → 0.9.1` (upstream
yanked 0.9.0 on 2026-05-27; we pull it via `russh 0.60.3` only). And the
`pbs_missing_binary_yields_clear_message` regression test is now hermetic
— tempdir HOME, explicit `--yes` (the confirmation gate `pbs restore` now
requires), unset stray `PROXXX_*` creds — so it tests the named behaviour
on any machine instead of passing-by-accident against whatever
`~/.config/proxxx/config.toml` happens to exist locally.

### Changed
- **HTTP transport helpers extracted to `src/api/transport.rs`.**
  Retry policy (`RETRY_MAX_ATTEMPTS`, `RETRY_BASE_DELAY_MS`,
  `is_retryable_status`, `is_retryable_error`, `backoff_delay`,
  `retry_after_secs`) and the bounded-body / blocking-parse plumbing
  (`MAX_RESPONSE_BYTES`, `PARSE_BLOCKING_THRESHOLD`,
  `parse_json_maybe_blocking`, `read_bounded_body`) all moved verbatim,
  `pub(super)` only. `client.rs` keeps a single
  `use super::transport::{...}`. No public API change.
- **`Command::Watch` dispatch extracted to `src/cli/watch.rs`.** Single
  call site in `cli/mod.rs`; same flags, same JSON shapes, same
  behaviour, plus three falls-out cleanups from the split
  (`parse.map_err(...)?`, `find().ok_or_else(...)?`,
  `notify.as_deref() == Some("telegram")`).
- **`aes 0.9.0 → 0.9.1`** (Cargo.lock only). Upstream yanked 0.9.0 on
  2026-05-27; we pull it transitively via `russh 0.60.3`'s pre-release
  crypto chain. Zero source change, zero behavioural risk. Unblocks the
  scheduled `cargo audit --deny warnings` cron.

### Fixed
- **`pbs_missing_binary_yields_clear_message` regression test.** Two
  silent passes:
  1. `pbs restore --yes` became a required confirmation gate; the test
     was bailing on that before reaching the missing-binary check.
  2. The test inherited the developer's real `$HOME` and picked up any
     existing `~/.config/proxxx/config.toml`.
  Both fixed: explicit `--yes`, tempdir HOME with a minimal pinned
  `config.toml`, and explicit `env_remove` of `PROXXX_TOKEN_SECRET` /
  `PROXXX_PASSWORD` / `PROXXX_PBS_TOKEN_SECRET`. The match bar is also
  broadened to accept any of `proxmox-backup-client` / `not found` /
  `install` / `config` / `pbs` / `profile`, since depending on whether
  the binary check or the config check fires first, both messages are
  actionable.

## [0.6.1] — 2026-05-23

Headline: **Correctness — kill the swallowed-error → silent-partial-result
bug class.** Cluster-wide read paths that gather data per-node used to
hand-roll `for n in nodes { if let Ok(x) = fetch(n) { out.extend(x) } }`,
which swallowed a transient per-node failure (a 401 mid token-rotation, a
fenced node, a network blip) and returned a *partial* list as a complete
success. Downstream this surfaced as guests/pools vanishing, or a vmid
reading as "not found" — which could mis-target or abort a mutation on the
wrong node. The ~24 ad-hoc sites are replaced by three propagating,
online-gated default methods on `ProxmoxGateway`: `get_all_guests()`,
`get_all_storage_pools()`, and `find_guest(vmid)` (`Ok(None)` = genuinely
absent vs `Err` = fetch failed). An offline node reports no error (nothing
to list); a failed fetch on a *reachable* node propagates. The Prometheus
exporter — which returns a `String` and cannot propagate — instead gains a
`proxxx_up` gauge (`0` if any fetch in the scrape failed), the idiomatic
way to flag a partial scrape without silently dropping counters. CLI
commands, exit codes, and JSON output are unchanged (additive `proxxx_up`
only); behavior differs solely on the partial-failure path, now covered by
a new mock regression test.

## [0.6.0] — 2026-05-22

Headline: **Per-profile incident freeze.** The `incident freeze` / `thaw`
write kill-switch gains a `--profile <name>` scope — freeze one cluster
during an incident while the rest of the fleet stays writable. Without
`--profile` the freeze is global (fleet-wide), exactly as before. A
mutation is refused if the global lock OR the client's own profile lock is
active, so freezing profile A never blocks profile B; the gate lives in
`PxClient::{post,put,delete}`, so `state apply` and every other write
honour it. `incident status` now reports all active freezes (global +
per-profile) — its `--format json` keeps the `state` field (the global
freeze) and adds a `freezes` array, additive per the SemVer contract.
Lock files: the global `freeze.lock` (unchanged on disk) plus per-profile
`freeze.<profile>.lock`; pre-existing/global locks read back byte-identically.

## [0.5.0] — 2026-05-22

Headline: **GitOps state expansion + cloud-init templates.** Three new
declaratively-managed resource families — scheduled backup jobs, the
cluster firewall (options + aliases + IP sets + security groups), and
notification matchers — carry epic #74 to 5 of 6 writable families
(HA groups deferred: PVE 9's node-affinity `/cluster/ha/rules` has no
write gateway yet). Plus one-command cloud-init **template** provisioning
(`cloud-img provision`), PBS single-file restore (`pbs restore
--pattern`), an interactive TUI SSH-key passphrase prompt, and a
correctness fix turning `patch`'s silent serial downgrade into a loud
error. Seven PRs (#112–#118); every state family and `cloud-img
provision` verified end-to-end against the live PVE 9.1.1 cluster.

### Added
- **TUI prompts for an SSH key passphrase interactively.** When a guest
  SSH session uses an encrypted OpenSSH key and no passphrase is set
  (neither `PROXXX_SSH_KEY_PASSPHRASE` nor a prior prompt), the TUI now
  shows a masked passphrase prompt before connecting instead of failing.
  The entered passphrase is cached for the rest of the session (prompted
  at most once), rendered as bullets (never echoed), and Esc cancels.
  Detection is a metadata-only check of the key file — no connection
  attempt is wasted.
- **`pbs restore --pattern` — single-file / selective restore.** The
  restore command now takes one or more `--pattern <glob>` flags
  (repeatable), wiring `proxmox-backup-client restore`'s own pattern
  matching to extract just the matching files/subdirs instead of the
  whole archive (e.g. `--pattern etc/network/interfaces`). Matched
  files land under `--target` preserving their in-archive path. No FUSE
  mount needed — the earlier "single-file needs FUSE" assumption was
  wrong. (Command-construction is unit-tested; an end-to-end restore
  needs a Linux host with `proxmox-backup-client` + a live datastore.)
- **`cloud-img provision` — one-command cloud-init template** (#65).
  Completes the feature's original purpose: instead of the manual
  `qm create` → `qm set --scsiN import-from` → `--ide2 cloudinit` →
  `--ciuser/--sshkeys/--ipconfig0` → `qm template` dance, a single
  verified command does it all. It (optionally) downloads the
  checksum-pinned image, creates the VM with the image imported as its
  boot disk (PVE 8.2+ `import-from`), attaches a cloud-init drive, wires
  the serial console + guest agent (cloud images need a serial console),
  applies cloud-init config, optionally grows the disk, and converts to
  a template. `--no-template` / `--start` stop short of templating for
  boot-testing; `--download` fetches the image inline. Verified
  end-to-end against PVE 9.1.1.
- **`state` now manages scheduled backup jobs** (epic #74). A new
  `backup-jobs` resource family is wired through the full GitOps loop:
  `state export --resource backup-jobs` snapshots every recurring
  vzdump job (`/cluster/backup`) sorted by `id`, `state diff` detects
  drift, and `state apply` converges (create / update / delete). The
  scheduler-derived `next-run` and the deprecated `mailnotification`
  field are dropped on export so the TOML stays diff-stable. Deleting a
  backup job is flagged as a **Warning** by the pre-flight gate (silent
  loss of data protection). `--resource all` now includes backup jobs.
- **`state` now manages the cluster firewall** (epic #74). A new
  `firewall-cluster` resource family covers the whole writable surface
  in one selector: the **options** singleton (enable / default policy /
  ebtables / log-ratelimit), **aliases**, **IP sets** (with nested CIDR
  membership), and **security groups**. Export is diff-stable (sets +
  CIDRs sorted; derived `ipversion`/`digest` dropped). Apply handles the
  awkward PVE semantics: an IP-set comment change has no update endpoint
  so it's a lossless delete+recreate, while CIDR membership is an
  incremental add/remove delta; security groups are create/delete only
  (no PVE update, and their rules are read-only, so a recreate would
  drop them). Pre-flight gates the dangerous moves: disabling the
  firewall or deleting a security group are **Severe**; loosening a
  default policy to ACCEPT and deleting aliases / IP sets are
  **Warnings**. `--resource all` now includes the firewall.
- **`state` now manages notification matchers** (epic #74). A new
  `notifications` resource family brings PVE's native notification
  *matchers* (routing rules) into the GitOps loop with full CRUD:
  `state export --resource notifications` snapshots every matcher
  (`/cluster/notifications/matchers`) sorted by `name` (list fields
  canonicalised, `origin` dropped), `diff` detects drift, `apply`
  converges. Matcher updates use PVE's `delete` param to clear emptied
  fields so a stripped-down matcher actually converges. Deleting a
  matcher is a pre-flight **Warning** (events it routed go silently
  unrouted). Notification *endpoints* are intentionally out of scope —
  they carry secrets PVE never returns on `GET`, so they can't
  round-trip export→apply; operators provision endpoints out-of-band
  and `state` manages the routing rules that reference them by name.
  `--resource all` now includes notifications.

### Changed
- **`patch apply` now rejects `max_concurrent > 1` with a loud error**
  instead of silently downgrading to serial. Patch execution is serial
  by design (a node upgrade is a non-atomic apt dist-upgrade + reboot;
  concurrent reboots risk HA quorum loss), so a parallel request that
  was quietly ignored misled the caller. It now fails fast with a
  message pointing at the workaround — multiple invocations over
  disjoint node sets. No CLI flag sets it above 1 today, so this only
  affects programmatic callers constructing `PatchStrategy`.

## [0.4.0] — 2026-05-21

Headline: **post-v0.3.0 debug pass** — a code-wide hunt fixed
remote-triggerable crash panics and several robustness gaps, and made
`cloud-img download` actually work (it never could before). Five
bug-fix PRs (#106-#109) on top of v0.3.0, every one regression-tested;
one fix verified end-to-end against the live PVE 9.1.1 cluster. Minor
bump: `cloud-img` goes non-functional → working, plus a `--format json`
field rename on that (previously dead) surface.

### Fixed
- **`cloud-img download` now works** (#108). The v0.3.0 registry shipped
  with all-zero placeholder SHAs (every download refused) AND two latent
  bugs the placeholders masked: the Alpine entry named a non-existent
  `nocloud_` artifact, and all three `.qcow2` entries used
  `content=iso` — which PVE rejects with "wrong file extension"
  (`.qcow2` requires `content=import`, PVE 8.2+). All four entries are
  now pinned to **dated immutable build dirs** with **real checksums**
  fetched from each distro's official sidecar, verified end-to-end
  against PVE 9.1.1 (live Alpine download → checksum OK).
- **Char-boundary-safe truncation** (#106) — 4 UTF-8 byte-slice panic
  vectors (`&s[..n]` / `split_at(len-1)`) that crashed the TUI / HITL
  daemon / CLI on PVE-supplied or operator text containing multi-byte
  characters (CJK / Cyrillic / emoji / `µ`).
- **PBS client typed errors** (#107) — PBS 401/403 now exit 4 (was a
  generic 1); the whole PBS `get()` helper routes through `ApiError`.
- **Connect timeouts** (#107) — termproxy WSS + SSH handshake no longer
  hang indefinitely on a black-holed node (20 s each).
- **Bounded resize body** (#107) — the disk-resize PUT was the last REST
  read with an unbounded body + untyped parse; now capped + `ApiError::Parse`.
- **TUI queued delete** (#109) — the `d` key enqueued a `DeleteGuest`
  the operation-queue executor couldn't dispatch ("Unsupported in queue
  yet"); now wired to `delete_guest`. Start/Stop/Restart were already
  handled; delete was the dead one.

### Changed
- **`CloudImg` checksum model**: the `sha256` field is renamed
  `checksum` and joined by `checksum_algorithm` (`sha256`/`sha512`),
  because Debian + Alpine publish only SHA-512. Affects
  `cloud-img list --output json` (field rename) and `cloud-img download`
  JSON (`sha256` → `checksum` + `checksum_algorithm`). Justified as a
  data-model fix on a surface that never produced a working download.
- Stale rustdoc corrected (#107): `state apply` pre-flight/HITL is
  shipped (not "out of scope"); firewall alias/IP-set/group CRUD is
  implemented (only individual rule add/remove remains).

## [0.3.0] — 2026-05-20

Headline: **GitOps for Proxmox + 17 new top-level commands + honest invariant attestation**.
24 feature PRs landed on 2026-05-20 morning closing the entire strategic-gap backlog
(#57-#73) and the cluster-state epic (#74). The evening shipped three test-only sweeps
(PR #101 / #102 / #103) that took honest end-to-end-verified invariant coverage from
~15% → ~37% (24 → 73 ✅ rows across `pre-commit/*.md`), and surfaced **three real latent
gaps** in the API client's typed-error path that ship-fixed alongside the test sweep.

Numbers: **429 → 536 lib tests** (+107) plus **+49 new integration tests** across the
sweep suites. Pre-flight risk gates + interactive HITL on state apply. Unified daemon
(alerts + HITL + schedule under one SIGTERM). MCP stdio + HTTP/SSE notifications at
parity. RRD time-window accounting integrated into per-pool/node/tag chargeback.

Minor-bump-worthy on the cumulative surface; new exit code (`8` —
incident lockdown). Detailed audit in [`docs/AUDIT-2026-05-20.md`](docs/AUDIT-2026-05-20.md).

### Added — cluster-state GitOps (epic #74)

- **`proxxx state export`** — byte-stable TOML snapshot of pools, ACL grants, cluster
  storage definitions. Diff-stable across runs against an unchanged cluster.
- **`proxxx state diff <declared.toml>`** — structural diff of declared vs live; exit 2
  on drift. CI-gateable.
- **`proxxx state apply <declared.toml> [--dry-run] [--prune] [--continue-on-error]
  [--allow-risk] [--interactive]`** — converge live toward declared. Pre-flight risk
  gate refuses Severe changes (non-empty pool delete, root-role ACL delete, shared-
  storage delete, batch ≥ 50) unless `--allow-risk`; `--interactive` adds per-Severe
  `[y/N]` stdin prompts. Exit code 6 on refusal.

### Added — new top-level commands

- **`proxxx migrate --stream`** — live per-disk progress bars (TTY) or NDJSON for migrations.
- **`proxxx logs tail [--node N] [--service U] [--since "1h ago"] [--grep PAT] [--no-follow]`**
  — cross-node journalctl fanout via SSH; client-side merge + filter. Graceful per-node failure.
- **`proxxx explain <error-id> [--output text|md|json]`** — bundled knowledge base for every
  typed error (13 entries). Cause / numbered fixes / diagnostic commands / references.
- **`proxxx incident {freeze,thaw,status}`** — cluster-wide write kill-switch with TTL +
  audit log. Halts `POST`/`PUT`/`DELETE`. Reads keep working. Exit code 8 on refused mutation.
- **`proxxx ls --all-profiles`** / **`proxxx find <vmid>`** — cross-cluster fanout for
  read-only queries. Per-cluster failures surface as error rows; rest of the fleet keeps
  answering. Writes deliberately not plumbed through fanout.
- **`proxxx describe [--output text|md|json|llm-context] [--include events|rbac|all]`** —
  structured cluster digest. The `llm-context` format is token-compact, designed to paste
  at the top of an LLM chat.
- **`proxxx serial --record [PATH]`** + **`proxxx play-cast <PATH>`** — asciinema cast v2
  recording and replay for serial sessions (compliance / training).
- **`proxxx cloud-img {list,download}`** — bundled SHA-256-pinned cloud-image registry
  (Ubuntu / Debian / Alpine / Fedora). Server-side verified download via PVE's `download-url`.
- **`proxxx schedule {add,list,remove,pause,resume,run-due}`** — interval-based scheduler
  for recurring proxxx operations. TOML-backed persistence at `<data_dir>/schedules.toml`.
- **`proxxx upgrade-check --target 9.x [--output text|json]`** — PVE major-upgrade
  pre-flight scanner. Bundled rule set with severity (info/warn/block). Exit 1 on any
  block-severity finding. CI-gateable.
- **`proxxx accounting --group-by pool|node|tag [--timeframe none|hour|day|week|month|year]
  [--include-unassigned]`** — per-pool / per-node / per-tag resource accounting. Time-window
  variants integrate per-guest RRD into CPU-hours, GiB·h, network GiB, disk-read/write GiB.
- **`proxxx heatmap [--output text|json]`** — per-node API RTT bucketed green/yellow/red.
- **`proxxx anomaly [--threshold 3.0] [--output text|json]`** — z-score outlier detection
  on cluster-wide CPU + mem% snapshot. Exit 1 on any anomaly.
- **`proxxx backup-verify [--max-age-days 7] [--output text|json]`** — metadata-level
  probe of each guest's most-recent backup (pass / stale / missing / error). Exit 1 on
  any missing or error.
- **`proxxx import <file> [--format raw|qcow2|vmdk|vdi|vhdx|vhd] [--output PATH] [--dry-run]`** —
  qemu-img convert wrapper. OVA/OVF parsing + libvirt-XML / VMware-direct chains deferred.
- **`proxxx gpu-inspect --node <node>`** — SSH-probe a node for IOMMU + vfio readiness +
  per-device lspci. The bind step (write configs + reboot) deferred behind explicit
  operator confirmation flow.
- **`proxxx daemon serve [--no-alerts] [--no-hitl] [--no-schedule]`** — unified
  background-task graph: alerts watcher + HITL Telegram listener + schedule run-due tick
  under one process with one SIGTERM handler. Per-component opt-out for systemd-unit
  flexibility.

### Added — MCP server-sent notifications (#71)

- **Both transports at parity**: HTTP `GET /mcp` SSE channel emits
  `event: notifications/cluster-event` per broker event; stdio interleaves
  JSON-RPC 2.0 `notifications/cluster-event` lines with the request/response
  stream. Lagged consumers see `notifications/lagged { missed: N }` (HTTP)
  or the equivalent JSON-RPC line (stdio).
- **Tracked event kinds**: `task_state_change` (started / completed / failed)
  and `incident` (frozen / thawed).
- New `notifications/subscribe` + `notifications/unsubscribe` RPC handlers
  (informational acks; actual delivery flows over the SSE/stdout channel
  automatically).

### Added — exit code 8

- **`8` — Incident lockdown active.** Fired by every `PxClient::{post,put,delete}`
  when the freeze lock is in effect. See [`docs/reference/exit-codes.md`](docs/reference/exit-codes.md).

### Fixed — typed-error gaps in `src/api/client.rs` (PR #101)

Three error paths flowed through plain `anyhow::Error::context` and so
`main.rs`'s exit-code dispatch couldn't route them and observability
layers couldn't `.downcast_ref::<ApiError>()`. All three now produce
the typed variant:

- DNS NXDOMAIN / TCP-handshake errors at the request layer →
  `ApiError::Transport`.
- Body-stream errors (mid-stream TCP close, decompression failures) at
  `read_bounded_body` → `ApiError::Transport`.
- JSON parse failures (HTML on 200 from CDN intercept; schema drift) at
  `parse_json_maybe_blocking` → `ApiError::Parse { path, source }`.

Each is regression-pinned by a wiremock-driven test in
`tests/error_handling_e2e.rs`.

### Added — invariant attestation sweep (PRs #101 / #102 / #103)

Three test-only PRs that promote every row in `pre-commit/02-error-handling.md`
and `pre-commit/04-resilience-and-chaos.md` from ❌ to ✅ with a named
attesting test, plus 6 opt-in live Rust tests against PVE 9.1.1 for
the `01-feature-coverage.md` typed-deser surfaces. Honest end-to-end-
verified row count across `pre-commit/*.md`: **24 → 73** (~15% → ~37%).

| Suite | Tests | What it pins |
| :--- | ---: | :--- |
| `tests/error_handling_e2e.rs` | 24 | HTTP status mapping, transport errors, sqlite resilience, CLI contract, TUI sanitation, SSH FFI, PBS FFI |
| `src/mcp/server.rs` inline | 3 | Stdin oversize DoS guard, non-UTF-8 byte delivery, JSON-RPC parse-error envelope shape |
| `tests/resilience_chaos_e2e.rs` | 20 | SIGTERM/SIGHUP raise + receive, semaphore caps, Instant monotonicity, `pop_view` shrink, WS frame cap, Proxmox quirks (HA-managed, pvestatd freeze, QGA timeout) |
| `tests/feature_coverage_live.rs` | 6 (`#[ignore]`-gated) | Typed deserializer round-trip vs live PVE 9.1.1 for `get_nodes` / `get_guests` / `get_guest_config` / `get_storage_pools` / `get_cluster_tasks` / `list_snapshots` |

### Architecture notes

- Stdin-reader background task pattern in `mcp::server` because `read_until`
  is NOT cancel-safe under `tokio::select!`. The mpsc-mediated channel makes
  the outer `select!` arm cancel-safe.
- Narrow-trait + blanket-impl pattern (`state::apply::StateWriteView`,
  `migrate_progress::TaskLogView`) lets unit tests stub a handful of
  methods instead of the full 200+-method gateway.
- Explicit-path `_at(path, …)` test variants (`incident::*_at`,
  `schedule::*_at`) avoid env-var contention under parallel test execution.

## [0.2.1] — 2026-05-19

Headline: **hardening pass** — 27 PRs in one day across three sessions,
zero real vulnerabilities discovered, two latent bugs fixed thanks to
property-based testing. No CLI / `--format json` / MCP registry / config
schema break; pure patch bump.

### Fixed
- **`app::snaptree::assemble` phantom synthetic node** (found by
  proptest). Duplicate-name input caused `build_node` to be called
  twice on the same name; the second call hit the `unwrap_or_else`
  fallback whose comment said "should never happen". The renderer
  would draw a ghost row with zeroed-out fields. Fix: deterministic
  dedup at function entry (sort by total order over every field,
  then `entry().or_insert()`). Pinned by
  `proptest::assemble_preserves_every_unique_name` +
  `assemble_order_independent`.
- **`shell_quote("")` returned bare empty** (found by proptest). The
  `chars().all(...)` predicate is vacuously true on an empty string,
  so empty input slid through the safe-char branch and bash word-
  splitting silently dropped the argument. `pveum user permissions
  --` would be called with NO user argument. Fix: explicit early
  return `"''"` for empty input. Pinned by
  `shell_quote_round_trips_via_bash_dequote`.

### Added
- **Property-test harness (`proptest`, ~25 properties × 256 random
  cases = ~6 400 invariant checks per `cargo test`)** across
  `util::sanitize` (6 — ANSI-injection defence), `app::snaptree` (6 —
  graph termination + dedup + order-independence + 1500-deep no
  overflow), `audit` (4 — HMAC chain integrity + mutation blast
  radius + design boundary), `cli::access::shell_quote` (4 — round-
  trip via bash dequoter + bare-path correctness + determinism + no
  metachars bare), `cli::common::BatchPolicy::parse` (5 — never
  panics + bounds + case-insensitive + trim-neutral).
- **`THREAT_MODEL.md`** — explicit attack-surface enumeration (8
  numbered surfaces with per-surface mitigation tables, accepted-
  risks section, verification-ladder table).
- **`ARCHITECTURE.md`** — one-page module map: "three callers, one
  core" diagram, per-`src/` directory responsibility, three end-to-
  end data flows traced (CLI mutation / TUI keystroke / MCP tool
  call), reducer + side-effect bus, process model.
- **`deny.toml`** + cargo-deny CI job + gate stage 4 — license
  whitelist (MIT/Apache-2.0/BSD/ISC/MPL-2.0 + r-efi LGPL exception),
  banned crates (openssl / native-tls / openssl-sys — rustls-only
  posture enforced at PR time), crates.io-only source lock,
  wildcard-version ban, multiple-major-version drift warning.
- **CodeQL Rust SAST workflow** — `security-and-quality` query set,
  weekly cron + every PR, SHA-pinned actions.
- **proptest-regressions seeds** checked in at
  `proptest-regressions/` so every shrunk counterexample (incl. the
  two bug-finding seeds above) replays deterministically on every
  `cargo test`.

### Changed
- Local gate + CI now run **8 stages** instead of 7. Added stage 4
  `cargo deny check`; subsequent stages renumbered (tests 4→5, live
  probes 5→6, mutation lifecycle 6→7). End-to-end wall time with
  live cluster: ~340–480 s.
- Clippy now silent on `--all-targets --all-features` (down from 43
  unique warnings). Deny tier: `unwrap_used / expect_used / panic /
  todo / await_holding_lock`.
- **Branch protection on `main`** enforced via GitHub: 5 required
  status checks, strict mode, linear history, no force push, no
  deletions, conversation resolution required.
- **Secret scanning + push protection** enabled at the repo level.
- README / CONTRIBUTING / docs/index reconciled: 7→8 stages, KLOC
  ~44→~48, wall-time refresh, clippy deny list refresh, added
  Property testing row to "By the numbers".

### Dependencies (no breaking-to-user changes)
- `tokio` 1.52.1 → 1.52.3 (mpsc bugfixes).
- `tower-http` 0.6.8 → 0.6.10.
- `russh` 0.60.2 → 0.60.3.
- `tokio-tungstenite` 0.24 → 0.29 — internal: `Message::Binary` now
  wraps `bytes::Bytes` instead of `Vec<u8>`, `WebSocketConfig` is
  `#[non_exhaustive]`.
- `crossterm` 0.28 → 0.29 (KeyModifiers Display impl change — we
  only use `.contains()`, no user impact).
- `hmac` 0.12 → 0.13 **coupled with** `sha2` 0.10 → 0.11. Internal:
  `use hmac::KeyInit;` import + `hex::encode(digest)` instead of
  `format!("{:x}")`.
- `getrandom` 0.2 → 0.4 — internal: migrated
  `getrandom::getrandom(buf)` → `getrandom::fill(buf)`.

### Dependabot policy
- New ignore rule for `keyring` major bumps — upstream v4 is
  "sample only" per release notes; app users should migrate to
  `keyring-core` v1 + a backend crate when ready.

### GH-action major bumps (SHA-pinned)
`actions/checkout` 4→6 (Node 24), `actions/setup-node` 4→6,
`actions/upload-artifact` 4→7, `actions/download-artifact` 4→8,
`actions/configure-pages` 5→6, `actions/deploy-pages` 4→5,
`actions/upload-pages-artifact` 3→5, `github/codeql-action`
3.35.3→4.35.5, `softprops/action-gh-release` 2→3,
`sigstore/cosign-installer` 3.10→4.1.

## [0.2.0] — 2026-05-19

Headline: **broad LLM + IaC surface expansion**. New subcommands for
guest creation, cloud-init at clone time, real-time events, and a
self-diagnostic. MCP registry grew from 22 → 25 tools (append-only,
SemVer-safe). Audit log, EU compliance positioning, SIGHUP hot-reload,
shell completions. Statically-linked **aarch64-musl** Linux binary
now in the release matrix — Pi 4/5, Ampere, Graviton, Oracle Free Tier.

Minor bump (not patch) because the cumulative CLI / MCP surface
added since 0.1.27 is well beyond a single-feature release.

### Added
- **Shell completions** — `proxxx completions {bash|zsh|fish|powershell}` prints the shell
  completion script to stdout; pipe to your shell's completions dir.
- **`proxxx doctor`** — self-diagnostic: validates config, cluster connectivity, auth,
  Telegram HITL, PBS, SSH key, and audit log in one pass. Exits 0 if all critical
  checks pass, 1 otherwise. Pipeline-friendly JSON output.
- **Audit log v2** — SQLite append-only log with per-entry HMAC-SHA256 chain.
  New subcommand `proxxx audit {log,export,verify}`:
  - `log` — show recent entries (filterable by time, default 50)
  - `export` — dump to JSON or CSV for SIEM ingestion
  - `verify` — walk the full chain and check every HMAC (NIS2/ISO27001 alignment)
- **`proxxx vm create`** — create a new QEMU VM from scratch (node, vmid, name,
  memory, cores, disk, iso, ostype, bridge). VMID auto-assigned if omitted.
- **`proxxx ct create`** — create a new LXC container (node, vmid, hostname,
  template, memory, cores, rootfs, bridge, password). VMID auto-assigned if omitted.
- **MCP tool `create_guest`** (tool #23) — LLM-callable guest creation for both
  QEMU and LXC; node, type, name, memory, cores, storage, disk_size, template/iso,
  bridge. Registry SHA-256 updated; counter 22→23.
- **Real-time event stream** — `proxxx events stream` polls cluster task
  queues and prints new task starts/completions as they appear (STARTED /
  DONE / FAIL). Supports `--node`, `--type`, `--vmid` filters, `--interval`
  (default 2 s), and `--format json` for NDJSON piping. Shows currently-running
  tasks at startup; `--no-existing` skips the snapshot.
- **MCP tool `list_cluster_events`** (tool #24) — returns recent cluster-wide
  task events with elapsed time; `limit` (default 50) and `running_only` params.
- **Config hot-reload** — `SIGHUP` atomically swaps the live config in the
  `alerts watch`, `mcp serve`, and `mcp serve-http` daemons. After `kill -HUP
  $(pgrep proxxx)`, the next tick/request picks up new `[[alerts]]` rules,
  `[[policies]]`, `[telegram]` structure, and `mcp_token` without restarting.
  Fields baked into `PxClient` at startup (`url`, `user`, `token_id`,
  `token_secret`) and Telegram bot credentials require a full restart. The
  `ConfigHandle` (`Arc<RwLock<ProfileConfig>>`) is re-exported from
  `crate::config` for downstream use.
- **MCP schema type validation** — `dispatch_rpc` now validates every param
  against its declared `ParamType` (Int/Bool/Str) and returns a clear error
  (`"Parameter 'guest_id': expected integer, got \"abc\""`) rather than
  silently misrouting the value.
- **EU & compliance section** in README — NIS2/ISO 27001/GDPR alignment table.
- **Cloud-init clone** — `proxxx clone <src> --cloud-init-user <file.toml>`
  parses a TOML profile (ciuser, cipassword, sshkey/sshkey_file, ipconfig0,
  searchdomain, nameserver), waits for the clone task to land, then applies
  the cloud-init fields and regenerates the drive. Canonical IaC pattern in
  one command — no more clone → set → regen dance.
- **MCP tool `clone_with_cloudinit`** (tool #25) — same flow callable by LLMs
  with inline params (no file). QEMU-only; LXC is rejected explicitly.
  Registry SHA-256 updated; counter 24→25.
- **ARM64 Linux release artefact** — `aarch64-unknown-linux-musl` statically-
  linked binary in the release matrix, built via `cross` (Docker-based
  cross-compile sidesteps rusqlite/sha2/russh native-dep linker breakage).
  Pi 4/5, Ampere, Graviton, Oracle Free Tier.

## [0.1.27] — 2026-05-14

Headline: **draconian TUI polish** — the rendered surface is now native
ASCII / sentence-case throughout, no emoji, fewer borders, smaller
palette. No behaviour, CLI, MCP, or config-schema changes.

### Changed — TUI only

- **Glyph purge** (`refactor(tui): glyph purge`). Removed every emoji
  from rendered surfaces: status icons (🟢🔴🟡⏳⏰), title decoration
  (⚡📝🕒🛡️💾🖥🚀), banner glyphs (⚠️🚨), modal "⚠️ WARNING" header.
  Status carries via row color + the status word column. Telegram
  callback strings retain emoji (different audience, not TUI surface).

- **Separators unified**. Footer drops `│` after the mode pill and uses
  `·` only. View titles drop inline `│` between header spans (use
  whitespace). Arrows `↵ ← → ↑ ↓` replaced with keyboard letters
  (`Enter`, `h/l`) or ASCII (`->`). snaptree's `│  ` tree-drawing
  lines kept (semantic).

- **Progress bars consolidated**. Sub-block precision glyphs
  (`▏▎▍▌▋▊▉`) duplicated in guests + storage collapsed to full-block
  + light-shade `█░` (matches nodes.rs). Input-bar fake cursor `█`
  now a `Modifier::REVERSED` space — the terminal's native cursor look.

- **Color palette: 18 → 13** (`refactor(tui): palette diet`). Removed
  `ACCENT_DIM` (unused). Collapsed `ONLINE / OFFLINE / STALE / PAUSED`
  onto `SUCCESS / DANGER / WARNING / INFO` (purple paused → blue, since
  paused is an intentional state, not a warning). Removed
  `GAUGE_LOW / MED / HIGH` (triple-aliased SUCCESS / WARNING / DANGER).
  `status_badge()` and `gauge_color()` reference semantic colors
  directly. 9 callsites in guests / approval / tasks migrated.

- **Density pass** (`refactor(tui): density pass`). ha_console's 4
  stacked sections each wrapped in `Borders::ALL` (box-of-boxes feel)
  now use `Borders::TOP` only — single underlined title line per
  section. Reclaims ~6 vertical rows + ~80 char columns of border
  chrome on a 100-col terminal. Input bar: `Length(3) + Borders::ALL`
  → `Length(2) + Borders::TOP` (the prompt prefix `/` `:` already
  carries the mode signal).

- **Text discipline** (`refactor(tui): text discipline`). Lowercased
  all user-visible labels — table column headers (VMID → vmid),
  status badges (HEALTHY / STALE / FAILING / QUORATE / NO QUORUM /
  STUCK / DEGRADED / UNPROTECTED / DIRECT / CREATED / DELETED →
  lowercase), mode pill labels (NORMAL / SEARCH / CONFIG GREP →
  lowercase). Color still carries severity. External Proxmox output
  ("TASK OK", "ERROR", "FAILED") and log/warn! lines untouched.

### Test surface

- 13 TUI snapshot tests regenerated to match the polished rendering.
  4 `dump.contains(...)` assertions updated for the new sentence-case
  strings. All 22 snapshot tests + 355 lib tests + 224 integration
  tests pass.

### SemVer note

Per `CHANGELOG.md` SemVer contract, TUI layout changes are explicitly
NOT covered. This release is therefore a patch bump despite the broad
visual change — no CLI command, exit code, `--format json` field, MCP
tool, or config schema was touched.

## [0.1.26] — 2026-05-14

Headline release: **MCP registry expands 10 → 23 tools**, Streamable HTTP
transport, multi-profile TUI switching, Prometheus exporter, batch
execution policies, full audit campaign sweep (HIGH + MEDIUM + LOW), and
the README hero asset rebuilt from scratch.

### Added — MCP surface expansion

- **MCP tool registry: 10 → 23 tools** (`feat(mcp): expand tool registry
  10 → 22 tools`). New tools: `suspend_guest`, `resume_guest`,
  `clone_guest`, `migrate_guest`, `get_cluster_status`, `list_tasks`,
  `get_node_status`, `list_backup_jobs`, `get_replication_status`, plus
  registry-completeness fixes for `list_snapshots`, `get_task_log`,
  `get_node_resources` (which had `ToolAction` variants but no
  `ToolDef`). Registry remains compile-time-fixed and SHA-256 pinned;
  fetch the new checksum via `proxxx mcp tools --checksum`. **The
  append-only SemVer promise is honoured** — no tool was renamed or
  removed.

- **Streamable HTTP transport for MCP** (`feat(mcp): add Streamable HTTP
  transport — POST /mcp + GET /mcp SSE`). Opt-in via
  `proxxx mcp serve --transport http --bind 127.0.0.1:8080`. Stdio
  remains the default (no behaviour change for existing Claude Code /
  Cursor integrations). Unlocks remote LLM agents and multi-tenant
  deployments without the per-call fork/exec cost of stdio.

### Added — operational surface

- **Multi-profile TUI switching** (`feat(tui): multi-profile support`).
  `Tab` cycles between configured clusters without restarting the
  binary. Cached state is now segregated per profile — see RBAC row 108
  test below.

- **Prometheus exporter** (`feat(metrics): proxxx metrics serve`).
  Exposes guest CPU / memory / disk + node + storage metrics in the
  Prometheus text format on a configurable port. Cardinality-bounded
  labels (`vmid`, `name`, `node`, `storage`); designed for Grafana
  scraping at sub-30 s intervals.

- **Batch execution policies — canary + rolling** (`feat(batch): canary
  + rolling execution policies for multi-guest ops`).
  `--policy canary=N%` runs the first percentile, waits an observation
  window, then continues only if no errors. `--policy rolling=N` caps
  concurrency. Replaces the previous all-at-once behaviour for
  `batch stop` / `batch restart`. Pilot count uses ceiling division
  (`min(n, max(1, ceil(n·p)))`) — see `canary_pilot_count` for the
  exact contract.

- **PBS typed auth errors + `pbs ping` command** (`feat(pbs): typed auth
  errors + pbs ping command`). Auth failures now surface as
  `AuthFailed` rather than generic `RequestFailed`, so callers can
  match on error category instead of grepping prose.

- **TUI blind-persona hardening** (`feat(tui): blind-persona hardening
  — surface guest fetch errors in VM list`). When a guest fetch fails
  (typically RBAC blocking `/nodes/X/qemu`), the VM list now surfaces
  the per-node error inline instead of silently dropping the row.
  Operators with restricted permissions can now SEE what they cannot
  see — closes a long-standing footgun.

### Fixed — draconian audit campaign

- **HIGH findings** (`fix(audit): HIGH findings`). Seven correctness
  fixes: batch policy parser rejected `canary=10%`, `find_guest`
  accepted ambiguous cross-node matches, JoinError in the retry path
  was silently swallowed, the HITL approval gate could double-fire
  under a tight race, `clone_guest` was incorrectly classified
  non-destructive (allowed an LLM agent to clone without HITL),
  sensitive config fields (`token_secret`, `password`, PBS
  `token_secret`) are now wrapped in `Zeroizing<String>` and
  zero-on-drop, and the Prometheus exporter called `get_nodes()` once
  per metric kind instead of once per scrape.

- **MEDIUM findings** (`fix(audit): MEDIUM findings`). Six fixes: the
  `watch` subcommand had no timeout cap (now `--timeout 300s` default
  with `<` / `>` comparator parsing); cache directory was not created
  on first run for non-state callers; SSH `--cmd` arg now rejects NUL
  / CR / LF (command-injection prevention); `poll_task_until_done`
  honoured `timeout_secs=0` as "poll forever" (now capped at
  `DEFAULT_TASK_TIMEOUT_SECS=3600`); `escape_label` did not escape
  `\r` (Prometheus label-injection vector closed); `idle_client()`
  test helper now returns the `MockServer` so it cannot be
  drop-killed mid-test (RBAC E2E flake source).

- **LOW findings**. Clock-before-UNIX-epoch now surfaces a typed error
  instead of silently saturating with `unwrap_or_default()`; alert-dedup
  persistence assertions use `assert_eq!(count, 1, …)` instead of the
  weaker `>= 1`.

- **MCP correctness** (`fix(mcp): 3 correctness issues from draconian
  audit`). `action_str` dropped the suffix on multi-word tool names
  (so audit logs showed `stop` instead of `stop_guest`); `clone_guest`
  was incorrectly classified non-destructive; registry checksum test
  was pinned to a stale SHA.

- **Cache directory creation moved into `open_db`** (`fix(cache):
  ensure_cache_dir in open_db — covers all callers, not just
  save_state`). The original audit fix had `ensure_cache_dir()` only
  in `load_state` / `save_state`. CI revealed
  `alert_dedup_persistence_round_trip` failed on clean runners because
  `save_alert_dedup` (and four other callers) did not call it.
  `create_dir_all` now lives in `open_db` itself, so the invariant
  holds for every SQLite opener — no future caller can forget.

- **Shutdown daemon-saturation, follow-up** — see also v0.1.25.

### Security

- **OpenSSF Scorecard `TokenPermissions` alerts**
  (`ci: add explicit permissions`). Both `.github/workflows/ci.yml`
  and `.github/workflows/release.yml` now declare minimal top-level
  `permissions: contents: read`, with `release.yml` explicitly
  elevating only the `release` job to `contents: write, id-token:
  write`. Scorecard `TokenPermissions` score moves from 0 → 10.

### Tests

- **RBAC cache segregation per-profile** (`test(rbac): cache
  segregation per-profile — closes row 108`). The multi-profile TUI
  switching above (the feature) is paired with the test that pins the
  contract: a switch between two profiles does not leak cached cluster
  state between them. Row 108 of the RBAC test matrix now passes.

### Documentation

- **README hero asset rebuilt from scratch.** The AI-generated
  `assets/proxxx-overview.jpg` is gone; in its place is
  `assets/demo.svg` — a 13 KB animated SVG storyboard generated by
  [firstframe](https://github.com/fabriziosalmi/firstframe) (a small
  companion tool that produces beat-based animated terminal demos
  from TOML manifests). The demo types a destructive command,
  the pre-flight risk gate refuses it, HITL approval arrives via
  Telegram, the action executes. Same SVG is the VitePress home hero.
  Respects `prefers-reduced-motion`.

- README + `docs/index.md` numbers refreshed: source 28 → 44 KLOC,
  tests 5 → 14 KLOC, MCP tool registry 10 → 23 tools.

## [0.1.25] — 2026-05-13

### Fixed — shutdown daemon-saturation

- **`shutdown_guest` did not pass a timeout to PVE**, so any guest
  that did not respond to ACPI (or had a stuck init) would leave the
  `qmshutdown` task appended indefinitely on the node — saturating
  `pvedaemon` worker threads. Observed in production as a node-level
  hardware freeze requiring a manual reset.

  `shutdown_guest` now takes `timeout_secs` (default 60 at every call
  site) and forwards both `timeout=N` and `forceStop=1` to PVE for
  QEMU (PVE rejects `forceStop` for LXC, so only `timeout=N` is sent
  there). CLI gains `--stop-timeout <secs>`; ignored with `--force`.
  Three wiremock tests assert per-guest-type body params.

## [0.1.24] — 2026-05-13

### Added — `snapshot rollback`

- **`proxxx snapshot rollback --vmid N --name S --yes`** rolls a
  guest back to a named snapshot via
  `POST .../snapshot/{name}/rollback`. Trait method, `PxClient` impl,
  mock stubs (`patch.rs` + `hitl_e2e.rs`), and two wiremock routing
  tests (QEMU + LXC, with a negative guard on wrong guest type)
  included. Map-coverage snapshot updated.

### Fixed — live RBAC test failures

- Six live RBAC E2E tests were flaking intermittently; root cause was
  test-side HITL callback signing using the wrong HMAC key when the
  runner had `PROXXX_HITL_SECRET` set globally. Tests now sign with
  the per-test ephemeral key — no production code change.

## [0.1.23] — 2026-05-12

### Fixed — password-auth credential rotation + auth-failure UX

- **`resolve_password()` had the resolution order BACKWARDS.** The
  helper checked the inline `password =` value in config.toml
  FIRST, then `PROXXX_PASSWORD` env, then keychain. So any profile
  with a hand-edited inline password silently ignored the env-var
  rotation path — `PROXXX_PASSWORD=new` would NEVER take effect
  unless the operator first edited config.toml to remove the
  inline value. This was inconsistent with `resolve_token_secret`,
  which has always put env > inline.

  Flipped to **env > inline > keychain**. Same hierarchy as
  token-secret; matches the long-standing "env always wins"
  promise in `docs/guide/secrets.md`.

  Operator-visible behaviour change: a profile with BOTH inline
  `password =` AND `$PROXXX_PASSWORD` set will now use the env
  value. If you were intentionally relying on the inline value
  while having a stale env var set, unset the env var.

- **Password-auth 401 surfaced as "Failed to parse auth response"
  instead of "401 Unauthorized".** `AuthMethod::login` called
  `.json()` directly on PVE's response without checking the
  status code first. When the credentials were wrong, PVE
  returned 401 with a JSON body that didn't match
  `TicketResponse`, so the visible error was a parse failure —
  burying the actual cause and silently breaking any caller
  grepping for "401" / "Unauthorized".

  `login` now reads `resp.status()` first and bails with a
  proper "Authentication failed: 401 Unauthorized from <url>
  — <body snippet>" error, capped to 1 KiB of body so a hostile
  server can't OOM the auth path.

### Fixed — E2E test flakiness on clean cluster runs

- **`e2e_alpha` (CRUD lifecycle) timed out 60s every clean run.**
  PVE returns `500 "Configuration file 'nodes/X/lxc/N.conf' does
  not exist"` (NOT 404) on `/status/current` for a deleted LXC.
  Two poll loops in the test+harness classified that as transient
  and retried until timeout: the in-test step-6 "guest 404s after
  CLI delete" poll and the RAII teardown's "guest reaches stopped"
  poll.

  Both now recognise the PVE quirk via a new helper
  `pve_error_is_gone(&err)` that matches the literal substring
  pattern PVE actually emits (case-insensitive `"does not exist"`
  alongside the existing `"404"` / `"not found"` checks). Added
  a `guest_is_gone()` fast-path to `TestResourceGuard` so the
  whole stop+poll+delete dance is skipped when the test has
  already removed the guest.

- **`e2e_beta::beta_bad_token_surfaces_401_cleanly`** assumed the
  local config.toml uses token-auth and only overrode
  `PROXXX_TOKEN_SECRET`. On password-auth configs the env-override
  was a no-op (compounded by the resolve_password bug above) so
  proxxx silently authenticated with the REAL password and the
  test failed the "must exit non-zero" assertion. Now overrides
  both `PROXXX_TOKEN_SECRET` AND `PROXXX_PASSWORD` so either
  auth path lands a 401.

### Internal

- `pve_error_is_gone` + `guest_is_gone` helpers added to
  [`tests/common/mod.rs`](tests/common/mod.rs) — reusable by any
  future E2E test that needs to detect deleted-guest state.
- 2 E2E tests now green that were pre-existingly broken on the
  local cluster fixture; no other test changes.
- Live gate (87 read + 47 mutation probes) green on every commit.

## [0.1.22] — 2026-05-12

### Breaking — HITL callbacks must now be HMAC-signed

- **The v0.1.21 backward-compat shim is gone.** Unsigned callbacks
  (anything without a trailing `:<16-hex-char-tag>`) are refused
  outright by both the standalone daemon (`proxxx hitl serve`) and
  the in-process TUI poller. This was the explicit promise in
  v0.1.21's CHANGELOG and in the test name
  `legacy_unsigned_callback_still_accepted_in_v0_1_21`.

- Refusal surface:
  - Daemon: returns `CallbackOutcome::InvalidFormat`, answers the
    user with `"❌ Unsigned callback refused — daemon upgrade needed"`,
    no PVE-side mutation attempted.
  - TUI poller: drops the callback, answers
    `"❌ Unsigned callback refused — TUI upgrade needed"`,
    `coord.resolve` is not called so any pending approval stays
    in flight (the operator can re-issue after restart).
  - Inverted test `legacy_unsigned_callback_is_refused_in_v0_1_22`
    pins the contract; also asserts the refused txn does NOT
    consume the replay-protection slot (a re-signed retry of the
    same txn must not falsely 401 as replay).

### Upgrade path

- v0.1.21 → v0.1.22: restart the HITL daemon (or the TUI) so the
  next `request_approval` mints a freshly-signed inline keyboard.
  Approvals issued under v0.1.21-or-earlier daemons that haven't
  been clicked yet will be refused — the operator must re-trigger
  the destructive op so a new signed prompt is generated.
- Skipping v0.1.21 entirely (v0.1.20 → v0.1.22 direct): same as
  above. The HMAC key auto-bootstraps at
  `<config_dir>/telegram_hmac.key` on first start.

### Internal

- 4 pre-existing tests (`replay_callback_does_not_re_execute`,
  `pve_403_during_execute_surfaces_as_failure`,
  `deny_callback_does_not_invoke_gateway`,
  `fast_op_skips_intermediate_executing_edit`) constructed callbacks
  by hand without a tag and silently passed under the v0.1.21 shim.
  All now build their callback via the new `signed(key, payload)`
  helper that mirrors what `request_approval` emits at runtime.
- The `Replay.txn_id` assertion in
  `replay_callback_does_not_re_execute` now matches the full signed
  string (tag included) since that's what the dedup engine keys off.
- 12 hitl_e2e tests pass; no production change beyond the two
  parser sites (daemon + TUI poller).

## [0.1.21] — 2026-05-12

### Added — HMAC-signed HITL callback_data (defence-in-depth against bot-token leak)

- **Before this release, HITL callback authentication was a single layer:
  the TLS channel to `api.telegram.org` plus the secrecy of the bot
  token.** If the bot token leaked (env-var dump, log scrape,
  supply-chain compromise of a deploy step), an attacker could:
  1. Send arbitrary messages from the bot, including a freshly-forged
     inline keyboard whose `callback_data` is `approve:delete:9001`.
  2. Coerce or social-engineer any chat member into clicking it.
  3. The proxxx HITL poller — TUI in-process or `proxxx hitl serve`
     standalone — happily dispatches the PVE-side delete because the
     callback parsed cleanly.

  Real-CA TLS doesn't help: the attacker is sending messages **through**
  the legitimate Telegram bot, not impersonating the server.

- New module `hitl::hmac_key`:
  - `load_or_generate_hmac_key()` auto-bootstraps a 32-byte random
    key at `<config_dir>/telegram_hmac.key` (mode 0600 on Unix,
    atomic temp+rename write). Same `directories::ProjectDirs`
    layout as the TLS-pin file from v0.1.17.
  - `sign(key, payload)` → 16-hex-char truncated HMAC-SHA256 tag
    (8 raw bytes = 64-bit forgery resistance, fits comfortably in
    Telegram's 64-byte `callback_data` cap).
  - `verify(key, payload, tag)` → constant-time check via
    `Hmac::verify_truncated_left`, fails-closed on bad hex / wrong
    length / signing key mismatch.

- Send side: `TelegramGateway::request_approval` now appends `:<tag>`
  to both the Approve and Deny `callback_data`. The receive side in
  BOTH `daemon::handle_callback_update` (used by `proxxx hitl serve`)
  AND `tui::run_hitl_poller` (used in-process by the TUI) peels the
  tag off and verifies before dispatching.

### Backward compatibility

- Callbacks issued by v0.1.20-or-earlier daemons have no tag. v0.1.21
  accepts them with a structured `warn!(target: "hitl.legacy_unsigned", ...)`
  log — so an operator running the rollout can grep for sustained
  unsigned traffic before flipping the toggle. **v0.1.22 will refuse
  unsigned callbacks** — the contract change is staged so in-flight
  approvals at upgrade time still resolve cleanly.

### Internal

- New direct deps: `hmac = "0.12"` and `getrandom = "0.2"` (both were
  already transitive via `rustls`/`tokio-rustls`; promoted to direct
  so the call sites are grep-able).
- 10 new unit tests in [`src/hitl/hmac_key.rs::tests`](src/hitl/hmac_key.rs):
  - `sign_is_deterministic_for_same_payload`
  - `sign_changes_with_payload`
  - `sign_changes_with_key`
  - `verify_accepts_own_signature`
  - `verify_rejects_tampered_payload`
  - `verify_rejects_tampered_tag`
  - `verify_rejects_wrong_length_tag`
  - `verify_rejects_non_hex_tag`
  - `verify_rejects_with_wrong_key` — the bot-token-leak defence
  - `telegram_callback_data_budget_holds` — locks the 64-byte cap
- 4 new integration tests in [`tests/hitl_e2e.rs`](tests/hitl_e2e.rs):
  - `signed_callback_with_valid_tag_executes`
  - `callback_with_tampered_tag_is_refused`
  - `callback_signed_with_wrong_key_is_refused`
  - `legacy_unsigned_callback_still_accepted_in_v0_1_21`
    (test name itself documents the v0.1.22 inversion point)

## [0.1.20] — 2026-05-12

### Fixed — snapshot tests now enforce content, not just layout

- **TUI snapshot tests in `tests/tui_snapshot.rs` were layout-only.**
  `insta::assert_snapshot!(dump)` catches "anything visible changed"
  but the de-facto regression workflow is `cargo insta review` →
  accept all → commit. A test named
  `dashboard_with_two_nodes_aggregates_correctly` could silently
  lock in a snapshot where one node had silently dropped out, as
  long as the layout still rendered.

- Added per-test `assert!(dump.contains(...))` semantic anchors on
  top of every snapshot call. The two layers complement each other:
  the snapshot still catches layout shifts; the explicit asserts
  catch data-flow regressions that `cargo insta accept` would
  otherwise hide.

  Per-test contract:

  - `help_overlay_renders_keymap` — title `"Help"`, `"Navigation"`
    section header, `"quit"` binding documented.
  - `dashboard_empty_cluster_does_not_panic_and_shows_idle_state`
    — must show `"Loading"` hint (the "idle state" the test name
    promises) and the `"0 nodes"` header.
  - `dashboard_with_two_nodes_aggregates_correctly` — both node
    names + the `"1/2 guests"` aggregate header.
  - `guests_table_with_mixed_status` — both `"running"` +
    `"stopped"` statuses, all four vmids (100/101/200/999), and
    crucially **no raw `\u{1b}` ESC byte** (the Phase 5.13
    ANSI-injection invariant — a snapshot can't safely enforce
    "no ESC in dump" because a reviewer scanning a unicode diff
    won't spot a U+001B).
  - `compare_view_with_two_selected_guests` — both guest names +
    `"(2 guests)"` panel header.
  - `nodes_view_with_quorum_and_stale_stats_badges` — both node
    names + `"(2 total)"` header.
  - `ssh_session_with_pty_content` — pty content (`"alpine"`,
    `"uname"`) renders through the parser.
  - Empty-state hints pinned: `"No pending approvals"`,
    `"No guests to monitor"` (backup + heatmap), `"Queue is empty"`,
    `"No snapshot data"`, `"Loading storage"`, `"Waiting for logs"`,
    `"No data for this snapshot"`.
  - `tasks_view_empty_state` also pins the `"UPID:test"` prefix —
    the UPID is the only forensic anchor between a log view and the
    task that triggered it; a refactor that "cleans up" the header
    by truncating it must break this test.

### Internal

- All 22 snapshot tests pass with the added asserts against the
  existing accepted snapshots — no snapshot regeneration needed.
- No production code changes.

## [0.1.19] — 2026-05-11

### Fixed — typed `ConfigError` wired to exit code 3

- **Config-load failures now exit `3` ("Configuration error") as
  `docs/reference/exit-codes.md` has promised since v0.1.10.** Before
  this release every config-load failure (file missing, IO error,
  malformed TOML, missing required field) became an opaque
  `anyhow::Error` that landed in main.rs's catch-all and exited `1`.
  Scripts written against the documented contract (`case $? in 3) ...`)
  silently never matched.

- New `config::ConfigError` enum with three variants:
  - `NotFound { path }` — `config.toml` doesn't exist at the
    resolved path (first-run case; message points to `proxxx init`).
  - `Io { path, source }` — file exists but couldn't be read
    (permission denied, EIO, disk gone — fix is chmod / unmount
    diagnostics, not `proxxx init`).
  - `Toml { path, source }` — read succeeded but TOML parsing
    failed: syntax error, type mismatch, or missing required field
    (the `toml::de::Error` `Display` carries line/col).

- All three map to `ConfigError::EXIT_CODE = 3`. Single constant
  because the contract slot is one code; splitting variants to
  distinct codes later is an additive (minor) bump per the doc.

### Internal

- New unit tests in `src/config/mod.rs::config_error_tests`:
  - `config_error_variants_carry_through_anyhow_chain` — every
    variant is downcast-recoverable from `anyhow::Error::chain()`,
    pinning the contract main.rs's typed-exit walker relies on.
  - `config_error_exit_code_is_three` — locks the documented value.
  - `config_error_not_found_renders_actionable_message` — the
    operator-facing message must keep pointing at `proxxx init`.

- main.rs's typed-exit chain walker grew a third arm next to the
  existing `ApiError` (v0.1.15) and `PreflightRefusal` (v0.1.13)
  branches — same downcast pattern.

## [0.1.18] — 2026-05-11

### Fixed — panic visibility for fire-and-forget TUI dispatch spawns

- **17 `tokio::spawn(async move { ... })` call sites in
  `src/tui/mod.rs::dispatch_side_effect` + 1 in the SSH-session open
  branch were dropping their `JoinHandle` on the floor.** Any panic
  inside (e.g. `unreachable!` reached on malformed cluster data, an
  `as` truncation hitting `panic = abort` in release, a serde
  deserialise on garbage from a misbehaving PVE) was silently eaten
  by the runtime: the task vanished, the user saw "operation did
  nothing" and the log was blank.

  New helper `util::spawn_traced::spawn_traced(name, future)`:
  - Spawns `future` exactly like `tokio::spawn`.
  - Spawns a tiny observer task that awaits the inner `JoinHandle`
    and, on `JoinError::is_panic()`, recovers the payload and emits
    `tracing::error!(task = name, "background task panicked: ...")`.
  - Cancellation stays quiet (expected on runtime teardown).
  - The observer self-completes when the inner task finishes — no
    leak, no extra resource cost beyond ~200 ns per call.

  Per-task labels: `start_guest`, `stop_guest`, `restart_guest`,
  `create_snapshot`, `delete_guest`, `migrate_guest`,
  `execute_guest_command`, `fetch_task_log`, `execute_queue`,
  `download_iso`, `move_disk`, `resize_disk`, `fetch_hardware`,
  `fetch_ha_console`, `fetch_snapshot_tree`, `config_grep`,
  `hitl_approval`, `ssh_session_open`. `grep "task panicked"
  proxxx.log` is now a usable triage command.

  Long-lived tasks at [`src/tui/mod.rs:262`](src/tui/mod.rs#L262)
  (HITL poller) and [`src/tui/mod.rs:347`](src/tui/mod.rs#L347)
  (API worker) are unchanged — they already keep their
  `JoinHandle` and are aborted + awaited at teardown
  ([:679-692](src/tui/mod.rs#L679-L692)), so panic visibility was
  already covered for those.

### Internal

- New module [`src/util/spawn_traced.rs`](src/util/spawn_traced.rs)
  with 3 unit tests:
  - `spawn_traced_runs_to_completion_for_normal_task`
  - `spawn_traced_observer_completes_after_panic`
  - `spawn_traced_observer_handles_string_panic`

## [0.1.17] — 2026-05-11

### Added — TLS certificate pinning (Trust On First Use)

- **New `tls_pin_mode = "tofu"` profile option** for homelab clusters
  with self-signed certificates. The v0.1.10 audit flagged that
  `verify_tls = false` accepts ANY certificate, which is silent MITM
  bait: a rogue cert on the same network can intercept the entire
  REST/WebSocket session including serial-console tickets. TOFU sits
  between "strict CA validation" and "accept anything":

  - **First connect:** proxxx opens a TLS handshake with an
    accept-any verifier, snapshots the leaf cert in DER form to
    `<config_dir>/known_certs/<host>_<port>.der`, and logs the
    SHA-256 fingerprint.
  - **Subsequent connects:** reqwest is built with the pinned cert
    as the ONLY trusted root (built-in roots disabled). If the
    cluster rotates the cert — legit renewal or MITM swap — the
    standard rustls verifier rejects the new cert with a clear
    error and the operator can inspect the cert out-of-band and
    delete the file to re-trust.

  Pin storage is keyed by `host_port`, not by profile name — two
  profiles targeting the same cluster (e.g. `--profile readonly` +
  `--profile admin`) share the pinned cert because it's the same
  cluster identity. Writes use temp-file + rename so a crash mid-
  write can't leave a half-written cert.

  New module: [`src/api/tls_pin.rs`](src/api/tls_pin.rs) with
  `probe_leaf_cert`, `fingerprint_sha256`, `pinned_cert_path`,
  `load_pinned_cert`, `save_pinned_cert`. Wired into
  `PxClient::new` via the new `resolve_tofu_cert` helper in
  [`src/api/client.rs`](src/api/client.rs).

### Config

- New optional field `tls_pin_mode: Option<String>` on
  `ProfileConfig`. Defaults to `None` (current behaviour: trust
  decided by `verify_tls` alone). Set to `"tofu"` (case-insensitive)
  to opt in. Documented inline in the `proxxx init` template.

### Internal

- New direct dep: `tokio-rustls = "0.26"` (rustls 0.23 ABI) for the
  bootstrap handshake. The `rustls` crate was already a direct dep
  for the WebSocket custom verifier.
- 6 new lib tests in `src/api/tls_pin.rs::tests`:
  - `fingerprint_sha256_empty_input`
  - `fingerprint_sha256_deterministic`
  - `pinned_cert_save_load_round_trip`
  - `load_pinned_cert_missing_file_returns_none`
  - `pinned_cert_path_sanitises_special_chars`
  - `pinned_cert_path_collapses_url_variants_to_same_path`

## [0.1.16] — 2026-05-11

### Fixed — async SQLite writers (TUI render-loop latency)

- **The three steady-state SQLite writers now run on `spawn_blocking`
  instead of pinning the tokio runtime worker.** The v0.1.10 audit
  flagged that `cache::save_queue` was called synchronously from the
  TUI render loop; under WAL-checkpoint contention the writer can
  block for up to `busy_timeout` (5000 ms), stalling every keypress
  and every API tick in the same window. Same pattern as
  `config::keyring_get` which already uses `spawn_blocking` for the
  identical reason on the keychain side.

  New async wrappers in `src/app/cache.rs`:
  - `save_queue_async(Option<String>, Vec<PersistedQueueEntry>)`
  - `save_state_async(Option<String>, Vec<Node>, Vec<Guest>, Vec<StoragePool>)`
  - `save_alert_dedup_async(Option<String>, Vec<(String,String,u64)>)`

  Each wrapper takes owned arguments (`spawn_blocking` requires
  `'static`) and routes the synchronous `save_*` impl through
  `tokio::task::spawn_blocking`. The sync versions stay intact for
  any non-async callers.

  Call-site updates:
  - `src/tui/mod.rs:400` — queue persistence flush every render tick
  - `src/tui/mod.rs:543` — full cluster-state snapshot after each
    storage sync (every ~5 s)
  - `src/cli/monitoring.rs:579,630` — alerts daemon tick + graceful
    shutdown flush

  Reads at TUI startup (`load_state`, `load_queue`, `load_state_at`)
  and at daemon startup (`load_alert_dedup`) remain synchronous —
  they're one-shot cold-path calls before any concurrent writer
  exists, so spawn_blocking would add overhead without buying
  anything.

### Internal

- 3 new lib tests in `src/app/cache.rs::concurrency_tests`:
  - `save_queue_async_round_trips_through_load_queue`
  - `save_state_async_round_trips_through_load_state`
  - `save_alert_dedup_async_round_trips_through_load_alert_dedup`

  Each writes via the async wrapper and reads back via the sync
  loader, pinning that the wrapping doesn't break the data path.
  The structural claim ("doesn't block the runtime") is left to
  `spawn_blocking`'s own docs — we don't try to measure latency
  here.

- Total lib tests: 314 → 317. clippy --all-targets clean.
- No public-API or CLI surface change.

## [0.1.15] — 2026-05-11

### Fixed — typed exit codes (closes documentation drift)

- **`main.rs` now exits with the typed exit code documented in
  [docs/reference/exit-codes.md].** The contract had been published
  for several releases (`4` = auth/authz, `5` = not found, `7` =
  cluster transient, `6` = pre-flight refused) but `main.rs` always
  exited `1` for any `Err(_)` from the CLI dispatch. Shell scripts
  branching on `$?` to distinguish "auth expired" from "guest gone"
  silently got the wrong code.

  Implementation:
  - **`ApiError::exit_code() -> i32`** — closed match over every
    variant. `Unauthorized` and `Forbidden` collapse to `4` (one
    `case` arm in shell); `NotFound` → `5`; `RateLimited` and
    `StorageHang` collapse to `7` (transient — same retry strategy).
    `Parse` / `Transport` / `PayloadTooLarge` / `Other` → `1`
    (no shell-actionable distinction; the hint and stderr carry
    the detail).
  - **`app::preflight::PreflightRefusal`** — new typed error with
    `pub const EXIT_CODE: i32 = 6`. `enforce_preflight` previously
    bailed with an untyped `anyhow::bail!("refusing destructive
    op …")`; the message is unchanged but the chain now carries the
    typed marker so `main.rs` can map it to `6` instead of `1`.
  - **`main.rs` Err path** walks the anyhow chain via
    `Error::chain().find_map(downcast_ref)` looking for `ApiError`
    or `PreflightRefusal` and exits with the typed code. Non-typed
    errors fall through to `1` as before.

### Internal

- 5 new lib tests in `src/api/error.rs` pinning the exit-code
  contract per variant + a full-table assertion catching future
  variants that forget to extend the `exit_code` match. The
  existing `enforce_preflight_bails_on_severe_without_force` test
  now also asserts the chain carries `PreflightRefusal` so a future
  refactor reverting to `anyhow::bail!` breaks the test loudly.
- `docs/reference/exit-codes.md`: fixed stale `ApiError::Schema` →
  `ApiError::Parse`, added `Other`, marked configuration-load
  errors as still exiting `1` pending a follow-up `ConfigError`
  variant. Total lib tests: 309 → 314.

## [0.1.14] — 2026-05-11

### Added — actionable error hints

- **`ApiError` now carries a per-variant `actionable_hint()` returning a
  one-line "what should I do next?" string.** The v0.1.10 audit flagged
  that proxxx's typed-error architecture existed but every error
  collapsed to the same generic anyhow chain at the application
  boundary — operators saw "Proxmox rejected our credentials" with no
  follow-up. Each variant now points at a concrete next step:
  - `Unauthorized` → "credentials rejected — re-run `proxxx init
    --interactive` to rotate the token, or verify `$PROXXX_TOKEN_SECRET`
    matches the live secret in PVE (`pveum user token list <user>`)"
  - `Forbidden` → "token is valid but lacks the privilege for this op —
    inspect the ACL with `proxxx access acl` and grant the needed role
    on the affected path; `proxxx perms <user>` shows effective rights"
  - `NotFound` → "the resource doesn't exist on the cluster — it may
    have been deleted, renamed, or the vmid/storage/node name is wrong
    (try `proxxx ls guests` / `proxxx ls nodes` to enumerate)"
  - `RateLimited`, `StorageHang`, `Transport`, `Parse`, `PayloadTooLarge`,
    `Other` — each gets its own targeted hint pointing at the right
    diagnostic command or config knob.
- **`api::error::extract_hint(&anyhow::Error) -> Option<&'static str>`**
  walks an anyhow chain and surfaces the inner `ApiError`'s hint. Used
  by `main.rs` for CLI error rendering:
  - Text mode: appends `  hint: …` line under `Fatal Error: …`
  - JSON mode: adds a `"hint"` field to the error object alongside
    `"error"` and `"status"`. Non-API errors omit the field — proxxx
    doesn't invent hints for config-parse or IO failures.

### Internal

- 7 new lib tests in `src/api/error.rs` covering: every variant has a
  non-empty hint (≥20 chars), specific text checks for the four
  highest-traffic variants, `extract_hint` finds typed errors through
  `.context()` wrapping, and returns `None` for non-API errors.
- Total lib tests: 302 → 309. No production-API change beyond the new
  `actionable_hint()` / `extract_hint()` surface area.

## [0.1.13] — 2026-05-11

### Added — pre-flight risk gate coverage

- **9 new unit tests** closing the pre-flight risk gate coverage gap
  the v0.1.10 audit flagged. The cheap `assess()` path already had
  6 tests pinning `Locked`/`HaManaged`/`Running`/`LongUptime`/
  `TaggedProd`/`ActiveNetTraffic`, but the 5 deep-only variants and
  the entire `--allow-risk` bypass semantic were unprotected:

  - **`assess_deep` (5 tests in `src/app/preflight.rs`)** — each
    exercises the corresponding code path via wiremock against PVE:
    - `HasManySnapshots` (Op::Delete + 6 snapshots → Warning)
    - `BackupAgeWarning` (Op::Delete + backup ctime 30h ago → Warning,
      with a ±1h slop for clock drift)
    - `NoBackupFound` (Op::Delete + empty backup storage, no PBS → Notice)
    - `ListeningOnService` (running QEMU + QGA returns `LISTEN ... :80`
      → Warning, `name: "http"`) — exercises the two-step
      `agent/exec` POST + `agent/exec-status` GET wiring end-to-end
    - `DeepCheckSkipped` for running LXC (no QGA path → Notice). The
      test asserts **zero** HTTP calls hit the mock server, pinning
      that the LXC short-circuit returns before any I/O.

  - **`enforce_preflight` (4 tests in `src/cli/common.rs`)** — pins
    the `--allow-risk` bypass contract that the audit found had zero
    tests:
    - `bails_on_severe_without_force` — Locked guest, force=false
      surfaces an error that names both `SEVERE` and `--allow-risk`
      so the operator sees the escape hatch.
    - `proceeds_on_severe_with_force` — same Locked guest, force=true
      returns Ok (operator owns the consequence).
    - `proceeds_on_warning_without_force` — tagged-prod guest yields
      `TaggedProd` (Warning); the gate only refuses on Severe.
    - `returns_ok_on_clean_guest` — no risks: Ok regardless of force.

  Total lib tests now: 302 (was 293). Cargo clippy --all-targets
  clean (8 missing-backtick lints fixed inline).

### Internal

- No production code change; tests-only patch release.

## [0.1.12] — 2026-05-11

### Fixed — TUI concurrency hardening

- **Main `tokio::select!` is now `biased;` with a shutdown branch.**
  The TUI run loop in `src/tui/mod.rs` previously had a 2-arm select
  between UI events (`events.recv()`) and API worker messages
  (`data_rx.recv()`). With tokio's default fair (random) selection,
  a busy data channel could starve a `q` keypress for up to one API
  tick (~5 s). The select is now `biased;` with three arms in priority
  order: external shutdown signal → UI events → data messages. The
  `q` keypath is unchanged but the shutdown signal is now first-class:
  SIGINT/SIGTERM cleanly breaks the loop and runs the teardown
  (queue cache flush, terminal restore, background task abort)
  instead of dying on runtime drop. Pattern mirrors the HITL daemon
  (`src/hitl/daemon.rs`) and the alerts daemon
  (`src/cli/monitoring.rs`), which already used `biased;` for the
  same reason.
- **`JoinHandle` stored for the HITL poller and the API worker.**
  Both long-lived spawns previously discarded their handle —
  `tokio::spawn(async move { … })`. On quit the tokio runtime dropped
  them silently. Symptoms: if the HITL poller died hours earlier
  (Telegram token revoked, panic in the resolve path) the TUI
  reported "TUI exited cleanly" with no indication. Now both handles
  are captured. On quit we `abort()` + `await` each; the expected
  outcome is `JoinError::is_cancelled() == true`, anything else is
  logged via `tracing::warn!`. An operator restarting the TUI now
  sees in the audit log whether a background task had been quietly
  dead.

### Internal

- No public-API or CLI surface change. `proxxx --help` is identical;
  exit codes and JSON output unchanged.

## [0.1.11] — 2026-05-11

### Added — RBAC test coverage

- **12 new wiremock-based RBAC tests** covering the read-path /
  visibility-filter gaps the v0.1.10 audit flagged. The Phase 7 fixture
  pinned the three matrix-level invariants (typed `ApiError::Forbidden`
  on destructive 403; filtered-empty deserialization; `privsep` wire
  format) but said nothing about what each non-root persona is allowed
  to *see*. The new section pins per-persona contracts:
  - **operator@pve** (PVEVMAdmin on `/vms`, no `/nodes`, no `/access`):
    `/nodes` returns filtered-empty (not 403 — PVE prefers filtering
    for collection endpoints); `get_guests` returns only owned VMIDs;
    per-VM `status/current` on an unowned VMID returns typed Forbidden
    on both QEMU and LXC fallback paths; `cluster/resources` returns
    a partial union containing owned VMs but no `node`-type entries.
  - **auditor@pve** (PVEAuditor global, read-only): `get_guests` sees
    the full list (no filtering for `Sys.Audit` globally); `list_users`
    succeeds (read path != User.Modify write path); `stop_guest` and
    `create_snapshot` both surface typed Forbidden on the destructive
    POSTs against `/qemu/{vmid}/status/stop` and `/qemu/{vmid}/snapshot`.
  - **blind@pve** (PVEVMUser scoped to VMID 999): `get_guests` returns
    a single-entry filtered list (not empty — the operator-test bonus
    above only covered all-empty); `get_guest_status` on the scoped
    VMID succeeds; `get_guest_status` on any other VMID returns typed
    Forbidden on both QEMU+LXC paths; `cluster/resources` returns
    only the scoped entry.

  `tests/rbac_e2e.rs` is now 27 wiremock tests (15 Phase 7 + 12
  Phase 8). The live-cluster suite (`tests/rbac_live.rs`, 10 tests,
  `#[ignore]`) still depends on a re-provisioned PVE test cluster
  for end-to-end `pveum` validation — unchanged.

### Internal

- No production-code changes; tests-only patch release.

## [0.1.10] — 2026-05-11

### Internal — refactor

- **`src/cli/mod.rs` split into 12 domain submodules.** The CLI module
  had grown to 9141 lines (208 `Command` enum variants + 27 nested
  sub-enums + 45 async handlers + 7 shared helpers, all inline), making
  compile times, merge conflicts, and onboarding all measurably worse.
  Pulled out per-domain modules — `cli::{vm, ct, node, cluster, access,
  storage, firewall, monitoring, console, patch, init}` plus
  `cli::common` for shared helpers (`find_guest`, `enforce_preflight`,
  `wait_and_classify`, `classify_pending`, `parse_kv_pairs`, `BatchOp`,
  `NoSsh`, `execute_batch_op`). Sub-enums move with their handler (e.g.
  `VmCommand` lives in `cli/vm.rs`, referenced from the top-level
  `Command` as `vm::VmCommand`). `mod.rs` is now ~1670 lines — the
  irreducible `Command` enum + dispatch + small daemons (`hitl_serve`,
  `execute_search`, `execute_delete`, `build_version_payload`).
  `ssh_discovery_tests` migrates to `console.rs` alongside the
  predicates it pins; `parse_kv_pairs_tests` to `common.rs`;
  `shell_quote_tests` to `access.rs`. **No user-facing surface change**
  — clap parser tree, `--help`, `--format json` shapes, exit codes, and
  the MCP tool registry are all bit-identical to 0.1.9.

## [0.1.9] — 2026-05-07

### Fixed — security hardening

- **SSH argv injection (CWE-88).** The CLI's `proxxx ssh <vmid>` and the
  init-wizard's connectivity probe both shell out to system `ssh(1)`
  with `format!("{user}@{host}")` as the destination positional. Without
  a `--` separator before the destination, a `host` value beginning with
  `-` (e.g. via a tampered TOML or a hostile QGA reply) would be parsed
  as a flag — `-oProxyCommand=…` is the canonical exploit. Both call
  sites now (1) refuse the operation up-front via the new
  `config::validate_ssh_destination(user, host)` helper and (2) emit a
  POSIX `--` before the destination as defense-in-depth. The validator
  rejects empty strings, leading `-`, embedded `@` in `user`,
  whitespace, and NUL bytes; covered by six unit tests.

### Fixed — test reliability

- **Process-global `env::set_var` race in test fixtures.** Five mock
  client builders (`src/app/preflight.rs`, `tests/api_test.rs`,
  `tests/common/mod.rs`, `tests/rbac_e2e.rs`, `tests/rbac_live.rs`)
  injected the auth secret via `std::env::set_var("PROXXX_TOKEN_SECRET",
  …)`. Cargo runs unit and integration tests in parallel and env state
  is process-global, so any concurrent test reading the variable could
  observe the wrong value or race a sibling's `remove_var`. Replaced
  with the `cli_secret` resolver-priority-#1 parameter — same effect,
  zero shared mutable state, no `serial_test` annotation needed for the
  wiremock-only suites.

### Internal — code clarity

- `Orchestrator::wait_for_reboot` reads as if it swallows API errors
  in its node-liveness poll loop. The `unwrap_or_default()` is in fact
  load-bearing — the loop is designed to outlast a reboot, so transient
  TCP/TLS failures during cluster reconvergence MUST keep polling
  rather than abort the upgrade orchestration. Comment added; behaviour
  unchanged.

## [0.1.8] — 2026-05-07

### Added — supply chain

- **Every GitHub Actions `uses:` is now pinned to a 40-char commit
  SHA**, with a trailing `# vX.Y.Z` comment recording what version
  the SHA mapped to at pin time. Closes the floating-tag attack
  surface (the tj-actions/changed-files class of supply-chain
  compromise where a re-tagged `@v4` silently picks up malicious
  code with the runner's `GITHUB_TOKEN`). Dependabot is configured
  to update both the SHA and the trailing comment together so pins
  do not drift past published releases.
- **OpenSSF Scorecard workflow** (`.github/workflows/scorecard.yml`)
  running weekly + on push-to-main + on branch-protection-rule
  changes. Results land in GitHub Code-Scanning (per-finding
  remediation, visible under Security → Code scanning) and the
  public Scorecard API at api.securityscorecards.dev — feeds the
  badge added to README.md.

### Changed — operator-facing

- `proxxx init` SSH-key discovery now compares the `.pub` extension
  case-insensitively. On a case-preserving filesystem (HFS+ default,
  exFAT, NTFS via fuse) a public key named `id_rsa.PUB` previously
  slipped past the filter and was offered as a private-key candidate
  in the wizard menu.
- iso library detail panel: the "NOT PINNED — download refused"
  status string no longer carries a parenthetical maintainer note.
  The refusal behaviour is unchanged.

### Fixed — contributor experience

- `scripts/gate.sh` now resolves its working tree from the hook's
  cwd when invoked under `GIT_DIR` (i.e. as a pre-commit hook).
  Previously, in nested-worktree layouts (e.g. Claude Code's
  `.claude/worktrees/<name>` under the main checkout) the gate
  resolved `ROOT` to `scripts/` itself and stage 3 (`cargo audit`)
  died with "Couldn't load Cargo.lock". Single-worktree commits are
  unaffected.
- The OpenSSF Scorecard workflow's pins for `ossf/scorecard-action`
  and `github/codeql-action/upload-sarif` now point at the underlying
  commit SHAs, not the annotated-tag object SHAs the GitHub git-refs
  API initially returned. The Scorecard webapp's workflow-verification
  step rejects annotated-tag SHAs as "imposter commits", so the very
  first weekly run failed at the publish step with a 400. Other pinned
  actions in `ci.yml` / `release.yml` / `docs.yml` use lightweight
  tags (no dereferencing required) and were unaffected.

### Added — community / repo surface

- `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1) — closes the
  broken link `CONTRIBUTING.md` already pointed at.
- `.github/ISSUE_TEMPLATE/{bug_report,feature_request,config}.yml`
  with required-field validations and a security redirect to the
  private advisory flow.
- `.github/PULL_REQUEST_TEMPLATE.md` matching the gate.sh + live-
  cluster + CHANGELOG verification policy.
- `.github/CODEOWNERS` routing for build-system, CI, and the
  security-impacting source paths.
- README badge sweep: latest release, MSRV (linked to
  `rust-toolchain.toml`), and OpenSSF Scorecard alongside the
  existing CI + license badges.

### Internal — code health

- `cargo clippy --all-targets` now emits zero warnings on Rust
  1.95.0 — including the pedantic / nursery groups already wired
  as `warn`. Five pedantic-level production fixes (case-insensitive
  `.pub`, `Option<&T>` over `&Option<T>`, `format!` collapse,
  struct-bools allow on the genuinely-flat `GuestFirewallOptions`,
  blank-line-after-outer-attr) plus a sweep of the test stubs
  (justified file-level `default_trait_access` allow on the
  fake-gateway fixtures, `float_cmp` allow on the exact-min/max
  sparkline asserts, digit-grouping + missing-backtick fixes).

## [0.1.7] — 2026-05-06

### Added — supply chain

- **Sigstore keyless cosign signatures on every release tarball.**
  Each per-target tarball now ships with a `.cosign.bundle`
  (signature + signing certificate + transparency-log inclusion
  proof — all in one self-verifiable file). Verification:
  ```bash
  cosign verify-blob \
    --bundle proxxx-0.1.7-<target>.tar.gz.cosign.bundle \
    --certificate-identity-regexp 'https://github.com/fabriziosalmi/proxxx/.github/workflows/release.yml@.*' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    proxxx-0.1.7-<target>.tar.gz
  ```
  The cert-identity regexp pins to the exact workflow path —
  a leaked sigstore cert from any other repo or workflow can
  not validate against these bundles. Offline verification (the
  transparency-log inclusion proof is embedded in the bundle).
- **CycloneDX SBOM (`proxxx-0.1.7.cdx.json`).** Generated in
  the release job from `Cargo.lock` via `cargo-cyclonedx
  --frozen` — authoritative source-side dep graph (more precise
  than scanning the binary). Ships with its own `.sha256`
  sidecar. Audit with `grype sbom:proxxx-0.1.7.cdx.json` or
  any CycloneDX-aware scanner.

### Added — docs

- **README "Who is this for?" personas table** above "What you
  get". Six rows mapping persona → concerns → deep link, so a
  first-time visitor evaluating in 30 seconds gets a
  jump-to-the-right-page table instead of a feature list.
- **`/guide/troubleshooting`** — 16 common errors covering
  connection, TLS, auth, secrets, SSH, config, backup, HITL,
  MCP, and pre-commit-gate failure modes. Every entry quotes
  the exact `Fatal Error: ...` string proxxx emits, then the
  cause + a copy-pasteable fix.
- **`/guide/production-checklist`** — 7-section, 26-item
  walkthrough for operators deploying to prod: verify the
  binary (sha + cosign + SBOM), configure access (token /
  TLS / secret storage), HITL setup with systemd, alerting,
  SSH layer, host hardening, operational runbook (inventory
  pin, release notifications, recovery test).
- **Persona quickstarts**: `/guide/quickstart-homelab`
  (5-min single-node walkthrough) and `/guide/quickstart-llm-mcp`
  (5-min Claude Desktop / Cursor wiring with HITL on destructive
  tools). Sidebar new "Quickstarts by persona" section.

## [0.1.6] — 2026-05-06

### Added

- **Click-to-zoom on the docs landing page hero image.** The
  6-panel overview infographic embedded in the home hero slot
  is now zoomable via `medium-zoom` (~3 KB JS, the canonical
  vitepress recipe). Click anywhere on the image → smooth
  zoom-to-viewport with the page-bg as backdrop; click again
  or Esc → zoom back. Wired generically to `.VPHero img` and
  `.vp-doc img`, so any future screenshot in `/guide/` or
  `/reference/` benefits automatically. The navbar logo
  (`.VPNavBar img`) is intentionally excluded — clicking the
  brand mark in the corner shouldn't zoom it. SSR-safe (init
  gated in `onMounted`); re-binds across SPA navigation.

### Removed

- **Dead `repl_jobs` pipeline pruned from the TUI path.** Pre-cleanup
  the TUI fetched `client.list_replication_jobs()` on every HA-console
  open, routed it through `DataMsg::HaData → Action::HaDataLoaded →
  state.repl_jobs`, and… nothing read it. Six call sites surgically
  removed: `AppState.repl_jobs` field + initializer, `Action::
  HaDataLoaded.repl_jobs` variant field, `DataMsg::HaData.repl_jobs`,
  the `client.list_replication_jobs()` future in the HA fetch
  fan-out + its `tokio::join!` arm, the `repl_status.clear()`-
  alongside `repl_jobs.clear()` line in the view-pop GC, and a
  test fixture. The trait method `ProxmoxGateway::list_replication_
  jobs()` and the CLI `proxxx replication jobs` command stay —
  the CLI reads the gateway directly, bypassing AppState. Net:
  one less network round-trip per HA console open, ~30 lines
  removed, no behaviour change visible to operators. Surfaced by
  the from-zero project audit; verified with `grep -rn repl_jobs
  src/ tests/` returning nothing in the live tree.

### Docs

- **CHANGELOG `[Unreleased]` section restored.** Post-v0.1.5
  release the section was missing — future commits had nowhere
  to land until the next bump. Added at the top so the next
  feature/fix lands in the right slot without a manual restore.

## [0.1.5] — 2026-05-06

### Fixed

- **Operation Queue: navigation + remove key wired, instruction
  text honest.** Pre-fix the queue's instruction strip advertised
  `[Q] Back · [D] Remove Selected · [C] Commit · [R] Refresh` and
  three of those four were lies:
  - `[Q]` switches TO the queue (no-op when already there); `q`
    actually quits the app.
  - `[D]` only deletes guests in GuestList; on the queue, it did
    nothing.
  - `j/k` navigation was broken because `item_count()` didn't
    include `OperationQueue` — the selected-index was frozen at
    0 even with multiple entries.
  - Only `[C]` and `[R]` worked.
  Result: the queue was a viewer with one usable button. Now `j/k`
  walks the entries, lowercase `d` removes the highlighted one
  (`Action::DequeueOperation` was reachable from the reducer side
  but never wired to a key — fixed), and the legend reflects the
  truth: `[j/k] Nav · [d] Remove · [C] Commit & Execute · [R]
  Refresh · [Esc] Back`. The global status footer's
  `OperationQueue` bindings updated to match.

## [0.1.4] — 2026-05-06

### Fixed

- **TUI single source of truth for the bottom status row.** Two
  related fixes after operator feedback on v0.1.3:
  - Footer truth-in-binds: the global status footer claimed
    `q back` on every internal view (NodeList / GuestList / etc.)
    — a lie. `event::map_key` wires `q` unconditionally to
    `Action::Quit`; `Action::Back` is bound to `Esc / h / ←`.
    An operator on GuestList who hit `q` expecting to return to
    Dashboard got dumped to the shell instead. Now internal views
    surface BOTH chords with their real labels (`Esc back · q
    quit`); Dashboard shows only `q quit` (it's the nav root,
    where `Action::Back` would also exit). 2 new tests pin the
    contract.
  - Two-stacked-bars across views: `dashboard.rs::draw_status_bar`
    rendered its own mode pill + binds row, BELOW which the new
    global footer rendered another row — two visually identical
    lines. `nodes.rs::draw` was even worse: it called
    `super::dashboard::draw` (a forgotten copy-paste from when
    nodes.rs was forked) which fired the WHOLE dashboard pipeline
    into a 1-row chunk with everything but the trailing line
    clipped. `guests.rs` and `storage.rs` had their own
    `draw_action_bar` hint rows on top of the table, also
    duplicated by the new footer. All four per-view status / hint
    bars removed; the mode pill is promoted into the global
    footer. Each view reclaims its bottom row for content. Single
    source of truth: `widgets::status_footer` is THE bottom row
    for every view.

## [0.1.3] — 2026-05-06

### Added

- **Wizard step 4 now optionally pins per-guest SSH overrides.**
  After the standard `[ssh]` block, the wizard asks "Pin per-guest
  SSH targets now?" and (on yes) loops VMID → host until empty
  VMID. Each pair lands as `[ssh.guests."<vmid>"]` in config.toml.
  Default is no — auto-discovery via QGA covers most cases now;
  the explicit-pin path stays surfaced for the legitimate
  exceptions: agent-less guests, QGA reporting only loopback /
  link-local, or operator preference for a stable DNS name over a
  rotating DHCP IP. Duplicate VMIDs in one session overwrite (with
  a warning) so a typo doesn't get re-typed; non-numeric VMIDs are
  rejected loudly. Round-trip-via-serde test pins that wizard
  output parses back as `ssh.guests` table with the right VMIDs.

### Changed

- **`proxxx ssh <vmid>` now auto-discovers guest IPs via QGA / LXC
  interfaces.** Previously required an explicit
  `[ssh.guests."<vmid>"]` block in config.toml; now falls back to
  asking PVE for the live IPs (QGA `network-get-interfaces` for
  QEMU, `/lxc/{vmid}/interfaces` for LXC) and picks the first
  routable IPv4 (skipping loopback 127.0.0.0/8 and link-local
  169.254.0.0/16). Uses `[ssh].user` / `[ssh].key_path` as
  defaults. Explicit config still wins; the source ("config.toml"
  or "QGA / lxc-interfaces auto-discovery") is echoed before the
  ssh exec so the operator knows which path resolved. Diagnostic-
  rich error chain when both fail (agent off vs. only-loopback
  vs. no [ssh].key_path) so the message tells you what to fix
  rather than just "guest not found". 6 unit tests pin the IP
  selection invariants (loopback skipped, link-local skipped,
  IPv6-only returns None, malformed input rejected).
- **Wizard SSH step now auto-discovers `~/.ssh/` private keys.**
  Previously hardcoded `~/.ssh/id_ed25519` as the default path —
  operators with named keys (`id_ed25519_root`,
  `proxxx_e2e_ed25519`, `id_rsa`) accepted the default, the SSH
  probe failed, the config got written pointing at a path that
  didn't exist. Now the wizard scans `~/.ssh/`, content-checks each
  candidate against `-----BEGIN ... PRIVATE KEY-----` (so `.pub`
  siblings, `known_hosts`, `config`, `authorized_keys`, and random
  files don't pollute the list), and presents a numbered choice
  (OpenSSH-format keys first, then RSA PEM, alphabetical within).
  Falls back to free-form prompt only when no keys are found OR
  HOME is unset. 3 unit tests pin the filter rules + sort order.

### Added

- **`proxxx ssh <vmid>` CLI subcommand.** Opens an interactive SSH
  session into a guest by spawning the system `ssh` (so the
  operator's existing keys, agent, known_hosts, and `~/.ssh/config`
  apply transparently — re-implementing those in russh would be
  incomplete and invisible to muscle memory). Per-guest connection
  details come from `[ssh.guests."<vmid>"]` in config.toml. When
  the block is missing, proxxx prints the exact TOML to paste in
  plus a `proxxx --format json ls guests | jq` recipe to discover
  the guest's IP. `--cmd "<remote-command>"` runs a one-shot
  instead of an interactive shell. Closes a long-standing gap
  where `proxxx ssh 100` was advertised in the docs but unreachable
  at the CLI (existed only inside the TUI's `c` keypress flow).
- **TUI always-visible status footer with contextual keybindings.**
  Bottom row of every view now surfaces 3-9 view-specific bindings
  (`j/k:nav  ↵:detail  s:start  S:stop  r:restart  c:console
  /:search  ?:help  q:back` for the guest list) plus universal
  `?:help  q:back` so a new user always sees how to leave the
  current view. Follows the htop / lazygit / k9s convention; the
  `?` modal stays for the full keymap reference. Input bar
  (Command / InputTag / InputBroadcast) and modal overlays cover
  the footer naturally when active. 7 unit tests pin invariants:
  every top-level view has `?:help`, every view has a quit/back
  binding, GuestList surfaces all four lifecycle keys (s/S/r/c),
  Help mode collapses to "any key dismisses".
- **`proxxx init --interactive` config wizard.** Five-step prompted
  flow that walks a first-time user from "fresh machine" to
  "validated, working `config.toml`". Each input is probed live
  against the cluster before write — anonymous PVE version probe,
  token / password authentication test against
  `/access/permissions`, optional SSH `uname -a` round-trip via
  `ssh -o BatchMode=yes`, optional Telegram `getMe`. A failed probe
  never lands in TOML; the user fixes the wrong field in place.
  Existing config triggers a backup-or-cancel prompt
  (`config.toml.bak.<epoch>`); the new file is written atomically
  with mode 0600 (token / password lives in it). No new dependency
  — uses reqwest + crossterm (already in tree). Pinned by 12 unit
  tests covering token-string parsing, URL normalisation, TOML
  rendering, and round-trip-via-serde so wizard output is
  guaranteed to parse as TOML.

## [0.1.2] — 2026-05-05

### Added

- **SSH layer live tests (`tests/ssh_live.rs`).** Two `#[ignore]`-
  gated tests exercise the SSH layer end-to-end against a real PVE
  node: `ssh_pool_exec_uname_round_trip` (boring smoke — `uname -a`
  pins the russh handshake + channel exec) and
  `ssh_pool_exec_pveum_user_permissions_round_trip` (mirrors the
  `proxxx perms` shell-out path; pins the parse contract by
  asserting `root@pam` is in stdout). The harness builds an
  `SshConfig` from env vars (NOT from the user's `config.toml`) and
  uses a per-process tmp `known_hosts` so the operator's real host
  key store is never touched. Opt in with `PROXXX_E2E_SSH_ENABLE=1`.
- **`setup_demo.sh --with-ssh`.** New flag that adds an SSH
  preflight phase (key file mode 600/400, round-trip `uname -a`
  over `ssh -o BatchMode=yes`, `pveum` reachable on remote PATH)
  before declaring the cluster ready. Read-only by design — never
  deploys keys, never edits the operator's `~/.ssh`.
- **HITL callback replay-attack live test
  (`hitl_callback_replay_rejected_under_live_pve`).** Drives
  `handle_callback_update` twice with an identical `Update` against
  a real `PxClient` (operator persona) + a wiremock Telegram
  stand-in; pins `CallbackOutcome::Replay` on the second call and
  `pending.consumed_count() == 1`. Pure-logic dedup is already
  unit-tested; this test pins the contract under realistic
  live-PVE wiring. Side-effect-free — uses the sentinel
  `BLIND_VMID` so the first call lands at `NodeNotFound` rather
  than restarting a real VM. `#[ignore]`-gated; opt in with
  `PROXXX_E2E_RBAC_ENABLE=1` and persona tokens.
- **Alert daemon dedup persistence (cache schema 1 → 2).** `alerts
  watch` now persists the `(rule, target) → last_fired` window to
  the SQLite cache after each tick (and at graceful shutdown), and
  reloads it on startup. Without this, a routine daemon restart
  (config reload, kernel update, accidental SIGHUP) re-fired every
  active alert immediately — a single restart could flood Telegram
  with 50 duplicate notices for problems the operator had already
  seen and acknowledged. Best-effort: a missing/corrupt cache
  yields an empty state rather than failing the daemon. Schema
  bump pinned by a 1 → 2 migration regression test plus an
  end-to-end round-trip test.
- **MCP per-tool execution timeout (DoS guard).** Each `ToolDef`
  carries a `timeout_secs` budget; the JSON-RPC `tools/call`
  dispatch wraps `handle_tool_call` in `tokio::time::timeout`. On
  expiry the request returns server-defined error code `-32001` with
  the budget in the message; the request loop continues. Without
  this, a single hung call (storage lock, network stall, upstream
  PVE wedged) would block every subsequent JSON-RPC line — stdio is
  serialized. Read-only tools get 30 s; lifecycle ops 60 s; snapshot
  ops 120 s; `delete_guest` 180 s to accommodate the 120 s HITL
  Telegram round-trip plus the actual delete. Budget is also
  serialized into `proxxx mcp tools --json` for external audit.

## [0.1.1]

Documentation patch release. No functional changes; no API surface
shift; no `--format json` schema change. Two doc-only edits prompted
by an external review pass:

- **Default `verify_tls = true`** in the starter config written by
  `proxxx init`. Operators with self-signed homelab clusters now opt
  out explicitly with `verify_tls = false`. Inline comment in the
  generated `config.toml` warns that disabling TLS verification
  exposes the full API + WebSocket traffic (incl. serial-console
  tickets) to MITM. Existing config files are unaffected — this only
  changes what `proxxx init` writes for new installs.
- **PBS restore caveat clarified** in `docs/integrations/pbs.md`. The
  prior wording said `kill_on_drop` "cleans up the stale download" —
  inaccurate. SIGKILL stops the `proxmox-backup-client` child
  immediately (good — bandwidth + I/O bounded) but bypasses
  upstream's own cleanup. Partial archive files (`*.pxar`,
  `*.img.fidx`, chunk-store working files) **may remain in the
  target directory** after a kill. Doc now states that explicitly +
  recommends treating the target dir as untrusted after an
  interrupted restore.

## [0.1.0]

First public release. proxxx 0.1.0 ships as a single static binary
with a CLI, a TUI, an MCP server, an alert daemon, and a HITL daemon
in the same executable. PVE API map coverage: 163 of 190 endpoints
(85%); the remaining 27 are documented design boundaries (Ceph
cluster writes, SDN config writes, browser-only auth flows).

### Talking to the cluster

- **PVE REST client** with typed `ApiError` (8 categorical variants),
  reqwest + rustls, 32 MiB body cap, per-profile rate limiter
  (`governor`).
- **PBS REST client** for read-only browse (datastores, snapshots,
  archive metadata) plus shell-out to `proxmox-backup-client restore`
  with `kill_on_drop` supervision and `tokio::signal::ctrl_c`
  propagation.
- **SSH layer** (`russh`, publickey only) for the paths PVE doesn't
  expose over REST: patch apply, `proxxx perms` shell-out to
  `pveum user permissions`, per-guest interactive sessions. TOFU
  `known_hosts` is dedicated (separate from `~/.ssh/known_hosts`).
- **WebSocket termproxy** for serial console, custom rustls verifier
  for `verify_tls = false` profiles, raw-mode terminal with `Ctrl+] q`
  exit chord.
- **Local console handoff** — SPICE (`.vv` mode 0600 with `O_EXCL`
  + 128-bit random suffix; launches `remote-viewer`), noVNC (system
  browser; never embeds the auth ticket in the URL).

### Operational surface

- **65 top-level CLI subcommands**. Stable exit codes (`0` ok, `1`
  runtime, `2` argparse, `3` HITL denied, `4` precondition refused).
  `--format json | table | plain`.
- **18 TUI views** under one Elm-pattern reducer (sync, total, async-
  free). Vim keys, fuzzy search across the cluster (`/`), command
  palette (`:`), quick-open (`Ctrl+K`), bulk ops with multi-select.
- **Operation queue** with dry-run, diff preview, and replay-as-
  script export (proxxx CLI / pvesh / curl / Ansible).
- **SQLite-backed time-travel cache** — `proxxx replay <timestamp>`
  reconstructs the cluster as it looked at any past moment.
- **MCP server** — stdio JSON-RPC for LLM agents. 10-tool registry
  is compile-time fixed and SHA-256 pinned via
  `proxxx mcp tools --checksum`.

### Pre-flight risk gate

Every destructive op routes through 11 risk variants — `Locked`,
`Running`, `LongUptime`, `TaggedProd`, `ActiveNetTraffic`, `HaManaged`,
`HasManySnapshots`, `BackupAgeWarning`, `NoBackupFound`,
`ListeningOnService`, `DeepCheckSkipped` — with per-op weighting.
`Severe` refuses without `--allow-risk`; `Notice` and `Warning`
print and proceed. Operator owns the override.

### HITL approval gate

Real Telegram round-trip via `HitlCoordinator` and a single shared
`getUpdates` poller. Deny on 120 s timeout, deny when Telegram is
unconfigured but a policy matched. Policy-driven by tag / vmid /
wildcard with multi-approver support (`require = N`).

### Security hardening

- All secrets (token, ticket, CSRF, password, PBS token) live in
  `Zeroizing<String>` — `Drop` overwrites the heap allocation.
- 32 MiB body cap on every API response (no OOM via hostile JSON).
- `cargo clippy --deny unwrap_used --deny expect_used --deny panic
  --deny indexing_slicing --deny await_holding_lock` in production
  code. Tests are relaxed via `cfg_attr(test, allow(...))`.
- TOFU `known_hosts` for SSH; `HostKeyVerifier` trait
  (`TOFU` / `Strict` / `Off`).
- TOCTOU-safe SPICE handoff (`tempfile` + `O_EXCL` + 128-bit random
  suffix + mode 0600).
- Shell-injection-safe `pveum` invocation: 3 layers of defence
  (metachar refusal + `shell_quote` + `--` separator), tested with
  `'; touch /tmp/pwned`, `$(rm -rf /)`, backticks, pipes, semicolons,
  newlines.
- `cargo audit --deny warnings` runs as gate stage 3 + nightly cron
  in CI. Documented advisory ignores live in `.cargo/audit.toml`
  with crate, dependency path, threat model, and remediation.
- Compile-time-fixed MCP tool registry — no runtime registration
  path; an attacker controlling the config file cannot inject tools.
- Pre-flight risk gate refuses destructive ops on running guests
  without `--allow-risk`.

### Quality gate

Six stages, run as both a pre-commit hook and the CI contract:

1. `cargo fmt --check`
2. `cargo clippy --release --all-targets` (deny tier)
3. `cargo audit --deny warnings`
4. `cargo test --release --all-targets` (lib unit + wiremock + TUI
   snapshot + integration)
5. 88 read-only probes against a live PVE cluster
6. Full mutation lifecycle (LXC create → start → snapshot → stop →
   delete, plus cluster-level CRUD across pool, firewall-cluster
   alias / group / ipset, backup-jobs, notifications endpoint +
   matcher, storage-defs; QEMU 9998 from an alpine ISO; opt-in QGA
   agent-required round-trips via `PROXXX_E2E_QGA_VMID=<vmid>`)

The matrix at `pre-commit/01-feature-coverage.md` distinguishes
*implemented* from *verified end-to-end live* row by row.

### Known limits

See `## Honest non-goals` in [`README.md`](README.md) for the full
list of design boundaries. Highlights:

- ISO library checksums are pinned (5× SHA-256, 1× SHA-512 for
  Debian) against dated upstream manifests; the `all_entries_are_
  pinned` invariant test enforces at every `cargo test` that no
  future entry can ship with `checksum: None`.
- PBS restore is Linux-only (no `proxmox-backup-client` for macOS /
  Windows upstream).
- HA console has no full failover simulator; the deterministic
  priority-list preview suffices for the common case.
- Hardware-passthrough mapping is read-only (no VFIO writes —
  modprobe + initramfs + reboot territory, out of scope).
- Effective-permissions resolution shells out to `pveum user
  permissions` (`proxxx perms`) since the Perl evaluator on the
  node is canonical. The API-side `proxxx access permissions` is
  also available — same typed tree from `/access/permissions`,
  no SSH dependency — for the common case where the evaluator's
  full grant-tree expansion isn't needed.
- WebAuthn enrolment from the TUI is impossible (browser cert
  ceremony). proxxx exposes the API-driven primitives (token CRUD,
  password change, ACL editing) but stays out of `/access/openid/*`
  and `/access/tfa/u2f`.
- Snapshot rollback is intentionally not exposed — the TUI shows a
  read-only rollback impact preview; the destructive trigger runs
  through `qm rollback` / `pct rollback` or the PVE web UI by
  design.
