# HITL via Telegram

Human-In-The-Loop approval gates for destructive operations. proxxx
intercepts the destructive op, pushes an inline-keyboard request into
a Telegram chat, and waits for a callback. Approve, deny, or timeout
— never silent bypass.

## Why Telegram

It's the path of least resistance for the threat model:

- **Out-of-band.** A network attacker who has compromised the proxxx
  process cannot also forge a Telegram callback (different transport,
  different auth, different host).
- **Auditable.** Every callback is logged in the chat with timestamp
  and the responder's user_id. Reviewable forever.
- **Mobile-friendly.** The on-call engineer can approve from a phone.
- **Free.** No bot platform fees, no per-message billing.

Slack, Mattermost, Discord all have similar primitives — Telegram
ships first because the inline-keyboard pattern is dead simple.

## Setup

### 1. Create a bot

Talk to [@BotFather](https://t.me/BotFather), `/newbot`, name it
`proxxx`. Copy the token.

### 2. Find your chat ID

Add the bot to your chat (or DM it). Send any message. Then:

```sh
curl -s "https://api.telegram.org/bot<TOKEN>/getUpdates" | jq '.result[].message.chat.id'
```

Note the ID (negative for groups, positive for DMs).

### 3. Configure

```toml
[telegram]
bot_token         = "123456:ABC..."
chat_id           = "-1001234567890"
allowed_approvers = [123456789]   # numeric Telegram user IDs allowed to press Approve
```

`allowed_approvers` is required in practice: an empty or missing list refuses
every callback, so nothing can ever be approved.

### 4. Add policies

```toml
[[policies]]
action  = "stop"
target  = "tag:prod"
channel = "telegram"
require = 1

[[policies]]
action  = "delete"          # TUI action name
target  = "tag:prod"
channel = "telegram"
require = 2                 # two distinct approvers
```

`action` is matched against a different name on each surface:

| Surface | Names a policy can match |
| :--- | :--- |
| CLI | `start`, `stop`, `restart`, `suspend`, `resume`: the batch commands (`proxxx stop 100 101`) |
| TUI | `start`, `stop`, `restart`, `delete`, `snapshot`, `migrate`, `exec`, `download_iso`, `move_disk`, `resize_disk` |
| MCP | the tool name: `stop_guest`, `restart_guest`, `delete_guest`, `create_snapshot`, ... |

On the CLI, `delete`, `migrate` and the other single-guest destructive
commands do **not** consult policies: they run once `--yes` is given. Use
`--secure` to refuse them outright (exit 8), or run them from the TUI, where
the `delete` policy above applies. A policy written for the CLI (`stop`)
does not match the MCP tool (`stop_guest`); declare both if you need both.

### 5. Test

```sh
proxxx hitl serve  # in one terminal
# elsewhere, with guest 100 tagged prod:
proxxx stop 100    # exits 9: waiting for approval in Telegram
```

You should see an inline keyboard appear in your chat with **Approve**
and **Deny** buttons.

## How it works

```
TUI / CLI / MCP  ──→  enforce_preflight  ──→  check_hitl
                                                  │
                                                  ▼
                                       policy match found?
                                          │
                                       ┌──┴──┐
                                       no    yes
                                       │     │
                                       ▼     ▼
                                  execute*   HitlCoordinator.register(txn_id)
                                                                      │
                                                                      ▼
                                                Telegram::request_approval(...)
                                                                      │
                                                                      ▼
                                                  long-poll getUpdates ──┐
                                                                          │
                                  (Approve / Deny callback arrives)       │
                                                                          ▼
                                            HitlCoordinator.resolve(txn_id, true|false)
                                                                          │
                                                                          ▼
                                                       execute  OR  refuse
```

> `*` **MCP diverges here — fail-closed.** On the MCP transport a *destructive*
> tool with **no matching policy is REFUSED**, not executed: the transport is
> network-reachable, so an unauthenticated caller must never reach a destructive
> op. TUI / CLI keep the present-operator behaviour above (no policy → execute)
> because a human is already at the keyboard. (v0.13.0)

Internals:

- **`HitlCoordinator`** holds a `HashMap<txn_id, oneshot::Sender<bool>>`.
  Register before sending the Telegram request; resolve when the
  callback arrives.
- **`run_hitl_poller`** is a single shared task that long-polls
  `getUpdates`. Telegram returns 409 Conflict if you call `getUpdates`
  concurrently from the same bot, so there's exactly one poller.
- **120 s timeout.** If no callback arrives, the gate refuses and the
  op is denied.
- **`run_hitl_poller` is only spawned if `[telegram]` is configured.**
  If Telegram isn't set up and a policy matches, the gate **denies**
  hard — better safe than secret-bypassing.

## Four terminal outcomes

```rust
// src/tui/mod.rs : check_hitl callback flow
//
// 1. Telegram not configured     → DENY
// 2. request_approval send fails → DENY + error log
// 3. Callback arrives in 120 s   → forward user's decision
// 4. 120 s timeout               → DENY (default-secure)
```

This is the an earlier review fix. Pre-fix, the TUI's `check_hitl` slept
3 s and auto-approved. Post-fix, every gated op is a real round trip.

## Inline keyboard format

```
🛡️ proxxx HITL approval

Action: delete
Target: 100 (vm-prod-web, tag: prod)
Reason: TUI requested delete on guest 100
Profile: homelab
Timestamp: 2026-05-03 09:32:11 UTC

[ ✅ Approve ] [ ❌ Deny ]
```

The callback data is HMAC-SHA256 signed with the local HITL key and encodes
`approve:<id>:<hmac>` (41 bytes) or `deny:<id>:<hmac>` (38 bytes), where `<id>`
is a 16-character lowercase hex identifier (64 bits of OS CSPRNG entropy)
leaving 23 bytes of headroom under Telegram's 64-byte `callback_data` cap
regardless of the action name.

Senders (CLI policy intercept and MCP dispatch) persist each request in
`<config_dir>/hitl_pending.db` (SQLite, `0600` permissions in a `0700` parent
directory alongside `telegram_hmac.key`) with `id`, `action`, `vmid`, `node`,
`guest_type` (`qemu` or `lxc`), `params`, `require`, `issued_at`, `expires_at`
(default 120 s TTL), `status` (`pending` / `approved` / `denied` / `expired` /
`executed` / `failed`), `approvers`, `upid`, and `error`. Terminal rows older
than 7 days are pruned on open.

Both the HITL daemon and the TUI poller validate incoming callbacks through
`verify_callback` and the pending store in fail-closed order:

1. A 16-hex-character HMAC tag is present and valid.
2. The originating chat ID matches `[telegram].chat_id`.
3. The pressing user's numeric Telegram ID is listed in
   `[telegram].allowed_approvers` (an empty allowlist refuses all
   callbacks).
4. The payload matches `<decision>:<id>` where `<id>` is 16 lowercase hex
   digits. Legacy 3/4-segment buttons (`approve:<action>:<vmid>[:r<N>]:<hmac>`)
   are refused with `"⚠️ This approval button is from an older proxxx, request again"`.
5. Store lookup (`hitl_pending.db` in the daemon, or `HitlCoordinator` in the
   TUI): unknown IDs return `"⚠️ Unknown request"`, expired requests
   (`now > expires_at`) transition to `expired` and return
   `"⏰ Request expired — request again"`, and non-`pending` rows
   return `"⚠️ Already handled (...)"` — preventing replay even across
   daemon restarts.

For policies with `require > 1`, `require` and distinct approver votes are
stored in `hitl_pending.db` (or `HitlCoordinator` in the TUI) rather than on
the button, so quorum progress survives daemon restarts and unblocks or
executes only after `require` distinct authorised approvers press Approve (a
single Deny from an authorised approver denies immediately).

## Daemon executors & guest binding (`proxxx hitl serve`)

Once a request reaches `approved` in `hitl_pending.db`, `src/hitl/daemon.rs`
deserializes `(action, params)` into the closed `ApprovedOp` enum
(`#[serde(deny_unknown_fields)]`, `Shape::Name` validation on path-bearing
strings) and dispatches through an exhaustive `match` (no wildcard arm) covering
all 15 supported operations:

- **CLI batch operations (`cli::common::exec_cli_batch_op`)**:
  - `start` (`CliEmptyParams`)
  - `stop` (`CliStopParams`: `force`, `timeout_secs`)
  - `restart` (`CliEmptyParams`)
  - `suspend` (`CliEmptyParams`)
  - `resume` (`CliEmptyParams`)
- **MCP destructive tools (`mcp::dispatch::exec_*`)**:
  - `stop_guest` (`McpStopGuestParams`: `guest_id`, `force`)
  - `restart_guest` (`McpGuestIdParams`: `guest_id`)
  - `delete_guest` (`McpGuestIdParams`: `guest_id`)
  - `create_snapshot` (`McpSnapshotParams`: `guest_id`, `name`)
  - `delete_snapshot` (`McpSnapshotParams`: `guest_id`, `name`)
  - `suspend_guest` (`McpGuestIdParams`: `guest_id`)
  - `clone_guest` (`McpCloneGuestParams`: `guest_id`, `newid`, `name`, `full`)
  - `migrate_guest` (`McpMigrateGuestParams`: `guest_id`, `target_node`, `online`)
  - `create_guest` (`McpCreateGuestParams`: `node`, `type`, `vmid`, `name`, `memory`, `cores`, `storage`, `disk_size`, `template`, `iso`, `bridge`)
  - `clone_with_cloudinit` (`McpCloneWithCloudinitParams`: `guest_id`, `newid`, `name`, `full`, `ciuser`, `sshkey`, `ipconfig0`, `searchdomain`, `nameserver`)

Pre-execution safety gates:

- **Undecodable row refusal**: any row whose `(action, params)` fails
  deserialization or parameter validation is marked `failed` with
  `cannot decode approved operation: ...` and nothing is executed.
- **Guest binding (VMID reuse protection)**:
  - For operations on an existing guest, the daemon resolves `find_guest(vmid)`
    at execution time and checks that the guest still exists and matches the
    stored `(node, guest_type)`. If the guest disappeared, moved to another
    node, or changed guest type (`qemu` vs `lxc`), the row is marked `failed`
    with `guest changed since the request (expected <node>/<type>, found ...)`
    and nothing is executed.
  - For `create_guest`, `clone_guest`, and `clone_with_cloudinit`, if an
    explicit target VMID (`vmid` / `newid`) is now occupied on the cluster, the
    row is marked `failed` with
    `guest changed since the request (expected target VMID <id> to be free, found <node>/<type>)`
    and nothing is executed.
- **Outcome recording**: on `Ok(upid)` the row is marked `executed` with `upid`
  stored in `hitl_pending_requests.upid`; on error it is marked `failed` with
  the error text, and the Telegram message footer is updated to show either
  `✅ Done — <upid>` or `❌ Failed: <error>`.

## Audit trail

- The PVE call that runs after an approval goes through the same client as
  every other mutation, so it is recorded in the HMAC-chained audit log
  (`audit.db`, verify with `proxxx audit verify`).
- The request itself, its approvers' Telegram IDs (`approvers`), its final
  status and the resulting UPID or error are kept in `hitl_pending.db`;
  terminal rows are pruned after 7 days.
- The daemon's log file records each callback it receives
  (`Received HITL callback: ...`), refused callbacks with the reason, and
  quorum progress (`HITL quorum not yet met for <id>: <n>/<require>`).
- Telegram keeps the chat history with each responder's identity.

## TUI gated actions

In the TUI (`src/tui/mod.rs`), every `SideEffect` is classified by the
exhaustive `hitl_action` matcher (which has no wildcard arm, so new
`SideEffect` variants must be classified at compile time) before dispatch:

- **Policy-matchable TUI actions (`[[policies]]`)**: `start`, `stop`,
  `restart`, `delete`, `snapshot` (`CreateSnapshot`), `migrate`, `exec`
  (`ExecuteGuestCommand`), `download_iso` (`DownloadIso`, target `0`),
  `move_disk`, and `resize_disk`.
- **Destructive TUI actions gated by `--secure`**: `stop`, `delete`,
  `restart`, `migrate`, `exec`, `move_disk`, and `resize_disk`.
- **Operation queue (`ExecuteQueue`)**: queued operations are gated
  individually before batch dispatch. Operations that do not require
  approval keep their write-ahead persistence and run immediately with the
  batch; operations that require HITL approval are sent through the same
  Telegram approval flow and execute only after approval (or are marked as
  failed on denial or timeout).

## Self-HITL (`--secure`)

Both the TUI and the CLI consult the shared destructive-action set defined in
`src/hitl/mod.rs` (`DESTRUCTIVE_ACTIONS`). By the classification rule in
`src/hitl/mod.rs` (`#399`), an action is **destructive** if it is irreversible,
removes data or a resource, or interrupts availability:

- **Shared TUI + CLI actions**: `stop`, `delete`, `restart`, `migrate`, `exec`,
  `move_disk` (`disk move`), `resize_disk` (`disk resize`).
- **Additional CLI destructive actions (`#399`)**:
  - Guest & task availability / irreversible lifecycle: `suspend`, `task_stop`
    (`task-stop`), `backup_stop` (`backup --mode stop|suspend`), `template`,
    `snapshot_delete` (`snapshot delete`), `vm_raw_set` (`vm raw-set`),
    `vm_sendkey` (`vm sendkey`), `vm_unlink` (`vm unlink`), `ct_raw_set`
    (`ct raw-set`), `qga_write` (`qga write`), `ssh_cmd`
    (`ssh <vmid> --cmd ...`).
  - Node-level bulk power & rolling upgrades: `node_stopall` (`node stopall`,
    requires `--yes`), `node_suspendall` (`node suspendall`, requires `--yes`),
    `patch_apply` (`patch apply`), `node_subscription_delete`
    (`node-system <node> subscription delete`), `node_cert_delete`
    (`node-system <node> cert delete`).
  - Cluster, HA, corosync & hardware mapping removal / quorum changes:
    `ha_group_delete` (`ha group-delete`), `cluster_mapping_pci_delete`
    (`cluster-mapping pci delete`), `cluster_mapping_usb_delete`
    (`cluster-mapping usb delete`), `corosync_node_add`
    (`cluster-bootstrap nodes add`), `corosync_node_remove`
    (`cluster-bootstrap nodes remove`), `cluster_join`
    (`cluster-bootstrap join join`), `qdevice_setup`
    (`cluster-bootstrap qdevice setup`), `qdevice_update`
    (`cluster-bootstrap qdevice update`), `qdevice_delete`
    (`cluster-bootstrap qdevice delete`).
  - Firewall removal & match/policy updates: `firewall_alias_update`
    (`firewall-cluster alias update`), `firewall_alias_delete`
    (`firewall-cluster alias delete`), `firewall_group_delete`
    (`firewall-cluster group delete`), `firewall_ipset_add_cidr`
    (`firewall-cluster ipset add-cidr`), `firewall_ipset_delete`
    (`firewall-cluster ipset delete`), `firewall_ipset_remove_cidr`
    (`firewall-cluster ipset remove-cidr`), `firewall_options_set`
    (`firewall-cluster options set`), `guest_firewall_alias_update`
    (`firewall-guest <vmid> alias update`), `guest_firewall_alias_delete`
    (`firewall-guest <vmid> alias delete`), `guest_firewall_options_set`
    (`firewall-guest <vmid> options set`).
  - Access control, pools & tokens: `pool_remove_members`
    (`pool remove-members`), `pool_delete` (`pool delete`), `user_update`
    (`access user-update`), `user_delete` (`access user-delete`), `group_delete`
    (`access group-delete`), `acl_unset` (`access acl-unset`), `access_password`
    (`access password`), `token_revoke` (`token revoke`),
    `token_bootstrap_rotate` (`token bootstrap --rotate`).
  - Storage, backups, notifications & schedules: `storage_delete`
    (`storage delete`), `storage_def_update` (`storage-defs update`),
    `storage_def_delete` (`storage-defs delete`), `backup_job_delete`
    (`backup-jobs delete`), `pbs_restore` (`pbs restore`),
    `acme_account_delete` (`acme account delete`), `acme_plugin_delete`
    (`acme plugin delete`), `metric_server_delete` (`metric-servers delete`),
    `notification_endpoint_delete` (`notifications endpoint delete`),
    `notification_matcher_delete` (`notifications matcher delete`),
    `schedule_remove` (`schedule remove`).
  - Declarative convergence (can delete resources under `--prune`):
    `state_apply` (`state apply`), `reconcile_converge` (`reconcile converge`).

`cli::cli_hitl_action` (`src/cli/mod.rs`) matches exhaustively over `Command`
and every mutating subcommand enum (with no `_ =>` wildcard), so adding a new
CLI subcommand fails to compile until it is explicitly classified. When
`proxxx --secure schedule run-due` (or `proxxx --secure daemon serve`) runs,
`--secure` is forwarded to every spawned child process so destructive scheduled
entries also fail closed with exit code `8`.

- **In the TUI (`proxxx --secure`)**: every destructive operation is forced
  through the Telegram HITL approval flow regardless of whether a
  `[[policies]]` rule matches.
- **In the CLI (`proxxx --secure <command>`)**: the CLI does not implement
  interactive HITL approval yet, so every destructive CLI command in
  `DESTRUCTIVE_ACTIONS` fails closed before any API call with
  `hitl::SecureModeRefusal` and exit code `8` (the same "mutation refused by a
  local lock" family as `read_only` and `incident freeze`):

  ```text
  Fatal Error: --secure: delete requires human approval, which the CLI does not implement yet; run it from the TUI with --secure, or drop --secure
  ```

  Non-destructive CLI commands (for example `proxxx --secure ls nodes`,
  `proxxx --secure start 100`, or `proxxx --secure snapshot create 100 --name s1`)
  run normally.

## Limits

- **Replay protection & TTL.** Each request receives a random 64-bit hex ID
  with a 120 s TTL and is persisted in `<config_dir>/hitl_pending.db`. Stale
  or replayed callbacks are refused both within a daemon session and across
  daemon restarts, and subsequent legitimate requests for the same
  `(action, vmid)` receive fresh IDs.
- **No escalation.** A timed-out request is denied; it does not
  escalate to a second channel. Add a separate alert rule if you
  want oncall to know.

## See also

- [Configuration → `[telegram]`](/reference/configuration#telegram)
- [Configuration → `[[policies]]`](/reference/configuration#policies-hitl)
- [Security model — HITL invariants](/architecture/security#hitl-gate)
