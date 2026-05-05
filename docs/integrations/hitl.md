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
bot_token = "123456:ABC..."
chat_id   = -1001234567890
```

### 4. Add policies

```toml
[[policies]]
action           = "delete"
target           = "tag:prod"
require_approval = true
timeout_secs     = 120

[[policies]]
action           = "stop"
target           = "tag:critical"
require_approval = true
```

### 5. Test

```sh
proxxx hitl serve  # in one terminal
# elsewhere:
proxxx delete 100 --yes  # if guest 100 is tagged prod
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
                                   execute   HitlCoordinator.register(txn_id)
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

The callback data encodes `approve:txn_id` or `deny:txn_id`. The
poller parses, calls `HitlCoordinator::resolve`, and the spawned task
unblocks.

## Audit trail

Every callback is logged at `INFO` level in the proxxx audit log
(file appender, daily rotation, 14-day retention by default):

```
2026-05-03T09:32:14.123Z INFO  HITL approve: delete vm-100 by user_id=12345
2026-05-03T09:32:14.124Z INFO  Executing delete on vm-100
2026-05-03T09:32:14.567Z INFO  Task completed: UPID:pve1:00045A:...:vmrm:100:root@pam:
```

Telegram itself preserves the chat history with the responder's
identity. proxxx writes the audit-side correlation.

## Self-HITL (`--secure`)

For unattended scripts that want belt-and-suspenders:

```sh
proxxx --secure delete 100 --yes
```

`--secure` forces every destructive operation through the HITL gate
regardless of policy match. Use this in CI to require human approval
on mutations.

## Limits

- **Replay attacks.** A stale callback (forwarded message, old chat
  log) could in theory re-trigger an approval if the txn_id is
  predictable. Mitigation: txn_ids are random + time-bound.
  E2E-verified replay rejection is on the security-invariants matrix
  (still ❌ as of the last audit).
- **No multi-approver.** Only the first callback wins. "Two
  approvers required" needs explicit policy plumbing — not yet
  implemented.
- **No escalation.** A timed-out request is denied; it does not
  escalate to a second channel. Add a separate alert rule if you
  want oncall to know.

## See also

- [Configuration → `[telegram]`](/reference/configuration#telegram)
- [Configuration → `[[policies]]`](/reference/configuration#policies-hitl)
- [Security model — HITL invariants](/architecture/security#hitl-gate)
