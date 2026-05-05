# Alerts

A rule-driven alerting daemon that polls the cluster, fires events on
predicate match, and routes via Telegram, ntfy, or webhook. No
SaaS account required.

## Configuration

```toml
[[alerts]]
name              = "node_down"
trigger           = "node_offline"
threshold         = 60                          # seconds
severity          = "critical"
route             = ["telegram", "ntfy:proxxx-prod"]
dedup_secs        = 600

[[alerts]]
name              = "ceph_full"
trigger           = "storage_above"
storage           = "ceph-rbd"
threshold_percent = 85
severity          = "warning"
route             = ["telegram"]

[[alerts]]
name              = "replica_broken"
trigger           = "replication_failing"
severity          = "critical"
route             = ["telegram", "ntfy:proxxx-prod", "webhook:https://hooks.example/notify"]
```

## Triggers

The `trigger` field is a closed enum — three predicates today:

| Trigger | Fires when | Tunables |
| :--- | :--- | :--- |
| `node_offline` | A cluster node has been offline for `threshold` seconds | `threshold` |
| `storage_above` | A storage pool's usage exceeds `threshold_percent` | `threshold_percent`, optional `storage` filter |
| `replication_failing` | Any replication job has `fail_count > 0` or non-empty `error` | none |

Adding a trigger requires a code change and a PR. This is intentional
— predicate evaluation must be auditable and the closed enum prevents
"alert spec injection" via a config file. New triggers go through the
gate.

## Channels

`route` is an array of channel specs:

| Spec | Transport |
| :--- | :--- |
| `telegram` | Reuses the `[telegram]` config from HITL |
| `ntfy:<topic>` | HTTPS POST to `https://ntfy.sh/<topic>` (or self-hosted ntfy) |
| `webhook:<url>` | HTTPS POST `application/json` with the full event |

Unknown channel specs are warned and skipped — the daemon does not
abort on a misconfigured channel; the others still fire.

## Running

### One-shot evaluation

```sh
proxxx alerts eval
```

Polls once, prints what would fire as JSON, exits. Useful for `cron`
or for testing rules against current state. No notifications are
sent.

### Daemon mode

```sh
proxxx alerts watch --interval 30
```

Long-running. Polls every `--interval` seconds (default 30), evaluates
rules, fires events, dedups via in-memory cache. Respects SIGTERM
(systemd / launchd) — flushes pending events and exits within ~1
second.

### Test routing end-to-end

```sh
proxxx alerts test --route telegram --severity warning
```

Sends a synthetic event through the channel without waiting for a
predicate match. Use this in your install runbook.

## Dedup

```toml
dedup_secs = 600
```

A `(rule, target)` tuple won't re-fire within `dedup_secs`. So
`node_offline` for `pve2` fires once at minute 0, then is silent
through minute 10, then fires again at minute 11.

The dedup cache is in-memory — daemon restart resets it. This is
intentional: post-restart, current-state alerts SHOULD fire so the
operator knows the daemon caught back up.

## Severity

Three levels: `info`, `warning`, `critical`. Mapped to channel-native
priority:

| Severity | Telegram emoji | ntfy priority | Webhook field |
| :--- | :---: | :---: | :--- |
| `info` | ℹ️ | 2 (low) | `"severity": "info"` |
| `warning` | ⚠️ | 4 (default) | `"severity": "warning"` |
| `critical` | 🚨 | 5 (max, bypass DnD) | `"severity": "critical"` |

ntfy maps priority to phone push behaviour. Critical bypasses Do Not
Disturb on most setups.

## Webhook payload

```json
{
    "rule": "ceph_full",
    "severity": "warning",
    "summary": "Storage 'ceph-rbd' usage 87.4% exceeds threshold 85%",
    "target": "ceph-rbd",
    "fired_at": "2026-05-03T09:32:11Z",
    "details": {
        "trigger": "storage_above",
        "threshold_percent": 85,
        "current_percent": 87.4,
        "node": "pve1"
    }
}
```

The `details` object is shape-stable per trigger.

## Backoff

The Telegram poller (also used by HITL) retries on outage with
exponential backoff: 1 s, 2 s, 4 s … capped at 60 s. ntfy and webhook
calls retry up to 3 times with jittered exponential backoff before
giving up; failures are logged and surfaced via the file appender.

## Limits

- **No oncall scheduler.** Rules don't have time-windowed routing.
  If you want "wake me only off-hours," use ntfy's silent topics or a
  separate router downstream.
- **No history persistence** in the daemon. The `tracing` audit log
  preserves every fire and route, but cluster-wide history /
  dashboards are not built in. Pipe to Loki / Grafana / your SIEM.
- **No mute time-windows.** Comment out the `[[alerts]]` rule for
  scheduled maintenance — there is no `--silence` flag.
- **No ack via reply.** HITL infra is for approvals, not for alert
  ack. If you want acknowledgement semantics, the webhook channel
  carries the rule name and you can wire an ack endpoint downstream.

## See also

- [Configuration → `[[alerts]]`](/reference/configuration#alerts)
- [HITL via Telegram](/integrations/hitl) — same Telegram bot, different surface
