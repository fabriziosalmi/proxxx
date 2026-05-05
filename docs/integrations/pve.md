# Proxmox VE

proxxx talks to PVE via its REST API, hosted on port 8006 by default.
No agent, no plugin, no patched daemon.

## Authentication

Two modes are supported.

### API token (recommended)

```toml
auth = "token"
user = "root@pam"
token_id = "proxxx"
token_secret = "..."
```

The token is sent as
`Authorization: PVEAPIToken=user!token_id=secret`. PVE supports
**Privilege Separation** — a token can be more restricted than its
owning user. proxxx works with separated and non-separated tokens
identically; the API surface respects whichever permission set PVE
applies.

### Password (legacy)

```toml
auth = "password"
user = "root@pam"
password = "..."
```

This drives the `/access/ticket` endpoint and gets a session ticket
+ CSRF token. Tickets expire after 2 hours; proxxx refreshes them
transparently. Cookies are stored in a per-process cookie jar —
nothing is written to disk.

## TLS

```toml
verify_tls = true     # default
verify_tls = false    # accept self-signed
```

`verify_tls = false` enables `danger_accept_invalid_certs` on the
reqwest client. This is appropriate for homelabs with self-signed
certs but must be off in production. proxxx does not provide a way
to pin a specific certificate — use a real CA-signed cert for prod.

## Endpoint coverage

The static-analysis gate at `tests/proxmox_map_coverage.rs` cross-checks
proxxx's API surface against a curated catalog of every PVE endpoint
in `tests/fixtures/proxmox_map.json` and emits a snapshot diff. As of
the most recent commit: **163 of 190 endpoints covered (85%)**. Run
`cargo test --test proxmox_map_coverage` for the live count.

| Group | Endpoints | Notes |
| :--- | :--- | :--- |
| Cluster reads | `/cluster/resources`, `/cluster/status`, `/cluster/tasks`, `/cluster/replication`, `/cluster/log`, `/version` | Fan-out reads |
| Cluster config | `/cluster/options`, `/cluster/config/{nodes,join,qdevice,totem}` | Global options + corosync bootstrap |
| Nodes | `/nodes`, `/nodes/{n}/status`, `/nodes/{n}/{syslog,journal,report,time,dns,hosts,subscription,wakeonlan,certificates,...}` | Full node-system layer |
| QEMU lifecycle | `/nodes/{n}/qemu/...` | start, stop, shutdown, reboot, suspend, resume, delete, clone, template, migrate, snapshot |
| QEMU config | `/nodes/{n}/qemu/{vmid}/{config,pending,resize,unlink,sendkey,move_disk,feature}` | Typed + raw config writes |
| QEMU agent | `/nodes/{n}/qemu/{vmid}/agent/{exec,exec-status,file-read,file-write,network-get-interfaces}` | QGA — file ops + net introspection |
| QEMU console | `/nodes/{n}/qemu/{vmid}/{vncproxy,vncwebsocket,termproxy,spiceproxy}` | Ticket mint + WS URL builder |
| LXC | `/nodes/{n}/lxc/...` | start, stop, snapshot, exec, migrate, move_volume, resize, interfaces (no QGA — uses `lxc-info`) |
| Firewall | `/cluster/firewall/{rules,aliases,groups,ipset,options}`, `/nodes/{n}/{kind}/{vmid}/firewall/{rules,aliases,options}` | Full CRUD on cluster + per-guest |
| Storage | `/storage`, `/nodes/{n}/storage/{s}/{content,upload,download-url}` | Cluster CRUD + content upload/download |
| Backup | `/cluster/backup` (recurring jobs CRUD), `/nodes/{n}/vzdump` (one-shot), `/cluster/backup-info` | Scheduler + ad-hoc |
| HA | `/cluster/ha/{rules,resources,groups,status/current,status/manager_status}` | Read + group CRUD; PVE 9 renamed `groups` → `rules`, both paths exposed |
| HW | `/nodes/{n}/hardware/{pci,usb}`, `/cluster/mapping/{pci,usb}` | Read inventory + cluster-wide passthrough mapping CRUD |
| ACME | `/cluster/acme/{account,plugins,tos,directories,challenge-schema}`, `/nodes/{n}/certificates/{info,custom,acme}` | Cluster account + plugin CRUD; per-node cert order |
| Notifications | `/cluster/notifications/{endpoints,matchers,targets}` | PVE 8+ native routing CRUD |
| Metrics | `/cluster/metrics/server` (exporters CRUD), `/nodes/{n}/{rrddata,rrd}`, `/nodes/{n}/{kind}/{vmid}/{rrddata,rrd}` | Numeric series + PNG graph references |
| Pools | `/pools`, `/pools/{poolid}` | Multi-tenancy CRUD + member add/remove |
| Access | `/access/{users,groups,roles,realms,tfa,acl,permissions,password}`, `/access/users/{u}/token/{id}` | Full ACL + token CRUD + API-side permissions tree |
| Disks | `/nodes/{n}/disks/{list,smart,zfs,lvm,lvmthin}` | Read-only inspection |
| Tasks | `/nodes/{n}/tasks`, `/nodes/{n}/tasks/{upid}/{status,log}`, `DELETE /nodes/{n}/tasks/{upid}` | Per-node listing + cancel |
| Utils | `/nodes/{n}/{aplinfo,query-url-metadata}` | LXC template catalog + URL pre-flight |

## QEMU vs LXC dispatch

PVE's REST surface is path-segregated: `/qemu/` for VMs, `/lxc/` for
containers. proxxx's `ProxmoxGateway` trait takes a `GuestType` on
every write method — calling `start_guest("pve1", 100, GuestType::Lxc)`
routes to `/nodes/pve1/lxc/100/status/start`, not `/qemu/`. This was
audit bug #1; nine wiremock tests pin the routing.

## Rate limiting

```toml
rate_limit = 10    # max requests per second
```

Backed by the [`governor`](https://crates.io/crates/governor) crate
(GCRA). Each request blocks until a token is available. The default
of 10/s is comfortable for homelabs and small clusters; scale up if
PVE is fronted by a robust load balancer.

## Body cap

Every response body is bounded at 32 MiB. A misbehaving node returning
a 2 GiB JSON cannot OOM proxxx — the read aborts and surfaces
`ApiError::PayloadTooLarge`.

## Schema drift handling

When PVE returns a field shape proxxx doesn't recognize, the response
fails to deserialize and surfaces `ApiError::Schema`. Callers should
not retry — open an issue with the PVE major version. Unknown enum
variants on `serde` types use `#[serde(other)]` fallbacks where
applicable so a single new state doesn't poison the whole list.

## Design boundaries

What proxxx will not ship. These mirror the project-wide
[honest non-goals](https://github.com/fabriziosalmi/proxxx#honest-non-goals)
and are stable design decisions:

- **No Ceph cluster writes.** Operators reach for the `ceph` CLI
  directly on the node where the kernel module is loaded; proxxx
  wraps Ceph reads (status, metadata, flags) but not destructive
  ops (osd add/down, mon create, pool prune). Ceph wire shape
  changes between major releases — staying out of the write path
  is a deliberate maintenance choice.
- **No SDN config writes.** PVE SDN is opt-in cluster config that
  few clusters enable, and the wire shape changes between PVE
  versions. Skipped rather than ship a fragile surface.
- **No browser-only auth flows.** U2F/WebAuthn registration and
  OIDC's redirect-callback dance both need a browser to drive them.
  proxxx exposes the API-driven primitives (token CRUD, password
  change, ACL editing) but stays out of `/access/openid/*` and
  `/access/tfa/u2f` — no terminal UX for those beats the web UI.

## Was a non-goal, now shipped

Earlier proxxx versions called these out as out-of-scope on this
page. They have since landed and are first-class — listed here so
the boundaries above stay honest:

- **Cluster + per-guest firewall CRUD** (aliases, groups, ipsets,
  options) — `proxxx firewall-cluster`, `proxxx firewall-guest`.
- **Live cluster bootstrap** (corosync membership, join wizard,
  qdevice, totem inspection) — `proxxx cluster-bootstrap`.
- **HA group CRUD** + user-facing `/status/current` —
  `proxxx ha group-create/update/delete`, `proxxx ha status-current`.
- **ACME accounts + challenge plugins** (the cluster-wide config
  that backs per-node cert ordering) — `proxxx acme`.
- **Hardware passthrough mapping** (cluster-wide PCI / USB device
  pools) — `proxxx cluster-mapping`.
- **Storage definitions CRUD** (add/update/delete cluster storages
  — NFS, PBS, ZFS pool, dir, RBD, etc.) — `proxxx storage-defs`.
- **PVE 8+ notification routing** (endpoints, matchers, targets) —
  `proxxx notifications`.
- **Cluster metric exporters** (InfluxDB / Graphite) —
  `proxxx metric-servers`.
- **Recurring vzdump scheduler** (vs the existing one-shot
  `proxxx backup`) — `proxxx backup-jobs`.
- **Node system layer** (DNS, hosts, NTP, journal/syslog,
  subscription, certs, support report, wake-on-LAN) —
  `proxxx node-system <node>`.

## See also

- [Configuration](/guide/configuration) — `[profiles.X]` section
- [Error categories](/reference/errors) — `ApiError` variants
