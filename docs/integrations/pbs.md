# Proxmox Backup Server

proxxx browses PBS over REST and shells out to `proxmox-backup-client`
for restore.

## Why split

The PBS REST API exposes datastore listings, snapshot manifests, and
file indices — perfect for browse / inspection, cross-platform, no
binary dependency. But restore reads chunked encrypted data and is
authoritatively implemented in `proxmox-backup-client` upstream.
Re-implementing the chunk reader in Rust would be 5,000+ LOC of
maintenance debt for a feature that already works.

| Operation | Path |
| :--- | :--- |
| List datastores         | REST   `/api2/json/admin/datastore` |
| List snapshots          | REST   `/api2/json/admin/datastore/{store}/snapshots` |
| List files in snapshot  | REST   `/api2/json/admin/datastore/{store}/files` |
| Restore archive         | shell  `proxmox-backup-client restore ...` |

## Configuration

```toml
[pbs]
url          = "https://pbs.lan:8007/"
user         = "proxxx@pbs"
token_id     = "reader"
token_secret = "..."
verify_tls   = false
rate_limit   = 10
```

## The PBS auth gotcha

```rust
// PBS:  PBSAPIToken=user!tokenid:secret    ← colon
// PVE:  PVEAPIToken=user!tokenid=secret    ← equals
```

PBS and PVE use different separators between `tokenid` and `secret`.
Sending the PVE form to PBS gets a 401 with no useful diagnostic.
proxxx handles the difference internally — you supply the same shape
in both `[profiles.X]` and `[pbs]` config sections, and proxxx
formats the header correctly per service.

## Browsing

```sh
# List datastores
proxxx pbs datastores

# List snapshots in a datastore
proxxx pbs snapshots --store main

# Filter by guest type / id
proxxx pbs snapshots --store main --backup-type vm --backup-id 100

# List files (.pxar.didx, .img.fidx, .blob) in a snapshot
proxxx pbs files --store main \
    --type vm --backup-id 100 --time 1700000000
```

## Restore

```sh
proxxx pbs restore \
    --store main \
    --snapshot 'vm/100/2026-01-15T03:00:00Z' \
    --archive root.pxar.didx \
    --target /mnt/restore/ \
    --yes
```

`--yes` is mandatory — restore is a destructive write to the local
filesystem. proxxx does NOT restore directly back into a guest; the
re-injection path is too sharp (no permission preservation, no atomic
dir rebuild, no rollback).

The restore subprocess is supervised by `kill_on_drop(true)` — if
proxxx is killed (Ctrl+C, OOM, parent crash), tokio sends SIGKILL to
the `proxmox-backup-client` child so it stops consuming bandwidth
and disk I/O immediately.

**Caveat**: SIGKILL bypasses `proxmox-backup-client`'s own cleanup —
upstream has no graceful-shutdown protocol when the parent dies.
Partial archive files (`*.pxar`, `*.img.fidx`) and any chunk-store
working files **may remain in the target directory** after a kill.
Treat the target directory as untrusted after an interrupted restore:
delete its contents and re-run the restore from scratch. proxxx does
not attempt to clean up partial output, because deleting unknown
content under the operator's chosen target path could destroy data
that pre-existed the restore.

## Encrypted backups

proxxx surfaces encrypted snapshots in the listing (the
`is_encrypted()` flag on `SnapshotInfo`). Restore of an encrypted
backup requires a master key configured in the PBS client — proxxx
does not currently manage that key flow. Workaround: invoke
`proxmox-backup-client restore --keyfile ...` directly.

## Limits

- **Linux only for restore.** `proxmox-backup-client` is not packaged
  for macOS / Windows. proxxx detects the missing binary and tells
  you to install it (or to invoke restore from a Linux box).
- **No FUSE mount.** macFUSE is blocked on Apple Silicon; WinFsp is
  Windows-only; setuid mount on Linux is fragile. We restore full
  archives instead. Single-file extraction post-restore is `cp` /
  `tar` / `pxar` from the restored tree.
- **No cross-snapshot search.** "Find `/etc/nginx` in the last 7 days
  of vm-100 backups" would require iterating chunk indices for every
  snapshot — gigabytes of metadata. Future work, when local catalog
  indexing makes it tractable.
- **No re-injection into running guests.** The QGA `guest-file-write`
  primitive is single-call, no permissions, no atomicity. Too sharp.

## See also

- [PBS restore — kill_on_drop signal handling](/architecture/security#pbs-restore-supervision)
- [Configuration → `[pbs]`](/reference/configuration#pbs)
