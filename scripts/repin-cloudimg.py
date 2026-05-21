#!/usr/bin/env python3
"""Re-pin the cloud-image registry in src/cli/cloudimg.rs to each distro's
latest dated/immutable build + its official checksum.

Why this exists
---------------
`cloud-img download` pins every entry to a SHA so PVE verifies the
download server-side. A pinned SHA requires an *immutable* URL (a dated
build dir, never a `current`/`latest` symlink). That means the registry
goes stale when a distro ships a new point release — this script is the
automation that keeps it fresh (run weekly by
`.github/workflows/cloudimg-repin.yml`, which opens a bump PR on change).

Discovery is per-distro because each publishes differently:
  - Ubuntu : releases/noble/release-YYYYMMDD/  + SHA256SUMS
  - Debian : images/cloud/trixie/YYYYMMDD-NNNN/ + SHA512SUMS (no sha256)
  - Alpine : v3.20/releases/cloud/ generic_…-r0.qcow2 + .qcow2.sha512
  - Fedora : releases/41/Cloud/x86_64/images/ + …-CHECKSUM (sha256)

Stdlib only (urllib) — runs in CI with no pip install.

Usage:
  scripts/repin-cloudimg.py            # patch cloudimg.rs in place
  scripts/repin-cloudimg.py --dry-run  # print what would change, touch nothing
Exit codes: 0 = ok (changed or not), 2 = a distro probe failed (stale
entry left untouched, loud warning), 3 = (--dry-run only) drift found.
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path

REGISTRY_FILE = Path(__file__).resolve().parent.parent / "src" / "cli" / "cloudimg.rs"
HTTP_TIMEOUT = 30
UA = {"User-Agent": "proxxx-repin-cloudimg/1.0 (+https://github.com/fabriziosalmi/proxxx)"}


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:  # noqa: S310 (https only, official hosts)
        return resp.read().decode("utf-8", errors="replace")


def hrefs(index_html: str) -> list[str]:
    """Extract href targets from an autoindex HTML page."""
    return re.findall(r'href="([^"]+)"', index_html)


@dataclass
class Pin:
    """The mutable fields of a registry entry, freshly discovered."""

    url: str
    checksum: str
    checksum_algorithm: str
    version: str


# ── Per-distro discovery ────────────────────────────────────────────────


def discover_ubuntu() -> Pin:
    base = "https://cloud-images.ubuntu.com/releases/noble/"
    dirs = sorted(
        m.group(1)
        for h in hrefs(fetch(base))
        if (m := re.fullmatch(r"(release-\d{8})/", h))
    )
    if not dirs:
        raise RuntimeError("ubuntu: no release-YYYYMMDD dirs found")
    latest = dirs[-1]
    fname = "ubuntu-24.04-server-cloudimg-amd64.img"
    sums = fetch(f"{base}{latest}/SHA256SUMS")
    checksum = _sum_for(sums, fname, hexlen=64)
    return Pin(
        url=f"{base}{latest}/{fname}",
        checksum=checksum,
        checksum_algorithm="sha256",
        version=f"24.04 LTS (noble, build {latest.removeprefix('release-')})",
    )


def discover_debian() -> Pin:
    base = "https://cloud.debian.org/images/cloud/trixie/"
    dirs = sorted(
        m.group(1)
        for h in hrefs(fetch(base))
        if (m := re.fullmatch(r"(\d{8}-\d+)/", h))
    )
    if not dirs:
        raise RuntimeError("debian: no YYYYMMDD-NNNN dirs found")
    latest = dirs[-1]
    fname = f"debian-13-genericcloud-amd64-{latest}.qcow2"
    sums = fetch(f"{base}{latest}/SHA512SUMS")
    checksum = _sum_for(sums, fname, hexlen=128)
    return Pin(
        url=f"{base}{latest}/{fname}",
        checksum=checksum,
        checksum_algorithm="sha512",
        version=f"13 (trixie) genericcloud, build {latest}",
    )


def discover_alpine() -> Pin:
    base = "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/cloud/"
    pat = re.compile(r"generic_alpine-3\.20\.(\d+)-x86_64-bios-cloudinit-r0\.qcow2")
    patches = sorted(
        {int(m.group(1)) for h in hrefs(fetch(base)) if (m := pat.fullmatch(h))}
    )
    if not patches:
        raise RuntimeError("alpine: no generic_alpine 3.20.N qcow2 found")
    fname = f"generic_alpine-3.20.{patches[-1]}-x86_64-bios-cloudinit-r0.qcow2"
    # Alpine publishes a per-file .sha512 sidecar; no .sha256.
    sidecar = fetch(f"{base}{fname}.sha512").strip()
    checksum = sidecar.split()[0]
    _validate_hex(checksum, 128, f"alpine {fname}")
    return Pin(
        url=f"{base}{fname}",
        checksum=checksum,
        checksum_algorithm="sha512",
        version=f"3.20.{patches[-1]} generic (bios cloudinit)",
    )


def discover_fedora() -> Pin:
    base = "https://download.fedoraproject.org/pub/fedora/linux/releases/41/Cloud/x86_64/images/"
    pat = re.compile(r"Fedora-Cloud-Base-Generic-41-(\d+)\.(\d+)\.x86_64\.qcow2")
    builds = sorted(
        {
            (int(m.group(1)), int(m.group(2)))
            for h in hrefs(fetch(base))
            if (m := pat.fullmatch(h))
        }
    )
    if not builds:
        raise RuntimeError("fedora: no Generic Base 41 qcow2 found")
    n, m = builds[-1]
    fname = f"Fedora-Cloud-Base-Generic-41-{n}.{m}.x86_64.qcow2"
    checksum_file = fetch(f"{base}Fedora-Cloud-41-{n}.{m}-x86_64-CHECKSUM")
    checksum = _fedora_sum_for(checksum_file, fname)
    return Pin(
        url=f"{base}{fname}",
        checksum=checksum,
        checksum_algorithm="sha256",
        version=f"41 cloud (Generic Base {n}.{m})",
    )


# ── Checksum-file parsers ───────────────────────────────────────────────


def _sum_for(sums: str, fname: str, *, hexlen: int) -> str:
    """Parse a `<hex>  [*]filename` SHA{256,512}SUMS line."""
    for line in sums.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == fname:
            _validate_hex(parts[0], hexlen, fname)
            return parts[0]
    raise RuntimeError(f"checksum for {fname} not found in SUMS file")


def _fedora_sum_for(checksum_file: str, fname: str) -> str:
    """Fedora CHECKSUM lines: `SHA256 (fname) = <hex>`."""
    m = re.search(rf"SHA256 \({re.escape(fname)}\) = ([0-9a-f]{{64}})", checksum_file)
    if not m:
        raise RuntimeError(f"fedora SHA256 for {fname} not found")
    return m.group(1)


def _validate_hex(value: str, length: int, what: str) -> None:
    if not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        raise RuntimeError(f"{what}: checksum {value!r} is not {length} lowercase hex")
    if set(value) == {"0"}:
        raise RuntimeError(f"{what}: refusing all-zero placeholder checksum")


# ── Rust-source patching ────────────────────────────────────────────────

# Map registry `id:` → discovery fn. Keying on the stable id (never the
# rotating filename) keeps the patch anchored even as URLs change.
DISCOVERERS = {
    "ubuntu-24.04-noble-amd64": discover_ubuntu,
    "debian-13-trixie-amd64": discover_debian,
    "alpine-3.20-virt-x86_64": discover_alpine,
    "fedora-41-cloud-x86_64": discover_fedora,
}


def patch_entry(block: str, pin: Pin) -> str:
    """Replace the url/checksum/checksum_algorithm/version fields inside a
    single `CloudImg { … }` entry block. Each field is a `key: "value",`
    line; we rewrite only the value, preserving indentation + commas."""

    def repl(field: str, value: str, text: str) -> str:
        pat = re.compile(rf'(?m)^(\s*{field}: ")[^"]*(",)\s*$')
        new, n = pat.subn(rf"\g<1>{value}\g<2>", text)
        if n != 1:
            raise RuntimeError(f"expected exactly one `{field}:` line, found {n}")
        return new

    block = repl("url", pin.url, block)
    block = repl("checksum", pin.checksum, block)
    block = repl("checksum_algorithm", pin.checksum_algorithm, block)
    block = repl("version", pin.version, block)
    return block


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="report drift; write nothing")
    args = ap.parse_args()

    src = REGISTRY_FILE.read_text()
    out = src
    failures: list[str] = []
    changes: list[str] = []

    for entry_id, discover in DISCOVERERS.items():
        # Slice this entry's block. A `CloudImg { … }` body contains no
        # braces, so `[^{}]*` can't cross into a neighbouring entry —
        # which keeps the match anchored on the brace that actually
        # precedes THIS id (a plain `.*?` would match the first
        # `CloudImg {` in the file and skip ahead to any id).
        m = re.search(
            rf'(CloudImg \{{[^{{}}]*?id: "{re.escape(entry_id)}"[^{{}}]*?\}},)',
            out,
            re.DOTALL,
        )
        if not m:
            failures.append(f"{entry_id}: entry block not found in registry")
            continue
        block = m.group(1)
        try:
            pin = discover()
        except Exception as e:  # noqa: BLE001 — one distro's outage must not nuke others
            failures.append(f"{entry_id}: probe failed: {e}")
            continue
        new_block = patch_entry(block, pin)
        if new_block != block:
            changes.append(f"{entry_id} → {pin.checksum_algorithm}:{pin.checksum[:12]}…  {pin.url}")
            out = out[: m.start(1)] + new_block + out[m.end(1) :]

    for f in failures:
        print(f"WARN  {f}", file=sys.stderr)

    if not changes:
        print("cloud-img registry already current — no changes.")
        return 2 if failures else 0

    print("cloud-img registry drift:")
    for c in changes:
        print(f"  {c}")

    if args.dry_run:
        return 3

    REGISTRY_FILE.write_text(out)
    print(f"\nPatched {REGISTRY_FILE}.")
    # A probe failure mid-run is non-fatal (other entries still repinned),
    # but surface it so the workflow can flag the PR for human attention.
    return 2 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
