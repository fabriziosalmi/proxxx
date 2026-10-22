#!/usr/bin/env python3
"""Re-pin the two image registries to each distro's latest dated/immutable
build + its official checksum, and check that every pinned URL still
answers.

Registries
----------
  - src/cli/cloudimg.rs     `CloudImg` entries  (`proxxx cloud-img download`)
  - src/app/iso_library.rs  `IsoEntry` entries  (`proxxx iso list/download`)

Why this exists
---------------
Both registries pin every entry to a checksum so PVE verifies the download
server-side. A pinned checksum requires an *immutable* URL (a dated build
dir, never a `current`/`latest` symlink), so the registries go stale when a
distro ships a new build, and some mirrors delete old builds outright:
iso_library.rs, which this script did not cover, had 4 of 6 URLs answering
404 on 2026-10-22 (#492). `.github/workflows/cloudimg-repin.yml` runs this
weekly, opens a bump PR on change, and fails when a pinned URL is dead.

Discovery is per-distro because each publishes differently:
  - Ubuntu : releases/<codename>/release-YYYYMMDD/ + SHA256SUMS (kept since GA)
  - Debian : images/cloud/<codename>/YYYYMMDD-NNNN/ + SHA512SUMS (no sha256)
  - Alpine : v3.N/releases/cloud/ generic_…-r0.qcow2 + .qcow2.sha512, or
             v3.N/releases/x86_64/ alpine-virt-3.N.P-x86_64.iso + .iso.sha256
  - Fedora : an end-of-life release is pinned to the permanent archive
             (archives.fedoraproject.org); the mirror network drops it
  - Rocky  : pub/rocky/<major>/images/x86_64/ + CHECKSUM (sha256)

Stdlib only (urllib) — runs in CI with no pip install.

Usage:
  scripts/repin-cloudimg.py              # patch both registries in place
  scripts/repin-cloudimg.py --dry-run    # print what would change, touch nothing
  scripts/repin-cloudimg.py --check-urls # only check every pinned URL answers
Exit codes: 0 = ok (changed or not), 2 = a distro probe failed (stale
entry left untouched, loud warning), 3 = (--dry-run only) drift found,
4 = (--check-urls) a pinned URL does not answer.
"""

from __future__ import annotations

import argparse
import functools
import re
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLOUDIMG_FILE = ROOT / "src" / "cli" / "cloudimg.rs"
ISO_LIBRARY_FILE = ROOT / "src" / "app" / "iso_library.rs"
HTTP_TIMEOUT = 30
UA = {
    "User-Agent": "proxxx-repin-cloudimg/1.1 (+https://github.com/fabriziosalmi/proxxx)"
}


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers=UA)
    # https only, official hosts — the URL comes from this file.
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        return resp.read().decode("utf-8", errors="replace")


def hrefs(index_html: str) -> list[str]:
    """Extract href targets from an autoindex HTML page."""
    return re.findall(r'href="([^"]+)"', index_html)


@dataclass(frozen=True)
class Build:
    """A discovered build: where it is, its official checksum, and the
    build tag the registry's version label is made from."""

    url: str
    checksum: str
    checksum_algorithm: str
    tag: str


@dataclass
class Pin:
    """The mutable fields of a registry entry, freshly discovered."""

    url: str
    checksum: str
    checksum_algorithm: str
    version: str


# ── Per-distro discovery (cached: two entries may share one build) ─────


@functools.cache
def ubuntu(codename: str, number: str) -> Build:
    base = f"https://cloud-images.ubuntu.com/releases/{codename}/"
    dirs = sorted(
        m.group(1)
        for h in hrefs(fetch(base))
        if (m := re.fullmatch(r"(release-\d{8})/", h))
    )
    if not dirs:
        raise RuntimeError(f"ubuntu {codename}: no release-YYYYMMDD dirs found")
    latest = dirs[-1]
    fname = f"ubuntu-{number}-server-cloudimg-amd64.img"
    checksum = _sum_for(fetch(f"{base}{latest}/SHA256SUMS"), fname, hexlen=64)
    return Build(
        f"{base}{latest}/{fname}", checksum, "sha256", latest.removeprefix("release-")
    )


@functools.cache
def debian(codename: str, number: str) -> Build:
    base = f"https://cloud.debian.org/images/cloud/{codename}/"
    dirs = sorted(
        m.group(1)
        for h in hrefs(fetch(base))
        if (m := re.fullmatch(r"(\d{8}-\d+)/", h))
    )
    if not dirs:
        raise RuntimeError(f"debian {codename}: no YYYYMMDD-NNNN dirs found")
    latest = dirs[-1]
    fname = f"debian-{number}-genericcloud-amd64-{latest}.qcow2"
    checksum = _sum_for(fetch(f"{base}{latest}/SHA512SUMS"), fname, hexlen=128)
    return Build(f"{base}{latest}/{fname}", checksum, "sha512", latest)


@functools.cache
def alpine_cloud(branch: str) -> Build:
    base = f"https://dl-cdn.alpinelinux.org/alpine/v{branch}/releases/cloud/"
    pat = re.compile(
        rf"generic_alpine-{re.escape(branch)}\.(\d+)-x86_64-bios-cloudinit-r0\.qcow2"
    )
    patches = sorted(
        {int(m.group(1)) for h in hrefs(fetch(base)) if (m := pat.fullmatch(h))}
    )
    if not patches:
        raise RuntimeError(f"alpine {branch}: no generic cloud qcow2 found")
    fname = f"generic_alpine-{branch}.{patches[-1]}-x86_64-bios-cloudinit-r0.qcow2"
    # Alpine publishes a per-file .sha512 sidecar for cloud images.
    checksum = fetch(f"{base}{fname}.sha512").strip().split()[0]
    _validate_hex(checksum, 128, f"alpine {fname}")
    return Build(f"{base}{fname}", checksum, "sha512", str(patches[-1]))


@functools.cache
def alpine_virt_iso(branch: str) -> Build:
    base = f"https://dl-cdn.alpinelinux.org/alpine/v{branch}/releases/x86_64/"
    pat = re.compile(rf"alpine-virt-{re.escape(branch)}\.(\d+)-x86_64\.iso")
    patches = sorted(
        {int(m.group(1)) for h in hrefs(fetch(base)) if (m := pat.fullmatch(h))}
    )
    if not patches:
        raise RuntimeError(f"alpine {branch}: no virt ISO found")
    fname = f"alpine-virt-{branch}.{patches[-1]}-x86_64.iso"
    checksum = _sum_for(fetch(f"{base}{fname}.sha256"), fname, hexlen=64)
    return Build(f"{base}{fname}", checksum, "sha256", str(patches[-1]))


@functools.cache
def fedora_archived(release: str) -> Build:
    # An end-of-life release leaves the mirror network (some mirrors
    # answered 404 for 41 on 2026-10-22, others 200); the archive keeps it
    # for good.
    base = (
        "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/"
        f"{release}/Cloud/x86_64/images/"
    )
    pat = re.compile(
        rf"Fedora-Cloud-Base-Generic-{release}-(\d+)\.(\d+)\.x86_64\.qcow2"
    )
    builds = sorted(
        {
            (int(m.group(1)), int(m.group(2)))
            for h in hrefs(fetch(base))
            if (m := pat.fullmatch(h))
        }
    )
    if not builds:
        raise RuntimeError(f"fedora {release}: no Generic Base qcow2 in the archive")
    n, m = builds[-1]
    fname = f"Fedora-Cloud-Base-Generic-{release}-{n}.{m}.x86_64.qcow2"
    checksum = _tagged_sum_for(
        fetch(f"{base}Fedora-Cloud-{release}-{n}.{m}-x86_64-CHECKSUM"), fname
    )
    return Build(f"{base}{fname}", checksum, "sha256", f"{n}.{m}")


@functools.cache
def rocky(major: str) -> Build:
    base = f"https://dl.rockylinux.org/pub/rocky/{major}/images/x86_64/"
    pat = re.compile(
        rf"Rocky-{major}-GenericCloud-Base-({major}\.\d+)-(\d{{8}}\.\d+)\.x86_64\.qcow2"
    )
    builds = sorted(
        {
            (tuple(int(x) for x in m.group(1).split(".")), m.group(2), m.group(0))
            for h in hrefs(fetch(base))
            if (m := pat.fullmatch(h))
        }
    )
    if not builds:
        raise RuntimeError(f"rocky {major}: no GenericCloud-Base qcow2 found")
    version, build, fname = builds[-1]
    checksum = _tagged_sum_for(fetch(f"{base}CHECKSUM"), fname)
    return Build(
        f"{base}{fname}",
        checksum,
        "sha256",
        f"{'.'.join(map(str, version))} build {build}",
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


def _tagged_sum_for(checksum_file: str, fname: str) -> str:
    """Fedora / Rocky CHECKSUM lines: `SHA256 (fname) = <hex>`."""
    m = re.search(rf"SHA256 \({re.escape(fname)}\) = ([0-9a-f]{{64}})", checksum_file)
    if not m:
        raise RuntimeError(f"SHA256 for {fname} not found in CHECKSUM")
    return m.group(1)


def _validate_hex(value: str, length: int, what: str) -> None:
    if not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        raise RuntimeError(f"{what}: checksum {value!r} is not {length} lowercase hex")
    if set(value) == {"0"}:
        raise RuntimeError(f"{what}: refusing all-zero placeholder checksum")


# ── Registry entries: id → (discovery, version label) ───────────────────

Entry = tuple[Callable[[], Build], Callable[[str], str]]

# Keyed on the stable id (never the rotating filename), so the patch stays
# anchored as URLs change.
CLOUDIMG_ENTRIES: dict[str, Entry] = {
    "ubuntu-24.04-noble-amd64": (
        lambda: ubuntu("noble", "24.04"),
        lambda t: f"24.04 LTS (noble, build {t})",
    ),
    "debian-13-trixie-amd64": (
        lambda: debian("trixie", "13"),
        lambda t: f"13 (trixie) genericcloud, build {t}",
    ),
    "alpine-3.20-virt-x86_64": (
        lambda: alpine_cloud("3.20"),
        lambda t: f"3.20.{t} generic (bios cloudinit)",
    ),
    "fedora-41-cloud-x86_64": (
        lambda: fedora_archived("41"),
        lambda t: f"41 cloud (Generic Base {t})",
    ),
}

ISO_LIBRARY_ENTRIES: dict[str, Entry] = {
    "ubuntu-22.04-cloud": (
        lambda: ubuntu("jammy", "22.04"),
        lambda t: f"22.04 LTS (Jammy) build {t}",
    ),
    "ubuntu-24.04-cloud": (
        lambda: ubuntu("noble", "24.04"),
        lambda t: f"24.04 LTS (Noble) build {t}",
    ),
    "debian-12-cloud": (
        lambda: debian("bookworm", "12"),
        lambda t: f"12 (Bookworm) build {t}",
    ),
    "fedora-41-cloud": (
        lambda: fedora_archived("41"),
        lambda t: f"41 (Generic Base {t})",
    ),
    "alpine-3.21-iso": (
        lambda: alpine_virt_iso("3.21"),
        lambda t: f"3.21.{t}",
    ),
    "rocky-9-cloud": (
        lambda: rocky("9"),
        lambda t: t,
    ),
}


# ── Rust-source patching ────────────────────────────────────────────────


def _replace_string_field(field: str, value: str, text: str) -> str:
    """Rewrite the value of the single `field: "…",` line in `text`."""
    pat = re.compile(rf'(?m)^(\s*{field}: ")[^"]*(",)\s*$')
    new, n = pat.subn(lambda m: f"{m.group(1)}{value}{m.group(2)}", text)
    if n != 1:
        raise RuntimeError(f"expected exactly one `{field}:` line, found {n}")
    return new


def patch_cloudimg(block: str, pin: Pin) -> str:
    """`CloudImg` keeps url / checksum / checksum_algorithm / version as
    plain string fields."""
    block = _replace_string_field("url", pin.url, block)
    block = _replace_string_field("checksum", pin.checksum, block)
    block = _replace_string_field("checksum_algorithm", pin.checksum_algorithm, block)
    return _replace_string_field("version", pin.version, block)


def patch_iso_entry(block: str, pin: Pin) -> str:
    """`IsoEntry` carries the algorithm in the checksum's type:
    `checksum: Some(Checksum::Sha256(\\n "<hex>",\\n )),` (rustfmt layout)."""
    block = _replace_string_field("url", pin.url, block)
    block = _replace_string_field("version", pin.version, block)
    variant = {"sha256": "Sha256", "sha512": "Sha512"}[pin.checksum_algorithm]
    pat = re.compile(
        r'(?m)^(?P<indent>\s*)checksum: Some\(Checksum::Sha(?:256|512)\(\s*"[0-9a-f]*",?\s*\)\),[ \t]*$'
    )

    def repl(m: re.Match[str]) -> str:
        i = m.group("indent")
        return (
            f'{i}checksum: Some(Checksum::{variant}(\n{i}    "{pin.checksum}",\n{i})),'
        )

    new, n = pat.subn(repl, block)
    if n != 1:
        raise RuntimeError(
            f"expected exactly one `checksum: Some(Checksum::…)` field, found {n}"
        )
    return new


@dataclass
class Registry:
    path: Path
    struct: str
    entries: dict[str, Entry]
    patch: Callable[[str, Pin], str]


REGISTRIES = [
    Registry(CLOUDIMG_FILE, "CloudImg", CLOUDIMG_ENTRIES, patch_cloudimg),
    Registry(ISO_LIBRARY_FILE, "IsoEntry", ISO_LIBRARY_ENTRIES, patch_iso_entry),
]


def entry_block(src: str, struct: str, entry_id: str) -> re.Match[str] | None:
    # An entry body contains no braces, so `[^{}]*` cannot cross into a
    # neighbouring entry; that keeps the match anchored on the brace that
    # actually precedes THIS id.
    return re.search(
        rf'({struct} \{{[^{{}}]*?id: "{re.escape(entry_id)}"[^{{}}]*?\}},)',
        src,
        re.DOTALL,
    )


def repin(registry: Registry, failures: list[str], changes: list[str]) -> str:
    src = registry.path.read_text()
    out = src
    for entry_id, (discover, label) in registry.entries.items():
        m = entry_block(out, registry.struct, entry_id)
        if not m:
            failures.append(
                f"{entry_id}: entry block not found in {registry.path.name}"
            )
            continue
        try:
            build = discover()
        except Exception as e:  # noqa: BLE001 — one distro's outage must not nuke others
            failures.append(f"{entry_id}: probe failed: {e}")
            continue
        pin = Pin(build.url, build.checksum, build.checksum_algorithm, label(build.tag))
        block = m.group(1)
        new_block = registry.patch(block, pin)
        if new_block != block:
            changes.append(
                f"{registry.path.name} {entry_id} → {pin.checksum_algorithm}:{pin.checksum[:12]}…  {pin.url}"
            )
            out = out[: m.start(1)] + new_block + out[m.end(1) :]
    return out


# ── Liveness ────────────────────────────────────────────────────────────


def pinned_urls() -> list[tuple[str, str, str]]:
    """(file, id, url) for every entry of both registries."""
    rows = []
    for registry in REGISTRIES:
        src = registry.path.read_text()
        for m in re.finditer(
            rf'{registry.struct} \{{[^{{}}]*?id: "([^"]+)"[^{{}}]*?url: "([^"]+)"',
            src,
            re.DOTALL,
        ):
            rows.append((registry.path.name, m.group(1), m.group(2)))
    return rows


def url_answers(url: str) -> str | None:
    """None when the URL serves the file (one byte asked for), else why not.
    GET with a Range rather than HEAD: some mirrors answer HEAD differently."""
    req = urllib.request.Request(url, headers={**UA, "Range": "bytes=0-0"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            return None if resp.status in (200, 206) else f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001 — report any transport failure
        return str(e)


def check_urls() -> int:
    dead = []
    for file, entry_id, url in pinned_urls():
        why = url_answers(url)
        print(
            f"{'ok  ' if why is None else 'DEAD'}  {file} {entry_id}  {url}"
            + (f"  ({why})" if why else "")
        )
        if why is not None:
            dead.append(entry_id)
    if dead:
        print(
            f"\n{len(dead)} pinned URL(s) do not answer: {', '.join(dead)}",
            file=sys.stderr,
        )
        return 4
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--dry-run", action="store_true", help="report drift; write nothing"
    )
    ap.add_argument(
        "--check-urls", action="store_true", help="only check every pinned URL answers"
    )
    args = ap.parse_args()

    if args.check_urls:
        return check_urls()

    failures: list[str] = []
    changes: list[str] = []
    outputs = [
        (registry, repin(registry, failures, changes)) for registry in REGISTRIES
    ]

    for f in failures:
        print(f"WARN  {f}", file=sys.stderr)

    if not changes:
        print("image registries already current — no changes.")
        return 2 if failures else 0

    print("image registry drift:")
    for c in changes:
        print(f"  {c}")

    if args.dry_run:
        return 3

    for registry, out in outputs:
        if out != registry.path.read_text():
            registry.path.write_text(out)
            print(f"Patched {registry.path}.")
    # A probe failure mid-run is non-fatal (other entries still repinned),
    # but surface it so the workflow can flag the PR for human attention.
    return 2 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
