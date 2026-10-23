#!/usr/bin/env python3
"""Line-coverage ratchet over the `lcov.info` the CI coverage job writes (#298).

`.coverage-floor` holds the floor (the measured line coverage minus the
tolerance) and the covered/total lines of every file at the time it was
written. The CI job runs `check`:

  - Below the floor: fail, and name the files whose uncovered line count
    grew since the floor was written, worst first. A drop is always some
    files' doing; the totals alone do not say which.
  - More than one tolerance above the coverage the floor was written from:
    fail, and ask for the floor to be raised in the same pull request. The
    new file is written next to the report, so it ships in the CI
    artifact. Without this the floor would never move, and a later drop
    back to it would pass.
  - Otherwise: pass.

`update` rewrites `.coverage-floor` from a report. Use the `lcov.info` of
the pull request's own CI run (artifact `coverage-lcov`): coverage measured
on another platform differs.

Stdlib only; runs in CI with no pip install.

Usage:
  scripts/coverage-ratchet.py check  lcov.info [.coverage-floor]
  scripts/coverage-ratchet.py update lcov.info [.coverage-floor]
"""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path

TOLERANCE = 0.5
DEFAULT_FLOOR = Path(".coverage-floor")


def read_lcov(path: Path) -> dict[str, tuple[int, int]]:
    """Map each source file under src/ to (lines hit, lines found)."""
    files: dict[str, tuple[int, int]] = {}
    current = None
    hit = found = 0
    for raw in path.read_text().splitlines():
        if raw.startswith("SF:"):
            current = raw[3:]
            hit = found = 0
        elif raw.startswith("LH:"):
            hit = int(raw[3:])
        elif raw.startswith("LF:"):
            found = int(raw[3:])
        elif raw == "end_of_record" and current is not None:
            rel = repo_relative(current)
            if rel is not None:
                files[rel] = (hit, found)
            current = None
    if not files:
        sys.exit(f"{path}: no source files under src/ in the report")
    return files


def repo_relative(path: str) -> str | None:
    marker = "/src/"
    i = path.rfind(marker)
    if path.startswith("src/"):
        return path
    return None if i < 0 else path[i + 1 :]


def percent(files: dict[str, tuple[int, int]]) -> float:
    hit = sum(h for h, _ in files.values())
    found = sum(f for _, f in files.values())
    return 100.0 * hit / found if found else 0.0


def render_floor(files: dict[str, tuple[int, int]]) -> str:
    measured = percent(files)
    lines = [
        "# Line-coverage floor (#298), written by scripts/coverage-ratchet.py update.",
        "# CI fails below `floor`, and asks for this file to be rewritten when",
        "# coverage rises more than `tolerance` above it. Do not edit by hand.",
        f"measured = {measured:.2f}",
        f"floor = {measured - TOLERANCE:.2f}",
        f"tolerance = {TOLERANCE}",
        "",
        "# file = [lines covered, lines total]",
        "[files]",
    ]
    lines += [f'"{name}" = [{h}, {f}]' for name, (h, f) in sorted(files.items())]
    return "\n".join(lines) + "\n"


def responsible(
    now: dict[str, tuple[int, int]], base: dict[str, list[int]]
) -> list[tuple[int, str, str]]:
    """Files whose uncovered line count grew, worst first."""
    out = []
    for name, (h, f) in now.items():
        bh, bf = base.get(name, (0, 0))
        grew = (f - h) - (bf - bh)
        if grew > 0:
            was = f"{100.0 * bh / bf:.1f}%" if bf else "new file"
            now_pct = f"{100.0 * h / f:.1f}%" if f else "-"
            out.append((grew, name, f"{was} -> {now_pct}"))
    return sorted(out, key=lambda t: (-t[0], t[1]))


def summary(text: str) -> None:
    print(text)
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if target:
        with open(target, "a") as fh:
            fh.write(text + "\n")


def check(report: Path, floor_path: Path) -> int:
    now = read_lcov(report)
    cfg = tomllib.loads(floor_path.read_text())
    floor = float(cfg["floor"])
    tolerance = float(cfg["tolerance"])
    measured = percent(now)
    head = (
        f"### Coverage ratchet\n\nLine coverage {measured:.2f}%, "
        f"floor {floor:.2f}% (tolerance {tolerance}pp)."
    )
    if measured < floor:
        rows = responsible(now, cfg.get("files", {}))
        table = "\n".join(
            f"| `{name}` | {grew} | {change} |" for grew, name, change in rows[:20]
        )
        summary(
            f"{head}\n\n**Below the floor.** Files whose uncovered lines grew "
            f"since the floor was written:\n\n| File | New uncovered lines | "
            f"Coverage |\n| :--- | ---: | :--- |\n{table}\n\nAdd tests for "
            f"them, or remove the untested code."
        )
        return 1
    if measured - tolerance > floor + tolerance:
        new = render_floor(now)
        Path(str(report) + ".coverage-floor").write_text(new)
        summary(
            f"{head}\n\n**Coverage rose: raise the floor in this pull request.** "
            f"This run's `coverage-lcov` artifact holds the new file as "
            f"`lcov.info.coverage-floor`: commit it as `.coverage-floor`. "
            f"The new floor is {measured - tolerance:.2f}%."
        )
        return 1
    summary(f"{head}\n\nWithin the ratchet.")
    return 0


def update(report: Path, floor_path: Path) -> int:
    floor_path.write_text(render_floor(read_lcov(report)))
    print(f"wrote {floor_path}")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) not in (3, 4) or argv[1] not in ("check", "update"):
        print(__doc__, file=sys.stderr)
        return 2
    report = Path(argv[2])
    floor_path = Path(argv[3]) if len(argv) == 4 else DEFAULT_FLOOR
    return (check if argv[1] == "check" else update)(report, floor_path)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
