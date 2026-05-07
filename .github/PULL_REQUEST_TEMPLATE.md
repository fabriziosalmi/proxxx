<!--
Thanks for the contribution. Keep the description tight — the gate
runs locally + in CI; this template is here to surface intent and
verification, not to gate on paperwork.

Security-impacting changes go through SECURITY.md, not a public PR.
-->

## What this changes

<!-- One paragraph. Lead with the operator-facing effect, not the diff stats. -->

## Why

<!-- The problem it solves, or the issue / discussion link. -->

Closes #

## Verification

How did you confirm this works? Tick what applies and add specifics.

- [ ] `scripts/gate.sh` passed locally (fmt + clippy + audit + tests + live probes + mutation lifecycle)
- [ ] Live cluster verification (PVE node + version):
- [ ] Live PBS verification (host + version):
- [ ] New tests added (unit / integration / E2E)
- [ ] Updated `pre-commit/01-feature-coverage.md` row(s)
- [ ] Updated `CHANGELOG.md` `[Unreleased]` section
- [ ] Updated user-facing docs (`docs/`, `README.md`)

## Areas reviewers should look at

<!-- Pointers to the trickier hunks; risk surfaces; edge cases you intentionally didn't cover and why. -->

## Risk

- [ ] Touches the API client (`src/api/`) or mutation lifecycle
- [ ] Touches HITL / approval gates (`src/hitl/`)
- [ ] Touches secret handling (`src/config/`, anything `Zeroizing`)
- [ ] Adds a new dependency (justify in description; recheck `cargo audit`)
- [ ] Changes a CLI flag or default behaviour (note in CHANGELOG breaking-changes section)
- [ ] None of the above
