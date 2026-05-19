# Installation

proxxx is a single Rust binary. There are no runtime dependencies beyond
a working Proxmox VE cluster (and optionally a PBS host) reachable over
HTTPS.

## Pre-built binaries (recommended)

Each [tagged release](https://github.com/fabriziosalmi/proxxx/releases)
ships **three layers of artifact verification** for every tarball:

1. **SHA-256 sidecar** — pin the bytes.
2. **Sigstore keyless cosign signature** (`.cosign.bundle`) — the
   signing certificate is pinned to this exact GitHub-Actions
   workflow path; the transparency-log inclusion proof is embedded
   so verification is offline.
3. **CycloneDX SBOM** (`proxxx-VERSION.cdx.json`) — every dep with
   name + version + checksum + license, generated authoritatively
   from `Cargo.lock`.

```sh
TARGET=x86_64-unknown-linux-musl     # or aarch64-apple-darwin
VERSION=0.1.7

gh release download v${VERSION} --repo fabriziosalmi/proxxx \
  --pattern "*-${TARGET}.tar.gz" \
  --pattern "*-${TARGET}.tar.gz.sha256" \
  --pattern "*-${TARGET}.tar.gz.cosign.bundle"

# Layer 1
shasum -a 256 -c proxxx-${VERSION}-${TARGET}.tar.gz.sha256

# Layer 2 — needs sigstore/cosign installed locally
cosign verify-blob \
  --bundle proxxx-${VERSION}-${TARGET}.tar.gz.cosign.bundle \
  --certificate-identity-regexp 'https://github.com/fabriziosalmi/proxxx/.github/workflows/release.yml@.*' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  proxxx-${VERSION}-${TARGET}.tar.gz

# Layer 3 (optional) — audit the dependency tree
gh release download v${VERSION} --repo fabriziosalmi/proxxx \
  --pattern "*.cdx.json" --pattern "*.cdx.json.sha256"
shasum -a 256 -c proxxx-${VERSION}.cdx.json.sha256
grype sbom:proxxx-${VERSION}.cdx.json   # or trivy, cyclonedx-cli

tar xzf proxxx-${VERSION}-${TARGET}.tar.gz
sudo mv proxxx-${VERSION}-${TARGET}/proxxx /usr/local/bin/
proxxx --version
```

Targets shipped today:

| Target                        | Platform                                       |
| :---------------------------- | :--------------------------------------------- |
| `aarch64-apple-darwin`        | macOS Apple Silicon                            |
| `x86_64-unknown-linux-musl`   | Linux x86_64 (static, every distro)            |
| `aarch64-unknown-linux-musl`  | Linux ARM64 (Pi 4/5, Ampere, Graviton, Oracle) |

ARM64 Linux is now a first-class release artefact (since v0.2.0),
built via `cross-rs/cross` against a containerized musl-aarch64
toolchain. No glibc dependencies — drops straight onto Alpine,
Raspberry Pi OS, Debian/Ubuntu, Amazon Linux on Graviton.

## From source

Requires a stable Rust toolchain (1.75 or newer) and `cargo`.

```sh
git clone https://github.com/fabriziosalmi/proxxx.git
cd proxxx
cargo build --release
./target/release/proxxx --version
```

The stripped release binary measures roughly 6 MB on Linux x86_64
musl and 8–9 MB on macOS arm64 — the gap is mostly objc/CoreFoundation
metadata that Linux musl doesn't link.

## Static musl build (Linux)

For deployment on minimal containers or distroless images:

```sh
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

The resulting binary at
`target/x86_64-unknown-linux-musl/release/proxxx` has no glibc
dependency and runs on Alpine, distroless, scratch.

## First-run configuration

proxxx reads its configuration from an OS-conventional path:

| Platform | Path |
|---|---|
| Linux   | `~/.config/proxxx/config.toml` |
| macOS   | `~/Library/Application Support/dev.proxxx.proxxx/config.toml` |
| Windows | `%APPDATA%\dev\proxxx\proxxx\config.toml` |

### Easy: interactive wizard

```sh
proxxx init --interactive
```

A 5-step prompted flow asks for URL, TLS posture, auth method
(API token or username + password), optional SSH layer with key
auto-discovery from `~/.ssh/`, optional per-guest SSH overrides,
and optional Telegram for HITL. Every input is probed against
the live cluster before write — a wrong token is caught at the
prompt, never lands in the TOML. Existing config triggers a
backup-or-cancel choice; the new file is written atomically
with mode 0600.

### Manual: edit the TOML

If you prefer to edit by hand, `proxxx init` (no flag) writes a
commented starter template you can fill in:

```sh
proxxx init                # writes the template; --force to overwrite
```

Or paste the minimum directly:

```toml
url = "https://pve.example.org:8006/"
user = "root@pam"
auth = "token"
token_id = "proxxx"
token_secret = "00000000-0000-0000-0000-000000000000"
verify_tls = false
```

See [Configuration](/guide/configuration) for the full schema, profile
support, and PBS section.

## Verifying the install

```sh
proxxx ls nodes --format json
```

If the cluster responds, you are configured. If not, the error message
will name the failing layer (`Transport`, `Unauthorized`, `Forbidden`,
`Schema`) — see [Error categories](/reference/errors).

## Pre-commit gate (for contributors)

If you plan to commit to the repo, install the gate:

```sh
git config core.hooksPath .githooks
chmod +x scripts/gate.sh .githooks/pre-commit .githooks/pre-push
cargo install cargo-audit --locked
```

See [Pre-commit gate](/guide/pre-commit-gate) for the policy.
