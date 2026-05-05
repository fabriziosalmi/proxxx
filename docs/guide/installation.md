# Installation

proxxx is a single Rust binary. There are no runtime dependencies beyond
a working Proxmox VE cluster (and optionally a PBS host) reachable over
HTTPS.

## From source

Requires a stable Rust toolchain (1.75 or newer) and `cargo`.

```sh
git clone https://github.com/fabriziosalmi/proxxx.git
cd proxxx
cargo build --release
./target/release/proxxx --version
```

The release binary is roughly 6 MB on macOS arm64 / Linux x86_64 after
strip.

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

A minimal config:

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
