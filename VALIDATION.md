# Validation & Testing

Styx validates Rust crates, MCP contracts, platform packagers, and browser/desktop executors from `src/`.

## Prerequisites

- **Rust toolchain** pinned by [`rust-toolchain.toml`](rust-toolchain.toml) (`1.97.1`)
- **Node.js 22+** with `npm --prefix src ci --ignore-scripts --no-audit --no-fund`

## Local Checks

```sh
# Workspace typecheck and strict lint
cargo check --locked --offline --workspace
cargo clippy --locked --offline --workspace --all-targets -- -D warnings

# Formatting check
rustfmt --edition 2024 --check src/crates/*/src/*.rs

# Targeted Rust unit and protocol tests
cargo test --locked --offline -p styx-contracts
cargo test --locked --offline -p styx-core
cargo test --locked --offline -p styx-runtime

# Repository test entrypoints
npm run test:unit
npm run test:contracts
```

## Full Quality Gate

To run the full local quality gate (dependency tree/audit checks, SBOM checks, deterministic unit/contract suites, and lockfile consistency) into a fresh evidence directory:

```sh
npm run quality -- /absolute/path/to/evidence-dir
```

Keep acceptance artifacts and release verification receipts outside `/tmp` for large bundles, and record unit/contract checks, signed package checksums, actual installations, and live end-to-end runtime effects separately. Never replay state-changing operations whose prior outcome is `unknown`.
