# Styx Product Source (`src/`)

`src/` contains the Styx v0.4.0 Rust workspace, native macOS/Windows desktop bridges, and pinned external worker adapters. The earlier JavaScript Gateway/Host/Core prototype has been retired.

## Directory Layout

- `src/crates/` — Rust workspace crates:
  - `styx-contracts`: Pure protocol, capability, session, operation, and release contracts.
  - `styx-core`: Pure policy, session routing, enrollment, and management state machines (no OS/network I/O).
  - `styx-crypto`: Ed25519/RSA device, claim, and release-publisher cryptography.
  - `styx-tls`: Strict X.509/TLS certificate issuance, pinning, and renewal.
  - `styx-runtime`: Gateway, Host, App control, storage journals, and provider supervisors.
  - `styx`: Unified CLI and daemon entry point (`styx setup`, `styx status`, `styx invite`, `styx gateway`, `styx host`, `styx computers`, `styx plugin`, `styx upgrade`).
- `src/host/macos/` and `src/host/windows/` — Native Swift (`Styx.app`) and C# (`Styx.cs`) desktop UI and OS bridges.
- `src/providers/browser-worker/` — Bounded Playwright MCP worker supervised by the Rust Host.
- `src/providers/cua-native/` — Pinned TryCua `cua-driver` 0.47.24 source descriptor and patch.
- `src/plugin/` — ChatGPT Custom MCP plugin package template and skills.
- `src/ci/` and `src/tools/` — Local quality gate (`rust-quality.py`), test runner (`local-tests.py`), and signed release builders.
- `src/docs/` — Active setup and architecture references:
  - [Stable 0.4.0 setup guide](docs/stable-setup.md)
  - [Rust architecture and contracts index](docs/rust-core-rewrite/README.md)
  - [Reduced release scope](docs/rust-core-rewrite/REDUCED-SCOPE.md)

## Development & Verification

```sh
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --workspace --locked --offline -- --test-threads=1
npm --prefix src run test:all
```
