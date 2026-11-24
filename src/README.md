# Styx `src/`

Canonical product source for the Styx Rust Gateway, Host, Core ledger/policy, CLI, native platform UIs, and bounded executors.

- **Gateway / Host / Core / CLI**: [`crates/`](crates/) (`styx-contracts`, `styx-core`, `styx-runtime`, `styx`, `styx-android`)
- **Native UIs**: [`host/macos/`](host/macos/), [`host/windows/`](host/windows/), [`host/android/`](host/android/README.md)
- **Executors**: [`providers/browser-worker/`](providers/browser-worker/README.md) (Playwright), [`providers/cua-native/`](providers/cua-native/README.md) (TryCua CUA)
- **Release & quality automation**: [`ci/`](ci/)

## Documentation

- [Overview & quick start](../README.md)
- [Installation, pairing & upgrades](../INSTALL.md)
- [Validation & test suites](../VALIDATION.md)
- [Architecture & ownership boundaries](docs/architecture.md)
- [Architecture & scope index](docs/rust-core-rewrite/README.md)
- [Releasing procedure](docs/RELEASING.md)
