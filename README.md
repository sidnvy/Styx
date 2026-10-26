# Styx

Styx connects authorized native Linux, macOS and Windows devices to model-facing MCP tools through a Gateway, outbound Host connectors and one shared management Core. Exec, Browser and Computer Use are independent capabilities. Styx does not plan tasks or replay operations with unknown outcomes.

**Developer Preview; Stable release is NO-GO.** The only product source is [`src/`](src/README.md). The previous root implementation was retired in the repository migration; it remains available in Git history at `6fd902e`. There is no parallel legacy runtime or root plugin entrypoint.

- [Installation and first use](INSTALL.md)
- [Product boundaries](src/docs/product-boundaries.md)
- [Release convergence and remaining gates](src/docs/release-convergence.md)
- [Validation](VALIDATION.md)

Source-checkout runtime commands use the workspace Rust CLI and the Rust toolchain pinned in `rust-toolchain.toml`. Node.js 22 and the independent lockfiles under `src/` and its three providers remain necessary for the existing tooling, fixtures and interoperability checks.

```sh
npm --prefix src ci --ignore-scripts --no-audit --no-fund
npm run quality -- /absolute/fresh/evidence-directory
```

For development, `npm run styx -- ...` invokes `cargo run --locked --package styx -- ...`; `npm run gateway -- ...` invokes its `gateway run` subcommand. Cargo builds the current checkout as needed. These aliases never fall back to the JavaScript Core.

```sh
npm run styx -- --help
npm run styx -- status --native --state-dir /absolute/private/profile --json
npm run styx -- host run --state-dir /absolute/private/profile
npm run gateway -- --state-dir /absolute/private/profile
```

The runtime examples require an explicitly configured native profile and the matching manager intent. Use the Rust CLI help for supported commands, including `host`, `gateway`, `release`, `plan`, `apply`, `migrate`, `recover`, and Linux `service`. Old onboarding commands such as `create`, `advance` and `foreground` are not accepted by these aliases; fresh setup parity is still incomplete. Historical fixture and interoperability scripts remain available explicitly. Production installers and existing signed packages are unchanged by this source-checkout entrypoint switch.

Source migration does not rename deployed state, pairing identities, publisher pins, protocol identifiers or signed bundle members. Existing native packages retain their verified internal layout. Historical candidates and test receipts remain bound to their original SHA.
