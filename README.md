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

`npm run build:checked -- ...` now invokes the official native runtime packager directly: `python3 src/tools/release/build-native-runtime.py`. It consumes an already built Rust binary and its original passing build receipt, the exact clean source revision, target, version, externally trusted publisher pin, and any selected signed worker closure. It performs the existing input and signature checks; it does not compile the CLI or install a profile.

```sh
npm run build:checked -- --help
npm run build:checked -- \
  --binary /absolute/native-build/styx \
  --build-receipt /absolute/native-build/receipt.json \
  --output /absolute/fresh/native-runtime \
  --source-revision FULL_SOURCE_SHA --target x86_64-unknown-linux-gnu \
  --version CANDIDATE_VERSION --expected-publisher ORIGINAL_PUBLIC_PIN \
  --publisher-file /absolute/original-publisher.pem --prepare-signing \
  --worker-release /absolute/signed-worker-release \
  --worker-publisher-file /absolute/original-worker-publisher.pem \
  --worker-kind codex_exec
```

Replace the placeholders with the exact reviewed inputs. This example prepares an unsigned manifest for the producer's existing detached-signature flow; it is not a signed delivery. The completed output is a native runtime candidate, not an App, installer, or proof of fresh setup parity. App wrapping and platform signing remain separate steps. The old Node-Core preview builder is available only through explicit `npm run build:legacy:checked -- ...` for historical fixtures and interoperability; there is no fallback from the native build command.

Source migration does not rename deployed state, pairing identities, publisher pins, protocol identifiers or signed bundle members. Existing native packages retain their verified internal layout. Historical candidates and test receipts remain bound to their original SHA.
