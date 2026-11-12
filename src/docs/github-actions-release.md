# GitHub Actions releases

`.github/workflows/styx-release.yml` builds and packages the existing Rust Runtime
and native Apps. It never installs a product, changes a device profile or creates a
ChatGPT connection. The fixed Gateway/Host topology remains a separate user setup.

## Pipeline

1. A Debian 12 integration gate runs once. At the same time, three native dependency
   jobs fetch pinned public executors, install locked Browser dependencies and build
   the existing Cua source/patch on Linux, Windows and macOS.
2. After the gate, three native Core builds run in parallel using their Cargo caches.
3. A Linux signing job consumes this run's original build receipts and worker outputs,
   signs the worker manifests and full Runtime payloads with the fixed publisher.
4. Windows Inno and macOS App/DMG packaging run in parallel without rebuilding Rust.
5. The final job requires all four assets, generates checksums, uploads them to a draft,
   and publishes only after every upload succeeds. Failure cannot expose half a release.

## Credentials

The owner authorized GitHub Actions signing on 2026-11-13. The `sidnvy/Styx` GitHub
`release` environment contains these encrypted Secrets and permits `develop` and
`v*` tags only:

| Secret | Value |
| --- | --- |
| `STYX_PUBLISHER_PRIVATE_KEY_PEM` | Existing Ed25519 private PEM matching `src/release-publisher.pub` |
| `STYX_MACOS_CERTIFICATE_P12_BASE64` | New exportable macOS release certificate/private key in an encrypted P12 |
| `STYX_MACOS_CERTIFICATE_PASSWORD` | Password protecting that P12 |

The publisher PEM and both P12 Secrets were actually configured. The previous Mac
key could not be exported; the owner explicitly chose a new exportable identity.
Its public fingerprints are recorded in `src/host/macos/release-signing-identity.json`.
Original local keys and the installed App were retained. The Ed25519 publisher pin
was not rotated. No self-hosted runner was registered.

Credentials are materialized only under `RUNNER_TEMP`; they are excluded from every
cache and artifact and removed during cleanup. Only the sealing job uses the
publisher key. Only native Mac signing steps use the P12. On disposable GitHub-hosted
Mac runners, the exact self-signed certificate receives temporary codeSign-only trust,
removed during cleanup. Owner devices receive no trust change. A P12 import alone
cannot make a self-signed identity valid for `codesign`.

GitHub can decrypt Secrets in authorized jobs; uploading them deliberately extends
custody to GitHub. This is the owner's scoped exception to the earlier local-only
custody rule. Never put a private key in source, packages, logs, profiles or caches.

## Public dependencies and caches

There is no historical private dependency bundle, owner upload or build-inputs Release.
CI obtains dependencies directly from their public upstreams:

| Input | Source of version/checksum |
| --- | --- |
| Rust 1.97.1 / workspace crates | `rust-toolchain.toml`, `Cargo.lock` |
| Codex `rust-v0.163.0` | `src/host/prepare-codex.py` |
| Node 22.23.3 | `src/host/prepare-node.py` |
| Browser worker packages | `src/providers/browser-worker/package-lock.json` |
| Secure MCP tunnel-client 0.0.17 | `src/ci/release-tunnel.json` |
| Cua 0.36.0 fixed source commit/patch | `src/providers/cua-native/source.json`, existing baseline patch and Windows DPI fragment |
| Portable Inno Setup | `src/host/windows/platform-update/toolchain.json` |

Public archives use content-addressed/checksum-verified caches. npm uses its normal
integrity-checked cache and `npm ci --ignore-scripts`. Cua source and the existing
bounded patches are checked before native compilation; no new desktop functions or
permissions are added by the release pipeline. Fresh Mac Codex/Node/Tunnel copies are
platform-signed before their publisher manifests are created, with provenance retaining
the original download digest. Sealed payload bytes are never signed again.

Native Core caches keep explicit target, release profile and existing LTO/codegen
settings. `--reuse-workspace-cache` preserves native Git-checkout outputs; archive
source production retains its original correctness cleanup. Cua has a separate
persistent target cache keyed by platform/toolchain/source/patch. No whole-cache clean
runs. Rust registry caches store compressed downloads/index and git objects, avoiding
redundant expanded registry trees. Each producer uses allocated CPU jobs unless the
owner explicitly overrides `CARGO_BUILD_JOBS`. Swift modules are cached against the
actual compiler/SDK and source generation. Packaging does not recompile Rust.

## Run

Pushing release wiring/producer changes to `develop` automatically builds without
publishing a product Release. Once the workflow exists on the repository default
branch, `workflow_dispatch` with `publish=false` offers the same dry run on a selected
ref. Download the `complete-release` Actions artifact. No product tag is created.

For release, update the workspace version and workspace lock entries, commit the
intended source, then push its exact `v<version>` tag. The version must match Cargo.
A version containing `-` produces a prerelease; a plain semantic version produces a
normal release. Manual `publish=true` also requires the exact existing tag. The
workflow does not invent a tag, alter source versions or overwrite an existing release.
The native App build number is 1142 (the last installed preview) plus the Actions run
number, so new artifacts advance rather than resetting to build 1. Values over 9999 need an
explicit policy update rather than silently truncating the sequence.

Assets:

- `Styx-<version>-windows-x64.exe`: normal Styx product identity/default path, original Inno producer.
- `Styx-<version>-macos-arm64.dmg`: native App and new fixed local release certificate.
- `Styx-<version>-linux-x64.tar.gz`: full signed Runtime, public pin and normal setup README.
- `Styx-<version>-gateway-debian12-x64.tar.gz`: signed Gateway/tunnel Runtime, public pin and setup README.
- `SHA256SUMS` and `styx-publisher.pub`.

Linux users extract to a permanent owner-private location and run
`./payload/bin/styx setup`. Choose Gateway only on moedeu-apps; other computers choose
Join. No profile, pairing, login state or pre-created device identity is packaged.

Windows outer installers currently have no Authenticode signature. The Mac certificate
is local, not Developer ID/notarized. Ed25519 authenticates the Runtime payload; it does
not establish OS publisher trust. Keep these facts in release notes. CI success proves
build/package checks, not new GUI/account acceptance or formal Stable approval. Reuse
unaffected functional evidence; a new Mac signer still needs matching App/Core native
acceptance before claiming that installed version is qualified.
