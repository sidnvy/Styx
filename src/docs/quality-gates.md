# Local development and release checks

Develop and reproduce locally with the existing toolchain and cache. Pull requests
and main run the same `src/ci/rust-quality.py` gate in `.github/workflows/styx.yml`;
the release workflow reuses it. CI is an integration check, not a prerequisite for
local development. Local tests, packaging and real-device acceptance have different
boundaries. A PASS names what ran.

## What the Rust checks prove

| Check | Scope |
| --- | --- |
| `cargo fmt --all -- --check` | The source follows the pinned formatter. |
| `cargo check --workspace --all-targets` | Libraries, binaries, tests and examples compile for the selected platform. |
| `cargo clippy --workspace --all-targets -- -D warnings` | Compiler checks plus enabled Rust/Clippy lints; warnings fail the gate. The integration gate already compiles through Clippy, so it needs no duplicate check stage. |
| `cargo test --workspace` | Selected non-ignored tests actually run. Ignored and platform-gated cases require their own execution. |

All four crates inherit the workspace lint policy (`unsafe_code = deny`,
`clippy::all = warn`). Platform-specific unsafe bridges have scoped exceptions.
`--all-targets` does not select every operating system. Native-only consumers still
need the affected Mac/Windows build and scenario. These checks do not prove desktop
permissions, browser interaction or an external write, and are not a dependency
vulnerability audit. Do not enable every pedantic/nursery lint to inflate a score.

## Daily regression

Use the pinned Rust toolchain and existing Cargo cache. Do not clean or create
a cache per task. The thin local entry defaults to 8 Cargo jobs on Linux for
that invocation, preserving an explicit existing setting. Libtest is serial
because descriptor-owning fixtures must not overlap accidentally.

Check the affected crate and its changed scenario or package regression:

```sh
cargo check -p styx-core --locked --offline
npm run test:unit -- --package styx-core
npm run test:contracts
```

These are choices by impact, not three mandatory layers after every edit.
`test:unit` accepts repeated `--package` arguments and runs their non-ignored
tests. Include affected consumers of shared contracts; compiling a dependency
does not execute its tests. Unknown packages, toolchain mismatch, command
failure and zero passed tests fail the entry.

`test:contracts` covers public Computer schema projection/equivalence plus the
actual fixed native rejection client's legal TLS request and local negative
admission controls. Synthetic test keys and loopback peers are used, never real
profiles. This catches a missing client route early; it does not establish a
persisted Core decision, account connector, OS permission or desktop effect.

```sh
python3 -I -B src/ci/local-tests.py --dry-run contracts
python3 -I -B -m unittest discover -s src/ci/test -p test_local_tests.py
```

Dry-run says NOT RUN, never PASS. The Python checks cover subprocess failure,
version mismatch, invalid selection, missing inputs and zero-test false passes.

For JS/native-shell/packaging changes use the appropriate existing suite in
`src/package.json`, or `npm run test:js`. Root `npm test` and `src` `test:all`
remain JS-only for compatibility: neither means Rust or device acceptance ran.

## Integration checkpoint

Use existing `src/ci/rust-quality.py` once at a shared integration/candidate
checkpoint, not after each helper or platform-only edit. It includes pinned
dependency/toolchain checks, fmt, clippy, workspace regression, ignored-test
inventory and controlled HTTP boundaries.

Replace these example paths with a new external evidence directory and the
already-owned external Cargo cache recorded in current integration receipts:

```sh
npm run test:integration -- --evidence /absolute/new/evidence --target-dir /absolute/existing/cargo-cache
```

This delegates to the same gate as `npm run quality -- --evidence ...`, not a
second implementation. See `rust-quality.py --help` for explicit synthetic PKI,
Node, Codex and Browser inputs. Full native-client enrollment and paired
TLS/MCP/WSS/executor scenarios need their declared inputs/flags. An ignored-test
inventory is not execution. Missing/unrequested native cases remain NOT_RUN.

The full persisted rejection journey must use the actual App client, including
its route admission: a generic HTTP test previously hid a broken client. Keep
that integration regression alongside the fast transport admission regression.

## Browser and Computer Use effects

Schema coverage, mocked dispatch and an ignored-test inventory are not evidence of
a real input or write. Keep these existing layers distinct:

| Existing test | What actually runs |
| --- | --- |
| Browser provider contracts and ordinary Rust admission tests | Request shape, policy and routing; some deliberately spawn no browser. |
| `--browser-host --browser-references` quality scenarios | Actual Node/Chromium Host sessions, fresh references, navigation/tabs, text input, click, independent HTTP effects, unknown outcomes and owned cleanup. Require explicit Node, Codex and browser inputs. |
| `browser_sessions_survive_chat_close_and_transfer_requires_sockets` | Actual loopback TLS/MCP/WSS Gateway and Host with Chromium. A fresh snapshot supplies the textbox for `browser_type`; after session transfer, another snapshot supplies the submit button for `browser_click`. A separate snapshot and server-side effect ledger must agree on the saved nonce and exactly one write. |
| Computer contract/FakeDriver/transport tests | Exact target binding, schema, dispatch and refusal behavior. They do not establish an OS effect. |
| Manual native owned GUI fixture through public tools | Observe the test field, set its value, independently read the same value, then click the observed button and inspect the fixture's own facts. Report the running installed Core identity separately from the source revision. |

The paired Browser test additionally retains its disconnect, takeover, stale-owner,
stale-reference, busy-operation and capability lifecycle checks. Do not replace
normal input controls with page-side JavaScript assignment when claiming those
controls work. JavaScript remains useful for explicit busy/unknown fault injection.
The tests above do not claim that every exposed Browser tool, site, upload,
download or dialog has been exercised.

The paired Browser case is an explicit exact ignored test. Select it with
`cargo test -p styx-runtime --locked --offline enrollment::service::tests::paired_journey::browser_sessions_survive_chat_close_and_transfer_requires_sockets -- --ignored --exact --nocapture`
and its declared test-only Node, Codex, Chromium, TLS and output inputs. The
quality flag `--paired-host` selects the separate paired Codex enrollment journey;
it does not run this Browser case. `owned-gui-acceptance.py` retains a narrower
direct-Cua socket screenshot/tree/click check; the public-tool text-write/readback
sequence above is manual device verification.

Run the selected real case when its boundary changes; use the existing quality
flags and declared inputs for an integration checkpoint. Ordinary PR quality
retains explicit `NOT_RUN` values for optional cases. A green PR is not a fresh
installation or ChatGPT account acceptance. Reuse unaffected native evidence and
name the remaining gaps instead of promoting historical effects to a new build.

## Native checks and frozen candidates

| Change | Local response |
| --- | --- |
| Rust domain or shared contract | Affected crate/consumer and actual cross-layer scenario; full quality at the integration checkpoint. |
| Swift/C# or GUI state | Original platform owner runs existing check-only compilation and affected native scenario; no release producer per typecheck. |
| Package/resource/integrity/signing | Affected package/native verification; new candidate only when executable/package inputs change. |
| Docs or management alias | Syntax/links and affected entry behavior; no installer rebuild or device journey for a doc edit. |

Frozen candidates additionally require exact artifacts, native permission,
GUI identity/pairing, independent effects, negative controls and normal
exit/recovery on relevant platform/role paths. Counts, mocks, synthetic windows
and package verification cannot replace these checks. Preserve FAIL/UNKNOWN;
never replay unknown actions or relabel them using later success.

Reuse exact-artifact evidence; changes require impact-based verification and a
consistent final candidate, not silent version mixing. The current role matrix
and sequence are in [the delivery plan](rust-core-rewrite/END-TO-END-DELIVERY-PLAN.md).
Keep one short result per platform role plus the aggregate matrix. A device bug
gets its smallest real-boundary local regression; the device then closes the
OS/account part, without multiplying full suites.

Signing keys and real account secrets stay on their authorized devices. Hosted
CI reuses these commands with synthetic inputs; ordinary CI must not acquire
personal profiles or signing private keys.

## Hub pairing recovery references

The ordinary unit suite covers exact target/ingress checks, expired-request
preservation, rollback refusal and protection of already approved credentials.
The following local integration entry point additionally uses a real signed
current native-runtime payload, strict loopback TLS and a current explicitly built CLI:

```sh
CARGO_BUILD_JOBS=8 cargo build --locked --offline -p styx --timings
npm run test:hub-recovery -- \
  --cli /absolute/current/debug/styx \
  --payload /absolute/signed-runtime/payload \
  --publisher /absolute/public-publisher.pem \
  --publisher-pin EXTERNALLY_TRUSTED_64_LOWERCASE_HEX_DIGITS
```

It verifies the original binding refusal after restart, explicit retirement and
new identity in the same Hub root, and the expired path's durable clock floor
with unchanged pending records. Each reference owns a fresh temporary fixture;
it opens no Tunnel or persistent service. These are local references, not
account effects, device acceptance or a release gate. Missing inputs, failed
commands and zero selected tests fail rather than count as a pass.

For the existing TLS quality scenarios, generate new **test-only** certificates
for each fresh quality run; do not overwrite or reuse expired evidence:

```sh
python3 src/ci/test-tls-fixtures.py --output /absolute/new/private-test-pki
```

Pass this directory as the quality runner's `--tls-fixtures`. The generator
requires a new directory, verifies both chains and cross-CA refusals, records
OpenSSL and certificate inputs, and keeps generated test keys private. It does
not read publisher, installed Gateway or device signing keys.
