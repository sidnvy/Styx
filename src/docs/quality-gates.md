# Local development and release checks

Owner policy (2026-11-10): improve and run tests locally. GitHub Actions is not a
development dependency. Later CI should call these same verified commands; this
work does not change workflows, add runners or publish. Local tests, packaging
and real-device acceptance have different boundaries. A PASS names what ran.

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

Signing keys and real account secrets stay on their authorized devices. Future
hosted CI can reuse these commands with synthetic inputs; ordinary CI must not
acquire personal profiles or signing private keys.
