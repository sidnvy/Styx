# Pinned native source inventory and license evidence

`../ci/native_inventory.py` inventories exact upstream source inputs without
executing Cargo, npm, crate build scripts or downloaded binaries. It requires
Python 3.11+ and the standard library. If available, curl provides one bounded
HTTP/1.1 fallback after repeated urllib transport errors; TLS verification is
never disabled. A fallback is an idempotent public GET, not code execution. `native-source-pins.json` records immutable
commit URLs, exact byte lengths and SHA-256 digests for the fixed releases:

| Source | Release | Immutable commit |
|---|---|---|
| Codex | rust-v0.163.0 | 83086188ae0614bd882818ff1aa23f3194962012 |
| Cua driver | cua-driver-rs-v0.36.0 | 6d6c734c127025fb39ad5d585a10382808b39dc1 |
| Node | v22.23.3 | 80dc632040e6bada37aac1220dde9c79581c9c22 |

The evidence includes the exact Cargo lockfiles and workspace manifests,
upstream license/NOTICE files, release workflows and available Linux legacy
cosign blob bundles. Bundle availability and hash checks do **not** constitute
signature or build-provenance verification; that gate remains NOT RUN. The
release workflow files describe available upstream build inputs, without proving
that a downloaded executable was built with any particular dependency/features.

From the repository root, generate a source-only report:

```
python3 src/ci/native_inventory.py --fetch \
  --cache /absolute/scratch/native-source-cache \
  --output /absolute/scratch/native-source-inventory
```

Network is opt-in. Existing output directories are refused. Every cached pinned
source is rehashed before parsing. The tool does not infer SPDX expressions
from freeform notices or assign a root project's license to its workspace/git
crates. It emits `inventory.json` and a CycloneDX 1.6 **source inventory** with
an incomplete composition and explicit binary-equivalence NOT RUN metadata.
Cargo dependency strings are preserved and deterministic edges are resolved
within each exact source lock using name, optional version and optional source.
Ambiguous/missing identities remain explicit diagnostics; no edge is guessed.
The actual locks yield 9170 edges and zero unresolved edges. This remains a
source graph, without feature/target filtering or binary-inclusion proof. Node
is included as a source root; its 43 top-level license notice headings are
listed separately in `inventory.json`, without invented library versions.

For bounded real license enrichment, the CI uses:

```
python3 src/ci/native_inventory.py --fetch \
  --cache /absolute/scratch/native-source-cache \
  --output /absolute/scratch/native-source-inventory-with-licenses \
  --metadata-limit 12 \
  --crate serde@1.0.228 --crate ring@0.17.14 --crate tokio@1.52.3
```

`--metadata-limit` selects the first N distinct crates.io lock identities in
name/version/checksum order (default 0, maximum 2000). Registry results must
match name, exact version and locked archive checksum. Their license fields
remain registry declarations: a matching archive checksum does not authenticate
that metadata field. By default the tool stops on missing/mismatched selected evidence or
registry rate limiting; it never silently turns a failed fetch into completeness.
Requests are globally paced at no more than two starts per second, with one
worker by default and an explicit --workers limit of 1–4. A 1596-query full
sweep is supported using --metadata-limit 2000. --allow-incomplete-metadata
continues after bounded network failures, records every missing record, marks
the metadata gate FAIL and returns exit2; it never suppresses integrity failures
or429. Queued tasks stop promptly on integrity/rate-limit failures. Larger
metadata runs do not establish system-library coverage or binary equivalence.

Each explicit `--crate name@version` instead downloads the exact locked source
archive, verifies SHA-256, and reads its regular Cargo.toml plus top-level
LICENSE/COPYING/NOTICE and any safe declared license-file. No general archive
extraction occurs; notice bytes are saved by hash under `notices/`. Symlinks,
unsafe declared paths, missing/duplicate manifests and checksum mismatches fail
closed. This authenticates the declaration and selected notices against that
source archive, without asserting legal sufficiency or shipped binary inclusion.

For exact offline replay, retain the cache and output's
`registry-metadata-pins.json`, omit `--fetch`, and add:

```
--registry-pins /absolute/saved/registry-metadata-pins.json
```

Use the same metadata limit and crate selections. The snapshot pins raw registry
metadata bytes, including fields not used by this tool; changes fail closed.
Registry metadata can change over time, so live runs without a supplied snapshot
are new observations. Source pins and offline snapshot replay are deterministic.
CI retains the source/metadata/archive cache and all output under the existing
acceptance artifact. Deterministic tests require no network.

Observed bounded sample results (also in `native-source-sample.json`):

| Scope | Exact count |
|---|---:|
| Codex lock entries | 1474 (1296 registry, 18 git, 160 workspace) |
| Cua lock entries | 642 (625 registry, 0 git, 17 workspace) |
| Combined lock entries | 2116 |
| Distinct crates.io name/version/archive-checksum identities | 1596 |
| Registry metadata selected | 12 |
| Checksum-verified source archives | 3 |
| Exact workspace/Git manifest license declarations | 35 |
| Codex workspace lock/manifest version mismatches observed | 160 |
| Lock entries without exact-identity license expression after this sample | 2060 |

All 17 Cua workspace licenses resolve from exact inherited/explicit manifests.
All 18 locked Git packages resolve from exact commit manifests. The final
runfiles manifest was fetched from its immutable commit over verified HTTPS
after earlier transport failures; those failures remain recorded separately. Exact Codex source manifests inherit version
0.163.0 while all 160 workspace lock identities record 0.0.0. Their actual source
license declarations are exposed as version-mismatch observations, not silently
assigned to a different locked identity. No root license is guessed.

The bounded source-archive sample preserved serde's MIT/Apache notices, ring's LICENSE,
LICENSE-BoringSSL and LICENSE-other-bits, and Tokio's LICENSE. The declared
expressions are respectively `MIT OR Apache-2.0`, `Apache-2.0 AND ISC`, and `MIT`.
Node's source LICENSE SHA-256 is
`c738ae413cf561f174e34f6961f8ca458aae2369a73640dda6234c629b98bcc4`;
it matched the LICENSE extracted from the checksum-verified official Linux x64
Node 22.23.3 distribution during local evidence collection. This is a notice-file
match, not a full Node binary dependency attestation.

Native license completeness remains BLOCKED. Still required are unresolved
registry/git/workspace licenses/notices, native/system libraries, actual release
features/targets, cryptographic upstream provenance verification and a reviewed
mapping from source materials to shipped executable contents. The root legacy
npm inventory and VNext npm SBOM are separate graphs and do not fill these gaps.
