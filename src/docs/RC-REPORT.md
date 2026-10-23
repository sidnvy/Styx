# Styx VNext consolidated engineering assessment

> Historical development record. Its checkout paths, build versions and acceptance claims apply only to the recorded revision. Current source and release gates are described in [release convergence](release-convergence.md).

Date: 2026-10-19 Asia/Shanghai. RC gate: BLOCKED. Release decision: NO-GO.

## Repository recovery and source

Repository: https://github.com/sidnvy/Styx
Original native Workstation/m600 development checkout:
`/tmp/styx-cua-session-doc-audit-20261018`, HEAD
`b51cfb06a8786c021ba20e2da441d117cd176536`, with13 dirty/untracked entries
preserved without reset, overwrite or clean. Another older pilot checkout is
`/tmp/styx-vnext-crosshost-gateway-20261018`.

Selected newest legitimate baseline:
`212814388967cf748030c2315de9f3442e0b01c8`, exactly two commits after requested
reference `1736a10ab9922c7d95f39f8f5d9dcba754a301aa`.

Persistent integration worktree:
`/home/sid/Documents/Codex/2026-10-19/files-pasted-by-the-user-styx/work/styx-vnext-integration`.
Branch: `feat/vnext-rc-integration-20261019`; current verified implementation SHA: `17fd0e0683431bd1c557a06e2fdb2356e9aa1385`.
Its independent Git common directory is under`work/styx-vnext/.git`; retain
that clone with its worktrees. Review:https://github.com/sidnvy/Styx/pull/37
All PRs remain drafts; none merged or promoted.

## Implemented changes

- Patched dependency advisories and pinned SDK/Ajv; explicit TAP receipts with
  failures/skips, raw evidence artifacts, advisory check and npm SBOM in CI.
- Native UID/SID/NTFS private files/directories BEFORE enrollment/state writes;
  no silent broad-directory repair. Signed stable bootstrap includes its helper.
- Signed bundled Node 22.23.3, native runtime provenance and notices, service
  runtime hash selection, Windows offline-runtime-change refusal and explicit
  owner task recovery/enable/disable controls.
- Stable native Styx.app owner, upstream embedded Cua parent-liveness stdin,
  private per-user endpoint, publisher signing/notarization pipeline and real
  native app-parent attribution/lifetime evidence without TCC grants.
- Passive explicit allowed-device status; no connection/native mutation and no
  false readiness/version/permission claim. Separate owner-admin recovery
  persists exact identity retirement before new-key/new-ID pairing approval.
- Admission rechecks across async handshakes and native Cua owner-close fences;
  bounded pre-dispatch worker reconnect without retrying uncertain actions.
- Bounded signed preactivation health gate retains exact previous pointer on
  rejection/timeout and rejects concurrent/stale/bootstrap-incompatible state.
- Fixed a real lost-stdout bug: upstream process exit precedes output EOF;
  wait for exited+closed+empty cursor page. Failing-before/passing-after raw
  native evidence and deterministic UTF-8/late-output tests are retained.
- Complete signed Host payload now contains onboarding/Doctor/native service
  helper entrypoints, with actual module resolution tested from the product.

## Continued device-independent work

Doctor refuses runtime probes after invalid signed selection or private credential
validation. Launch, direct CLI, native service setup and publisher signing-key
consumers enforce native owner/private permissions before reading executable
paths or creating bundles. Windows checks actual DACLs; bounded synchronous
batching reduces PowerShell starts without caching permissions across callbacks.

The signed Host now ships a durable offline service-update transaction: verify
both releases, inhibit service restart, switch signed bootstrap/runtime, observe
health, and roll back exactly once on a known rejection. Uncertain callbacks
retain a private recovery journal and exclusive lock; explicit recovery requires
observed stopped/restart-inhibited state and never auto-replays service actions.
Real Linux evidence verifies official Node22.23.3 ->22.23.2 test-only replacement,
actual mapped executable versions, controlled health-rejection rollback and
uncertain recovery. Production release building still pins22.23.3. The injected
rejection follows a successful native Exec call; it is not evidence of a broken
upstream runtime. See linux-managed-update-pilot.md and its strict receipt.

Native source inventory pins exact upstream commits and Cargo files, resolves
2116 lock entries/9170 edges without ambiguity, and records all18 Git package
license declarations. A paced registry metadata sweep supplements the bounded
CI sample. Source lock graphs include dev/optional/all-target dependencies;
these are not claims about exact shipped binary composition or complete legal
review. See ../licenses/NATIVE-SOURCE-INVENTORY.md for explicit remaining gates.

## Verification and practical boundaries

PASS:213 fixture/protocol/Host tests,201 passed/12 explicitly skipped on native
Linux (clean source17fd0e0, Node22.23.3); real native Exec19/19 on the same source; top-level dependency audit zero
reported vulnerabilities; npm CycloneDX 1.5 SBOM with 93 components. CI platform
fixtures and actual binary packaging/ACL tests are recorded separately.

PASS:current integrated56458aa installed Linux signed Host pilot using verified
Node 22.23.3/Codex 0.163.0/Cua 0.36.0, real CA-checked HTTPS/WSS, systemd start,
controlled restart, own-cgroup SIGKILL recovery (NRestarts1), signed upgrade and
rollback, actual signed connector/fresh native peers, exact owned Zenity
screenshot+3AX elements+observed click+independent exit0, uninstall and secret
cleanup. This is an existing-device ephemeral-publisher pilot, not cold install.

PASS:native macOS arm64 27.0.1 scratch app compile, actual Cua daemon cleanup
on owner SIGKILL/EOF, LaunchServices parent app identity and read-only host
permission attribution. AX and Screen Recording were FALSE. No macOS capture,
GUI action, permission prompt or unrelated app/service mutation occurred.
Developer ID signing/notarization and signed GUI acceptance remain BLOCKED.

PASS:actual Linux/macOS/Windows official runtime package CI, Windows native
ACL/storage negative checks and Mac compile/liveness CI on focused branches.
The latest integration CI is pending at this documentation snapshot; its actual
completed result and observed head belong in the task output/PR, not inferred
from sibling branch success.

## Soak and remaining release gates

The old baseline component soak was stopped/interrupted after 1675 seconds,
with its receipt preserved. The fixed source `fb7f0aae9b4f2bb15c71a0f904f2b27000159b2f` is frozen in
`work/styx-vnext-soak-final` and runs a fresh 24h Exec component soak under
Node 22.23.3. State:`work/soak-linux-final-24h/receipt.json`; running status is
NOT RUN until actual completion. It does not prove installed-service/GUI soak.

A separate frozen17fd0e0 installed-service/native Exec24h run started at
2026-10-19 01:59:37 Asia/Shanghai. State:
`work/soak-managed-service-24h/managed-soak.json`; owned unit:
`styx-rc20261019-owned-soak24h.service`. It records service identity/restart count,
real Exec roundtrips and process/cgroup resources. Short completion and graceful
abort/cleanup tests passed; the24h gate remains NOT RUN while active. Even its
completion would not establish full GUI/session or per-platform stability.

Physical Windows lifecycle/GUI, macOS Developer ID/notary/TCC, clean-device
independent installation and durable publisher trust, distinct-account native
isolation, physical Windows/macOS post-switch recovery and offline runtime upgrades, complete native
transitive SBOM/license review, actual ChatGPT account authorization and full
per-platform 24h soak are still outstanding. See RELEASE-BLOCKERS.md and
SUPPORTED-PLATFORMS.md. These limits prevent RC approval.

No production MCP endpoint, tunnel, installed Charon/Coder, unrelated user
application or production service has been replaced, migrated or removed.
