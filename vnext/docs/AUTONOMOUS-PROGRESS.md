# Autonomous engineering progress

## Reconnaissance — 2026-10-19 Asia/Shanghai

Baseline: `212814388967cf748030c2315de9f3442e0b01c8`.
Initial isolated clone status: clean. Original checkout status: dirty (preserved).
Reviewed VNext README, architecture, acceptance, onboarding, per-user isolation,
enrollment, Linux managed Host, native service/build adapters and CI.

GitHub baseline CI: PASS for VNext contracts and legacy project CI.
VNext run: https://github.com/sidnvy/Styx/actions/runs/39143276897
These are historical upstream results, not results for this feature branch.

Original unpublished changes include Windows ACL checks, portable signed Node,
Windows timer recovery, Computer transport acquisition wait and a Windows GUI
acceptance script. They have NOT been silently incorporated or counted as tested.

## Milestone A implementation

Files: `vnext/package.json`, `vnext/package-lock.json`,
`vnext/ci/acceptance.mjs`, `vnext/host/test/acceptance-receipt.test.mjs`,
`.github/workflows/styx-vnext.yml`, `vnext/.gitignore`, and these tracking docs.

Fixed pinned MCP SDK 1.30.1 -> 1.32.1 (GHSA-6qxp-vccf-f47h) and Ajv
8.17.1 -> 8.20.0 (GHSA-2g4f-4pwh-qvx6). Full npm audit after update: PASS,
zero reported vulnerabilities; this is an advisory check, not a security proof.

New TAP receipts record per-suite passes, failures, cancellations and skips.
All-skipped or absent/malformed results cannot produce PASS. Native Exec,
GUI, physical Host, cold-install, signed distribution, ChatGPT and soak are
separate gates. CI uploads raw logs/receipts even on failure.

Execution environment: native Workstation/m600, Arch Linux x64,
kernel 7.1.5-arch1-2, Node v26.5.0; CI remains Node 22.
Sandbox-restricted first test attempt: FAIL, requiring native loopback/process
execution. Native baseline `npm run test:all`: PASS, including actual pinned
Codex executor tests. Post-update fixture receipts: PASS, 128 passed and
9 skipped out of 137 tests. The 9 skipped operations are not native evidence.
Native Cua 0.36.0 schema smoke: PASS, portable contract compatible;
GUI owned-window attempt: BLOCKED (`native_wayland_session_required`).
No graphical-session variables were manufactured and no permissions changed.

Pinned upstreams: Codex rust-v0.163.0, Cua 0.36.0, ws 8.22.0;
official archive SHA-256 checks passed for locally prepared Codex and Cua.
Complete dependency tree and audit are retained in this task's work directory.
Refreshed native Exec: PASS, 18 passed / zero skipped, including authenticated
MCP shell/PTY, outbound transport, disconnect isolation and envPolicy.
Feature CI must be recorded after completion.

Implementation commit: the commit introducing this record (`git log -- vnext/ci/acceptance.mjs`);
exact resulting SHA is recorded in the task output and PR.
No production endpoint, tunnel, installed Charon/Coder or existing user service
was changed. No physical native result from an older pilot is claimed as a
new acceptance result.

## Milestone B/E subset — native credential boundaries and Windows recovery

Baseline: `0f08b370a370f2dfcc0dd77101a4bd863251d1aa`.
Recovered the original unpublished private-file implementation into the separate
branch, added POSIX UID enforcement and Windows null-DACL refusal, and wired
Gateway/Host credential consumers and signed payload packaging. Added actual
signed-module import verification. Windows task now includes explicit
owner-scoped enable/disable and disables recovery before a deliberate stop.

Files: shared/private-file.mjs; Gateway cli/cua/runtime/outbound; Host connect,
build-host-release, windows-task; private-file/native-build/linux-build tests;
docs/native-private-state.md and progress tracking.

Linux fixture/protocol rerun: PASS, 132 passed / 9 skipped (141 total).
Actual pinned native Exec rerun: PASS, 18 passed / zero skipped.
Windows ACL tests: NOT RUN locally, queued for native Windows CI.
Real interactive Windows task recovery/GUI: BLOCKED in current Linux context.
This is a subset of B/E, not full native Windows acceptance. Original dirty
worktree is unchanged; portable signed Node and Computer lease wait changes
remain separate unintegrated work.

## Milestone E/F subset — authorization across asynchronous handshakes

Baseline: `65252490b47d07b17b4b0f05fc8d036df6f848aa`.
Changed gateway/runtime.mjs and gateway/cua.mjs plus registry/Cua tests.
Exec binding now rechecks target admission and generation after the handshake;
a revoked/replaced runtime is closed and discarded. Native Cua closes clients
when admission is revoked during its handshake. Closing a model owner fences
pending native Cua connections so an orphan cannot dispatch after session exit.
No dispatched GUI action is retried.

PASS: 16 targeted protocol/negative tests. Complete fixture/protocol rerun:
PASS, 136 passed / 9 skipped (145 total). Real Codex Exec rerun: PASS,
18 passed / zero skipped. These are fixture race and real executor results,
not physical cross-account or native GUI isolation evidence. Separate native
account adversarial tests and soak remain NOT RUN.

Foundation PR #27: upstream feature-branch CI PASS on Linux/macOS/Windows.
Native private-state PR #28: Windows ACL tests and portable contract CI PASS;
real interactive Task Scheduler recovery remains BLOCKED.

## Milestone F subset — bounded native Exec soak

Baseline: `d6b4ff2eabf2e4ff615f97db824f28db7e2a29eb`.
Files: host/exec-soak.mjs, host/test/exec-soak.test.mjs, docs/exec-soak.md.
PASS: option-boundary tests and actual two-second native Exec smoke, three
exact-output samples, isolated loopback Gateway/outbound Host/Codex 0.163.0.
Cleanup terminates only the spawned connector. Metrics are Gateway-only;
no Host-total memory/CPU claim is made. Runtime requires the fixed executable
hash, fresh private state and no operator-supplied shell commands.

A 24-hour run is being started in a separate task-owned state root. Its gate
remains NOT RUN until elapsed duration and receipt say PASS. This is not a
signed installed-service, reboot, GUI or full-platform soak. Those remain
independent NOT RUN gates; current GUI context remains BLOCKED.

## Integrated C/D/G subsets and distribution evidence

Integration worktree: `/home/sid/Documents/Codex/2026-10-19/files-pasted-by-the-user-styx/work/styx-vnext-integration`.
Branch `feat/vnext-rc-integration-20261019`; the original worktree now remains
immutable for the running soak at `dbce92dceaa24655fcd5d914bced785ea5eede29`.
Local integrated head before notice changes: `5fce30f`.

Merged locally from independent owned worktrees (no remote PR merged):
- Runtime distribution `75e6a39`, `1640180`: official checksum-pinned Node
  22.23.3, signed bootstrap/runtime and safe Windows offline-switch refusal.
  Actual Linux/macOS/Windows packaging CI PASS on run39145407393. Host counts:
  Linux29/32, macOS26/32, Windows20/32 passed; other tests explicitly skipped.
  All three OSes executed real official Node/Codex/Cua signed packaging and
  tamper checks. Python archive checks PASS 3/3 per OS.
- Device readiness `8cf9c9f`: passive explicit allowed-target status; socket
  connectivity does not claim native permissions/readiness/version. PR32 CI
  PASS including all three OS schema/Host tests and actual Linux Exec.
- macOS owner `cd34a5f`, `ab9f78b`, `3119e1b`, `456ed4d`: stable app.styx.host,
  native embedded Cua owner, exact upstream parent-liveness stdin contract,
  publisher signing/notarization pipeline and compile/liveness CI.
  Final macOS CI PASS on39145582975. Physical macOS arm64 27.0.1 own-/tmp
  compile, ownership, real Cua SIGKILL/EOF cleanup and unsigned app packaging
  PASS. LaunchServices reported parent_application/app.styx.host and matching
  owned parent PID. Read-only permissions reported host attribution with both
  Accessibility and Screen Recording FALSE. Exact app/daemon/socket teardown
  PASS. No TCC prompt, screenshot or GUI action on macOS. Developer ID and
  notarization BLOCKED (only Apple Development identity present); GUI BLOCKED
  due absent grants. Sanitized receipt retained with task outputs.

Linux native GUI re-evaluation: initial command context lacked Wayland, but
read-only native systemd user environment inspection found the actual logged-in
Hyprland session. Inheriting ONLY its display/runtime/DBus/compositor variables
resolved the environmental block. PASS: 7/7 native Cua outbound tests, zero
skipped; actual owned Zenity screenshot, three AX elements, observed click and
independent exit-code verification. No permissions or unrelated windows changed.

Distribution adds pinned upstream Cua MIT, Codex Apache-2.0 LICENSE/NOTICE and
Styx LICENSE, provenance hashes, signed Host inclusion and pre-signing app
notice inclusion. Real Linux signed runtime package test PASS after inclusion.
VNext npm CycloneDX1.5 SBOM generated (93 dependency components); full native
transitive crate/license/SBOM review remains NOT RUN. No full legal audit claim.

## Final E/F/D additions

Owner recovery source `30841f8` retires an exact device fingerprint/generation
before a new key/device identity, fresh invitation and independent approval.
Revocation tombstones persist before live effects; save failure does not
silently claim revocation. Negative tests cover wrong realm/identity, old
invitations/keys, live Exec+Computer disconnect and restart persistence.
PR35 corrected cross-platform macOS plan paths; latest native CI passed.

Health gate source `e9c9df1` verifies staged/previous signatures and unchanged
stable bootstrap/runtime, retains exact old active pointer on a failed bounded
local trusted health callback, and refuses concurrent/stale/late results.
It does NOT implement post-switch service restart rollback or offline runtime
replacement. PR34 actual native Linux/macOS/Windows health tests passed.

Original unpublished Computer reconnect wait is now integrated with additional
bounds/generation checks: up to five seconds for a newly authenticated native
worker before dispatch, immediate busy-slot refusal, no action retry/replay.
New targeted tests PASS (8 passed, 2 existing native tests explicitly skipped).

Native Linux managed pilot source `e06e24e`: PASS signed bundled Node/Codex/Cua
build/install, real loopback HTTPS/WSS with CA checks, systemd start/restart,
exact owned cgroup SIGKILL recovery (NRestarts=1), signed upgrade and rollback,
actual signed connector-generation and fresh-peer checks, owned Zenity
screenshot/3 AX elements/click/independent exit 0, uninstall and secret cleanup.
The initial observer race is retained as FAIL evidence, corrected before PASS.
No production services or the independent 24-hour soak were modified.
See docs/linux-managed-pilot.md and docs/evidence/ for exact sanitized receipts.
Cold-install trust and full-platform soak remain NOT RUN.
