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
