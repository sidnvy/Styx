# Autonomous engineering progress

> Historical development record. Its checkout paths, build versions and acceptance claims apply only to the recorded revision. Current source and release gates are described in [release convergence](release-convergence.md).

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

Files: `src/package.json`, `src/package-lock.json`,
`src/ci/acceptance.mjs`, `src/host/test/acceptance-receipt.test.mjs`,
`.github/workflows/styx.yml`, `src/.gitignore`, and these tracking docs.

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

Implementation commit: the commit introducing this record (`git log -- src/ci/acceptance.mjs`);
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

## Final correctness/security closure and native rerun

Implementation code SHA:`fb7f0aae9b4f2bb15c71a0f904f2b27000159b2f`. Output-drain sourcec8070c0 (integrated343d1e3)
reproduced true missing stdout with official binary: exited=true,closed=false,
empty page can precede late output. Fix waits for EOF; deterministic regression
failed before/fixed after, real native19/19 and both push/PR CI PASS. Raw benign
before/after transcripts are committed; original failed CI is retained.

Native storage source2668cf8 (integrated56458aa), test followup1d00701:
current owner UID/SID and actual private DACL validation precede secret writes.
New leaf directories only receive protected ACLs; existing broad/foreign/
symlink/junction state is refused. Stable signed helper is included and health
hash checks cover it. Windows planner default now matches StyxPilot-Host.
All six new actual Windows storage tests passed; Mac symlink fixture was
corrected with realpath. Test-only CAS async waits now observe bounded RPC
completion rather than fixed sleeps; no experiment runtime change.

Final integrated Linux fixture/protocol/Host receipt56458aa:PASS182 tests,
171 passed,11 skipped; native ExecPASS19/19. Fresh integrated managed Linux
pilot56458aa repeats all10 scoped real gates PASS, including GUI and cleanup.
Standalone signed package imports all onboarding/Doctor/service helpers.

Soak rollover: baseline dbce92d run stopped with BLOCKED/interrupted after1675s
and its test credentials removed. Fresh immutable`fb7f0aae9b4f2bb15c71a0f904f2b27000159b2f` run started
2026-10-19 00:58:29 Asia/Shanghai under verified Node22.23.3, PID1559314.
Completion NOT RUN until actual elapsed24h and successful receipt. No production
service or unrelated process was stopped. Final documentation-only revision/CI
are recorded in the task output and PR37.

## Exact focused-milestone source commits

These are implementation/review source commits; integration uses equivalent
cherry-picked commits. The RC itself remains BLOCKED.

| Scope | Baseline SHA | Final source SHA |
| --- | --- | --- |
| A foundation | `212814388967cf748030c2315de9f3442e0b01c8` | `0f08b370a370f2dfcc0dd77101a4bd863251d1aa` |
| B/E native private files | `0f08b370a370f2dfcc0dd77101a4bd863251d1aa` | `65252490b47d07b17b4b0f05fc8d036df6f848aa` |
| C native Mac owner | `0f08b370a370f2dfcc0dd77101a4bd863251d1aa` | `456ed4d22c2963e6109be36716efff084c8d507c` |
| D bundled runtime | `65252490b47d07b17b4b0f05fc8d036df6f848aa` | `1640180cb9c6bf507e97fca355e1f8aac2342e82` |
| E/F admission fencing | `65252490b47d07b17b4b0f05fc8d036df6f848aa` | `d6b4ff2eabf2e4ff615f97db824f28db7e2a29eb` |
| F component soak harness | `d6b4ff2eabf2e4ff615f97db824f28db7e2a29eb` | `dbce92dceaa24655fcd5d914bced785ea5eede29` |
| G passive status | `65252490b47d07b17b4b0f05fc8d036df6f848aa` | `8cf9c9f3f1b1429a53d1f3a5ef6ae918f91ac5d1` |
| D/E owner recovery | `5fce30f4cf44ee964ff450a3c8d6d6cc85bbaf1b` | `383ebbd779f747c736873550a0518f2080dcb1bb` |
| F preactivation health | `5fce30f4cf44ee964ff450a3c8d6d6cc85bbaf1b` | `93f67fe5c6909c8848ef1610cafa22a4c805b6b0` |
| D/E native private storage | `0bb1f6cdc5b5d72a62a954a92cd0e5c144eafb51` | `1d00701d096aca5457a1d9f6055a2c284da77d21` |
| F output EOF correctness | `0bb1f6cdc5b5d72a62a954a92cd0e5c144eafb51` | `c8070c0271beaa0f5935c51f5fb14566cd2acbd3` |
| D/F native Linux managed pilot | `fe3f3e94f9e82735cd46252c3af4e303ff0d0f39` | `a78279aed46e358cb8fe49331157f97b39241166` |

## Final Windows cold-start timeout correction

The final documentation-head push run 39147772569 failed enrollment directory
creation after 7056 ms, while the same-head PR run 39147776400 passed all native
Windows checks. The ACL subprocess had a 7000 ms deadline. Increase that bounded
deadline to 30000 ms for loaded Windows PowerShell startup and retain fail-closed
behavior with explicit timeout errors. No retry, ACL relaxation or skipped native
test is introduced. Preserve the original failure; replacement CI must be read
against its actual new head before any PASS claim. The existing frozen soak is
evidence only for its recorded Linux implementation snapshot.

## Continued independent work: Doctor trust boundary

Baseline: `4e5d0f33d339f15ae1367240d572de8bbc391e37`. Doctor now stops
all runtime version probes if selected signed-install validation or native
credential privacy fails. It reuses the UID/SID/NTFS checker used by the Host
connector. Previously invalid signed selection could fall back to raw enrollment
binary paths, and Doctor did not enforce Windows DACL/native owner checks.
Files: host/doctor.mjs; host/test/doctor-{signed,private}.test.mjs.
Native Linux Node22.23.3 focused tests: 6 passed, zero skipped; includes an
executable marker proving no fallback program runs after signed payload damage.
Windows/macOS execution of the new cases remains dependent on subsequent CI.
Physical device, signed GUI and account integration gates are unchanged.
Final commit is the commit containing this entry; final consolidated receipt
will record its full SHA and successor integration revision.

## Continued independent work: private launch configuration

Baseline Doctor commit: `f9d2f75`. Stable launch, direct Host/Doctor file CLI and
Linux/macOS service setup now require native-owned private Host configuration,
using the existing UID/SID/DACL implementation. Windows task setup checks its
setup and Host config owner/DACL before reading executable paths or registering
a task; it rejects reparse points and null/broad DACLs. Caller-approved stdin
configuration from the signed launcher retains its existing pipe boundary.
Linux focused installation/service/Doctor suite: 21 passed, 3 platform skips.
Windows native DACL helper test uses AST extraction of only the checker; it
does not create a scheduled task or count as physical lifecycle acceptance.
The final integration CI will record actual Windows execution.

## Continued independent work: publisher key privacy

Baseline: `f1c01290cc6e92afbd2dee4b607ee3f90c935553`. The release builder
now validates native owner/private permissions for signing keys on all OSes,
including NTFS DACLs, before executing binary version probes or creating a bundle.
The native runtime packaging fixture creates its signing key in a protected
directory. Linux publisher/build tests passed; actual Windows check is in the
existing three-OS CI matrix. No real publisher key was accessed or changed.

## Continued independent work: offline service update transaction

Integrated source commits02cb27c/e5d473b/50f5b7f from a separate worktree based
on4e5d0f3. New host/service-update.mjs provides signed bootstrap/runtime switch,
post-switch observed health, exact previous-pointer/verified-byte rollback and
private durable intent receipts. Known unhealthy results roll back once; uncertain
callbacks retain the lock for explicit stopped recovery with no replay. Native
stop observations must include durable restart inhibition. Recovery validates
receipt identity, phase, pointer versions and signed hashes before callbacks.
The new module ships in the signed Host payload and its packaged imports are
checked. Focused API tests:12 PASS; a separate native Linux service pilot will
provide service-level evidence. Windows/macOS physical updates remain NOT RUN.


## Continued integration: real service recovery, source inventory and soak

Clean integration17fd0e0683431bd1c557a06e2fdb2356e9aa1385 passed213
fixture/protocol/Host cases:201 passed,12 platform skips,0 failures. Signed
payload imports include the updater. Doctor/config/publisher-key privacy fixes
are included. Native ACL batching preserves fresh per-path checks at each
synchronous boundary and revalidation after callbacks; native Windows timing
improvement must be measured by final CI rather than inferred from spawn counts.

Real Linux update pilot receipts establish actual mapped official runtime
22.23.3 ->22.23.2 test-fixture replacement, controlled health rejection with
exact rollback, and uncertain timeout/late-result refusal plus explicit stopped
recovery. This does not relax the production22.23.3 pin. Owned GUI and cleanup
passed. Physical Windows/macOS updater lifecycle remains NOT RUN.

Source inventory now pins exact upstream inputs,2116 Cargo lock entries and
9170 unambiguous resolved edges; all18 Git dependency declarations are observed.
Bounded CI verifies selected crate archives/notices. Full registry metadata
collection is recorded separately; exact shipped binary composition, all notice
texts and upstream publisher attestation are not established by source graphs.

New installed-service/native Exec24h sampling started2026-10-19 01:59:37
Asia/Shanghai from frozen17fd0e0, driver1645138, owned unit
styx-rc20261019-owned-soak24h.service. The existing fb7f0aa component run remains
untouched. Both gates stay NOT RUN until actual elapsed completion; full
GUI/session/platform soak remains separate. Final CI/status snapshots are in
task outputs and PR37, with no production deployment or remote merge.
