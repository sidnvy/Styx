# v6 integration checkpoint — 2026-10-20

This is a development integration checkpoint, not a production release or complete first-install acceptance.

## PilotMac onboarding correction — dev5

Current installed App: `0.3.0-v6-dev.20261020.5`, source `bff132d`. The user's first setup had successfully prepared and paired the Host, then recorded `host.doctor: blocked / codex_executor_unavailable`. The initial probe's precise failure cause was not recorded. A later real version read succeeded, but aggregate local setup refused to repeat even this read-only blocked check, making Continue ineffective.

- The existing Core explicitly rechecked that doctor successfully and selected the same local default device. Configuration, identity, Host credential and Gateway certificate bytes were verified unchanged; no pairing replay or permission changes occurred.
- `c3a2e28` allows a new explicit local-setup call to repeat only a blocked read-only doctor. Completed installation/pairing and uncertain steps remain protected. Public status and journey share this retry policy and expose only whitelisted failure reasons. Native startup defers a selected but unprepared Browser.
- `bff132d` uses an 18pt transparent menu-bar template derived from the supplied logo. Preparation shows three user stages, with implementation details collapsed. Safe rechecks have clear explanations/buttons. Restoring the App reviews Browser preparation, foreground ownership and separate native permissions before selecting the next page.
- Related onboarding regression: 346 tests, 340 passed, 6 environment skips, zero failures. Native production and separate `STYX_TESTING` builds compiled with warnings as errors; only the test App ran self-tests. The real supplied-artwork template was exported and checked visually and for alpha.
- The final packaged Mac flow passed real TLS pairing, reopen-before-Browser deferral with retained identity, real headed Chromium/Exec, explicit reconnect and plugin-profile saving. Read-only DMG signature/source checks and native window fixture passed. These are isolated local checks, not target-account or native Cua acceptance.
- Updated only the installed App after a private rollback backup at `/Users/it-bootstrap/Library/Application Support/Styx-Test-Backups/20261020-175834-dev5-_kkvzzl0`. Kept the existing configuration, identities, credentials, signed Host release and its publisher trust. The dev5 DMG is on Desktop. Normal production startup/reopen has one visible native product window.

Evidence: parent task `outputs/v6-candidate-dev5/acceptance-receipt.json`. Manual user onboarding, actual Cua operations, target chat/plugin calls, signing/permission responsibility and the other platform/lifecycle gates below remain pending. This same-user development update does not establish fresh-user permissions or a signed release migration.

## PilotMac development installation — later checkpoint

The tested/packaged revision is `1dbccf8`, release `0.3.0-v6-dev.20261020.4`. The earlier sections below retain the initial integration evidence.

- `922aad8` prevents stale shared HTTPS socket reuse during onboarding verification/enrollment by using a fresh validated TLS connection; no enrollment replay or trust relaxation. Real packaged macOS setup reproduced the failure before this fix.
- `0c76e58` observes the later App-owned GUI descriptor and connects an approved Computer lane without a second Core start. Scope changes, stopping and deferred observations are covered; this is not native Cua action acceptance.
- `1dbccf8` removes source image metadata from the generated plugin PNG and validates it with the existing Core image contract before sealing the App. The original supplied brand artwork is retained. The real package previously failed plugin-profile saving at this boundary.
- Final Node 22.23.2 regression: **686 tests, 659 passed, 27 skipped, zero failures/cancellations**. Native/environment skips remain unverified. Raw failed test-runner and package attempts are retained separately.
- Final packaged macOS Node 22.23.3 flow used a new temporary Gateway and Host on **the same PilotMac**, with real TLS pairing, signed Host preparation, matching App/CLI role status, real Exec output/exit, real managed Chromium navigation/snapshot, explicit stop/reconnect with unchanged identity/credentials, and plugin presentation saving. It did not use piermini, NAB, an existing deployment identity or a real chat account.
- The final DMG was mounted read-only: ad-hoc signature and all 163 packaged source hashes passed. Both Browser production dependency closures imported, and a read-only native welcome-window fixture against the packaged authenticated Core passed.
- Under the user's explicit authorization to clear the old installation on the existing `it-bootstrap` account, old App/config/preferences/runtime were privately backed up on PilotMac before replacing `/Applications/Styx.app`. The DMG is on that user's Desktop. Normal LaunchServices startup now runs the new App and bundled Core; setup was presented, and no new deployment, Host identity or Cua process had been created at handoff.

Backup: `/Users/it-bootstrap/Library/Application Support/Styx-Test-Backups/20261020-172157-m8ulu3j7`. It contains the old App, support directory, preferences, Cua runtime and a receipt; credentials remain on PilotMac. TCC and Keychain were not reset. Because this is the same macOS user, inherited permission history cannot establish a fresh-user permission flow. Production signing, notarization, manual native onboarding, Cua actions, target-account plugin/chat calls, multi-machine pairing and restart/login/logout/crash/network acceptance remain pending.

Evidence: parent task `outputs/v6-candidate-dev4/acceptance-receipt.json` and its hash-bound logs. No GitHub main merge or production deployment occurred; piermini and NAB were unchanged. The remaining-work list below still applies, with the rebuild and preparatory isolated Core tests now complete.

## Inputs and integration

- Architecture contract: `13bf0af`.
- Browser development: `a97c0a7`; imported by the v6 implementation as `f09d0ad` with the same stable patch ID. Do not merge the original Browser patch again.
- Native/Core v6 development: `8c68b10`.
- Integration fixes: the commit containing this record. Original development worktrees and their untracked outputs are preserved.

The Browser implementation uses the pinned official Playwright MCP contract. Native onboarding, plugin creation/reuse handoff, App lifecycle management, offline Browser capability transactions, stopped Linux Host update/recovery and offline first-device ingress transactions have been connected to the shared Core.

## Defects corrected before integration

1. A joining Host may request Browser and Computer Use while its owner approves only Exec. Browser observation now reports `not_approved`; explicit preparation still rejects the unapproved capability. Native onboarding continues with the approved capabilities and does not request Computer Use permissions or start App-owned Cua from desired configuration alone.
2. Native capability settings restore the App-owned foreground after a successful change. Browser changes explicitly confirm suspension and operate only on the current App manager's known foreground. Services, other owners and uncertain states are rejected. Uncertain capability writes are not replayed; recovery is explicit.
3. Ingress rollback and Host update recovery can resume after their own recovery process dies. Recovery guards bind the transaction, PID, random owner/token and file identity. Live, inaccessible, unknown, foreign or replaced guards are retained.

The new management API keeps the authenticated public foreground observation separate from this manager's owned foreground. The stop action is available only to a trusted native App session and Core never adopts another manager's process.

## Verification

- Existing candidate integration gate: 180 passed, zero failures.
- Final full regression with Node 22.23.2: 678 tests, 651 passed, 27 skipped, zero failures/cancellations. Includes real isolated Exec and recovery test processes; many service/platform checks use test adapters.
- Isolated PilotMac compile with warnings treated as errors and native `--self-test`: passed. This did not start the product UI, request system permissions or access an account.
- Browser thread's Linux evidence and v6 thread's real PilotMac Chromium test remain separate evidence. Neither establishes target ChatGPT account acceptance.
- The original PilotMac DMG/ZIP hashes and all 162 packaged source file hashes match `8c68b10`. Those packages predate these integration fixes and must be rebuilt before testing the updated candidate.

Raw logs and source hashes are retained in the parent task's `outputs/v6-integration-review-20261020/` directory. Failed test-fixture attempts are retained alongside the successful final run.

## Remaining work, in order

1. Use the installed macOS developer candidate for complete manual native onboarding, platform Tunnel credentials, plugin create/reuse, and actual Exec/Browser/Cua calls from the intended chat account. Separately verify system permission behavior in a fresh macOS user. Login, MFA and system permission grants are user actions.
2. Verify close-window versus Quit, login/logout/reboot, separate App/Cua/Core crashes, stale sockets/locks and network recovery. Stable permission responsibility across upgrade/rollback still requires a real signing identity; ad-hoc builds do not establish it.
3. Complete the Add Computer secure entry transaction and native UI while preserving the existing loopback chat endpoint. Existing chat tunnel/plugin ingress migration remains blocked. Verify TLS renewal, address/identity changes, expiration, confirmation, revocation and old credential rejection. The chat tunnel is not a Host/pairing relay.
4. Finish Mac/Windows managed Host updates and active-work admission/draining. The current product update execution is restricted to supported stopped Linux deployments. Verify migration and rollback without replacing identity, credentials or browser profiles.
5. Verify Mac primary + Windows Host and headless primary + desktop Host. A complete Windows native App is still absent. Existing CAS Run/Wake is retained; ordinary App autonomous-task integration, long-duration resource cleanup and cross-chat Browser login behavior need separate product/acceptance work.

The initial checkpoint did not replace an installed App. The later PilotMac development installation is recorded above. No GitHub main merge, production deployment or system permission change occurred. No piermini/NAB online services were changed.
