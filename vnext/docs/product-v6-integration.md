# v6 integration checkpoint — 2026-10-20

This is a development integration checkpoint, not a production release or complete first-install acceptance.

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

1. Rebuild the macOS developer candidate from the integrated revision. In an isolated fresh user/environment, verify the complete native onboarding, platform Tunnel credentials, plugin create/reuse, and actual Exec/Browser/Cua calls from the intended chat account. Login, MFA and system permission grants are user actions.
2. Verify close-window versus Quit, login/logout/reboot, separate App/Cua/Core crashes, stale sockets/locks and network recovery. Stable permission responsibility across upgrade/rollback still requires a real signing identity; ad-hoc builds do not establish it.
3. Complete the Add Computer secure entry transaction and native UI while preserving the existing loopback chat endpoint. Existing chat tunnel/plugin ingress migration remains blocked. Verify TLS renewal, address/identity changes, expiration, confirmation, revocation and old credential rejection. The chat tunnel is not a Host/pairing relay.
4. Finish Mac/Windows managed Host updates and active-work admission/draining. The current product update execution is restricted to supported stopped Linux deployments. Verify migration and rollback without replacing identity, credentials or browser profiles.
5. Verify Mac primary + Windows Host and headless primary + desktop Host. A complete Windows native App is still absent. Existing CAS Run/Wake is retained; ordinary App autonomous-task integration, long-duration resource cleanup and cross-chat Browser login behavior need separate product/acceptance work.

No GitHub main merge, production deployment, installed App replacement or system permission change is part of this checkpoint. No piermini/NAB online services were changed.
