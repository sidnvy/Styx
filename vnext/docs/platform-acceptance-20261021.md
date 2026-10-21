# Windows and Linux integration — 2026-10-21

This is development-preview evidence, not formal product acceptance. macOS UI
development belongs to the separate Mac-local thread. No piermini mutation or
production deployment was performed in this work.

## Implemented and integrated

- Portable Linux x64 CLI distribution uses the same Core, signed independent
  Gateway runtime and optional signed Host runtime. Extraction installs no
  service and creates no device identity. Gateway-only excludes Exec/Cua.
- Checked Linux/Windows build entrypoint requires dependency audits, dependency
  inventory, SBOMs and contract/logic checks before loading the platform builder.
  Failed checks and absent evidence block the build. Cross-staged Windows output
  remains STAGED; it is not native compilation or account acceptance.
- Repeatable native Windows Exec/Edge and own-window Cua acceptance runners;
  packaged Linux Core invitation/Exec/Chrome/reconnection acceptance runner.
- Workflow includes native Windows compilation, Edge acceptance and PowerShell
  parsing. Workflow code has local/native validation; hosted CI and required
  branch protection have not been verified.

## Actual native checks

| Target | Observed result | Scope |
| --- | --- | --- |
| Arch/workstation Gateway-only | Packaged CLI help/create/plan/status; authenticated TLS MCP; crash/restart with seven identity/config files unchanged | No Host install/start |
| Arch/workstation systemd | Temporary product-generated user unit automatically restarted a killed Gateway; TLS verification passed; stop/uninstall removed it | No real logout/reboot or global linger change |
| Arch/workstation combined | Core prepared signed Gateway/Host, explicitly approved local identity, passed doctor; actual TLS MCP Codex command and exit code | Real Core, no mocked service observer |
| Arch/workstation Chrome | Navigate, observe, type and click; independent local HTTP server observed exactly one action | Installed Chrome, private headless profile, synthetic site/login only |
| Arch/workstation Host recovery | Foreground stop/start retained identity and credentials; Exec worked again; synthetic login restored, click not replayed | No Cua started; desktop state not_requested |
| Arch/workstation join-existing | Actual invitation, explicit TLS trust, wrong fingerprint refused, correct approval/claim/doctor, second Host Exec/Chrome; no second Gateway | Two real isolated Core installations on one physical computer |
| NAB Windows native Host | Signed test runtime verified; modified bundle refused; HTTP MCP through Gateway/outbound Host ran real Codex command | Separate native Host process, owned loopback HTTP/WS |
| NAB Edge | Two MCP sessions, reference/storage isolation, stale-reference rejection, reconnect and Host restart, synthetic login restoration | Installed Edge, private profiles, no personal account login |
| NAB authorization | Old credential refused after rotation (401); revoked Host's existing MCP access and both credentials refused (403) | Owned disposable identity only |
| NAB desktop | Actual session 1, WinSta0/Default; own WinForms window screenshot and six AX elements; Cua clicked button; independent Exec readback exited 0 | Limited InteractiveToken temporary task; exact own PID only |

Windows temporary task was unregistered. Own UI/native processes were absent;
Linux foreground Hosts, Gateway and browser processes stopped; private test
state and temporary publisher private keys removed. Existing production
services, identities, browser profiles and permissions were preserved.

## Engineering checks and evidence

Clean checked Gateway-only build at a9b0263: 14 quality checks passed; contract
suites recorded 728 passed, 0 failed, 29 skipped. Skips are explicit, not native
passes. Separate real Exec adapter acceptance passed 19 cases. After integrating
the Linux runner and Windows desktop harness, 14 targeted runner/build protection
tests passed with no skips. Four independently locked dependency trees passed
audits and emitted CycloneDX SBOMs. Both prototype SDK locks use 1.32.1.
The final Host-inclusive checked build at 05b6312 also passed: 730 passed,
0 failed, 29 skipped, including the two new Linux runner protection tests.

Evidence directories under this task's `outputs/`:

- `platform-second-20261021/native-exec/receipt.json`
- `linux-second-20261021-checked/checked-build/quality/receipt.json`
- `linux-second-20261021-checked/runtime-comparison-and-acceptance.json`
- `linux-host-second-20261021/native-run2/receipt.json`
- `linux-host-second-20261021/run3/checked-build/quality/receipt.json`
- `windows-native-second-20261021/receipt.json`
- `windows-native-second-20261021/desktop/desktop-receipt.json`
- `windows-native-second-20261021/desktop/cleanup-receipt.json`
- `windows-native-second-20261021/ci-syntax-v2/parse-receipt.json`

The first Linux Host checked build failed because required ignored test inputs
were absent; evidence is retained. Its corrected second build passed. The first
native Host run exposed a missing await in the acceptance runner after real
Exec/Chrome had succeeded; corrected run2 passed all seven gates and cleanup.
Neither failed run is presented as successful acceptance.

## Packaged, deployed, and remaining

Linux Gateway-only portable preview and a separate Host-inclusive preview are
built with temporary test publishers. Their delivery records bind artifact
hashes and checked source to native-runtime byte comparisons. They are not a
signed formal outer updater or public production release.

Windows signed test Host and native App/control compilation were exercised;
this is not a complete checked end-user Windows installer delivery. No existing
App was replaced on NAB. No production deployment was performed.

Remaining: cross-physical-device TLS/reachability and pairing (including Linux
Gateway + Windows Host), real login/logout/reboot/network recovery, durable
Windows product lifecycle, complete fresh-user installation/upgrade/rollback,
long-running reliability, production publisher trust and ChatGPT account-side
tool invocation. Linux graphical Computer Use is not accepted by these headless
tests. Chrome and Edge were respectively tested on Linux and Windows; this does
not prove every browser/platform combination.

## Third integration round: transport and Windows preparation

The verified-TLS client no longer treats ten seconds without socket traffic as
failure after TLS establishment. Its ten-second deadline covers connection
establishment; established calls use their caller/SDK deadline and cancellation.
A real TLS MCP response delayed eleven seconds and a separate cancellation test
passed. Authentication, wrong-CA and redirect protections remain tested. This is
not a claim about arbitrary-duration account-side calls.

Windows signed public-payload staging now creates new files and directories in
bounded native ACL batches. This path handles publisher-signed public code only;
credential APIs keep their existing behavior. It binds exact BigInt file IDs,
checks current ownership and actual DACLs, rejects unknown/replaced objects,
verifies all signed members, and publishes only the completed generation.
An interrupted or foreign tree never authorizes recursive cleanup.

The first actual 2200-member NAB run rejected imprecise Number file identities;
the next run exposed excessive per-directory ACL startup cost. Neither passed.
With exact identities and directory batching, the same public payload staged in
100977 ms, with 195 PowerShell invocations and actual DACL checks on all 2689
installed paths. That measurement is scoped to ed0885a + 7b922a6. The subsequent
unknown-empty-directory rejection and complete adversarial retest remain separate
acceptance gates; this timing alone does not accept the final installer.

At integrated revision 55207e3, all fourteen shared engineering quality checks
passed: 748 tests passed, zero failed, 39 skipped. Four dependency audits and four
SBOMs completed. Skipped platform tests do not establish native acceptance. The
receipt is `outputs/platform-third-20261021/quality-final-stage/receipt.json` in
the parent task directory. Cross-physical Core join/Exec/Edge/reconnect and the
final Windows preview remain pending their own receipts.
