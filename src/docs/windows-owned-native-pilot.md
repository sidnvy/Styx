# Owner-controlled Windows native acceptance

`host/managed-windows-pilot.mjs` is an explicit local acceptance driver. Ordinary imports and CI do not install a task. Run only in the intended interactive Windows x64 user session, with `STYX_RUN_MANAGED_WINDOWS_PILOT=1` and a private JSON options file:

```json
{
  "directory": "C:\\owner-private-parent\\fresh-run",
  "nodeBinary": "C:\\public-runtime\\node.exe",
  "codexBinary": "C:\\public-runtime\\codex.exe",
  "cuaBinary": "C:\\public-runtime\\cua-driver.exe"
}
```

```powershell
$env:STYX_RUN_MANAGED_WINDOWS_PILOT='1'
& $nodeBinary .\host\managed-windows-pilot.mjs $optionsFile
```

The parent directory must already pass the real native owner/DACL checks; the run directory and its sibling driver lock must not exist. Prepare Node with the repository's `prepare-node.py` provenance contract (adjacent `LICENSE` and `node-provenance.json`). The driver independently pins the three executable digests and builds a new signed package with an ephemeral owner-only Ed25519 key. Only signed packaged executable copies run under the fresh task. The source dependencies must be installed from the pinned lockfile before the driver starts.

Each run chooses its own `StyxPilot-RC20261019-…` task, private state, loopback Gateway and distinct model/Host credentials. Native Codex/Cua execute product operations through that Gateway, independently of any bootstrap connection. Host config inherits an explicit small set of operating-system environment variables, not arbitrary controller environment secrets. Existing tasks, profiles, Host configuration and credentials are never reused. Public executable bytes may be reused only after exact digest/version validation.

The bounded gates are: signed build/install; Interactive/Limited task start and exact native Exec marker; an exact-pid/title self-expiring WinForms window, PNG plus UIA observation, one observed button click and independent file/exit readback; disabled/quiescent stop observed across at least 65 seconds (longer than the native one-minute recovery trigger), then start; forced termination of the uniquely owned launcher process tree and native task automatic recovery; exact owned-task uninstall; private release/key/token/profile cleanup. The GUI fixture accepts only a verified private scratch directory and does not persist screenshot bytes or retry uncertain clicks. An exclusive sibling driver-lock receipt remains after completion or failure, preventing an uncertain run from being replayed. Use a fresh run directory for another acceptance attempt.

`receipt.json` records fixed phase results and executable/source digests. Errors contain fixed codes, not arbitrary native/SDK stderr. Installation is marked attempted before invoking Task registration. A timeout after successful registration still triggers exact owner-verified Task reconciliation; unknown status, foreign ownership, uncertain uninstall or remaining owned processes retain private state. Focused negative tests exercise these cases without native service effects. If cleanup reports attention required, inspect only the exact receipt task name and owned install path; do not issue wildcard task removal. The driver does not establish a distribution publisher trust policy or verify reboot/login, runtime-version migration, 24-hour soak, remote TLS transport or transactional upgrade/rollback. Those require their own acceptance evidence.

## Physical result on nab

The native Windows interactive session completed all seven gates on 2026-10-19 (UTC run start `2026-10-18T18:26:09.240Z`, completion `18:27:26.919Z`). Node was 22.23.3, Codex 0.163.0 and Cua 0.36.0. Native Cua observed six accessibility elements and the click's independent receipt/exit code was zero. Task `StyxPilot-RC20261019-2d7e6bb3` was removed; a separate final query confirmed zero fresh-owned tasks, zero fresh-owned Node processes and no private run state. Existing `StyxPilot-Host` remained running with the same marker, principal, least-privilege interactive logon, executable and arguments.

The pinned Node archive was obtained over verified official HTTPS on the development workstation after nab's Schannel handshake failed. A temporary server exposed only the dedicated public artifact directory; both archive digests were checked on nab before extraction/execution, and that server was stopped afterward. No trust-store, TLS, production service or existing Task changes were made. The bootstrap process receipt API returned an uncertain outcome; reconciliation and the exclusive driver lock prevented duplicate execution. The eventual native Task and all product operations were independently observed.

The same session also directly checked the current ACL batch helper under real PowerShell 5.1: valid one- and three-path batches (including a space/Unicode filename) passed; adding an Everyone-readable file rejected the complete batch with `private_paths_acl_not_owner_only`. The scratch fixture was removed. This confirms compatibility/security behavior, not a Windows CI wall-time improvement.

The final committed driver was independently rerun with the hardened uncertain-install cleanup and fixed error receipt. Its [final seven-gate receipt](evidence/windows-owned-native-20261019.json) pins both source files and all executable digests. The stop observation lasted 65,925ms before an explicit start; crash recovery and subsequent Exec passed. [Separate reconciliation](evidence/windows-owned-native-20261019-reconciliation.json) then confirmed zero fresh-owned tasks, zero fresh-owned Node processes and zero private run states, with the pre-existing Task's observed contract unchanged. Public bootstrap binaries, archives, source/dependencies and ACL scratch were removed after this check; only private nonsecret receipts/logs/options and exclusive driver-lock receipts remain on nab. Native Node22.23.3 tests reported 5 total, 4 pass and 1 foreign-platform-only skip; the same tests on Linux reported 5/5 pass. Earlier acceptance receipts retain their original source hashes rather than being relabeled as final-source evidence.
