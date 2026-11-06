# Native GUI delivery convergence — 2026-11-07

Owner request: finish the existing product's native GUI and deliver packages that
can be accepted end to end on PilotMac and NAB5. This is not a new Rust rewrite.

Historical acceptance remains scoped to its original artifacts:

- `/home/sid/Developer/Artifacts/Styx/2026-10-29-v1/RESULT.md`: candidate 37,
  three-platform reduced v1 journey; Mac Computer Use deferred at that checkpoint.
- `/home/sid/Developer/Artifacts/Styx/20261105-final-clients/FINAL-ACCEPTANCE.txt`:
  b31a4dd desktop effects and lifecycle on two Linux machines, Windows and Mac.
- November 6–7 Custom MCP candidates: icon, local setup and lifecycle checks;
  their narrower runtime packages are not the complete product delivery.

## Delivery contract

Keep the Rust Core/Gateway/Host owners and the existing native UI. Use the
existing Gateway admin routes, approval binding and Tunnel private storage.
No JS management runtime, second profile authority, production-plugin deletion,
publisher-key transfer, or unobserved operation replay.

Required journey for the final immutable candidate:

1. Install the signed Mac DMG on PilotMac and the Windows Inno package on NAB5.
2. In the GUI create a hub with the required private LAN address, or join it
   from the other computer without creating another Gateway.
3. Show real computer inventory in the App; create/copy an expiring invitation;
   compare and approve the exact pairing code; observe the joined computer.
   Wrong confirmation and revoking the hub's own computer must be refused.
4. Configure Tunnel in the owning App. Keep the runtime API key private and
   preserve it on edits that omit a replacement. Confirm actual Tunnel health.
5. Add/reuse Custom MCP in the intended ChatGPT account, upload the Styx icon,
   and verify the installed detail after refresh. Keep the production plugin.
6. Through that account connection, list the two real computers and demonstrate
   Exec, Browser and Computer Use with independent readback on each platform.
7. Quit and reopen the App; retain pairing and configuration, reconnect, and
   repeat a read. Revoke the disposable joining computer and verify exclusion.

All final runtime packages must contain the selected platform's required Codex,
Browser and Tunnel workers; Mac also embeds its verified Cua bridge, Windows
includes its verified Cua worker. A working subset is not the full package.
OS grants and account provisioning are user-owned prerequisites when needed.

## Current work, not an acceptance claim

Product: native inventory/invitation/approval/revoke and Tunnel UI are connected.
Installed testing exposed a missing Mac transport allowlist entry (fixed in
fdb1ef9), a missing pending-approval view in the native tray, misleading feature
editing controls, and lost actionable join-failure feedback. The latter UI fixes
are the next candidate. Feature selection remains first-run/re-pair in this
release; selected features are displayed as choices, never approval evidence.
Architecture: original-App-scope adapters reuse the existing Rust owners. There
is no new management authority or JS runtime.
Integration: development remains in the existing develop checkout, no worktree.
Release: fdb1ef9 full-worker Mac DMG (1116) and Windows Inno (0.4.20261107.2)
were built and installed on PilotMac and NAB5. They are intermediate candidates.
Reliability: disposable real TLS pairing, binding refusal, self-revoke refusal,
revoke and reopen passed. Installed fdb1ef9 Mac Exec file effect, HTTP 401 negative
and Browser navigation/readback/close passed. Windows GUI joining did not pass:
macOS ALF logs show its incoming connection held pending the styx firewall prompt.
Computer Use found the Mac fixture window but window read returned permission
required. Neither result is end-to-end acceptance. The owner subsequently confirmed system grants; a fresh LAN TLS probe responded.
The independent account Tunnel was created with explicit owner approval:
`tunnel_6aee2359dfb48191b3a50e2ba095b595`. Pairing, Computer Use and account
acceptance must still be rerun on the final candidate; production stays intact.
Evidence: `/home/sid/Developer/Artifacts/Styx/20261107-gui-convergence/`, with
exact fdb1ef9 inputs and quality receipt under `candidate-2/`. Installed native
effects are retained on PilotMac under
`/Users/it-bootstrap/Developer/Artifacts/Styx/20261107-gui-fdb1ef9/`.
Decision: Stable remains NO-GO until the above journey and explicit release
gates close. Public signing/distribution and deferred services/auto-update are
not silently promoted into this task.
