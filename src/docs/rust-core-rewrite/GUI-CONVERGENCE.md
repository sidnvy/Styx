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

Product: connecting native inventory/invitation/approval/revoke and Tunnel UI.
Architecture: adding original-App-scope adapters to existing Rust owners.
Integration: development on the existing develop checkout, no new worktree.
Release: no final candidate built yet; current installed packages remain the
November 6 test candidates until an exact replacement is verified.
Reliability: run real disposable TLS pairing and mutation-negative scenarios
before producing packages; then verify native installed effects separately.
Decision: Stable remains NO-GO until the above journey and explicit release
gates close. Public signing/distribution and deferred services/auto-update are
not silently promoted into this task.
