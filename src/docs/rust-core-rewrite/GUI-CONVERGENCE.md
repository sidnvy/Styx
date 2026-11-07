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
Installed fdb1ef9 also failed normal Mac Quit after changing TCC permissions:
the App stopped Cua before Rust drained the original native transports. Source
now retains the daemon during permission/discovery withdrawal, drains the Host
before explicit permission recovery, and allows cleanup on the authenticated
original FD after discovery withdrawal. New actions remain fenced; process,
socket and image checks and the actual drain acknowledgement remain required.
The failed installed run is not lifecycle acceptance; a fresh candidate must
repeat the real read/effect, withdrawal cleanup and normal Quit/reopen journey.
The 2845635 reference DMG (1118) subsequently passed installed Mac Exec, Browser,
exact-window screenshot, AX click and text input with independent fixture
readback. Normal tray Quit ended App/Core/Cua and the Hub listener without
forced termination. The original-FD withdrawal scenario also passed, using the
corrected native test fixture (ef076b5). Separate tree and screenshot reads and
explicit text-write target fields are now explained in the MCP instructions;
unsupported combined reads are not treated as missing OS permission. Final
same-revision packages, Windows pairing and account acceptance remain pending.
The a67ef91 candidate (Mac 1119, Windows 0.4.20261107.5) exposed a Mac
overview navigation defect: View chat connection still used the legacy
preparation gate. First-run and Settings now share the Rust-backed Tunnel and
Custom MCP view; reopening native onboarding also bypasses that legacy gate.
Native Swift typechecking passed; installed verification remains pending.
NAB5's candidate-5 installation failed with zero free bytes on C: and Inno
completed rollback. This is an installation failure, not Windows acceptance;
the original failure log is retained and a new attempt requires available space.
On follow-up, 21 inactive historical Windows installer files were copied to D:
with SHA-256 and alternate-stream verification before removing the C: copies.
This released 3.31 GB; candidate-6 Inno then installed successfully on NAB5 and
the GUI reached the join form with the requested Computer and Browser choices.
Candidate-6 Mac local Exec and Browser passed, but Computer returned
SESSION_DISCONNECTED before dispatch. The console was logged in; the earlier
lock-screen inference was incorrect. macOS logs prove the first tray Quit was
blocked by the open Tunnel sheet. After dismissing it, normal Quit still did
not settle. A subsequent invitation committed, but its link was not returned.
The enrollment clock led the independently recorded wall-clock commit time by
77 ms. Link export now caps the advertised expiry at the original dispatch
wall-time deadline and the committed Gateway deadline. Confirmed mutation
replies are separated from local link-rendering failures. A focused regression
and the disposable real-TLS computer-management scenario passed.
The Mac component-status false branch now withdraws discovery while retaining
the daemon for the live Core's original transports. Swift typechecking passed;
the next installed candidate must verify session recovery and normal Quit.
Candidate-6 recovery required TERM then KILL after exact image/parent checks,
no child workers or remote clients, expired committed invites, no pending
pairings, and unchanged desktop fixture output. This remains failed lifecycle
acceptance; the failed App and Core were not counted as a normal Quit.
The independent account Tunnel was created with explicit owner approval:
`tunnel_6aee2359dfb48191b3a50e2ba095b595`. Pairing, Computer Use and account
acceptance must still be rerun on the final candidate; production stays intact.
Candidate-7 (8631a75, Mac 1121 and Windows 0.4.20261107.7) installed on both
machines. GUI invitation, independent CA comparison, mismatched-code cancellation,
approval and claim passed. Both machines produced real Exec file effects,
Browser navigation/readback/close, native desktop click/text/screenshot and normal
Quit/reopen evidence. Windows exported the exact 128px, 9163-byte Custom MCP PNG
through its native Save dialog. These local checks do not close account acceptance.
The Mac desktop source failed again on the same reopened App after its earlier
successful effects. Eight independent native observations reported unlocked
console state and both TCC grants. Separate window probes and closing one of
two independent read transports also passed. A specific publication race was
then reproduced with the actual Rust secure reader: 52 failures in 87714 reads
over ten seconds while the descriptor generation and contents stayed identical.
The App had atomically replaced that same descriptor every 200ms. The native
publisher now leaves identical contents in place, and sets private permissions
on a new temporary file before publishing changes or a withdrawn descriptor.
The opt-in installed-source continuity regression retains strict Rust identity
checks. A new installed candidate must pass it and repeat delayed desktop reads.
Native self-test execution also exposed an outdated Tunnel expectation from
before the Rust adapter. Rust reports configured status with separately observed
ready transport health; the existing self-test now expects that pair as connected
while keeping unobserved configured state unknown. Account connection, saved-key
editing, installed Logo refresh and disposable guest revocation remain pending.
Candidate-8 (d6fb84c, Mac 1122 and Windows 0.4.20261107.8, fresh guest H)
installed and completed real GUI invitation, mismatched-code cancellation,
approval, claim and reconnect. The installed Mac descriptor regression passed
119256 actual protected reads with zero failures over ten seconds. That narrow
regression does not establish desktop or account acceptance.
With explicit owner approval, Custom MCP `Styx GUI Acceptance` was created and
connected to the independent acceptance Tunnel. Refreshing its installed detail
retained the black Styx ripple Logo. A real ChatGPT conversation listed both
new identities, and separate Exec calls created unique files on both machines;
independent SSH readback matched their nonce. However, immediate write_stdin
returned unknown_session, including polling in the same assistant turn. The
first Windows call supplied an unsupported shell alias and was definitely
refused; the later default-shell call was dispatched once. Neither file command
was replayed after dispatch. Account Computer Use returned not-dispatched
capability_unsupported on Mac and capacity_busy on Windows. A same-session local
Mac read also returned capability_unsupported. Their causes remain unproven.
Saving the existing Tunnel from the Mac GUI preserved the exact key bytes on
that machine but failed to restore the connection. This is failed save/recovery
acceptance, not a passed key-edit journey. No secret was exported in evidence.
The Mac address clarification is checked in as cbf48fe and Swift-checked, but is
not yet in installed build 1122. A bounded, private-file-opt-in Tunnel diagnostic
now records only tool names and hashes of transport/correlation identifiers;
payloads, raw identifiers and credentials are excluded. Its disabled, forged
marker, bounded retention, correlation and private-permission controls passed.
It changes no owner or admission rules. The next diagnostic candidate must
establish the actual transport facts before a session-binding fix is selected.
Candidate-9 (93161ad, Mac 1123) installed from its DMG and completed fresh GUI
setup and Tunnel connection. Its actual setup view distinguishes the other
computers' joining address from this Mac's loopback connection. In the real
Work conversation, two consecutive read-only list calls in one assistant turn
arrived with different MCP transport sessions; all three selected correlation
metadata fields were absent. This establishes transport facts, not a safe
replacement owner policy. No owner isolation or authentication rule was relaxed.
NAB5's old November 6 setup-check App/Core tree was audited and normally quit;
its files and profile were retained. The current H guest remains paired to the
archived candidate-8 hub, so candidate-9 is not two-machine acceptance.

The owner's subsequent network/setup and Windows settings corrections are
implemented in source. CLI and both native GUIs now share pinned `if-addrs
0.15.0` discovery in Rust, replacing the empty Windows interface adapter.
Enabling other computers' access detects operational private LAN/VPN IPv4
interfaces, recommends the current route's source (falling back to an available
interface), and offers a selector with advanced manual input. No peer scan or
DHCP rebinding is implied. Setup revalidates the selected interface before any
configuration write. Wildcard, loopback, public, link-local and removed
addresses cannot become the joining address; explicit invalid input still
fails instead of silently selecting a different address. The existing listener
policy and explicit opt-in remain unchanged.
Windows settings now use content-sized text, matching Computers/ChatGPT/General
navigation, a real General page and a separate runtime maintenance page. A
joined computer directs ChatGPT setup to its main computer. These are native
adapters over the existing Rust Core, not missing Rust product authority.
Incremental runtime checking, real Linux OS-interface/bind comparison, the
existing pre-write setup refusal scenario, Mac Swift typechecking and Windows
native C# compilation passed. The first invalid-input regression failed because
empty explicit input had accidentally selected automatically; that behavior was
corrected and the full affected local-gateway filter passed. An isolated native
Windows settings preview was inspected using own-window bitmaps; the earlier
desktop capture hit the old foreground window and is invalid evidence.
These corrections are not yet installed packages or native setup acceptance.
Product: network discovery and settings corrections are source-complete.
Architecture: shared Rust discovery retains the sole configuration authority.
Integration: focused checks passed; final same-source candidate remains pending.
Release: no new installed Windows/Mac acceptance is claimed for these changes.
Reliability: stale network selection refuses before writes; account session
continuity and Tunnel saved-key recovery remain open.
Decision: final end-to-end delivery and Stable remain NO-GO.
Evidence: `/home/sid/Developer/Artifacts/Styx/20261107-gui-convergence/`, with
exact fdb1ef9 inputs and quality receipt under `candidate-2/`. Installed native
effects are retained on PilotMac under
`/Users/it-bootstrap/Developer/Artifacts/Styx/20261107-gui-fdb1ef9/`.
Decision: Stable remains NO-GO until the above journey and explicit release
gates close. Public signing/distribution and deferred services/auto-update are
not silently promoted into this task.
