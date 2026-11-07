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
2. In the GUI create a hub, enable other computers to join and automatically
   detect an available LAN/VPN interface without requiring manual IP entry;
   join it from the other computer without creating another Gateway.
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
arrived with different MCP transport sessions. The claim that all three
correlation metadata fields were absent was withdrawn: the diagnostic read the
typed parameter field after the MCP SDK had moved wire metadata into envelope
extensions. Its transport-session hashes remain valid; metadata absence is
unproven. The diagnostic now reads the SDK's canonical envelope metadata and
its regression decodes a complete JSON-RPC request, checking the exact expected
correlation hash and absence of raw payloads. No owner isolation or
authentication rule was relaxed.
NAB5's old November 6 setup-check App/Core tree was audited and normally quit;
its files and profile were retained. The current H guest remains paired to the
archived candidate-8 hub, so candidate-9 is not two-machine acceptance.
In the installed C9 GUI after read-only account calls, saving the same Tunnel
with no replacement key restored the connected state. Current key bytes matched
the original authorized source over a direct encrypted stdin comparison pipe;
neither key nor its digest was exported. The first post-action evidence script
tried to read the old key filename, which normal configuration rotation had
removed; the correction only read the current file and did not repeat saving.
This passes that narrow journey, not the C8 recovery with execution resources.

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
C10 e2a829b passed the unified development quality gate, but its native build was
not started once the metadata diagnostic defect was identified. The next
immutable candidate must include the diagnostic correction as well as these UI
changes. C10's source and passing quality evidence are retained without claiming
that its known-bad metadata diagnostic was accepted.
C11 200b5e3 passed the unified development gate and both native Core producers.
Mac DMG build 1124 installed, automatically selected en0 / 10.0.8.165 without
manual IP input, and started the independently observed private and loopback
listeners. Windows Inno 0.4.20261107.11 installed as test profile I after the old
H App/Core normally exited with code 0. Its real network selector discovered
Ethernet / 10.0.8.146; that local setup form was left without submitting a second
Gateway. NAB5 instead joined PilotMac through the GUI: independent CA comparison,
the mismatch/cancel path, matching-code approval, original claim and connection
completed. Both real native UIs showed the paired guest connected. Windows
General displayed the correct settings page and its joined ChatGPT page directed
connection management to the main computer.
The corrected C11 diagnostic observed two real Work calls with different
transport sessions and identical, present organization/subject/conversation
hashes. This supersedes C9's invalid metadata-absence inference. The installed C11
transport-bound owner remains unchanged, so these list calls are not account
Exec/Browser/Computer acceptance. A dedicated authenticated Tunnel conversation
adapter is still required; ordinary HTTP callers must not gain metadata-derived
authority or share an owner across unrelated chats.
Installed testing exposed three small follow-ups: the native pending projection
dropped the existing Gateway label, the Windows browser selector inherited an
incorrect accessibility name, and claim feedback could tell an already connected
computer to reconnect. Source now retains a bounded literal pending label, names
the selector Browser, and bases that feedback on actual Host/Exec observations.
Focused runtime/admin scenarios and native C# compilation passed; these follow-up
changes are not yet installed. Do not produce another native candidate until the
account continuity reference and shared source converge.
ADR-036 now implements the dedicated authenticated Tunnel conversation adapter
in Rust. A fresh private forwarding credential distinguishes that ingress from
the ordinary model bearer. Canonical organization/subject/chat metadata only
correlates resources inside that authenticated domain; it is not account
identity or a tool-supplied OwnerId. Each logical owner keeps the existing
bounded reservation, fence and cleanup supervision. Transport DELETE closes
its own SDK transport without revoking the conversation's resources.
The actual official-SDK TCP reference passed continuation across two connections,
transport deletion, cross-chat/subject/org isolation, ordinary bearer forgery
refusal, malformed-context no-dispatch and dropped HTTP waiter retention. The
strict-TLS/enrolled-Host/real Codex reference then started one native shell,
independently read one nonce effect, deleted the first MCP connection, refused
cross-scope input, continued through a second connection and observed exit 0
and the original PID/starttime's exit. These are owned Linux references, not
installed or account acceptance. The separate capacity/Unknown cleanup control
keeps all reservations and refuses reminting a closing conversation.
A real signed-runtime disposable App with a live native Exec also completed the
existing strict settlement, with exact Host/Gateway cleanup and independent
file/PID observations. This did not reproduce the hypothesized general Host-first
shutdown defect, so no speculative settlement-order change was made. Installed
Tunnel saving after account Exec/Browser/Computer work remains to be repeated.
The C13 full optional checkpoint passed the new Tunnel and real paired journey
but stopped on an older preverified-owner WSS fixture: after a lost final read,
the Host had already observed exit/drain and released provider storage. A fresh
read correctly returned STATE_CONFLICT/not_dispatched; the old fixture still
required another successful decoded read despite read_resume=false. The updated
fixture accepts only that exact refusal with matching operation/digest, terminal
inspection and independent original PID absence. Normal reads still require
exact output, exit 0 and drain; both nonce files must remain single effects.
No product behavior was relaxed. The first terminal-proof probe used the wrong
Snapshot DTO field (`id` instead of `operation_id`), failed before cleanup proof,
and was corrected without replaying its actions. Fresh focused WSS and HTTP
scenarios then passed, including completed idle-context collection and rejection
of an ordinary bearer deleting an actually active Tunnel session. C12/C13 raw
failures remain retained; neither candidate started native compilation.
Product: C11 automatic network setup and GUI pairing remain installed passes;
Windows claim/name/accessibility follow-ups and conversation continuation are
source-only until the next package is installed.
Architecture: the authenticated Tunnel adapter separates logical conversation
ownership from SDK transport lifetime; ordinary admission stays isolated.
Integration: focused SDK/TLS/Codex references passed; the next unified checkpoint
and same-source native candidate remain pending.
Release: C11 is still installed on both machines, not final end-to-end acceptance.
Reliability: malformed/forged contexts never gain ownership, dropped waiters keep
work/capacity, and unknown cleanup never becomes successful collection. Final
account continuity and saved-key recovery remain open.
Decision: proceed to a frozen candidate after the shared-source quality checkpoint;
final end-to-end delivery and Stable remain NO-GO.
Evidence: `/home/sid/Developer/Artifacts/Styx/20261107-gui-convergence/`, with
exact fdb1ef9 inputs and quality receipt under `candidate-2/`. Installed native
effects are retained on PilotMac under
`/Users/it-bootstrap/Developer/Artifacts/Styx/20261107-gui-fdb1ef9/`.
Decision: Stable remains NO-GO until the above journey and explicit release
gates close. Public signing/distribution and deferred services/auto-update are
not silently promoted into this task.

## C14 account acceptance and revoked-guest recovery correction

Product: C14 (`f94260d`) was installed from its Mac DMG and Windows Inno package.
Both native GUIs paired the real devices, and the target Custom MCP account
proved Exec continuation, Browser nonce read/close and Computer Use input/click
with independent effects on both machines. Normal Quit/reopen and account
readback passed. Refreshing the installed detail retained Styx's own ripple Logo.
GUI revocation excluded NAB5; one rejected Exec produced no forbidden marker.
The final usable two-device handoff is still incomplete: repairing the revoked
Windows guest exposed a startup/reconfiguration failure.

Architecture: the new real TLS regression reproduced a fixed initial WSS 403
after revocation. The original signed executor and event tasks had joined, but
the App classified this as `app_cleanup_unknown`. Only this initial admission
refusal is now represented as disconnected/refused; repeated startup reads and
explicit Connect cannot resend that credential. Prior Unknown cleanup remains
fenced and no remote drain receipt is invented. Role changes retain the original
strict remote-cleanup preflight. Both native UIs now guide an already locally
stopped user to Quit/reopen when that preflight cannot confirm remote cleanup,
and direct a refused identity to fresh pairing instead of Reconnect.

Integration: the disposable signed-runtime/TLS scenario failed before the fix
with `gateway_wss_admission_refused` followed by `app_cleanup_unknown`, and passed
after the correction, including physical role-backup paths and no startup retry.
The existing Unknown/quit/role controls and both native UI compile-only checks
passed. The ignored scenario is explicitly registered because it requires an
owner-provided signed payload and LAN address; no dependency was added.

Release: these recovery corrections are source-only until a new same-source
candidate is packaged, installed and exercised. C14 remains immutable; its
installed passes do not prove the corrected recovery path.

Reliability: the original Windows App/Core were normally exited once after the
first preflight refusal. The reopened old C14 App remains preserved for diagnosis;
no forced termination, profile rewrite, credential transfer or automatic replay
was used. The UI runner's earlier Windows Text-type comparison failure is retained
separately from the independently verified successful runtime reopen.

Decision: continue to the integration checkpoint and next candidate; final GUI
delivery and Stable remain NO-GO. Evidence is under
`/home/sid/Developer/Artifacts/Styx/20261107-gui-convergence/candidate-14/` and
`revocation-investigation/`. The reference uses its declared signed fixture;
it is not a claim about the next installed package or its native pixels.

## C15 installed candidate and local client ownership

Product: C15 (`f10e20186fdc68519563fd57bb3274fb9c0ed631`) is installed on both
machines. GUI first setup, automatic LAN address selection, independent CA and
code comparison, mismatch refusal and approved pairing were exercised. Actual
Custom MCP Browser nonce read/close passed on both machines. Windows desktop
input and one click have independent file effects; the account model also read
the random paint-only visual marker from its returned screenshot. Mac Computer
Use returned `CAPABILITY_UNSUPPORTED / not_dispatched`; no Mac desktop mutation
was sent. The current installed Custom MCP details were explicitly refreshed
again and retained Styx’s own black ripple Logo; screenshot and observation are
under `candidate-15/account-logo-refresh/`. C15 Exec, complete lifecycle and
revoke/restore remain open. C14 passes do not fill those C15 gaps.

Architecture: the revoked initial WSS admission correction is included in C15.
The Mac Computer source bootstrap failure is a separate unconfirmed cause; a
running Cua process and advertised capability do not prove a ready provider.

Integration: the frozen C15 unified quality receipt is PASS with unchanged inputs
and source revision. Both native packages were produced from the same archive
`f7adb5b586431f2ce096a35fdd8b40699274dace47f95ac964d229f307b26b18`.
The owner requested device-local Codex work to replace serialized SSH/UI
round trips. [Client leases](CLIENT-ACCEPTANCE-LEASES.md) assign disjoint devices
and evidence paths; shared source and Git remain integrator-owned.

Release: Mac build 1126 DMG SHA-256 is
`7b6708727f986f738a3b402a09f76aa1bc028231b857bacfd9aec5cb2d8d3a9d`;
Windows Inno 0.4.20261107.15 SHA-256 is
`49eeb80ddb0e4143c1c216520906d1915a4644546cd8b5d2e501b21a6789c19f`.
Verified delivery copies and provenance are under `candidate-15/deliverables/`.
Mac uses its original local signing identity, without Developer ID/notarization;
Windows is an unsigned outer preview with verified signed Runtime. Installation
does not imply complete account acceptance or a Stable release.

Reliability: the old C14 J processes exited after one unclean normal Quit. A
subsequent attempted UI-only termination found the process already absent and
had no force effect. The original raw failed receipt and independent correction
are retained in `candidate-15/installed-evidence/old-J-exit-correction.json`;
this supersedes the earlier statement that the old J App remained running and
does not relabel that exit as a clean lifecycle pass. New C15 native acceptance
owners must retain original process identity and avoid replaying uncertain work.

Decision: proceed with parallel native client diagnosis/acceptance, then coordinated
account and recovery work. Final GUI delivery and Stable remain NO-GO. Evidence:
`/home/sid/Developer/Artifacts/Styx/20261107-gui-convergence/candidate-15/`, with
device-local reports in the lease directories. Local Codex startup is execution
evidence only, not a new native acceptance pass.

## C15 local-owner results and bounded startup visibility correction

Product: the Mac local owner performed a normal GUI Quit and one reopen. All
five original App/Core/Cua/worker identities and the old listener/socket exited
before reopening. Device identity, configuration, binary identities and private
credential equality were retained. Actual account Computer then read the exact
fixture, set its input once and pressed its button once; independent effects
matched, including the paint-only `VIEW-MAC-47E23B` screenshot oracle. Actual
Exec continued the original live PID across separate account turns with one
nonempty stdin line, exit 0 and independent file/process confirmation. Browser
nonce navigation/read/close also passed after reopen. These establish recovered
C15 behavior; the original cold-start failure cause remains unproven.

Architecture: App previously discarded the typed `computer_unavailable` startup
event. The source correction retains its fixed code as optional private App
status `foreground.computerStartupError`, independent of Exec transport events.
It clears with the original Host's stop/new start and grants no admission or
cleanup authority. Both native settings views show a normal Quit/reopen recovery
instruction when that explicit optional-lane failure exists. This is visibility
and guidance, not a claim to have corrected the original initialization cause.

Integration: incremental `styx-runtime` check (8 jobs, existing cache) and existing
App lifecycle/refusal/role controls passed. Mac Swift typecheck and Windows C#
compile-only passed; neither installed C15 App was changed. The next same-source
quality checkpoint and candidate acceptance remain required. No extra test count
is claimed as a platform effect.

Release: installed C15 remains immutable. The stale Windows enrollment guidance
correction and optional Computer failure visibility are source-only pending the
next candidate. Normal Mac lifecycle after all successful tool effects plus the
saved-key edit are assigned to the same local owner, with no active account work.

Reliability: NAB5's local owner independently matched its one existing click,
input, paint-only visual oracle and one original Browser request. It found one
App with legitimate Core descendants. Its lifecycle did not run: the test-profile
root has two extra Codex sandbox grants; only one root node is affected, and the
original ACL is saved. Automatic review rejected removing those grants pending
specific owner approval. No permission repair occurred. NAB5 was disconnected
after the coordinated Gateway reopen and must be recovered through that boundary,
then complete account Exec, lifecycle and revoke/fresh-pairing acceptance.

Decision: parallel local work produced independent effects and physical lifecycle
evidence. Continue the full final-candidate journey; delivery and Stable remain
NO-GO. C15 evidence is in `candidate-15/local-client-owners/`,
`account-browser-desktop-observation/`, `account-logo-refresh/` and the device-local
lease paths. Startup visibility checks are in `startup-failure-native-checks/`.

## Windows public installation reader correction

Product: the owner approved removal of exactly the two test-only sandbox grants
on the NAB5 acceptance profile. The original private ACL was backed up; only its
root changed, retaining Sid, SYSTEM and Administrators. The profile now has three
protected grants. Normal bundled CLI control still refused before sending a
request because it incorrectly required public installed files to be private.

Architecture: public metadata and managed App bytes now use the existing local
image modification boundary with retained namespace/file handles, bounded reads
and digest checks. Ordinary read access is permitted. Private profile policy,
PE64 executable admission, actual server PID/birth/SID/image binding and the C#
server's exact bundled-caller path gate remain enforced. An unbundled test caller
was correctly rejected before Hello; that invalid positive reference was removed.

Integration: native Windows compile and the actual-filesystem read/write ACL,
bounded-read, sharing, modification-refusal and recovery scenario passed in
`windows-public-install-check-2/`, source archive
`44e323ee862cfce13694ba1b6f7a51cc8b052685ef48a4671dd1408072d10df1`.
The Windows local owner continues with the real tray menu, not a protocol bypass.

Release: installed C15 remains unchanged. C16 unified quality passed and its Mac
Core compiled, but C16 was not packaged or installed; the public-reader correction
requires a new same-source candidate before final installation acceptance.

Reliability: the failed development control references sent no normal Quit.
Original Windows process closure and reconnect remain pending. The Mac local
owner subsequently verified saved-key editing and a second normal post-tools
Quit/reopen; independent same-machine key comparison retained the original bytes.
Neither those C15 passes nor native ACL tests establish final-candidate acceptance.

Decision: complete real Windows lifecycle, integrate the bounded reader fix and
produce the next immutable candidate. Full GUI delivery and Stable remain NO-GO.

## Native tray outcome and public signed Runtime closure

Product: the NAB5 owner identified the original NotifyIcon by its actual
PID/HWND/icon ID, correlated the visible overflow icon and invoked its real
owned `Quit Styx` menu once. Original App/Core/conhost physically exited with
codes 4/2/0. This is an unclean shutdown, not lifecycle acceptance. One authorized
reopen retained the same installation/profile but failed package verification
before a Core started. No Retry, setup, force stop or duplicate launch followed.

Architecture: signed Runtime verification had the same confidentiality mismatch
as outer App control: its public publisher, payload and worker readers used
`PrivateRoot`. A distinct `PublicInstallationRoot` now exposes only reads,
identity, retained-file pins and inventory. Its Windows backend carries the
protected-modification policy through namespace reads, snapshots and image pins.
Staging accepts a narrow read-source port; destinations and every configuration
writer remain private. Signatures, exact closure membership, file identities,
PE64 and suspended process admission still apply. Snapshot revalidation also
rechecks the installation root/ancestor policy. The unused private-file pin
facade was removed; no public installation writer is exposed.

Integration: the native development snapshot
`6b7a850224f9ed73ef808f9314b63910c379dc524f4ba8b1cb8f4f7fb008a2c2`
passed Windows compilation, the extended real-filesystem ACL/refusal/recovery
scenario and untouched C15 installed signed-closure verification: 2156 members,
all worker image pins, selected reopening and wrong-publisher refusal. Evidence
is under `windows-public-payload-check/` and the local owner Phase9 directory.
The subsequent root-policy recheck and dead-facade removal require the next
exact-source checkpoint. The affected Linux signed staging/exclusive failed
publication scenario passed; this is not Windows GUI or account acceptance.

Release: C17 unified quality and its Mac native Core build passed. The later
Windows signed-reader correction supersedes C17 before App packaging; no C17
final App or Windows producer was dispatched. Final packages must share the
next immutable source. Existing installed C15 remains unchanged.

Reliability: actual tray and failed-reopen receipts are retained under
`candidate-15/local-client-owners/windows-phase8/`. The old failure is not
relabelled by successful package reads. Current NAB5 has one blocked App4460
and no Core; account Exec/reconnect, clean lifecycle and revoke/fresh pairing
remain open. PilotMac retains its independently verified recovered C15 state.

Decision: finish exact-source checks, produce both native packages locally and
repeat the full installed journey. Delivery and Stable remain NO-GO.
