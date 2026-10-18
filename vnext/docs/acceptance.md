# Styx VNext acceptance gates — macOS, Linux, Windows only

| Gate | Status | Evidence / qualification |
| --- | --- | --- |
| Catalog allow/deny and Windows paths | PASS unit | gateway/test/registry.test.mjs; exec-adapter/test/windows.test.mjs |
| Authenticated MCP and per-session isolation | PASS integration | gateway/test/http.test.mjs |
| Codex Exec stdout/stdin/PTY | PASS real Linux | packages/styx-exec-adapter/test |
| MCP HTTP -> real Codex Exec WSS loopback | PASS | gateway/test/live.test.mjs, STYX_LIVE_EXEC_TEST=1 |
| Native Cua 0.36.0 MCP | PASS all 3 hosts | host/native-cua-smoke.cjs |
| Portable Cua tool contract | PASS all 3 hosts | generated gateway/cua-portable-0.36.0.json |
| Linux Hyprland XWayland screenshot + AX + click | PASS scratch | host/native-cua-gui.cjs |
| Linux Hyprland Wayland screenshot + AX + click | PASS scratch | host/native-cua-gui.cjs |
| macOS Embedded Cua Styx.app GUI scratch | PASS prior pilot | isolated 2026-10-17 prototype; not repeated in this work |
| Windows Cua MCP on user logon session | PASS read-only | native smoke init / list_apps |
| Windows GUI screenshot / click / independent readback | PASS owned Edge scratch | Cua 0.36.0 screenshot + 10 UIA elements + button click; independent Windows UIAutomation found STYX_CLICKED |
| Three-OS unattended headless CI | PENDING CI | .github/workflows/styx-vnext.yml |
| Host Outbound WS (Codex Exec lane) | PASS isolated loopback with real Codex | gateway/test/outbound.test.mjs, STYX_LIVE_EXEC_TEST=1 |
| Host Outbound WS (Cua MCP lane) | PASS isolated with real Linux Cua 0.36.0 | gateway/test/computer-outbound.test.mjs, STYX_LIVE_CUA_TEST=1 |
| Per-owner Cua transport and GUI uncertain-result behavior | PASS fixture integration | gateway/test/computer-outbound.test.mjs |
| Signed/notarized macOS product | NOT RUN | release gate |
| Physical macOS Host to separate Gateway via private-network WSS/mTLS | PASS bounded native pilot | Real Codex 0.163.0: Shell, stdin, PTY, stdout/exit validation; 2026-10-18 |
| Real ChatGPT -> Styx -> three host execution | NOT RUN | integration gate |
| Browser Playwright/CDP | NOT RUN | separate component |
| Cross-restart process durability | NOT IMPLEMENTED | fail closed |
| Production migration | NO-GO | intentionally excluded |

The three native Cua schemas share tool names but are not byte-identical.
Styx exposes the common compatible field set from native version 0.36.0.
Actions never automatically retry an unknown mutation. The result of a GUI
dispatch alone is not proof of an actual state change.

No production service, user authorization or Tunnel configuration changed.
GO for additive implementation; NO-GO for production cutover.

## Additional Cua v0.36.0 source audit and isolated regression — 2026-10-18

- PASS: tag-pinned upstream CLI, process/session, proxy, embedding, Wayland
  and tool reference contracts checked directly against source.
- PASS: native Hyprland Wayland scratch via Styx outbound Cua MCP:
  list_windows(pid) -> get_window_state(PNG + AX tree) -> click(element_token)
  -> independent scratch process readback exit code 0.
- PASS: Cua Host connection pool separates owners and reports
  computer_slots_busy for lease exhaustion, without inventing generic
  execution errors or replaying uncertain actions.
- PASS: explicit HTTP MCP terminateSession() permits immediate native lease
  release; Client.close() alone does not imply a server-side DELETE.
- PASS: unattended resource cleanup reaps genuinely idle native transport
  leases at five minutes without terminating an active tool call.
- PASS: macOS Embedded Cua stdio proxy uses upstream documented
  mcp --embedded --socket against an app-owned daemon.
- PASS: the bounded Windows Edge scratch UIA action and independent
  system readback were previously recorded in the native Windows pilot;
  not re-executed during this source review.
- PASS: the physical macOS-to-Linux cross-host Cua GUI test using an exact
  owned scratch window, PNG + AX snapshot, button action, and independently
  confirmed native scratch exit code 0.
- PASS: self-contained unattended physical acceptance using ONLY Styx
  MCP tools for scratch GUI creation, PID discovery, Cua PNG + AX observation,
  click and independent process-exit readback. Executed four successive
  times on the actual Piermini Gateway -> Workstation Host WSS/mTLS path,
  including the corrected Codex Exec envPolicy. No SSH/Coder Agent in the
  action/test data path.

Source documentation and evidence: docs/cua-0.36-source-contract.md.


## Installation and onboarding release gates — production only

Not implemented or verified: signed per-OS installer and full binary manifest;
local-first trust establishment without SSH/Coder Agent; user device selection
and one-time mutual-auth pairing; ChatGPT-guided onboarding plus native/CLI
fallback; OS permission ownership (stable macOS TCC app identity);
supervised user services on three OSes; reboot/reconnect/upgrade/rollback;
revocation/uninstall; 24-hour unattended soak; real ChatGPT registration and
independent operation without the old control plane.

These are mandatory for production migration, not just paperwork.
Design and threat/acceptance checklist: docs/onboarding-installation.md.


### GUI environment inheritance regression (2026-10-18)

- Codex Exec Server rust-v0.163.0 with no envPolicy uses the exact process/start
  env; therefore a Gateway-provided empty env does not preserve native GUI
  session variables and the unattended scratch fixture was undiscoverable.
- Styx now sets the upstream process/start.envPolicy with an explicit
  platform-specific allowlist for native session essentials. It never
  blindly inherits the Host's key/token/credential variables.
- PASS: real Codex contract test found the Wayland, XDG_RUNTIME_DIR and DBus
  markers in a child process; sensitive canary variables were absent.
- PASS: three repeated additional physical cross-Host native Cua GUI runs,
  plus the original successful run; each had screenshot, three AX elements,
  observed click and independent native exit code zero.
- PASS: authenticated Gateway/Host WSS/mTLS, no Coder execution tools
  involved beyond temporary OOB test-process startup.

Installers, device pairing, upgrade/rollback, login/reboot lifecycle, and
ChatGPT device selection remain independent production gates documented in
docs/onboarding-installation.md.


### Explicit Host restart acceptance (isolated, 2026-10-18)

- PASS: stopped the isolated Linux Host Connector and confirmed its temporary
  Cua/Exec children and WSS sockets exited; the gateway remained running.
- PASS: restarted the Host Connector from an existing OOB test process manager;
  both independently authenticated outbound Exec and Cua connections became
  connected again.
- PASS: a NEW model-side MCP client executed the complete owned-window
  npm run test:physical:cua after reconnect, with PNG, AX tree, observed
  click and independent scratch program exit code zero.
- NOT TESTED: autonomous service-manager restart after machine reboot or a
  disconnected GUI session. The existing OOB manager started this isolated
  test connector and is not the intended production installer/runtime.


## Device pairing and immutable installer pilot — 2026-10-18

- PASS on isolated HTTPS Gateway: private owner invitation, native RSA
  possession proof, full fingerprint approval, unapproved refusal, signed
  request tamper rejection, public-key-encrypted first Host credential,
  device-local decryption and keyed confirmation.
- PASS: one-use and expired requests rejected; secrets and HTTP owner token
  distinct from model MCP token; device revocation terminates live Host
  sessions and survives Gateway restart.
- PASS: newly approved first Host is visible in live MCP tools and
  list_execution_environments without Gateway restart.
- PASS: one native onboarding command can wait until owner approval.
- PASS: offline Ed25519-signed release verification, side-by-side version
  staging, activation, corruption refusal and safe rollback.
- PASS: portable user-level service-plan generation WITHOUT actual OS
  registration.
- NOT RUN: physical two-machine cold pairing without OOB bootstrap.
- NOT IMPLEMENTED: production native signed app/package, keychain-backed
  identity, real ChatGPT onboarding UI, service manager activation,
  reboot/login/startup upgrade and independently verified uninstall.

See docs/enrollment-pilot.md for code and the explicit security boundary.


## Physical first-contact enrollment and revocation pilot — 2026-10-18

PASS: Started a new isolated TLS Gateway with an EMPTY target catalog on
the native macOS Host. A separate native Linux device generated its own new
RSA identity and applied with a single-use invitation. The owner-side
pending list and Host console independently displayed the identical
64-character SHA-256 public key fingerprint.

PASS: An explicit owner approval enabled Exec and Computer capabilities.
The Host received its encrypted initial capability and locally generated a
private host.json and host.token, mode 0600. styx doctor reported
ready_for_exec, a present graphical session and native Wayland opt-in.

PASS: Without restarting Gateway, the newly registered Host established
both authenticated outbound lanes over private WSS. The owner device list
changed from approved/offline to approved/online.

PASS: The pre-existing but fully independent Styx MCP GUI acceptance script
executed a self-owned Wayland scratch dialog using BOTH new device lanes:
Exec created the window, Cua returned screenshot and 3 AX elements, clicked
the observed button, Exec independently confirmed native exit code 0.

PASS: The owner revoked this specific device. Both reverse lanes closed
and further reconnection attempts were denied. After stopping and starting
the Gateway from the unchanged private state directory, device listing
remained revoked/offline and the old Host could not reconnect.

IMPORTANT LIMIT: existing Charon OOB actions still transferred the public
Gateway certificate and one-time invitation and started the isolated native
processes. This is a physical FIRST-CONTACT PAIRING acceptance, not proof of
a signed cold install or ChatGPT UI onboarding without OOB. The Host token
itself was not preprovisioned; it was generated only after explicit approval.

No personal application or production Host registration was modified.
All native execution was restricted to separate temporary test directories.


## Linux managed Host installation pilot acceptance (2026-10-18)

PASS in an isolated native Workstation user context:

- Offline release builder selected only the pinned Codex Exec Server, Cua
  Driver and minimal Node websocket Host implementation. The Ed25519-signed
  manifest covered each file hash/size and target platform.
- Verified stage, activation and owner-scoped systemd user unit install,
  enable/start. Actual managed Host process and both signed Cua/Codex native
  executables ran from the installed version folder, not the Git checkout.
- The managed Host completed real scratch GUI Observe/Act/Verify via its
  outbound channels, including PNG image, three AX nodes, native button
  action and independent program exit code zero.
- Signed upgrade pilot1 -> pilot2 -> pilot3 and stable launcher refresh from
  a verified signed release; explicit normal restart no longer reports a
  false failure.
- Pilot launcher crash injected by SIGKILL; systemd automatically recovered,
  increased NRestarts, and the repaired Host passed GUI acceptance again.
- Signed rollback pilot3 -> pilot2 passed native GUI verification, followed
  by reactivation of the signed pilot3.
- Loss and restoration of the isolated private loopback Gateway caused
  Host outbound disconnect/reconnect WITHOUT restarting the user service;
  the subsequent native GUI test again returned PASS.
- Only Styx-owned unit was removed by uninstall. Reinstallation preserved
  signed releases; enabling/starting it passed native GUI acceptance.
- Signed release retention pruned inactive pilot1 while retaining verified
  pilot3 and previous pilot2; unexpected/untrusted releases block pruning.
- No sudo/system-wide services, other user units, network routes, production
  Coder agents or production MCP endpoints were changed.

Not tested or not implemented: a user-login/reboot test, screen lock and
headless Cua behavior, 24-hour soak, real cold install from a separately
trusted publisher, bundled Node runtime, full native package notarization/
signing, device pairing from a real ChatGPT UI, or production cutover.

The user-scoped Pilot is deliberately NOT the final supported installation.
See docs/linux-managed-host.md and docs/onboarding-installation.md.
