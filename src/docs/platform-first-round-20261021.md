# Linux and Windows first-round integration

This is a development preview, not a complete installer release. Development
and regression tests run locally. Workstation and NAB are used only for isolated
native checks; existing services, identities, pairing and credentials stay intact.

## Delivered behavior

- Arch/Linux uses the existing Core and CLI for headless Gateway, Exec and Browser.
  `linux-session` reports the observed session and user-manager policy, without
  claiming Computer Use has been verified. No Linux desktop App is introduced.
- Both the service Host and Core foreground path observe the owning user's active
  graphical session. Loss/replacement drains only Computer. Recovery uses the
  same identity. See [Linux lifecycle](linux-desktop-lifecycle.md).
- `browser-select STATE chrome|msedge|auto --authorize` updates the existing
  deployment through its capability transaction. The App API accepts the same
  browser selection and login-persistence fields. No daily browser profile is used.
- Browser operation references remain MCP-session isolated. Optional login
  snapshots are scoped to an authenticated Gateway bearer authority, not to an
  inferred ChatGPT account. Clients sharing a bearer share that login authority.
  Caller-supplied principal metadata is ignored. Bearer rotation starts fresh;
  concurrent snapshots use the last completed save rather than merging state.
  Cookies, local storage and IndexedDB cannot guarantee every site's login stays
  valid indefinitely. Snapshot files are private and atomically replaced.
- Signed Host releases include the installed-browser and login-state modules.
- Windows has a native tray/settings preview backed by the same Core API. A
  package-pinned native probe prevents foreground Computer readiness in session 0
  or an unavailable input desktop. This is a startup check, not continuous
  Windows lock/logout supervision. Failed tunnel saves retain the entered key.
  Package inputs verify the Ed25519 SPKI publisher pin and signed Host payload.

## Verified

| Area | Evidence | Limit |
| --- | --- | --- |
| Local regression | Gateway, Exec, GUI, Host, plugin, onboarding and Browser suites; corrected Mac preview fixture rerun passed | Native opt-in cases skipped by default |
| Chrome | Two real native Browser tests, including HTTP MCP → Gateway → authenticated Host → Chrome, fresh-session synthetic login retention, separate profiles and reference isolation | Test website, not a real account login |
| Arch/Hyprland | Seven real Computer tests; own scratch window observation, screenshot, accessibility read and button action/readback | No real lock/logout/reboot |
| Linux lifecycle | Deterministic session loss/replacement tests and isolated systemd user-unit lifecycle | Does not enable linger; lock hints depend on compositor/logind |
| Windows | Native compilation, self-render, private Core startup, pinned probe refusal from SSH session, ten bridge/package tests | No interactive Cua acceptance |
| Edge on NAB | Installed Edge 155, isolated headless navigation/semantic read and synthetic cookie retention after relaunch; own processes cleaned up | Not the complete Windows MCP chain |

## Remaining release gates

Windows still needs a complete signed Host/runtime payload, TLS and tunnel
components, installer/update integration, bilingual UI polish, login/reboot and
interactive desktop acceptance. The current portable preview reports missing
components rather than claiming setup succeeded.

Linux still needs the distributable CLI/runtime package and complete clean-machine
installation/upgrade/recovery acceptance. Actual logout, reboot and network-loss
recovery remain unverified. A machine without logind can use headless roles but
does not advertise Computer readiness through this implementation.

Neither platform has passed new-user ChatGPT account acceptance. No production
deployment was performed.

## macOS follow-up

PilotMac became reachable at its updated address. Real native compilation caught
and fixed two earlier Swift errors: a field assigned to the wrong decoded model
and duplicate brand-asset type declarations. Native protocol/async self-tests,
Foundation ZIP transport and actual Command-V in ordinary and secure input fields
passed. The `0.3.0-platform-integration.20261021.1` arm64 preview was built using
the existing persistent local signing identity. Its App and Cua identifiers and
designated requirements match the installed version; seven Mach-O signatures and
the signed Host payload verified. New Browser modules load with bundled Node.

The built runtime source tree is `4a687c7a79feff8c1f388e03b92a98850adb630a`
(integration branch `fefc162`, build branch `5a302a1`). This is a locally signed
development preview. Existing installation/configuration were not replaced.
Upgrade permission retention, real reboot and ChatGPT acceptance remain untested;
matching signatures alone do not establish those results. No Chrome/Edge binary
was available on this Mac for a new native Browser website test.
