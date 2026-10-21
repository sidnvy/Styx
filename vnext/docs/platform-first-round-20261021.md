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
deployment was performed. The preceding macOS follow-up also still requires its
native build and regression; passing a packaging fixture is not a Mac build.
