# Styx @VERSION@

Styx connects ChatGPT to your Windows, macOS and Linux computers through one
Gateway. Each computer decides locally whether to enable commands, Browser
Automation and Computer Use. One conversation can use several computers;
several conversations can use the same computer.

## Changes

This release candidate builds on `0.8.1-rc.6` (Phase 2A/2B/2C convergence,
15s Desktop freshness / 30s TTL, Windows modularization, and Android Host
branding/hardening) with two targeted fixes:

- **Desktop local Gateway + Host upgrade & reboot recovery**: Passes the
  verified bundled App runtime candidate when inspecting the local Gateway
  binding in `HostApp::open_native` (`inspect_gateway_binding_for_app_retained`),
  preventing single-machine desktop hubs (`create_local` + `join_existing`) from
  latching `unknown` after an App upgrade or a macOS APFS `st_dev` change on
  reboot while keeping the exact same-publisher SPKI pin check.
- **Android `MainActivity` `scrcpy` compatibility**: Replaces blanket
  `FLAG_SECURE` with API 33+ `setRecentsScreenshotEnabled(false)` so live
  `scrcpy` mirroring renders `MainActivity` normally without breaking fixed
  release signing; the invitation short-code field remains password-masked and
  is cleared immediately on submit.

Wire protocols are unchanged from `0.8.1-rc.6` (`computer_v3`, 39 MCP tools);
hosts already running `0.8.1-rc.6` remain compatible. Update both Gateway and
desktop Hosts together when upgrading from `0.8.1-rc.4` or earlier. Existing
profiles, identities, pairing and capability grants are preserved.

### Android package availability

The four downloads below update Gateway and desktop Hosts. A signed Android APK
is not published in this Release because CI Android signing secrets are not yet
configured; local fixed-key signed APKs can be built and verified via
`src/ci/release-android.py` and upgraded in place when signed with the same
keystore. Existing accepted Android Hosts continue working with the updated
Gateway using the same pairing and permissions.

## Choose your download

| System | Download | Role |
| --- | --- | --- |
| Windows x64 | `Styx-@VERSION@-windows-x64.exe` | Host, with an optional local Gateway |
| macOS Apple silicon | `Styx-@VERSION@-macos-arm64.dmg` | Host, with an optional local Gateway |
| Linux x86_64 desktop | `styx-@VERSION@-linux-x86_64-desktop.tar.gz` | Host, with an optional local Gateway |
| Linux x86_64 server | `styx-@VERSION@-linux-x86_64-gateway-only.tar.gz` | Gateway only |

## Install and connect

**Windows:** run the installer, then open Styx from the Start menu.
**macOS:** open the disk image, copy Styx to Applications, then open it.
Choose to join your existing Gateway or set up a local Gateway and this computer.
Desktop Gateway setup includes the ChatGPT Tunnel configuration.

**Linux:** extract the matching archive, enter its folder, then run `./install.sh`.
The installer retains the program in your user data directory and starts setup.
You can remove the downloaded archive and extracted folder after installation.
Linux uses a terminal setup wizard and systemd user services. For a headless
Gateway to remain running after logout, enable linger for its service account
when setup requests it. Browser and desktop Computer Use require a logged-in
graphical session.

On the Gateway, run `styx invite` (or use its invitation screen). On the joining
computer, enter the Gateway address and one-use pairing code. The computers must
already be able to reach that address; Styx does not configure your VPN or routing.
An invitation admits a computer. It does not grant its capabilities: those are
selected on the Host itself.

Connect ChatGPT once, using the Gateway's Tunnel. On macOS, grant Styx the
Accessibility and Screen Recording permissions needed for Computer Use.

## Existing installations

When upgrading from official 0.5.x releases, update the Gateway and its Hosts
together. The Browser capability protocol changed in 0.6.0; an older Gateway
will not recognize the new Host's Browser capability.

Quit the desktop App, install the complete new package, then reopen Styx from
its installed location. The App uses the Runtime included in that bundle.
On Linux, run the new package's `./install.sh` to update the existing installation.
Keep the existing profiles, identities, pairing, keys and publisher pins, and
retain the prior working package until the new installation is verified.

Closing a desktop window leaves Styx in the tray/menu bar. **Quit Styx** stops
its local tasks and connection. On Linux use `styx quit` and `styx start`;
`styx uninstall` removes its user services while retaining configuration.

## Package verification

Runtime payloads use the existing Styx publisher signature. `SHA256SUMS` covers
all four downloads; `styx-publisher.pub` contains the public publisher key.
Packages contain no paired device profile or private key.

The Windows installer is not Authenticode signed. The macOS App uses the
existing local signing certificate and is not Developer ID notarized. These
packages do not claim operating-system publisher trust.
