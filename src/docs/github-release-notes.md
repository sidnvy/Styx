# Styx @VERSION@

Styx connects ChatGPT to your Windows, macOS and Linux computers through one
Gateway. Each computer decides locally whether to enable commands, Browser
Automation and Computer Use. One conversation can use several computers;
several conversations can use the same computer.

## Changes

This release candidate restores the existing `set_value` operation in ordinary
Chrome on Linux/Hyprland. It replaces the contents of an observed input, including
clearing the field with an empty value, using the same public arguments.

Linux now uses Cua's normal setter instead of the Styx-only strict extension.
When the control has no accessibility setter, native Hyprland input selects all
and replaces the contents. This may bring the target window forward and focus
the field; previous focus is not restored. The existing `type_text` operation
continues to insert at the caret.

The adapter preserves Cua's native result and keeps the existing Computer Use
setting, observed target and operation ownership. Actual native setter errors
are propagated instead of being mistaken for a missing route and retried.
Independent observation confirms the application's resulting value.

Update the Linux Host to obtain the native fix and Gateway to obtain the updated
tool descriptions. The existing `set_value` arguments and tool name are unchanged.
The macOS and Windows setter implementations are unchanged.

### Android package availability

The four downloads below update Gateway and desktop Hosts. A signed Android APK
is not published in this Release. The release APK build and verification path
is now available, but an approved Android signing identity and CI distribution
are not yet configured. The existing accepted Android Host APK can continue using the updated
Gateway with the same pairing and permissions. No phone reinstall is needed for
this Gateway/desktop update.

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
