# Styx @VERSION@

Styx connects ChatGPT to your Windows, macOS and Linux computers through one
Gateway. Each computer decides locally whether to enable commands, Browser
Automation and Computer Use. One conversation can use several computers;
several conversations can use the same computer.

## Changes

This release candidate repairs native Desktop text input on Linux/Hyprland
with Lua dispatch (validated on Hyprland 0.57.1).
The new `type_text` tool inserts text at the caret in a freshly observed editable
control. Callers explicitly select foreground delivery, which permits activation
of the target window. It can interrupt work in the foreground and does not
restore the previous focus. The native worker checks the exact process, window
and focused editable element before every keystroke.

Strict `set_value` remains an exact native replacement operation. When an
application such as Chrome does not expose AT-SPI EditableText, Styx reports
Unsupported instead of incorrectly reporting an OS permission denial. It does
not switch from a failed setter to keyboard input. Unknown input outcomes are
preserved and must be inspected before any further action.

Host input admission uses keyboard availability from the same native worker,
including the Wayland virtual keyboard protocol. Existing owner, observation,
capability and once-only dispatch checks remain in the normal Core/Host route.

Update both Gateway and the Linux Host. Gateway advertises `type_text`; the Host
and its bundled native worker execute it. Refresh the existing ChatGPT Styx
connection's metadata after the Gateway update, then use a fresh conversation
to verify that the tool is exposed. This candidate's installed public MCP input
acceptance is recorded separately from its source and native-component tests.

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
