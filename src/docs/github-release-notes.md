# Styx @VERSION@

Styx connects ChatGPT to your Windows, macOS and Linux computers through one
Gateway. Each computer decides locally whether to enable commands, Browser
Automation and Computer Use. One conversation can use several computers;
several conversations can use the same computer.

## Changes

This release candidate fixes native Desktop actions returning
`UNAUTHORIZED / not_dispatched` after another conversation reads the same Host.
Each owned Desktop resource now retains its own latest accessibility observation
inside its existing resource record. Reading, writing or closing one resource no
longer replaces or consumes another resource's observed targets.
Read-only metadata and screenshot calls also preserve the latest complete
accessibility observation instead of discarding otherwise valid element tokens.

The existing owner, target, permission and once-only dispatch checks remain in
place. The Host does not retry a dispatched action or restore its consumed
observation after an unknown result. Input freshness is checked before dispatch;
an acknowledged click or type_text result is no longer discarded solely because
the original observation expired while that operation was running.
This change does not grant new permissions or alter native input delivery.

Linux/Hyprland `set_value` retains the replacement input support from
0.8.1-rc.2, including empty values and Unicode. Native foreground delivery may
bring the target window forward and focus its field; previous focus is not
restored. The macOS and Windows setter implementations are unchanged.

Update the affected Host to obtain the observation ownership fix. Public tool
names, arguments and the Gateway protocol are unchanged. Existing profiles,
identities, pairing and capability grants are preserved.

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
