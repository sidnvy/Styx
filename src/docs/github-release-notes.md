# Styx @VERSION@

Styx connects ChatGPT, Gemini, and other MCP OAuth clients to your Windows,
macOS, Linux, and Android devices through one Gateway. Each computer decides
locally whether to enable commands, Browser Automation and Computer Use. One
conversation can use several computers; several conversations can use the same
computer.

## Changes

Styx `0.8.8` hardens the Chrome Extension CDP relay around strict structural invariants on top of the `0.8.7` baseline:

- **Strict per-session FIFO CDP ordering (`cdp_relay`)**:
  - Replaces unordered per-message task spawning with dedicated per-`sessionId` FIFO workers so protocol sequences such as `Page.getFrameTree` and `Runtime.enable` never reorder on heavy or multi-frame tabs.
- **Cancellation-safe RAII tab ownership & bounded teardown (`cdp_relay`)**:
  - Cancels in-flight `attach_tab` work immediately on relay disconnect, rolls back partial attachments, and runs concurrent `detach_and_cleanup_tab` calls before releasing `ExtensionPeer` ownership so interrupted connects never leak `chrome.debugger` sessions.
- **Lazy non-blocking indicator & focus emulation + extension hardening**:
  - Defers visual indicator injection and `SharedExisting` focus emulation off passive attach onto active CDP commands so `browser_tabs(action="list")` / `list_pages` never stalls behind hung tab scripts.
  - Excludes Chrome Memory Saver `tab.discarded` tabs from attachable tab lists and self-recovers only self-owned `"already attached"` `chrome.debugger` states.
- **Previous `0.8.7` & `0.8.6` baseline**:
  - Reconnecting local CDP discovery proxy (`styx host browser-extension cdp-proxy`), idle WebSocket keepalive `Pong` flushing, active-only Chrome indicator persistence, direct authenticated loopback CDP bridge, and parallel Chrome Tab Groups (`Styx · N`).

All existing Gateway MCP tool names, Host identities, device pairings, browser
profiles, and Android/Windows/macOS release signing identities remain unchanged.

### Android signing & in-place upgrades

`Styx-@VERSION@-android-arm64.apk` is signed with the fixed Styx Android release
key (APK Signature Scheme v2/v3, 16 KiB ELF aligned, SHA-256 certificate
fingerprint `a83c569e96981ce31d6ad50dace6094c1f644be7b0a09c3fe84addc74af4b7b3`).
Devices already running a fixed-key release APK can upgrade in place without
re-pairing or re-granting permissions.

## Choose your download

| System | Download | Role |
| --- | --- | --- |
| Windows x64 | `Styx-@VERSION@-windows-x64.exe` | Host, with an optional local Gateway |
| macOS Apple silicon | `Styx-@VERSION@-macos-arm64.dmg` | Host, with an optional local Gateway |
| Linux x86_64 desktop | `styx-@VERSION@-linux-x86_64-desktop.tar.gz` | Host, with an optional local Gateway |
| Linux x86_64 server | `styx-@VERSION@-linux-x86_64-gateway-only.tar.gz` | Gateway only |
| Android arm64 | `Styx-@VERSION@-android-arm64.apk` | Host (phone) |

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
all five downloads; `styx-publisher.pub` contains the public publisher key.
Packages contain no paired device profile or private key.

The Windows installer is not Authenticode signed. The macOS App uses the
existing local signing certificate and is not Developer ID notarized. These
packages do not claim operating-system publisher trust.
