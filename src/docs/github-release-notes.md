# Styx @VERSION@

Styx connects ChatGPT, Gemini, and other MCP OAuth clients to your Windows,
macOS, Linux, and Android devices through one Gateway. Each computer decides
locally whether to enable commands, Browser Automation and Computer Use. One
conversation can use several computers; several conversations can use the same
computer.

## Changes

This release candidate builds on `0.8.1-rc.11` with Google Gemini Web & concurrent Browser session stability fixes, on top of opt-in local Browser CDP attachment, Public MCP compatibility, legacy forwarder cleanup, and release CI caching improvements:

- **Gemini Web & concurrent Browser session stability (0.8.1-rc.12)**:
  - Marked interactive and navigation `browser_*` tools `destructiveHint: false` in `PUBLIC-MCP-V1.json` and documented automatic idle/new session allocation plus explicit `"new"` isolated sessions.
  - Bound non-OpenAI `PublicMcp` callers without OpenAI `_meta` to a stable `public-mcp-subject:` owner across `Mcp-Session-Id` rotations while preserving `tunnel-conversation:` correlation for ChatGPT.
  - Enabled multi-profile idle/new auto-allocation, explicit `"new"` isolated sessions, concurrent omitted-ID `browser_navigate` isolation without auto-selecting `existing-browser` (CDP), and visible `browser_session_id` text headers in Playwright action outputs.
- **Opt-in local Browser CDP attachment in Coexist Mode (default OFF)**:
  - Host-local `browser-cdp.json` toggle (`styx host browser-cdp status|enable|disable`, App IPC `hostBrowserCdp`, macOS SwiftUI & Windows WinForms Settings controls), never modifiable by remote MCP/Gateway callers.
  - Supports Chrome 144+ `chrome://inspect/#remote-debugging` (`DevToolsActivePort` auto-discovery) and optional canonical loopback (`127.0.0.1` / `localhost` / `[::1]`) endpoints.
  - Isolated managed browser profiles remain the default (omitting `browser_session_id` never implicitly attaches to the user's browser); when enabled locally, `list_browser_sessions` exposes `existing-browser` (`mode: "cdp"`) for explicit selection and concurrent non-conflicting use alongside isolated profiles, and `browser_close` detaches non-destructively without closing external Chrome or its tabs.
  - Updated `PUBLIC-MCP-V1.json` guidance to prefer `browser_*` over desktop Computer Use for web pages while reserving desktop tools for native apps/dialogs.
- **Public MCP handshake, SSE framing & legacy cleanup**:
  - Return direct `application/json` responses for synchronous handshake and discovery requests (`initialize`, `tools/list`, `ping`, `prompts/list`, `resources/list`, `resources/templates/list`), frame SSE `tools/call` responses cleanly with `event: message` without empty priming events, and route `PrincipalDomain::PublicMcp` cleanly for ChatGPT and Gemini / standard MCP clients.
  - Removed legacy `public-mcp-forwarder.token` fallback and aligned Linux `chromium` channel selection.
- **CI & Release caching optimization**: Shared `main`-scoped release dependency warm caches (`styx-cache-warm.yml`), external-crate-only `Cargo.lock` cache keys (`cache-key.py`), pruned target caching, and full-CPU release builds.

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
