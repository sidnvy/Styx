# Cua 0.36.0 integration contract — source-backed verification

This file records findings from the exact official Cua Driver release tag
`cua-driver-rs-v0.36.0` used by Styx VNext. The GitHub links below are to
versioned sources, not a paraphrase of newer documentation or a guessed API.

## Documented upstream behavior

1. **Native entrypoint:** `cua-driver mcp` serves MCP over stdio. On
   Windows/Linux the MCP process owns its runtime and shuts down at stdin
   EOF. macOS defaults to CuaDriver.app proxying. A daemon can instead be
   reached through `mcp --socket <private-endpoint>`. [CLI reference](https://github.com/trycua/cua/blob/cua-driver-rs-v0.36.0/docs/content/docs/cua-driver/reference/cli/mcp.mdx)
2. **Transport-scoped implicit session:** unnamed calls reuse the MCP
   transport's implicit session. A new connection creates a different lease.
   Native Cua expires idle implicit sessions after **five minutes**; old
   element tokens become invalid. Named sessions require their explicit
   label on later calls and are not an authorization mechanism.
   [Process model](https://github.com/trycua/cua/blob/cua-driver-rs-v0.36.0/docs/content/docs/cua-driver/concepts/how-cua-driver-works.mdx),
   [session tools](https://github.com/trycua/cua/blob/cua-driver-rs-v0.36.0/docs/content/docs/cua-driver/reference/mcp-tools/sessions.mdx)
3. **Daemon-backed proxy:** when launched with `mcp --socket` the proxy
   maintains one long-lived daemon control connection for the full proxy
   lifetime while ordinary calls can use short-lived connections. Control
   disconnect triggers native session cleanup. An alive-but-idle daemon
   proxy is not guaranteed to be reaped merely because no tools are called.
   [proxy.rs](https://github.com/trycua/cua/blob/cua-driver-rs-v0.36.0/libs/cua-driver/rust/crates/cua-driver/src/proxy.rs)
4. **macOS Embedded:** the TCC-authorized signed Styx.app must spawn
   `cua-driver serve --embedded --socket` itself. A generic Gateway cannot
   inherit those permissions. A gateway-side MCP client can connect via
   `cua-driver mcp --embedded --socket` to the **app-owned** daemon.
   [Embedding.md](https://github.com/trycua/cua/blob/cua-driver-rs-v0.36.0/libs/cua-driver/rust/Skills/cua-driver/EMBEDDING.md)
5. **Native Linux Wayland:** `CUA_DRIVER_RS_ENABLE_WAYLAND=1` is an
   explicit opt-in. Without it, the driver uses XWayland routes, which
   cannot discover every native Wayland window. Hyprland itself is listed
   as experimental and the optional Hyprland plugin is not part of the
   portable Driver binary. [Platform support](https://github.com/trycua/cua/blob/cua-driver-rs-v0.36.0/docs/content/docs/cua-driver/concepts/platform-support.mdx)
6. **Window actions:** identify a precise window with `list_windows`
   filtered by pid or app; use `get_window_state` to obtain screenshot,
   Accessibility elements and one-use element tokens. Use `click` on
   that exact observed target. The tool result is not proof of the
   resulting application state: verify independently after an action.
   [window tools](https://github.com/trycua/cua/blob/cua-driver-rs-v0.36.0/docs/content/docs/cua-driver/reference/mcp-tools/window-state.mdx),
   [click](https://github.com/trycua/cua/blob/cua-driver-rs-v0.36.0/docs/content/docs/cua-driver/reference/mcp-tools/click.mdx)
7. **MCP revision:** native Cua stdio supports modern `2026-07-28`
   and the legacy `2025-06-18` initialize flow. Styx currently uses
   the compatible legacy profile of its pinned MCP SDK; no unreviewed
   metadata or extra tool protocol is injected. [MCP protocol](https://github.com/trycua/cua/blob/cua-driver-rs-v0.36.0/libs/cua-driver/docs/mcp-protocol-and-skills.md)

## Additional MCP SDK finding (not a Cua driver requirement)

In the locked Styx MCP SDK 1.30.1,
`StreamableHTTPClientTransport.close()` terminates the local transport but
**does not send an HTTP DELETE**. The separate `terminateSession()` method
sends session DELETE. A test confirmed that `Client.close()` alone did not
release the Gateway's Cua lease, whereas explicit session termination did.
This is a Styx gateway resource ownership issue, NOT a flaw in Cua's native
session implementation.

The Gateway now releases an otherwise abandoned Cua transport after
five **Gateway-idle** minutes (independently of the native Cua session
lifecycle). The resource policy matches Cua's published idle window but
does not attempt to modify native session semantics. An explicit MCP session
DELETE releases it promptly. Reaper never ends a call in progress.

## Observations and limits

- On Workstation with native Hyprland Wayland, `get_window_state` on an
  owned scratch Zenity window returned screenshot and three AX/AT-SPI elements;
  a click on the owned button independently made the test process exit 0.
  This completed through authenticated reverse Cua MCP, with
  `computer.env.CUA_DRIVER_RS_ENABLE_WAYLAND=1` explicitly provided by the
  trusted Host config. Without the opt-in, `list_windows` returned no
  windows for the same kind of native Wayland fixture.
- Reverse Cua connection capacity exhaustion is reproducible when all
  registered MCP leases occupy their Host slots. Styx now identifies it as
  `computer_slots_busy`, rather than the nonspecific
  `computer_transport_unavailable`.
- The older physical cross-host `computer_transport_unavailable` error
  has no surviving complete transport trace. These tests show plausible
  reproducible causes, not proof of that historical event's exact cause.
- Windows native GUI readback and macOS final signed application packaging
  remain separate acceptance gates. No production cutover is implied.

All test-only secrets, screenshot payloads and machine-specific IPs are
excluded from this document.
