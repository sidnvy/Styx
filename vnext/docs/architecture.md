# Styx VNext — one product, one cross-platform native Cua provider

          ChatGPT (planning)
                  |
           MCP Streamable HTTP
                  |
             Styx Gateway
           target + ownership
              /       \
     Codex Exec        Cua MCP Driver
     Process/PTY       Computer Use
              \       /
          Native Host OS
        macOS/Linux/Windows

No second reasoning agent. Coder is absent from the new dependency graph.
Existing Charon is used only for temporary bootstrap and native acceptance
until the independent Styx transport has passed tests.

## Execution and computer-use boundaries

The Codex Exec Server owns process RPC, PTY and filesystem. Gateway exposes
Codex-shaped exec_command and write_stdin with environment_id. The Cua Driver
owns accessibility, screenshots, UIA/AX/AT-SPI and native action results.
Gateway passes native Cua MCP calls and their official schemas unchanged
except for one optional environment_id. Native GUI sessions and screen
snapshot tokens are distinct from process sessions.

The native Cua 0.36.0 schema differs among macOS, Linux, and Windows:
get_window_state requires window_id for macOS/Windows but only pid on Linux;
Linux-only coordinate_frame, platform-only action and differently shaped
count/capture_id are not published by the common model-facing surface.
The portable contract was generated from the actual three-OS tools/list
responses and is checked against all three native runtimes. Do not fake
portability by publishing fields that only one OS accepts.

## Native session identity

macOS: A signed Styx.app with stable bundle identifier must own
Accessibility and Screen Recording TCC permissions and the Embedded Cua
driver. Standalone read-only Cua mcp --direct is not a substitute for this.
Linux: Cua runs inside the user graphical session; Hyprland XWayland and
Wayland owned Zenity button tests have passed, including screenshot and
independent exit-code readback.
Windows: Cua MCP has started and responded in the same interactive desktop
session as Explorer. An owned scratch GUI action test is still pending.

The Gateway keeps one native Cua MCP Client per authenticated MCP owner
and environment. Other owners cannot reuse its implicit native session.
Only catalog-allowed targets may execute. Model arguments cannot set
credentials, endpoints or permission grants. The native Cua result does not
constitute proof of desired application state without independent readback.

## Still open

Native Host outbound WebSocket for Codex Exec now works in isolated tests.
Remaining: full Host fleet bootstrap and signed distribution;
Windows GUI action/readback; signed/notarized macOS app;
real ChatGPT MCP registration; long-process recovery; optional browser
provider. These are release gates, not claims of passing tests.
Production Styx, Charon, Coder, and Tunnel are untouched.


## Outbound Host transport VNext milestone

Styx Gateway registers pre-admitted Host IDs and independently held Host
tokens. A Host connector makes a single outbound authenticated WebSocket
connection to the Gateway, then forwards unmodified Codex Exec JSON-RPC
between that socket and one supervised local Codex Exec Server stdio child.

The Gateway owns connection/session identity; Host-side Codex owns the
processes. A broken connection terminates that bridge and loses old process
identity without automatic replay. Host connector retries new connections
with bounded backoff, but a new connection always creates a new Exec
session. See docs/outbound-host.md.

Cua is NOT tunneled by this first milestone; it remains a separate native
MCP transport, independently authenticated and bound to the GUI session.


## Computer outbound lane

A dedicated /computer WebSocket carries native Cua MCP JSON-RPC (one stdio
Cua process per connection) while /exec carries Codex Exec JSON-RPC.
No new Computer Use action protocol exists inside Styx. Host admission,
authentication, generation binding, heartbeat and connection limits are shared
at the transport edge; session ownership is not shared between Exec and GUI.

The Gateway allocates one Cua MCP transport to each authenticated model-side
session and never returns it to another owner. Model inputs cannot set Cua's
native session label: Cua uses its authenticated transport lease. A
reconnected Host creates a fresh native worker and never revives previous
desktop tokens.

On macOS a signed Styx.app owns the embedded native Cua daemon; the Host
Connector only proxies to its socket. On Windows and Linux Cua mcp directly
owns its worker in the interactive session. The Windows/Hyprland native
Driver acceptance gates remain separate from MCP compatibility.
