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


## Cua upstream lifecycle reconciliation (v0.36.0)

Styx uses Cua's documented implicit transport-scoped Session, not a new
desktop action or session protocol. Native stdio on Windows/Linux owns
the runtime; a macOS Embedded proxy connects with mcp --embedded --socket
to the daemon spawned by the signed GUI app. An explicitly configured
Linux Host opts into native Wayland via CUA_DRIVER_RS_ENABLE_WAYLAND=1.

Styx resource ownership is distinct from native Cua lifecycle: an HTTP MCP
model session may retain a Host Computer WebSocket after Client.close()
because the installed MCP SDK sends DELETE only through terminateSession().
Closing an explicit Gateway MCP session releases the Cua lease. If the model
session is abandoned, the Gateway releases its otherwise idle Computer lease
after five minutes while protecting active tool calls. Native Cua is still
responsible for rejecting old snapshot tokens after session expiry.

See docs/cua-0.36-source-contract.md for upstream source links and qualified
test evidence. A legacy production desktop core is not required by this
design.


## Installer, device pairing and ChatGPT guided UI — PRODUCTION GATE

Before production cutover, use one signed Styx product to onboard native
macOS, Linux and Windows devices through an explicit local-first pairing
process. ChatGPT may offer an intelligent guided setup UI, but the first
installation cannot depend on SSH, Coder Agent, or a previously reachable
Host. Device private keys and native permission approvals belong to the
Host/user; enrollment and Host selection must be authorized and revocable.
A native/CLI fallback is mandatory.

The installer, enrollment control-plane, service supervisors, signed update
and rollback lifecycle are not yet implemented. See
docs/onboarding-installation.md. Production switch requires their separate
cold-install and independent no-OOB recovery acceptance.


## New dedicated pairing and install responsibilities

Gateway enrollment is a small OWNER-authorized control plane, separate from
the ChatGPT-visible Codex Exec and Cua MCP tools. The device establishes
trust locally, obtains an approved per-Host outbound identity, and can be
admitted to the live registry without restarting Gateway. Revocation closes
old Host sockets and excludes the ID from tool discovery.

The Host installer verifies signed release contents, stages versioned
generations and offers safe activation/rollback without modifying any
production OS startup configuration. A separate native service manager will
eventually supervise the stable launcher. ChatGPT guided selection/approval
is a future UI over these deterministic operations, never an AI-managed
secret generation or TCC bypass.

Sources and limitations: docs/enrollment-pilot.md and
docs/onboarding-installation.md.


## Linux signed Host installation role

The managed Linux Host does not execute out of the source checkout or
development node_modules. A trusted, user-scoped installer stages an
Ed25519-signed, versioned Host bundle and a systemd user unit. A stable
bootstrap verifies the publisher signature before launching a generation
and passes the selected native binaries via private one-shot stdin.
The model cannot choose another release or substitute executable paths.

Linux service install/restart/upgrades/rollback/owned uninstall now have
native acceptance. The analogous macOS and Windows production packages,
node runtime bundling, cold first-contact onboarding and ChatGPT visual
device selection remain separate release gates.
See docs/linux-managed-host.md.
