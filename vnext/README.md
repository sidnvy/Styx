# Styx VNext — unattended three-OS developer preview

**Scope: macOS, Linux (including Hyprland), Windows. No iOS.**

One Styx project, two deployment roles: a model-facing MCP Gateway and native
Styx Host execution processes. ChatGPT is the sole reasoning/planning layer.
This is an additive preview under vnext/, not a replacement for deployed
Styx/Charon/Coder services.

## Native runtimes

- **Execution:** OpenAI Codex Exec Server, with exec_command and write_stdin.
- **Computer Use:** TryCua Cua Driver 0.36.0, using original MCP tool names and
  input schemas. Styx adds only the optional environment_id routing parameter.
- **Portable tools:** list_apps, list_windows, get_window_state,
  get_desktop_state, click, set_value, type_text, press_key, scroll,
  verify_state.
- **Browser:** separate Playwright/CDP decision; not implemented. No iOS.

The portable schema is generated from official live Cua v0.36.0 tool
declarations captured on macOS, Linux and Windows. Fields that differ between
platforms are excluded. Native Cua always performs final action validation.
Native screenshot/session handles are not Codex Exec process session IDs.

## Test results, October 17 2026

| Test | Result |
| --- | --- |
| Native Cua 0.36.0 MCP init, discovery and schema on three OS hosts | PASS |
| Linux Hyprland XWayland owned scratch window screenshot/AX/click/readback | PASS |
| Linux Hyprland Wayland owned scratch window screenshot/AX/click/readback | PASS |
| macOS Styx.app Embedded Cua owned scratch window | PASS in prior isolated pilot |
| Windows Cua MCP on interactive session | PASS read-only |
| Windows owned scratch GUI mutation | PASS, isolated Edge Profile + system UIA readback |
| Real Codex Exec through authenticated Gateway MCP | PASS, Linux loopback |
| Host Outbound WebSocket, signed distribution, ChatGPT product integration | NOT RUN |

The actual native binaries were staged in private temporary directories and
official checksum files were checked. No package-manager or system-level
installation occurred. No unrelated application was touched.

## Developer tests

Requires Node.js 22+, Python 3, and Linux x86_64 for pinned Codex binary test.

    cd vnext
    npm ci --ignore-scripts --no-audit --no-fund
    python3 packages/styx-exec-adapter/prepare-runtime.py
    npm run test:all
    STYX_LIVE_EXEC_TEST=1 npm test

GitHub Actions also runs Cua MCP protocol/schema tests in ubuntu-24.04,
macos-15 and windows-2025, downloading pinned official archives and checking
the SHA256 digest before running a headless schema-only smoke test. This is
not a native GUI action test on CI runners.

Native Cua smoke example after supplying a verified absolute executable:

    DO_NOT_TRACK=1 STYX_CUA_PORTABLE_MANIFEST=./gateway/cua-portable-0.36.0.json STYX_CUA_SCHEMA_ONLY=1 node host/native-cua-smoke.cjs /absolute/path/to/cua-driver

On macOS, STYX_CUA_DIRECT=1 is permitted only for read-only native smoke. For
GUI action, a signed, TCC-authorized Styx.app must own the Embedded Cua runtime.
Do not assume standalone macOS MCP inherits the GUI application's privileges.

To update the Cua version deliberately, capture official tools/list on all
three operating systems into non-committed host/fixture-cua-OS.json inputs,
review versions and generate using node host/generate-portable-cua.mjs.
Run all unit, integration and OS checks. Never silently pull latest binaries.

## Starting a local test Gateway

Use config/targets.example.json only as an example; all endpoints are
placeholders and there are no committed credentials. Save a private configured
catalog and strong mode-0600 inbound bearer token. Then run:

    STYX_MCP_TOKEN_FILE=/path/to/token node gateway/cli.mjs /path/to/targets.json

By default MCP listens on 127.0.0.1:8795/mcp. The Gateway does not start a
Host daemon or provision any Cua/Codex executors. Direct WSS and native Cua
HTTPS MCP require independently configured, authenticated endpoints.
Never expose an unauthenticated plaintext remote RPC endpoint.

Unattended native tests create only owned scratch GUI windows. If session,
permission, driver, or fixture is unavailable the outcome is BLOCKED, not PASS.
Production deployment, OS permission changes, Tunnel changes, Coder/Charon
migration and access to personal applications are explicitly excluded.


## Outbound Host execution (implemented in preview)

The Gateway now accepts one authenticated Host-originated WebSocket per
admitted Host ID. The connector supervises a local pinned Codex Exec
Server over stdio and forwards its native JSON-RPC byte frames with no
secondary execution protocol. The Host needs no inbound port or Coder.

The model tools remain exec_command / write_stdin with environment_id.
Use host/config.example.json, host/prepare-codex.py, host/doctor.mjs and
host/connect.mjs for isolated bootstrap, then configure a Gateway target
with exec.transport set to outbound and a strong per-Host token_file.

Actual Codex process, PTY, input and disconnect/reconnect tests run via
the authenticated Gateway MCP and Host connector in separate OS processes.
TLS/WSS termination supports an operator-supplied private certificate.
Native Cua-outbound access is not part of this milestone: the existing
separate private Cua MCP connection remains necessary.

See docs/outbound-host.md. No production rollouts occurred.

Outbound Host identity can use either a private bearer token or certificate-pinned WSS mTLS. See docs/outbound-host.md.


## New milestone: Cua native MCP over outbound Host WebSocket

The same installed Styx Host Connector can open a bounded pool of outbound
Computer connections alongside its Codex Exec connection. Computer WebSockets
carry unmodified native Cua MCP JSON-RPC, not shell commands or Styx desktop
RPC. Each ChatGPT MCP session claims one dedicated Cua stdio worker.
Native Cua remains the final authority over screen, UIA/AX and input.

The Host configuration optionally contains:

    "computer": {
      "enabled": true,
      "binary": "/absolute/path/to/cua-driver",
      "connections": 2
    }

and the matching Gateway target has:

    "computer": {
      "enabled": true,
      "transport": "outbound",
      "max_connections": 2
    }

For macOS the Host computer configuration MUST include an absolute socket
path for a running Styx.app-managed embedded Cua daemon. The generic Host
Connector will not silently launch an unprivileged macOS GUI worker.

Cua tool schemas remain pinned to portable v0.36.0. The model-facing
session field is hidden: Host and Gateway bind implicit native sessions to
distinct authenticated MCP connections. Mutating GUI calls interrupted
by transport loss are marked uncertain and never automatically retried.

With the verified Cua binary present at its isolated pilot path:

    STYX_LIVE_CUA_TEST=1 npm test

See docs/outbound-computer.md and gateway/test/computer-outbound.test.mjs.


## Documented native Cua behavior and unattended Wayland acceptance

Cua v0.36.0 is the source of truth for macOS, Linux and Windows native tools.
Before changing a Cua-related execution path, consult the tag-pinned
docs/cua-0.36-source-contract.md and the linked official source files.

Linux native Wayland support explicitly requires the trusted Host environment
setting CUA_DRIVER_RS_ENABLE_WAYLAND=1, per Cua's platform support documentation.
The Styx Host example config provides this opt-in. With the setting present,
a real Cua 0.36.0 MCP process was able to find an owned Hyprland Wayland
test window, capture PNG + accessibility tree, click its observed button and
independently verify exit code zero over Styx's outbound Computer lane.

For unattended owned-window acceptance on a Linux graphical Host, first
prepare the official checksum-verified Codex/Cua binaries, set
STYX_CUA_NATIVE_BINARY to the absolute Cua executable path, then run:

    npm run test:native:cua

This is an **explicitly opt-in** real GUI test which only operates on its own
scratch Zenity dialog; it fails BLOCKED when the native graphical session or
binary/fixture is unavailable. It does not start an unattended production
daemon, change the compositor, modify host TCC/permission grants, or touch
personal application windows.

The Gateway uses a model-session-scoped Cua Transport Lease. An explicit MCP
session DELETE frees it immediately; an abandoned idle lease is reaped after
five minutes to avoid exhausting the Host's small native connection pool.
This is Styx resource management, not a replacement for Cua's own session
semantics. The original MCP SDK Client.close() by itself does not send DELETE.
