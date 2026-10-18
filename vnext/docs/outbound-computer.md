# Cua MCP over Host-Outbound WebSocket

Status: VNext implementation and isolated real Linux Driver acceptance,
not a production rollout.

## Protocol boundary

Styx Gateway exposes the official portable Cua 0.36.0 tool surface with
optional environment_id; the remote Host owns a separate outbound WebSocket
per native Cua MCP stdio worker. The WebSocket directly carries MCP JSON-RPC.
There is no Styx-specific mouse/keyboard/accessibility protocol, and these
calls are NEVER sent through Codex Exec Server.

- /styx/hosts/ID/exec: Codex Exec JSON-RPC, one Host connection.
- /styx/hosts/ID/computer: native Cua MCP JSON-RPC, a bounded pool.
- Both lanes share the Host's existing outbound authentication (Bearer or mTLS
  public certificate pin). The inbound ChatGPT MCP bearer is independent.
- Each model-side MCP session claims exactly one computer connection per Host.
  The connection is never leased to another model session.
- The native Cua transport lease owns the implicit Cua session. Styx hides the
  client-supplied session field. Element references and native session
  semantics remain owned by Cua.
- On disconnect, every pending MCP request fails. Mutating actions such as
  click and type_text have unknown outcomes; Styx never replays them.
- A later new Host connection must be initialized as a fresh Cua MCP session.
  Expired element references from a prior connection cannot be silently revived.

## Host setup

Gateway target catalog (in addition to exec.transport=outbound):

    "computer": {
      "enabled": true,
      "transport": "outbound",
      "max_connections": 2
    }

Native Host Connector config (in addition to the existing Exec settings):

    "computer": {
      "enabled": true,
      "binary": "/absolute/native/path/to/cua-driver",
      "connections": 2
    }

Host uses native Cua Driver mcp via stdio. Linux and Windows require an
interactive user desktop session for actual UI Automation. Cua is the single
cross-platform Desktop runtime, not three separate Styx Desktop engines.
The Host Connector supervises each child and terminates it when a WebSocket
connection closes.

macOS requires a signed, GUI-session-owned Styx.app with Embedded Cua. The
Host config must also supply the absolute Cua daemon socket path. The generic
Host Connector uses cua-driver mcp --socket to proxy that existing permission
owner; it will not use --direct or launch a GUI daemon under SSH.

All Host paths and credentials live outside Git. The Gateway Host bearer/mTLS
identity and process directory are explicitly registered. The test harness
never provisions user-wide OS services or changes TCC permissions.

## Test evidence

The isolated integration suite exercises:

- Dual-lane Host connectivity over authenticated loopback WS.
- Official MCP initialize/tools/call, unmodified Cua result envelopes.
- Different model sessions attached to distinct native MCP subprocesses.
- Exhaustion of the bounded Host connection pool, with fail-closed errors.
- Native Cua 0.36.0 read-only list_apps through a Host-originated WS.
- Unknown mutation outcome when the native computer transport is interrupted.
- No model ability to specify another Cua transport's session label.

Run in a Linux graphical test environment with a verified isolated Cua binary:

    STYX_LIVE_CUA_TEST=1 node --test gateway/test/computer-outbound.test.mjs

The macOS signed-app and Windows native UIA mutation acceptance remain
separate from this transport test. Native browser use is not included.
Production Charon, Coder, Styx and network rules were not changed.

## Unattended health and acceptance

A missing GUI session, Cua executable, signed macOS permission owner, or
unused outbound slot is BLOCKED/UNAVAILABLE rather than success. Read-only
operations may be retried by a caller after reconciliation. Any uncertain
mutating operation requires a fresh independent observation before a caller
decides whether to retry.


## Native Windows GUI pilot

NAB ran Cua Driver 0.36.0 in its interactive Windows logon session.
A dedicated Edge application window was launched with a brand-new isolated
browser profile and local scratch HTML fixture. Cua returned the screenshot,
10 native UIA elements and the exact button token, and successfully dispatched
the test-only click. A second, independent PowerShell process then queried
Windows UIAutomation for that owned window handle and confirmed STYX_CLICKED.

The Windows Calculator scratch had yielded a screenshot but an empty UIA tree,
so no blind coordinate click was attempted. Notepad was also excluded from
mutation tests because starting it restored previous application tabs, making
it unsuitable as an isolated fixture. No personal document was modified.

This validates a bounded native Windows UIA execution path, not arbitrary
Windows-app reliability, unattended login service packaging, or GUI-over-WSS.
