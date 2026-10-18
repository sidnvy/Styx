# Styx VNext acceptance gates — macOS, Linux, Windows only

| Gate | Status | Evidence / qualification |
| --- | --- | --- |
| Catalog allow/deny and Windows paths | PASS unit | gateway/test/registry.test.mjs; exec-adapter/test/windows.test.mjs |
| Authenticated MCP and per-session isolation | PASS integration | gateway/test/http.test.mjs |
| Codex Exec stdout/stdin/PTY | PASS real Linux | packages/styx-exec-adapter/test |
| MCP HTTP -> real Codex Exec WSS loopback | PASS | gateway/test/live.test.mjs, STYX_LIVE_EXEC_TEST=1 |
| Native Cua 0.36.0 MCP | PASS all 3 hosts | host/native-cua-smoke.cjs |
| Portable Cua tool contract | PASS all 3 hosts | generated gateway/cua-portable-0.36.0.json |
| Linux Hyprland XWayland screenshot + AX + click | PASS scratch | host/native-cua-gui.cjs |
| Linux Hyprland Wayland screenshot + AX + click | PASS scratch | host/native-cua-gui.cjs |
| macOS Embedded Cua Styx.app GUI scratch | PASS prior pilot | isolated 2026-10-17 prototype; not repeated in this work |
| Windows Cua MCP on user logon session | PASS read-only | native smoke init / list_apps |
| Windows GUI screenshot / click / independent readback | PASS owned Edge scratch | Cua 0.36.0 screenshot + 10 UIA elements + button click; independent Windows UIAutomation found STYX_CLICKED |
| Three-OS unattended headless CI | PENDING CI | .github/workflows/styx-vnext.yml |
| Host Outbound WS (Codex Exec lane) | PASS isolated loopback with real Codex | gateway/test/outbound.test.mjs, STYX_LIVE_EXEC_TEST=1 |
| Host Outbound WS (Cua MCP lane) | PASS isolated with real Linux Cua 0.36.0 | gateway/test/computer-outbound.test.mjs, STYX_LIVE_CUA_TEST=1 |
| Per-owner Cua transport and GUI uncertain-result behavior | PASS fixture integration | gateway/test/computer-outbound.test.mjs |
| Signed/notarized macOS product | NOT RUN | release gate |
| Physical macOS Host to separate Gateway via private-network WSS/mTLS | PASS bounded native pilot | Real Codex 0.163.0: Shell, stdin, PTY, stdout/exit validation; 2026-10-18 |
| Real ChatGPT -> Styx -> three host execution | NOT RUN | integration gate |
| Browser Playwright/CDP | NOT RUN | separate component |
| Cross-restart process durability | NOT IMPLEMENTED | fail closed |
| Production migration | NO-GO | intentionally excluded |

The three native Cua schemas share tool names but are not byte-identical.
Styx exposes the common compatible field set from native version 0.36.0.
Actions never automatically retry an unknown mutation. The result of a GUI
dispatch alone is not proof of an actual state change.

No production service, user authorization or Tunnel configuration changed.
GO for additive implementation; NO-GO for production cutover.

## Additional Cua v0.36.0 source audit and isolated regression — 2026-10-18

- PASS: tag-pinned upstream CLI, process/session, proxy, embedding, Wayland
  and tool reference contracts checked directly against source.
- PASS: native Hyprland Wayland scratch via Styx outbound Cua MCP:
  list_windows(pid) -> get_window_state(PNG + AX tree) -> click(element_token)
  -> independent scratch process readback exit code 0.
- PASS: Cua Host connection pool separates owners and reports
  computer_slots_busy for lease exhaustion, without inventing generic
  execution errors or replaying uncertain actions.
- PASS: explicit HTTP MCP terminateSession() permits immediate native lease
  release; Client.close() alone does not imply a server-side DELETE.
- PASS: unattended resource cleanup reaps genuinely idle native transport
  leases at five minutes without terminating an active tool call.
- PASS: macOS Embedded Cua stdio proxy uses upstream documented
  mcp --embedded --socket against an app-owned daemon.
- NOT RUN: physical cross-host Cua GUI action acceptance and Windows
  scratch GUI action. The loopback native GUI proof does not imply these pass.

Source documentation and evidence: docs/cua-0.36-source-contract.md.
