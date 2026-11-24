# Styx Delivery Status

## Shipped Release: `v0.8.2` (Stable)

Styx [`v0.8.2`](https://github.com/sidnvy/Styx/releases/tag/v0.8.2) carries the `0.8.x` Stable baseline forward with Public MCP OAuth resilience, refined cross-platform brand artwork, and repository cleanup:

- **Gateway**: Paired routing (`/styx/host/v3/{device_id}/exec`), ChatGPT Secure MCP Tunnel, and native `PublicMcp` HTTPS/OIDC ingress for Google Gemini and standard MCP OAuth clients with bounded 24h stale-JWKS cache fallback, fixed-category rejection telemetry, and RFC 6750 `WWW-Authenticate: Bearer` responses (`src/crates/styx-runtime/src/gateway/public_mcp.rs`).
- **Hosts**: Native Linux (`systemd --user` + CLI), macOS (`Styx.app` + SwiftUI + `cua-driver`), Windows (`StyxPreview.exe` tray/WinForms + `cua-driver`), and Android (`arm64` APK with Accessibility control + foreground `HostService`).
- **Capabilities & Reliability**:
  - `Exec` (`exec_command`, `write_stdin`, task control) with Host-retained process lifetimes.
  - `Browser` with persistent isolated Chromium profiles, multi-profile concurrent allocation, non-destructive ownership/takeover, and opt-in local Chrome CDP attachment (`existing-browser`, default off, 25s attach / 35s RPC budget).
  - `Computer Use` multi-owner AX/UIA/Hyprland reads and input without cross-owner clobbering.
  - `Android` Accessibility tree observation, screenshots, multi-display support, and gestures.
  - Bounded Linux `service_scope` shutdown loop (eliminating infinite `cleanup_unknown` hangs under `TimeoutStopSec=infinity`) and `native_service::install()` handling for cleared `failed` units.

## Deferred / Post-v1 Scope

Tracked in [REDUCED-SCOPE.md](REDUCED-SCOPE.md) without blocking `v0.8.x`:

- Persistent macOS (`launchd`) / Windows (SCM) system services and Apple notarization / Windows Authenticode signing.
- In-app auto-updater (`Sparkle` / background self-patcher).
- Automatic Gateway hub handover (`Flow A` replacement).
- Additional first-party AI client connectors beyond ChatGPT and Google Gemini / OAuth MCP.
