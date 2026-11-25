# Styx Release Scope & Deferred Boundaries

Product architecture and runtime ownership follow [REFACTOR-PLAN.md](REFACTOR-PLAN.md), and current release status is tracked in [END-TO-END-DELIVERY-PLAN.md](END-TO-END-DELIVERY-PLAN.md). This document defines the permanent scope cuts and deferred post-v1 items.

## Product Decisions

### Deployment Roles

Each deployment has one Gateway paired with one or more Hosts over outbound mTLS/WSS. Desktop packages on macOS, Windows, and Linux support **Host-only** or **Gateway + Host**; headless Linux packages run **Gateway-only**; Android packages run **Host-only**.

### Browser Lifecycle

- Browser automation connects exclusively to the user's real Chrome/Edge/Chromium browser on the selected Host via the Styx MV3 Chrome Extension Bridge, sharing the user's real cookies and signed-in sessions without dedicated Playwright profiles or direct `chrome://inspect` / loopback `http://` CDP attachment.
- By default (when `browser_session_id` is omitted or `"new"`), each conversation opens an isolated background Chrome Tab Group (`Styx · N`) so parallel browser operations across conversations run concurrently without switching tabs or stealing OS window focus. Passing `browser_session_id: "existing-browser"` targets the user's already-open browser tabs directly (also non-focus-stealing).
- Sessions belong to the Host runtime (`browser_sessions`), preserve sign-ins across chat cleanup, require explicit `take_over_browser_session` when another conversation owns the operator slot, and detach non-destructively on `browser_close` without closing Chrome or other parallel sessions.

### Legacy Compatibility Cut

Styx has no JavaScript Gateway/Host/Core runtime (`A38`) and no legacy state import, cutover, or previous-boot migration path. Publisher signing keys/pins, "unknown outcomes are never replayed", and Gateway/Host/Core separation remain mandatory invariants.

## Deferred Post-v1 Features

These items remain out of scope for `v0.8.x` and are not blocking release gates:

- Persistent OS system services on macOS (`launchd` daemon/PKG) and Windows (Windows SCM service).
- In-app custom maintenance / Sparkle auto-update replacement for "quit app and install new DMG/installer".
- Apple Developer ID notarization and Windows Authenticode signing.
- Automatic hub handover (switching a Host to a replacement Gateway without manual re-pairing).
- First-party client setup guides beyond ChatGPT Secure MCP Tunnel and `PublicMcp` OAuth (Gemini / generic OAuth MCP clients).
