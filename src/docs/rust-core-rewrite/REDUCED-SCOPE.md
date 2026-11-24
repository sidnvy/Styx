# Styx Release Scope & Deferred Boundaries

Product architecture and runtime ownership follow [REFACTOR-PLAN.md](REFACTOR-PLAN.md), and current release status is tracked in [END-TO-END-DELIVERY-PLAN.md](END-TO-END-DELIVERY-PLAN.md). This document defines the permanent scope cuts and deferred post-v1 items.

## Product Decisions

### Deployment Roles

Each deployment has one Gateway paired with one or more Hosts over outbound mTLS/WSS. Desktop packages on macOS, Windows, and Linux support **Host-only** or **Gateway + Host**; headless Linux packages run **Gateway-only**; Android packages run **Host-only**.

### Browser Lifecycle & Coexistence

- Isolated managed Browser launches a visible dedicated Chromium window per profile on the selected Host desktop. Profiles persist across conversation changes, context closure, and Host restarts and are reused by `browser_session_id` or explicit takeover (`take_over_browser_session`).
- Opt-in local Chrome CDP attachment (`existing-browser`, disabled by default via local Host setting `browser-cdp.json`) allows explicit attachment without interfering with default isolated profiles, and detaches non-destructively on `browser_close`.

### Legacy Compatibility Cut

Styx has no JavaScript Gateway/Host/Core runtime (`A38`) and no legacy state import, cutover, or previous-boot migration path. Publisher signing keys/pins, "unknown outcomes are never replayed", and Gateway/Host/Core separation remain mandatory invariants.

## Deferred Post-v1 Features

These items remain out of scope for `v0.8.x` and are not blocking release gates:

- Persistent OS system services on macOS (`launchd` daemon/PKG) and Windows (Windows SCM service).
- In-app custom maintenance / Sparkle auto-update replacement for "quit app and install new DMG/installer".
- Apple Developer ID notarization and Windows Authenticode signing.
- Automatic hub handover (switching a Host to a replacement Gateway without manual re-pairing).
- First-party client setup guides beyond ChatGPT Secure MCP Tunnel and `PublicMcp` OAuth (Gemini / generic OAuth MCP clients).
