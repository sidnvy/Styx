# Native menu and Settings preview — 2026-10-21

This preview implements the approved macOS direction: a separate setup window, daily status-item popover using system material, and a native Settings window. The official glyph remains in the status item. The popover uses observed device connectivity, a globe for ChatGPT, and separate Settings and Quit commands. Closing a window preserves the existing App lifecycle.

Connection details use a sheet with persistent labels, inline validation, a secure local key draft, and an explicit replacement action for a stored key. The Core retains an omitted saved key without returning it to the App. Optional package customization uses the existing Core export path, native Save dialog, and the actual successful file destination with Finder reveal. Direct ChatGPT setup is the default.

## Verification

- Full onboarding suite: 369 tests, 363 passed, 6 environment-dependent skips, no failures.
- Focused packaging/signing suite: 15 tests, 13 passed, 2 native-environment skips, no failures.
- PilotMac: Swift compiled with warnings as errors; native protocol and injected permission-state checks passed.
- PilotMac unlocked session: the hosted normal and secure fields accepted private-pasteboard input through the standard Command-V Edit-menu route. The general clipboard was not accessed.
- Native rendering used synthetic state without a running Core, stored identity, TCC requests or account access. The cacheDisplay image does not capture all composited sidebar layers; the native sidebar table contains four rows. This is not a complete visual or account acceptance result.

## Remaining product gates

- Automatic secure LAN entry preparation is not integrated; the existing ingress plan reports a blocker for an unreachable entry rather than advertising an unusable invitation.
- Post-join capability changes still require Gateway synchronization; pending-request rejection and invitation invalidation need Core API support.
- A changed invalid runtime key is not automatically rolled back after configuration. Failed editor entries remain available for correction.
- ChatGPT ZIP import compatibility, actual account tools, real Exec/Cua, reboot/login/network recovery and upgrade permission continuity have not been accepted by this UI test pass.

Packaging and signature receipts are kept with the task artifacts. This is a developer preview, not a complete production release. No existing App installation, identity, pairing, credentials or system permissions are changed by generating this package.
