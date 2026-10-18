# Styx — production onboarding and installer release gate

Status: PRODUCTION RELEASE REQUIREMENTS. Narrow device pairing and offline
signed staging PILOTS are implemented; native cold installers and the ChatGPT
setup UI are NOT implemented. This file is a release gate for
the single Styx product. It does not authorize production Charon/Coder changes.

## Initial trust/bootstrap boundary

ChatGPT is the primary planning and UI entrypoint, but cannot install an agent
or grant OS permissions on a device that has not already been paired.
First contact is a local user action: run a verified signed Styx installer or
open Styx.app. Existing SSH and Coder Agent may bootstrap isolated development
tests only; they MUST NOT be required for production installation, execution,
renewal, remote support, or recovery.

## User-facing device onboarding

1. In ChatGPT, user chooses Connect Computers. Show trusted paired devices,
   their OS, capabilities, generation and actual online/ready status.
2. User selects the device(s) to connect. For new devices, provide the
   verified official per-OS installer and a short-lived single-use pairing
   invitation. Do not ask for SSH credentials or OS account passwords.
3. On each native Host, the installer verifies signature/checksums, creates a
   stable device identity, generates a private key locally, and presents the
   Gateway identity and pairing fingerprint for local confirmation.
4. Host initiates authenticated outbound WSS to the Gateway. Owner approves
   the pending device and selected capabilities from ChatGPT. A native/CLI
   fallback enrollment UI must exist if ChatGPT intelligent UI is unavailable.
   Private keys never leave the device and stale/used pairing codes fail closed.
5. Gateway stores approved public Host identity and capability grants. Host
   receives an admitted stable environment_id. The operator can revoke,
   rotate, disable and remove hosts separately; no implicit access expansion.
6. Native permission and readiness: macOS user grants Accessibility and
   Screen Recording to one stable signed Styx.app; Windows driver runs in an
   interactive logon; Linux driver runs in graphical session with explicit
   Wayland opt-in when needed. GPT cannot programmatically grant TCC.
7. After local Doctor and owned scratch acceptance pass, enable a supervised
   user-level Styx Host service, verify reboot/login and reconnect, and show
   the final actionable readiness result. Device selection remains explicit.

The future ChatGPT intelligent UI may guide this state machine via small
deterministic enrollment/readiness operations. It cannot pretend a Host was
paired, fabricate permission status or bypass native user confirmation.
Do not create a large Styx-only execution/tool framework for onboarding.

## Single-product packaging

One Styx release and manifest, potentially containing multiple process roles:
Gateway, native Host Connector, pinned Codex Exec Server, native Cua Driver and
the platform-appropriate permission host. No separate Charon/Peekaboo/Coder
installation is a production dependency.

- macOS: signed/notarized Styx.app with stable Bundle ID, TCC responsibility
  chain, bundled native Cua daemon, user LaunchAgent if needed.
- Linux: reviewed native installer, user systemd service, Cua driver attached
  to graphical session (headless Exec can remain independently available).
- Windows: signed installer, user-scoped interactive Scheduled Task, Cua UIA
  in logged-on Session (never assume Session 0 GUI access).

Record OS/architecture, upstream pinned revisions, checksums, SBOM and signing
identity. Avoid system-wide Node/Python packages when a bundled runtime works.

## Update, rollback and uninstall

Lifecycle: discover -> download -> verify -> stage -> install -> pair ->
permission check -> doctor -> acceptance -> enable -> ready.

Every install/update verifies signed artifacts before activating. Stage a
versioned release alongside the last known-good generation; do not overwrite
running binaries. Drain/abort requests according to known result semantics,
then switch version atomically. On failed health check, roll back while
invalidating old process IDs and Cua snapshots. Keep Host identity stable
across revisions; verify macOS TCC survives signed upgrades rather than
assuming it will. Uninstall disables service, revokes approved public identity
and removes product-owned files only. No automatic OS permission escalation.

All install logs and receipts must exclude tokens/private keys/screenshot
content. Unknown mutation outcome is not re-run automatically.

## Minimum future control plane

- Create one-time enrollment invitation with expiry and bounded retries.
- Show the pending Host and fingerprint; approve/deny from the correct owner.
- Read device capabilities, permission/doctor status and install progress.
- Explicit allow/deny/revoke device and rotate credentials.
- Versioned update/rollback with signed machine-readable receipts.

These are product onboarding operations, not new Codex/Cua execution tools.

## Explicit production release acceptance

- Cold install on macOS/Linux/Windows WITHOUT SSH, Coder Agent or Styx.
- Select one or multiple machines; pairing approval/rejection, replay/expiry,
  wrong-Gateway attack, revocation and key rotation tests.
- Native permissions and interactive session detection, including decline,
  locked/logged-out desktops and unsigned/mismatched macOS app identity.
- Run signed app through startup, reboot/login, reconnect and 24h unattended
  soak; measure memory, CPU, startup time and connection stability.
- Model-facing ChatGPT -> Gateway -> Native Host with Exec, filesystem/PTY,
  and owned Cua screenshot/AX/action/readback for each OS.
- Upgrade and rollback with no lost secrets or old-session resurrection.
- No Coder/OOB dependency for remote operations or recovery.
- Scope-complete comparison with production Charon including Browser paths
  if Browser is intended to be replaced; independent rollback demonstrated.
- Only then authorize changing the production MCP endpoint and decommissioning
  production Coder/Charon.

Current state: these are gates, NOT claims of implemented installer, pairing
service, ChatGPT visual setup or completed production rollout.


## What the October 2026 installation prototype actually provides

- Opt-in owner-only Gateway enrollment endpoints, separate from model MCP tools.
- A device-generated RSA identity and proof-of-possession at first contact,
  a short-lived single-use invitation, user-approved exact fingerprint,
  and a public-key-encrypted Host capability. Keys stay local.
- Persisted registry admission and durable device revocation that terminates
  admitted outbound Host connections, with no Gateway restart.
- CLI owner and native-device fallback, including bounded unattended approval
  wait. These support a future ChatGPT guided UI but are not the UI itself.
- Offline Ed25519-signed manifest and all-file SHA-256 verification, protected
  version staging, activation, stable launch shim and signed rollback.
- OS-specific service plans WITHOUT registering/enabling services.
- All unit/integration and multi-platform tests are isolated; no production
  Charon/Coder/Tunnel endpoint has been replaced.

Reference implementation and reproduction: docs/enrollment-pilot.md.
The cold installer, downloadable signed product, PKI/keychain, unattended
OS service registration, device picker and production rollout are still
explicit release blockers.
