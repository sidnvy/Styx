# Styx VNext Linux native user-service installation pilot

**Status: tested on Workstation Linux / Hyprland. Not a production cutover
or production-signed Linux package.**

One Styx product, two roles: Gateway owns MCP/routing/enrollment, and native
Host owns Codex Exec, Cua Driver and the outbound connector. The installed
Host runs entirely from signed release directories, NOT the development
checkout. The existing Charon/Coder OOB tooling only initiated the test.

## Signed offline Host bundle

The Linux builder at host/build-linux-release.mjs includes only:

- host/connect.mjs, host/computer.mjs, launch.mjs, installer.mjs;
- Codex Exec Server JSON-RPC adapter;
- the pinned ws runtime package;
- upstream Codex CLI 0.163.0 and Cua Driver 0.36.0 Linux binaries.

The builder rejects incompatible native versions, untrusted signing key
permissions, symlinked source files and existing output folders.
Ed25519 signs an exact release manifest including each file path, size,
SHA-256 and executable flag. The publisher private key NEVER ships to
the Host; only the trusted public key is required to stage or activate.

The installer verifies every file on stage, keeps active and previous
versions in private directories, and switches a signed active pointer.
When the bootstrap itself changes, refresh-bootstrap can install updated
launch.mjs and installer.mjs ONLY from a verified signed release.
The stable launcher re-verifies signed bytes before starting the child
and passes a generation-specific config via one-shot local stdin,
substituting the active signed Codex/Cua binaries for any external paths
present in the Host config. It does not create an extra secret-bearing
temporary config file.

### Reviewable local test build

    node host/build-linux-release.mjs /private/bundle-v1 0.1.0-pilot1 \
      /private/publisher-private.pem /verified/codex /verified/cua-driver

For a real release, the signing key stays on the publisher's build system,
and the installer/downloaded files must be signed and independently verified.

## User-scoped service lifecycle

Recommended separate private directories: install root under
~/.local/share/styx-host, pairing/config under ~/.config/styx-host,
and user unit ~/.config/systemd/user/styx-host.service.

With an approved Host config, trusted publisher public key and signed bundle:

    node host/installer.mjs stage /private/install /private/bundle-v1 /private/publisher.pub
    node host/installer.mjs activate /private/install 0.1.0-pilot1 /private/publisher.pub

Create a private service.json containing unitName, installRoot,
hostConfigFile, trustPublicKeyFile, nodeBinary and restartSec. Then:

    node host/linux-service.mjs install styx-host.service /private/service.json
    node host/linux-service.mjs enable styx-host.service
    node host/linux-service.mjs start styx-host.service
    node host/linux-service.mjs status styx-host.service

Installation does NOT start or enable the service automatically. Only
specifically named Styx-owned SYSTEMD USER unit files may be created,
modified or removed. No sudo, system-wide service, linger modification,
Coder Agent, SSH server or production tunnel change occurs. The unit uses
Restart=on-failure, KillMode=control-group, UMask=0077,
NoNewPrivileges=true and the stable signed-generation launcher.

After staging a signed new version:

    node host/installer.mjs refresh-bootstrap /private/install VERSION /private/publisher.pub
    node host/installer.mjs rollback /private/install unused /private/publisher.pub
    node host/linux-service.mjs restart styx-host.service

Use the bootstrap refresh only when the signed bundle actually contains
verified new installer and launcher sources. Prefer retaining the previous
signed release until the new one passes Observe/Act/Verify acceptance.

    node host/installer.mjs prune-preview /private/install unused /private/publisher.pub
    node host/installer.mjs prune /private/install unused /private/publisher.pub

Pruning NEVER deletes active/previous versions, unsigned contents or
unrecognized directories; preview lists what could be removed.

    node host/linux-service.mjs stop styx-host.service
    node host/linux-service.mjs disable styx-host.service
    node host/linux-service.mjs uninstall styx-host.service

Uninstall removes only the OWNED service, preserves signed binaries and
identity for an explicit later revocation and data deletion decision.

## Installed-release Doctor

For an installed Styx Host, always verify the ACTIVE publisher-signed
release and its native runtimes before declaring execution readiness:

    node host/doctor.mjs /private/host.json /private/install /private/publisher.pub

With both optional install arguments, Doctor uses the fully verified
active release's own bin/codex and bin/cua-driver, NOT executable paths
embedded in an older enrollment config. It verifies each file against
the publisher-signed manifest, confirms pinned binary versions and the
private Host credential, and distinguishes native GUI/Wayland prerequisites
from Exec readiness.

An absent signature, altered payload, mismatched platform, damaged active
pointer, missing credential or bad binary produces BLOCKED. Doctor does not
start a service, modify OS permissions, contact Gateway or attest that the
desktop is unlocked. A successful result is a local readiness preflight,
not an end-to-end health check.

## Native GUI environment

The Linux user manager must have a graphical session for Cua desktop
automation. On Hyprland confirm that its environment contains
WAYLAND_DISPLAY, XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS.
The pinned Codex Exec envPolicy inherits only reviewed, non-secret
platform GUI/session variables, while Cua native Wayland requires explicit
CUA_DRIVER_RS_ENABLE_WAYLAND=1 on the trusted Host configuration.

A service may outlive the graphical login or start without unlocked desktop
access. The GUI must report BLOCKED/UNAVAILABLE in that state; Exec readiness
is a separate capability. This pilot did NOT change loginctl linger.

## Actual Workstation acceptance, October 18 2026

- PASS: signed offline install using real Codex/Cua binaries and a minimal
  vendored ws dependency; Host process was launched from versioned signed
  directories, not from Git/Node development dependencies.
- PASS: installed systemd user service started, and native Exec/Cua
  outbound lanes connected to a private loopback Gateway.
- PASS: real self-owned Zenity GUI test: signed Exec launched it, native
  Cua returned PNG screenshot plus 3 accessibility elements, Cua clicked
  its observed button, and Exec independently read back exit code zero.
- PASS: signed upgrade pilot1 -> pilot2 -> pilot3; process path/PID changed
  to each active version and runtime resumed.
- PASS: signed stable launcher update corrected the service's intentional
  SIGTERM behavior; normal restart now exits cleanly, not as an error.
- PASS: an intentional SIGKILL injected into ONLY the Pilot main process
  triggered systemd automatic recovery (NRestarts increased). Both lanes
  returned and full GUI acceptance passed again.
- PASS: rollback pilot3 -> pilot2, verified GUI, then reactivation of the
  trusted pilot3 version.
- PASS: stopped isolated Gateway while managed Host continued retrying;
  after Gateway restart it reconnected without another Host restart and
  native Cua GUI acceptance passed.
- PASS: uninstall/reinstall of the Styx-only user unit preserved the signed
  releases; enabling again restored full native GUI operation.
- PASS: release retention removed the older signed pilot1 while retaining
  active pilot3 and previous pilot2.
- NOT TESTED: full OS reboot/login, GUI lock/logout behavior, 24h soak,
  automatic signed cold install from a separate distribution, or production
  ChatGPT model-facing registration.

The bootstrap for this trial and the temporary Gateway process were
started through the existing OOB test controller. The resulting managed
Host does NOT depend on that controller for normal execution.

## Release blockers

This Pilot still uses the system's already installed Node.js binary
for its stable service bootstrap. Production must bundle/verify Node.js
or compile a standalone bootstrap, distribute fully signed OS packages,
implement platform credential storage/key rotation, cold-install without
pre-existing OOB access, and verify macOS/Windows managed service support.

The publisher signing identity here was ephemeral and test-only, not a
production publisher. The old Charon/Coder and production MCP entrypoint
remain unchanged. More: docs/onboarding-installation.md.
