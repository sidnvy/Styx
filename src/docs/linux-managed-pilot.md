# Opt-in native Linux managed Host pilot

This bounded acceptance path installs one new Styx user-systemd unit against a
private loopback Gateway, exercises real signed Host generations and native GUI,
then uninstalls that unit and deletes its private state. It is not a production
service, cold-install claim, publisher-trust bootstrap or 24-hour soak.

`host/managed-linux-pilot.mjs` requires Linux x64 and explicit
`STYX_RUN_MANAGED_LINUX_PILOT=1`. Importing it or running ordinary host safety
tests never installs a service. Unit names are restricted to
`styx-rcYYYYMMDD-owned[-suffix].service`; an existing unit or unit file is refused.
The output directory must be fresh, absolute and private. Paths containing
spaces are currently unsupported by this pilot's service adapter.

Prepare the fixed official binaries using the existing checksum-pinned
`prepare-node.py`, `prepare-codex.py`, and `prepare-cua.py` provisioning paths.
Node's LICENSE and node-provenance.json must be beside its binary. The pilot
requires the observed fixed Linux x64 binary SHA-256 values recorded in source
and evidence; changing runtime versions requires an explicit reviewed update.
Install locked Gateway test dependencies with `npm --prefix src ci
--ignore-scripts --no-audit --no-fund`.

Create a private config outside tracked source:

```json
{
  "directory": "/absolute/private/work/fresh-managed-run",
  "unitName": "styx-rc20261019-owned.service",
  "nodeBinary": "/absolute/pinned-node/node",
  "codexBinary": "/absolute/pinned-codex/codex",
  "cuaBinary": "/absolute/pinned-cua/cua-driver"
}
```

Run with the pinned Node runtime:

```sh
STYX_RUN_MANAGED_LINUX_PILOT=1 /absolute/pinned-node/node \
  src/host/managed-linux-pilot.mjs /absolute/private/pilot-config.json
```

The operator must authorize the real user-service and owned desktop test. A
reachable user systemd manager, OpenSSL, Zenity and an existing native Wayland
session are required. The script selects only WAYLAND_DISPLAY, XDG_RUNTIME_DIR,
DBUS_SESSION_BUS_ADDRESS, DISPLAY and HYPRLAND_INSTANCE_SIGNATURE from the real
user-manager environment. It does not import, mutate or print session values,
set lingering, use sudo, alter global service state or inspect personal windows.

The pilot:

1. Generates an ephemeral Ed25519 publisher key and builds/verifies two signed
   payloads containing official Node 22.23.3, Codex 0.163.0 and Cua 0.36.0,
   their bundled notices and the signed stable bootstrap.
2. Creates an ephemeral loopback HTTPS/WSS Gateway, a one-day local certificate
   and separate model/Host bearer values. Both clients verify the explicit
   local CA; no certificate validation or global trust is disabled.
3. Installs, enables and starts only its exact new unit, then checks the actual
   service process uses signed stable Node and its direct connector child comes
   from the selected signed generation. Fresh authenticated WSS peers and a
   native Exec marker readback establish readiness, beyond `systemctl active`.
4. Performs a controlled restart and an explicit SIGKILL of only that owned
   unit's cgroup. Requires a different main process, increased systemd restart
   count for crash recovery, fresh Exec/Computer peers and successful readback.
5. Stops the unit, activates/refreshed signed release 2, starts/verifies it, then
   performs the same stopped-service rollback to signed release 1.
6. Uses Styx Exec to launch a self-expiring Zenity scratch window. Only its exact
   PID/title is observed; Cua screenshots that window, reads its AX button,
   clicks the observed element token and verifies independent shell exit 0.
   Neither screenshots nor AX payloads are retained in evidence.
7. Terminates MCP leases, stops/disables/removes only the owned unit and reloads
   the user manager. Checks the unit is not found, then deletes all private
   credentials, configs, installed copies and staging bundles. Only the
   sanitized receipt remains in the run directory. If cleanup fails, the
   receipt identifies that gate and private state is retained for recovery.

## Observed acceptance on 2026-10-19 (Asia/Shanghai)

The [successful native receipt](evidence/linux-managed-pilot-20261019-pass.json)
records tested source `e06e24e6d7a0cb7fb0a669895e102f88f3712559`. All ten scoped
build/install/start/restart/recovery/upgrade/rollback/GUI/uninstall/secret-cleanup
gates are PASS. Crash recovery increased NRestarts from 0 to 1. The owned
window screenshot was present, three AX elements were returned, and clicking
its observed button independently produced exit 0. Independent post-run checks
also confirmed the unit file, enable link and private state were absent and the
unit was not found/inactive. No other running service or independent soak was
touched.

An [initial receipt](evidence/linux-managed-pilot-20261019-initial-harness-race.json)
retains a FAIL from the pilot's restart observer at source `53087fb`: it checked
the newly started launcher's child too early while old Gateway peers remained
in the same event-loop turn. That run still uninstalled its unit and deleted
private state. The corrected observer waits for the actual signed connector
child and distinct new Exec/Computer peer identities before asserting readiness.
This records a harness failure, not evidence that the Host restart failed.

Cold install, established publisher trust distribution and full-platform
24-hour soak remain NOT RUN. This machine already supplied its desktop/systemd
session, OS libraries and test dependencies. Ephemeral signatures prove payload
integrity within this test; they do not establish an operator's durable update
trust or a reviewed public release channel. Login/logout/reboot and interrupted
GUI mutation outcome recovery require separate acceptance. No release has been
merged, deployed or promoted by this pilot.
