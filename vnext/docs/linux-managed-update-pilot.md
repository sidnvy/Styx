# Native signed service update acceptance

`host/managed-update-pilot.mjs` exercises the trusted local service-update API
against one new isolated Linux user unit. It reuses the managed lifecycle
pilot's private HTTPS/WSS Gateway, ephemeral publisher, exact-generation process
checks, native Exec and owned scratch GUI checks. It is opt-in acceptance code,
not a model-visible update administration tool or a production release policy.

Production Node remains pinned to 22.23.3. The second release is explicitly a
**test-only signed fixture**: after the ordinary pinned build, the local pilot
publisher replaces only bin/node, Node LICENSE and provenance with a second
unmodified official Node 22 runtime, updates manifest member hashes and upstream
metadata, and signs that complete manifest with its ephemeral key. It does not
loosen the production builder's pin or modify the original downloaded binary.
Distinct harmless launcher comments additionally prove bootstrap byte restoration.

The official [release index](https://nodejs.org/dist/index.json) lists Node
22.23.2 (2026-07-28). Its [published checksums](https://nodejs.org/dist/v22.23.2/SHASUMS256.txt)
pin the [Linux x64 archive](https://nodejs.org/dist/v22.23.2/node-v22.23.2-linux-x64.tar.xz)
to `d60acfe00a2932254bb0ad20e01b0d74397a0875595de719654b214f4b03f307`.
The verified archive's Node binary hash is
`3517c2df0b2f8cd7f422b4b8450ef81c6889f08eb03e281d6de9079b15e6a327`.
`prepare-update-pilot-node.py` provisions only that second binary, LICENSE and
provenance into a fresh directory. It installs no service and does not run Node.

## Reproduce with explicit authorization

Prepare the regular managed pilot's fixed official Node 22.23.3, Codex 0.163.0
and Cua 0.36.0. Prepare the second fixture runtime:

```sh
python3 vnext/host/prepare-update-pilot-node.py /absolute/private/alternate-node
```

Use a fresh suffixed unit name and fresh output directory in a private config:

```json
{
  "directory": "/absolute/private/work/fresh-update-run",
  "unitName": "styx-rc20261019-owned-update1.service",
  "nodeBinary": "/absolute/pinned-node/node",
  "codexBinary": "/absolute/pinned-codex/codex",
  "cuaBinary": "/absolute/pinned-cua/cua-driver",
  "alternateNodeBinary": "/absolute/private/alternate-node/node"
}
```

```sh
STYX_RUN_MANAGED_LINUX_UPDATE_PILOT=1 /absolute/pinned-node/node \
  vnext/host/managed-update-pilot.mjs /absolute/private/update-config.json
```

Only a new `styx-rcYYYYMMDD-owned-suffix.service` may be used. Existing units
and nonfresh output directories are refused. Before every offline file switch,
the stop callback executes `systemctl --user disable --now` for only that unit
and observes inactive, PID 0, disabled and disconnected. Thus login/reboot
activation is inhibited before multi-file replacement. Health may start the
unit while disabled. Original enablement is restored only after a completed
transaction with coherent signed bytes. Uncertain transactions stay disabled.
Recovery's callback only observes stopped/disabled state; it never starts or
replays the service. The explicit operator start is a separate later action.
No reboot, session change, global service action or permission grant occurs.

## Observed result on 2026-10-19 (Asia/Shanghai)

The [sanitized receipt](evidence/linux-managed-update-20261019-pass.json) records
source `38fcb8b8162ebe1daccb7d379b753e4162ef69c5`. Actual user-systemd operations
and official binaries were used throughout:

- PASS: initial signed install, controlled restart and owned-cgroup SIGKILL
  recovery, with native Exec readback and fresh authenticated WSS peers.
- PASS: service release 1, Node 22.23.3, changed to signed test fixture release 2,
  Node 22.23.2. The mapped service executable's `/proc/<owned-pid>/exe --version`
  independently confirmed the version actually running.
- PASS: a subsequent switch back to release 1 was deliberately reported
  unhealthy after its actual native Exec readback. The transaction stopped it,
  restored the exact previous active.json bytes and independently signed helper,
  installer, distinct launcher and Node bytes, restarted release 2 and observed
  native Exec health with the actual Node 22.23.2 mapped runtime.
- PASS: a health callback's completion was deliberately withheld after its
  candidate was actually ready. The bounded timeout returned needs_recovery,
  retained its lock and durable journal, and left startup disabled. Late callback
  success did not mutate files, change the pointer or replay service callbacks.
- PASS: after an explicit stop/inhibit, recovery restored previous signed state
  and returned recovered_stopped without starting the unit. A separate explicit
  operator start returned healthy release 2/Node 22.23.2.
- PASS: the final exact-PID/title owned scratch-window screenshot, three AX
  elements, observed-token click and independent shell exit 0 through Styx.
- PASS: only the owned unit and enable link were removed; all private publisher,
  TLS, bearer, config, installed and staging state was deleted.

Initial trust distribution, cold install, physical reboot/power-loss acceptance
and a complete 24-hour platform soak remain NOT RUN. This is a runtime replacement
acceptance fixture including an intentional runtime downgrade; it does not
recommend or publish Node 22.23.2 as a supported Styx production release.
