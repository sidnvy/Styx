# Opt-in managed-service and Exec soak

`host/managed-service-soak.mjs` adds a bounded native managed-service sampling
window to the existing owned Linux pilot. Its default is 86,400 seconds with a
60-second interval; the accepted duration is 1–172,800 seconds and interval is
1–3,600 seconds. Importing the module and ordinary CI tests never start a
service. The independent existing component soak is not controlled by this tool.

The runner requires its distinct `STYX_RUN_MANAGED_SERVICE_SOAK=1` opt-in and a
fresh `styx-rcYYYYMMDD-owned-soaksuffix.service` name, with the existing fixed
Linux x64 Node 22.23.3, Codex 0.163.0 and Cua 0.36.0 inputs. It builds signed
private payloads and runs initial start/restart/owned-cgroup crash recovery
checks. During the sampling window it makes **no GUI calls**. After successful
completion it runs one exact-PID/title owned scratch-window GUI acceptance, then
removes only its owned unit and private state. There is no update/rollback
operation during the soak.

Each periodic sample requires the owned unit to remain reported, loaded, active
and enabled, with the same main PID and restart count observed at the start of
the sampling window. An unexpected restart fails the window; it is not hidden
by replay or a retry. Every sample performs a fresh native Exec marker roundtrip
through authenticated Styx HTTPS/WSS, checks the expected computer connection
slot remains connected, verifies the main process maps to signed installed
Node, and records:

- Monotonic elapsed time, timestamp and Exec latency.
- Exact owned main PID and systemd restart count.
- Main-process RSS and thread count, plus systemd cgroup memory, CPU nanoseconds
  and task count when available. Missing optional accounting is null, not zero.

These are resource measurements, not a promise that a short sample establishes
memory stability. No command output, bearer value, private key, window content,
screenshot bytes or arbitrary SDK exception text is persisted. Observer failures
use fixed allowlisted error codes. Only newly created owned process IDs appear.

## Durable records and runtime boundaries

The fresh output directory contains a fsync'd atomic `managed-soak.json`
snapshot and append/fsync `managed-soak-samples.jsonl`. The snapshot identifies
the driver PID, actual Node version, frozen Git revision, exact owned unit,
configured duration/interval, sample count, current phase and last sample. The
surrounding `receipt.json` includes initial lifecycle and final cleanup gates.
All evidence statuses use PASS / FAIL / BLOCKED / NOT RUN; an active window has
status NOT RUN and phase running until its configured duration actually finishes.

The isolated test certificate lasts three days, with per-client CA trust only.
Before sampling, its real X.509 notAfter must exceed the requested duration by at
least one hour. Thus the maximum 48-hour window has expiry headroom. No global
TLS validation or trust store is changed.

Graceful SIGINT/SIGTERM aborts the pending sample or interval, marks the window
BLOCKED, terminates MCP leases, and uses the existing ownership-checked uninstaller
to stop/disable/remove its exact unit and remove private payload/credentials.
It skips the final GUI test after an abort. A hard SIGKILL, driver crash or OS
reboot cannot guarantee execution of this cleanup: inspect the snapshot and
exact ownership marker before operator-directed removal of that one unit and
its private state. This runner does not steal locks, kill discovered PIDs,
automatically resume an interrupted window, or emit completion notifications.
The caller must inspect its durable records and arrange any authorized follow-up.

## Config and operator invocation

Use a private absolute-path config and a fresh output directory:

```json
{
  "directory": "/absolute/private/work/fresh-managed-soak",
  "unitName": "styx-rc20261019-owned-soak24h.service",
  "nodeBinary": "/absolute/pinned-node/node",
  "codexBinary": "/absolute/pinned-codex/codex",
  "cuaBinary": "/absolute/pinned-cua/cua-driver",
  "durationSeconds": 86400,
  "intervalSeconds": 60
}
```

After reviewing and freezing the source snapshot, an authorized operator can run:

```sh
STYX_RUN_MANAGED_SERVICE_SOAK=1 /absolute/pinned-node/node \
  vnext/host/managed-service-soak.mjs /absolute/private/soak-config.json
```

No 24-hour run was launched while implementing this harness. Short native
completion and graceful-abort checks are recorded separately. Even a completed
24-hour service/Exec window does not establish a full GUI/session/platform soak:
`full_gui_session_soak_24h` and `full_platform_24h_soak` stay NOT RUN. GUI continuity,
login/reboot, cold install and distribution trust require separate acceptance.

## Observed bounded verification on 2026-10-19 (Asia/Shanghai)

Source `1635af6b8a9dd8f26738c8438066b726968b6cb6` completed a two-second window
with three actual samples at one-second intervals. The
[completion receipt](evidence/linux-managed-soak-short-20261019-pass.json) and
[redacted samples](evidence/linux-managed-soak-short-20261019-samples.jsonl)
record PASS native Exec roundtrips, one unchanged owned service PID/restart
count, and non-null RSS, cgroup memory, CPU and task values. The final owned GUI
check and exact-unit/private-state cleanup also passed. Its three-day certificate
and standalone source/driver fields were observed, not inferred from a plan.

A separate newly spawned runner was sent SIGTERM after its first real sample.
The [abort receipt](evidence/linux-managed-soak-abort-20261019-blocked.json)
correctly reports the interrupted window BLOCKED; the
[abort-verification result](evidence/linux-managed-soak-abort-20261019-verification.json)
is PASS for exit code 2, owned-unit removal, secret cleanup and no final GUI
call after abort. Independent postchecks found both final test units not found
and inactive, without their unit files or enable links. No other soak was
signalled or inspected. The managed service/Exec 24-hour gate remains NOT RUN.
