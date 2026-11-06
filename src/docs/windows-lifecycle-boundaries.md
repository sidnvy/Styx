# Windows process and login boundaries

The current user App and the explicitly managed user tasks are separate owners.
Neither is a Windows service that runs before user login.

| Entry | Owner and scope | Window close / Quit | Login and unattended restart |
| --- | --- | --- | --- |
| Native App | Current interactive user; private Core child owns its foreground components | Closing Settings hides it. Normal Quit uses work admission and stops only its owned Core/foreground work. Independent services are not adopted or stopped. | Optional fixed current-user `Styx.lnk`, registered through Core. A normal Quit leaves the next-login preference intact. Windows can independently disable the entry. |
| CLI foreground | Calling process and existing deployment identity | Process-owned; independent App/CLI ownership cannot be silently taken over | Does not itself register startup. Headless execution does not imply desktop availability. |
| Explicit Gateway task | Task Scheduler, exact owner SID, `InteractiveToken`, `Limited` | `stop` disables recovery before stopping. It is independent of App window closure. | User login plus a one-minute recovery trigger; requires that user's interactive session. **No unattended system-start mode is implemented.** |
| Explicit Host task | Same user-only Task Scheduler contract and signed Host runtime | `stop` disables before stopping; identity/configuration survive | Same login requirement. This is not a Session 0 Exec/Cua service. |

Gateway status is read-only and can be observed by the same user through SSH or
another noninteractive session. Observation still verifies task marker, owner,
logon type, run level and exact executable/arguments. Only the scheduler's exact
missing-task error establishes absence; provider/access errors remain unknown.
This does not authorize installation or start from that session.

The App passes a package-pinned `StyxSessionProbe.exe` result into Core before
starting Computer Use. It checks the actual nonzero session, `UserInteractive`,
`WinSta0` and accessible `Default` input desktop. The independent Core delegates to the signed Host probe, including when managed
through CLI. Missing probes remain unavailable. A connected Cua transport is
not evidence that observation/actions are possible.

The signed Host generation also includes this existing native probe. The launcher
selects its hash from the verified release manifest; Computer Use checks it in
its own caller session. Session 0, a locked/inaccessible desktop, a changed probe
or a legacy release missing the probe leaves Computer Use unavailable with an
explicit reason. The capability preference is retained. The existing desktop
lifecycle loop cancels and drains that lane when the desktop disappears and
reconnects when the same user has an accessible desktop again. Exec and Browser
ownership are separate and are not cancelled by this gate. A fresh probe is also
required before publishing a new Computer connection as ready.

This gate does not claim a completed tool test. Native observation/action,
lock/unlock recovery and remote tool acceptance must be verified separately;
unit lifecycle fixtures are not native desktop acceptance.

## Future unattended Gateway prerequisite

A Gateway-only deployment must remain free of Exec/Cua and desktop permissions.
Supporting it before user login needs an explicitly selected, least-privilege
native service identity and a mature service manager, with separate installation
consent and ownership reconciliation. The current interactive task is not that
implementation. Do not silently switch it to `SYSTEM`, elevated execution or a
password-bearing task.

Microsoft documents that `InteractiveToken` requires an already logged-on user;
S4U has no network or encrypted-file access and is not a drop-in networking
service solution. Services must not impersonate an interactive desktop in
Session 0. See [Task Scheduler logon types](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/ne-taskschd-task_logon_type)
and [interactive services](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services).

These are implementation boundaries. Same-user read-only task observation tests
do not establish unattended boot or service installation acceptance.

## Local App exit

The current-user native App exposes a local owner endpoint. The bundled
`native/bin/styx.exe quit --state-dir <outer-App-state> --json` and tray **Quit
Styx** call the same retained shutdown job. `styx app status` reads that owner
without contacting a Gateway. The state directory is the outer App directory,
not its nested `native-rust-host-v1/profile`.

The pipe is scoped by the current SID and the actual private profile directory's
volume/file identity. Only the original package's CLI is accepted; kernel peer
identity, package image and original process birth are checked. Two bounded pipe
instances allow status while Quit drains. A second App for the same profile is
refused before another UI/Core starts. Other profiles and independent services
are not adopted or stopped.

When a Core exists, a successful Quit requires original Core admission, stdin
EOF, joined stdout and stderr, observed Core exit 0 and observed App exit 0. Normal Quit uses retained
shutdown custody, with no timed force-kill. Proven pre-dispatch busy states can be
reported and explicitly tried again. A slow shutdown retains the original job; a client timeout reports `unknown`
and never replays the request. If admission fails, the same owner closes only its
stdin, joins its original read and waits for Core's existing EOF cleanup. Once
exit is actually observed the App may close with a nonzero, unclean result; a
missing admission response is never promoted to clean success.
An already exited abnormal Core no longer traps the UI: the App can exit while
reporting `unclean_exit`/nonzero status. This does not certify worker cleanup.
Endpoint absence on an older App is `unavailable`, not proof it has exited.
The next-login preference, identity, pairing and original journals are retained.

Run `node --test src/host/windows/quit-lifecycle-native.test.mjs` on Windows for
real process/pipe/WinForms custody regressions. Its test-only Core constructor is
compiled with `STYX_QUIT_TEST` into a separate harness; the App builder never
defines it. These fixtures cover active owned workers, disconnected component
state, long drains, busy refusal, abnormal/early Core exit, lost replies, and
same-profile reservation. They do not establish signed Host execution, remote
Computer Use, or acceptance against an unavailable production Gateway.

## 2026-11-04 design correction

Ordinary App Quit and bundled local `quit` judge local exit after the original Core, native work, stdout/stderr and event tasks have actually joined. Gateway availability is not an exit prerequisite. Core's `scope=local_app` ticket is not remote cleanup proof: a missing remote drain remains Unknown in the cleanup object and in a private immutable `app-local-exit-<ticket>.json` observation beside the profile container. No old result is cleared or action replayed. Maintenance/update handoff retains its strict full-settlement check.

Status is observed once per second through the same Core, at most one observation in flight. Mutations and shutdown pause observation; mutation revisions reject stale responses. Observing status does not reconnect a Paused profile or execute tools. The original Host retries only temporary initial network availability failures; credential and certificate refusals remain refusals.

Ordinary Core cleanup sends EOF and concurrently drains both original pipes before waiting for exit. It has no timed force-kill path. An unknown RPC result still reports failure and is not sent again. A long cleanup remains owned while the UI awaits it asynchronously.

The bootstrap hashes the original CLI once while its original non-writable/non-deletable file handle remains held. Each new bootstrap lifetime authenticates again; native signed-payload and manifest checks remain in place. Real Windows file-lock negatives and native process/WinForms scenarios must accompany this change.

## Coherent startup observations (2026-11-04)

An actual signed candidate painted in 494 ms but answered the App's initial Core read only after about 46.5 seconds. A separate original Core measured 32.0 seconds for open plus plain status and 7.8 seconds for startupStatus; Host admission/executor startup followed separately. These observations are a failed performance qualification, not evidence that the UI should skip verification.

Native enrollment inspection now reads its fixed five-phase prefix as one bounded read-only batch under the original configuration writer. Complete C07, material and phase validation brackets capture; each captured file must also match its original pin, and the canonical state digest must stay unchanged. Replacement during capture returns no prefix. State and its original seed are observed together instead of repeating the same full state read to return borrowed immutable seed bytes. These returned bytes remain DATA; network/append boundaries retain their original complete validation and unknown outcomes are never retried.

The App reuses its original formal verified release for the desktop-intent snapshot through the existing full retained-selection/member revalidation port. It does not reuse a receipt, accept a new path or weaken desktop source checks. Automatic resume observes Running and schedules the original strict Host admission without writing Running again; only an explicit Connect changes that intent. A newer Stopped state must therefore remain stopped. Native performance and effects still require measurement on the resulting candidate.

Explicit startup self-tests keep the first fixed-name receipt and create a unique, exclusively opened receipt for each later run. A repeat measurement must preserve the earlier bytes; these diagnostic files never authorize a runtime or replace platform acceptance.
