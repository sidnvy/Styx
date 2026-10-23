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
