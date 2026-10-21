# Linux sessions and services

Linux uses the CLI and owning user's systemd manager. A GUI application is not
required for Gateway, Exec, or an optional headless Browser provider. The Host
unit belongs to `default.target`; it does not depend on `graphical-session.target`
and does not embed display environment in the unit.

`host/linux-desktop.mjs` observes the current user's local, active graphical
logind session and its lock hint. It requires a private owned runtime directory
and an owned Wayland or local X11 socket. A DISPLAY variable or configured Cua
socket alone does not qualify. Only fixed GUI environment keys are read from
the current process or user manager; arbitrary environment values are not
forwarded. Multiple eligible sessions require a matching `XDG_SESSION_ID`.

`runLinuxDesktopLifecycle` starts the Computer connector for that observed
session. Logout, lock, failed observation, or a replaced session aborts and drains
only its Computer connector. A later eligible session starts another connector
using the same existing Host identity and configuration. It never enrolls a new
Host, revokes credentials, restarts Exec, or stops Gateway/Browser.

This is a conservative availability observation, not proof of screen contents or
permission to act. Lock detection depends on the desktop publishing logind's
`LockedHint`. Display access and native Cua operations still require their own
acceptance checks. Systems without logind remain usable for headless roles;
the Computer lane reports unavailable.

`linuxUserManagerStatus` reports existing headless startup policy without
changing it. If linger is disabled, systemd may stop the user's manager after the
last login ends. This implementation does not enable linger or install a root
service. `recoverLinuxService` resets failure/start limits and starts only an
owned enabled unit. A deliberately disabled service is not resurrected. Recovery
and unit removal preserve Host identity and installed signed releases.

Validation for this change: deterministic session/lock/logout/replacement tests,
Linux service ownership/recovery tests, and an isolated native systemd user-unit
install/start/status/stop/uninstall cycle. A read-only Workstation probe observed
the existing active Hyprland Wayland session. No real logout, lock, compositor
change, reboot, or operation against user applications was performed.
