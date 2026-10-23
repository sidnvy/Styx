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

## Before-login startup review

`styx linux-boot ABS_STATE` reports the same Linux boot projection attached to
`inspect ABS_STATE` / the App's existing background observation. It reads the
current deployment and signed, configuration-bound service observations. It
never writes another role configuration or changes system policy.

The result separates three questions:

- `linger` observes the owning user's existing logind setting. An enabled
  setting starts that user's service manager at boot and keeps it after logout.
- Each requested role reports whether its **own verified unit** is installed
  and enabled. Gateway-only ignores Host; joining another Gateway ignores the
  remote Gateway. Disabled units remain disabled. Unknown, invalid or foreign
  service observations never become an installation suggestion.
- `status: configured_unverified` means linger and the requested unit startup
  settings were observed. It is not proof that paths, encrypted home mounts,
  networking, credentials or tools work before login. Physical prelogin and
  chat-account acceptance remain `NOT RUN`.

The read-only `plan` lists missing steps as argument arrays. A missing linger
setting suggests `loginctl enable-linger UID` for review, with its user-wide
scope and conditional inverse operation. System policy may require administrator
approval. Styx does not execute this step, invoke sudo, or toggle linger during
installation, update or recovery. Its inverse must not be applied if another
service relies on the setting. Missing or disabled owned services use existing
Core `host-service` / `gateway-service` actions and their authorization/journal;
there is no new installer or service identity. Stopping disables startup while
preserving device identity, pairing and installed runtime. This is not an
uninstaller or a claim that installation has been rolled back.

Computer Use and headed browsers still need a graphical session. A headless
Browser can run independently, but this startup-policy observation does not
verify browser execution. Linger does not unlock a desktop or grant permissions.

See the systemd [loginctl documentation](https://www.freedesktop.org/software/systemd/man/latest/loginctl.html#enable-linger%20%5BUSER%E2%80%A6%5D)
for the native linger mechanism. No physical logout or reboot is performed by
this command or its deterministic tests.
