# Windows platform installer compatibility probe

This directory tests platform packaging against the existing WinForms, Node and
Core payload. It does not replace release signing or claim the existing separate
Host installation is upgraded by an App installer.

## Observed NAB prerequisites (2026-10-22)

Windows 11 build 26200 has App Installer 1.29.379.0. There is no installed SDK
packaging tool, no code-signing certificate with a private key, and no enabled
Developer Mode policy. Only task-local portable tools are used.

MSIX supports full-trust desktop processes, but its package directory is
immutable. AppData virtualization needs an explicit shared-state decision so
unpackaged CLI and packaged Core do not silently see different configuration.
A user-session Host remains in that session; it must not become a system service
merely because a package supports services.

Microsoft's unsigned executable MSIX test mode requires administrative/all-user
deployment. Our current test authorization is current-user only: do not invoke
that mode, enable Developer Mode or install certificate trust. An unsigned MSIX
can be built and checked, but native registration/App Installer acceptance is
blocked until a suitable existing trusted signing identity is available.

## Small native comparison

1. Reuse the already compiled rc7 public payload under distinct probe identity
   `Styx.PlatformProbe.9c71`, never the existing Styx installation. Two installer
   versions replace a separate package-generation marker; they do not represent
   new Styx code or a Host runtime update. The known rc6 startup failure is not
   treated as a healthy old-version baseline.
2. Build a normal per-user Inno Setup installer for each version. It owns only
   its program directory, uninstall record and distinctly named shortcut.
   State remains in an explicit independent external directory. No services,
   tasks, file associations, URL associations or trust changes are installed.
3. Install old, launch the real App with `--state-dir`, compare an external CLI
   observation of the same state. Quit through existing App admission and the
   normal Quit command. Prior capability tests are separate evidence; repeat
   them only if the packaging boundary changes their execution environment.
4. Install new with the same probe AppId. Reopen, compare program hashes,
   identity/config bytes and actual capability operation. Uninstall only the
   probe; external state must remain. Do not count UI construction as runtime
   or account acceptance.

The exact verified public payload stays in the `app` child directory. Standard
installer metadata and its uninstall executable stay outside that closed file
set, so the existing package verifier remains effective without exceptions.

Automatic forced application shutdown/restart is disabled. This probe establishes
installer file/data behavior after normal exit; it does not yet establish safe
busy-task admission when a user manually launches Setup. Product integration
must keep existing Core work admission before invoking the standard installer.

The installer replaces App files. Current `deployment.json` still points to a
separate signed Host runtime: that runtime needs a deliberate Core/package
boundary decision. Neither an MSIX nor an Inno upgrade alone means Host version
alignment. The bespoke Host handoff helper is not invoked by this probe.

## Upstream references

- [Packaged desktop process and file behavior](https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-behind-the-scenes)
- [Shared data / flexible virtualization](https://learn.microsoft.com/en-us/windows/msix/desktop/flexible-virtualization)
- [Unsigned MSIX test deployment restrictions](https://learn.microsoft.com/en-us/windows/msix/package/unsigned-package)
- [MSIX service installation boundary](https://learn.microsoft.com/en-us/windows/msix/packaging-tool/convert-an-installer-with-services)
- [Inno non-administrative installation](https://jrsoftware.org/ishelp/topic_setup_privilegesrequired.htm)
- [Inno Restart Manager behavior](https://jrsoftware.org/ishelp/topic_setup_closeapplications.htm)
- [Upstream artifact verification](https://jrsoftware.org/isdl-verify.php)

## Build entrypoint

`node build-inno-probe.mjs ABSOLUTE_BUILD_JSON` invokes the pinned, separately
verified upstream compiler. The JSON supplies `packageDirectory`, `compiler`,
`stateDirectory`, a fresh `outputDirectory`, four-part installer `version`, and
independently reviewed `expectedPackageSha256`. The existing Styx verifier runs
before and after compilation. `toolchain.json` records the upstream compiler
version and observed artifact digests. The output receipt is a build receipt,
not native installation acceptance.
