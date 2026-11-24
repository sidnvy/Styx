# Windows installation

The supported installer is the native Inno Setup package published by the
[release workflow](../../docs/RELEASING.md). It installs the C# App, Rust core and
fixed native workers together. The retired .NET self-extracting preview and
JavaScript installer are not alternative product installation paths.

## User flow

1. Quit the running Styx App.
2. Run the new `Styx-<version>-windows-x64.exe` from the GitHub Release.
3. Open Styx from the Start menu. It reuses the existing native profile and pairing.

Installation is per-user and requires no elevation. Program files live under
`%LOCALAPPDATA%\Programs\Styx\versions\<package-hash>`. Inno installs the new
version and points the Start menu shortcut to its App. The native core and workers
come from that same version directory.

The installation guard checks for an existing App using the selected installation
root. It does not force-stop unrelated processes or use a custom App-maintenance
handshake. A running App must finish its normal Quit before its files are replaced.

Native state remains outside the installation tree. The default profile is
`%LOCALAPPDATA%\StyxPreview\WindowsFirst`; an explicit `--state-dir` continues
to name its own profile. Updating program files does not reset that state, erase
device credentials or require a new pairing.

Inno provides the normal Windows uninstall entry. Its file removal is separate
from profile and credential storage; uninstalling program files is not a request
to erase a device's retained identity.

## Source and build entry points

| Source | Responsibility |
| --- | --- |
| `ci/release-windows.ps1` | Build/package adapter used by the release workflow |
| `host/build-windows-app.mjs` | Assemble the native App with its Rust runtime |
| `host/windows/platform-update/build-inno.mjs` | Build the Inno package from that native input |
| `host/windows/platform-update/product.iss` | Installation paths, shortcuts and uninstall |
| `host/windows/platform-update/InstallGate.cs` | Existing-installation process checks |
| `host/windows/Styx.cs` | Native App startup, normal Quit and settings |

Use the persistent Windows project and toolchain described in
[WORKSPACE.md](../../../WORKSPACE.md) for development. A successful compiler or
installer build does not establish that the installed App reopened, selected the
intended runtime and reconnected; those are separate behavior checks.
