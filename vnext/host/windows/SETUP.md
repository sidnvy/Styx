# Windows per-user setup preview

`build-setup.ps1 -PackageDirectory <verified native package> -OutputFile <fresh StyxSetup.exe>` creates one self-extracting Windows executable using the existing .NET Framework compiler. Run `build-windows-app.mjs` first; setup refuses a package that has not been natively compiled or whose inventory has changed. No extra installer toolchain is downloaded.

The setup window appears before extraction, reports preparation/checking progress, and offers Install (or Update), Restore previous, and Open Styx. It runs as the current user and installs under `%LOCALAPPDATA%\Programs\Styx`. The Start menu shortcut points to the stable `Styx.exe` launcher; a desktop shortcut is optional. An unrelated existing shortcut is never overwritten.

Each update installs a new release directory, verifies it, then atomically switches `installation.json`. The previous directory is retained for Restore previous. A failed copy or verification leaves the active version unchanged. Initial root creation is atomic and a failed first copy can be retried. Native Setup serializes operations with a per-user Windows named mutex; after an interrupted child exits, Retry can reclaim its stale transaction lock while holding that mutex. Direct internal JavaScript lifecycle calls never reclaim locks automatically. The launcher verifies the selected native executable against the receipt-bound package manifest before execution; the native App still verifies its full package before starting Core.

The launcher is protocol version 1 and is retained across updates. A future incompatible launcher needs an explicit migration; this is not an arbitrary executable replacement mechanism. Quit any currently running Styx instance before opening the new or restored version. Setup does not stop services or processes, migrate deployment configuration, or roll back configuration schema. Restoring binaries is supported only while the retained configuration remains compatible.

The standard App state remains `%LOCALAPPDATA%\StyxPreview\WindowsFirst`, outside the installation tree. Prior manually launched previews with a custom `--state-dir` are not silently adopted. Uninstall is not yet exposed as a user-facing action; deleting or cleaning device identities is never part of an update.

This is an **unsigned development preview**, not an Authenticode-signed public release. Hash checks establish consistency, not publisher trust. Native compilation and isolated lifecycle/shortcut tests do not establish Windows desktop presentation, onboarding, permission prompts, or ChatGPT account acceptance; those require the logged-in user's actual end-to-end run.

Focused tests: `node --test vnext/host/windows/setup-install.test.mjs` exercises actual generated package verification, copying and installation receipts with small fixture payloads. Native acceptance additionally uses a real compiled package on NAB in a dedicated test directory, without replacing existing shortcuts or state.
