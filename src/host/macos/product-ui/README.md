# Native product UI

The production App entry in `../Styx.swift` creates one `ProductOwnedCore`, then
`ProductModel(owned:)` and `ProductWindowController(model:)`. The Rust App process
owns configuration, identity, pairing, role and service decisions. Swift presents
its results and performs the necessary AppKit, permissions and login-item calls.
There is no production HTTP management backend or separate App Runtime updater.

## Current ownership

| Component | Responsibility |
| --- | --- |
| `ProductOwnedCore` | Own the Rust child, its request/reply pipe and observed process exit. |
| `ProductCoreClient` | Map UI actions to the existing Rust operations; retain unknown login/service outcomes without replay. |
| `ProductModel` | Present Rust observations, keep temporary form drafts, and share one observation loop among visible surfaces. |
| `ProductWindowController` | Retain the main/settings window and menu presentation; closing a window does not quit Styx. |
| `ProductLoginStartup` | Observe and apply the native login-item operation under the Rust intent ticket. |
| `ProductServiceActions` | Present the committed service client and export its existing installation request. |

The native model's `startupStatus` and `status` reads drive restoration. Ordinary
reads cannot create setup or replay an unconfirmed mutation. The App menu,
main window and status menu reuse the same settings controller.

## User entry points

- Create Gateway + Host: collect the Tunnel configuration and local capabilities,
  then call Rust `createLocal`; a retained setup uses `resumeLocal`.
- Join a Gateway: inspect the invitation, review its origin and certificate, and
  submit the device-side choices through the existing Rust join operations.
- Settings: capability controls call Rust `hostCapabilities`. System permission
  controls observe Accessibility and Screen Recording separately; the explicit
  permission or settings action uses the corresponding macOS API.
- Tunnel settings: `saveTunnel` calls Rust `tunnelSave`, then observes its status.
  A blank key retains the saved credential; the UI does not read it back.
- Device invitations and removal: use Rust invitation/device operations and their
  observed results. Current pairing identity and keys remain with Rust.
- Plugin details and optional ZIP export: Rust supplies the profile and archive;
  the UI owns the native picker/save panel and reports a saved file only after
  writing succeeds. Account installation is a separate user action.
- Quit: use the owned Rust child's quit admission and observe its exit. Existing
  service-client behavior comes from the committed native manager transfer.

Updates use the normal signed App installer: quit, replace the App and reopen the
same profile. The current bundle supplies executable code. There is no payload
handoff ticket, helper launch callback or second update state in this UI.

Temporary secrets are cleared when the surface closes. A copied secret is removed
from the clipboard only while its exact value and pasteboard version still match;
unrelated newer clipboard content is preserved.

## Tests and build

Compile all `product-ui/*.swift`, `BrandGlyph.swift` and `Styx.swift` with the
existing native build command and cache described in `../../../../WORKSPACE.md`.
The product build defines `STYX_PRODUCT_UI`; native self-tests additionally define
`STYX_TESTING`.

`ProductCoreClient(sessionURL:)` and its loopback HTTP transport exist only under
`STYX_TESTING`. Existing presentation, observation, invitation, permission and
ZIP-transport fixtures still use that injection. Their synthetic legacy snapshots
are test inputs, not a second production backend or proof of the current Rust
user flow. The production owned-child path must be compiled separately.

Run affected native tests on PilotMac through the persistent project's tools and
cache. Compilation, self-tests, live GUI behavior, system permissions and account
acceptance are distinct evidence. `NATIVE_VALIDATION.md` is a dated historical
record; it does not describe the current source or a current device installation.
