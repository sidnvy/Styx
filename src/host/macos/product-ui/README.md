# Native product UI

`../Styx.swift` creates one `ProductOwnedCore`, then `ProductModel(owned:)` and
`ProductWindowController(model:)`. Rust owns configuration, identity, pairing,
roles, capabilities and execution. Swift presents Rust observations and performs
the necessary AppKit, system permission and login-item calls.

## Ownership

| Component | Responsibility |
| --- | --- |
| `ProductOwnedCore` | Own the Rust child, its request/reply pipe and observed process exit. |
| `ProductCoreClient` | Call existing Rust operations and retain unknown native login outcomes without replay. |
| `ProductModel` | Present Rust state, retain temporary form drafts and share one observation loop among visible surfaces. |
| `ProductWindowController` | Own the main/settings window and menu presentation; closing a window does not quit Styx. |
| `ProductLoginStartup` | Observe and apply the native login-item operation under the Rust intent ticket. |

`startupStatus` and `status` drive restoration. Reads do not create setup or
replay an unconfirmed mutation. The App menu, main window and status menu use the
same settings controller. There is no second HTTP model, WebKit setup window,
service transfer flow or App Runtime updater.

## User entry points

- Create Gateway + Host: collect Tunnel configuration and local capabilities,
  then call `createLocal`; a retained setup uses `resumeLocal` explicitly.
- Join a Gateway: inspect the invitation, review its origin and certificate, and
  submit local choices. The Computers settings section preserves an in-progress
  or rejected original request, offers explicit `claimJoin`, and uses the existing
  role-retirement flow to cancel joining. Invitations authorize joining; the UI
  does not require a second administrator approval.
- Capabilities: call `hostCapabilities`; the next Rust observation drives toggles.
  Accessibility and Screen Recording remain separate macOS observations. Only an
  explicit permission action can request its matching OS grant.
- Tunnel settings: call `tunnelSave` and observe readiness. A blank replacement
  key retains the saved credential; the UI never reads it back.
- Invitations and removal: call Rust device operations. Pairing identity and keys
  remain with Rust.
- Optional ZIP export: Rust supplies the profile and archive; Swift owns the
  image picker and save panel. File-save success does not imply account setup.
- Quit: admit and join the original Rust child, then join its original Cua child.
  A failed cleanup remains visible and does not silently terminate the owner.

Updates use the normal signed App installer: quit, replace the App and reopen the
same profile. The current bundle supplies code; saved identity, pairing and
publisher continuity remain intact. Normal login startup remains available.

Temporary secrets are cleared when their surface closes. A copied secret is
removed from the clipboard only while its exact value and pasteboard version
still match; newer clipboard content is preserved.

## Tests and build

Compile `product-ui/*.swift`, `BrandGlyph.swift` and `Styx.swift` with the existing
native build command and cache described in `../../../../WORKSPACE.md`. Native
self-tests additionally define `STYX_TESTING`.

Tests inject a request closure at `ProductCoreClient`'s existing native boundary.
They use the same model, state projection and actions as production. The existing
native model self-test covers Rust JSON fields, observation coalescing, retained
form drafts, capability changes, invitations, join identity, saved Tunnel keys
and bounded ZIP responses. Permission and edit-menu tests host the actual views;
they inject permission observations and use a private pasteboard. Original-child
pipe, process-exit, Cua lifetime and AppKit quit tests remain separate.

Run affected native tests on PilotMac with the persistent project tools and
cache. Compilation, self-tests, live GUI behavior, system permissions and account
acceptance are distinct evidence. `NATIVE_VALIDATION.md` is a dated historical
record, not a description of the current source or installed App.
