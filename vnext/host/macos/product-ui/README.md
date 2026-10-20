# Native product UI

The AppKit owner embeds `ProductView` in `ProductWindowController` with `NSHostingView`.
All configuration, mutations, execution and receipts remain in the existing Node Core.
Compile all `product-ui/*.swift`, `BrandGlyph.swift` and `Styx.swift`; copy the supplied brand JPEGs and the
validated default plugin PNG to `Resources/brand/`.

## Integration contract

- `ProductWindowController(sessionURL:)` accepts the existing private child-pipe bootstrap.
- `present()` reopens the retained window; closing the window clears temporary secrets.
- `showPreferences()` opens language/capabilities/login settings.
- `prepareToQuit(completion:)` invokes authenticated `/api/app/quit` before the App owner terminates.
- `currentDesktopReadback(challengeID:)` reads an actual visible `NSTextField` with accessibility
  identifier `styx-acceptance-target`; its localized label is `桌面验收输入框` / `Desktop acceptance field`.
- The timer submits only matching, unexpired visible field values while desktop proof is pending.
  Core still requires authenticated Cua before/action/after evidence for the actual App PID. A local
  text edit or UI model state cannot establish Computer Use verification.
- `productCoreSelfTest()` covers strict bootstrap parsing, authorization decoding, role projection
  and read/write route separation. Invoke from the App's existing `--self-test` path. It does not
  claim GUI, permissions or account verification.

`ProductCoreClient` is an ephemeral URLSession client with cookies, URL credentials, caches and
proxies disabled; it rejects redirects. It obtains CSRF through the existing authenticated session
endpoint and supplies the exact Origin on every request. Route allowlists and a fixed binary export route prevent arbitrary URL
requests. ZIP and JSON share the same private session, Origin and CSRF checks; responses
must match the exact requested URL and MIME type. The archive obeys Core’s existing 2 MiB
bound and is written without extraction to a native save-panel destination. Raw transport/response error text and secret responses never appear in the status UI.
The model credential is available only through an explicit handoff action, expires on screen after
at most 60 seconds and is cleared on close. The clipboard is cleared only if the copied secret is
still the exact pasteboard content/version; it never destroys unrelated newer clipboard content.

## Real workflow mapping

- Welcome → create or join; no language picker or technical role selection.
- Capabilities → trusted packaged Host defaults and real create/local-setup or join advance.
- Browser preparation → existing `browser/prepare`, then owned foreground connection.
- Browser requested but not approved → Core's `not_approved` observation skips Browser preparation and leaves approved Exec available. Computer Use permission routing uses the actual approved foreground Host configuration, never deployment intent.
- Computer Use panels read AX/screen preflight separately. Allow requests only that permission, once per process; the OS owns its prompt and any navigation from it. A separate Settings action only opens the matching pane. The menu navigates to the App permission page without prompting.
- Platform Tunnel ID/runtime key → `tunnel/configure`, then `tunnel/start`.
- Default ChatGPT connection → official Add custom MCP server → Tunnel → Create as a plugin → install. No mandatory local create/reuse picker or presentation form. Explicit user confirmation creates a missing default local receipt profile, then uses `plugin/record`; saved custom/reused profiles are retained unchanged.
- Optional plugin ZIP editor → name/description/icon → native save panel → `plugin/profile` only when edited/missing → authenticated binary `plugin/export`. The existing Core performs real local Gateway verification and builds the archive. Metadata and onboarding skill travel in the ZIP; the user uploads and installs in ChatGPT. No automatic platform synchronization or account success is claimed. ZIP Tunnel import compatibility still needs actual target-account validation; the optional route is labelled preview.
- Entering the optional ZIP editor fills only a missing icon in an unsaved draft using the real packaged brand. Custom icons are retained. Saved-file feedback appears only after atomic writing succeeds; cancelling the native save panel does not mutate Core. Existing reuse profiles stay on their official management path.
- Connection context changes block ordinary confirmation/export. A separate explicit review action preserves the saved presentation/selection and rebinds the local receipt profile after confirmation; previous account/export receipts become invalid. Computer identity and credentials are not regenerated.
- Target-chat challenge/results → existing acceptance APIs; independent human target-chat confirmation.
- Overview/Computers/Chat → observed Core projections; no fabricated success events or activity page.
- Revocation → explicit NSAlert then `device/revoke`; never removes local identity files.
- Login preference → `app/lifecycle` observation, `app/login` mutation, gated by session capability.
- Capability changes → inspect fresh public and current-process owner observations. Browser changes explicitly confirm pausing this App's owned connection through `foreground/stop`, retain Core's offline checks, and resume only after a confirmed complete transaction. Computer Use-only changes honor `foregroundRestartRequired`. Unconfirmed mutations are not replayed; explicit recovery remains available. Foreign, service-owned or uncertain connections require separate reconciliation and are never stopped by the UI.

## Boundaries awaiting integration/validation

The native settings view includes CLI as the current Host's built-in capability because
Core has no independent Exec disable flag. Browser changes use Core's offline capability
transaction; unchanged Browser is omitted when saving Computer Use. Joined Hosts show
owner-managed optional capabilities and cannot expand their own grants through settings.
Local-only ingress displays a prerequisite and cannot generate a misleading remote invitation.
A controlled ingress preparation UI must be attached when its transaction API is available.

Default plugin branding requires the packaged PNG produced from the supplied source. Custom PNG
files are chosen through the native picker and fully validated again by Core. Language follows
macOS preferred languages; the settings button opens Language & Region. Packaging must advertise
both English and Simplified Chinese so macOS exposes per-App language selection.

Native compile, GUI controls, keyboard/accessibility, real Cua, system permissions, actual plugin
installation and target-account acceptance require separate platform evidence. Local protocol
checks are not substitutes for those gates.
