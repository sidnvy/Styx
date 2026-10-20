# Native product UI

The AppKit owner embeds `ProductView` in `ProductWindowController` with `NSHostingView`.
All configuration, mutations, execution and receipts remain in the existing Node Core.
Compile the four Swift files with `Styx.swift`; copy the supplied brand JPEGs and the
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
endpoint and supplies the exact Origin on every request. Route allowlists prevent arbitrary URL
requests. Raw transport/response error text and secret responses never appear in the status UI.
The model credential is available only through an explicit handoff action, expires on screen after
at most 60 seconds and is cleared on close. The clipboard is cleared only if the copied secret is
still the exact pasteboard content/version; it never destroys unrelated newer clipboard content.

## Real workflow mapping

- Welcome → create or join; no language picker or technical role selection.
- Capabilities → trusted packaged Host defaults and real create/local-setup or join advance.
- Browser preparation → existing `browser/prepare`, then owned foreground connection.
- Computer Use permission panels read AX/screen preflight separately and open OS settings on click.
- Platform Tunnel ID/runtime key → `tunnel/configure`, then `tunnel/start`.
- Plugin presentation/reuse → `plugin/profile`; official direct installation → `plugin/record`.
- Target-chat challenge/results → existing acceptance APIs; independent human target-chat confirmation.
- Overview/Computers/Chat → observed Core projections; no fabricated success events or activity page.
- Revocation → explicit NSAlert then `device/revoke`; never removes local identity files.
- Login preference → `app/lifecycle` observation, `app/login` mutation, gated by session capability.

## Boundaries awaiting integration/validation

The initial native settings view includes CLI as the current Host's built-in capability because
Core has no independent Exec disable flag. A change to Browser selection still requires Core's
capability migration implementation; unchanged Browser is omitted when saving Computer Use.
Local-only ingress displays a prerequisite and cannot generate a misleading remote invitation.
A controlled ingress preparation UI must be attached when its transaction API is available.

Default plugin branding requires the packaged PNG produced from the supplied source. Custom PNG
files are chosen through the native picker and fully validated again by Core. Language follows
macOS preferred languages; the settings button opens Language & Region. Packaging must advertise
both English and Simplified Chinese so macOS exposes per-App language selection.

Native compile, GUI controls, keyboard/accessibility, real Cua, system permissions, actual plugin
installation and target-account acceptance require separate platform evidence. Local protocol
checks are not substitutes for those gates.
