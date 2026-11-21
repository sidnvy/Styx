# ADR-023 — narrow AX read acquisition in the original operation ledger

Status: implementation in progress; no native acceptance claimed.

## Problem and decision

The Linux Desktop supervisor has real authenticated WindowsRead evidence. Other OS permissions are Unknown. Requiring a prior Granted AX descriptor before the first native tree read prevents acquiring that evidence. Promoting the entire `desktop.accessibility` descriptor after a read would also authorize `set_value`, which is not justified by reading a tree.

Keep the frozen public capability/tool contracts and ordinary execution policy. Introduce one internal immutable Core operation purpose, `DesktopAccessibilityReadAcquisition`. It is prepared only against an original DesktopAgent resource with the same current owner incarnation/device/session, AX capability, no input observation, and the same original operation ledger. Its dispatch permit remains move-only and contains the original bytes. No purpose flag is accepted from the network.

Only the trusted Linux Cua adapter can classify the existing `get_window_state` branch as acquisition: exact positive PID/window, `include_screenshot:false`, `include_accessibility_tree:true`, `tree_format:elements`, explicit bounded walk/depth/deadline, no session override, query/diff, output path or other branch. The provider rechecks this immutable payload when consuming that purpose. OS/native APIs still enforce the actual read. The original signed Cua remains unchanged.

Acquisition can try an Unknown/Required OS authorization and Unavailable AX provider. It still refuses explicit Denied/Revoked, missing remote grant/config/local policy, wrong device/session/generation, lock/disconnection, maintenance and deadline expiry. Ready/Degraded only; it does not use another session or imply input permission. Inspecting old Unknown metadata is not proof of availability: the exact source and original live worker are checked independently before and after the real native read. Ordinary execute/resource-access policy stays unchanged.

Delivery authorizes the exact acquisition action again, only after native ACK and original Core action success, with its parent resource still retained/live and current owner/grants/session/deadline. A lost native response remains Unknown and is never replayed. A completed but malformed/degraded/partial tree is a typed insufficient-read result, preserving the native ACK rather than claiming NotDispatched.

The first slice validates fixed upstream structured results, exact target, complete trusted elements and token consistency. Host replaces native snapshot/token strings with a nonreused Host presentation alias; no native snapshot is input authority. This slice does not publish AX Granted, mint an input ObservationId, retain a writable target map or open the existing input refusal gate. Later input admission needs separately proven operation-specific OS authorization, exact owned native observation/source/process lifetime bindings, live revocation and independent effect evidence.

## Compatibility and ownership

No public MCP schemas/tool counts, wire DTOs, installed member bytes, publisher/identity/pairing/TCC, or JS management authority change. Core owns purpose/once-only/outcome; Host owns source/grants/delivery; native adapter owns fixed branch and result parsing. Existing normal operation callers remain Execute. A future generic acquisition API or AX read-to-write promotion is explicitly excluded.

## Required evidence

Meaningful Core scenarios cover once-only, ordinary execution remaining refused, grant/revocation/session/deadline negatives, parent/owner-bound delivery and Unknown no replay. Parser scenarios cover real fixed-source shape, degraded/partial/count/token contradictions and bounded alias projection. One actual ordinary CLI/TLS/WSS/MCP owned GTK journey must read the exact window tree/nonce, keep input/capture refused, preserve independent unchanged input events, continue Exec and confirm original owned cleanup. Mock/parser PASS is not native/platform acceptance. Cross-platform implementations and full release gates remain open.

## Exact window capture extension

The AX-only slice passed its actual owned GTK read/refusal/Exec journey at fc470e6. A second fixed purpose, `DesktopWindowCaptureReadAcquisition`, now applies the same Core acquisition/delivery rules only to an exact PID/window screenshot with AX disabled and explicit bounded image dimension/deadline. It never permits the whole desktop, file output, implicit targets, AX, pointer or keyboard. Both purposes revalidate their own immutable branch in the native adapter. PNG/schema projection is only a protocol check: actual acceptance requires independently calculated pixels in the owned fixture and confirmed original cleanup. Full-frame/AX+capture combinations and input remain closed. No descriptor is promoted to Granted by either read.

## macOS descriptive rows without input references

Native macOS can return a complete window tree containing an object whose
`AXUIElementDestroyed` subscription is unsupported, even while the window and
editable/button objects support the required notifications. Such a row remains
explicitly `read_only:true` and carries no `element_token`. Core validates its
index/shape/counts and preserves its descriptive data, but never inserts it in
the native-token map or assigns a Host input alias. A token on a read-only row,
invalid flag type or duplicate index is contradictory and refused. Native
editable-target acquisition also refuses that original read-only object.
Required window subscriptions and all input-target lifetime checks still fail
closed. Other subscription failures still fence the original observer.

The pinned Mac capture-only format has explicit native frame validity, point
bounds/backing scale and exact PNG dimensions, plus an empty zero-element
Markdown placeholder. The adapter validates this specific shape and geometry,
then projects only the exact image and target. It discards the placeholder and
all native snapshot/capture references; this read never authorizes input.
Protocol/reference PASS remains distinct from installed Gateway acceptance.


## macOS exact element click capability evidence

The pinned mature Mac `click` element route performs AX actions and can restore
key-window state. The original authenticated daemon's fresh Accessibility
permission and successful current window probe therefore provide its Pointer
and WindowsControl capability evidence. Leaving both permanently unavailable
incorrectly rejects an exact observed element before native dispatch, even
when AX text input and window capture work.

This registration does not supply target authority. Host still requires the
same owner/resource/process/window, a fresh complete AX observation and native
token, every grant, and the final source refresh before one dispatch. All other
mutating routes without an exact Host click/write binding remain refused;
Keyboard remains unavailable on macOS in this slice. Missing native permission or current window
probe cannot authorize the click. Original not-dispatched receipts are retained,
and actual independent button effects remain required for acceptance.


## Descriptive reads and incomplete Linux Chrome observations (2026-11-17)

Read acquisition distinguishes a native **descriptive result** from an **actionable
observation**. A target-matched, structurally valid partial/degraded elements tree
is returned with `display_only:true`, `read_only:true`, `elements_complete:false`,
`input_authorized:false`, and its sanitized native reason. All native snapshot,
element-token and action fields are removed. No Host alias or input observation
is installed. The existing pre-read invalidation prevents a previous writable
map surviving this result. Complete observations retain the existing exact
window, owner, native-token, permission and once-only input checks.

The concrete niuda reproduction was not a complete Chrome tree rejected solely
for a strict flag: Cua 0.47.24 returned one window row, `degraded:true`, and
`x11_property_fallback_partial` because the running Chrome did not register on
the session AT-SPI bus. Screenshot/window discovery do not prove AX content.
Returning this row makes the actual limitation visible; it does not manufacture
DOM controls or enable Chromium accessibility, CDP, or broad pointer input.
Chrome's runtime accessibility must be enabled before native controls can be
observed. Do not restart Chrome or copy its profile to work around this.

Parsed actionable responses now own their validated data. Projection cannot
accept a second response argument, so repeated cryptographic comparisons of the
same immutable response are unnecessary. Native-reference **fields** are
translated or removed; native-looking text in a page label is ordinary content
and does not confer authority. Cardinality is checked once against returned
rows rather than imposing a second conflicting completeness flag.


## Linux/Hyprland text replacement and insertion (2026-11-21)

Linux `set_value` uses Cua's standard operation with the original public PID,
window, element token and value. The adapter supplies the existing foreground
mode so native replacement can activate the target when necessary. Cua first
uses the control's accessibility setter. When that route is unavailable on
Hyprland, it reuses the existing native keyboard writer to select all and replace
the contents; an empty value clears the field. This fixes the actual standard-call
Chrome reproduction, whose entry exposes neither EditableText nor Value.

The Host retains its existing Computer setting, owner, observation and late gate.
Linux no longer requires the Styx strict-text extension or its narrow response
shape. The existing one-call transport preserves Cua's native result, including
its route, delivery and readback evidence. A native acknowledgement is followed
by independent observation; transport uncertainty never triggers another call.
The macOS and Windows setter paths are unchanged.

`type_text` is an explicit Linux/Hyprland foreground keyboard action on the same exact
Host-owned AX element used by click. It requires PID, window ID, current element
token, text, and `delivery_mode:"foreground"`. It inserts at the caret; it does
not select all or replace the field. No pixel, clipboard, global focused-target
or caller-selected session form is exposed. The existing observation/grant/late
dispatch gate is shared; Keyboard and WindowsControl authority are checked too.

On Lua-dispatch Hyprland (validated on 0.57.1), the native executor verifies the
exact address/PID, sends one normal compositor focus descriptor, and invokes the
retained object's Component.GrabFocus. The existing in-process Wayland keyboard
writer and Unicode planner then deliver text. Each stroke rechecks the exact
active window and enabled, editable, focused element; paired press/release and
flush stay under Action::admit. Cancellation fences the connection and cleanup
is bounded. The previous desktop focus is not restored.

The shared keyboard writer does not require Cua's optional compositor plugin.
`type_text` inserts directly through that writer; `set_value` first tries its
standard accessibility route. Any uncertainty from the keyboard writer is
returned without another input attempt. Native permission discovery uses actual
virtual-keyboard globals, not XWayland availability or an environment hint.
User input must be independently observed after completion.
