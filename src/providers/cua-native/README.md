# Pinned upstream Cua with narrow behavioral fixes

Styx uses official Cua Driver 0.47.24 at the commit in `source.json`. Normal
snapshots, retained native elements, token resolution, sessions, permissions and
cleanup belong to upstream. There are no Styx private AX tools, replacement
snapshot/token stores, daemon observation methods, transport drain protocol or
owned-proxy file-descriptor extension in this worker.

`cua-0.47.24-styx-fixes.patch` retains only demonstrated behavior differences:

- On macOS and Windows, an internal `styx_strict_text:true` flag on standard
  `set_value` selects
  one text setter on the upstream snapshot object. It has no alternate setter,
  post-write activation, keyboard fallback or automatic write retry. A failed
  or lost setter reply remains Unknown. Normal upstream calls stay unchanged.
- DPI-unaware Windows HWND capture uses upstream WGC instead of accepting the
  independently observed partial PrintWindow image. WGC does not supply a
  proven screen origin; this image does not authorize mapped pixel input.
- Complete Windows SendInput followed by a focus transition has a typed
  outcome, recognized only in the retained-element click branch. Pre-dispatch
  failures and partial input remain errors; a completed dispatch is not proof
  of the application effect.

Linux Styx `set_value` uses upstream's normal route with the existing foreground
delivery option. Its AX/selection attempt remains first. If that route is unavailable
on Hyprland, the existing foreground keyboard selects all and replaces the value;
an empty value clears it. This shares the exact-target focus checks, in-process
Keyboard session, Unicode planner and outcome record used by `type_text`. The
replacement plan is complete before selection is sent, and no trailing Tab is added.
The superseded Linux strict extension and its dedicated fixture are removed;
macOS and Windows retain their existing implementations.

Core's owner/grant/session/observation/deadline checks and one-use dispatch permit
still apply. The standard ActionResult reports keyboard delivery as unverified;
independent fresh readback proves the value. No new native token is acquired or
cached by Styx. An uncertain write is not automatically replayed.

On macOS the existing signed App retains its embedded daemon and TCC identity.
Host uses the official MCP proxy and a distinct standard lifecycle session per
resource. Normal `end_session` success is checked before the original proxy is
closed and joined. App/process identity checks remain in the native Styx bridge;
the old Cua private IORegistry epoch protocol is removed. Official proxy calls
use the standard private socket path and server-side UID boundary. The retained
source-observation FD does not attest every subsequent proxy call FD against
a same-UID socket-replacement race; no new relay/custom transport is added.
A normal process exit
or a legacy daemon method ACK is not substituted for session cleanup success.

The common producer is `src/ci/release-cua.py` for all three platforms. It verifies
the pinned official archive, applies the single patch with zero fuzz, checks
original/final file hashes and builds with the locked upstream graph. The
upstream Cargo.lock is unchanged. Reuse native Cargo targets and dependency
caches with the same target/profile/features/compiler flags and resource-based
parallelism. No candidate-specific cache or extra Windows source producer is
required.

Actual compilation, installed native effects and release acceptance are separate
claims. The upstream comparison and original Linux activation counterexample
are recorded in `src/docs/rust-core-rewrite/CUA-UPSTREAM-REUSE-AUDIT-20261113.md`;
new-platform results must be bound to the current patch before a release claim.

Hyprland on Linux also exposes explicit foreground element typing through the
existing Cua `type_text` route. Activation uses the current Lua dispatcher API,
validated on Hyprland 0.57.1; older Hyprland dispatch protocols are not claimed
or retried through a fallback. Other Linux backends refuse this explicit route
before dispatch. It requires an observed enabled editable element, the exact
compositor window/PID, and native element focus. Each key rechecks that focus
and the existing action admission. It reuses Cua's Unicode key planner and
in-process Wayland virtual keyboard, including bounded roundtrips and cleanup;
no wtype child, optional isolated-input plugin or second writer is used. A focus change, cancellation or failed native reply
stops the call with an uncertain outcome and never authorizes replay.

The read-only `wayland_virtual_keyboard` fact reports normal compositor protocol
availability. It is separate from X11 pointer availability and never creates an
input device. Independent application readback is still required for acceptance.
