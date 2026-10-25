# ADR-031 — Exact-object accessibility write attempt

Status: integrator accepted for incremental implementation; not built, tested,
packaged or enabled by this document. The accepted a8572d2 .8 candidate remains
unchanged. This is an explicit narrow admission increment, not a generic change
to Unknown permissions or the frozen public38/Computer10 catalog.

The original Cua0.36 native set_value may repeat a write after an uncertain reply
and may invoke activate after a successful text replacement. An outer no-retry
wrapper cannot repair those effects. Its check_permissions does not establish
OS input authorization. Global Wayland keyboard input also cannot guarantee an
exact window merely by checking focus beforehand.

Keep those routes fenced. Add one private, signed Linux provider route: resolve
only an original acquired snapshot element into an exact EditableText target,
hold the original accessibility bus connection, unique owner, original PID/birth,
frame/window and object path, then consume an opaque target once for one
SetTextContents call. No ordinal rewalk, InsertText, Value, Selection, activation
or input-backend fallback. The standard Cua tools are not silently modified.
Private native tools belong only to the original owned child/stdio lifetime;
public session labels are not authentication and Core remains the owner/grant/
operation authority. New native bytes require a distinct immutable source/patch/
build/signature closure; original signed artifacts are untouched.

There is no atomic permission-only AT-SPI write query. The Core therefore gains
an explicit DesktopAccessibilityWriteAttempt purpose, issued only through its
dedicated prepare port. It requires current remote/local grants, original
owner/resource/session, an acquired native observation and a verified once-write
backend. Authorization stays Unknown; final OS authorization occurs inside the
protected native method invocation. This does not make Keyboard, Pointer or
ordinary Accessibility operations Granted. Known Required, Denied or Revoked
states remain closed. C01 authorization layers still all apply; an attempted
write is explicitly side-effecting, never described as a harmless permission
probe. Generic check_admission remains unchanged in behavior.

A successful native reply acknowledges text replacement only; independent fresh
readback establishes its effect. False, errors and missing replies after a
possible send remain Unknown and do not replay. Only a proven pre-send refusal
is NotDispatched. Target consumption, timeout, source/worker loss, owner end,
new snapshot or grant revocation invalidate future use. The final runtime gate
must recheck current authority before sending; revocation after OS dispatch
cannot retract a delivered D-Bus call and must preserve its result or Unknown.

An original connection and unique bus owner are not an application object
instance generation. Reused object paths and native snapshot invalidation need
explicit validation/event handling; do not claim an immutable kernel object pin.
Only same-process exact bound targets are admitted initially; unsupported
cross-process accessibility targets fail closed. Tests distinguish pure Core
contracts, private-bus transport fault counters and owned real GTK effects.
Compilation, a presentation alias, a native method ACK and task completion stay
separate. Other input routes and platform permission models are not covered.


The final runtime check occurs after private read-only acquisition and before
polling the only write request. It refreshes the original Desktop source and
rechecks the same Core owner, resource, immutable payload, grant revision,
session, observation and pinned process. The native job uses the absolute
original operation deadline, including queueing, acquisition and this check.
A revocation after this final admission cannot retract a dispatched OS call;
its acknowledgement/unknown history is preserved independently of delivery.

Native object-event fencing is being added on the original AT-SPI connection:
known structure changes, Defunct or event-stream loss invalidate eligibility
captured by the original snapshot. This guards observed invalidation; it does
not manufacture an atomic remote object-generation handle or assume every
application reports every mutation. Final artifact and real effect evidence
are required before this implementation is reported as accepted.
