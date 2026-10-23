# Local health-gated signed activation

`host/health-update.mjs` exports `activateHealthyRelease`. This API gates the
existing atomic active-pointer switch on a health observation of an already
staged, publisher-signed candidate. It does not install/restart a service,
refresh bootstrap, issue a shell command, or replay an action.

Call it from trusted local operator code with an explicit asynchronous,
read-only `checkHealth(context)` callback returning exactly `true` for observed
health. Context contains the version, immutable staged release path, manifest
hash, previous version and AbortSignal. Never construct callback code from
model output or remote configuration. No callback exception messages, output,
credentials or configuration are persisted by this module.

The old active pointer remains byte-for-byte untouched while health is checked.
A rejected/failed observation retains that pointer, including its original
previous-version and timestamp fields. Signature errors, candidate changes,
changed bootstrap/runtime and externally changed active pointers fail closed.
After health succeeds, the candidate and previous signed release are reverified
before the existing atomic activation. Rollback after a failed observation is
therefore retention of the unchanged previous state; this API deliberately does
not activate first and then guess whether a side effect should be replayed.
Existing explicit `rollbackRelease` remains available for trusted operator
recovery after a successful activation, with its original signed-generation
verification semantics.

An exclusive per-install `.health-update-lock` directory rejects simultaneous
gated operations. Legacy direct activation/rollback APIs do not honor this lock;
the gate compares exact pointer bytes before committing and never overwrites a
change observed during health. Operators must serialize all update entrypoints;
there is no cross-process OS transaction covering uncooperative legacy writers.

Timeout defaults to 10 seconds and accepts 1–60000 ms. The callback must honor
AbortSignal and avoid blocking the event loop. JavaScript cannot preempt a
synchronous operator callback. A probe finishing after its deadline is rejected.
On timeout the old pointer remains untouched and the lock is retained, even
if the probe later resolves successfully. No callback is retried or replayed.
After process death or timeout, a trusted local operator must inspect the probe
outcome and release the lock manually before another attempt. The API never
steals locks based on age or guessed PID liveness.

Stable launcher/verifier and bundled Node must match signed candidate and
previous-generation payload hashes. Any bootstrap/runtime upgrade requires a
separate offline owner-controlled switch. This restriction avoids partially
replacing a running Windows executable or leaving an incompatible previous
bootstrap behind. This is a useful application-payload update subset, not a
complete runtime upgrade or post-restart recovery orchestrator.

Tests use isolated signed fixtures and perform no service operations. Native
cold install, restart/health integration, physical Hosts, OS signing,
notarization, ChatGPT acceptance and soak remain separate release gates.
