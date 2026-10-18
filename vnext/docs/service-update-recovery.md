# Owner-controlled service update and offline bootstrap recovery

`host/service-update.mjs` provides a local JavaScript API for a trusted owner
program. It does not expose MCP administration, install service definitions,
execute supplied shell strings or silently resume an interrupted service action.
It requires an existing verified active release and a distinct staged signed
candidate. Both must contain the signed private-storage helper, installer,
launcher and platform Node executable. Older incomplete releases remain usable
through the existing installer, but cannot enter this stronger transaction.

Run the updater with a trusted independent Node executable **outside** the
installation root. Stop observation must account for all processes that can lock
its stable executable. Windows replacement can still fail if another process
holds a file; the transaction then retains its recovery lock. This is not
physical Windows/macOS service acceptance.

## Local API and callback contract

```js
import {updateServiceRelease, inspectServiceUpdate, recoverServiceUpdate}
  from './host/service-update.mjs';
const result = await updateServiceRelease({
  installRoot, version, publicKeyPem, timeoutMs: 10000,
  stopService, startService, checkHealth
});
```

Callbacks receive a frozen `{transactionId, version, previousVersion, phase,
signal}`. They are trusted executable owner code bound to one exact owned native
service. `true` means observed completion; health `false` means an observed
unhealthy service. Stop/start callbacks must not infer completion from an ACK;
observe actual service state. They must honor AbortSignal, never retry an
uncertain command internally, and keep credentials/output out of receipts.
Timeout is bounded from 1 to 60000ms per callback; blocking callbacks cannot
avoid a timeout by returning after its deadline.

The transaction obtains the same exclusive `.health-update-lock` as the earlier
health-gated activation path. It durably records intent before stopping,
switching signed stable bootstrap/runtime and active pointer, starting and
checking post-switch service health. A healthy candidate returns `activated`.
A known false start/health result causes one confirmed candidate stop, signed
previous-byte and exact-pointer restoration, one prior start and one prior health
check. A healthy restored service returns `rolled_back`.

A thrown, timed-out or malformed callback returns `needs_recovery`. It retains
the lock and current durable phase; no later service callback is issued. Late
completion cannot mutate the transaction or trigger replay. Filesystem or
signature failures also fail closed. Receipts are private files under
`update-transactions/TRANSACTION_ID.json`; they contain fixed reasons, release
identities/hashes and pointer snapshots, not callback exception text or secrets.
Files and directories are fsynced where the OS exposes that operation. Node does
not offer a portable Windows directory-fsync handle; power-loss durability on
Windows is therefore not asserted.

## Explicit interrupted-transaction recovery

1. Stop and inspect the exact owned service through an independent trusted
   administrative channel. Verify no stale start/stop callback or updater is
   still executing. Never steal another updater's lock.
2. Read the recorded transaction with
   `inspectServiceUpdate({installRoot, transactionId})`. Unknown IDs, mismatched
   lock ownership, changed native paths/permissions, external pointer changes
   and unsigned/modified previous releases are refused.
3. Invoke `recoverServiceUpdate({installRoot, publicKeyPem, transactionId,
   confirmStopped, timeoutMs})`. `confirmStopped` is a **read-only** observer of
   the already stopped service. It receives the same callback context. Recovery
   does not replay an uncertain stop/start, perform a health action, or start the
   service. It restores signed previous bootstrap/runtime and the exact original
   active pointer, then returns `recovered_stopped` and releases its own lock.
4. Independently review the result and explicitly start the owned service with
   its normal native service administration. Verify native Exec/Cua behavior.

Recovery accepts mixed previous/candidate stable bytes only when their hashes
match this transaction's originally verified signed releases. Unexpected stable
bytes or a concurrent legacy pointer selection are never overwritten. A crash
before a complete receipt/owner record, corruption of that private evidence, or
a failure removing a terminal lock requires explicit owner investigation; this
API does not guess, remove unknown locks, or automatically repair such state.

Tests use signed fixture payloads and fake callbacks without touching services.
They also kill an isolated updater subprocess to verify durable start intent
and explicit stopped recovery. Actual native service acceptance must separately
record exact service ownership, observations and cleanup. No GUI/ChatGPT,
publisher-signing identity, runtime-version upgrade or 24-hour soak is implied.
