# Native runtime staging and stopped selection

Decision: retain the existing C08 verifier, private roots and C07 transaction
coordinator. A version directory supplies signed bytes; only the original
configuration transaction selects which verified runtime a profile uses. This
adds no Gateway, configuration writer, updater service or model client.

Implementation and acceptance are separate. Consult the Owner Control Report
for the exact tested SHA and platform. This document does not certify installation,
App replacement, service updates, reboot recovery or a Stable release.

## Staging

`styx release stage --payload-dir ABS --publisher-file ABS --expected-publisher PIN
--parent-dir ABS_PRIVATE_DIRECTORY --name NEW_VERSION --authorize --json`

The original approved publisher pin remains mandatory. The command verifies the
source C08 closure before writing, exclusively creates the version directory,
streams each signed member to `payload/`, copies the public key to `publisher.pem`,
flushes and independently verifies the destination. It returns `runtime_selection`
in its JSON report. Save that selection privately for the next explicit command.
No profile, service, identity, permission or current runtime changes during staging.
A partial destination remains for inspection; it is never adopted, overwritten or
deleted by an automatic retry. Lost completion is Unknown.

## Selecting and recovering

`styx release select --state-dir ABS_PROFILE --runtime-selection-file ABS_PRIVATE_JSON
--transaction-id NEW_ID --sequence NEXT_SEQUENCE --authorize --json`

The first supported scope is a completely initialized fresh native configuration
managed by the foreground CLI, with all roles desired Stopped. Stop the original
Host/Gateway processes and retain their actual exit/cleanup results before asking
for a switch. An OS execution lease excludes a still-running Host; the original
configuration writer excludes another management operation. A Stopped value alone
is insufficient. App-managed, migrated and persistent-service updates remain
outside this slice.

The selected package must have the original publisher, the same platform target
and explicit `native_runtime_selected_v1` reader support. The coordinator verifies
the complete original C07 chain and internally constructs the successor. Generic
`plan`/`apply` cannot change the runtime selection. The command changes only the
stopped configuration; starting a role is a separate explicit step.

An interrupted update is recovered using the existing `recover --state-dir ABS
--transaction-id ORIGINAL_ID --authorize --json` command. It reopens the exact
recorded before/target releases, reacquires actual execution exclusion and resumes
the same transaction. Missing or changed material remains fenced. Do not resubmit
an update under a new ID after an unknown result.

## Reader and identity contract

- The original root marker, deployment, pairing identity, credentials, TLS keys,
  Host seed and Gateway ready material remain unchanged.
- The immutable marker retains `native_management_state_v1`. Only the closed
  combination state schema 3 / `native_runtime_selected_state_v1` is added under
  that marker. It is not a general numeric reader-floor relaxation.
- `runtime_selection_v1` records the current C08 selection. The typed
  `runtime_update_v1` records the immutable bootstrap selection, the immediately
  previous selection and its selecting transaction ID/sequence.
- Every historical assignment must link its exact before bytes to the previous
  target, starting at revision zero. Consumers accept the current pointer only
  after that complete chain and the selected C08 bytes are verified.
- Original seed/ready runtime references become historical bootstrap bindings;
  workers come from the committed current selection. Superseded payload paths
  need not remain reachable merely to start the current runtime.

## Rollback and App boundary

Rollback is another authorized forward C07 transaction to a retained, verified
package that supports the new reader. It advances sequence/revision and retains
the reader barrier. No journal deletion, marker rewrite or old `state.json`
restoration is a rollback.

Old build85 and R85 binaries do not understand promoted state/history. They are
not valid recovery executables after promotion. Retain a compatible signed Core
and runtime before updating. Exercising two signed versions with identical code
proves selection and forward rollback mechanics, not backward code compatibility.

Mac/Windows App replacement remains a distinct lifecycle task: keep the original
App identity/signature/permission subject, settle original App/Core/payload
handles, retain an updater outside the replaced bundle, and handle the separate
Host/Gateway roots without pretending they are one atomic transaction. The CLI
selection primitive does not establish that acceptance.
