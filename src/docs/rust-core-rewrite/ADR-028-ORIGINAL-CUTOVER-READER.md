# ADR-028 · Original-identity cutover and signed migrated reader

2026-10-25. Incremental C07/C08 implementation. Product scope and public MCP
contracts remain unchanged. This decision does not authorize ordinary activation.

## Decision and compatibility

The first legacy-to-native canonical state conversion remains a successor of the
original credential-retirement transaction, in its original state-root management
journal and continuously held writer/maintenance custody. Prepared/Applied use
existing Core phase rules and exclusive-write/conditional-rename/fsync primitives.
The exact old state is retained as an immutable attachment; all other captured
identity, pairing, CA, publisher, Browser and source observations are revalidated.
No enrollment-child second writer, generic fence clear, or invented successful
legacy step is allowed. Recovery inspection only validates existing complete data;
it does not recreate process proof, run a probe, commit or admit ordinary work.

A migrated state uses the closed `NativeMigratedStateV1` reader and carries its
original transaction, retirement, history, candidate and preservation hash bindings.
Old native state encoding is unchanged when migration is absent. Later native
transactions must retain the exact migration binding.

A signed runtime candidate must explicitly declare
`minimum_reader: native_runtime_migrated_v1` before any cutover preparation write.
The old `native_runtime_v1` remains valid for its original reader only; a verified
old worker closure does not prove its CLI can read migrated state. Schema2, the
management-state JSON version2 and original preview bytes remain unchanged. Old
readers reject the new enum rather than silently accepting an unsupported state.

The native binary provides `build-info --json` with a closed target and supported
state-reader declaration. Its actual same-source build receipt and binary hash
bind this declaration to the new signed manifest. An old receipt cannot be
upgraded by an argument or editing an existing signed package. `build-info` text
output stays compatible. A declaration is not runtime health, platform permission
or final migration acceptance.

## Callers and migration

- Contracts: `native_release::{NativeReleaseReader, NativeReleaseManifest}` and
  `native_management::NativeMigrationBinding`.
- Verified release: retained signed manifest plus reader-support check.
- `SettledLegacyRuntime::prepare_native_transition`: reject unsupported candidates
  before writing a marker or cutover record.
- `PreparedLegacyCutover::apply_candidate`: fixed, owned local Exec effect probe,
  complete physical cleanup, exact canonical conversion and Applied receipt.
- `inspect_pending_cutover`: closed pending-data inspection with root/deployment/
  history bindings; ordinary admission remains fenced.
- Release producer/builder: immutable same-source binary, receipt and original
  publisher; no mutation of old signatures or identities.

## Required evidence and limits

Verify old/new/unknown reader and preview rejection, actual signed artifact
verification, stale/tampered input rejection, same-journal interrupted phases and
file-budget peaks. Then freeze one source revision, run the complete local gate,
build and sign the candidate, and run the full original-runtime scenario with an
independent raw-file/process oracle. Unit/fixture results are not platform acceptance.

The currently composed facade stops at Applied plus owned local Exec evidence.
Final paired Gateway/Host TLS validation, Verified/Committed, ordinary migrated
reader/start/restart and safe rollback remain required. The old Gateway CA used
as its server leaf is rejected by standard Rust TLS; continuity requires retaining
the original CA/key/pairing and explicitly binding a separate CA-signed server
leaf. Do not weaken TLS verification or claim old exact-leaf evidence applies to
a new server leaf. macOS/Windows signatures and OS permission ownership require
their own real-device evidence.
