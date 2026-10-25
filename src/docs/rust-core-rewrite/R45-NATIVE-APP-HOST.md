# R45 — Native Windows App to Rust Host

This slice connects the existing Windows C# UI to the existing owned Rust Host actor. It does not complete native management parity or replace installed legacy profiles.

## Implemented boundary

- The App launches a fixed packaged Rust executable over its owned stdin/stdout transport. `release verify --runtime-selection` produces read-only selection data through the existing C08 verifier; UI-provided data cannot select arbitrary executables or runtime paths.
- `__app-core --runtime-selection-file` accepts typed `inspectJoin`, `join`, and `claimJoin` operations. Inspection is read-only. Join consumes the inspected invitation after explicit origin/certificate confirmation and creates fixed private input files under the original App container, using the existing platform writer. Partial publication stays fenced and is not retried or overwritten.
- The existing enrollment actor owns device generation, enrollment records and requests. Startup reads its protected records to restore the original pending comparison code or persisted Ready proof. Readiness here does not prove current Gateway authentication or tool effects.
- Pause and Quit retain the original Host, transport and executor settlement semantics. The C# bridge waits for the actual child and both output streams; forced termination cannot produce successful cleanup.
- Native packaging uses an explicit `nativeRuntime` input and fixed C08 payload. The historical Node packaging branch requires `legacyComparison: true`; omission cannot silently select Node management.

## Current limitations

The Windows UI slice enables Exec only. Computer Use, Browser, default local Gateway creation, account/tunnel administration, login startup, native installer/update and original-profile migration remain incomplete. Invitations without an explicit CA are rejected with `app_system_trust_not_supported`; system-root trust is not yet wired through native enrollment. The unsigned outer preview's manifest hash establishes consistency, not initial executable authenticity or Windows code signing. Original publisher pins and profiles remain authoritative.

## Verification boundary

Receipts are maintained outside source in `outputs/rust-rewrite-execution-20261024/r45-native-app`. Compiler, synthetic packaging checks, real Rust/Exec scenarios and native GUI/device acceptance are recorded separately. No test count is a product completion measure. No original publisher private key is used by this slice's implementation or tests.
