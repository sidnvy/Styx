# App runtime update boundary (R87)

Status: implementation in progress. This is not App, installer or device acceptance.
The last frozen candidate is 31e5476; its state3/foreground runtime-update
contract remains unchanged.

## Decision

App updates have a separate signed release reader `native_app_runtime_selected_v1`
and state4 reader `native_app_runtime_selected_state_v1`. R86 readers already
advertise foreground selection support but cannot read App-owned update history.
Reusing their identifier would falsely declare old packages rollback-compatible.
The original immutable root marker remains unchanged; only the closed new state
combination is admitted under its original native-management reader floor.

The pure Core grammar grants no ownership. Publication and recovery require the
actual retained `Arc<HostScope>`, original configuration writer, original C07
history, verified before/target C08 releases, original publisher and real execution
exclusion. The public foreground CLI cannot acquire App authority. This batch
covers completed fresh single-role App roots; migrated and persistent-service
updates require their own existing authority paths.

The App settles its original Host and Gateway tasks before recording stopped
state and selecting a staged release. Split roots have separate ordered C07
transactions. A fixed private immutable input may preserve the approved candidate,
role transaction IDs and original before-state bindings across process death.
That input contains no mutable progress ledger: each role's original C07 is the
only source of transaction outcome. Committed steps are inspected, never replayed;
unknown steps retain their original coordinator and scope. EOF joins the original
owned job. New work and Connect remain fenced until explicit original recovery.

Fixed `runtime-versions` and `runtime-updates` containers use existing native
private-root/file operations under the original container writer. Version payloads
and input files are exclusively published. Failed partial staging is not adopted
or overwritten. No caller-supplied executable, publisher, manager or arbitrary
path enters the App pipe.

## Delivery and verification

Rust owns configuration/runtime selection; existing Sparkle/Inno mechanisms own
App-directory replacement. Original App/signing/permission identity is retained.
The old App must settle before replacement. Legacy Node updater commands and
unconditional timer retries are not a fallback for missing native handoff.
Unsupported handoff remains an explicit blocker, not a synthetic success receipt.

Final acceptance must bind source, platform package, installed App, selected
workers and independent effects. It includes original-scope/writer refusal,
reader incompatibility, original transaction recovery, real normal reopen and
Exec after update/rollback, and complete owned-process settlement. Two versions
with identical code prove version-selection mechanics only; they do not prove
compatibility across different code revisions. Native signing, installation,
permissions and platform lifecycle remain separate gates.
