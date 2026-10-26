# Host-only migration admission report v2

Source implementation integrated after a55f071. Initial device migration remains unexposed. The existing explicit Mac `recover --authorize` command now routes validated original migrations; no device recovery has been executed or accepted.

SPEC §7.2/C07 require original identity, one writer, authenticated original pair,
actual candidate effect and settlement of this migration's resources. A Host-only
installation neither owns remote Gateway SDK tasks nor holds model credentials.

Keep schema1/kind preserved_remote_host decoder/validator body unchanged. Add
schema2/kind preserved_remote_host_admission, retaining all original tx/candidate/
target/source/origin/device/fingerprint/CA bindings. Require host authentication,
protocol readiness and actual protocol/link/validation-task joins; commit and
ordinary admission remain false. Strict dispatch decodes the original bytes;
unknown fields, versions, mixed observations and duplicate fields are rejected.
Local Exec is still a separate required validation attachment; no duplicate Exec
or invented SDK facts are introduced. No new journal, phase or public protocol.

This does not prove MCP effects, second-owner isolation or remote SDK cleanup.
Those remain mandatory release scenarios in their actual owner scope. Release
aggregation must never upgrade v2 migration admission into those release PASSes.
JSON booleans are only recorded data; an owned actual producer remains necessary.

Affected readers: management_cutover_native::validate_remote_report; existing
validate_paired_report/scanner/record_cutover_paired_validation and phase hashes;
committed_runtime_native + committed_runtime_native_owner use that same parser;
fresh Mac and later Windows producers; release evidence aggregation. Old readers
reject v2; package rollback reader compatibility needs explicit review before
writing v2. Existing state reader floor alone does not negotiate this addition.

Tests append to existing management_cutover_tests private scratch journal fixture.
The remote binding/report is explicitly derived in memory, never activated: tests
prove codec/data links, not OS/network/migration authority. Cases cover original
v1 raw/strict fields, v2 missing-ready/Unknown/false cleanup, foreign bindings,
mixed SDK fields, duplicate schema and unknown versions. Existing writer still
refuses pair-report recording with no local validation. Full schema4 phase/hash/reopen integration tests remain necessary before device migration.
The Mac producer now borrows the original applied profile, authenticates the
original WSS pair with no execution provider, observes actual protocol readiness,
and joins the protocol, link tasks and scoped validation worker. No remote SDK
settlement is inferred from this local worker.

Validation: full Darwin workspace/all-targets typecheck passed using the real
Apple SDK. The explicit private-fixture report codec test passed, including
v1/v2 rejection controls. A separate actual Tokio task-panic test passed after
fixing HostWssLink shutdown to reject JoinError and join its sibling.
These are compilation and local tests, not native migration/network acceptance.
No current device migration, signing or installation was performed. Tests use
the explicit STYX_TEST_MANAGEMENT_CUTOVER_ROOT and --ignored exact fixture
harness; a default skipped run is not a PASS.

Compatibility gate: before writing v2 on a real installation, the selected
forward and rollback readers must both support it, or rollback must restore the
original legacy state through the existing authorized transaction. Merely
passing the state reader floor is insufficient. This compatibility gate and the
unfinished final commit/recovery paths keep the internal Mac entry unexposed.


Signed package compatibility: `NativeRuntimeMigratedV3` declares Host admission
v2 plus the durable migration-plan journal feature. It continues to read the
existing StateV2 shape. V1/V2 release declarations do not imply these journal
features. The Mac preflight and final commit must reject them before writing a
v2 report. Build-info, original build receipts, package manifests and native App
packagers must preserve the actual declared reader; no packaging flag upgrades
an older binary. Old readers reject the unknown manifest variant. Downgrade to
an old reader remains refused while new journal evidence exists; a rollback must
use the authorized restoration transaction, not reinterpret new bytes as old.

Validated interruption recovery: the internal Mac resume consumer reopens the
original Applied/Verified transaction only when both successful report attachments
are durable. It verifies the exact plan/candidate, current protected nonce bytes,
original guard/archive post stamps, retired token and execution lease, then
appends only missing Verified/Committed phases under the same writer. It never
constructs a new Exec/pair probe or claims to recover an old JoinHandle/nonce
inode. Ordinary profile readers remain Committed-only. The final release check
binds the original report bytes and phase prefix, current App scope and lease.

This is internal implementation, not device acceptance. Missing report/Unknown
attempt recovery, earlier token-rename interruption reconciliation and
non-Host-only migrations remain incomplete. The initial migration
entry stays disabled. The focused private-journal scenario covers final report/
prefix rejection; Darwin compilation cannot prove boot/TCC or native recovery.

The validated reader rechecks the full original preservation set, including the
publisher, legacy active selector, both configured CA paths and original release
manifest/signature. Release metadata paths are derived only after matching the
selector to its original preserved bytes and file observation, using the same
selector codec as the original profile loader. Only canonical state replacement
and token retirement are exempt from matching their old paths; both effects are
checked separately against the original transaction. Existing signed-profile
loading and trust-substitution fixtures pass after the codec extraction.
Fresh App-managed migration and validated recovery both require the actual
same-root App scope, retain it on failure and through the joined success handoff,
and validate it inside the final admission lock. Foreground CLI uses no App scope.

Existing command recovery routing: Mac `recover` acquires the same native
configuration binding and management journal once, then inspects the original
migration ID under that owner. Completed migrations reuse the existing complete-tip
reader before any maintenance fence. Applied/Verified recovery requires the
original complete material/report chain, derives the signed candidate from it,
and moves the original journal into the existing recovery task. The coordinator
is reconstructed from the same binding/journal only after its actual worker join.
Pure configuration recovery keeps its existing authority and complete-tip policy.
The CLI supplies no AppScope and therefore cannot recover App-managed state by
submitting a manager string. Missing markers/reports and earlier unsupported
stages remain rejected; no new transaction, probe or fresh migration is attempted.

A bounded management permit stays with the actual worker during Unknown and
through final success reporting, including cancellation of an observation waiter.
Only a typed error from an actually observed retained Mac recovery job causes the
one-shot CLI to flush Unknown/no-replay/cleanup-unconfirmed output and explicitly
terminate its own process. This avoids hanging in Tokio runtime destruction;
it does not report cancellation, join or cleanup. Original journal/guards remain.
Library/App code never exits the process. Fresh migration and native App recovery
entry integration, original-token partial rename recovery, missing-report
reconciliation and device interruption/exit verification remain pending.
