# Host-only migration admission report v2

Source implementation integrated after a55f071. No device migration or public entry point is enabled.

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
