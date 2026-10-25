# ADR-032: Windows native Host persistence under the original owner

Status: implementation slice; platform acceptance remains pending.

## Decision

Reuse the existing configuration owner, enrollment protocol, bounded journal
records and native Host join phases on Windows. Keep one root/writer, the same
Core rules and the existing `win32` wire platform name. Windows root observations
use the already defined volume/file-ID/owner-SID contract. This adds no service,
policy authority, database, remote tool or new signing identity.

The writable backend currently requires a local fixed NTFS volume. Fresh
private directories reject existing names. Fixed genesis/phase files use
CREATE_NEW and never repair or overwrite partial files. Journal publication
retains the original writable source HANDLE through no-replace handle rename,
file flush and identity verification; clock replacement uses the same handle
path with a cooperative expected-value check under the original writer. That
check is not a kernel compare-and-swap. Unknown temporary/final files remain
observable, and ambiguous results do not authorize network request replay.

Directory barriers reopen the original protected directory with read/write
access under retained ancestor pins, validate the original volume/file-ID and
private ACL, invoke FlushFileBuffers, then revalidate. Fresh child creation
flushes child and parent. File/namespace publication also flushes the actual
directory before successful readback. No volume flush, administrator fallback,
ACL repair or fabricated directory-sync event is used. An access/flush failure
remains an error under the retained owner.

The C07 parser is shared as pure byte validation. Linux handoff/cutover parsing
keeps its existing behavior. Unsupported migration records on Windows remain
orphans and cannot certify a clean canonical tip. Native Gateway bootstrap,
historical migration, canonical C07 apply/recovery and the ordinary fresh Host
reader are separate capabilities; this slice does not enable them by inference.

## Evidence and limits

Microsoft documents file/metadata flushing and the handle-bound rename ABI:

- https://learn.microsoft.com/en-us/windows/win32/fileio/file-caching
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers
- https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info

The isolated NAB5 probe in execution evidence
`r39-windows-native/dir-flush-probe-1/receipt.json` observed read-only parent/child
directory flushes fail with Win32 code5, while read/write directory flushes
succeeded with code0 and unchanged original object IDs. All four handles closed
and the owned SSH process actually exited0. This is API availability evidence,
not a power-loss experiment or C07 acceptance. Storage honoring flush requests
remains an OS/device assumption, as for the Linux backend.

New backend source, shared parser and consumer wiring still require the frozen
candidate local quality gate and actual Windows owned-FS/fault/reopen aggregate.
Fresh request/approval/claim/self, ordinary execution, configuration recovery,
installation/login/reboot and cross-platform acceptance remain distinct gates.
Do not substitute the probe, compilation or static review for those journeys.

## Actual rename compatibility correction

The subsequent owned NAB5 probe `r39-windows-native/rename-api-probe-1`
observed Win32 error87 for both read-only and read/write RootDirectory handles
with a relative target. A NULL RootDirectory and an absolute target derived
from the retained original directory handle succeeded, preserved the source
file ID and content hash, and was flushed through the same source handle.
Use that supported Win32 form, matching the standard-library implementation's
NULL RootDirectory approach. The original source is never reopened by path;
the validated single-component destination stays under the original Root's
retained ancestor/name pins. Do not retry a failed business publication using
a second rename strategy; the three probe cases used independent fresh files.
The corrected owned-FS aggregate passed on NAB5 for d35896b, including
monotonic replacement, exact same-value resync, protected-reader refusal and
orphan retention. This is not C07, ordinary Host, or power-loss acceptance.


## R40: reuse the original C07 and ordinary Fresh reader

The Windows backend now supplies the same OwnedManagementJournal and
NativeTransactions coordinator as Linux. There is no second journal format,
configuration authority, recovery flag, or implicit Host activation. A successful
join still creates Stopped revision0. Starting an ordinary Fresh Host requires
an actual committed C07 desired-state transition to Running; the reader keeps
its Ready/root/seed/CA/credential and complete current-tip checks. Wire platform
identity remains `win32`, with original volume/fileID/current-SID matching.

Canonical replacement stages the existing exact target in the protected
management namespace. Windows reopens that already observed source with
OPEN_EXISTING and denies write sharing; original fileID, exact bytes and final
source path are checked before using its actual rename HANDLE. It retains the
same root/writer/maintenance and namespace pins, rechecks the original canonical
bytes/observation immediately before replacement, flushes that same file and
both affected directories, closes writable access and verifies the target's
original source ID and bytes. This is cooperating-writer conditional replacement,
not an atomic compare-and-swap against malicious same-user writers. The earlier
R39 immutable publication retains its source from CREATE_NEW without reopening.

Recovery re-syncs only the original exact transaction materials and phase chain
under the same writer. Windows still has no legacy migration reader: unknown
files stay retained orphans and prevent commit/recovery proof. No new or old
input action is replayed by configuration recovery. Browser/Computer readiness
remains independent; this slice wires ordinary Windows headless Exec and does
not claim new native desktop factories or OS permissions.

The new Windows C07 aggregate must verify fresh commit, exact close/reopen,
foreign/stale intent refusal and explicit original recovery after an actual
child process exits at the canonical rename boundary. Process interruption is
not physical power loss. Compilation, this store aggregate, and the later
request/approval/claim/self plus ordinary Host/Exec journey are separate gates.
