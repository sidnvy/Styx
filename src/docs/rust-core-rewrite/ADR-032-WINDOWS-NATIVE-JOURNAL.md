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
