# Windows signed payload staging

Windows `stageSignedRelease` now stages public, publisher-signed release bytes
with bounded native ACL operations. The previous implementation assigned and
checked ACLs repeatedly for each file and ancestor. A real 2,200-file Host
preparation made insufficient progress for interactive onboarding.

The optimization is confined to new release staging directories. Credential
creation still uses the original single-file `openPrivateFile` path. Existing
private paths are checked and never repaired by the new batch helpers. POSIX
release staging follows the existing path.

## Security and publication sequence

1. Verify the source release signature, manifest, complete file list and hashes.
2. Establish private install/release/temp roots. The optional directory
   `bigint:true` mode captures exact device/inode identities, verifies actual
   owner/DACL and rejects before/after identity changes. Creation binds native
   parent/directory handles while applying owner and inheritable private ACLs.
3. Create only fresh payload directories, one depth level at a time. Native
   groups of at most 32 retain parent/directory identity checks while assigning
   owner and ACLs. Read back the actual owner, protected DACL and inheritable
   FullControl rules for the current SID, SYSTEM and Administrators.
4. Open at most 32 new empty payload files with `wx`. Keep every Node descriptor
   open while native parent/file handles verify exact identities, assign private
   ownership/DACL and read back the actual descriptor before the first payload
   byte. Copy through these descriptors and flush them.
5. Check every ancestor identity before copying, then check every created file
   and directory identity and actual owner/DACL in bounded groups. Reject actual
   tree entries absent from the creation inventory, including empty directories.
6. Reverify the complete signed release, repeat identity/tree checks and publish
   only by renaming the private temporary directory to the generation name.

Authorization is local to one synchronous staging call. A failed stage deletes
its temporary tree only when its root, parents and every present child still
match the objects created by that call. Unknown or replaced objects cause the
tree to remain for inspection; they never authorize recursive deletion.

## Native NAB evidence — 2026-10-21

Evidence lives in task outputs `windows-stage-fast-20261021`.

| Run | Source | Actual result |
| --- | --- | --- |
| 1 | `f2b12bb` | 8 tests: 4 passed, 4 failed. A real directory inode exceeded Number's safe integer precision. Staging refused publication. |
| 2 | `1a41899` | Exact BigInt identities fixed that refusal. The remaining per-directory native operation was still slow: stopped at 370.36 seconds, 1,792 payload files, 472 directories, no published generation. The owned process tree and fixture were cleaned. |
| 3 | `ed0885a` + `7b922a6` | Full 2,200-file signed Host staged in 100,977 ms with 195 PowerShell invocations. All 2,689 installed paths had real owner/DACL checks; manifest hash matched. Tests: 10 passed, one attack-fixture injection failed because Windows returned EPERM before moving the parent. |
| 4 | `665ceb8` (production through `039cb78`) | Final full 2,200-file stage: **101,238 ms**, 195 PowerShell invocations, all 2,689 installed paths had actual owner/DACL verification and matching signed manifest. **12 tests passed, zero failed or skipped**, total 191,772.6 ms. Includes unknown-empty-directory refusal. |

The run 3 timing does not include the later `039cb78` whole-tree unknown-entry
checks; run 4 uses that final production implementation. The signed payload
manifest used by both runs is
`b7a43c76e7f9e3ee32e235398a00615a2d2f524e4e5cc237944c70ab63224fe7`.

When Windows refuses moving a parent with live child file handles (`EPERM` or
`EBUSY`), the native fixture verifies unchanged exact parent/file identities,
empty files, no foreign tree and no publication. It records `OS_PROTECTED` and
marks the rebound-parent cleanup branch **NOT EXERCISED**. If the OS permits the
move, the fixture instead requires the original inode's foreign-parent hardlink
and sentinel to survive refusal. These are distinct observations.

Run 4 actually took the `OS_PROTECTED` branch with `EPERM`; the rebound-parent
cleanup branch was not reached. The other real failure fixtures covered changed
payload bytes, a broad DACL, a replaced file, a redirected directory, unknown
file/empty-directory entries and actual installer process termination, with no
partial generation published. The independent final census found zero owned
Node processes or temporary fixtures. Public test bundle/source/evidence remain;
private fixture signing keys existed only in terminated Node process memory.

This acceptance covers installation mechanics, permissions and failure behavior
for an isolated test-publisher bundle. It does not establish official publisher
trust, full Windows App onboarding, upgrade permission retention, real reboot,
or ChatGPT account acceptance.
