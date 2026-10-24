# ADR-016 · Darwin private reads and original lease ownership

2026-10-24. R06 platform implementation subset. Native execution, writable journals,
App management, installed identities and final platform acceptance remain separate.

Reuse the existing PrivateRoot/RawFile/guard API and mature nix owned openat
handles, nofollow path walks, standard Rust nonblocking file locks, getrandom and
libc SDK types. Do not build another storage or configuration authority.

Darwin root identity is device/inode/current UID. Process identity is kernel boot
session UUID plus PID, microsecond start time and UID, sampled consistently through
libproc. PID-only, ps output and environment hints never establish ownership.
Only real proc_pidinfo ESRCH or observed different boot/birth establishes absence;
permission, unexpected lengths and changed UID remain errors. Mac identities are
never relabeled Linux and do not unlock the Linux-only native writable root.

POSIX mode bits are insufficient for Darwin ACL privacy. Query the original held
fd using the official opaque ACL API. Accept only an absent extended ACL property
or a valid allocated ACL with no first entry; conservatively reject every actual
entry, including deny-only entries. Do not parse ACL structures or modify an
existing ACL. NULL plus fresh ENOENT on a valid held descriptor denotes an absent
ACL property in Apple's fd implementation; other errors, including unsupported
filesystems, remain failures. Darwin acl_get_entry returns zero for an entry,
which differs from Linux conventions.

The workspace still denies unsafe generally. One small platform FFI module is
explicitly scoped and documented: opaque ACL allocation/free, libc-provided
proc_bsdinfo, and a fixed-size read-only sysctl buffer. Existing pinned dependencies
lack descriptor-bound safe Darwin ACL wrappers; exacl's public path API would
weaken this boundary, and libproc's wrapper adds a bindgen build chain. No new
crate, custom C struct, shell parser or ACL interpreter is introduced.

Private reads preserve original raw bytes and check bounded size, ownership,
permissions/ACL, nlink, original inode/timestamps and rewalked path bindings.
Existing-only writer acquisition does not repair missing locks; explicit creating
acquisition remains a separate action. Locks retain one original file description
and never unlink/recreate their namespace on release. They coordinate cooperating
Rust owners, not original JS/App services or hostile same-UID replacement.

Verification is one opted-in real Mac filesystem/process batch with synthetic
private data: exact raw reads, ACL/alias/replacement negatives, two independent
lock namespaces competing across real child processes, exact birth and actual
wait/reacquisition. Compile, actual native batch and platform installation are
reported separately. Tests may change only their freshly created synthetic ACL.

Primary API/source references: [Apple acl_get_entry](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/acl_get_entry.3.html),
[fd ACL query](https://github.com/apple-oss-distributions/Libc/blob/main/posix1e/acl_file.c),
[stat ACL absence](https://github.com/apple-oss-distributions/Libc/blob/main/sys/statx_np.c),
[filesec property absence](https://github.com/apple-oss-distributions/Libc/blob/main/gen/filesec.c).
Installed SDK/man inspection and the actual target run determine native acceptance;
latest public source alone is not evidence of installed behavior.
