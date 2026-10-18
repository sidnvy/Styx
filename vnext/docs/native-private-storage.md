# Native private enrollment and install storage

Styx verifies actual native private storage before writing device identity keys,
pending claims, Gateway enrollment state or installed bootstrap state. POSIX
requires current UID ownership, a regular directory/file, and no group/other
permissions. Windows validates the actual DACL and owner SID; POSIX mode bits
are not evidence of NTFS privacy. Allowed Windows principals are the current
user, Local System and built-in Administrators only.

New leaf directories are created under an explicitly selected existing parent.
On Windows their inherited ACL is replaced with inheritable full-control grants
for those three principals, then independently checked before writing secrets.
Existing directories and files are checked without silently changing permissions.
Broad permissions, foreign ownership and symbolic links/junctions fail closed.
Missing ancestor directories are not recursively created. Operators must choose
an existing parent and a new leaf, or provision private existing storage through
an independent OS administration channel.

The native check has one implementation in `host/private-storage.mjs`, reexported
by `shared/private-file.mjs`. The standalone installed installer keeps this helper
beside itself. Signed bootstrap refresh requires the signed helper whenever its
signed installer imports it; signed old installers with no such dependency remain
supported. Health-gated activation checks the helper hash when the signed
candidate/previous manifest includes it, both before and after health evaluation.
An existing broad installation is rejected, not automatically repaired. This
change performs no service mutations and grants no model administration rights.

Windows CI uses fresh test directories under its own Temp only. It exercises
broad inherited ACLs, new restricted creation, existing broad state refusal before
key/database writes, broadened identity-file rejection and junction denial. These
checks establish native permission enforcement, not protection from a hostile
administrator, full filesystem race resistance, physical desktop permission
approval, actual ChatGPT connector authorization or production enrollment.
