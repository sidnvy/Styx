# Owner-controlled credential recovery

The supported rotation procedure retires the old device identity and enrolls a
new one. It intentionally interrupts service. There is no in-place token
rollover, automatic identity regeneration or overlap of valid old/new bearer
credentials for one device ID. This also handles a lost or compromised Host
key: replacement approval does not trust possession of that old key.

The Gateway owner's private admin credential is required. The model MCP bearer,
Host bearer and pending claim secret have no recovery authority. The recovery
route is separate from MCP tools and is not available in the CAS-only surface.
Use an independent trusted owner channel to inspect and approve fingerprints.

## Reproducible recovery

1. On the owner machine, inspect the exact record with
   `node gateway/enroll-admin.mjs /private/admin.json devices`. Record its
   `device_id`, `fingerprint` and `generation`; verify the intended Gateway
   origin/CA in the private owner configuration.
2. Retire that exact record using
   `node gateway/enroll-admin.mjs /private/admin.json recover DEVICE_ID FINGERPRINT GENERATION`.
   A wrong fingerprint, stale generation or unknown/already-retired ID fails.
   A successful result contains only the retired ID, `status: revoked` and
   `recovery: fresh_enrollment_required`. It contains no new invitation or token.
3. Stop the old Host service using its platform service instructions. Preserve
   its old private storage for owner investigation if needed. Do not edit,
   overwrite or reuse its identity files. The Gateway rejects its old bearer,
   closes both live reverse lanes, deletes its Gateway token, and retains a
   durable revocation tombstone. Existing native processes may already have
   produced effects; recovery never replays commands or migrates handles.
4. Prepare a private install configuration with a **new, empty `storage_dir`**.
   Follow the existing enrollment/installation procedure: create a fresh
   owner invitation, securely transfer it to this Host, run
   `node host/enroll.mjs join /private/replacement.json /private/invitation.txt`,
   independently compare the new fingerprint, explicitly approve it with
   `approve REQUEST_ID NEW_FINGERPRINT [computer]`, then claim and install/start
   its service using the generated Host configuration. The normal signed join,
   RSA-OAEP encrypted claim and confirmation protocol deliver its new bearer.
5. Verify the replacement's new ID appears in allowed discovery. Query passive
   status explicitly and perform separately authorized native acceptance. The
   retired ID must remain unavailable, including after a Gateway restart.

A consumed invitation cannot be reused. A fresh invitation cannot resurrect a
retired device ID; a new device-generated key and ID are necessary. No owner
approval is transferred to a replacement automatically. Do not paste private
configuration, invitations, identity keys, claim secrets or tokens into chats.

## Durability and limits

Recovery first saves the revocation tombstone and removes pending claim
material, then denies live admission and disconnects both lanes in the same
synchronous control-plane operation. A failed save produces no successful
acknowledgment and restores the prior in-memory state. Restart loads approved
identities only, so a committed tombstone denies the old identity even if a
crash prevents deleting its obsolete token file. Later native bindings check
current admission; a lost binding never resumes/replays an old command.

This remains the documented single-process enrollment controller with local
private state and atomic file replacement. It does not establish cluster
coordination, remote key erasure, hardware attestation, publisher signing,
power-loss filesystem durability, physical-device replacement acceptance or
ChatGPT account authorization. Actual ChatGPT acceptance requires the account
owner's connector authorization; local fixture TLS tests are separate evidence.
