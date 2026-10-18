# Styx local-first enrollment and signed installation pilot

Status: IMPLEMENTED PILOT, not a production installer. This is a user-scoped,
outbound-first Host pairing process which does not require Coder or SSH
credentials for first-contact execution.

## Actual security and device onboarding contract

1. A private owner token, separate from the model MCP token, can create
   short-lived one-use invitations, inspect requests, approve an exact public
   key fingerprint, inspect devices and revoke an existing Host.
2. The new Host creates an RSA-3072 key pair LOCALLY and signs a public
   enrollment request (RSA-PSS/SHA-256). No device private key is transferred.
3. Owner sees the pending Host ID, OS, requested capabilities and the entire
   SHA-256 fingerprint of the device's SPKI public key. Owner must verify this
   fingerprint independently with the device before granting access.
4. Gateway generates a distinct per-Host connection capability and wraps
   it to the approved public key (RSA-OAEP/SHA-256). The Host decrypts it
   locally and confirms receipt by HMAC-SHA-256. Only after owner approval
   can it obtain and use the outbound credential.
5. Approved Host enters the Gateway Target Registry without restarting it.
   A new MCP client sees the new ID and its accepted Cua capabilities.
   Revocation immediately blocks new connections, disconnects both outbound
   lanes and prevents revoked IDs from returning after Gateway restart.
6. A one-command Host onboarding CLI can wait for owner approval. Native
   permission approval and startup service enrollment are always separate
   local decisions, NOT silent side effects of pairing.

The Gateway requires HTTPS for non-loopback requests; the Host enrollment
client requires HTTPS even during local testing. Enrollment is opt-in only.
The admin routes reject untrusted Origin, wrong bearer and duplicate auth
headers. Gateway state, private Host keys and capabilities are mode 0600
under private user-owned directories.

## Local developer workflow, independent of SSH/Coder

Use a separate trusted test Gateway instance, private TLS key and signed
release. Generate a separate model MCP bearer and OWNER bearer. A new
Gateway controller is enabled only if BOTH are configured:

    STYX_ENROLLMENT_DIR=/private/styx-enrollment
    STYX_ENROLL_ADMIN_TOKEN_FILE=/private/styx-owner.token

The existing Gateway still requires its model MCP token, catalog and TLS.
Enrollment endpoints are disabled by default when the variables are absent.
Example owner config: config/enroll-admin.example.json.
Example native device config: host/enroll.example.json.

The owner issues a short-lived invitation:

    node gateway/enroll-admin.mjs /private/admin.json invite

Transfer the returned invitation through a user-confirmed channel to a
protected local file on the new device. The device user launches once:

    node host/enroll.mjs onboard /private/local-config.json /private/invitation.txt

This prints its request ID and full fingerprint and waits for approval.
The owner checks and approves the EXACT same fingerprint:

    node gateway/enroll-admin.mjs /private/admin.json pending
    node gateway/enroll-admin.mjs /private/admin.json approve REQUEST_ID FULL_FINGERPRINT computer

The optional computer suffix explicitly grants Cua capability.
Once approved, the native Host writes its host.json and token without
printing any private value. It does not automatically grant OS permissions,
install a service or execute any remote command. Check readiness separately:

    node host/doctor.mjs /private/device-state/host.json

Device inspection/revocation:

    node gateway/enroll-admin.mjs /private/admin.json devices
    node gateway/enroll-admin.mjs /private/admin.json revoke DEVICE_ID

## Offline signed release staging

host/installer.mjs is a minimal stage/activate/rollback implementation.
A release bundle contains a manifest.json and Ed25519 manifest.sig. A
trusted publisher PUBLIC key verifies manifest bytes, OS/architecture,
payload paths, sizes and each file digest. Unknown extras, symlink paths,
path traversal, unsigned mutation and conflicting pre-existing versions are
rejected. Multiple versions remain side-by-side in one private install root.

    node host/installer.mjs stage /private/install /private/bundle /private/publisher.pub
    node host/installer.mjs activate /private/install VERSION /private/publisher.pub
    node host/installer.mjs rollback /private/install unused /private/publisher.pub

host/launch.mjs is a stable per-user entrypoint that verifies the selected
signed release before launching its Host Connector. Failure of a newly
activated release can roll back to the verified previous generation.
servicePlan() returns a non-mutating proposal for launchd-user,
systemd --user and Windows interactive scheduled task. It does not
enable or install these services.

This is NOT a full macOS signed/notarized app, native Windows MSI/MSIX,
Linux package, embedded Node runtime, platform keychain or automatic
upgrade service. Never distribute the publisher private signing key.

## Tests and remaining gates

HTTPS+cryptography unit/integration coverage verifies invitation expiry and
replay, wrong certificates, tampered signatures, explicit fingerprint
approval, refusal before approval, confidential claim, token confirmation,
device revocation, restart persistence and live Gateway tool discovery.

Native tests verify per-device identity, offline signed staging, activation,
rollback from a damaged generation and OS service plans with no system
changes. The GitHub OS matrix tests macOS/Linux/Windows independently.

The physical first-contact cold install, ChatGPT interactive device picker,
native permissions, keychain/PKI rotation, OS background service enrollment,
upgrade/uninstall and user rollback UI are future release gates. This pilot
does not assert otherwise. Read docs/onboarding-installation.md.


## Real two-machine pairing evidence (October 18, 2026)

The native Gateway was started on macOS with an empty Host catalog and a
private, short-lived HTTPS enrollment authority. The native Linux Host
created its RSA identity locally, applied with a one-use invitation and
waited for explicit owner approval. Its public fingerprint matched the
Gateway pending request exactly. The Gateway dynamically admitted it,
without restart, and the Host decrypted a new per-device bearer capability.

Both Codex Exec Server and Cua Driver connected over the private WSS
transport. A real scratch GUI test completed Exec -> Cua PNG/Accessibility ->
Cua click -> independent Exec exit code 0. The Host was then revoked,
connections dropped and attempts to reconnect were rejected even after
Gateway restart with its persisted state.

This was NOT an unattended cold install. Existing OOB controls transferred
the public Gateway CA and the one-use invitation and started the test Host.
The per-device capability and RSA private key were never prewritten by
Gateway or shipped to the Host. A signed installer, ChatGPT selection UI
and OS-managed service start remain separate production requirements.
