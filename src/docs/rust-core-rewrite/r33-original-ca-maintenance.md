# R33 — original CA maintenance boundary

This records current source, not completed acceptance. Real paired network validation has not passed; the driver/integration remains in progress. See ADR-029 appended to [DECISIONS](DECISIONS.md). Historical ADR files and results are unchanged.

## What current code does

* `tls/issuer.rs::issue_server_leaf` validates the original issuer/key/anchor and creates a distinct server-auth leaf with explicit `CA:false`. The leaf is not a replacement trust anchor. Its not-after is `min(now + 24 hours, original_CA_not_after)`; not-before permits up to 60 seconds clock skew, bounded by the original CA start. Insufficient original CA validity refuses issuance.
* `migration/legacy_endpoint.rs::issue_original_endpoint` reads the protected original `gateway/certificate.pem` and `gateway/private-key.pem`, checks their observations again after issuance, and revalidates the original maintenance profile. Original CA/key files are not rewritten. The current adapter requires create-local, the original IPv4 loopback origin/listen address and an explicit unprivileged port. Unsupported ingress/multiple anchors or an explicitly pinned original leaf refuse; there is no downgrade, new CA, automatic re-pair or publisher change.
* The issued chain keeps the original CA PEM bytes. The public binding contains schema, original transaction, root identity, candidate manifest hash, exact origin, anchor/leaf/chain hashes and validity. It contains no private-key bytes or key hash. These fields are data links, not standalone proof.
* `store/management_cutover.rs` schema2 intent hashes the binding/chain/private key in the same original namespace, using fixed `txn-ID.cutover-endpoint-{binding,chain,key}` names. Preparation checks complete attachments, exact root/transaction/candidate and chain hash, target Gateway presence and exact raw `gateway_endpoint_v1` JSON. File/byte totals and temporary canonical-apply peaks are checked before the first immutable write. Keys use private storage and zeroizing retained/prepare buffers; no private-key body is a report or debug field.
* Endpoint=None keeps schema1 intent fields/serialization and original reader behavior. The endpoint extension is forbidden under schema1. Schema2 requires all three materials; incomplete, unknown or changed attachments refuse. Its old local-Exec report does not authorize Verified/Committed: those stages are explicitly blocked until a genuine paired-verdict path is implemented.

## Required lifetime and ordering

`PreparedLegacyCutover::prepare_gateway_validation` must build the owned plan **before** `apply_candidate` replaces the legacy canonical state. The original maintenance profile loader needs the original state and observations; trying to reconstruct it after conversion is not a recovery mechanism. A failed plan is not permission to apply and improvise a replacement profile.

The plan retains the same original owner/transaction, exact Prepared cutover, original profile, Gateway execution lease, existing historical journal and original dual-scope proof. `GatewayMaintenanceBinding` checks exact owner identity/authority and the original historical baseline before/after access. It neither acquires a new configuration writer nor publishes a new ordinary registry. Original source files, publisher and paired identity/credentials remain preservation inputs; the authorized canonical state replacement is the only such exception.

Native release reader declarations are independently versioned. The old 1201 signed artifact is not upgraded in place. A new verified candidate must explicitly support `NativeMigratedStateV1`; package-signature verification or a local candidate worker probe alone is not ordinary migrated startup acceptance. Older readers refuse an unknown barrier instead of falling back.

## Not completed by this source slice

No PASS is claimed for real paired maintenance TLS/WSS/MCP traffic, final Gateway validation, migration Verified/Committed, ordinary admission, activation, automatic certificate renewal, long-lived runtime certificate storage/rotation, platform trust-store changes or existing user login/OS permission continuity. The 24-hour leaf cannot be presented as a complete ordinary certificate lifecycle. A later final commit must rely on the actual paired outcome and original single-writer chain, never a caller boolean, mere attachment presence, local Exec ACK or a successful package verifier.
