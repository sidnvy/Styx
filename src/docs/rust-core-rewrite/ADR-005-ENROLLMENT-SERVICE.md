# ADR-005 · Signed enrollment service composition

Status: implemented development slice; exact verification receipts are external. R12, the production Gateway and native release remain incomplete.

`styx-runtime/enrollment/service.rs` owns one recovered Core and an `OwnedEnrollmentJournal`. The latter moves the existing root and non-clonable configuration-writer guard into a static service, retaining the initial descriptor namespace identity. It borrows the existing journal primitives for each operation; no self-reference, second writer or duplicate filesystem implementation is introduced.

The trusted constructor requires an existing native namespace and clock floor. It does not initialize an old profile as empty. Core history is recovered before activation, and every referenced typed Profile, SPKI/fingerprint, credential encoding/hash and active sealed-ciphertext width is checked. A public key cannot prove what a ciphertext decrypts to: initial OAEP wrapping is bound to the exact Core credential target, and recovery verifies the immutable original references. No original device key is generated or replaced by service recovery.

## Authorities and publication

- A dedicated admin bearer is checked with the existing constant-time policy and must differ from the ordinary MCP digest. Ordinary MCP owners have no enrollment admin factory. Public join/claim/confirm reject unexpected Authorization; self routes require exactly one device bearer and return 403 on failed device authentication.
- `profile.rs` verifies the exact existing ordered join and v1/v2 capability preimages using AWS-LC RSA-PSS and SPKI. StoredProfile contains bounded public device metadata and the original legal public PEM, never invitation, claim secret or device token. Serde decodes strict typed DTOs; original journal intent bytes are not normalized.
- Existing Unicode Letter/Number labels and cross-platform absolute path/shell rules use pinned upstream regex, not the Gateway OS's path parser or a custom Unicode table. Canonical base64url signatures, no embedded NUL paths and strict final-string matching reject malformed inputs outside normal Host-generated payloads.
- Core stages and fences before material writes, original prepare and committed durability. Runtime publishes only after the actual commit receipt. I/O uncertainty or observed invalid protected material is sticky: new authentication/Host admission/frame authorization requires recovery. A failed response does not roll back or replay a transaction.
- Claim retries return the same sealed credential. A dedicated Core confirmation-target query works even after claimed=true and sealed=None. The same original token verifies HMAC on retry; already-confirmed success creates no new transaction. Confirmation/revocation remove logical authority, not historical journal files needed for replay.
- Expired bounded pending metadata is collected through Core's explicit durable mutation before a new join. Runtime does not silently clear maps to escape capacity. Live devices and revocation tombstones are never evicted for admission.
- Legacy approve carries a fingerprint but no comparison field. The authenticated admin path binds to the authoritative pending comparison code and exposes it for both-end comparison; this is not a wire proof that a human actually compared it. Do not silently change old clients' body schema or claim a new consent protocol.

## HTTP lifetime

`enrollment/http.rs` composes the existing strict GatewayServerTls with official Hyper HTTP/1. TLS's fixed actual leaf and validated Host create the pairing context; request JSON cannot supply them. Only origin-form, exact routes and allowed Hosts are accepted; Origin and query are rejected. Preflight rejects invalid credentials before body collection, and the final service turn rechecks authority after the bounded full body.

This listener has explicit local bounds: 16 connections, 8 requests/blocking work items, 16KiB request body, 1MiB serialized response, handshake/header/body deadlines and bounded shutdown observation. These are not a shared Host allocator or an RSS proof. Existing Host/Gateway process-budget composition is still required.

Blocking work owns its request permit and service until actual completion. A dropped HTTP waiter cannot cancel persistence or release that work quota early. Registered blocking handles are retained and reconciled, not assumed stopped on timeout. Public wait-for-blocking can report joined only after accept has stopped and all connection tasks ended; an active listener cannot issue a quiescence claim from an instantaneously empty job list.

## Required continuation

The new strict TLS journey uses independent Node-generated RSA/PSS/OAEP/HMAC and comparison-code observations, actual Core/store and close/reopen with the original credential. Core transport-lease hooks test authorization invalidation; they are explicitly **not** an actual Host WSS link or an Exec effect. The latter, Gateway registry/owner routing, legacy mixed-runtime interoperability, default-device mutation, separate LAN ingress management, signed candidates, original-profile migration, native platform lifecycle and actual account acceptance remain required. `set-default` and ingress-management endpoints are not silently implemented by this slice.

Recovered lanes remain RecoveredUnknown until actual original transport-owner quiescence is proven. Restart/self authentication and original confirmation can work without inventing Offline; browser CAS requiring all lanes Offline correctly refuses that uncertainty. Native Host execution liveness and permission/session state remain independent.
