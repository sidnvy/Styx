# Fixed release publisher

The owner authorized a fresh publisher on 2026-10-31. Linux, macOS and Windows
native runtime releases now use the Ed25519 public key in
`src/release-publisher.pem`, recorded by `src/release-publisher.json`.

SPKI SHA256: `cb06529011b4c35ffc79f76440beeb88c6e3615e60d993d1485b5be45b307819`. This pin is part of the reviewed source and
compiled App/installer trust anchors. A public key supplied inside a downloaded
package does not establish trust. Old publisher packages are not accepted under
this pin; first install and re-pairing are explicit owner-authorized actions.

The private key stays on PilotMac in its private StyxPublisher directory.
Prepare an exact immutable manifest, independently review its digest, sign on
PilotMac, then verify the raw 64-byte signature with the pinned public key before
packaging or deployment. Never copy private key bytes into a build, client,
repository, Gateway or chat. Reuse this publisher for later releases; rotation
requires another explicit owner decision. An offline private-key backup is a
separate owner action and is not established by creating the key.

This signature authenticates the Styx payload. macOS code signing/notarization
and Windows Authenticode remain separate platform mechanisms. Existing local
macOS certificate identity is retained; distribution certification is not claimed.
Gateway TLS/enrollment identity is also separate and must be backed up with its
private state after creation. This change does not migrate existing profiles.
