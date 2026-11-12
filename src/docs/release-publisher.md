# Fixed release publisher

The owner authorized a new fixed Workstation publisher on 2026-11-01, replacing the unavailable PilotMac signing identity for fresh installs. Linux, macOS and Windows
native runtime releases now use the Ed25519 public key in
`src/release-publisher.pub`, recorded by `src/release-publisher.json`.

SPKI SHA256: `bbb49c2626c3d4ef3cf9e1679db5305b100cee4a8c41c29c958ede82fb868bed`. This pin is part of the reviewed source and
compiled App/installer trust anchors. A public key supplied inside a downloaded
package does not establish trust. Old publisher packages are not accepted under
this pin; first install and re-pairing are explicit owner-authorized actions.

The original private key stays on Workstation in its owner-private Styx publisher directory. On 2026-11-13 the owner explicitly authorized an encrypted copy in the `sidnvy/Styx` GitHub Actions `release` environment as `STYX_PUBLISHER_PRIVATE_KEY_PEM`, restricted to `develop` and `v*` tags. The old PilotMac key and old publisher material are preserved, never copied or overwritten.
Prepare an exact immutable manifest, independently review its digest, sign on
Workstation, then verify the raw 64-byte signature with the pinned public key before
packaging or deployment. Never copy private key bytes into a release artifact, client, repository source, Gateway or chat. The authorized CI signing step materializes its encrypted Secret only in a temporary owner-private file and deletes it afterwards. Reuse this publisher for later releases; rotation
requires another explicit owner decision. An offline private-key backup is a
separate owner action and is not established by creating the key.

This signature authenticates the Styx payload. macOS code signing/notarization
and Windows Authenticode remain separate platform mechanisms. Existing local
macOS certificate identity is retained; distribution certification is not claimed.
Gateway TLS/enrollment identity is also separate and must be backed up with its
private state after creation. This change does not migrate existing profiles.

The macOS release signing identity was separately renewed with owner authorization on 2026-11-13 because the previous local key was non-exportable. The new exportable local certificate is SHA1 `9a4c8c7e15d006f9d0a576b137c7696f143f46d8`, DER SHA256 `f5a143072e85e8e393f199811937ceff4c884d2b74cf2509e08e9e53a4d0c1a9`. Its original private material remains in PilotMac ReleaseSigning-20261113 and encrypted P12/password copies are in the release environment Secrets. The old identity and installed App remain unchanged. This is still a local certificate, not Apple Developer ID/notarization; the Ed25519 publisher pin is unchanged. Exact retained third-party worker signatures remain pinned separately during packaging.
