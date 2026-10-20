# App upgrade registration and visible plugin ZIP export

The App now offers Review this upgrade and Keep settings and finish upgrade
when an old ad-hoc registration blocks a local-certificate build. The private
HTTP session asks the existing Core for a plan bound to the verified owning App;
clients supply only the returned plan ID and explicit authorization. They cannot
supply an App path, certificate or arbitrary transaction plan. Apply re-verifies
the actual bundle and configuration before writing. Existing Core snapshots,
locks, execution journals and exact-byte rollback remain authoritative.

After successful registration, the existing Core attempts to resume connections.
It still refuses unverified services or a connection owned by another process.
The App shows a bounded reason and offers a connection retry; it does not stop,
replace or take over legacy services. Registration success is distinct from
connection success, tool health, system permissions and account acceptance.
After upgrade or an explicit connection retry, the App reevaluates the next
onboarding page. Legacy optional Host-service installation records do not block
the App-owned local setup; actual service ownership checks are still enforced
by Core before a connection is started or reused.

Interrupted registration status is readable through Core and CLI
`mac-signing-status` without loading or replaying an incomplete deployment.
The authenticated native status route allows the App to show the recovery notice
even if its ordinary snapshot cannot load. An interrupted transaction requires
inspection and explicit rollback using the existing recovery interface; the App
does not blindly retry it. This change does not implement a general service
migration wizard or replace legacy installed services.

ChatGPT setup now has a visible segmented choice between manual connection and
ZIP import. Secure-channel prerequisites disable export with an explanation
rather than hiding the entire connection panel. The generated ZIP button is
prominent, the save dialog defaults to Desktop, and success shows the full path
and Show in Finder. The ZIP is generated for the current connection; it is not
the App installer and is not automatically shipped alongside the DMG. Existing
reuse profiles retain their existing-plugin path. ZIP import into a real target
ChatGPT account remains unverified.

Validation: 79 Core/HTTP/plugin tests passed; the final status/transaction subset
passed 49 tests. Real Mac signature and private HTTP tests passed normal upgrade,
service conflict, interrupted apply, malformed scope, missing confirmation,
CSRF rejection and replay rejection. Core service calls in that HTTP test are
injected, so it is not a real service migration acceptance claim. Native Swift
compilation with warnings as errors and both native self-tests passed.

A separate native testing App rendered the ZIP view and its visible generation
button with synthetic page data, including the explanation for a missing Tunnel.
This screenshot is UI-only evidence, not the user's current screen, a file-dialog
interaction, a successful ZIP export or an account installation. The initial
fixture bootstrap used the wrong Node path; the successful run used the packaged
runtime required by the launcher. Evidence is in task outputs
`preparation-recovery-20261021/`.

piermini was inspected read-only. Its desktop connector was disconnected, so no
live screen observation was claimed. No production configuration, service,
permission, credential or installed App on piermini was modified.
