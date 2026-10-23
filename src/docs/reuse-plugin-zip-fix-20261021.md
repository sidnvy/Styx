# Existing-plugin ZIP export and actionable connection UI

Read-only inspection found that PilotMac was running dev12 with an existing
`reuse` plugin profile. The UI hid the complete export section for that mode,
and Core independently refused its export. The earlier create-profile native
screenshot did not cover the user's actual saved state. piermini still had dev10;
no service or configuration on piermini was changed.

Both restrictions are removed. Export uses the current profile and Tunnel,
preserves the existing selection/account/URL, and keeps all connection-binding,
authenticated local discovery and credential-exclusion checks. Host-only joined
devices still cannot export another Gateway's plugin. An optional icon is filled
only on explicit export if the existing profile lacks one. No new Gateway,
identity, credential or ChatGPT plugin is created by local ZIP generation.

The default route is now three actions: Connect to OpenAI, Save the plugin ZIP,
and Upload to ChatGPT. Export is prominent for both create and reuse profiles;
custom presentation fields are collapsed. The ChatGPT upload action appears
after a local file has actually been saved. Manual setup remains an alternative.
Generic runtime status labels and repeated transport/account caveats are removed
from this page. Connection state is projected separately: saved configuration
is never shown as a live connection, and missing observation remains unknown
with a check action. Account verification remains a later real tool-call step.

Evidence: Core/HTTP/native-client regressions passed 48 tests with one Darwin-only
test skipped on Linux. Actual isolated TLS Gateway discovery generated a ZIP in
reuse mode and preserved the selection and deployment. The native compiler,
protocol self-tests and test-only existing-profile ZIP window passed on PilotMac.
The native screenshot uses synthetic page data and is not a live user-screen or
ChatGPT upload acceptance claim.

To unblock the user, the updated Core also exported their current PilotMac
profile to `Desktop/Styx-ChatGPT-plugin-20261021.zip`, 89884 bytes, SHA-256
`51ba41e19d5de0a1d9ccede199e14e2421365d9f14c5092755f7e64365bab275`.
Actual deployment bytes and existing selection were unchanged. A private profile
backup was saved before writing the export receipt. ZIP integrity, expected four
files, authentication declaration and absence of actual runtime/Gateway
credentials in decompressed contents were verified locally without printing
secrets. Real ChatGPT upload, compatibility and tool-call acceptance remain
NOT RUN.
