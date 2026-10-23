# Fresh native Styx onboarding

This is the native CLI onboarding path for an independent Styx candidate. It
does not need Charon, Coder, a previous conversation, or a pre-enrolled device.
It is not a graphical installer or evidence that the actual account-side
connection has passed. Use the new Styx plugin and its own HTTPS Gateway.

Before starting, obtain the exact candidate source/release, native signed Host
bundle, and trusted publisher public key with its independently confirmed
SHA-256 SPKI DER fingerprint. Do not trust a fingerprint merely because it is
beside a downloaded bundle. Bootstrap with a trusted local Node 22+; after
preparation use the verified bundled Node reported by the command. Public
artifact URLs/hashes belong in the concrete release handoff, not invented
examples. Do not use prior pilot state or derive credentials from old services.

## Prepare the native device

Create a fresh private parent directory using the native owner-only permissions
helper. Do not weaken or silently repair an existing directory. Save an
owner-private JSON configuration containing these fields (paths are absolute):

| Field | Meaning |
| --- | --- |
| `bundle` | Verified publisher's extracted native Host bundle |
| `publisherKeyFile` | Publisher Ed25519 public PEM file |
| `publisherSha256` | Independently trusted SHA-256 of its SPKI DER bytes |
| `baseDir` | Fresh, nonexistent install/state directory under a private parent |
| `gatewayUrl` | Exact new HTTPS Gateway origin; no credentials/query/path |
| `label` | Human-readable device label |
| `computer` | Explicit boolean granting requested GUI capability |
| `gatewayCaFile` | Optional dedicated CA certificate, never a TLS bypass |
| `macTeamID` | Required for macOS GUI; verify the already installed signed app |
| `wayland` | Explicit Linux Wayland opt-in, only when needed |

Run from the trusted candidate source:

```sh
node src/host/setup-native.mjs prepare /absolute/private/setup.json
```

The command verifies the publisher fingerprint, signature, every release file,
native platform and complete bootstrap before creating state. It stages and
activates the signed runtime, creates `enrollment.json` and `service.json`, and
returns a receipt with the bundled `node` and `release_root`. It does not pair,
request permissions, register a service or start remote execution. A partial
failure is retained for inspection and cannot be blindly replayed over that
directory. An existing install must use its separate verified update flow.

On macOS, GUI preparation requires the publisher-signed `/Applications/Styx.app`
and exact expected Apple team identity; app installation/signing is a separate
artifact step. Open the app through LaunchServices and let the user grant TCC.
The generated computer config connects to its private embedded socket.

## Pair with explicit owner approval

The Gateway owner uses its separate private admin configuration to issue a
one-use invitation with `gateway/enroll-admin.mjs ... invite`. Transfer it to
an owner-private local file; never put it in a plugin package or conversation.
Use the bundled Node and signed release's `host/enroll.mjs`:

```text
<bundled-node> <release_root>/host/enroll.mjs onboard <baseDir>/enrollment.json <invitation-file>
```

The command shows only the public request ID, device ID and fingerprint. The
owner compares the exact fingerprint against the native device output, then
approves it via `gateway/enroll-admin.mjs ... approve REQUEST_ID FINGERPRINT`
(append `computer` only for explicitly approved GUI). Model-facing MCP tokens
cannot perform owner approval. Pairing writes private `device/host.json`; it
does not install/start a service. Run signed `host/doctor.mjs` against that file.

## Enable the independent native service

Use the same bundled Node and signed release helpers. The generated service
config uses a new product identity and refuses a foreign existing service:

- Linux: `host/linux-service.mjs install styx-host.service <baseDir>/service.json`,
  then explicit `enable` and `start` for that name.
- macOS: `host/macos-launchagent.mjs install app.styx.connector <baseDir>/service.json`,
  then `start app.styx.connector`; keep the signed GUI app running in that user.
- Windows: `powershell.exe -NoProfile -File <release_root>/host/windows-task.ps1
  -Action install -TaskName Styx-Host -ConfigPath <baseDir>/service.json`, then
  `-Action start -TaskName Styx-Host` in the intended interactive user session.

Recheck local Doctor and service status. Add the new Styx plugin using the
Gateway's separate model credential via the supported connection flow. Never
reuse the owner/admin credential for the plugin.

## Fresh conversation acceptance

Use only the new plugin, its instructions and this release's public handoff.
Discover allowed environments, explicitly select the returned ID, inspect
passive status, execute an exact marker, exercise PTY/readback/cleanup and a
self-expiring owned GUI fixture. Verify owner revocation rejects the removed
device and that a new conversation does not inherit old process/GUI handles.
Record actual account-side results separately from SDK tests. Do not mark a
device ready just because its outbound socket connected. Do not silently fall
back to another plugin or backend when a step fails.
