---
name: styx-native-onboarding
description: Onboard a fresh native Linux, macOS, or Windows device to an independent Styx Gateway, then use its explicitly selected native execution and computer tools.
---

# Native Styx onboarding

Use only this standalone Styx connection and native Styx release. This is a CLI bootstrap workflow, not a graphical installer. Do not depend on a previous conversation, pilot state, another plugin, or an execution backend. If required tools or artifacts are missing, name the exact missing prerequisite; never silently substitute another connection.

## Choose the workflow from the actual pinned source

Read the source/release revision first. The developer preview tag
`v0.1.0-dev.20261019` does not contain the newer `vnext/onboarding` controller;
use the commands actually shipped by that tag. When the selected source does
contain `vnext/onboarding/README.md`, use its fixed CLI/UI workflow and persisted
status/plan instead of inventing shell steps or editing its journal/config.
A user-approved device scope can authorize the bounded installation sequence;
do not request the same permission at every mechanical substep. Owner pairing
approval and service startup must remain within that exact scope. Never pass an
approval flag merely because it makes a blocked step continue.

A prior succeeded journal entry is not live service health. An uncertain outcome
requires observation and reconciliation, not replay or lock deletion. SDK
Gateway verification does not prove the account plugin connection. No model tool
may receive owner credentials or device private keys. The local browser owner UI
is distinct from the account plugin and must not be publicly exposed.

## Establish the independent connection

A fresh account connection needs a newly provisioned Styx Gateway with its own state, model Bearer credential, and separate owner/admin credential. Use a verified HTTPS MCP endpoint or a newly created Secure MCP Tunnel ID belonging to this Gateway. Never borrow an existing tunnel, endpoint, token, plugin, device registration, or admin configuration. A Secure MCP Tunnel connects the account to MCP; it does not replace the Host's trusted HTTPS/WSS connection to the Gateway.

From the concrete merged-release handoff, obtain exact source/release revision, signed native Host bundle, publisher public key and independently trusted SHA-256 SPKI DER fingerprint. Do not invent download URLs, hashes, endpoints, or signing identities. Use the platform's supported private connection flow to enter the separate model Bearer credential; never put credentials in chat, a plugin package, or command arguments. Owner key operations are outside model-facing MCP tools.

For initial package generation, the Gateway owner first performs authenticated MCP discovery against the actual fresh connection. Record the exact connection identity, server name, tool names, and verification time using the release's plugin verification contract. Then run `node vnext/plugin/package.mjs ABS_CONFIG ABS_OUTPUT/styx-native` from the trusted source. This validates the operator receipt, not a new live probe. Inspect the package, archive the one `styx-native` directory outside itself, and save through the supported plugin creation/install flow. Creation is not successful connection acceptance. Never create a placeholder cloud plugin.

## Prepare a fresh native device

Use trusted local Node 22+ only for initial bootstrap. On the actual native device, create an owner-private parent directory and an owner-private setup JSON. Do not print secret file contents. The configuration requires absolute `bundle`, `publisherKeyFile`, a trusted `publisherSha256`, fresh `baseDir`, exact HTTPS Gateway origin `gatewayUrl`, human-readable `label`, and explicit boolean `computer`. Optional fields are dedicated `gatewayCaFile`, macOS `macTeamID`, Linux `wayland`, and native `shell`. A private CA must be trusted explicitly; never disable TLS verification.

From the trusted merged source run:

```text
node vnext/host/setup-native.mjs prepare ABS_PRIVATE_SETUP_JSON
```

Use the returned bundled `node`, `release_root`, `enrollment_config`, and `service_config` paths. Preparation verifies publisher fingerprint, release signature and files, stages the native runtime, and creates configuration. It does not pair, approve, grant OS permissions, or start a service. If it partially fails, inspect its exact state; do not replay over an existing directory or erase evidence. Existing installations require their separate signed update path.

On macOS computer access requires the publisher-signed `/Applications/Styx.app` and verified team identity. Open through LaunchServices; the user grants TCC permissions in the actual GUI. Do not infer permission from a connected socket. Linux Wayland requires explicit supported opt-in. Windows GUI work runs in the intended interactive user session.

## Pair and enable only with explicit owner approval

The Gateway owner issues a one-use invitation using the separate private `gateway/enroll-admin.mjs` configuration. Transfer the invitation directly into an owner-private local file. It is not a model credential. Using paths from the setup receipt:

```text
BUNDLED_NODE RELEASE_ROOT/host/enroll.mjs onboard BASE_DIR/enrollment.json PRIVATE_INVITATION_FILE
```

Compare the public device fingerprint shown on the native device with the pending owner request. The owner separately approves the exact request ID and fingerprint; add computer permission only when explicitly requested. Do not put owner/admin keys in MCP or automate approval through model-facing tools. Pairing produces `device/host.json` but does not install a service. Run the signed `host/doctor.mjs` using that file and follow its actual diagnostics.

Only after the user authorizes service installation/start, use the verified release helpers with the generated service configuration:

- Linux: `host/linux-service.mjs install styx-host.service BASE_DIR/service.json`, then explicit `enable` and `start` for that name.
- macOS: `host/macos-launchagent.mjs install app.styx.connector BASE_DIR/service.json`, then `start app.styx.connector`; retain the signed GUI app in the same user session.
- Windows: `powershell.exe -NoProfile -File RELEASE_ROOT/host/windows-task.ps1 -Action install -TaskName Styx-Host -ConfigPath BASE_DIR/service.json`, then explicit start for `Styx-Host`.

Use bundled Node for JavaScript helpers. Do not overwrite a foreign existing service. Recheck Doctor and service status independently.

## Discover and verify actual native tools

Discover this plugin's tools before calling them. Call `list_execution_environments`, select an exact returned environment ID with the user, then call `get_execution_environment_status` for it. Connection and configured capability do not prove readiness. If no enrolled environment exists, finish pairing rather than invent an ID.

Use `exec_command` with explicit `environment_id`, native command and working directory. Respect the returned `session_id`; poll or write only that owned session via `write_stdin`. A timeout, disconnect, or uncertain action is not permission to rerun it. Read back known state before deciding whether another action is safe. Never carry session handles across new conversations.

Computer tools are discovered dynamically. Use their actual input schemas, starting with supported observation tools such as `list_apps`, `list_windows`, `get_window_state` or `get_desktop_state`. Actions require current observed references and the selected device. Observe again after a mutation. Do not invent cross-platform tool names or reuse stale GUI references. If permission is absent, guide the user through native OS permission UI.

For fresh-conversation acceptance, execute an exact harmless marker, verify output, exercise a bounded PTY and cleanup, then use a self-expiring owned GUI fixture on the explicitly selected device. Check actual effect separately from dispatch. Verify revocation using owner-controlled administration, then confirm the removed device is rejected. Report the exact environment, revision, evidence and any failures. Never claim account-side acceptance from SDK tests or package creation alone.
