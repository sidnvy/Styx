# Fresh native Styx onboarding

The default fresh runtime is the Rust CLI from a publisher-signed native C08
payload. Use [the current CLI command guide](rust-core-rewrite/NATIVE-CLI-PAIRING.md)
for exact options and error outcomes. This is a portable, foreground pairing
journey with separate private Gateway and Host directories. It is not an
installer, an update/rollback flow, or proof of a ChatGPT account connection.
Fresh Gateway bootstrap currently supports loopback HTTPS. The commands below
use a Linux shell; they do not establish macOS/Windows GUI or service parity.

Obtain the exact candidate payload, public publisher PEM and independently
trusted original publisher SPKI SHA-256 pin from its release handoff. A pin
beside a download is not an independent trust source. Keep the verified payload
at its stable private location after creating runtime selection data. The
headless Exec path requires the signed `codex_exec` worker; it does not require
a Node Core, Browser or GUI permissions.

## Verify and prepare a fresh Gateway

Use absolute paths. Create new owner-private input and profile parent directories
(mode 0700 on Linux); do not adopt old state or repair an existing directory's
permissions. Write inputs as mode-0600 files under a private parent. All names
below are placeholders to replace with the release's actual paths and values.

```sh
STYX=/absolute/private/payload/bin/styx
# Use a new output file; retain a failed command's output for inspection.
(umask 077; set -C; "$STYX" release verify \
  --payload-dir /absolute/private/payload \
  --publisher-file /absolute/private/publisher.pem \
  --expected-publisher ORIGINAL_TRUSTED_PIN --runtime-selection \
  > /absolute/private/inputs/runtime-selection.json)
```

Require verification success before continuing. In the input directory save a
Gateway deployment, choosing an unused loopback port:

```json
{"schema":1,"mode":"create-local","gateway":{"url":"https://127.0.0.1:22022/","listenHost":"127.0.0.1"}}
```

```sh
"$STYX" gateway bootstrap --parent-dir /absolute/private/gateway-parent \
  --name gateway --deployment-file /absolute/private/inputs/gateway.json \
  --runtime-selection-file /absolute/private/inputs/runtime-selection.json --json
"$STYX" plan --native --state-dir /absolute/private/gateway-parent/gateway \
  --component gateway --run running --transaction-id gateway-first-run \
  --sequence 1 --json
"$STYX" apply --state-dir /absolute/private/gateway-parent/gateway \
  --plan-file EXACT_PLAN_FILE_FROM_PREVIOUS_REPORT --authorize --json
"$STYX" gateway run --state-dir /absolute/private/gateway-parent/gateway
```

Bootstrap creates TLS and enrollment materials with desired Stopped. Plan/apply
commits explicit Running intent; it does not start a listener. Keep `gateway run`
in its original terminal and wait for its real listening event. Use another
terminal for the following commands. Initial sequence 1 applies to this fresh
root only; subsequent changes must use the actual current transaction sequence.

## Request and compare the original Host identity

Create a one-use invitation in a new private file outside the Gateway root and
payload. Its parent must already be private; an existing file is refused.

```sh
"$STYX" gateway invite --state-dir /absolute/private/gateway-parent/gateway \
  --invitation-file /absolute/private/inputs/invitation.txt \
  --ttl-seconds 600 --authorize --json
```

The report exposes the output path and expiry, not the invitation. Keep invitation,
admin and Host credentials out of argv, conversations and plugin packages. The
Gateway's model MCP credential is separate from its owner/admin credential.

Create a private Host deployment as described in the
[CLI guide](rust-core-rewrite/NATIVE-CLI-PAIRING.md). It specifies `join-existing`,
the same exact Gateway origin, `caFile`, `expectedCaSha256`, a Host `label`,
private `cwd`, `/bin/bash` shell, `computer:false`, and the absolute
`runtimeSelectionFile` and `invitationFile` paths. Browser is omitted for this
headless journey. `expectedCaSha256` is the SHA-256 of the actual CA certificate's
DER bytes, not its PEM text, SPKI or TLS leaf. For example:

```sh
openssl x509 -in /absolute/private/gateway-parent/gateway/gateway-ca.pem \
  -outform DER | sha256sum
"$STYX" host join request --parent-dir /absolute/private/host-parent \
  --name host --deployment-file /absolute/private/inputs/host.json --json
"$STYX" gateway pending --state-dir /absolute/private/gateway-parent/gateway --json
```

Request exactly once. Compare the Host's request ID, device ID, full fingerprint
and comparison code with the pending entry. The code binds the original origin,
verified TLS leaf, request and device fingerprint. Do not approve a different or
expired request, and do not treat displaying the code as the user's comparison.

```sh
"$STYX" gateway approve --state-dir /absolute/private/gateway-parent/gateway \
  --request-id EXACT_REQUEST_ID --device-id EXACT_DEVICE_ID \
  --fingerprint EXACT_FINGERPRINT --comparison-code EXACT_COMPARISON_CODE \
  --authorize --json
"$STYX" host join claim --state-dir /absolute/private/host-parent/host --json
```

No Computer or Browser capability is enabled by default. `awaiting_approval` is
not ready. A successful `ready_to_connect` claim requires original claim/confirm
and current authenticated self proof; it starts no executor. Claim is not a
credential refresh command and is not part of ordinary reconnect.

## Connect, observe a real effect, and reopen

```sh
"$STYX" plan --native --state-dir /absolute/private/host-parent/host \
  --component host --run running --transaction-id host-first-run --sequence 1 --json
"$STYX" apply --state-dir /absolute/private/host-parent/host \
  --plan-file EXACT_HOST_PLAN_FILE_FROM_PREVIOUS_REPORT --authorize --json
"$STYX" host run --state-dir /absolute/private/host-parent/host
```

Wait for the original Host's connected event. Through the official MCP client or
supported plugin connection, discover allowed environments, select the returned
original device ID, and read `get_execution_environment_status`. Require that
exact environment's access to be allowed and Exec connection to be connected;
a socket connection alone is not readiness. This is read-only observation, not
another approval.

Issue one `exec_command` with a fresh nonce and a new file in the chosen private
Host working directory. Use no-clobber creation, drain its native session to
exit0, and independently inspect the file's exact bytes. Never repeat an Exec
because its result is Unknown. Close the original MCP owner with session DELETE
and client close; a close acknowledgment alone does not prove every remote job
has joined.

Stop the original foreground Host with Ctrl-C/TERM and wait for its joined
cleanup and actual exit, including complete remote transport drain. Then stop
and await Gateway. Preserve the same private roots and signed selection. Start
Gateway and Host again with the same `gateway run`/`host run` commands, without a
new invitation, request or claim. Confirm the same identity and pairing, observe
the exact device connected, and perform a second fresh independent nonce before
normal cleanup. Foreground exit does not change canonical Running intent.

## Failure and acceptance limits

A wrong approval binding is `not_dispatched`; an authenticated HTTP refusal is
`rejected`. A lost post-send response or uncertain cleanup remains Unknown.
Preserve the original transaction, files and process custody for explicit
reconciliation; do not automatically replay invite, approve, Join, Confirm or
business actions. Do not overwrite partial state or fall back to a JS runtime.

Signed installer/update/rollback, remote ingress, GUI/TCC, Browser/Computer,
persistent service and logout/reboot acceptance are separate paths. Native SDK
proof does not establish actual account-side plugin acceptance. Historical Node
setup/enrollment/service helpers remain archived implementation and interop
material, not this default onboarding route.

## Change this computer's role

In App Settings choose **Change this computer's role…** to stop this computer,
back up its settings, and return to **Set up this computer** or **Join an existing
Gateway** without restarting the App. If its local Gateway has other approved
devices, review their names and IDs and explicitly confirm **Disconnect these
devices too**. Those devices will need to be paired again as well.

On Linux stop the foreground roles or their service first, then use
`styx role retire --state-dir ABS_HOST --gateway-state-dir ABS_LOCAL_GATEWAY --authorize --json`.
Omit the Gateway option for Host only. A device-confirmation refusal lists the
other devices; add `--allow-other-devices` only after reviewing them. Follow the
[CLI guide](rust-core-rewrite/NATIVE-CLI-PAIRING.md#change-this-computers-role)
for report fields and recovery, then repeat normal fresh bootstrap/join.

The original roots become sibling `.retired-YYYYMMDDThhmmssZ` backups; they are
never deleted or migrated. Keep each machine's publisher signing keys and pins.
Retirement does not revoke a Host at a remote Gateway or move its other devices.
