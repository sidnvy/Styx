# Fresh native foreground CLI pairing

This path uses a verified native C08 payload, a fresh Gateway-only root and a fresh Host root. It does not install services, change App management or migrate an old identity. ChatGPT reaches the loopback Gateway only through OpenAI’s Secure MCP Tunnel. Fresh Gateway bootstrap keeps its local HTTPS origin on loopback; explicit private-network listeners can also admit remote Hosts. Keep the payload at its stable verified private location; do not move it after creating selection data.

1. Verify the signed native payload with the original externally trusted publisher pin: `styx release verify --payload-dir ABS_PAYLOAD --publisher-file ABS_PUBLIC_PEM --expected-publisher ORIGINAL_PIN --runtime-selection`. Save this public selection to a protected private input file. Use a payload with codex_exec; headless pairing/Exec does not require Node or Browser.
2. In a private input directory create schema1 Gateway deployment `{"schema":1,"mode":"create-local","gateway":{"url":"https://127.0.0.1:PORT/","listenHost":"127.0.0.1"}}`. Run `styx gateway bootstrap --parent-dir PRIVATE_PARENT --name gateway --deployment-file ABS_DEPLOYMENT --runtime-selection-file ABS_SELECTION --json`. This publishes real TLS/empty enrollment/ready, with desired Stopped; it does not start a process.

   To accept Hosts over Wi-Fi and an existing overlay at the same time, use `{"schema":1,"mode":"create-local","gateway":{"url":"https://127.0.0.1:PORT/","listenHost":"127.0.0.1","allowRemoteHosts":true,"lanAddresses":["10.118.53.220","10.0.2.19"]}}` in `ABS_DEPLOYMENT`, then run the same bootstrap command:

   ```sh
   styx gateway bootstrap --parent-dir PRIVATE_PARENT --name gateway --deployment-file ABS_DEPLOYMENT --runtime-selection-file ABS_SELECTION --json
   ```

   `lanAddresses` accepts 1–4 distinct IPv4 addresses assigned to this computer in RFC 1918 or `100.64.0.0/10` (for an existing overlay such as WireGuard or Tailscale). The existing `lanAddress` string remains supported; supplying both fields is refused. Public, loopback, link-local and wildcard private-listener addresses are refused. Gateway binds every selected address at the same port alongside loopback, and its endpoint certificate contains all of them as IP SANs. Any bind failure refuses startup. These private listeners expose join/claim/confirm, authenticated Host self enrollment and the Host link; MCP and administrator/control routes stay on loopback. Styx configures no router ports or overlay.

   `gateway invite --json` reports `origin` (the first private address by default when enabled) and `origins` (loopback plus every private address). Use `--origin loopback`, `--origin lan` (first private address), or `--origin-address 10.0.2.19` (must be configured); `--origin-address` and `--origin` are mutually exclusive. Copy the selected origin into the Host deployment's `gateway.url` with the existing CA file and CA hash, or export an App join link in step 4. The invitation file remains a raw one-use token. Private transfer and comparison/approval remain required.

   Address changes require a rebuild for v1. Stop and join the original processes, retire the local role roots using the **Change this computer's role** procedure below, update `ABS_DEPLOYMENT`, then bootstrap and pair again. For local Host + Gateway roots, run `styx role retire --state-dir ABS_HOST --gateway-state-dir ABS_GATEWAY --authorize --json`; if other devices are reported, review them before adding `--allow-other-devices`. The current role-retire CLI requires a Host root. For a Gateway-only profile, retain the stopped original root and bootstrap under a new name (for example `--name gateway-v2`) instead. Retirement preserves the old root under its reported backup path. A fresh bootstrap creates a new CA and identity; every Host must re-pair, and tunnel configuration must be supplied again. No in-place network-change command is provided.

3. Use `styx plan --native --state-dir ABS_GATEWAY --component gateway --run running --transaction-id UNIQUE_TX --sequence 1 --json`, then `styx apply --state-dir ABS_GATEWAY --plan-file EXACT_REPORTED_PLAN --authorize --json`. Run `styx gateway run --state-dir ABS_GATEWAY` in its original foreground terminal and wait for its ready/listening event.
   Configure account reachability with `styx gateway tunnel configure --state-dir ABS_GATEWAY --tunnel-id tunnel_OWNER_ID --api-key-file ABS_PRIVATE_KEY_FILE --auto-start --authorize --json`. The API key comes only from an owner-only private file; never put it on argv or in the environment. This stores a private managed copy. Stop and restart the foreground Gateway to start the transport; configuration/removal is refused while its tunnel supervisor owns the configuration. `styx gateway tunnel status --state-dir ABS_GATEWAY --json` reports configuration, signed-client availability and observed health without revealing credentials. `tunnel_started` means process startup; `tunnel_ready` requires both local health endpoints to return 200. Neither proves account-side acceptance. The owner must provide their OpenAI tunnel ID and key and complete account-side acceptance in ChatGPT.

   The selected signed payload must include optional `workers/tunnel-client/tunnel-client-runtime[.exe]` v0.0.17. Build it with `--tunnel-client ABS_BINARY --tunnel-client-sha256 EXPECTED_SHA256 --tunnel-client-license ABS_LICENSE --tunnel-client-notice ABS_NOTICE`; all four inputs are required together, verified and included in the signed manifest. Payloads without the client remain valid; Gateway emits `tunnel_unavailable` and keeps serving. The transport uses the Gateway CA and file-backed bearer header, clears inherited proxy/credential variables, and sends no `X-Styx-Tunnel-Context`. Unexpected client exits retry after 15 seconds without replaying MCP requests. Gateway stop terminates and joins the child. To remove configuration, first stop the Gateway, then run `styx gateway tunnel remove --state-dir ABS_GATEWAY --authorize --json`; the source API key file remains the owner’s responsibility.

4. Create a new invitation file outside the Gateway root and payload: `styx gateway invite --state-dir ABS_GATEWAY --invitation-file ABS_NEW_PRIVATE_FILE --ttl-seconds 600 --authorize --json`. The output file parent must already be private. Existing files are refused, never replaced. The stdout report contains the output path, expiry, one_use and usable origins; the invitation itself is never printed. TTL remains 60–600 seconds. To use the Mac App's **Join an existing Styx**, export a link containing the same token, expiry, selected origin and public CA:

   ```sh
   styx gateway invite --state-dir ABS_GATEWAY --invitation-file ABS_NEW_PRIVATE_FILE --origin-address 10.0.2.19 --app-link-file ABS_NEW_PRIVATE_LINK --ttl-seconds 600 --authorize --json
   ```

   Both output parents must already be private; both files must be new, distinct and outside the Gateway root and payload. Files are created with mode 0600 / private ACL. The App link is exactly `styx://join#<base64url(canonical JSON)>`; paste the file's contents into the App's join flow. The link is secret and is never printed in the report. The raw invitation and link share one one-use token: use one join flow. Transfer the link, or the raw invitation and public Gateway CA, using a trusted private channel; do not put invitation/admin tokens on argv.
5. Host private schema1 deployment: mode `join-existing`, gateway `{url,caFile,expectedCaSha256}` (SHA256 of actual CA certificate DER, not PEM/SPKI/endpoint leaf), host `{label,cwd,shell,computer:false}`, runtimeSelectionFile and invitationFile absolute locators. `gateway.url` is the bare origin (`https://127.0.0.1:PORT`, no trailing slash), unlike the Gateway deployment's `url`; anything else is `native_join_invalid_input`. Browser may be omitted; when enabled, host `browser` is `{enabled:true,headless:true,persistLogin:false,channel,executablePath}` and Linux requires an absolute `executablePath` (for example `/usr/bin/google-chrome-stable`). Pass `--enable-browser`/`--enable-computer` to `gateway approve` to grant those lanes. Run `styx host join request --parent-dir PRIVATE_PARENT --name host --deployment-file ABS_HOST_DEPLOYMENT --json` exactly once. Keep its public request/device/fingerprint/comparison_code report.
6. Run `styx gateway pending --state-dir ABS_GATEWAY --json`. Compare the exact request ID, device ID, fingerprint and comparison code with the Host report. Every displayed code is independently recomputed from this original origin, actual verified TLS peer leaf, request ID and device fingerprint. This is data for the user's comparison, not proof the user compared it.
7. Approve only the compared request: `styx gateway approve --state-dir ABS_GATEWAY --request-id HEX32 --device-id EXACT_DEVICE --fingerprint HEX64 --comparison-code AAAA-BBBB-CCCC-DDDD --authorize --json`. Optional `--enable-computer`/`--enable-browser` must have been requested by that exact Host; neither is enabled by default. The actor first reads the live pending list and refuses a wrong device/fingerprint/code before its unique approve POST. There is no bulk approve.
8. Run `styx host join claim --state-dir ABS_HOST --json`. `awaiting_approval` is not ready; successful ready_to_connect requires the original encrypted claim/confirm and current authenticated self proof. Claim never starts an executor. Then use native plan/apply for Host Running (initial sequence1 in this separate root), and `styx host run --state-dir ABS_HOST`. Wait for actual connected/public execution-environment status before issuing one Exec command.
9. Close the original MCP owner. Stop the original Host by its foreground Ctrl-C/TERM and await its joined outcome/actual process exit before stopping Gateway; retain the protected roots and reopen them normally without new invitation or pairing.

Each admin command emits schema1/operation/state_dir/operations_replayed:false. `pending` contains only public identities, requested capabilities and expiry. Approval reports the exact request/device/fingerprint/comparison and approved status. A binding refusal has exit2/error native_gateway_approval_binding_mismatch/outcome not_dispatched; an authenticated HTTP rejection has outcome rejected, not not_dispatched. TLS/connect pre-send failure is typed not_dispatched. Lost/invalid post-send responses, material changes after dispatch or failed invitation publication return exit4/outcome unknown. Never automatically repeat invite/approve/Join/Confirm after Unknown; preserve the original files and evidence for explicit reconciliation. No generic init, legacy advance, fake ready, new AppScope or second configuration writer is used by this route.

Native managed installation/update/rollback, nontransient host pause/resume, direct internet bootstrap and non-Linux persistent-service integration remain separate incomplete product paths. These commands establish foreground pairing only; real effects and cleanup require the native acceptance journey.

Reviewer checks: `cargo test -p styx-runtime tunnel -- --skip requires_loopback_sockets` runs the configuration, signed-payload availability and process-lifecycle scenarios without sockets. Run `cargo test -p styx-runtime requires_loopback_sockets` on a machine that permits loopback TCP binding for the health and real Gateway-owner scenarios; the latter compiles its own fake native client with `/usr/bin/cc`. These fixtures do not connect to the OpenAI control plane or establish account-side acceptance.

For the two-listener LAN scenario run `STYX_TEST_LAN_ADDRESS=192.168.1.20 cargo test -p styx-runtime gateway_two_listeners_lan_join_and_host_link_requires_sockets -- --ignored --nocapture`. The address must belong to the test machine; if omitted, the test tries the default route's local private IPv4 without sending a UDP packet. This ignored Linux scenario requires sockets, creates synthetic TLS/device keys and a private journal under `target/`, enrolls/claims/confirms through LAN with local approval, observes a negotiated Host in the Gateway registry, and checks LAN MCP/admin refusal with valid credentials. For the two-private-address sibling, run `STYX_TEST_LAN_ADDRESSES=10.118.53.220,10.0.2.19 cargo test -p styx-runtime gateway_three_listeners_two_lan_addresses_join_and_host_link_requires_sockets -- --ignored --nocapture`. Both addresses must belong to the test machine. It checks private-listener MCP/admin refusal on each address, shared enrollment/self proof and Host reconnect through each address. These are transport evidence, not package or two-machine acceptance.

## Change this computer's role

Stop and join the original Host and (if local) Gateway first. On Linux, retire
only this computer's chosen private role roots:

```sh
styx role retire --state-dir ABS_HOST --gateway-state-dir ABS_LOCAL_GATEWAY --authorize --json
```

Omit `--gateway-state-dir` for Host only; never supply a remote Gateway's root.
A held execution/configuration lease refuses retirement. If the local Gateway
has other approved devices, `role_retire_gateway_has_devices` reports their
`deviceId` and `label` in `retirement.otherDevices`, without renaming anything.
After reviewing them, explicitly add `--allow-other-devices` to disconnect them
from this retired Gateway too; they must be re-paired separately.

Each root is renamed in its existing parent to `<name>.retired-YYYYMMDDThhmmssZ`.
The JSON report lists `oldPath`/`newPath`; nothing is deleted or migrated and an
existing backup is never overwritten. A partial rename returns `outcome: unknown`
and the paths already moved: preserve those backups and inspect the remaining
paths instead of replaying the command. Afterwards use the normal fresh Gateway
bootstrap plus Host pairing, or Host join flow, with the original root names.
Publisher signing keys and pins stay on their original machines.

In macOS/Windows App Settings choose **Change this computer's role…**. The App
stops its roles, asks **Disconnect these devices too** if other approved devices
exist, and backs up its fixed setup inputs alongside `host/` and `gateway/`.
It returns to the existing welcome choices in the same process; no restart is
required after success. Cancelling the device confirmation leaves the setup
retained and stopped, ready to reconnect. It does not revoke this Host at a
remote Gateway; its owner can do that there.
