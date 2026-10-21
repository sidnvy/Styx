# Physical Linux Gateway / Windows Host acceptance

`host/cross-platform-acceptance.mjs` provides two explicitly authorized native
test actors. Source development stays local; execute actors on their physical
test hosts. Ordinary unit tests do not start listeners, change tasks, or enroll.

Both actors require `STYX_RUN_CROSS_PLATFORM_ACCEPTANCE=1`. The Gateway input
contains a fresh `directory`, existing verified Linux CLI `distribution`, an
exact owned IPv4 `listenHost` and `authorizeExactInterface:true`. Core validates
the actual interface and generates its TLS identity. Wildcard and loopback binds
are rejected for this cross-machine test. No firewall rules, NAT forwarding,
systemd unit, scheduled task, daily profile, or production configuration changes.

The Windows actor input contains its own fresh `directory` and explicit public
runtime paths `nodeBinary`, `codexBinary`, `cuaBinary`, `nodeLicenseFile`. It
checks the previously verified native hashes, creates a test-only publisher,
builds the real signed Host with the locked Browser closure, then deletes the
private signing key. This is not official release publisher acceptance.

Run the actor with `node host/cross-platform-acceptance.mjs gateway|host INPUT`.
Each owns only its private test directory and process lifetime. Its ready file
contains public endpoint/certificate information or its own loopback test site.
Private `send` command JSON goes through stdin. Commands are queued under that
actor's private directory, and results go to an explicit fresh `responseFile`;
stdout contains only status/path, never invitation material or credentials.
Keep private files private on both native platforms. Move only the short-lived
invitation through the encrypted management connection, not keys or Host tokens.

Sequence:

1. Read physical addresses/routes and test direct reachability. SSH is only the
   management channel; do not use an SSH tunnel as evidence of direct access.
2. Start Gateway on its explicitly authorized exact interface. Its ready file
   records the real certificate fingerprint. Request an `invite`.
3. Start Windows actor. Send `join` with the one-use `link`, `approvedOrigin`,
   `approvedCaSha256` independently checked against Gateway ready material.
   Core verifies the reachable TLS endpoint, imports approved CA trust and
   requests enrollment using its own generated Windows identity.
4. Send Gateway `approve` with Windows `requestId`, `deviceId`, `fingerprint`.
   Owner compares the actual pending identity; wrong fingerprint is rejected
   before exact explicit approval. Send Windows `claim` to complete Core doctor
   and foreground Host startup. Joining must not create another Gateway.
5. Gateway `verify` takes the approved `deviceId`, Windows actor's own `siteUrl`,
   `longCommand:true`, `expectedStoredCount:0`. It performs actual PowerShell
   `Start-Sleep -Seconds 12` via Exec (15-second initial yield), checks exact
   marker/exit, and observes/types/clicks in installed Edge's dedicated profile.
6. Windows `status` independently checks the synthetic test server saw exactly
   one action. Windows `crash` terminates only its verified own Codex child;
   actual Host supervision reconnects. Repeat Gateway `verify` with
   `expectedStoredCount:1`; Windows `confirm` checks unchanged identity/credentials,
   restored own executor and no replay of the original browser action.
7. Stop Windows actor, then Gateway actor. Confirm both foreground processes
   exit and private deployment/profile/credential state is removed. Preserve
   public receipts and source/runtime hashes; no test private key is retained.

Gateway output is not chat-account acceptance. Windows SSH execution does not
prove interactive Cua, login/lock/reboot recovery, or arbitrary NAT traversal.
The VPN or LAN supplies a route only; TLS identity, invitation and explicit
device approval supply trust. A blocked direct route is a blocked result, not a
reason to disable TLS or silently alter firewall policy.
