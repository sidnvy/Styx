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

Set `additionalEntry:true` for the ordinary Add Computer acceptance. This starts
an independently prepared Gateway on localhost and connects a real MCP client
first. Core then adds the authorized exact-interface listener. The actor checks
that the same MCP session and all primary TLS, owner and token files remain
unchanged. Invitation origin and certificate come from the new listener.
`close` closes its pairing window; approved devices must still reconnect and run
tools afterward. The final receipt requires these extra gates in this mode.
This does not prove an existing external chat account or a local Host remained
connected: those require their own recorded live clients.

Sequence:

1. Read physical addresses/routes and test direct reachability. SSH is only the
   management channel; do not use an SSH tunnel as evidence of direct access.
2. Start Gateway on its explicitly authorized exact interface. Its ready file
   records the real certificate fingerprint. Request an `invite`.
3. Start Windows actor. Send `join` with the one-use `link`, `approvedOrigin`,
   `approvedCaSha256` independently checked against Gateway ready material.
   Core verifies the reachable TLS endpoint, imports approved CA trust and
   requests enrollment using its own generated Windows identity.
4. Send Gateway `approve` with Windows `requestId`, `deviceId`, `fingerprint`, and (for additional-entry mode)
   the joining side’s `comparisonCode`. Owner compares the actual pending identity; wrong fingerprint is rejected
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

## Physical acceptance result — 2026-10-22 (Asia/Shanghai)

Final Windows `host-run4` and Linux `gateway-run4` completed with `PASS`,
respectively six and seven required gates, no missing gates. These are two
physical machines, unlike the earlier two-Host test on one Linux workstation.
The direct route used Workstation's explicitly authorized `10.0.2.19` VPN
interface and NAB `10.0.8.146`; SSH transferred control inputs only. The listener
was not wildcard-bound, no SSH data tunnel or firewall change was used.

The final Core flow created and consumed a new one-use invitation, independently
confirmed the actual TLS fingerprint, generated the Windows identity, refused
an incorrect device fingerprint, approved the exact pending identity, claimed
credentials, ran doctor and started the foreground Host. The owned foreground
projection reported an external Gateway and no local Gateway directory existed.
Real Windows PowerShell Exec slept for 12 seconds and returned the exact marker
with exit 0 in **12,307 ms**. Installed Edge observed the dedicated loopback site,
typed and clicked, with the independent site observing exactly one stored action.
After terminating only owned Codex PID **20444**, supervision created PID
**12892**. Exec then succeeded in **264 ms**, Edge observations succeeded, and
identity/configuration/credential hashes remained unchanged.

A request overlapping the deliberate executor crash failed. Its original
`BLOCKED` attempt remains in the Gateway receipt; an explicit probe after crash
completion succeeded. This is recovery of the connection and executor, not
transparent replay of failed requests or durable task resumption.

Both actors exited 0. Windows recorded 12 owned descendant observations with
none remaining; an independent CIM/listener check found no actor or fixture
listener. Linux owner/runtime PIDs and port 35431 were independently absent.
Both sides removed only their own private state and request/response IPC,
including invitations, credentials, signing key and browser profile. No task,
service, firewall, daily profile or production configuration was changed.

Source scope matters: Linux Gateway Core came from the previously checked
`a9b0263` CLI distribution; its actor's MCP client used the corrected
`connection.mjs` digest recorded in the evidence, which exercised the long TLS
response fix. The Windows public source snapshot received six explicitly hashed
runtime overlays matching integration commit `0bd097f`, then built a fresh signed
Host with a test-only publisher and fresh journal. This does not claim that the
old Linux distribution was rebuilt with every later Core change. The ephemeral
private publisher key was deleted, not delivered as an official release key.

Earlier attempts remain separate: the initial attempt exposed slow Windows
staging; run2 exposed script-file policy/headless status refusal; run3 found an
acceptance actor using the cross-process projection instead of the owned API.
Those blocked/diagnostic receipts were retained. The final run used the approved
staging fix, hash-bound helper command, honest scheduler query errors, and owned
foreground API; no fake service observer was substituted.

Public evidence is under the task's
`outputs/cross-platform-20261021/delivery-run4/`: `delivery.json` inventories
receipt/module hashes, both final actor receipts, initial/recovered tool results,
the retained during-crash failure, source overlays and independent cleanup.
Original attempt evidence remains beside that delivery directory. This does not
validate interactive Windows Cua, machine reboot/login/logout, Linux update
migration or rollback, ChatGPT account acceptance, arbitrary NAT traversal, or
an official release signature. Those remain separate acceptance boundaries.
