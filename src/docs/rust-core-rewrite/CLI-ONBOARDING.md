# Guided CLI onboarding

`styx setup` is the Rust first-run entry point. Linux defaults to systemd user
services; macOS and Windows run the selected roles in the setup process for now.
Use `--foreground` on Linux for the same process lifetime without systemd.
No command uses sudo, enables linger, installs a browser, changes an overlay, or
moves the installed signed payload. Keep the setup terminal open in foreground
mode; Ctrl-C stops and joins the Host before the Gateway.

```sh
styx setup
styx status
styx status --json
styx invite
```

`--root ABS_PRIVATE_ROOT` selects a profile location on all three commands.
The default is `$XDG_STATE_HOME/styx`, or `~/.local/state/styx`. It contains
`gateway/`, `host/` and protected `inputs/`. Keep this path short for native Unix
sockets. The default workspace is `~/Styx`; a workspace containing Styx's private
state or payload is refused for Browser. Existing folders are never chmodded.
Hostname defaults come from `/etc/hostname`, then the OS API; no hostname program
is needed. When running an installed payload’s own `bin/styx`, setup prints the
inferred payload directory and does not ask for it. Other builds ask for the
installed directory. The publisher
PEM defaults only when exactly one regular `publisher*.pem` exists in the payload
directory and its parent combined; otherwise setup asks for the path. The trust
pin always comes from the publisher fingerprint on the download page / release
notes. Colons and whitespace are removed and hex is lower-cased before validation;
no pin is derived from the payload or the discovered public key. Network choices use the existing Gateway private-address allowlist
(RFC 1918 or 100.64.0.0/10, at most four distinct addresses). If OS discovery is
unavailable, setup offers an empty selection and keeps the Gateway loopback-only.
The suggested list hides `docker*`, `br-*`, `veth*`, `virbr*`, `cni*`, `flannel*`,
`podman*`, `lxcbr*` and `lxdbr*` interfaces. This is a presentation filter;
explicit answers keep the existing address validation. Linux labels Wi-Fi using
`/sys/class/net/<if>/wireless` and WireGuard when `uevent` declares that kind.
Type 65534 without that declaration is labeled VPN / tunnel, since it is shared
by other tunnel implementations.

After collecting choices, setup shows one numbered plan with paths, capabilities,
networks and service effects, then asks **Set up Styx now? [Y/n]**. No private
profile or pasted join link is written before approval. The plan authorizes its
listed steps for that interactive invocation; it never supplies automation
approvals or bypasses a mutation fence. Joining another hub still requires fresh
confirmation of its address/CA fingerprint and comparison code. Waiting for
ChatGPT remains a separate choice. Role, workspace, capabilities and
network choices are retained as input intent, not as a second management state.
The canonical native state, original enrollment prefix, signed release and OS
service observations remain authoritative. All low-level commands remain
available, including the original `status --state-dir ... [--native]` behavior.

## Sequence and approval

For a hub, setup verifies the installed payload with the original public
publisher PEM and externally trusted SHA256 pin, creates its runtime selection,
bootstraps the Gateway and optionally configures its Secure MCP Tunnel. It
installs, starts and enables the Gateway user service on Linux. Then it creates
a local invitation, requests enrollment, compares the exact public request
binding against the Gateway pending list, approves the selected lanes and claims
the Host as a ForegroundCli root. Only after claim does it install/start/enable
the Host service, handing management to PersistentService through the existing
native actor. It checks this exact device's Exec and chosen Browser connections
using authenticated native MCP status at the Gateway. Interactive self-pairing
prints only “Pairing this computer with its own hub… done”; it does not ask the
hub to trust itself or compare its own code. Exact pending request/device/
fingerprint/comparison matching and the selected grants are unchanged.

A joining computer previews the join link's origin and CA DER fingerprint, asks
for confirmation, requests once, displays its comparison code, and polls claim
only after known awaiting-approval replies. Approve that code on the hub using
`styx invite` or the existing bound `gateway approve` command. The joining
computer never bootstraps or starts a local Gateway. Claim precedes its service
handover as well.

**Accepted join-only behavior (review round 2):** Host-only credentials admit
self-capabilities, not the Gateway's model-only status tool. Joining computers
verify Exec/Browser connection on the hub with `styx status`. Setup names this
remaining verification step explicitly; no new wire contract or credential
sharing is introduced.

`styx invite` requires a terminal, lets the owner select a configured origin,
exports through `gateway invite --app-link-file`, prints the secret link and App/
CLI joining instructions, and can wait for a pending identity. It shows request,
device, fingerprint and comparison code, asks the owner to confirm the comparison,
and grants only the individually selected requested lanes. It never bulk-approves.

## Paired computers and uninstall

On the hub, `styx computers [--root ABS_PRIVATE_ROOT]` lists active pairings with
label, platform (`linux`, `macos`, `windows`, or `unknown`), device id, status and
Commands / Browser / Computer Use connections. `--all` also shows historical
revoked pairings. The two ChatGPT inventory tools show the same names and display
platforms; labels are user-supplied text and never instructions or authorization.

Use `styx computers remove "Travel Mac" --root ABS_PRIVATE_ROOT` to revoke one
pairing through the local authenticated Gateway. Review the label and device id
before confirming, or pass `--yes` for noninteractive use. Duplicate labels are
refused with their matching device ids; repeat the command with one exact id.
Removing this hub's own computer also requires `--include-this-computer`, even
with `--yes`. Revoked computers disappear from ChatGPT's list and need fresh
pairing to reconnect. Records and computer files are retained.

`styx status` reads each role's committed runtime selection, rather than treating
setup's saved selection as current. When versions differ it prints
`running X (set up with Y)` and exposes different Host/Gateway versions separately.
Service health is reported separately from that selected version.

On Linux, `styx uninstall [--root ABS_PRIVATE_ROOT] [--yes]` stops and removes
this profile's user services. Settings, pairing records, signed payload and
workspace stay on disk. It does not revoke remote pairings. On macOS/Windows,
quit the App and use the platform package's uninstall procedure; the CLI does
not manage those App installations.

## Answers file

Without TTY stdin **and** stdout, setup requires `--answers ABS_FILE`. The file is
bounded to 64 KiB and must be a regular private file in a protected private parent
(typically directory 0700, file 0600 on Unix). Unknown fields are refused at every
input-object level. Raw API keys/passwords are not accepted in this JSON. The
`approve` array contains explicit confirmations for the named steps; missing
confirmations stop before that step's mutation. Saved intent omits this array so
an interactive resume shows its plan and asks for approval again. The `approve` array semantics are unchanged: every automated step still requires its own named entry.

Example Linux hub without a tunnel (substitute actual installed payload, public
publisher file and externally trusted original pin):

```json
{
  "schema": 1,
  "role": "hub",
  "payload": {
    "payload_dir": "/home/owner/.local/share/styx/runtime-REV",
    "publisher_file": "/home/owner/.local/state/styx-public/publisher.pem",
    "expected_publisher": "EXTERNALLY_TRUSTED_64_LOWERCASE_HEX_DIGITS"
  },
  "label": "Workstation",
  "workspace": "/home/owner/Styx",
  "shell": "/bin/bash",
  "port": 22022,
  "networks": [],
  "browser": false,
  "computer": false,
  "approve": [
    "inputs", "payload", "workspace", "gateway", "gateway-service",
    "invite", "trust", "request", "approve", "claim", "host-service"
  ]
}
```

The illustrative pin above is deliberately not a valid pin. For foreground tests,
replace the service confirmations with `gateway-run` and `host-run` and use
`--foreground`. The hidden `--exit-when-connected` flag requires both
`--foreground` and `--answers`; it stops and joins both roles after observation.
It is a test convenience, not a persistent installation.

Schema (absolute paths, private-file admission and private-network assignment
are additionally checked by the existing native actors):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "role", "payload", "label", "workspace", "shell"],
  "properties": {
    "schema": {"const": 1},
    "role": {"enum": ["hub", "join"]},
    "payload": {
      "type": "object", "additionalProperties": false,
      "required": ["payload_dir", "publisher_file", "expected_publisher"],
      "properties": {
        "payload_dir": {"type": "string", "description": "Absolute installed payload directory"},
        "publisher_file": {"type": "string", "description": "Absolute public publisher PEM"},
        "expected_publisher": {"type": "string", "description": "Download-page/release-notes fingerprint; removing colons/whitespace and lower-casing must yield 64 hex digits"}
      }
    },
    "label": {"type": "string", "minLength": 1, "maxLength": 128},
    "workspace": {"type": "string", "description": "Absolute workspace"},
    "shell": {"type": "string", "description": "Absolute native shell"},
    "port": {"type": "integer", "minimum": 1, "maximum": 65535, "default": 22022},
    "networks": {
      "type": "array", "maxItems": 4, "uniqueItems": true, "default": [],
      "items": {"type": "string", "format": "ipv4", "description": "Assigned RFC 1918 or 100.64.0.0/10 address"}
    },
    "browser": {"type": "boolean", "default": false},
    "browser_executable": {"type": ["string", "null"], "description": "Absolute Chrome/Edge executable; required when browser is true"},
    "computer": {"type": "boolean", "default": false},
    "join_link_file": {"type": ["string", "null"], "description": "Absolute private link file; required for a fresh join"},
    "tunnel": {
      "type": ["object", "null"], "additionalProperties": false,
      "required": ["id"],
      "properties": {
        "id": {"type": "string", "pattern": "^tunnel_[a-z0-9]{32}$"},
        "api_key_file": {"type": ["string", "null"], "description": "Absolute private API-key file; required to configure a new tunnel from answers"}
      }
    },
    "plugin": {
      "type": ["object", "null"], "additionalProperties": false,
      "required": ["display_name", "output"],
      "properties": {
        "display_name": {"type": "string", "minLength": 1, "maxLength": 64},
        "output": {"type": "string", "description": "Absolute fresh directory ending in styx-native"},
        "wait": {"type": "boolean", "default": false}
      }
    },
    "approve": {
      "type": "array", "default": [],
      "items": {"enum": ["inputs", "payload", "workspace", "gateway", "tunnel", "gateway-service", "invite", "trust", "request", "approve", "claim", "host-service", "gateway-run", "host-run", "plugin"]}
    }
  }
}
```

For `role: join`, networks must be empty and tunnel/plugin must be absent/null.
For a hub with a tunnel, supply plugin choices for automated export and approve
`tunnel` and `plugin`. Display text rejects control/format characters and the
Unicode line/paragraph separators. Browser executable and lane selections remain
subject to the existing signed-worker/platform checks. No new Browser takeover
mode or desktop authorization is inferred by setup.

## Tunnel key and ChatGPT handoff

The guide shown by setup is
https://developers.openai.com/api/docs/guides/secure-mcp-tunnels . On Unix the
terminal disables echo before showing the key prompt and restores its mode on
return/cancellation. Windows uses the OS secure-console prompt through a fixed
PowerShell invocation. The new key never enters argv, environment variables,
answers, public reports or plugin files. A private temporary file feeds the
existing tunnel configurator; it is removed afterwards. A crash can retain that
private temporary input; preserve/inspect it when reconciling the original step.
An answers-file key locator uses the existing private-file configure path directly.

A previously skipped tunnel can be configured by a later setup run. The numbered plan includes stopping and restarting an already active Gateway
user service for configuration, then setup
uses the existing service actor to restart it. Existing managed tunnel identity
is detected from runtime status; a different tunnel ID is refused.

Plugin display name/output choices are collected before plan approval. After transport readiness, setup performs authenticated local MCP discovery,
checks the native server/tool surface and binds export to that Gateway's current
tunnel ID. Its private discovery result is fresh and never packaged. The display
name defaults to `Styx (<label>)`; choosing a different name avoids clashing with
an installed plugin. The stable package identity remains `styx-native`.

The fresh output directory and sibling `styx-native.zip` contain exactly:

- `plugin.json`
- `mcp.json` (`tunnelId`, `auth.type: none`; no URL or credential)
- `skills/styx-native-onboarding/SKILL.md`
- `skills/styx-cli/SKILL.md`
- `skills/styx-browser/SKILL.md`
- `skills/styx-computer-use/SKILL.md`
- `assets/icon.png` (the trusted embedded default PNG)

The output parent must be private; the suggested default creates one under
`~/Styx/plugin`. Existing files are never overwritten. On resume, a completed
export is compared with the exact allowlisted bytes and ZIP before it is skipped.
The Rust writer embeds its own current native onboarding skill under the same
allowlisted path; the reference template still contains retired JS commands and
is left unchanged outside this task. The other three skills and default icon
come from the existing plugin source. The writer uses deterministic stored ZIP members; an independent Python ZIP
reader test checks names, CRCs and byte equality. No archive dependency was added.

Setup prints the supported ChatGPT upload/import/install steps and the first
prompt **List my Styx computers**. It does not upload, install or claim account
acceptance. Waiting is optional and Ctrl-C stops waiting. The Gateway records only
a successful tunnel-forwarded MCP POST counter and last-seen Unix timestamp.
A per-process file-backed observation marker is supplied only in the signed
client's forwarding headers, not its discovery headers. Matching is diagnostic
and occurs after the existing bearer/path/protocol admission; it does not mint
owner/conversation authority. The original `X-Styx-Tunnel-Context` rejection is
unchanged. The marker is not configured for local CLI discovery. The reviewer
verified that the pinned client's `run --help` declares `--mcp.extra-headers` as
a repeatable stringArray: the observation header does not replace Authorization.
This closes that flag-semantics risk. Real account tool-call acceptance remains
a separate check. No request body, prompt, header value, account label or
conversation identifier is recorded.

## Interruption and resume

Run setup again with the same root (and the same answers file for automation).
Finished work is skipped using original native state and protected artifacts.
Role, payload selection, Host intent and network choices cannot silently change
after setup; use the existing explicit role-retirement flow for a new identity.
Public runtime-selection and enrollment reports are inputs/evidence, not grants.

| Interruption point | Resume behavior |
| --- | --- |
| Before input creation | No role exists; collect choices and ask again. |
| During payload verification | No identity is created. A failed verifier does not commit saved intent; a partial selection is refused. |
| After a valid selection | Reverify the same signed selection and original pin; do not move or replace the payload. |
| Workspace creation | Keep the existing folder; never chmod, delete or recreate it. |
| Gateway bootstrap | Inspect the existing native root; do not bootstrap over it. An incomplete/fenced root stops setup. |
| Tunnel prompt/configuration | Reuse a matching managed configuration. A started configuration without a completed observed result is fenced; inspect its original private inputs. |
| Gateway service install/start/enable | Query actual OS status and canonical revision; skip each already observed effect. The native actor fences unresolved transactions. |
| Foreground Gateway startup | Include starting the existing foreground root in the approved plan. Reconcile only its exactly committed C07 tip under the original writer. A setup start without completion, an uncommitted native tip or a mismatched service manager is refused. |
| Invitation publication | Reuse the published original link. A missing/uncertain original publication is not replaced with another invitation. |
| Join input publication | Reuse the protected deployment, CA and invitation; never silently overwrite partial inputs. |
| Host request | Inspect the original persisted enrollment prefix. Complete pending/ready prefixes are resumed; lost/partial replies stop without another request. |
| Exact approval | Keep its completion receipt; if the request disappeared without a known result, stop for reconciliation. |
| Awaiting remote approval | Each known 202 reply gets its own durable pending receipt. Only that receipt permits another claim poll; an unanswered dispatch is not replayed. |
| Claim/confirm | A validated ready prefix skips claim. Partial/uncertain claim/confirm stops; no replacement request is minted. |
| Host service handover | A PersistentService Host skips enrollment. The original public device ID is retained so another connected computer cannot satisfy the local wait. |
| Host install/start/enable | Query current OS effects/revision and skip installed/active/enabled steps independently. |
| Foreground Host startup | Reconcile the exactly committed C07 tip, reuse the claimed identity and running intent, then stop/join Host before Gateway on exit. Completed starts are not re-planned or re-paired. |
| Connection wait | Repeat read-only Gateway observations; never treat process startup as connected Exec/Browser. |
| Plugin export | Reuse saved presentation and verify all existing export bytes. Partial output is retained and is not overwritten. |
| ChatGPT wait | Use fresh tunnel-forwarding observations. Local discovery, ZIP creation and transport readiness are separate from account acceptance. |

Before a mutation, setup publishes an exclusive `.started` input fence; known
completion publishes a `.done` receipt. Service actions include the canonical
revision. Ctrl-C during a read-only connection/approval wait stops waiting and retains
progress; foreground roles are still joined. An interrupted in-flight mutation
is unknown. An unknown original outcome exits 4, retains original roots/files and
prints reconciliation instructions. It does not retry Join, approval, claim or
confirm based on a timeout. Known pending claim replies use append-only attempt
records so a crash cannot resurrect an older pending result by an unsynced delete.

## Validation checkpoint

Initial implementation checkpoint (before review round 2):

- **Product:** setup, invite, status, answers-file onboarding, plugin ZIP export and
  foreground test mode are implemented. Hub-side verification for joining
  computers is the accepted behavior above.
- **Architecture:** direct native actors retain validation and authority; there is
  no `styx` subprocess orchestration, JS management runtime, new dependency or new
  transitive crate. Thin libc OS adapters implement hostname/address/hidden input.
- **Integration:** eight Cargo jobs were used with the owned worktree `target/`
  cache and `--timings` on necessary builds/checks. Available memory stayed around
  16 GiB; no job reduction or cache cleaning was needed. Check/test results below
  distinguish compilation from effects.
- **Release:** no package was signed, installed or accepted, and no real profile or
  user service was changed. Stable remains NO-GO.
- **Reliability:** unknown-outcome fences, known-pending claim receipts, exact local
  device matching, private secret handling and export integrity checks were added.
- **Decision:** the confirmed order is Gateway start → Host request/approve/claim →
  Host service handover. Existing enrollment/service validation is unchanged.

The ignored Linux scenario uses a **real externally supplied signed payload** and
runs the rebuilt CLI with `--answers --foreground --exit-when-connected` twice.
It compares Host seed/ready and Gateway ready bytes, requires connected Exec on
both runs, and refuses evidence of a second invitation/request. It never installs
services. It creates `/tmp/sx-<8 hex>` exclusively with mode 0700 and retains the
private output/evidence files, including empty stderr files, for review.

Set all three inputs explicitly (the pin remains independently trusted):

```sh
export STYX_SETUP_TEST_PAYLOAD="$HOME/.local/share/styx/runtime-1efe544"
export STYX_SETUP_TEST_PUBLISHER="/absolute/path/to/dev-publisher.pem"
export STYX_SETUP_TEST_PIN="ORIGINAL_TRUSTED_PUBLISHER_FINGERPRINT"
cargo build -p styx --timings
cargo test -p styx-runtime --lib setup_hub_answers_foreground_connects_and_resumes_without_pairing_requires_sockets -- --ignored --nocapture
```

`STYX_SETUP_TEST_CLI` optionally selects another rebuilt CLI. Without any required
input, the explicit ignored run prints a clear `SKIP` message and returns before
creating a profile or binding a socket. It no longer generates a fake executor
payload. Loopback sockets are still required to execute the real journey.

## Review round 3 validation and changes

The reviewer accepted correctness after running the real signed-payload ignored
E2E through both first run and resume. The reviewer also ran a real PTY hub setup
with systemd user services: hub and computer services were active/enabled, Exec
and Browser were connected, and status was correct. The pre-polish transcript is
`/tmp/claude-1000/-home-sid-Developer-Styx/5de49ff3-9bdb-46ee-bfa1-0f2fafc9f1d2/scratchpad/setup-interactive.txt`.
Those accepted effects are separate from this round’s presentation checks.

- **Product:** network suggestions hide container bridges and label Wi-Fi or
  WireGuard when cheap OS metadata identifies them. Setup uses one numbered plan
  and approval, plain pairing text, inferred installed paths, short finish
  instructions, and human hints alongside common error codes. Status shows known
  disabled Browser/Computer Use as off and ChatGPT activity in local date/time
  with elapsed minutes. Local saved capability choices are display metadata;
  unknown remote settings are not guessed to be disabled.
- **Architecture:** the same direct native actors, validation, exact request
  selection and `.started`/completion fences remain. No wire contract, dependency
  or transitive crate was added. Local-time display uses existing OS bindings.
- **Integration:** the changed CLI was rebuilt with eight Cargo jobs and
  `--timings`. Real PTY prompt checks covered hub and join, installed-directory
  inference, one plan confirmation, and cancellation before any private state or
  pasted join link was written. Evidence is under
  `target/setup-round3-pty-506c23c2/{hub,join}.txt`. These checks used a
  prompt-only installed-layout fixture and declined the plan; no signature or
  connection acceptance is claimed from that fixture.
- **Release:** no owner installation or real user service was changed by this
  worker. Stable remains NO-GO pending its separate release gates.
- **Reliability:** the interactive plan grants no approval to `--answers`.
  Join trust/comparison remain fresh decisions. The accepted committed-tip
  reconciliation and unknown-outcome refusal are unchanged.
- **Decision:** reviewer first-run/resume and Linux service correctness are
  accepted. Real ChatGPT account/tool-call acceptance remains a separate gate.

The required checkpoint uses the supplied toolchain environment, eight jobs and
worktree `target/`:

```sh
cargo fmt --all -- --check && cargo check -p styx -p styx-runtime --all-targets && cargo test -p styx && bash src/tools/dev/cross-check.sh all
```

The required command passes: all 22 CLI unit tests and Linux/Windows/macOS
cross-checks succeeded. The runtime setup filter passes 10 tests with the live
journey ignored; explicitly invoking it prints the required missing-input skip
here. Eight jobs were retained with about 14 GiB available and no swap.

Additional focused coverage includes
`cargo test -p styx-runtime --lib setup`, the clean-stop regression,
container-interface suggestions, automated approval isolation, and status
formatting. Cross-checks are type checks, not native Windows/macOS acceptance.

## Updated hub transcript — expected

This is an **expected** successful Linux service transcript of the changed code,
using representative paths and interface metadata. The local sandbox PTY checks
above exercised the changed questions through plan cancellation; they did not
repeat the reviewer’s real service journey. The publisher fingerprint is not
inferred: the user supplies the public fingerprint from the release page.
Runtime discovery and hostnames vary by machine.

```text
Welcome to Styx. This setup connects only the computers and capabilities you approve.
1. Set up this computer as the hub (Styx Gateway)
2. Join an existing hub
Role [1]: 1
Styx checks that your installed files are authentic. You need the publisher public key file and the fingerprint from the download page / release notes.
Installed Styx files: /home/owner/.local/share/styx/runtime-1efe544
Publisher public PEM file [/home/owner/.local/share/styx/publisher-linux-dev.pem]:
Publisher fingerprint shown on the download page / release notes (colons and spaces optional): <fingerprint from the download page>
Hub HTTPS port [22022]: 22123
Choose the networks other computers will use to reach this one, e.g. your home Wi-Fi or a VPN. Select up to four; the default is none. Styx opens no router ports.
1. czy (WireGuard) 10.0.2.19
2. wlp4s0 (Wi-Fi) 10.118.53.220
Network numbers, separated by commas (empty for none): 2
ChatGPT connects with a Secure MCP Tunnel. Create a tunnel in your account using https://developers.openai.com/api/docs/guides/secure-mcp-tunnels . Styx hides your API key as you type and saves it privately.
Configure a tunnel now? Choose no to skip for now [y/N]: n
This computer's label [workstation]:
Choose a folder for commands and Browser Automation. Use a dedicated folder such as ~/Styx so Browser Automation can keep your private Styx files separate.
Workspace folder [/home/owner/Styx]:
Detected browser: /usr/bin/google-chrome-stable
Enable Browser Automation for this computer? [y/N]: y
Computer Use can observe and act on your desktop after the platform's permission checks. Enable it only for a desktop session you intend to share.
Enable Computer Use for this computer? [y/N]: n
Styx will do the following (completed steps will be kept):
1. Save your choices and connection details privately in /home/owner/.local/state/styx.
2. Check the signed Styx files in /home/owner/.local/share/styx/runtime-1efe544 against your publisher fingerprint.
3. Use /home/owner/Styx for commands and Browser Automation; create it privately if needed.
4. Set up the hub (Styx Gateway) on HTTPS port 22123 on this computer and 10.118.53.220.
5. Install, start and enable the hub as your systemd user service at login. No sudo or linger.
6. Pair this computer with its own hub using its exact local identity.
7. Enable commands for “workstation”; Browser Automation on; Computer Use off.
8. Install, start and enable this computer's connection as your systemd user service at login. No sudo or linger.
9. Wait for the hub to confirm this computer is connected.
10. Leave ChatGPT off for now and show how to connect it later.
Set up Styx now? [Y/n]: y
ChatGPT tunnel: skipped for now. Run styx setup again to configure it.
Pairing this computer with its own hub… done
Waiting for the hub to see this computer connected for commands and Browser Automation…
This computer connected (confirmed by the hub).
Setup complete. This hub and this computer's connection are running.
Commands: on · Browser Automation: on · Computer Use: off
Check Styx: styx status --root /home/owner/.local/state/styx
Add another computer: styx invite --root /home/owner/.local/state/styx
Connect ChatGPT later: styx setup --root /home/owner/.local/state/styx
```

If joining another computer, setup additionally shows the hub address and CA
fingerprint and asks to trust it. It shows that computer’s comparison code and
asks to continue only after checking it on the hub. The hub still approves that
exact request with the selected capabilities. A ChatGPT-enabled plan includes
its tunnel key storage and the plugin output path; after export, waiting for the
first ChatGPT request is optional.
