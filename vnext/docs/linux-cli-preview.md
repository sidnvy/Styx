# Linux CLI preview

This portable Arch/headless Linux x64 preview runs the existing onboarding CLI
and Core. It does not install an App, create an identity at build time, enable
linger, or install a service merely by unpacking. Use an independent private
directory; keep all deployment state outside the distribution directory.

## Offline publisher build

Prepare production dependencies from the checked-in locks without lifecycle
scripts. Prepare Node with `host/prepare-node.py`; the CLI builder requires its
22.23.3 Linux x64 provenance, official archive checksum, binary hash and license.
Build an optional Host bundle with `buildHostRelease` using the same publisher
key and actual pinned Codex/Cua binaries. Then run:

```sh
npm run build:checked -- linux /absolute/private/build.json /absolute/fresh/build-evidence
```

The private build file contains `destination`, `version`, `privateKeyFile`,
`nodeBinary`, and optional `sourceRoot`, `dependenciesRoot`, `hostBundle`.
The builder emits the public publisher key, independent signed Gateway runtime,
tracked product sources, locked Gateway dependencies, Node notices and receipt.
It never copies the publisher private key or mutable deployment files. Optional
Host input is signature-verified against the same publisher before copying.

The top-level shell launcher is `./styx`. No npm install or global Node is
required on the target. A test-generated publisher key means **development
preview**, not official release trust. The portable CLI wrapper itself is not a
signed public release/update format; distribute it only through an independently
verified preview artifact hash. Core still verifies each runtime signature.

## Role configuration

Use the existing `deployment.json` input schema; no extra role file is added.
All paths below must be absolute and normalized, parent directories private.

- Gateway-only: `mode: create-local`, `gateway.runtime` points to included
  `gateway-bundle`, public `publisher.pem`, the receipt `publisherSha256`, and a
  fresh private runtime `baseDir`; omit `host`. Supply an existing trusted regular
  OpenSSL executable and a free loopback HTTPS port ≥1024.
- Host-only: `mode: join-existing`, verified Gateway HTTPS URL and optional CA;
  `host` points to the included optional signed Host bundle, same public key/pin,
  private `baseDir`, label and `computer:false`. Pair through existing explicit
  invitation/identity confirmation. Join never prepares another Gateway.
- Combined: `create-local` with both configurations and disjoint runtime roots.
  Owner-local pairing still requires scoped explicit authorization.
- Browser: select `host.browser:{enabled:true,headless:true,channel:"chrome",
  persistLogin:true}` (or `msedge`). Installed Chrome/Edge is required; no daily
  browser profile is attached. `./styx browser-select STATE chrome --authorize`
  changes an existing prepared deployment through the same Core transaction.
- Computer Use: the first Linux desktop target is **Arch with Hyprland**.
  Select `host.computer:true` when creating a desktop Host. An existing combined
  deployment can use `./styx capabilities STATE computer-on --authorize`.
  Keep `computer:false` for an intentionally headless-only Host. If Computer Use
  is selected but no eligible graphical session exists, only the Computer lane
  stays unavailable; Gateway, Exec and optional headless Browser continue.
  `linux-session` observes the session; it does not enable Computer Use or prove
  that observation/input work.

Start with `./styx create PRIVATE_INPUT STATE`, `plan STATE`, `status STATE`.
`advance STATE STEP...` requires naming the exact planned steps. For interactive
foreground runtime use `foreground STATE --authorize`; keep its terminal open.
Persistent user-service control uses existing `gateway-service`/`host-service`
commands, explicit authorization and recorded preparation. It is separate from
package extraction and foreground execution. Run `help` for exact commands.

## Hyprland Computer Use

Use the signed Host bundle containing the pinned Cua driver, then the same
`create` → `plan` → preparation/pairing → `foreground` flow as other Hosts.
The existing identity and pairing are reused; no Linux desktop App is required.
Host-only devices choose `computer:true` in their own input before joining and
confirm the current invitation/identity through the existing join flow.

Run `./styx linux-session` first. An eligible session is the owning user's local,
active, unlocked Wayland login with a private runtime directory and owned
display socket. The CLI/Host can recover the GUI environment from the user's
systemd manager; a stale `WAYLAND_DISPLAY` alone is not sufficient. Hyprland
must publish its current environment to that manager for service-based use.
Styx does not change the compositor, enable linger, or modify system permissions.

Logout, lock or loss of that session stops only Computer Use. A later eligible
session reconnects with the same identity; it does not replay previous actions.
Lock observation relies on logind's `LockedHint`. A session observation or
connected transport is not a completed native acceptance test.

For source/native acceptance, `host/run-native-cua.mjs` reuses that same session
probe and requires executable pinned Codex/Cua binaries plus Zenity. Its owned
scratch dialog verifies window discovery, screenshot, accessibility elements,
button click and independent successful process exit through Gateway MCP and
Host. The dialog and its temporary Host/Gateway are cleaned up afterward.
This does not certify other compositors, lock/logout/reboot behavior, or a
ChatGPT account connection.

## First local run: headless Gateway-only

After checking the separately supplied archive SHA-256, unpack into a private
versioned directory. Set `STYX_DIST` to that absolute directory. This sequence
uses a new state directory and port 18443; choose another free loopback port if
needed. OpenSSL must already be installed. Package extraction does not start a
service, and a Gateway-only installation does not install Exec or Cua.

```sh
umask 077
STYX_DIST=/absolute/Styx-VERSION-linux-x64
STYX_TEST=$(mktemp -d "$HOME/styx-first-run.XXXXXX")
"$STYX_DIST/runtime/node" --input-type=module - "$STYX_DIST" "$STYX_TEST" <<'JS'
import fs from 'node:fs';
import path from 'node:path';
const [dist, root] = process.argv.slice(2);
const build = JSON.parse(fs.readFileSync(path.join(dist, 'build-receipt.json')));
const config = {schema: 1, mode: 'create-local', gateway: {
  url: 'https://127.0.0.1:18443', openssl: '/usr/bin/openssl', runtime: {
    bundle: path.join(dist, 'gateway-bundle'),
    publisherKeyFile: path.join(dist, 'publisher.pem'),
    publisherSha256: build.publisherSha256,
    baseDir: path.join(root, 'gateway-runtime')
  }
}};
fs.writeFileSync(path.join(root, 'input.json'), JSON.stringify(config), {mode: 0o600});
JS
"$STYX_DIST/styx" create "$STYX_TEST/input.json" "$STYX_TEST/state"
"$STYX_DIST/styx" plan "$STYX_TEST/state"
"$STYX_DIST/styx" advance "$STYX_TEST/state" gateway.runtime.prepare gateway.prepare
"$STYX_DIST/styx" foreground "$STYX_TEST/state" --authorize
```

The last command stays open and prints `Styx foreground connection started`
after authenticated local Gateway verification. It should not open a browser or
request desktop permission. In another terminal use the same absolute paths:

```sh
/absolute/Styx-VERSION-linux-x64/styx foreground-status /absolute/styx-first-run.XXXXXX/state
/absolute/Styx-VERSION-linux-x64/styx status /absolute/styx-first-run.XXXXXX/state
```

Expect Gateway running, Host/Exec/Computer/Browser disabled, and account
acceptance `NOT RUN`. Press Ctrl-C in the first terminal to stop its owned
Gateway; starting the same foreground command again reuses the same state and
identity. Keep the state directory for later pairing; never put it inside the
versioned distribution. A server without a user systemd manager can use this
foreground mode under its administrator's process supervisor. Boot-before-login
persistence is not configured by this recipe.

## Foreground Secure MCP Tunnel

The CLI uses the same `configureTunnel` and `TunnelRuntime` as the App.
A distribution can include the official Linux `tunnel-client` with public release
notices and `runtime/tunnel-client.json`, which records its version and verified
binary SHA-256. Official runtime client 0.0.17 has passed local `--version` and
`run --help` contract checks; those checks do not connect an OpenAI account.
Ordinary users of that distribution do not enter an executable path or hash.
The CLI never downloads or substitutes a missing client.

First finish the existing create-local Gateway preparation and keep its owned
loopback HTTPS Gateway running. For a combined headless installation, leave
`computer:false` and select Browser separately if wanted. `tunnel-run` neither
starts Cua nor changes any role or capability. A Host-only joined deployment
uses its Gateway owner's connection and does not create a second account entry.

In the intended OpenAI organization, the user creates/selects a Secure MCP
Tunnel, associates it with the target ChatGPT workspace, and obtains its runtime
key. Official steps and permission names are documented in
[Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).
Enter the ID and key locally in an owner-private JSON file, inside an
owner-private directory (POSIX directory mode 0700 and file mode 0600):

```json
{
  "tunnelId": "<the actual tunnel ID>",
  "apiKey": "<runtime key entered locally>",
  "autoStart": false
}
```

The only accepted fields are `tunnelId`, `apiKey`, and optional `autoStart`.
The initial configuration needs its runtime key. A later configuration may omit
`apiKey` to retain the existing server-owned key. `autoStart` is the existing
App resume preference; it does not install a service or make CLI observation
start a process. Configure explicitly:

```sh
./styx tunnel-configure /absolute/private/STATE /absolute/private/connection.json --authorize
./styx tunnel-status /absolute/private/STATE
```

The key is stored by the existing private Tunnel configuration; it is absent
from command arguments and command results. Do not paste it into the ChatGPT
conversation, plugin ZIP, or a shell command. The connection file is not a
plugin package or a replacement Gateway role/configuration file.

Use the existing `./styx foreground /absolute/private/STATE --authorize` in one
terminal to keep the prepared Gateway/selected Host alive. In another terminal:

```sh
./styx tunnel-run /absolute/private/STATE --authorize
```

The default client and manifest are resolved only from the installed
`app/onboarding` module's fixed `../../runtime/` directory. The manifest must
have schema 1 and the exact basename `tunnel-client`; runtime directory,
manifest, and executable symlinks are rejected. The executable must match the
manifest's SHA-256 and be executable. Missing material returns
`packaged_tunnel_client_unavailable`; invalid material returns
`packaged_tunnel_client_invalid`. Neither case searches the environment, CWD,
or another installation.

Advanced operator-supplied client: if a preview omits the bundled client, an
operator may use a separately verified official release. Put only `binary`
(its absolute executable path) and `sha256` (its independently verified 64
lowercase hex pin) in a private `client.json`, then run
`./styx tunnel-run /absolute/private/STATE /absolute/private/client.json --authorize`.
This explicit override does not download a client. A self-computed hash alone
is not publisher verification.

Keep that terminal open. SIGINT/Ctrl-C and SIGTERM stop only this invocation's
owned runtime/supervisor. The runtime can reconnect its transport after an
unexpected client exit using its existing policy; it never replays an MCP call.
A startup failure cancels this invocation's recovery before returning an error.
The executable pin is rechecked by the runtime and its supervisor. No persisted
PID is adopted or killed; no user/system service, login task, or download is
performed. Systemd persistence is an explicit `tunnel-service` operation described below;
it is not an effect of `autoStart` or package extraction.

`tunnel-status` is read-only. `packagedClient.available` reports only local
manifest/executable integrity; it does not start or execute the client.
`configured` proves saved configuration only;
`owner_unobserved` means an owner lock exists but this CLI process has not
observed its owner. It does not mean that owner is dead or that the transport
is active. Do not remove the lock or launch another client to bypass it.
Transport readiness and ChatGPT account acceptance remain `not_observed` /
`NOT RUN` in this standalone status output.

In the target ChatGPT account/workspace, the user opens Plugins, chooses
**Add custom MCP server → Tunnel**, selects the same tunnel, chooses
**No authentication** for this App/CLI-owned forwarding path, creates the
plugin, and installs it. The local runtime supplies the Gateway model Bearer;
the runtime key stays in Styx. These are the documented
[custom MCP connection steps](https://developers.openai.com/plugins/deploy/connect-chatgpt),
separate from ZIP export or public plugin submission.

For the existing combined Gateway+Host acceptance flow, run
`./styx acceptance-begin /absolute/private/STATE --authorize`, copy its current
challenge prompt to a new target chat with the installed plugin selected, and
inspect `./styx acceptance /absolute/private/STATE` after the real tool calls.
Only after seeing the results in that target chat should the user provide the
current `challengeId` and `observedInTargetChat:true` in a private approval JSON
and run `./styx acceptance-confirm STATE PRIVATE_APPROVAL_JSON --authorize`.
Local Tunnel startup, fixture tests, and ZIP generation do not establish those
account-side results. A Gateway-only deployment has no local Host challenge;
verify its selected enrolled Host separately.

## Repeatable acceptance, without production mutation

Use a fresh private test root and an available loopback port. Record artifact
hash, publisher pin, process ownership, config roles and account acceptance.

1. Invoke the packaged launcher for help/create/plan/status. Verify Gateway-only
   has disabled Host/Exec/Computer/Browser roles and no Host steps; join has no
   Gateway steps. Compare CLI status with the same Core projection.
2. Advance Gateway-only runtime.prepare/prepare/start/verify in one owner process.
   The verification makes actual authenticated MCP TLS calls. Check the staged
   signed manifest has no Exec or Cua executables and no Host device config.
3. Stop/start using that owner and verify again. Compare all identity, TLS, bearer
   and registry bytes before/after; don't regenerate them to obtain a pass.
4. For optional Host bundles, explicitly pair and test actual Exec command/exit,
   installed-browser page operation and independent login state using only a
   synthetic local test website. Do not claim these from unit fixtures.
5. Only with separate authorization install temporary user services, exercise
   owned-process crash/recovery, then stop/uninstall exactly those generated
   units. Preserve unrelated units and global user-manager/linger settings.

Log each actual result separately from simulated error cases. Real logout,
reboot, lock-screen recovery, remote pairing and ChatGPT account invocation
remain separate native/manual acceptance gates. Failure to include a signed
Host bundle blocks Host setup. The Tunnel connector requires either the
bundled official client or the explicit operator-supplied verified client
described above; its absence does not block local Gateway-only or headless CLI
use.

## Native Host and Browser acceptance runner

`host/linux-cli-acceptance.mjs` is opt-in, outside ordinary test execution. It
requires a preview distribution containing both signed runtimes, installed
Chrome, OpenSSL, and an owning user without a conflicting `styx-host.service`.
It never installs or stops that global unit. If the real Core service observer
refuses the environment, inspect the blocker; do not replace it with a mock.

Run on an explicitly authorized native Linux x64 test host:

```sh
STYX_RUN_LINUX_CLI_ACCEPTANCE=1 node host/linux-cli-acceptance.mjs /absolute/public-test-paths.json
```

The input contains `directory` (fresh evidence output), `distribution`
(existing portable preview), `listenHost` (one exact non-loopback IPv4 of the
authorized test machine), and `authorizeExactInterface:true`. The additional
TLS listener exercises invitation reachability on that selected interface; it
does not modify the firewall. The runner creates private disposable deployment
state, actual TLS Gateway, actual signed Host installation, scoped owner-local
pairing approval and doctor. It then uses Core foreground lifecycle, genuine
Codex Exec and installed Chrome through TLS MCP. A synthetic loopback site
provides independent click readback and test-only login storage. It tests Host
stop/reconnect without identity recreation, then imports a real one-use invite
into a second independent Core deployment and approves its exact fingerprint.
The second Host executes and browses through the first Gateway without creating
another Gateway. Both devices in this scenario run on one physical Linux
computer; it does not prove cross-machine routing or firewall behavior.

The receipt separates each real gate, account boundaries and cleanup. Only
owned child processes and disposable state are involved. A failed cleanup keeps
state for reconciliation instead of reporting success. `CODEX_HOME` and browser
profiles are isolated; no production credentials or daily profiles are read.


## Explicit Linux user-service Tunnel lifecycle

A distribution containing the packaged Tunnel client can run the same owner in
its current user's systemd manager. Finish `tunnel-configure` first and keep the
prepared Gateway running through its own authorized lifecycle. Then use:

```sh
./styx tunnel-service /absolute/private/STATE install --authorize
./styx tunnel-service /absolute/private/STATE status
./styx tunnel-service /absolute/private/STATE start --authorize
./styx tunnel-service /absolute/private/STATE stop --authorize
./styx tunnel-service /absolute/private/STATE uninstall --authorize
```

`install` writes only the exact owned unit definition and reloads the user
manager. It does not start or enable the service. `start` explicitly enables the
unit for the user session and starts it; `stop` disables it and confirms it is
inactive. `uninstall` disables/stops its exact unit, confirms it is inactive,
and removes that definition. Deployment state, runtime keys and browser
profiles remain. No command invokes sudo, changes linger, changes a firewall,
or installs a system service. **Boot without user login: NOT CONFIGURED.**

The unit name is derived from the absolute state-directory hash. Its command
uses only the actual installed module's fixed `runtime/node` and
`app/onboarding/cli.mjs tunnel-run STATE --authorize`. Node must match its
packaged provenance hash; `packagedCliTunnelClient()` verifies the packaged
client pin. The operator-only private client override cannot be selected by
this service. Package paths containing executable-path characters systemd
rejects (such as quotes, backslashes or wildcards) are refused before install.
An altered/non-owned unit or a conflicting manager definition is
refused; an existing definition is never silently replaced. Stop/uninstall can
still stop the owned unit when package material needs repair.

Status is read-only and creates no state or user-unit directories. It reports
systemd `ActiveState`, `MainPID` and enablement separately. An enabled unit is
not evidence of an active process. Even a running service does not establish
Tunnel cloud readiness, plugin installation or target ChatGPT account
acceptance; those remain `not_observed` / `NOT RUN`. Do not run a simultaneous
foreground Tunnel for this state. An unobserved existing Tunnel owner lock
blocks a fresh service start and is retained for inspection.

This first lifecycle module has no durable operation journal. A partial
systemctl failure returns `needs_reconciliation` and retains the owned unit
when possible; an uninstall reload failure attempts an exclusive restoration
without overwriting another file. Inspect `status` and the exact unit before
retrying. A process/power interruption is not automatically adopted or replayed.
Unit-contract tests use a fake user home and command runner and are **not native
systemd acceptance**. Real user-manager startup, stop, logout/login recovery,
network reconnect and account-side behavior require separate native evidence.
The portable preview's external artifact-verification boundary still applies;
a generated unit is not a new distribution signature.
