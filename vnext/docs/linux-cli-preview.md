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
node host/build-linux-cli.mjs /absolute/private/build.json
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
- Desktop Computer Use: optional on Arch graphical sessions. `linux-session`
  only reports observed session suitability, never claims Cua acceptance. A
  headless user must leave `computer:false`.

Start with `./styx create PRIVATE_INPUT STATE`, `plan STATE`, `status STATE`.
`advance STATE STEP...` requires naming the exact planned steps. For interactive
foreground runtime use `foreground STATE --authorize`; keep its terminal open.
Persistent user-service control uses existing `gateway-service`/`host-service`
commands, explicit authorization and recorded preparation. It is separate from
package extraction and foreground execution. Run `help` for exact commands.

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
Host bundle blocks Host setup; lack of a tunnel binary blocks that connector,
but does not block local Gateway-only or headless CLI use.

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

The input contains only `directory` (fresh evidence output) and `distribution`
(existing portable preview). The runner creates private disposable deployment
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
