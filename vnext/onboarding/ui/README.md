# Local browser setup UI

This is a working local browser control plane over `onboarding/core.mjs`, not a
shipped native graphical installer. It supports editable create-local or
join-existing configuration, terminal/desktop capability selection, explicit
one-step authorization, persisted progress/resume, manual account prerequisites,
fixed Host doctor checks, and start/stop of the current process-owned Gateway.
Startup preference is saved only in browser local storage; no system service is
installed. The actual Gateway runtime is shown separately from successful
journal entries. `uncertain` steps are never offered an automatic retry.

Run with the project's supported Node runtime and the core module installed:

```sh
node vnext/onboarding/server.mjs --state /absolute/private-parent/new-deployment
```

The parent must already be private to the current user, as checked by the core.
Use a new deployment directory initially; reopening the same directory resumes
its persisted journal. The terminal prints a private local URL. Open that full
URL in a trusted browser. Its random fragment is removed from history after
bootstrap and the session is kept in that tab's session storage. Do not share
the URL. A server restart creates a new session, requiring the new URL. No
credentials from a previous chat are needed or used.

The listener always binds `127.0.0.1`. Every API request requires its random
bearer; mutations additionally require exact Origin and a separate CSRF value.
Host names are pinned, no CORS is enabled, static paths are an explicit allowlist,
and config requests cannot choose executable helpers or arbitrary commands.
The UI never serves stored config, invitations, account credentials or raw core
exceptions. Only recognized progress states, actual local Gateway state, bounded
error codes and the public device fingerprint/approval requirement are projected.

Local Gateway creation requires a trusted OpenSSL executable configured by the
local launcher, never selected by the browser. macOS/Linux default to
`/usr/bin/openssl`. Where that path is absent or a symlink, configure a trusted
regular executable using `STYX_ONBOARDING_OPENSSL`; the core checks it before
use. Windows requires this explicit helper configuration for create-local.
Join-existing can use a trusted administrator's Gateway and a local invitation
file; the UI does not accept pasted invitation secrets. Software bundle/public
key paths and the trusted public-key fingerprint remain explicit local inputs.
This interface does not download unverified bundles.

## Headless host with explicit trusted forwarding

Keep the setup listener private and use a trusted SSH/local forwarding channel.
For example, reserve port17895 on the host, forward that port to localhost17895
on the browser machine, and start with:

```sh
STYX_ONBOARDING_PORT=17895 \
STYX_ONBOARDING_BROWSER_ORIGIN=http://localhost:17895 \
node vnext/onboarding/server.mjs --state /absolute/private-parent/new-deployment
```

The printed URL uses the explicitly configured browser origin. Only loopback
HTTP browser origins are accepted; binding remains127.0.0.1. The user configures
the authenticated SSH tunnel separately. Never expose this admin listener on a
LAN/public address, use an untrusted reverse proxy, or forward to a shared
browser. Windows can set the same environment variables in its local shell.
No tunnel is created automatically.

## Verification

`node --test vnext/onboarding/ui/server.test.mjs` checks unauthenticated routes,
Host/Origin/CSRF boundaries, executable/command refusal, redacted state, trusted
forwarding, mutation serialization and supported local start/pause dispatch.
`ui/browser.test.mjs` is opt-in and requires a trusted Chrome/Chromium binary:

```sh
STYX_ONBOARDING_BROWSER_TEST=1 \
STYX_ONBOARDING_BROWSER_BINARY=/absolute/path/to/chrome \
node --test vnext/onboarding/ui/browser.test.mjs
```

The browser test uses a fresh isolated profile, real core, private TLS Gateway,
and explicit UI interactions. It checks save → prepare → actual running → stop →
reload/resume, then cleans only its own temporary state/browser/Gateway. It never
prepares or enrolls a Host. An alternate absolute `STYX_ONBOARDING_CORE_MODULE`
may point to a separately checked-out core during development. The observed run
was on Linux; native Windows/macOS graphical wrapper acceptance is NOT RUN.
ChatGPT connection/account acceptance, native installers and system service
installation are NOT RUN by these tests. Initial security-test failures in test
mock cleanup and a fetch-normalized Host-header test were corrected; final HTTP
suite passes. Desktop/mobile layout were rendered with isolated headless Chrome.
