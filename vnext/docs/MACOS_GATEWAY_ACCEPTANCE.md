# Native Mac Gateway acceptance

The native pilot passed the actual path: official MCP SDK → private loopback
HTTPS Gateway → outbound WSS Host → installed `/Applications/Styx.app` embedded
Cua. The same Gateway executed the native Codex marker, launched a uniquely
owned AppKit fixture, observed its screenshot and six AX elements, clicked the
observed button, and independently read its PID/title-bound result through
native Exec. The fixture exited0. No screenshot bytes were retained.

This is SDK integration evidence, not a ChatGPT connector invocation. No Charon
plugin, endpoint, runtime or service was used. Production endpoints, tunnels,
installed app signatures and TCC settings were untouched. The test did not
install a Host service or establish external notarized distribution acceptance.
Actual runtime versions/digests and provenance limits are in
`evidence/macos-gateway-20261019.json`: native Homebrew Node25.6.1 runner,
official Codex0.163.0, and installed locally signed Cua0.36.0. The production
Node22.23.3 pin remains unchanged; this pilot does not claim a signed packaged
Node22 launch.

The first functional run passed but needed a verified owned Host SIGTERM to
release a test-harness shutdown ordering deadlock. The corrected run stopped
its Host before closing HTTP and completed autonomously. Final independent
inspection found zero pilot Host/fixture/driver processes and no private
credentials directory. Only public source/fixture/runtime material and
sanitized receipts remain. The existing installed Styx app is intentionally
retained and running with both grants true.

## Reproduce this scoped snapshot

This is an opt-in native developer harness, not the product onboarding command.
It takes an existing fresh private marked scratch root containing the checked
source snapshot, installed npm dependencies under `vnext/node_modules`, and a
compiled `OwnedGuiFixture`. The directory must be owned by the caller, mode0700,
with `.styx-local-owner.json` containing kind
`styx-local-development-app-pilot` and the actual source revision. The fixture
uses the documented `STYX_OWNED_GUI_` title prefix and only writes beneath
`/private/tmp/styx-local-dev-…`.

Before the run, the installed Styx app must already be signed, launched and
manually granted Accessibility and Screen Recording. The harness checks its
exact process path and prompt-disabled host grant readback. It never requests
permissions or starts a replacement Cua daemon. This snapshot expects the
checksum-verified official Codex0.163.0 binary at
`/private/tmp/styx-local-dev-20261019-0743bc4c/runtimes/codex/codex`; its digest
is validated before use. That public runtime cache is a documented prerequisite,
not a credential or hidden chat state. To prepare a different clean machine,
use `host/prepare-codex.py --output` for this path only when absent/empty; never
overwrite another installation. This fixed pilot path is not a product default.

On the Mac, with a fresh scratch root and current source, compile the test-only
fixture using `xcrun swiftc -warnings-as-errors` with the AppKit framework, then:

```sh
STYX_MAC_GATEWAY_ACCEPTANCE=1 /opt/homebrew/bin/node \
  "$PILOT_ROOT/vnext/host/macos/gateway-acceptance.mjs" "$PILOT_ROOT"
```

`PILOT_ROOT` is the absolute marked scratch directory. The harness refuses a
pre-existing `gateway-private` directory. Every run generates fresh independent
model/Host bearer credentials and a2day test CA, binds an ephemeral loopback port,
and passes Host config over stdin. Trust is per SDK/Host connection only; no
system trust settings or credentials from this chat are required. The final
receipt is `gateway-acceptance.json` outside the removed private directory.
A cleanup failure retains private state rather than reporting success. Existing
Styx app permissions and source-independent user state remain untouched.
