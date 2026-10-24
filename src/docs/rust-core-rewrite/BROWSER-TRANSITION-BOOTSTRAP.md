# Foreground Browser transition bootstrap

The paired foreground Host can optionally reuse the existing, publisher-verified
legacy release's Node and Browser dependency closure. It does not run the legacy
JS Host, rewrite a signed member, introduce Browser workers into the
`configuration_preview` release format, or change pairing/publisher authority.
The new thin worker/config are fixed `include_bytes!` assets of the Rust image.

The original protected deployment and Host profile must both explicitly select
Browser, headless mode and `persistLogin: false`. Their explicit executable path
and optional channel must agree; the Host profile root must equal the original
`base/browser`. Missing/disabled selection leaves Exec available. Unsupported
Browser choices, including channel-only executable discovery, are separately
unavailable rather than enabling a fallback. This slice accepts Node 22 metadata
from the signed manifest and exactly MCP 0.0.83, Playwright/core
1.64.0-alpha-1790635538000 and JS MCP SDK 1.32.1 package versions from the verified
inventory. Local Chrome/Edge bytes are explicitly configured and pinned; the
legacy publisher is not claimed to have signed that system executable.

Preparation creates only fresh 0700 runtime directories below the protected Host
base. It never adopts the previous Browser login profile. Worker/config are 0600,
and the only intentional dependency link points exactly to the retained verified
release closure. Each opaque original Core OwnerLease receives distinct fresh
profile/output directories. Equality includes the lease incarnation; a reused
OwnerId cannot adopt a prior profile. At most 16 owner bindings are retained for
one Host lifetime, without eviction. Ordinary workspaces cannot contain or lie
inside the private Host base. No path or credential is accepted from a WSS tool.

The factory retains the original profile, publisher-verified inventory, signed
Node pin, staged asset identities and local browser image observation. Full
release validation happens before preparation/spawn. Existing control validates
the original protected raw input observations, executable pins, local browser
bytes, exact staged bytes/link and all private directory identities, without
rehashing the entire dependency tree for every action. All filesystem work runs
on bounded blocking workers. The foreground wrapper also validates the held
original execution lease and original-owner refusals before delegating.

Core and the Host coordinator remain the only admission/operation authority.
The factory neither constructs availability/permission facts nor selects a
remote grant. Missing inputs do not trigger install/download/global environment
changes. Assets and input owners stay alive until actual Host/provider cleanup;
Drop does not delete staged files. This preserves explicit failure evidence and
avoids deleting assets still used by a child. Cleanup of old runtime directories
is not implemented by this slice. Compilation and the ordinary-CLI native
Browser scenario remain separate acceptance evidence.
