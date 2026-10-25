# Foreground Browser transition bootstrap

The paired foreground Host can optionally reuse the existing, publisher-verified
legacy release's Node and Browser dependency closure. It does not run the legacy
JS Host, rewrite a signed member, introduce Browser workers into the
`configuration_preview` release format, or change pairing/publisher authority.
The new thin worker/config are fixed `include_bytes!` assets of the Rust image.

The original protected deployment and Host profile must both explicitly select
Browser, headless mode and `persistLogin: false`. Their explicit executable path
and optional channel must agree; the Host profile root must equal the original
`base/browser`. Missing/disabled selection leaves Exec available. On Linux,
unsupported Browser choices, including channel-only executable discovery, are separately
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

## Windows managed headless integration (native acceptance pending)

The Windows adapter reuses this same Core owner/permit/reference/operation path.
It accepts the publisher-verified native C08 Node 22 worker closure and the same
fixed Playwright dependency versions. The existing native App requires an explicit
Chrome or Edge selection; fixed OS Program Files locations are inspected, not PATH,
registry commands or arbitrary running browser profiles. Multiple installations
without one explicit usable target are unavailable rather than silently selected.

Each owner receives private workspace, profile and output sibling directories.
The Exec working directory remains unchanged: it is not automatically a Browser
file root, especially when the user's home contains Styx credentials. Windows
uses exclusive private asset files and fixed imports into the retained verified
closure instead of symlink/junction setup or privileged filesystem changes.

The original verified Node PE is created suspended with fixed worker/config
arguments, put in the existing non-breakaway kill-on-close Job, revalidated and
only then resumed. The Job limits are 2 GiB total memory and 256 active processes;
this process count is not equivalent to Linux's task/thread count. A root-exit
observation stops admission but is not cleanup: cleanup requires original root
wait and Job ActiveProcesses zero. Unknown input results are never replayed.

The selected browser executable has a separate local-system trust policy. Its
owner/ACL/image identity and exact bytes are retained; ordinary user read/execute
permissions are allowed, unauthorized mutation is not. The publisher is not said
to have signed the system browser or its vendor DLL closure. Retained no-write/
no-delete-share handles can prevent an updater replacing that browser executable
while this Host owns the Browser configuration; automatic update continuity has
not been verified. No global permissions are repaired.

Implementation and Linux regression do not prove native Windows Browser behavior.
Acceptance requires native compilation, an independent HTTP effect oracle, stale
and foreign-owner refusal, original Node/Job cleanup, and Exec continuity using
the exact candidate. Headed/attach modes, persistent login, Mac Browser and full
installed-product lifecycle remain separate outstanding work.
