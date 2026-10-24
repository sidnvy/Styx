# ADR-008 · Browser ownership through the existing Host and Core

Status: implementation in progress; not R19 completion or native release acceptance.

Rust owns the Browser operation, authorization, profile selection and lifecycle.
The existing Host state mutex contains the same Core operation ledger, Browser
facts and configured profile bindings. Browser does not get another owner ledger,
configuration writer or authority from Desktop readiness. Headless has Browser
scope and no desktop session/observation. A Browser context is never accepted on
an Exec path, or an Exec context on a Browser path. Native desktop and Browser
availability remain independent.

The provider consumes the Core linear DispatchPermit only after synchronous
capacity admission. Existing IDs return their original state, never native replay.
All result delivery rechecks current owner/grant policy. Sensitive payloads are not
put in cleanup audit. Exact owner incarnations bind profiles and opaque handles;
shared ordinary workspaces are permitted, but one workspace may not contain another
owner's private profile/output, in either registration order.

The first implementation uses one active headless resource, at most16 configured
profiles and128 retained provider records. One16MiB Browser I/O partition is reserved
from the existing64MiB Host allocator. These are separate limits: neither the I/O
partition nor the SDK256KiB incoming buffer bounds Node/Chromium heap or outgoing
JSON allocation. No live context is silently evicted to admit a new owner.

The external Node process is a thin, pinned Playwright backend. Its adjacent locked
closure contains the official MCP JS SDK1.32.1, Playwright MCP0.0.83 and Playwright
1.64.0-alpha-1790635538000. It gets only private directories, an executable and
stdio. It owns no Gateway credential, enrollment, grant, durable state or retry
policy. The official Rust rmcp3.7 client uses call_tool_once: the convenience MRTR
loop is inappropriate for potentially mutating native calls. InputRequired and
uncertain SDK errors retain Unknown. There is no automatic relaunch/reconnection.

The initial action surface is Navigate, Evaluate and Close. The worker may list
upstream tools, but the Rust adapter does not thereby admit arbitrary tools. DOM
refs, snapshots, downloads/uploads, headed mode, login continuity and public routing
still need their own existing-contract implementation. Explicit attach remains
unsupported; a running desktop Chrome is not silently adopted.

Linux uses the mature systemd transient user-service mechanism for the Node and
Chromium process tree. Chromium can detach its own process group, so Node-PGID kill
cannot prove descendant cleanup. A random unit name, Restart=no, KillMode=control-group
and Delegate=no preserve one owned invocation without a persistent new service.
The same-UID manager's unique identity, kernel PID/birth, original InvocationID and
opened cgroup kernel directory are checked; cleanup never switches to a new unit,
PID-name lookup or arbitrary cgroup path. StopUnit has no server-side InvocationID
CAS. This is an owned lifecycle boundary within a trusted local user account,
not a sandbox against a compromised process running as that same UID.

The worker factory uses a2GiB aggregate cgroup memory cap, zero swap,256 tasks
(including threads) and disabled core dumps. The original cgroup must expose the
actual matching kernel controls before first native dispatch; unsupported or
unavailable controls fail closed. These are initial development resource budgets,
not a final browser performance/SLA conclusion or a Host RSS limit. They apply only
to the owned transient unit. No user slice, existing service, root privilege or
machine configuration is changed to enable them. The target environment is cleared
with env -i even though the launcher environment was already cleared; a user
manager's environment is a different inheritance source. HOME points to the private owned output directory. TMPDIR uses a
short0700 systemd RuntimeDirectory bound to the same random unit; the first actual
Chrome navigation failed with its original long output path because Chromium
SingletonSocket exceeded the Unix socket path limit. The failure and clean
process/cgroup exit receipts remain preserved. RuntimeDirectory uses the invoking
user runtime root, not root privileges or an existing service. Full signed runtime/provenance/bootstrap
integration remains required; open file pins do not freeze arbitrary adjacent
module or shared-library directories against a compromised same UID.

Close has three distinct facts: upstream tool ACK, exact persistent context.close,
and native process/stdio/cgroup settlement. None substitutes for the others.
MCP initialize/list success proves worker transport readiness, not Chrome readiness:
Playwright lazily creates the context on the first native call. Cleanup is one
owned future retained across observer cancellation/deadline; permits, pinned files
and the original Child remain until actual wait and I/O settlement. A timeout
reports Unknown and poisons the resource rather than replaying an input action.

Physical retirement reuses Core ProviderReleasePermit/Confirmation. Known action
correlation can transfer to bounded Core audit; uncertain actions require an exact
ended/drained parent bundle and real execution quiescence. A missing provider tuple
never implies NotDispatched. Only an exact Unknown audit plus the parent bundle
may archive such a record after real native cleanup; standalone missing-Unknown
release is refused. No successful cleanup changes an original Unknown operation
into Succeeded. Repeated matching physical settlement is idempotent; contradictory
exit evidence fails IntegrityFailure. Scope inactivity, context ACK or an absent
handle alone is not proof of physical release. A begun failed release remains
fenced rather than blindly retried.

Required development evidence: independent local HTTP nonce and cookie observations,
owner/profile negative controls, current-policy denial, dropped waiters, a native
side effect followed by an unresolved response, same-ID non-replay, actual descendant
exit and return of provider capacity. Compile, mock or source review does not prove
these. Exact source/dependency/binary identities and original FAIL receipts must be
retained. This checkpoint is not signed candidate, installed runtime, account,
paired-network, macOS/Windows Browser or final platform acceptance.

Primary implementation references: pinned local rmcp and JS/Playwright SDK source;
[systemd resource controls](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)
and [execution limits](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).
Online documentation describes mechanisms; local kernel controls and native results
must still be observed. Mature dependency reuse is deliberate; no new stdio, CDP,
D-Bus or process-supervisor protocol is implemented here.

Development evidence now exists: the corrected short-runtime-directory native batch
completed independent HTTP effects, cross-profile cookie isolation, local-policy
refusal, lost-waiter completion and same-ID non-replay. A second effect deliberately
preceded an unresolved browser response: Core remained Unknown, duplicate dispatch
returned the original Unknown and the historical state survived physical bundle
release. Both owner scopes released with zero remaining provider records while
profile directories were preserved. The independent observer saw both original
cgroups removed and all24 sampled PID/birth identities gone; actual kernel limits
matched and per-scope peak charged memory was about249/236MiB. Sampling is not a
claim to have enumerated every short-lived child. Original native1/2 FAIL receipts
remain preserved. These development results do not cover worker/Host forced-crash,
refs, headed mode, login restore, public Browser routing, macOS/Windows Browser,
final packaging or account journeys. The complete frozen-source regression gate
and integration remain separate evidence.
