# Styx same-machine multi-user isolation — production requirement

Status: **PRODUCTION RELEASE GATE, not implemented by the current Gateway.**
Scope: distinct ChatGPT users may each enroll Styx on the SAME physical
macOS, Linux or Windows computer. The unrelated Chat-Codex application is
not a Styx component, dependency, management target or migration scope.

## Separate three identities

1. **User principal**: verified owner account of one Styx installation.
   This is NOT an MCP connection UUID or a model-supplied owner string.
2. **Host instance**: one per-user Styx enrollment, with an independently
   generated device identity, outbound credential, state root and service.
   Several such instances can have the same physical-machine fingerprint;
   that does not merge their rights or enrollment records.
3. **Native OS user/session**: actual UID/SID/login & graphical session
   under which Codex Exec and Cua Desktop operate. This supplies the OS
   security boundary. A Gateway identifier alone cannot secure a GUI.

A model tool's environment_id selects one instance **only after** the
caller has been authenticated and explicitly authorized for that instance.
Device IDs should be opaque and unique; a physical-machine ID must never
serve as an authorization key.

## First supported deployment shape: separate per-user instances

Prefer a minimal, robust isolated deployment over inventing a complex
multi-tenant administrative framework:

- **Gateway**: separate authenticated Gateway realm/instance per user or
  independently verified principal-scoped registry. The current single
  bearer + global TargetRegistry design is **single-owner only** and MUST
  NOT be exposed as multi-tenant. A second client knowing the shared token
  would currently see the same admitted targets.
- **Host**: separate Styx identity and outbound connector for each OS user
  on a physical computer. Each is launched by that user, has no inbound
  execution port, and holds its own private credentials.
- **State**: per-user private config, install root, logs, process sessions,
  Cua token/snapshot state, device enrollment and task receipts; do not
  place other users' material in shared or iCloud-synced writable folders.
- **Authority**: Codex Exec runs with the native user's OS access. Cua
  attaches only to that user's permitted desktop session. Never run a
  universal root/system GUI broker and route actions by model-provided UID.
- **Isolation of identifiers**: connection IDs, MCP session IDs, process
  IDs, GUI element tokens and replay/abort keys are bound to the verified
  user principal, specific Host instance and runtime generation.
  Another user's session/element ID must fail closed even if copied.
- **Revoke/uninstall**: one owner disabling, revoking or uninstalling
  their Styx instance must not terminate another user's connector or delete
  their data. No global 'kill Styx on machine' control by ordinary users.

Each per-user instance may use the SAME reviewed Styx product version and
signed distribution. Separate installations are process/state isolation,
NOT a requirement to maintain different products or engines.

## Platform process and GUI constraints

| OS | Preferred native boundary | Practical GUI limitation |
| --- | --- | --- |
| macOS | Separate login UID, per-user LaunchAgent, private Application Support/container state and per-user Cua Embedded lease | Signed Styx.app is the permission owner; do not assume Accessibility or Screen Recording grants are transferable between logins |
| Linux | Separate UID, systemd --user unit, private runtime dir, separate Hyprland/Wayland compositor session and Cua Driver process | Native Wayland screen/input access is session-specific; no GUI assumption when user is logged out or locked |
| Windows | Separate SID, per-user Scheduled Task in interactive logon, private AppData/credential storage and Cua UIA process | Session 0 is not an interactive UI; identify the actual logged-on user session before executing GUI actions |

**Same OS login account caveat:** two logical Styx identities that execute
under the SAME native UID and desktop are not strongly security-isolated.
They share the OS account's filesystem and input/screen capabilities.
A malicious peer process under that same UID can often inspect the other's
resources. Claim only *logical* segregation there. Strong isolation
requires distinct OS users/session contexts or separately isolated
VMs/desktops, subject to native GUI backend support.

## Gateway authorization requirements for a future shared realm

A single network listener may serve multiple owners later, but only with
a verified per-request principal and an authorization check on every
registration, discovery and tool call. The current Gateway must first be
changed in all of these places:

- Authenticate each MCP caller to a stable user principal, not merely a
  shared global bearer. Never accept tenant_id / owner_id from a model tool.
- Associate every enrollment invitation, pending approval, Host identity,
  public key, capability, target and job with that principal.
- Resolve (principal, environment_id) before opening an Exec or Cua lane.
  Filtering list_execution_environments alone is insufficient.
- Scope model sessions, input streams, process state, Cua leases,
  screenshots, error messages, logs, caches and any persisted job receipts
  to the verified user and Host instance.
- Isolate instance generation changes, quotas and resource cleanup so
  one user's disconnect does not revoke another user's process or desktop.
- Separate owner administrators from execution clients. Enrollment approval,
  secret rotation and revocation are not model-exposed execution tools.

**Do not describe the current single-token Gateway as multi-user safe.**

## No relationship to other users' applications

Other installations such as Chat-Codex may coexist on the same physical
Mac. Styx must not inspect, modify, supervise, restart, migrate or clean
up those applications, their LaunchAgents, credentials or file-provider
state unless their verified owner explicitly authorizes that separate
operation. Troubleshooting an unrelated Tunnel cannot prove why the
current ChatGPT UI stalled.

## Production acceptance / negative tests

1. Two distinct native OS users install the SAME Styx version on one
   machine with separate device keys, services and data roots.
2. Enrolling both on their respective Gateways allows each to see ONLY
   their own devices and capabilities (including after Gateway restart).
3. Wrong principal, bearer, token, request ID, element token and target
   combination cannot run commands, observe screens or enumerate devices.
4. Both users can execute separate Cmd/PTY jobs; GUI works only in its
   actually authorized OS/desktop session, not the other user's session.
5. Concurrent jobs and one user's cancellation, GUI-worker crash,
   upgrade, revoke or uninstall cannot affect the other's running job.
6. A stolen device ID, physical fingerprint or guessed environment_id
   never grants another owner's authority. Owner approvals are
   independent and cannot be replayed across realms.
7. Credential and state file permissions, signed upgrade and error logs
   stay segregated; no cross-user screenshot/cache/job receipt leakage.
8. Connection loss and session recovery are observable for each owner.
   Any future persistent execution ledger must be owner+Host scoped;
   it is NOT a solution for ChatGPT's native chat-stream interruptions.

**Release gate:** until the tests above pass, Styx deployment is supported
only in explicitly isolated single-owner Gateway/Host instances. No
production switch to a shared multi-user Gateway.
