# Styx architecture

This page describes the current Rust implementation. Product decisions are in
[rust-core-rewrite/REFACTOR-PLAN.md](rust-core-rewrite/REFACTOR-PLAN.md);
[RELEASING.md](RELEASING.md) defines distribution. Dated rewrite plans and
acceptance reports are history, not alternative implementations or current device status.

## Request path and ownership

A deployment has one Gateway. ChatGPT reaches its MCP endpoint through the
Gateway's Private MCP Tunnel. The Gateway authenticates the caller, selects a
paired Host and forwards the request over that Host's outbound authenticated
WebSocket. The Host owns execution and calls the appropriate local executor.

| Component | Owns | Does not own |
| --- | --- | --- |
| Gateway | MCP HTTP sessions, caller authentication, device directory, pairing and revocation, routing, Tunnel | A second Exec task or Browser session directory |
| Host | Capability settings, caller access, tasks, output cursors, Browser sessions, executor and platform lifetimes | The deployment's Tunnel configuration |
| Codex Exec | Processes, PTYs and process I/O | Gateway connections |
| Playwright Browser worker | Browser processes, contexts and page operations | Host admission policy |
| Cua/native bridges | Desktop observations and input through the OS frameworks | Deployment management or a second reasoning agent |

A broken Gateway connection ends a link. It does not recreate the Host executor
or erase its tasks. Closing a conversation removes that caller's access;
Host-owned Exec tasks and Browser sessions remain until their own explicit
close, capability disable or Host exit. Browser takeover changes the operator
and invalidates the previous operator's references. Host restart does not restore
old processes or browser sessions.

Computer Use follows Cua's concurrency model. There is no conversation-wide
desktop lock. Separate capability settings determine whether Exec, Browser and
Computer calls are admitted; changing one setting does not disconnect the Host.

## Code layout

The Cargo workspace has four crates:

| Crate | Responsibility | Main source |
| --- | --- | --- |
| `styx-contracts` | Typed identifiers, wire messages, public errors, management and release data | `crates/styx-contracts/src/` |
| `styx-core` | Policy and pure state transitions, operation ownership and transaction rules | `crates/styx-core/src/` |
| `styx-runtime` | Networking, persistence, native adapters, workers and App/Host/Gateway composition | `crates/styx-runtime/src/` |
| `styx` | CLI commands, onboarding, installation and service lifecycle entry points | `crates/styx/src/` |

Within `styx-runtime`:

| Module | Boundary |
| --- | --- |
| `gateway/mcp`, `gateway/http` | Official rmcp server and authenticated HTTP session lifecycle |
| `gateway/paired` | Paired-device routing, connection generation and response settlement |
| `host/link`, `host/protocol` | WebSocket transport and authenticated Host protocol |
| `host/coordinator`, `host/exec_tasks`, `host/browser_sessions` | Host-owned execution, continuation and Browser ownership |
| `providers/codex`, `providers/browser`, `providers/cua` | Adapters for the fixed upstream executors |
| `foreground` | Compose one native Host/Gateway for CLI, App or a native service |
| `management`, `store` | Native configuration changes, persisted state and credential storage |
| `platform`, `app` | OS service and native App lifecycle integration |
| `release` | Installed payload selection and publisher verification |

Swift in `host/macos/` and C# in `host/windows/` provide native UI and OS
integration. They call the Rust core. Node runs the Playwright Browser worker;
build and test scripts may also use Node, but there is no JavaScript Gateway,
Host or management runtime.

## Transport and operation state

The public interface is the MCP tool contract in
[rust-core-rewrite/PUBLIC-MCP-V1.json](rust-core-rewrite/PUBLIC-MCP-V1.json).
The Host connects to `/styx/host/v3/{device_id}/exec`; this paired transport
carries the supported Host protocol operations. Foreground startup reads the native profile; it does not fall back to a
JavaScript deployment or signed legacy worker closure.

There are no custom quotas on devices, conversations, tasks or retained history,
and no idle-session eviction. Message framing, actual transport backpressure and
explicit cancellation still have their normal roles. A lost response to a
state-changing operation is inspected through its existing owner; it is not
automatically replayed.

Each state holder answers a different question:

| State | Question |
| --- | --- |
| Gateway session/caller binding | Which authenticated caller is making this request? |
| Core operation ledger | Who owns the operation, and what has been dispatched or settled? |
| Host task/session state | Which process or Browser resource exists, and where should continuation resume? |
| Executor state | What happened in the actual process, browser or OS action? |

Do not copy these records into another directory merely to make a second
component answer the same question. Moving ownership includes deleting the old
path.

The Host caller registry retains active leases and unresolved cleanup. Once both
executor cleanup and profile release are confirmed, that caller is removed
immediately; an earlier active caller does not retain completed later callers.
The existing per-Gateway-epoch sequence boundary prevents reopening removed
callers. Gateway authentication records are also released individually after
cleanup; an absent record remains unauthorized. These are separate admission
and execution responsibilities, without a second completion-order directory.

## Installation and update

The installed package supplies the executable and its fixed worker versions.
Native Apps use their installed bundle and the normal platform installer:
Quit, replace the App, reopen the same profile. There is no second in-App
Runtime updater or App-maintenance protocol.

Linux installation stages the release and updates the selected native runtime
and stable CLI entry through one installer flow. An update that replaces a
running Host executes independently of that Host, so stopping the old service
cannot kill the remaining installation work. Native service management uses the
OS manager directly; the former transient-Host CLI protocol is removed.

Native configuration owns identity, pairing and desired roles. For persistent
services, it also selects the active runtime. For App-managed processes, the
current signed App bundle supplies executable code; the profile's original
selection remains enrollment history. A replacement bundle must retain the
publisher and support the persisted state reader.
Previously committed App runtime-update records remain readable after removal
of their updater. New stopped-profile runtime selection uses the existing native
transaction writer; historical App records do not require a second live writer.

OS observations report what is actually running. The Linux upgrade plan records
unfinished installation intent and the pending dispatch; the native journal
supplies commit evidence, without a second set of per-step receipts. After a
service update, its selected runtime, running process and CLI must agree. An
App's running core and workers must come from its current bundle.

Publisher/package verification belongs at installation or update. Ordinary
startup reads the installed metadata and retained native identities; it does
not perform another full package scan. Keep OS signing, pairing and private
credential protection. The historical JavaScript deployment codec and signed
legacy worker closure are no longer accepted by foreground startup.

All platforms are distributed through one route: code merged to `main`, a new
matching version tag, the release workflow, and the complete GitHub Release
assets. Local builds remain development and test inputs.

## Supported compositions

Desktop installations offer Host only or Gateway + Host. Headless Linux offers
Gateway only. The one Gateway owns the deployment's Tunnel. Hosts pair with its
address and one-time invitation; opening another conversation does not create a
new device identity.

Current native profiles and pairing survive an update. Source cleanup never
deletes runtime profiles, keys or publisher pins. Historical migration cuts are
not instructions to reset already installed Rust deployments.
