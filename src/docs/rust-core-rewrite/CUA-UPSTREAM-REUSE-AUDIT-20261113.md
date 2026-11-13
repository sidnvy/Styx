# Cua upstream reuse audit — 2026-11-13

## Finding

There is no evidence that Styx needs to retain its entire Cua 0.36.0 patch
unchanged. There **is** a demonstrated difference preventing a blind replacement:
official Cua 0.47.24 Linux `set_value` performs an additional `activate` after a
successful EditableText write. Its error path also allows another native write.
The existing no-replay boundary cannot be implemented by merely calling that
upstream tool once from Core.

Prefer pinned official Cua and ordinary adapter updates. Retire redundant
patches when the corresponding route is qualified; retain or upstream only a
demonstrated behavioral fix. Existing private interfaces and exact-schema pins
are integration work, not evidence that a fork is inherently necessary.
This audit changes no product dependency, install, signing identity or policy.

## Implementation follow-through

The owner subsequently requested the removal. The current source now pins
0.47.24 and replaces the 33-file historical patch with an 8-file patch: strict
text handling, two Windows repairs, and focused native regressions. It uses the
unchanged official Cargo.lock, snapshot store and lifecycle implementation. The
old private acquire/write tools, daemon observation/drain methods, owned-proxy
FD protocol, duplicate Mac console epoch checks and Windows-only build scripts
have been removed. Core's operation/grant/owner and no-unknown-replay policy is
unchanged.

The newly compiled Linux worker passed the owned GTK scenario with one text
change and **zero activate events**, stale-token refusal without a second
write, and a real private-D-Bus success/false/error/stall regression with no
alternate setter. Host adapts the ordinary upstream ActionResult and optional
recovery hints; the upstream SDK projection is not customized.

See [development convergence evidence](../evidence/cua-upstream-0.47.24-convergence-20261113.json).
This is source/native development work; no updated installation or Stable
release is implied. The original comparison below describes the unmodified
upstream counterexample and the retained differences.

## Inputs and actual execution

- Styx source: `0f33bec2f3670b2a69554a6e306981b78bd27de7`.
- Current Cua: 0.36.0, commit `6d6c734c127025fb39ad5d585a10382808b39dc1`;
  baseline patch touches 33 files, adding 6,384 and removing 314 lines, plus the
  separate Windows capture fragment. This is substantial maintained source.
- Reviewed official release: [Cua Driver 0.47.24](https://github.com/trycua/cua/releases/tag/cua-driver-rs-v0.47.24),
  commit `b168ff39fef15d993ab66facce9b0027ea556dce`. The repository-wide Latest
  release is a different product, Cua Spaces; it is not the Driver version.
- Downloaded the official Linux x86_64 binary archive, verified SHA256
  `e5333da45b233e8ec93550ec8061fdc9513b23621145def3a3ea22a01c328738`,
  and executed it without installing or replacing the product worker.
- Actual MCP initialization/tools-list: version 0.47.24, 66 standard tools,
  no `styx_private_*` tools, normal EOF exit code 0.
- Actual desktop probe used one disposable GTK Entry owned by the probe:
  exact-window AX read, one standard `set_value`, fixture-owned text/event
  report, fresh AX read, `end_session`, EOF and original child exit. All passed.
  The fixture reported **one text change and one activate event**. No user
  window, Styx account, installed worker or persisted product profile was changed.
- The sandbox-only first fixture launch could not initialize GTK; it performed
  no write. The subsequent authorized desktop probe created and closed its own
  fixture normally. No unknown write was replayed.

Machine-readable results and reviewed-source hashes:
[audit evidence](../evidence/cua-upstream-0.47.24-audit-20261113.json).

## Patch assessment

| Area | Official 0.47.24 evidence | Assessment |
| --- | --- | --- |
| Exact snapshot/element targeting | `SnapshotStore::resolve` retains the original snapshot object, refuses stale tokens and conflicting window IDs. Windows retains UIA references; macOS rechecks the retained object's window before mutation. | Ordinary retained targeting already exists. It does not justify maintaining another complete snapshot implementation by itself. The extra observed-invalidation and two-phase one-use semantics are not automatically equivalent. |
| Linux strict text replacement | `set_value_on` uses `SetTextContents(...).await.unwrap_or(false)`, then may call `InsertText`; successful writes may call `commit_editable_write`, which invokes `activate`. The normal-path activation was independently observed. | A real gap remains if one exact text replacement, no post-write activation and no fallback after an uncertain reply are required. Use a narrowly scoped upstream fix/strict route; an outer no-retry wrapper is insufficient. Fault-path behavior here is source evidence, not a fault-injection result. |
| Windows/macOS general `set_value` | Windows can fall from a failed ValuePattern setter into RangeValuePattern. macOS can try numeric then string writes and increment/decrement routes. Both expose broad semantic controls beyond a plain text field. | These general tools are not proven substitutes for the private strict text-only route. Qualify the eligible control/error paths rather than claim every upstream write is unsafe or every private check necessary. No native Windows/Mac effect test was run in this audit. |
| Normal shutdown/session cleanup | The SDK closes admission, waits on its lifecycle lock, revokes sessions, retires snapshots and stops recording. Session lifecycle tracks in-flight work and fallible cleanup hooks. Daemon shutdown joins connection tasks. Linux actual `end_session`/EOF/exit passed. | The claim that upstream lacks cleanup is false. Prefer these standard facilities. They do not alone prove equality with Styx's original-transport drain acknowledgement or Mac overlay presentation receipt. |
| macOS embedded App binding | Official MCP supports embedded/private service endpoints and retains App-based TCC attribution. Styx additionally reads private process/console/TCC observations and expects its own drain/overlay acknowledgement. Upstream `remove_cursor` queues a removal without a matching confirmation receipt. | Necessary App/TCC integration must stay, but it is not evidence for retaining the whole executor fork. Audit the existing native bridge and standard lifecycle API as replacements; signed-App lock/revoke/in-flight/overlay tests remain open. Do not substitute a new unsigned direct child or change TCC grants. |
| Hyprland empty special workspace | Official `Workspace.id` has a default for the missing ID and an explicit empty-special-workspace regression test. | The reported ordinary empty-workspace bug is already handled upstream. Styx's stricter malformed/ambiguous-data handling is additional policy, not proof the original bug remains. |
| Windows DPI-unaware capture | Official capture already uses WGC for selected errors, XAML/black frames, plus other fallbacks. The reviewed module does not have the Styx fragment's explicit DPI-unaware-window branch. | WGC availability is not proof that the specific partial-GDI-image case is fixed. Retest the original 120-DPI/DPI-unaware owned-window case before keeping or dropping this small fix. This audit supplies source comparison only. |
| Windows completed-click outcome | The patch changes classification around a completed input followed by a focus transition. The latest upstream has also changed input handling. | No current native reproduction was performed. Neither necessity nor redundancy is established by this audit; do not retain it solely on historical failure evidence. |
| Private schema/CLI/proxy hooks | Styx calls two private AX tools and Mac private observation/drain methods. Its Linux catalog validator freezes all old schemas and interprets 66 tools as old 64 plus the private pair. Official 66 instead adds `browser_select` and `get_guide`; schemas have also evolved. | A direct binary swap is incompatible today. Updating this adapter/version contract is normal dependency maintenance, not justification for continued source customization. Preserve the existing public Styx tool surface. |

## Recommendation and remaining proof

Do not keep the whole historical patch merely because CI now builds it. Also do
not delete it by swapping binaries: current calls would fail, and the Linux
write behavior would change in an independently observed way.

The migration target is official pinned upstream plus the smallest demonstrated
fixes. First qualify strict text replacement (including lost/negative reply,
no alternate setter and no activation), then the existing Mac App/session
lifecycle and Windows DPI/click regressions. Remove superseded private plumbing
and update source/catalog/package bindings as the corresponding routes pass.
Reusing an unaffected result is sufficient; this is not a request for another
full three-platform acceptance campaign. No implementation/removal or release
acceptance is claimed by this audit.

## Primary source pointers

All links below are pinned to the reviewed official release commit.

- [Linux setters and post-write activation](https://github.com/trycua/cua/blob/b168ff39fef15d993ab66facce9b0027ea556dce/libs/cua-driver/rust/crates/platform-linux/src/atspi/native.rs#L5791)
- [Snapshot resolution](https://github.com/trycua/cua/blob/b168ff39fef15d993ab66facce9b0027ea556dce/libs/cua-driver/rust/crates/cua-driver-core/src/snapshot_store.rs#L878)
- [SDK shutdown](https://github.com/trycua/cua/blob/b168ff39fef15d993ab66facce9b0027ea556dce/libs/cua-driver/rust/crates/cua-driver-sdk/src/runtime.rs#L285)
- [Tracked session cleanup](https://github.com/trycua/cua/blob/b168ff39fef15d993ab66facce9b0027ea556dce/libs/cua-driver/rust/crates/cua-driver-core/src/session.rs#L1595)
- [macOS overlay removal](https://github.com/trycua/cua/blob/b168ff39fef15d993ab66facce9b0027ea556dce/libs/cua-driver/rust/crates/platform-macos/src/cursor/overlay.rs#L440)
- [Hyprland empty-workspace handling](https://github.com/trycua/cua/blob/b168ff39fef15d993ab66facce9b0027ea556dce/libs/cua-driver/rust/crates/platform-linux/src/wayland/hyprland.rs#L27)
- [Windows capture](https://github.com/trycua/cua/blob/b168ff39fef15d993ab66facce9b0027ea556dce/libs/cua-driver/rust/crates/platform-windows/src/capture.rs#L365)
