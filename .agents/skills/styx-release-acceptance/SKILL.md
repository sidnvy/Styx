---
name: styx-release-acceptance
description: Freeze, sign, package or install a Styx release, or execute final cross-device and Custom MCP acceptance. Do not use for routine native debugging, typechecks or documentation edits.
---

# Styx release and acceptance

Deliver the requested artifact or close the identified acceptance exits, using the existing
project and producers. User authorization persists across the task; do not add approval
checkpoints merely because a new step or platform starts. Tool-enforced permissions still apply.

## Load the requested phase

For packaging, consult the existing producer and its validated inputs.
For device/account acceptance, read only the latest relevant checkpoint and missing matrix
cells in [the delivery plan](../../../src/docs/rust-core-rewrite/END-TO-END-DELIVERY-PLAN.md).
Use [REDUCED-SCOPE.md](../../../src/docs/rust-core-rewrite/REDUCED-SCOPE.md) for scope questions.
Read historical evidence only to resolve a specific old receipt or failure.
A status request alone does not authorize installation, configuration reset or topology changes.

## Freeze and production

- Integrate validated source once, run the integration quality gate, then freeze source/inputs.
  Keep immutable release receipts and outputs; do not require a new project, worktree, chat,
  toolchain or Cargo cache. Daily development remains incremental.
- Differentiate a build needed by a native scenario from final release production.
  Reuse completed, matching builds; inspect producer receipts/processes before dispatch.
  Never repeat a producer whose result is unknown.
- Use existing full Runtime/App producers and per-platform caches. Preserve source hashes,
  signing pins, payload integrity and cache-correctness checks; do not replace sealed binaries
  or invent success receipts. Signing private keys remain on their original machine.
- Normal install/Quit/reopen can proceed within existing authorization. Force termination,
  profile reset, new permission grants or production changes need their own applicable authority.
  Make any needed request concrete after completing independent preparation.

## Native and account acceptance

- Native owners hold each GUI lease; Root coordinates shared source, fingerprints, topology and
  the independent acceptance MCP. Reuse the original project/chat and do not start a second writer.
- Verify fresh original process/binary identity and fixture lifetime before effects.
  A queued instruction proves submission only; require the matching owner result.
- Cover missing boundaries with real effects and negative/recovery controls. Reuse passed
  unaffected scenarios, while binding final release claims to the actual tested artifacts.
  Do not expand one direction's missing route check into another full three-platform campaign.
- Preserve unknown outcomes without replay. Fresh read-only inspection can resolve state;
  an observed permission/transport refusal is not proof of a native effect.
- For recovery, verify actual original-process exit, reopen with the intended persisted state,
  reconnection and a fresh independent effect. Keep Gateway and Host desired-state semantics.
  Clearing profiles or re-pairing does not substitute for same-profile recovery.
- Use the independent Styx GUI Acceptance connection, never the production icon-check connection.
  Final installed detail/Logo refresh follows the final Gateway/account route.

## Exit

Separate checks, packages, installation and real acceptance, with source/artifact bindings.
For a release checkpoint, report changes in Product, Architecture, Integration, Release,
Reliability and Decision compactly; routine updates need only result, blocker and next action.
State which gates remain open. Stable stays NO-GO until its explicit gates close.
