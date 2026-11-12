---
name: styx-native-development
description: Develop or debug Styx native GUI/Core integration, including startup, shutdown, role switching, reconnection and desktop build/run wiring. Excludes final packaging and documentation-only edits.
---

# Styx native development

Produce a reproducible fix in the persistent project and verify the affected behavior.
Explicit user instructions and existing authorization govern scope; this skill adds no approval gate.

## Select the smallest useful context

Read the relevant paths/commands in [WORKSPACE.md](../../../WORKSPACE.md).
Inspect the changed adapter and its Rust authority. Read current contracts only when
changing a boundary; read delivery status only when resuming a device acceptance task.
Historical failures are clues, not diagnoses of the current failure.

## Develop and run

- Reuse the device's existing native owner/chat, source checkout, tools and cache.
  Root integrates shared Rust/contracts/manifests; lease only the platform paths being edited.
- Start with affected-crate incremental cargo check and the changed contract/capability scenario.
  Native Swift/C# typechecks are useful for compile errors; actual startup/recovery requires
  the real GUI/Core and full workers. Do not stop at a self-test when execution is in scope.
- Use the existing development wrapper and builder. A direct App build/deploy can skip
  DMG/Inno packaging; keep original signing, publisher/Runtime verification, source qualification
  and fixed trusted execution paths. Missing development wiring is a defect to fix, not a reason
  to add a permissive trust mode or rebuild all platforms.
- Reuse one Cargo target. Start workstation Linux at 8 jobs; pho at 4 Cargo/2 CMake jobs.
  NAB5 uses its owner's bounded setting. Record resource settings for necessary builds;
  reduce on observed contention. Use --timings for those builds, not extra benchmark builds.
- Keep source/input binding and release producers' existing cache-correctness barriers.
  Changed copied sources need refreshed mtimes and compiler evidence of rebuilding affected targets.
  Do not clean the whole workspace or install a new cache service for routine diagnosis.

## Lifecycle failures

Capture the first failing stage and the original process identity, actual exit status,
closed error code and relevant durable state. Keep diagnostics local and free of credentials.
Separate GUI/Core bootstrap, role restoration, transport, account authorization and worker readiness.

Choose regressions matching the change rather than running every combination:

- Reopen the same persisted profile in a new process and preserve identity, grants and desired state.
- For role/update changes, exercise valid old history, completed retirement and partial/unknown state.
- For interrupted pairing, check certificate/identity continuity and the supported terminal/recovery path.
- For target/session changes, prove the old target has no effect and a fresh target works.

Use disposable local fixtures for repeated regression runs. Preserve live test profiles and
historical UNKNOWN outcomes. Diagnose unknown writes with read-only evidence; do not replay them,
reset a profile or weaken validation to make a recovery test pass.

## Exit

Run the affected checks, then the authorized native behavior. Record source/binary identity,
observed result and remaining gap; a queue acknowledgment or build receipt is not GUI success.
Run full workspace quality once at integration/freeze, not for every helper edit.
When signing/packaging or final cross-device delivery is requested, use
[styx-release-acceptance](../styx-release-acceptance/SKILL.md) for that phase only.
