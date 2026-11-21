# Existing Android agent skill patterns reviewed (2026-11-22)

This is a **read-only pattern review**, not a third-party code dependency.
Do not install or execute scripts from these repositories without a separate
source/dependency review. Keep Styx native pairing, permissions, and execution.

## Useful existing designs

1. [yang1ming/android-harness](https://github.com/yang1ming/android-harness)
   ([SKILL.md](https://github.com/yang1ming/android-harness/blob/main/SKILL.md)):
   app-specific helpers by package; observe the actual app/window before acting;
   target by accessibility semantics and use screenshots where custom UIs are
   opaque; verify that the state changed after navigation.
2. [EgiStr/android-agent-skills](https://github.com/EgiStr/android-agent-skills):
   compact text-first UI and *changed-state* summaries to reduce agent tokens;
   screenshots only for incomplete accessibility; reproducible QA flow receipts.
   Its ADB uiautomator latency estimates are not Styx benchmarks.
3. [robbin/android-adb-control](https://github.com/robbin/android-adb-control):
   a small Observe -> Act -> Verify loop; preserve observed effects and stop
   bounded workflows after uncertainty; do not silently replay input.
4. [amit-nayar/android-adb-skill](https://github.com/amit-nayar/android-adb-skill):
   thin task skills over one structured, deterministic command contract;
   testing and debugging are separate workflows from ordinary navigation.

## Adopt for Styx, not their ADB backends

- Prefer concise accessibility-tree output; include screenshot when it adds
  independent evidence. A note's non-visible accessibility text may be present
  but must not be confused with visually verified text.
- Prefer stable resource-id and accessible label over coordinates. Node IDs are
  observation-scoped; when state or window changes, obtain a fresh observation.
- Batch actions only when the targets and ordering are known beforehand.
  If a new page determines the next action, finish the batch and observe.
- After an asynchronous navigation, validate the expected app/window or target
  text. On empty/stale results, observe again; never invent success or replay an
  uncertain write. Existing bounded event-based observation in Android Host
  does not guarantee completion of a remote page's network loading.
- Keep task recipes short and evidence-based. Record expected outcome, app
  package, trigger, date and known failure modes. Refactor a truly shared
  behavior into the Android Host or generic skill rather than duplicating it
  in every app file.
- Diagnose crashes with actual package/version/OS/process exit evidence before
  recommending clear storage, reinstall, system spoofing or security bypass.

No external package or runtime code from these projects was imported.
