# Upstream Android agent implementations vs Styx (2026-11-22)

**Decision: reuse small instruction patterns; prototype an optional compact
observation projection; defer persistent UI diffs and a generic flow runner.**
This is a source-level comparison and read-only device measurement, not a
third-party code import or a shipping feature claim.

## Reviewed real source (main branch; blob hashes on date of review)

| Upstream | Concrete implementation reviewed | Decision for Styx |
| --- | --- | --- |
| [android-harness](https://github.com/yang1ming/android-harness) | [SKILL.md](https://github.com/yang1ming/android-harness/blob/main/SKILL.md), [targeting.md](https://github.com/yang1ming/android-harness/blob/main/interaction-skills/targeting.md), [recovery.md](https://github.com/yang1ming/android-harness/blob/main/interaction-skills/recovery.md), and [app-skills/README.md](https://github.com/yang1ming/android-harness/blob/main/agent-workspace/app-skills/README.md). Verified target ordering: accessibility label -> resource ID -> screenshot -> coordinates; recovery verifies app state and stops bounded retries; per-package files include app/version, expected screen cues, verified recovery, stop conditions. | **Adopt the behavior in the generic skill and optional app references.** Already consistent with Styx's scoped node identity. Do not copy its subprocess ADB, optional daemon, or plugin runtime. |
| [android-agent-skills](https://github.com/EgiStr/android-agent-skills) | [_ui.py](https://github.com/EgiStr/android-agent-skills/blob/main/skills/android-adb/scripts/_ui.py): `display_list` keeps labeled/interactive nodes, `fmt_el` formats compact lines; `save_last` persists labels+centers; `diff_rows` reports added/removed/moved based on *label keys and coordinate lists*. [input.py](https://github.com/EgiStr/android-agent-skills/blob/main/skills/android-adb/scripts/input.py) invokes `print_diff_after_action`. [flow.py](https://github.com/EgiStr/android-agent-skills/blob/main/skills/android-qa/scripts/flow.py) executes YAML/JSON test steps with waits/assertions, bounded status, evidence and crash scanning. | **Prototype compact presentation only; defer copying automatic diff/history and YAML runner.** The label-keyed diff loses distinguishing information for repeated labels, and its saved snapshot cannot replace Styx's caller-scoped `observation_id` and node identity. |
| [android-adb-control](https://github.com/robbin/android-adb-control) | [SKILL.md](https://github.com/robbin/android-adb-control/blob/main/SKILL.md): preflight one device, bound actions/time, observe -> act -> settle -> verify, verify before retry, stop ambiguous writes, read screenshot for opaque UIs, record pending outcomes. | **Adopt a short task budget and explicit completion evidence.** Styx already implements fresh observations, first-failure batch termination and unknown/no-replay semantics; do not duplicate admission in a shell script. |
| [android-adb-skill](https://github.com/amit-nayar/android-adb-skill) | [command-contract.md](https://github.com/amit-nayar/android-adb-skill/blob/main/docs/command-contract.md): structured JSON actions; [android-navigate/SKILL.md](https://github.com/amit-nayar/android-adb-skill/blob/main/skills/android-navigate/SKILL.md): thin UI-find/tap/wait/verify orchestration over one execution interface. | **Already matches Styx's one MCP surface + thin Skill architecture.** No second ADB CLI, daemon, app-specific automation engine, or full command DSL. |

Selected reviewed upstream content blob hashes: EgiStr `_ui.py`
`15760f932572e5d792426a534e1e9341e4c3f9b6`; EgiStr `flow.py`
`616b18dfd2faa382424fefe0b67c4130e0ad09e7`; android-harness
`targeting.md` `7aa1a899f47ea52d91f15c8fa3b50c181a2f158`;
robbin `SKILL.md` `b6fd7193b19bc1910693d6cc4fda925a4d167729`;
amit `command-contract.md` `bc995bf55809842f225130669049b10597750b76`.

## Styx source and live behavior against that baseline

- Existing Android Host: `src/host/android/app/src/main/java/com/styx/host/StyxAccessibilityService.kt`.
  `android_observe` walks the Accessibility tree, stores **one current
  observation per caller**, creates new ephemeral `node_id` values, and
  returns all tree JSON unless `include_tree=false`; it constructs tree
  JSON internally even when not returned. `android_act` verifies original
  window/package and node identity before dispatch. `android_run_steps`
  sequences known actions and stops at the first failure/uncertainty. **No
  `wait element` predicate or UI-diff API exists** in the current MCP schema
  `src/docs/rust-core-rewrite/PUBLIC-MCP-V1.json`.
- The separate Android transition fix in PR #85 adds a bounded event-based
  wait before `observe_after` for navigation-style actions. This cannot
  prove a network-loaded third-party page has finished loading. Integrate
  its review separately; do not duplicate or rewrite it here.
- Pixel 7 Pro, Android 17, five **read-only** calls on the unchanged launcher
  on 2026-11-22: full tree returned 31 nodes and 9,590-9,591 JSON bytes
  each, Host duration 71-119 ms, ChatGPT MCP elapsed 1,132-1,615 ms.
  `include_tree=false` returned 535 bytes, Host duration 85-86 ms and
  elapsed 1,369-1,424 ms. All 31 node signatures matched across the three
  full observations. This establishes repeated payload, **not** a latency
  win from delta output: network/tool overhead dominates host processing.
- A read-only, local JS projection of one full observation keeping
  `observation_id`, package/window, visible labels and all actionable
  nodes (including unlabeled clickable nodes), with resource IDs and bounds
  for actions, measured **2,491 bytes vs 9,590 (-74%)**. This projection
  was not deployed as a tool. It excluded offscreen text, which must be
  available on demand for tasks like reading Xiaohongshu note comments.

## Recommended bounded next experiments (no implementation in this PR)

1. **Compact observation, opt-in, no diff history.** First validate a
   projection of the *same fresh observation* that preserves the current
   `observation_id`, `package_name`, `window_id`, truncation, text,
   description, stable resource IDs, action flags, and unlabeled clickable
   containers with bounds. Retain `full` mode for troubleshooting and
   large/offscreen review text. Do **not** return only visible labels: in
   Xiaohongshu, `searchNoteCard` is an unlabeled clickable container and
   `noteTitle` is non-clickable; offscreen comments can contain relevant
   text. Proof threshold: >=60% smaller navigation payload, correct node
   targeting in 10 varied real transitions (including duplicate labels,
   custom-rendered pages and scroll), no increased unknown actions.
   Record time and model-context savings separately.
2. **Application readiness, only if reproduced.** For the repeatedly
   observed post-click empty page in Xiaohongshu, evaluate an optional
   bounded `observe` wait for **a caller-supplied target condition** (e.g.
   active package + accessible text/resource ID), returning a fresh
   observation and an explicit not-ready result on timeout. Prefer Android
   Accessibility events and bounded condition checks to fixed sleeps. Never
   repeat the click on timeout. Integrate only if it demonstrably reduces
   extra MCP calls without hiding genuine errors; do not add another
   task manager, daemon or conditional workflow DSL.
3. **Task recipes remain Markdown.** Keep a few verified per-app entry,
   target, postcondition, failure/stop cases under `references/`. Use
   existing `android_run_steps` for deterministic pre-known consecutive
   actions, `android_observe` for new decisions, and native
   instrumentation for repeatable Android Host QA. Do not copy the
   `flow.py` YAML replay engine unless repeated evidence-driven QA use
   later establishes requirements beyond current integration tests.

Security/scope: neither upstream code nor third-party dependencies were
installed or executed. No app data, credentials, private text, screenshots,
or user identifiers were copied to this file. Generic `SKILL.md` in the
Gateway/onboarding worktree has another owner; edit it only after integration.
