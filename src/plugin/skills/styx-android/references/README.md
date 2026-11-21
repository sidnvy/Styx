# Android app knowledge (Styx)

These are **optional references** for the shared `styx-android` skill. The runtime is
Styx's native paired Android Host and its three MCP tools: `android_observe`,
`android_act`, and `android_run_steps`. These notes never authorize a second ADB
execution backend or application-specific monkey patches.

Load a reference only when its app, problem, or debugging topic is relevant:

- [Community Android agent practices](external-android-agent-patterns.md)
- [Xiaohongshu / rednote](xiaohongshu.md), package `com.xingin.xhs`
- [China Unicom crash investigation](china-unicom.md), package `com.sinovatech.unicom.ui`

Provenance: device evidence is marked with the date and environment, community
examples are linked to their source, and uncertain hypotheses are explicitly
labeled. App-specific resource IDs may change; use a fresh observation and
confirmed package/window identity. Never cache ephemeral `node_id` values.

Integration: the shared `styx-android/SKILL.md` is owned by the concurrent
Gateway/onboarding Codex task. Once that work reaches main, link this index
from its skill as an optional reference; avoid concurrently changing that SKILL.md.
