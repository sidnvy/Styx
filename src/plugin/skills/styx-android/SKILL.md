---
name: styx-android
description: Observe and control a paired Android device through Styx, batch known consecutive actions, and recover from partial or uncertain input.
---

Select the Android Host with `list_execution_environments` and keep its `environment_id` on each call. Read `get_execution_environment_status` when Android capability, connection or permissions are unclear. Report a locked device or missing AccessibilityService when the Host identifies it.

Call `android_observe` for this caller's current observation and node references. Request a screenshot when visual details are needed. Use `android_act` for a single input when its outcome determines what to do next. After navigation, observe the new page before selecting a node or coordinate.

Prefer a single `android_run_steps` when the order is known and every target has a reliable basis in the current observation. For example, the system actions Recents and Home can run together when the goal is simply to return Home. If the goal is to open a particular app from Recents, stop in Recents and observe the app cards before selecting one. Set `observe_after` when a final tree will guide the next action or verify a result. Ask `android_observe` separately for a screenshot.

The first failed or uncertain step stops execution. `completed_steps` counts confirmed steps, `failed_step` is the zero-based index of the first failed or uncertain step, and `results` describes each attempted step, including that final attempt if reported. A later step was not attempted. For partial or unknown results, verify current state using the final observation if available or a fresh `android_observe`. Continue only with actions that remain appropriate. Replaying the entire batch can repeat completed input.
