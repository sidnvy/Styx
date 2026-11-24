---
name: styx-cli
description: Run commands, inspect files, build and debug projects on a selected paired Styx computer using native Exec and owned terminal sessions.
---

# Styx CLI

Use for command-line tasks on an enrolled Styx computer. Discover this plugin's
actual tools and schemas. Call list_execution_environments, resolve the user's
target to an exact returned environment_id, and check get_execution_environment_status.
Ask only if the target is ambiguous. Never invent an ID or substitute a different
plugin, local executor or computer when Styx is unavailable.

Use exec_command with the selected environment_id, an explicit working directory
and the requested native command. Prefer rg for file/text searches. Quote shell
arguments for the target shell; never interpolate untrusted text as executable
syntax. Keep credentials out of command arguments, output and chat.

Exec tasks belong to the selected Host runtime and survive conversation closure
or Gateway reconnection. Preserve both environment_id and session_id. In a new
conversation, use list_execution_tasks on that Host, then write_stdin with empty
chars to inspect progress or the retained terminal result. The live output cursor
is shared by callers; a retained terminal result contains the final output chunk,
not a complete transcript. Use stop_execution_task only for an authorized task.
Quitting Host stops its tasks and does not resume them on the next launch.
A timeout or disconnect does not prove failure: inspect the task or expected
artifact before a fresh mutation. Never automatically replay an unknown action.

Prefer Exec for files, Git, builds and CLI downloads. Do not open a GUI terminal
to work around an Exec error or restriction. Use the Browser skill for web UI and
Computer Use for native GUI operations. Follow user scope for destructive actions,
external communication and installation; a skill is not blanket authorization.

Verify exit status and the actual result, such as generated files or relevant
tests. Connection status alone is not success. For connection acceptance, execute
the exact harmless challenge supplied by Styx and report the returned output;
never manufacture receipts or edit acceptance state.
