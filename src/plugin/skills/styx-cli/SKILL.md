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

A running command returns its own session_id. Use write_stdin only for that owned
session, preserving environment selection. Poll reasonably and report progress.
Do not carry session IDs across conversations. A timeout or disconnect does not
prove failure: inspect the known process or expected artifact before replaying
any mutation. Stop only processes belonging to the authorized task.

Prefer Exec for files, Git, builds and CLI downloads. Do not open a GUI terminal
to work around an Exec error or restriction. Use the Browser skill for web UI and
Computer Use for native GUI operations. Follow user scope for destructive actions,
external communication and installation; a skill is not blanket authorization.

Verify exit status and the actual result, such as generated files or relevant
tests. Connection status alone is not success. For connection acceptance, execute
the exact harmless challenge supplied by Styx and report the returned output;
never manufacture receipts or edit acceptance state.
