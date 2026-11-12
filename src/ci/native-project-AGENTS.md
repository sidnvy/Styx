# Styx persistent native project

The product Git repository is source/. Read source/AGENTS.md when taking over this
project; its paths are relative to that repository. Follow only the task-relevant
workflow, not all historical documents. This file is a pointer, not a second policy.

Keep this existing project/chat. Use source/ for Git and product commands and the
project's tools/dev-env wrapper for native commands. Cache and output locations are
mapped in source/WORKSPACE.md. Preserve current leases and uncommitted source changes.

The project .agents/skills is a discovery link to source/.agents/skills. Resolve skill
references against that canonical source location. Updates belong in the Git
repository; do not maintain a separate copy of its rules in this project root.
