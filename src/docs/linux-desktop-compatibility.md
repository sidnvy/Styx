# Linux desktop compatibility

The native Computer Use adapter currently supports the audited Arch UWSM/Hyprland launch form. UWSM 0.26.6, 0.27.0 and 0.27.1 are recognized by exact source hashes. All six root-owned source files must match the supported bundle; the five shell/unit files are unchanged across these versions. Unknown files or versions are refused.

A connected command executor does not prove desktop readiness. If the Host records `computer_unavailable` with `desktop_association_unsupported_launch_form`, inspect the installed UWSM version and source integrity. Do not change desktop units, source ownership, or permissions to bypass the check. A new version needs an audited source compatibility update.

Association still independently checks the actual login session, active/unlocked state, process birth and cgroups, exact systemd unit properties, original socket peers, and the running compositor. The supported source list does not supply an Agent registration or OS permission.

The 0.27.0 and 0.27.1 compatibility entries were checked against the signed Arch packages using signing key `B0D65295476606B71F0C6F82A85E811EB4CA2E08`, then against their installed files. Session unit files and the signal-handler bridge remain identical to 0.26.6. The main.py changes concern environment export configuration, application-daemon FIFO handling, descriptions, and the explicitly selected stop job mode; the observed lifecycle bindings remain checked in code.
