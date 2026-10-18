# Isolated native Linux Exec soak

This is a native loopback Gateway -> outbound Host -> checksum-pinned Codex
Exec test. It creates fresh private test state and supervised test children;
it does not install/modify a production service, change OS permissions, or
exercise GUI/native packaging/ChatGPT. A transport soak is one reliability
check, not full platform acceptance.

Prepare the fixed executor, then from vnext:

    python3 packages/styx-exec-adapter/prepare-runtime.py
    node host/exec-soak.mjs /absolute/new/private/soak-root 86400 60

The state root must not already exist. Durations are seconds; bounds are
1–172800 seconds and intervals 1–3600 seconds. A short smoke may use 2 and 1;
that does not satisfy the 24-hour gate. The executable is checked against the
fixed official Linux binary digest before launch. No model-provided command,
remote endpoint, credential or existing Host state is accepted by the harness.

receipt.json stays NOT RUN while phase=running and becomes PASS only after
the requested monotonic elapsed duration and successful exact-output samples.
The 24-hour Exec gate is reported separately; full_platform_soak_24h,
native_gui, installed_service, signed_distribution and cold_install remain
NOT RUN. Interrupted runs record BLOCKED; execution/sample errors record FAIL.
A potentially uncertain command is never replayed. Each new sample is only a
fresh fixed printf marker with login=false.

samples.jsonl records timestamp, monotonic elapsed seconds, exact-output result,
latency, Gateway RSS/heap/CPU and outbound socket connectivity. Resource fields
refer to Gateway/soak process only, not total Host or executor consumption.
The report never includes token values, command output, user env or screenshots.
Tokens/private config stay in the mode-0700 state root and are not CI artifacts.

Stop using SIGTERM to the exact PID in receipt.json; the harness marks its
receipt BLOCKED and terminates only its own spawned connector. It does not
search for or kill other Styx/Cua/Codex processes. Preserve receipts before
owner-scoped removal of this test directory. System reboot, screen lock,
service-manager crash recovery and GUI soak require independent native pilots.
