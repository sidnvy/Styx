# App-owned onboarding and acceptance

Styx owns local configuration, device identity, process lifecycle and progress.
Codex guides the user and invokes the same bounded operations; it must not build
an alternative installer, copy internal credentials into chat, or infer success
from a clicked account button.

## Primary path

1. Open the installed App and select **Set up this computer**.
2. Choose terminal/desktop capabilities and approve that scope once. The fixed
   local workflow prepares the Gateway, verifies an authenticated MCP call,
   prepares and pairs the Host, and runs Doctor. Internal preparation steps are
   available under technical details, not separate mandatory confirmations.
3. Choose background/login startup once. The coordinator installs both user
   services, hands off the foreground Gateway, verifies its readiness and reads
   Host status. An interrupted mutation is retained for reconciliation, not replayed.
4. Grant OS permissions when desktop control is wanted. Application permission
   status is distinct from successful screen capture/action acceptance.
5. Connect the account. Where the platform requires a tunnel ID/runtime key,
   the App receives it in a private form and runs the publisher-pinned client.
   It derives its own Gateway address and model credential privately. No YAML,
   command file or internal token handoff is required from the user.
6. Finish only after a real account tool call. Local SDK discovery, process
   liveness and tunnel readiness alone do not establish account acceptance.

## Ownership of settings

- App: device identity, capabilities, OS grants, default device, background
  services, local connection runtime, recovery and diagnostics.
- Gateway: authoritative allowed-device registry and scoped access decisions.
- Account plugin: account/workspace connection and which tools are available to
  the conversation. It does not duplicate Host installation configuration.
- Codex: explanation and assistance using the existing workflow. No independent
  installation state, credentials or model-generated service scripts.

The native macOS settings window uses the same local control plane as advanced
headless administration. Browser sessions use ephemeral bootstrap/CSRF secrets;
external navigation does not inherit the local session. Settings are not a
public LAN administration endpoint.

## Failure evidence from the 2026-10-19 user trial

The previous preview rejected spaces in the default Application Support path;
Host background installation therefore failed. Existing manually running Host
processes must not be mistaken for installed persistent services.

MCP discovery sessions could consume all 32 slots because ordinary idle expiry
was disabled. Abandoned diagnostics that called close() without terminateSession()
also contributed; the evidence does not attribute all sessions to ChatGPT.
Production cleanup now uses a bounded idle policy at capacity while protecting
in-flight calls and retained Exec owners. Desktop slot contention and a missing
default device must remain distinct actionable errors.

The reported desktop permissions subsequently passed, and actual local read-only
desktop and terminal calls passed. This does not retroactively prove the original
account call or a complete calculator task succeeded.

## Acceptance gates

- Native App-owned WebKit loads authenticated setup and removes its fragment.
- Fresh configuration completes the fixed workflow without step-by-step prompts.
- Default paths with spaces and Unicode work through actual plist argv parsing.
- A blocked/interrupted operation is not automatically repeated.
- Gateway and Host service readiness is observed, with the observation time.
- Tools include terminal, device status and desktop capability contracts.
- Discovery-only success cannot pass the Gateway connection verifier.
- Real account terminal and desktop calls, logout/login startup and upgrade
  permission continuity are separate acceptance items with explicit evidence.
