# Styx CAS Lab — isolated real-ChatGPT acceptance runbook

Status: **local Gateway ready; OpenAI Tunnel and ChatGPT app enrollment pending**.
This runbook intentionally creates no production migration or Coder/Charon changes.

## Current lab profile

- Branch: exp/cas-native-mcp-app-continuation, not main.
- Gateway: workstation, loopback 127.0.0.1:18895/mcp.
- Private state: ~/.local/state/styx-cas-lab/p0-20261018 (mode 0700).
- CAS ledger: private runs/ directory, unrelated to Styx/Charon production state.
- Exact experiment configuration: STYX_CAS_EXPERIMENT_ONLY=1 and
  STYX_CAS_EXPERIMENT_STATE_DIR=<private runs dir>.
- Catalog: {"version":1,"targets":[]} — no real Host or Environment authority.
- Runtime: OpenAI tunnel-client v0.0.16, official linux-amd64 ZIP
  SHA256 d60cdba019bce451bcc3a15478cc5b9cb11270b049f5b56ea39a80b517f8b117.
- Tunnel client copy: ~/.local/share/styx-cas-lab/bin/tunnel-client.
- Only nine CAS experiment tools are published; native Exec/Cua and project
  enumeration are not exposed, even if a caller guesses their tool names.
- Private inbound token: <state>/mcp.token; never put it in chat, Git or logs.
- Private HTTP Authorization header: <state>/mcp-auth-header (Bearer value;
  tunnel-client loads the whole header from this file, not from a CLI argument).
- Launcher: <state>/start-tunnel.sh. It does not work without a new Tunnel ID
  and restricted runtime key. This is intentional.

The authenticated local client has verified tool discovery, MCP App resource
read, and safe start/stop. This is not real ChatGPT Host acceptance.

## OpenAI Platform provisioning — requires a human session

1. Sign into the correct OpenAI Platform organization / ChatGPT workspace.
   If Platform asks for human verification, complete it manually; the
   automated environment must not try to bypass that challenge.
2. Create a **new** private Secure MCP Tunnel named "Styx CAS Lab P0".
   Associate it with the same ChatGPT workspace in which the test plugin
   will be installed. Do not edit the production Charon Tunnel.
3. Create a **Restricted runtime API key** with **Tunnels Read + Use**.
   Creating a tunnel requires the human principal to have
   **Tunnels Read + Manage**. If the existing runtime key already has
   Read + Use on the new tunnel, it may be reused without copying it
   into a ChatGPT conversation.
4. On workstation, place the new ID and runtime key into two private files:
   <state>/tunnel-id.txt and <state>/control-plane.key, mode 0600.
   Enter the API key locally through a masked terminal prompt or approved
   secret manager reference; never paste a secret into ChatGPT or a shell
   command line. Do not put an admin key into the long-lived daemon.
5. Start the tunnel-client using the prepared launcher as a separately
   journaled process, then check readiness with the client doctor/health URL.
   Report only redacted state; do not reveal API keys or Bearer headers.

Official guide: https://developers.openai.com/api/docs/guides/secure-mcp-tunnels
Official CLI: https://github.com/openai/tunnel-client

## ChatGPT custom MCP plugin (separate from production Charon)

1. With tunnel-client running and ready, open ChatGPT Plugins -> Add ->
   Add custom MCP server.
2. Name: "Styx CAS Lab P0". Connection: Tunnel. Choose the newly created
   CAS-specific tunnel ID. Authentication: No authentication (the local
   Gateway still requires the tunnel-client's protected Bearer header).
3. Do not install this lab app for anyone else or expose it as a shared app.
   Confirm the discovered CAS-only tool inventory and controller resource.
4. In a **new ordinary Chat** explicitly request one harmless two-round
   CAS experiment. Let it call cas_experiment_create then
   cas_experiment_present, and finish its CURRENT turn promptly.
5. Record the exact Run ID, due Wake, ui/message dispatch outcome and,
   separately, whether a FRESH ChatGPT model turn actually invoked
   cas_experiment_consume. A Host ACK does not prove model resumption.
6. Repeat first in Web foreground, then background and Mobile only
   after foreground is proven. No user-click bypass or quota circumvention.

Important: existing VNext uses MCP SDK 1.30.1, offering protocol 2025-11-25.
Actual ChatGPT MCP App admission may require an isolated compatibility change
to the experimental Gateway before any Host test can work. Do not modify
production transport and Cua leases to paper over a failing lab handshake.

## Native MCP App v2 diagnostic refresh

After deploying the CAS-only Gateway, verify ChatGPT refreshed the
cas_experiment_present descriptor to ui://styx/cas-continuation/v2.
The old v1 card in a previous conversation remains a stale View.
Use a new ordinary Chat and a new v2 card to test the lifecycle.
Refresh only the isolated CAS Lab Plugin, never production Charon.

The bounded view and view_events contain no prompt text or secrets.
When a repeated ui/message returns exactly -32601, the controller may
feature-detect the documented ChatGPT compatibility entry point and
use it once in the same already prepared Wake. Unknown delivery is
fenced; only the next model Turn's exact consumption proves success.

## Local acceptance / cleanup

From the disposable branch checkout:

    cd vnext
    node --test gateway/test/cas-*.test.mjs
    npm run test:all

The ui/message payload is checked against a pinned upstream JSON Schema
snapshot of @modelcontextprotocol/ext-apps@2.0.3, McpUiMessageRequest.
The application emits ContentBlock[] (not a single object) and will not
dispatch if the Host fails to advertise text message capability.

After testing: stop the journaled lab Gateway and tunnel-client processes;
remove/disable ONLY "Styx CAS Lab P0" custom app and its exact newly created
Tunnel ID; revoke its restricted key only if newly dedicated; preserve a
bounded redacted acceptance report. Do not touch Charon's connected app,
Tunnel ID, runtime credentials, or live service.
