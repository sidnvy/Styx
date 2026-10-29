---
name: styx-native-onboarding
description: Guide the owner through Rust Styx setup or joining an existing hub, then verify the explicitly selected native computer through the actual plugin connection.
---

# Styx native onboarding

Use the installed Rust Styx CLI or native Styx App. This package is for an
independent owner-managed Gateway and explicitly paired computers. Discover this
plugin's actual tools and schemas; never substitute another deployment, plugin,
executor or computer when Styx is unavailable.

## Set up the computer locally

For a new CLI installation, have the owner run `styx setup` in their own terminal.
They choose a hub (Gateway plus this computer) or join an existing hub using its
one-use link. Setup confirms mutations and reuses the original enrollment and
service actors. Use the release actually installed; obtain its original public
publisher PEM and externally trusted SHA256 pin from the trusted release handoff.
Never invent download links, pins, tunnel identities, endpoints or signing keys.

On a hub, setup starts the Gateway, requests and approves this exact local Host,
claims it, and only then hands the Host to its Linux user service. Linux services
run as the owner, without sudo or linger. macOS/Windows CLI setup runs foreground
for now; retain that terminal or follow the printed native run commands. The
installed native App may provide its own supported first-run/join flow.

To add a computer, have the hub owner run `styx invite`. Transfer the secret link
through a trusted private channel. On the other computer choose Join an existing
Styx in the App, or Join an existing hub in `styx setup`. Confirm its Gateway
origin and CA fingerprint and compare the request's comparison code on both
computers before the hub owner approves its chosen Browser/Computer Use lanes.
Joining computers use the existing hub owner's plugin; they do not create another
Gateway or duplicate account connection. Do not perform owner approval through
model-facing tools or ask for owner/admin credentials in a conversation.

`styx status` shows the setup profile, service observations and, on the hub, actual
paired connections. A started process or approved capability is not evidence of a
connected lane or a successful native action. If an enrollment, approval, claim,
confirmation or native action has an unknown outcome, preserve its original root,
inputs and transaction identity. Observe/reconcile it; do not request again,
delete locks, edit journals, remove the profile, or silently re-pair.

## Connect ChatGPT

The hub owner configures a Secure MCP Tunnel in their account using
https://developers.openai.com/api/docs/guides/secure-mcp-tunnels and enters its
runtime API key locally in setup's hidden prompt (or an owner-private file for
authorized automation). Never request the key in chat or put it in command
arguments, environment variables, plugin files, logs or screenshots.

Setup exports the verified allowlisted plugin directory and ZIP. Its stable
identity is `styx-native`; its display name may differ to avoid clashing with an
existing plugin. Import/install or update the ZIP through the account's supported
plugin workflow. The MCP connection declares `tunnelId` and No authentication:
the local tunnel client supplies the Gateway's model-only bearer. This does not
remove the Gateway's authentication requirement. The tunnel is the account MCP
route; it does not replace the computer's pinned HTTPS/WSS route to its hub.

Check the intended account/workspace and its actual tunnel/plugin permissions.
Local TLS discovery, transport readiness, export and installation are separate
checkpoints. None proves that the account has made a tool call. First test prompt:
**List my Styx computers**. Report the actual response or exact blocker; never
manufacture account acceptance or treat a local SDK test as a ChatGPT request.

## Verify the selected computer

Call `list_execution_environments`, resolve the user's computer to one exact
returned `environment_id`, and call `get_execution_environment_status`. Ask if
the target is ambiguous. Never invent identifiers or reuse session handles from
another conversation. A Host-only CLI may require the hub owner to check its
Gateway connection status; do not infer connected Browser from local startup.

Use the packaged CLI skill for commands, files, Git and builds. Use Browser
Automation for supported web tasks and Computer Use for native GUI tasks, with
fresh target-bound observations. Do not open a GUI terminal or use OS scripting
to bypass an unavailable Exec/Browser/Computer Use tool or denied permission.
The owner handles OS permission grants, account login and MFA personally.

For acceptance, run the exact authorized harmless command on the selected
computer and independently read its visible file effect. Open/read a Browser
page when that lane is requested; observe an actual desktop target before and
after a Computer Use action. A dispatch response, synthetic fixture, test count,
package or service registration is not independent native-effect evidence.
Unknown actions are observed before another mutation is considered. Report the
exact environment, observed effects, cleanup and remaining gaps honestly.
