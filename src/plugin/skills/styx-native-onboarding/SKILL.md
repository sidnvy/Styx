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

## Connect a model client

Choose Public HTTPS or OpenAI Private Tunnel during Gateway setup. A computer
joining an existing Gateway uses the connection already configured there.

For Public HTTPS, enter the external /mcp URL and the authentication mode. Use an
HTTPS reverse proxy with a valid certificate and preserve the external Host,
Authorization, MCP protocol/session headers and event stream. For OAuth, publish
the protected resource metadata path, configure the authorization server and the
approved subject IDs, and save the introspection client secret privately. For
Static Bearer, use a client that accepts a custom bearer. Use Styx's model-only
credential and keep owner/admin credentials out of the client.

For OpenAI Private Tunnel, create or reuse the owner's Tunnel and enter its
runtime API key locally in Styx. In the intended ChatGPT account, choose Plugins
> Add > Add custom MCP server. Choose Connection: Tunnel, enter the Gateway's
Tunnel ID, and select Authentication: No authentication. The local tunnel client
supplies the Gateway's model-only bearer. Keep the runtime key in Styx.

Use Styx as the name and upload the PNG saved by setup or Settings. Reuse the
existing connection for this Gateway when updating. A Custom MCP connection uses
the server's tool descriptions and instructions. An optional ZIP export also
includes skills and keeps the saved plugin identity. Neither setup nor export
installs or updates a client account.

Check HTTPS reachability or Tunnel readiness first, then authentication, then
tool discovery. In the actual client, choose **List my Styx computers** and use
the selected device for the authorized acceptance action. Record the actual
response and the exact blocking stage if the path cannot be completed.

## Verify the selected computer

Call `list_execution_environments`, resolve the user's computer to one exact
returned `environment_id`, and call `get_execution_environment_status`. Ask if
the target is ambiguous. Never invent identifiers or reuse session handles from
another conversation. A Host-only CLI may require the hub owner to check its
Gateway connection status; do not infer connected Browser from local startup.

For an authorized capability change, call `set_execution_environment_capabilities`
on that Host with only the requested fields. The Host owns and persists these
settings; an invitation only allows the device to join. Disabling stops that
capability's existing tasks and rejects new calls, while the other capabilities
and pairing remain active. If the update is incomplete or unknown, read
`get_execution_environment_status`; do not automatically resend. A saved setting
does not prove OS permission or native readiness.

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
