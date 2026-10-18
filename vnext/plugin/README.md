# Standalone Styx plugin source

This directory is a portable plugin template and generator, not an installed plugin. It has no server address, tunnel identity, app binding, credentials, or copied plugin skills. The application source remains in this repository. Actual new connection provisioning and account installation happen during fresh onboarding after the candidate merge.

Generate only after the owner has provisioned an independent Gateway and performed successful authenticated native MCP discovery. Pass an absolute JSON configuration with exactly `connection` and `verificationFile`. `connection` is exactly one of `{ "url": "<actual verified HTTPS MCP endpoint>" }` or `{ "tunnelId": "<actual fresh verified tunnel ID>" }`. These descriptions are not working endpoints and must not be packaged. `verificationFile` is an absolute path to the operator's discovery receipt:

```json
{
  "version": 1,
  "connection": { "url": "<same actual verified HTTPS MCP endpoint>" },
  "independentStyx": true,
  "freshConnection": true,
  "verifiedAt": "<actual ISO timestamp>",
  "serverName": "styx-vnext",
  "tools": ["list_execution_environments", "get_execution_environment_status", "exec_command", "write_stdin"],
  "method": "authenticated-mcp-discovery"
}
```

Include the actual complete discovered tool list. The receipt must be at most 24 hours old and match the exact endpoint/tunnel; old backend and CAS tool contracts are rejected. The generator validates operator-supplied evidence for consistency. It does not authenticate a receipt issuer, perform a live probe, or prove tunnel ownership/freshness itself. A fabricated receipt is not verification. HTTPS URL syntax checking is not evidence of deployment or public reachability. Tunnel IDs must match `tunnel_` plus 32 lowercase letters/digits. The account MCP tunnel and native Host HTTPS/WSS routes are distinct.

```text
node vnext/plugin/package.mjs ABS_CONFIG_JSON ABS_NEW_OUTPUT/styx-native
```

The output parent must exist; the `styx-native` directory must not exist. Invalid inputs create no package. Output is allowlisted: root `plugin.json`, `mcp.json`, and `skills/styx-native-onboarding/SKILL.md`. Verification receipts and config are not included. Bearer auth is declared as `api_key`/`bearer` under server `extensions.com.openai`, without credential bytes. Enter the model-only credential in the supported account connection UI; never reuse owner/admin credentials.

Inspect final JSON and skill frontmatter, then archive this single directory outside itself. Save/install through the supported plugin workflow only after verifying the connection. This generator does not upload or create a cloud plugin. A new conversation must discover the actual tools and complete device pairing/native acceptance before success is claimed.

Run focused tests with `node --test --test-isolation=none vnext/plugin/test/*.test.mjs`. The tests use clearly synthetic in-memory receipts to verify packaging rules; they do not establish a live endpoint.
