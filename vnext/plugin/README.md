# Standalone Styx plugin source

This directory is a portable plugin template and generator, not an installed plugin. It has no server address, tunnel identity, app binding, credentials, or copied plugin skills. The application source remains in this repository. The App and CLI now share `onboarding/plugin-flow.mjs` for presentation, create/reuse selection, ZIP export, and separately recorded account actions. Cloud creation, installation, and actual ChatGPT connection are not performed by the local package generator.

Generate only after the owner has provisioned an independent Gateway and performed successful authenticated native MCP discovery. Pass an absolute JSON configuration with `connection`, `verificationFile`, and optional `presentation`. `connection` is exactly one of `{ "url": "<actual verified HTTPS MCP endpoint>" }` or `{ "tunnelId": "<actual fresh verified tunnel ID>" }`. These descriptions are not working endpoints and must not be packaged. `verificationFile` is an absolute path to the operator's discovery receipt:

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

The output parent must exist; the `styx-native` directory must not exist. Invalid inputs create no package. Output is allowlisted: root `plugin.json`, `mcp.json`, `skills/styx-native-onboarding/SKILL.md`, and optional `assets/icon.png`. Verification receipts and config are not included. An App-owned Tunnel declares `auth.type: "none"` for the ChatGPT connection: the local tunnel client injects the model-only Bearer for both discovery and requests to the loopback Gateway. The Gateway still requires that credential. A direct HTTPS target retains `api_key`/`bearer`, without credential bytes, and needs a client that supports that authentication flow. Runtime API keys belong only in Styx; never reuse owner/admin credentials. Declaration correctness and local discovery do not establish actual account acceptance.

Inspect final JSON and skill frontmatter, then archive this single directory outside itself. Save/install through the supported plugin workflow only after verifying the connection. This generator does not upload or create a cloud plugin. A new conversation must discover the actual tools and complete device pairing/native acceptance before success is claimed.

Run focused tests with `node --test --test-isolation=none vnext/plugin/test/*.test.mjs`. The tests use clearly synthetic in-memory receipts to verify packaging rules; they do not establish a live endpoint.

## Guided account handoff

Every installation checks whether the owner is creating a plugin or reusing one in the intended account/workspace. Presentation defaults are usable without customization; display name, a 30-character subtitle, description, and optional PNG icon can be edited. `styx-native` remains the stable package identity when its display name changes. New Host-only computers use their existing Gateway owner's plugin and do not create another.

`onboarding/cli.mjs plugin STATE` reads the same profile as the App. `plugin-profile STATE PRIVATE_JSON --authorize` saves `{presentation,selection}`; `selection` has `mode`, a local-only `accountLabel`, and `pluginUrl` (required for reuse). `plugin-export STATE FRESH_ZIP --authorize` checks the real owned Gateway over TLS, discovers tools and performs the read-only environment-list call, then exports one allowlisted plugin ZIP. This local evidence is explicitly `authenticated-local-mcp-discovery`, bound to the configured tunnel and Gateway identity; it does not verify cloud tunnel reachability or workspace membership. No config, credential, raw receipt, or account remark is packaged.

The App exports via authenticated POST with CSRF. Browser downloads are requested as a ZIP; the macOS shell uses a main-frame same-origin byte bridge with a fixed ZIP filename and a user-controlled native save panel. Cancelling save is not a successful save. A local export receipt means archive bytes were generated, not that a file was saved or uploaded.

The default account flow is ChatGPT Plugins → + → Add custom MCP server → Tunnel → the same Tunnel ID → No authentication → Create as a plugin, followed by installation and a real tool call. It creates the plugin without requiring ZIP import. A ZIP additionally packages the optional Styx onboarding skill; import it only through a supported account import workflow. Neither a ZIP nor the separate Create a plugin authoring entry replaces the live MCP connection. Do not invent an account upload API. Record user confirmations for creation/upload and installation separately. The local receipts say `user_confirmed`; they do not attest remote state. A reused plugin skips new export/upload. A changed Gateway/tunnel or profile invalidates these receipts and requires review. Actual connection is established only by subsequent real chat requests and separately recorded target-chat confirmation; provider identity remains unverified.

Official references checked 2026-10-20: [custom MCP connection](https://developers.openai.com/api/docs/guides/custom-mcp-server), [Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels), [package format and authentication](https://developers.openai.com/plugins/build/plugins). Personal connection does not imply public-directory submission readiness.

Images are optional: bounded PNG only (256 KiB, square 48–1024, 8-bit noninterlaced with validated chunks, CRCs and bounded IDAT). SVG, external assets, embedded text/profiles, EXIF and animation are refused. Use a plain PNG export if an image is rejected.
