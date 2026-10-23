# Passive device discovery and readiness

Authenticated MCP clients can call `list_execution_environments` to discover
only owner-admitted allowed environments, then call
`get_execution_environment_status` with an explicit `environment_id`. There is
no implicit default for status and no admin approval/revocation tool. Owner
approval and revocation remain on the separate enrollment administration plane.
Missing and forbidden identifiers receive the same `environment_unavailable`
error. Replies exclude native paths, endpoints, token files, generations and
credentials. Native Codex and Cua tool schemas remain unchanged. CAS-only
credentials cannot discover or call this gateway tool.

Status is a passive local snapshot. For outbound lanes `connected` means an
open authenticated socket from the current catalog generation; `offline`
means no such socket is currently observed. A connection can become stale
immediately after the snapshot. Inbound WebSocket, stdio and MCP HTTP transports
report `unknown`: this tool never connects, starts a process, consumes a native
slot, or invokes native tools to determine their state. Disabled computer
capability is `not_configured`. OS permissions, usable native readiness, and
versions report `unknown`; socket authentication is not evidence of any of
these. Host announcements do not introduce a new native readiness protocol.

## Manual acceptance in the actual ChatGPT account

This checklist needs the account owner's connector authorization and an
owner-approved Host. Local fixtures do not establish ChatGPT acceptance.

1. Authorize the intended production-profile connector in the intended account.
   List tools and confirm both discovery tools appear while the separate CAS
   profile exposes neither execution nor device discovery/status.
2. List environments and verify only admitted allowed identities appear. Select
   one returned identity explicitly; missing selection must fail even when a
   default execution environment exists.
3. Query an offline outbound Host and verify offline connection with unknown
   permission/readiness/version. Connect its existing native Host service and
   verify connection changes to connected without claiming native readiness.
4. With native permissions absent, repeat status and verify no readiness claim.
   Native actions, if separately authorized for acceptance, must retain their
   original native error/result behavior.
5. Revoke the Host using owner administration, then verify listing omits it and
   explicit status fails identically to an unknown identifier. A model bearer
   must not grant approval, reconnect, revoke, or edit this policy.
6. Inspect returned status for credentials, native paths, endpoints and raw
   errors. Confirm status did not start a process, attach an executor, or claim
   any Cua connection slot.

Actual ChatGPT acceptance is blocked until the account owner supplies connector
authorization; the deterministic HTTP/MCP and relay tests are separate evidence.
