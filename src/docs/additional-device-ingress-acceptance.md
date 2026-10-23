# Add Computer: additive device entry

The existing localhost Gateway remains the MCP/tunnel endpoint. Add Computer
creates a second exact-interface HTTPS listener on **the same Gateway**, sharing
the registry, enrollment controller, relay and credential generation. It exposes
only enrollment and authenticated outbound Host lanes, never MCP or owner APIs.
`gateway.deviceIngress` in `deployment.json` is the desired authorization. TLS
paths and runtime definitions are derived; no second role configuration exists.

## Operation and recovery

App HTTP and CLI use the same Core prepare, status, retry, rollback and pairing
window operations. An ambiguous interface requires one explicit selection. A
configured entry is not remote reachability evidence. The joining computer must
verify the actual TLS listener and explicitly accept its identity, consume a
limited one-use invitation, compare the current request-bound confirmation, and
claim the credential after owner approval. Its own signed request selects its
capabilities. The owner cannot silently change them during confirmation.

Preparation records its claim before asynchronous preflight and an actionable
transaction before configuration/listener changes. It keeps the primary TLS,
owner/model credentials, local Host identity, tunnel and plugin settings.
Controlled metadata changes keep the full configuration hash valid while the
existing local connection/acceptance binding excludes only the additional entry.
A failed bind preserves the authorized desired image for explicit retry or
rollback. Rollback restores only its recorded configuration metadata and stops
its listener, never rolls back the shared enrollment database or resurrects
revoked credentials. Reopening an already active invitation preserves the
original rollback point.

A fresh recovery guard excludes competing recoveries before stale common locks
are inspected. Lock inode/device and private claim bytes are checked before
mutations. An empty, unknown or leftover recovery guard is deliberately retained
with `device_ingress_recovery_guard_requires_inspection`. Automatic retry and
rollback cannot steal it; an operator must inspect that exact interrupted owner
and recorded transaction. No arbitrary-crash-point automatic recovery is claimed.

Gateway startup restores only the existing authorized descriptor. A temporary
missing address or occupied port retries with 1/2/4/8/15-second bounded backoff,
keeping the exact address, generation and certificate pin. It neither reopens an
invitation nor regenerates identity. Explicit listener operations and close cancel
old retries, including an in-flight attempt. Expired or changed certificates fail
closed. IP changes, certificate renewal and identity replacement require an
explicit migration; this version does not promise unattended certificate renewal
or arbitrary cross-network traversal.

Closing the pairing window invalidates unused invitations while approved devices
retain credentials and may reconnect. Revocation uses the durable shared
controller. An older Gateway application that cannot parse deviceIngress is
refused for upgrade/rollback until the entry is explicitly rolled back; primary
identity is not reset to make a downgrade appear successful.

## Evidence to collect

- Real Core TLS join, request-bound comparison and exact identity approval.
- Original MCP session and actual local Host Exec/Browser still work after Add
  Computer, and after closing the pairing window.
- Physical Windows Host to Linux main: verified TLS, no second Gateway, real
  PowerShell and installed Edge actions, reconnect with unchanged identity.
- Occupied-port failure, explicit retry/rollback and interrupted preflight.
- Recovery concurrency, replaced lock refusal and stale guard retention.
- Old signed application upgrade, offline rollback, interrupted pointer switch
  and explicit recovery, preserving existing TLS/config/credential hashes.

These engineering/native observations do not establish ChatGPT account
installation, GUI authorization, full machine reboot or new-user acceptance.
Those gates must retain their separate actual results.
