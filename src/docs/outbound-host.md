# Styx outbound Host runtime (VNext preview)

The native Host initiates ONE authenticated outbound WebSocket to Styx Gateway.
This is an opaque transport for existing Codex Exec Server JSON-RPC, not a
second Styx execution protocol. Gateway retains its model-facing MCP tools
exec_command and write_stdin, with optional environment_id routing.

~~~
ChatGPT -> MCP Gateway -> Host Resolver -> outbound WebSocket
                                           ^
                                     Styx Host Connector
                                           |
                                    Codex Exec (stdio)
                                           |
                                        Host OS
~~~

## One-time provisioning

Native Host prerequisites: Node 22+ and official pinned Codex CLI. The isolated
preparation helper supports Linux x86_64, Apple Silicon macOS, and Windows x86_64.
It downloads rust-v0.163.0 and verifies a fixed SHA-256, without system install:

    python3 host/prepare-codex.py --output /EMPTY/ISOLATED/HOST/DIRECTORY

Create a private Host configuration (host/config.example.json) with matching
host_id and Gateway URL, and a private random per-Host bearer token file. Put
the same token in the Gateway target registration, but DO NOT reuse the MCP
inbound token. Unix token file permissions must be 0600; on Windows restrict
the ACL to the trusted user. Configure the Gateway catalog:

    {
      "id":"example-host","kind":"host","platform":"linux",
      "generation":"generation-1","allowed":true,
      "cwd":"/home/operator","shell":"/bin/sh","shells":["/bin/sh"],
      "exec":{"transport":"outbound",
              "token_file":"/secure/gateway/host-token"}
    }

Verify with a read-only preflight, then launch the Host connector:

    node host/doctor.mjs /private/host.json
    node host/connect.mjs /private/host.json

The Host connector spawns and supervises Codex Exec via stdio; it does not
listen on an inbound port. A service supervisor may restart the Host connector
after login or reboot, but the preview does not register system services,
change OS permissions, or install packages for you.

For an unattended production installer later: Linux systemd --user, macOS
per-user LaunchAgent, and Windows interactive-user Scheduled Task can supervise
the same Node Host binary. macOS native GUI TCC permissions still belong to a
signed Styx.app/Cua process, not this generic Exec Host child.

## Network configuration

- Use WSS for all non-loopback hosts. Plaintext WS is permitted only for
  loopback smoke tests.
- Operators own LAN/WireGuard/reverse-proxy network reachability and CA trust.
- Gateway may terminate TLS directly with STYX_TLS_CERT_FILE and
  STYX_TLS_KEY_FILE or run behind an operator-controlled TLS reverse proxy.
- One authenticated connection is accepted per registered Host ID.
- Duplicate Host peers receive 409; unregistered/denied receive 403;
  invalid bearer and browser-origin upgrades receive 401.
- Host access and token revision are rechecked. Gateway heartbeat detects
  dead connections. Disconnect invalidates old process session identity.
- A reconnect creates a new Codex Exec session. Mutating operations are NEVER
  retried after an ambiguous transport failure.

## Current limits

This preview transports Codex Exec RPC ONLY. Native Cua uses a separate,
private authenticated MCP transport until the Host-outbound Computer channel
is implemented and tested. No durable job continuation through disconnect,
multi-tenant policy engine, automatic machine enrollment, or product deployment
is included. Existing production Charon, Coder, Tunnel and Styx remain unchanged.

## Local secure listener example

    STYX_MCP_TOKEN_FILE=/private/mcp.token \
    STYX_ALLOWED_HOSTS=gateway.private.example:8795 \
    STYX_TLS_CERT_FILE=/private/server.pem \
    STYX_TLS_KEY_FILE=/private/server-key.pem \
    STYX_LISTEN_HOST=10.0.2.19 STYX_LISTEN_PORT=8795 \
    node gateway/cli.mjs /private/targets.json

Match the TLS certificate SAN to the configured private Host URL. Do not
expose a test Gateway to the public Internet without deployment hardening.


## Optional mTLS Host identity (no shared bearer token)

For unattended Host pairing without copying a symmetric secret, Styx accepts
a certificate-pinned Host over WSS. Each Host retains its own TLS client
private key; only the public certificate SHA-256 is registered with Gateway.

In Gateway target config use client_certificate_sha256 (64 lowercase hex
characters) INSTEAD of token_file. On the Host use client_cert_file,
client_key_file and optional gateway_ca_file; omit token_file entirely.
Gateway HTTPS requests client certificates; on the Host WebSocket upgrade the
exact SHA-256 of the presented DER public certificate must match the trusted
target registry entry. No certificate, an untrusted certificate or plaintext
WS fails closed. The model-facing MCP endpoint retains separate bearer auth.

For a private pilot, use short-lived test-only certificates. A production
installer needs a key rotation, credential lifecycle and revocation design.
Never disable TLS server verification or publish pilot private keys.


## Physical cross-host acceptance — 2026-10-18

A native macOS Host connected outward over a private VPN to a Styx Gateway
running on a different Linux machine. The Gateway verified the Host's pinned
mTLS client certificate. A separately authenticated MCP client then executed
a real Codex Exec Server 0.163.0 on macOS through that connection.

Observed PASS: Codex-shaped exec_command, Darwin OS identification, stdout
marker, interactive write_stdin / ACK, and true PTY. No Coder execution
protocol, local AI agent, or SSH execution path was involved. The tests used
scratch directories and temporary WSS services only.

This demonstrates remote Exec routing, not native Cua GUI-over-outbound,
long-task durability, or a production deployment. The temporary Gateway
listener was stopped after testing. No user-specific IPs, Host credentials or
private certificates are recorded in the repository.
