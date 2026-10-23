# R08 Linux management-read IPC slice

This is a real isolated transport implementation, not a complete product Control API or native Desktop authentication. macOS/Windows endpoint and child-identity constructors return Unsupported. HTTP/native GUI adoption belongs to R23.

## APIs and trust

- `EndpointRoot::open(existing_private_root)`: reuses secure store validation, checks the safely opened directory identity, pins an owned directory descriptor. Only `control-v1.sock` is derived beneath it, using a short `/proc/self/fd/...` pathname. Requests never select paths. Existing endpoints (including stale endpoints) are not unlinked by bind.
- `ManagementServer::bind(root, ReadHandler)` → `run(CancellationToken)`: Tokio UDS plus kernel connect-time UID/GID/PID and store boot/birth identity. Only the current private-root user receives ManagementRead. `ReadPeer` is not Deserialize; `client_instance` remains an untrusted correlation claim. Linux credential facts do not prove logind/seat/compositor identity, and inherited/passed sockets do not identify each individual writer. No Desktop privilege is granted.
- `ManagementClient::connect(root, ExpectedServer::from_trusted_manager(...))`: expected UID and boot/PID-birth identity must come from a trusted manager/owned launch receipt, not socket self-description. Verify kernel peer and endpoint inode/permissions. No discovery-by-payload or automatic takeover.
- `ReadHandler` receives typed read-only calls and must observe existing state only. `unsupported_read()` is an explicit structured CapabilityUnsupported, not a successful stub. Cancellation and Session registration are refused before a handler sees them; untrusted descriptor params are skipped without constructing their vectors.
- `BackendStdio::from_owned_child(&mut Child)`: take existing child stdin/stdout, record kernel birth identity, use the same bounded/correlated framing. Composition is responsible for verified release/executable inputs and the child's lifecycle; this adapter does not spawn arbitrary paths or kill providers.

## Bounds, framing and timeout

Frozen Control v1 DTOs validate protocol and timeout1..35000ms. Tokio-util LinesCodec is the sole decoder with a 1MiB frame limit. Invalid UTF8/JSON/envelopes and overlong frames close the connection, with no invented response correlation ID. Serializer uses serde_json::to_writer into a thin bounded writer that checks before extending/copying; a huge handler-owned Value is never first copied to an unbounded buffer. Oversize read results produce a small structured wire-budget refusal.

One request per connection is processed at a time; application queue length is zero. The per-connection transport reservation accounts conservatively for geometric input-buffer capacity/read slack, decoded line, gate/typed parsing scratch, and bounded serialized response, rounded up to8MiB. Frozen host64MiB therefore permits8 connections, below peer16MiB. A semaphore reserves a slot before codec buffers are allocated; excess accepted connections are closed, not queued. Kernel socket buffers, allocator overhead and business state already owned/allocated by handlers are not claims of bounded process RSS; Core/provider state needs its own budgets.

Server read deadline starts when a frame is yielded; parsing counts against it. Client/stdio call uses one end-to-end wait deadline for write+response. Expiry drops only a read wait, does not imply backend cancellation/termination, and never dispatches a mutation. Pending request ID is retained before any writes; new requests are refused while pending. `read_pending` continues the same response wait without resending. Protocol/ID mismatch is a correlation failure, not retry permission.

Shutdown closes acceptance, cancels only read tasks, and checks UID/type/device/inode before removing the exact owned socket. Replacement files/sockets are preserved and cleanup reports failure. Explicitly owned child lifetime remains with composition.

## Verification boundary

Tests use private synthetic temporary directories, real UDS connections, an independent child client, and an explicitly owned Python stdio fixture. Their positive/negative controls cover healthy read, unsupported tx, identity spoof fields/scope denial, malformed/oversize frames, read timeout followed by health, bounded output, exact capacity refusal, active-old-server preservation, substituted inode refusal, kernel child identity, and pending-response resumption without duplicate frames. Successful fixture results do not establish product method completeness, signed installation, Desktop Session authorization, service persistence or TCC. Native cross-user ACL denial, full G03 Desktop binding, other platforms and UI/client adoption remain outstanding.
