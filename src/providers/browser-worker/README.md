# Thin Browser native worker

This is the external Node Browser executor, not a second Styx Host. Rust alone owns authorization, owner/session/resource binding, URL and file policy, serialization, snapshots, cancellation certainty, Unknown history and cleanup admission. This process attaches to the Host's Extension Bridge WebSocket CDP relay (`ws://127.0.0.1:<port>/devtools/browser/<id>`), operating the user's real Chrome/Edge/Chromium browser without launching a separate headless or managed browser instance.

Start with the pinned Node 22 executable:

`node worker.mjs --config /absolute/private/startup.json`

The Rust-created `0600` configuration has exactly `schema: 1`, `cdp_endpoint`, `output_dir`, `workspace_dir`. The directories are canonical absolute paths and already exist (with `/proc/<positive-pid>/fd/<decimal-fd>` accepted on Linux for Rust-held File pins). Unix ownership/private modes are defensively checked here; Windows ACL authority belongs to the Rust native adapter.

The stdio protocol uses the official MCP SDK `StdioServerTransport` (256 KiB incoming read buffer). Rust bounds total result frames at 8 MiB and owns admission/output validation.
- Main-frame navigations (`frame === page.mainFrame()`), page open/close, and context close advance `nativeEpoch`.
- Backend/transport exceptions return `browser_native_result_unconfirmed` with `reason: 'result_unconfirmed'` so Rust treats them as `Unknown` rather than automatically retrying; clean Playwright tool errors preserve `isError: true` without `reason` so the session remains recoverable.
- Explicit `browser_close` detaches the Playwright CDP attachment non-destructively (leaving the user's browser and tabs open) and reports `styx_context_closed: true` before exiting cleanly.
