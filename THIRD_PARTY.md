# Third-party components

The native product uses Node.js, the MCP SDK, pinned Codex Exec Server, Cua Driver and Playwright-related browser components. Exact manifests, checksums and notices live under [`src/licenses/`](src/licenses/) and the runtime preparation/build modules in [`src/host/`](src/host/). Each candidate includes its dependency and binary provenance notices.

The repository-root legacy dependency graph and implementation were retired; historical notices remain in Git at `6fd902e`. This source migration changes neither upstream licenses nor installed publisher trust.
