# Styx

The current native product is under [`vnext/`](vnext/README.md): a standalone
Styx plugin, MCP Gateway, outbound native Host Connector, pinned Codex Exec
Server and Cua Driver. It does not use a Charon plugin, Coder Agent or legacy
execution backend.

Start a clean candidate evaluation with [fresh native onboarding](vnext/docs/fresh-onboarding.md).
Use the `vnext` package and entrypoints for this product; the repository-root
Node scripts and the historical documentation below describe the older server.
Candidate merge is separate from publication and actual account-side acceptance.

## Historical server documentation

> **Repository migration in progress.** The private package metadata, MCP Server identity and portable Plugin template still use `chat-codex` / `Chat-Codex` at v0.3.0. Renaming the repository does **not** update or reconnect existing installations. See [Styx Foundation RFC](docs/RFC-0002-STYX-FOUNDATION.md).

**ChatGPT-native, self-hosted development workspace** with one typed execution API for persistent Hosts and disposable Environments.

Chat-Codex is an independent, MIT-licensed open-source project. It does not require Charon, Coder, Codex CLI, a home-lab setup or a hosted coding agent. It is not affiliated with OpenAI.

## Resource architecture

A **Host** is a machine you maintain. Registration controls access only; it does not confer lifecycle ownership. The Local Linux/macOS Host requires explicit authorization, is non-root and **UNSANDBOXED**.

A **Disposable Environment** is created by a Provisioner. The first real Provider is Docker, with an independent create/start/stop/delete lifecycle. A persistent VM or Docker service may still be a Host if Chat-Codex does not own its lifecycle.

A **Project** is independent working data (repository or project directory). Deleting an Environment does not delete its Project data. A **Connection** is an internal transport contract, not a separate MCP tool family.

See [Resource Ownership ADR](docs/ADR-0001-resource-ownership.md), [Provider Contract](docs/PROVIDER-CONTRACT.md), and [Migration](docs/MIGRATION-v2.md).

## MCP tools (breaking API redesign)

| Resource | Tools |
|---|---|
| Host | `host_list`, `host_status` |
| Environment | `environment_list`, `environment_status`, `environment_create`, `environment_start`, `environment_stop`, `environment_delete` |
| Project | `project_list`, `project_status` |
| Shared target | `target_status`, `target_exec`, `target_list_directory`, `target_read_file`, `target_write_file`, `target_apply_patch`, `target_process_start`, `target_process_poll`, `target_process_stop`, `target_task_list` |

Every shared execution tool takes an explicitly typed admitted target:

~~~json
{"target":{"kind":"environment","id":"dev"},"command":"node --test"}
~~~

or, only when Host registration was explicitly enabled:

~~~json
{"target":{"kind":"host","id":"local"},"command":"git status"}
~~~

Unknown IDs, invalid kind, extra target fields, path traversal and provider/workspace overrides are rejected. Docker IDs, SSH endpoints and PVE-specific details stay internal. No Docker-to-Host fallback exists.

Execution receipts preserve stdout, stderr, exit_code, termination, duration_ms. Background tasks distinguish `running`, `completed`, `failed`, `cancelled`, `lost`, `unknown`; unknown is never success. The old five flat tools were removed. See [Migration Notes](docs/MIGRATION-v2.md).

## Start here

Start with [Connect your devices to Chat](INSTALL.md): give its prompt to your local Codex agent, choose devices and authorize access. The agent uses deterministic setup and verification tools. Host execution and Desktop preparation form the default onboarding path; containers are optional. Desktop access requires its own authorization and verified platform prerequisites. The [operator guide](docs/ONBOARDING.md) documents the underlying steps. The supported installation is a source checkout with `npm ci`; `package.json` is `private: true`, and this guide does not assume an npm registry release or global installer.

## Requirements and installation

- Linux or macOS for Host-only execution, Node.js 22+, npm, a non-root user.
- Linux Docker Engine for optional Docker Environments (macOS Docker Desktop is not yet verified), with a reviewed official pinned Node image and access granted to the trusted Chat-Codex control process. Host-only mode needs no Docker.
- Your own ChatGPT account/workspace/plugin authorization and a secure MCP endpoint or tunnel for ChatGPT integration.

~~~sh
git clone https://github.com/sidnvy/Styx.git
cd Styx
npm ci --ignore-scripts --no-audit --no-fund
# Use NEW separate directories outside the source checkout.
mkdir -p "$HOME/chat-codex-data"
npm run setup -- "$HOME/chat-codex-data/project" "$HOME/chat-codex-data/private" --backend host
export CHAT_CODEX_CONFIG="$HOME/chat-codex-data/private/config.json"
npm start

# In a second terminal, from the same checkout:
npm run verify -- --config "$HOME/chat-codex-data/private/config.json"
~~~

The Host-only sequence above needs no Docker. On Linux, if containers are selected, install and authorize Docker access, pull `node:22-bookworm-slim` before setup, and choose `--backend both` (or container-only `--backend docker`). After starting the server, optionally run `npm run verify -- --config "$HOME/chat-codex-data/private/config.json" --sandbox` for a separate verifier-owned Docker execution check.

Run `npm run setup` without arguments for guided prompts. The positional form above is suitable for scripts. `--port` selects another loopback port.

`--backend host` is the default and requires authorization for unsandboxed access. On Linux, `--backend both` adds an optional Docker Environment; `--backend docker` selects container-only execution and registers no Host.

The setup tool creates a private v2 config and Bearer token in a 0700 directory, 0600 files. A generated `owner_id` identifies Docker resources; project registration remains outside the Environment lifecycle. Credentials must remain outside both your repository and ChatGPT messages. Administrators edit registration in private config while the service is stopped. There is no model-facing Host enrollment tool.

The server binds only loopback (`127.0.0.1:8791` by default), requires Bearer authorization, and rejects unexpected Host/Origin headers. `/healthz` proves only the process is live, not Environment readiness. Never expose this endpoint publicly without a correctly configured private tunnel/gateway.

## Diagnose and verify installation

Run `npm run doctor` or `npm run --silent doctor -- --json` to inspect local
prerequisites and configuration without provisioning containers, changing
system security settings, reading token contents or altering private files.
The script accepts `--config /absolute/private/config.json` or the
`CHAT_CODEX_CONFIG` environment variable.

A fresh system before setup is expected to show `action_required`; Doctor
identifies which prerequisites are missing and what to configure next.
`ready` means **local preflight only**: it is not an authenticated MCP
smoke test, verified ChatGPT account installation, or proof that the graphical
desktop is unlocked. See [v0.4 product plan](docs/V0.4-PRODUCT-PLAN.md).
`npm run verify -- --config /absolute/private/config.json` separately checks authenticated MCP. On Linux, add `--sandbox` to exercise a temporary, verifier-owned Docker environment; it does not execute in your registered Project or Host. Neither check installs the external ChatGPT connection. See [onboarding](docs/ONBOARDING.md) for the complete sequence.

## Provision an Environment

If you selected Docker and registered Environment `dev`, use an authenticated MCP client:

~~~text
environment_status({environment:"dev"})          # absent
environment_create({environment:"dev"})          # created
environment_start({environment:"dev"})           # running
target_exec({target:{kind:"environment",id:"dev"},command:"node -v"})
target_write_file({target:{kind:"environment",id:"dev"},path:"hello.txt",content:"hello\n"})
environment_stop({environment:"dev"})            # stopped, Project retained
environment_start({environment:"dev"})           # stable identity
environment_delete({environment:"dev"})          # container deleted, Project retained
~~~

Docker Environments are non-root, network-isolated, read-only-root, capability-dropped, no-new-privileges, restricted by CPU/memory/PID limits and pinned to a reviewed image digest. The Project path is the only bind mount; no HOME, tokens, secrets or Docker socket. Timeout/output-limit cancellation **stops the Environment** to kill otherwise unconfirmed children. The Docker daemon remains trusted; a container is not a hardened VM boundary.

Host mode is **UNSANDBOXED**. Commands run with the current OS user's privileges, can access files outside the Project, credentials and network. File tool path checks do not sandbox host shell commands. Host connection is not a power state and Hosts are never eligible for Environment lifecycle.

## Plugin extensions

The server advertises `openai/mentions` and exposes `resource_search` as a read-only, **app-only** typeahead search. It returns canonical resource links such as:

~~~text
chat-codex://host/local
chat-codex://environment/dev
chat-codex://project/default
chat-codex://project/default/file/src/example.mjs
~~~

Project file search never creates a Docker Container, does not follow symlinks, hides sensitive/dot files and caps directory depth, entry scans, bytes and results. A mention identifies a resource; it does not grant additional permissions. Compatible legacy mention metadata is also advertised.

Real Desktop selection path (requires a separately installed plugin):

**Work -> @ -> MCP servers -> Chat-Codex -> Search Resource -> Select**

Direct `@resource-name` typing is not a guaranteed trigger. Composer Mentions currently require a compatible ChatGPT desktop client and account.

`chat_codex_home` is a minimal read-only MCP App Home and Conversation Panel with Projects, Hosts, Environments, recent execution results and task receipts. The `ui://chat-codex/home` resource is served as `text/html;profile=mcp-app`.

## Experimental Desktop Capability

Host Desktop is independent of Coder/SSH/WinRM command connectivity. The four APIs are target_desktop_status, target_desktop_observe, target_desktop_act and target_desktop_wait. Desktop is disabled by default. Trusted administrators may opt in a Local Linux Host with capabilities: {"desktop":{"enabled":true,"driver":"hyprland"}}. An Environment cannot inherit the Host GUI.

Observe supports bounded window metadata and ephemeral exact-window screenshots (2 MiB max) with target-bound, one-use snapshots expiring in 30 seconds. Act reports `verified:false`; independently check the expected UI state after dispatch. An uncertain outcome must not be retried automatically.

Canonical Hyprland, Peekaboo and WinApp adapters have native scratch-window acceptance evidence in controlled configurations. That evidence does not install dependencies, admit another session or prove your installation. Host Runner and setup support Linux/macOS command execution. macOS Host setup does not install or enable Peekaboo; Desktop worker exports remain building blocks for separately authorized integrations. Windows native Host installation is not supported. See the [platform prerequisites](docs/ONBOARDING.md#desktop-prerequisites).

See [Desktop Capability ADR](docs/DESKTOP-CAPABILITY.md) and [generic Windows preflight](docs/WINDOWS-ONBOARDING.md).

## Portable Agent Plugin

Root [`plugin.json`](plugin.json), [`mcp.json`](mcp.json) and [`skills/`](skills/) follow Agent Plugins 1.0.0. The root manifest intentionally has no nonstandard top-level `skills` or `mcpServers` field. Offline tests validate against bundled copies of both official Agent Plugins schemas.

**Installation template only:** the `https://chat-codex.example.invalid/mcp` URL is a placeholder, not an operational service. Replace it with your own secure MCP endpoint and configure `CHAT_CODEX_BEARER` using the installing client's secret configuration; do not commit tunnel IDs or tokens. Server-side tokens are not bundled.

Skills: Styx Onboarding, Red-Green-Refactor, Host vs Disposable Environment, Safe Project Operations. Skills are guidance; the Core enforces resource admission.

## Tests

~~~sh
npm test                 # offline units, contracts, plugin schema
npm run test:integration # REAL HTTP MCP Client, Host, Docker lifecycle
npm run test:onboarding  # REAL authenticated first-run Docker verifier
npm run test:all
~~~

The integration suite uses a fresh temporary Project, real Docker Engine, real MCP SDK HTTP transport, environment restart, project data retention, red/green tests, permission boundaries, background tasks, mentions and MCP App resources. When running this suite in a **trusted development container** with the Docker socket, `TEST_TMP_ROOT` must point at a separate bind-mounted **host-identical absolute directory**; the daemon resolves mount paths on the host. Never mount the socket into ordinary disposable Environments.

See [VALIDATION.md](VALIDATION.md) for verified checks and unverified installation steps.

## Limitations

- Implemented backends: Local Linux/macOS Host and Linux Docker Environment only. PVE, Firecracker and other sandbox vendors are **contract-only** future backends, not fake tools.
- No arbitrary Host enrollment, no automatic dependency installation or Environment network exposure.
- Local persisted task receipts are not a distributed task queue; a gateway restart with in-flight tasks yields `lost`. Unconfirmed cancellation yields `unknown`, never success.
- The minimal single-file `target_apply_patch` accepts unified diff context for existing text files up to 32 KiB.
- Real ChatGPT account installation, Desktop Composer Mentions dropdown and sidebar UI acceptance require a separate actual Desktop/client test. MCP protocol tests do not imply they passed.

See [LICENSE](LICENSE) and [THIRD_PARTY.md](THIRD_PARTY.md).

### Optional Desktop Drivers

The Core is not tied to Hyprland, Peekaboo or Windows UI Automation: it
accepts only a validated Desktop driver identifier, then resolves it in an
installer-maintained `DesktopDriverCatalog`. New desktop implementations can
register trusted factory functions without adding MCP tools or OS-specific
fields to shared Target APIs. Driver absence fails closed. Desktops remain
**disabled by default** for all Hosts. See
[Desktop Capability](docs/DESKTOP-CAPABILITY.md) and the optional
[MCP live scratch-window test](scripts/desktop-live-acceptance.mjs).
Release process: [source and Plugin publication governance](docs/RELEASE-GOVERNANCE.md). An approved source change is not automatically an installed Plugin release.
