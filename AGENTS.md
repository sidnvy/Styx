# Working on Styx

## Product boundaries

- Product source is only src/. Rust owns Gateway, Host, Core, state and policy. Retain mature Codex/Cua/Playwright executors and native Swift/C# bridges; Node is limited to the Browser worker. Use mature, pinned libraries rather than rebuilding standard protocols.
- Preserve Gateway/Host/Core boundaries and the owner's chosen scope in src/docs/rust-core-rewrite/REDUCED-SCOPE.md. Do not add product features or restore a legacy management runtime during convergence.
- Keep task lifetime separate from caller access: Exec tasks and continuation state belong to Host; Gateway must not keep a second task directory or stop Exec on chat cleanup. Host runtime owns task/caller state across protocol reconstruction; ordinary disconnect ends the link, while explicit revocation and local quit enter the existing Host shutdown path. Browser sessions also belong to Host: chat cleanup preserves them, explicit takeover changes only the current operator and invalidates old references, and close/capability disable/Host exit ends them. Gateway holds no second Browser directory; Cua keeps upstream concurrency.
- Start with the platform framework or upstream executor's normal behavior. Add a process, durable state or protocol only for a concrete user-visible requirement. When ownership moves, remove the superseded path and verify the change through its normal entry point. Keep the runtime stop reason separate from observed cleanup facts; clients consume the same result instead of inferring cleanup from an error code.

## Default development loop

- Work in the existing project and native cache. WORKSPACE.md maps paths and commands; read only the relevant section. On the workstation, integrate into /home/sid/Developer/Styx on develop; origin is GitHub.
- Reuse the existing development command and cache in WORKSPACE.md. Match build settings to the warm artifacts and size parallelism to observed resources.
- Develop and reproduce locally before release production: incremental affected-crate check, the changed scenario, and actual native execution when runtime behavior needs it. A typecheck is sufficient for a typecheck task, not for a startup/recovery fix.
- For a product behavior change, trace every existing user entry point (main window, settings, menu/tray, CLI). Remove superseded controls and their dedicated callbacks; checking one surface or the shared Core is not proof that the other surfaces agree. When changing a shared executor interface, inspect its platform-gated consumers and compile the affected native targets. Update affected tool contracts and test inventories before the full integration gate.
- For conversation concurrency, verify two independent owners on the same Host, including overlapping calls and continued use after the other owner closes. Reads must not probe or lock unrelated owners. One conversation using two Hosts does not cover this boundary. Trace platform-specific admission paths; a Mac-only removal does not establish Windows/Linux behavior.
- A candidate freezes release outputs; it is not a development project, cache or prerequisite for every GUI run. Run workspace quality at integration/release checkpoints. Reuse unaffected evidence; rerun when a relevant change, failure or uncertainty justifies it.
- Reuse existing installation paths and persisted profiles for authorized fixes and recovery. Do not accumulate new acceptance scopes or isolated projects for each step; keep ordinary disposable unit-test fixtures separate from product delivery.
- Continue authorized implementation and verification to the requested outcome. Reuse existing authorization; do not invent per-step approval gates. Respect tool permissions and ask only for genuinely missing authorization or a required human-only action; keep independent work moving.
- Do not add unrequested runtime security or validation layers. Signed payload verification belongs at install/update; ordinary startup, status and pairing must not repeatedly scan the whole package or impose payload ACL requirements on shared parent directories. Preserve OS signing, pairing and private credential boundaries. Fix scope deviations in the implementation rather than asking the user to change permissions or reinstall around them.

## Task-specific guidance

Read a skill only when its trigger applies; do not load all references or historical checkpoints.

| Task | Workflow |
| --- | --- |
| Native GUI/Core behavior, lifecycle bugs, or desktop build/run wiring | .agents/skills/styx-native-development/SKILL.md |
| Release freeze, signing/packaging, installation or cross-device/account acceptance | .agents/skills/styx-release-acceptance/SKILL.md |
| Architecture or interface changes | [Confirmed product behavior and role ownership](src/docs/rust-core-rewrite/REFACTOR-PLAN.md); the [architecture index](src/docs/rust-core-rewrite/README.md) routes to implementation contracts |
| Delivery status or next acceptance exit | Current checklist in src/docs/rust-core-rewrite/END-TO-END-DELIVERY-PLAN.md |

## Ownership and safety

- Give parallel writers disjoint paths/devices. The integrator owns shared contracts, manifests/locks and Git integration; native owners operate their platform clients in the same persistent project/chat.
- Serialize shared Gateway shutdown/replacement with client Runtime updates and lifecycle acceptance. Build independent devices in parallel, but keep their common connection stable while draining or updating a client. Installing a new App does not prove its persisted Runtime selection changed; report completion only after the selected manifest and actual running Core match the intended release.
- Default to no new worktree. If isolation is necessary, record owner, reason and retirement; use only /home/sid/Developer/worktrees/Styx, at most two additional trees including retained historical S. Before removal, preserve HEAD and owned dirty inputs; protect live paths.
- Preserve profiles, pairing, signing identities and publisher pins. Never transfer signing private keys, disable the sandbox, modify production Tunnel/plugin state, operate piermini or reboot the development workstation.
- Do not automatically replay a state-changing operation with an unknown outcome. Resolve it with fresh read-only evidence; an established not-dispatched result permits a fresh authorized attempt. This does not prohibit read-only diagnosis or rerunning isolated local tests. Native actions need a fresh target-bound observation.

## Evidence

Use the current delivery checklist, not historical checkpoints, to choose remaining work. Before adding a blocker, check the confirmed product scope and existing evidence. Record structural cleanup with concrete callers and a deletion target; do not invent a new manager or compatibility layer to make old paths coexist. Keep historical results separate from current acceptance, and do not promote deferred features into release gates.

Report what changed, what actually ran, and the remaining blocker. Separate checks, packages, installation and real independent effects. Keep plans and history out of completion claims. Stable remains NO-GO until its explicit gates close.
