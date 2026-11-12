# Working on Styx

## Product boundaries

- Product source is only src/. Rust owns Gateway, Host, Core, state and policy. Retain mature Codex/Cua/Playwright executors and native Swift/C# bridges; Node is limited to the Browser worker. Use mature, pinned libraries rather than rebuilding standard protocols.
- Preserve Gateway/Host/Core boundaries and the owner's chosen scope in src/docs/rust-core-rewrite/REDUCED-SCOPE.md. Do not add product features or restore a legacy management runtime during convergence.

## Default development loop

- Work in the existing project and native cache. WORKSPACE.md maps paths and commands; read only the relevant section. On the workstation, integrate into /home/sid/Developer/Styx on develop; origin is GitHub.
- Reuse the known working build command, dependency cache and target directory. Preserve cache-affecting target triple, profile, features and RUSTFLAGS; the same cache root alone does not guarantee a hit. Inspect CPU/memory and the current compile/link stage, then use the available parallelism instead of defaulting to a conservative job cap. Reduce jobs for observed contention, not hypothetical load.
- Develop and reproduce locally before release production: incremental affected-crate check, the changed scenario, and actual native execution when runtime behavior needs it. A typecheck is sufficient for a typecheck task, not for a startup/recovery fix.
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
| Architecture or interface changes | src/docs/rust-core-rewrite/README.md routes to current contracts and decisions |
| Delivery status or next acceptance exit | Latest checkpoint in src/docs/rust-core-rewrite/END-TO-END-DELIVERY-PLAN.md |

## Ownership and safety

- Give parallel writers disjoint paths/devices. The integrator owns shared contracts, manifests/locks and Git integration; native owners operate their platform clients in the same persistent project/chat.
- Default to no new worktree. If isolation is necessary, record owner, reason and retirement; use only /home/sid/Developer/worktrees/Styx, at most two additional trees including retained historical S. Before removal, preserve HEAD and owned dirty inputs; protect live paths.
- Preserve profiles, pairing, signing identities and publisher pins. Never transfer signing private keys, disable the sandbox, modify production Tunnel/plugin state, operate piermini or reboot the development workstation.
- Do not automatically replay a state-changing operation with an unknown outcome. Resolve it with fresh read-only evidence; an established not-dispatched result permits a fresh authorized attempt. This does not prohibit read-only diagnosis or rerunning isolated local tests. Native actions need a fresh target-bound observation.

## Evidence

Report what changed, what actually ran, and the remaining blocker. Separate checks, packages, installation and real independent effects. Keep plans and history out of completion claims. Stable remains NO-GO until its explicit gates close.
