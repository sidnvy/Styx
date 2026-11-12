# Styx Rust core: architecture and task references

Rust is the owner-selected implementation of the Styx management core. Product source is
src/; Codex/Cua/Playwright executors and native OS/UI bridges remain bounded adapters.
The earlier no-Rust choice is superseded.

Read only the material needed for the task. This index is not a mandatory reading sequence.

| Need | Reference |
| --- | --- |
| Current delivery exits, owners, verified results and remaining failures | Latest checkpoint in [END-TO-END-DELIVERY-PLAN.md](END-TO-END-DELIVERY-PLAN.md) |
| v1 scope, exclusions and deferred features | [REDUCED-SCOPE.md](REDUCED-SCOPE.md), which overrides conflicting earlier scope |
| Service responsibilities and architecture | [SPEC.md](SPEC.md) |
| Identity, capability, session, operation, IPC and package contracts | [CONTRACTS.md](CONTRACTS.md) and [CONTRACT-V1.json](CONTRACT-V1.json) |
| Selected contract/lifecycle corrections | [DELIVERY-BOUNDARY-DECISIONS.md](DELIVERY-BOUNDARY-DECISIONS.md) |
| Architectural findings and their evidence | [ARCHITECTURE-REVIEW-20261108.md](ARCHITECTURE-REVIEW-20261108.md) |
| CLI setup behavior and input schema | [CLI-ONBOARDING.md](CLI-ONBOARDING.md) |
| Rewrite task dependencies or an existing leased work item | [EXECUTION-PLAN.md](EXECUTION-PLAN.md) and [WORK-ITEMS.json](WORK-ITEMS.json) |
| Scenario design and independent oracles | [ACCEPTANCE.json](ACCEPTANCE.json) |
| Earlier decisions and research | [DECISIONS.md](DECISIONS.md), [REFERENCES.md](REFERENCES.md) and [GUI-CONVERGENCE.md](GUI-CONVERGENCE.md) |

Dated status inside older documents is historical; it does not override current device
receipts or restart the rewrite from its original R00/R01 tasks. Planning, compilation,
packaging, installation and real acceptance are separate facts. Stable remains NO-GO
until its explicit gates close. Existing user authorization and the current task determine
execution scope; ordinary implementation choices do not require a new design approval.
