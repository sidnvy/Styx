# Native configuration CLI · development slice

These commands manage an offline native configuration root through the shared
Rust management API. They do not start Gateway/Host/services, create a paired
identity, migrate an old profile, or change permissions. A saved `running` value
is desired configuration, not a running process. macOS/Windows secure-store
adapters are not implemented by this slice.

Use an existing private, current-user-owned parent directory and a private
schema-1 deployment input. Initialization creates a NEW child; existing/native
or legacy directories are never adopted. Mode and explicit roles must agree with
the deployment. Initial run/autostart are always stopped/disabled.

```sh
styx init --parent-dir /private/owned --name native \
  --deployment-file /private/deployment.json \
  --mode join-existing --manager foreground-cli --host --json

styx plan --native --state-dir /private/owned/native \
  --component host --run running --transaction-id config-1 --sequence 1 --json

styx apply --state-dir /private/owned/native \
  --plan-file /private/owned/native/plan-config-1.json --authorize --json

styx status --native --state-dir /private/owned/native --json
styx transaction --state-dir /private/owned/native \
  --transaction-id config-1 --json
styx recover --state-dir /private/owned/native \
  --transaction-id config-1 --authorize --json
```

For create-local, explicitly select `--gateway` and optionally `--host`; no role
or manager is silently inferred. The deployment must contain the corresponding
known local/remote configuration. These inputs do not select an executable to run
in this configuration-only command family.

Planning writes a new 0600 private review artifact, without changing canonical
state. Its exact target retains unknown extension bytes; stdout contains hashes
and redacted desired-state summaries, not opaque fields or credentials. Artifacts
are limited to1MiB and never overwritten. Do not publish their contents.

Apply binds actual root identity, scope, deployment, before/target bytes and
original transaction. Existing writers refuse admission. Native inspection first
checks format without creating a Rust lock in an old profile; it remains read-only.
Query reports observed stage but does not claim a fresh durability receipt.

Each command is a separate process. Plan/apply may verify and resync an already
complete original Committed tip before continuing. This never fills a pending
phase. Pending or unknown outcomes require explicit original-ID recovery; unknown
temporary/orphan state is retained for inspection. No command replays native side
effects. A lost stdout reply does not undo commit; inspect/recover the same ID.

Errors use curated codes, with exit2 for invalid/conflicting input, exit3 for
unavailable/unsupported/busy input, and exit4 for Unknown requiring inspection.
Output transport failure is separately reported. A failed request does not grant
permission to replace identity, delete locks or create another transaction.

The default legacy `plan`/`status` routes remain distinct. This native-only slice
is not a completed legacy compatibility migration or a release installation path.
Exact source/build/actual-CLI evidence is recorded in the external Owner Control
Report; tests of a development binary are not signed platform acceptance.


## Windows original-Host migration review (development)

The additive `migrate-review` command enters the same Rust management API and
original configuration writer. Existing commands and their arguments are unchanged.

```powershell
styx migrate-review --state-dir D:\Styx\state `
  --runtime-selection-file D:\Styx\candidate.json `
  --transaction-id migration-1 --run stopped --json
```

This Windows-only review may initialize the existing private management journal
namespace. It does not publish a migration plan, exclude the original Startup
link, retire the pairing credential, or change canonical configuration. Other
platforms return Unsupported before reading the supplied paths.

The schema1 response contains `transaction_id`, `plan_sha256`, and
`canonical_plan` (the exact UTF-8 JSON reviewed). Its digest binds the original
configuration and Host roots, original source observations, candidate manifest
and publisher, selected runtime, desired state, transaction and original Startup
maintenance plan. A new candidate, source observation or desired state requires
new review. The digest is an explicit local request confirmation, not a reusable
bearer credential. Executor guard randomness is generated and durably stored by
the original transaction before effects, rather than treated as user input.

This is a development entry: the complete submit/recovery CLI and App flow is
still being connected. Windows native compilation and actual original-identity
migration are NOT VERIFIED for this change. A review response is neither a
migration receipt nor platform acceptance.

### Windows App review integration (development work)

The original private App pipe now accepts `reviewMigration` with `transactionId` and `run: "stopped"`. Review uses the original App HostScope and returns `plan_sha256` with the canonical plan. This is distinct from the foreground CLI manager: its digest cannot be substituted for an App review. An explicit `startMigration` request echoes that digest as `planSha256`; recovery continues only the original transaction. A review request cannot replace an already observed transaction. A failed review retains any original management custody.

Windows startup projection uses the protected Windows directory handles and the existing journal inventory. A later-boot checkpoint is reported as `waiting_for_later_boot`, not a successful commit or an unknown replayable action. Native Windows compile and device acceptance of these changes remain pending. The private App dispatcher/recovery rejection/EOF join/read-only startup scenario group passes locally on Linux; the shared Darwin workspace typecheck passes. Neither proves Windows OS effects.
