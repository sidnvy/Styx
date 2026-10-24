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
