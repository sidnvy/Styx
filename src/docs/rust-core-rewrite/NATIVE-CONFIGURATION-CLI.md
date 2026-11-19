# Native configuration CLI

These commands manage an offline native configuration root through the shared
Rust management API. They do not start Gateway/Host/services, create a paired
identity, migrate an old profile, or change permissions. A saved `running` value
is desired configuration, not a running process. These statements concern the
offline configuration commands below; Linux service commands have their own
OS effects. Platform acceptance is recorded
against each exact candidate, not inferred from this command reference.

Use an existing private, current-user-owned parent directory and a private
schema-1 deployment input. Initialization creates a NEW child; existing/native
or legacy directories are never adopted. Mode and explicit roles must agree with
the deployment. Initial run/autostart are always stopped/disabled.

```sh
styx init --parent-dir /private/owned --name native \
  --deployment-file /private/deployment.json \
  --mode join-existing --manager foreground-cli --host --json

styx plan --state-dir /private/owned/native \
  --component host --run running --transaction-id config-1 --sequence 1 --json

styx apply --state-dir /private/owned/native \
  --plan-file /private/owned/native/plan-config-1.json --authorize --json

styx status --state-dir /private/owned/native --json
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

## Linux persistent user services

The Linux `service` command uses the selected, verified C08 Rust CLI and a
fixed per-profile systemd user unit. It preserves the original identity,
configuration journal and pairing. It does not enable linger, change login
policy, acquire root privileges, or claim survival across logout. The canonical
profile path must fit the platform Unix socket address limit when Gateway is
selected; an excessive path is rejected before configuration or service effects,
without truncation or a fallback endpoint.

```sh
styx service install --state-dir /private/native --component gateway \
  --transaction-id install-gateway --expected-revision 4 --authorize --json
styx service start --state-dir /private/native --component gateway \
  --transaction-id start-gateway --expected-revision 5 --authorize --json
styx service status --state-dir /private/native --component gateway --json
styx service status --state-dir /private/native --component gateway \
  --transaction-id start-gateway --json
```

`enable`, `disable`, `stop` and `uninstall` use the same explicit transaction,
revision and authorization arguments. Install both roles before starting a
combined profile. A live Gateway remains the single writer for Host start,
role stop and autostart changes. `status --transaction-id` inspects the original
transaction; it never resubmits it. Transaction-target revision and current
canonical revision are separate observations.

The original writer commits desired configuration before the CLI performs the
single corresponding OS request. A committed desired Start or Stop is not an
actual process result. Start observes the fixed signed image and actual manager
invocation. Stop captures the original process birth and cgroup before committing
intent; completion requires that original birth gone, its held group empty and
successful manager exit. Unknown or reply loss requires inspection of the same
transaction and OS state; no automatic retry, force kill or rollback is implied.

A retained service scope can follow only complete same-identity C07 autostart/run
successors. Incomplete history withdraws new execution admission; a committed
stop for that role triggers normal draining. Existing result inspection and
cleanup remain available. Forged environment variables do not grant a service
scope. Current-format CLI and App readers use the same native state.

These commands are available on Linux GNU. Desktop macOS and Windows use the
App-owned lifecycle and normal login startup; there is no export, role transfer
or persistent OS-service repair command. Compilation and local tests do not
establish installed-device or signed-release acceptance.

## One configuration model

`plan` and `status --state-dir` operate on the current native configuration. The
old JavaScript deployment inspection and the `--native` selector have been removed.
`plan` requires the component, desired run state, transaction ID and sequence.
Use `doctor --state-dir` for read-only runtime/profile diagnostics, or `status
[--root]` for the setup installation summary. These commands do not import old
configuration formats. The current state is `native_state_v1`, schema 1;
`native_runtime_v2` releases understand that format. Optional runtime update
history does not create a different reader or configuration type.
