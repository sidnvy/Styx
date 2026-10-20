# PilotMac preparation recovery — 2026-10-21

The installed App was the dev9 local-certificate build (CDHash
`b9dedace9658d81b1df65e1296f1243f5502c6ec`), while deployment registration still
pinned an earlier ad-hoc build. Preparation and local pairing had already
succeeded. The server correctly paused foreground startup at the explicit signing
migration boundary; refreshing could not complete this migration.

Applied the installed Core's reviewed signing-registration transaction
`e05b30ac3f6689f36035066bc7c4e1b9`. It changed only the App registration and bound
configuration digest, preserving device identities, pairing, credentials and
system permissions. Exact before/after rollback snapshots remain in the private
deployment's `mac-signing-registration-snapshots/` directory. The separate private
review plan is in `signing-migration-20261021-ibkX4G/` under Styx application data.

After a controlled App restart, authenticated foreground observation reported
Host, Gateway, Exec, desktop and browser connections connected. This verifies
connection recovery, not actual tool operations or ChatGPT account acceptance.
No configuration reset, TCC edit or installed-App replacement was performed.

The UI previously offered two buttons invoking the same read-only refresh and
projected this startup block as pending preparation. The source now retains one
Check current status action, describes its read-only behavior, presents startup
reconciliation as Needs review, and explains that an incomplete upgrade requires
repair rather than another refresh. This UI change is not installed in dev9.

Native compilation and protocol-policy regression use a separate testing-only
binary under the authorized isolated PilotMac test directory. Compilation with
warnings as errors and both native protocol/ownership self-tests passed,
including the regression for a signing upgrade incorrectly appearing pending.
The initial compilation invocation used the wrong Swift top-level filename;
the final invocation used the build's `main.swift` convention. Evidence is saved
in task outputs `preparation-recovery-20261021/`.
