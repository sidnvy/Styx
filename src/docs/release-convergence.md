# Release convergence

> Current direction: see [Rust core rewrite](rust-core-rewrite/README.md). This page describes the legacy convergence/candidate baseline; its source/test/package results are not Rust implementation or acceptance.

Product scope and Gateway/Host/Core separation are frozen. Exec uses the pinned Codex execution protocol; Browser and Computer Use are independent execution capabilities. No additional Agent reasoning layer or management authority is introduced.

## Canonical source and compatibility

`src/` replaces the former `vnext/` repository directory. The old root server, desktop adapters, plugin and Docker onboarding implementation were retired, with the complete source preserved at `6fd902e` and in Git history. Root npm commands target this source only. Independent provider locks remain independent; this migration does not hoist or change dependency versions.

Native package members such as macOS `onboarding/vnext/` and Windows `vnext/` remain unchanged because launchers, update transactions and signature manifests bind those paths. The existing `styx-vnext` MCP identity and `styx-vnext-*` service compatibility patterns also remain. Historical `git show <old-revision>:vnext/...` reads must retain the old path. These compatibility strings do not indicate another source tree.

## Evidence before source migration

The frozen rc16 source `6fd902ef675f5035e7fa9225dfaa6aee1a604091` passed a full local gate: 1145 PASS, 0 FAIL, 57 explicit skips. Windows isolated same-identity install/update, Pause, independent CLI refusal, persistent capability Apply, real Exec/Cua/Browser and ordinary Quit/reopen passed. Linux rc16 package/permission guards passed; the complete rc15 native pairing journey and older desktop/headless evidence retain their own versions. Intel Mac build1023 compiled strictly, but was not a finalized signed delivery.

These are historical baselines, not acceptance claims for the renamed source. After migration, a fresh quality receipt and new candidate version are required; never relabel rc16 archives.

## Open release gates

- Original Windows Pair: the latest pinned TLS probe succeeded, but its self-device capability endpoint returned404. Upgrade that Gateway through the authorized same-identity path before the original Pair lifecycle journey; do not replace pairing to hide the gap.
- Windows physical boot/login recovery remains unaccepted. Win32 boot timestamp readings varied by approximately2.546s within the preserved original process lifetime; verify stable boot identity and actual recovery rather than extrapolating from fixtures. Historical cold-login ready145.687s performance remains unresolved.
- Linux historical second Apply capturing failure has unknown underlying cause. Independent full recovery passed and the original owned fixture was formally rolled back. Keep both outcomes.
- Mac stable publisher identity, finalized native delivery, installed GUI/TCC and first-install acceptance remain pending. No alternate/ad-hoc identity may stand in for the existing publisher.
- New-account ChatGPT plugin upload/login and full account-side acceptance remain pending. Direct SDK calls do not establish this gate.
- Windows App/Inno Authenticode and macOS Developer ID/notarization are not established. Preview status must remain explicit.

## Worktree ownership

Use existing integration checkouts. No new checkout for each release or parallel reader. Archive HEAD refs before removing an inactive checkout; preserve dirty files, private evidence, native inputs and dependency consumers. Keep build inputs in explicitly owned caches outside worktrees. Removal counts and retention reasons belong in the Owner Control Report.

## Owner Control Report

Report only changes, with evidence: Product scope; Architecture/authority changes; Integration SHA/cleanliness/worktree count; Release package/install/native acceptance per platform; Reliability unresolved failures; Decision items requiring owner intervention. Preview and Stable gates are separate.
