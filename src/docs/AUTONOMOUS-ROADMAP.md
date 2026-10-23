# Autonomous RC roadmap

> Historical development record. Its checkout paths, build versions and acceptance claims apply only to the recorded revision. Current source and release gates are described in [release convergence](release-convergence.md).

Client date: 2026-10-19 (Asia/Shanghai). Production cutover is outside scope.

## Source and integration ownership

Workstation is the native m600 Linux host (the existing host registry maps
Workstation to m600). Original VNext checkout:
`/tmp/styx-cua-session-doc-audit-20261018`, HEAD
`b51cfb06a8786c021ba20e2da441d117cd176536`. It contains uncommitted changes;
it was inspected read-only and must not be reset, cleaned or overwritten.
A second older checkout is `/tmp/styx-vnext-crosshost-gateway-20261018`.
The CAS experiment checkout is `/tmp/styx-cas-exp.Lyv1PNd9/repo`.

GitHub repository: https://github.com/sidnvy/Styx
Development ref: `feat/styx-vnext-unified-runtime`.
Selected baseline: `212814388967cf748030c2315de9f3442e0b01c8`, a two-commit
descendant of requested reference `1736a10ab9922c7d95f39f8f5d9dcba754a301aa`.
The selected baseline includes merged CAS experiment PR #26, disabled by default.
No open PRs were returned by GitHub at reconnaissance.

Dedicated independent clone:
`/home/sid/Documents/Codex/2026-10-19/files-pasted-by-the-user-styx/work/styx-vnext`.
Branch: `feat/vnext-rc-foundation-20261019`; initial working tree clean.
Do not treat this clone as the pre-existing developer checkout.

## Milestones and next executable work

Active integration worktree is `work/styx-vnext-integration`; original independent
clone retains the shared Git directory; immutable Exec soak uses work/styx-vnext-soak-final.

| Milestone | Status | Next executable work |
| --- | --- | --- |
| A Foundation/CI | PASS | Locked audits, native Exec and three-OS checks; final successor integration checks tracked per SHA |
| B Windows lifecycle | BLOCKED | Native private storage/config/signing-key checks and Scheduled Task implementation exist; physical interactive lifecycle/GUI remains required |
| C macOS lifecycle | BLOCKED | Stable app, native owner/liveness and packaging exist; Developer ID/notary/TCC GUI evidence required |
| D Distribution/onboarding | NOT RUN | Signed bundles, Node, private enrollment and recovery exist; clean-device installation/persistent publisher trust remain |
| E Multi-user isolation | NOT RUN | Adversarial realm/session/credential tests exist; distinct native accounts still required |
| F Reliability | NOT RUN | Post-switch rollback/offline runtime recovery has real Linux evidence; component soak running, independent managed-service/Exec/resource soak running from frozen17fd0e0 |
| G ChatGPT | BLOCKED | Passive deterministic discovery/status tools and manual checklist exist; account-side authorization required |
| H RC | BLOCKED | Native source dependency/license inventory underway; signing, binary-equivalent SBOM, physical and soak evidence remain |

Each implementation milestone requires its own coherent commit and actual test
receipts. PASS applies only to the tested layer/environment. Skipped native
operations remain NOT RUN or BLOCKED. Missing credentials do not block
independent code changes. Never replay an uncertain mutation.
