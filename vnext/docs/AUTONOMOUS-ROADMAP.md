# Autonomous RC roadmap

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
clone is retained unchanged for the native Exec soak.

| Milestone | Status | Next executable work |
| --- | --- | --- |
| A Foundation/CI | PASS | Fresh dependency audit, typed receipts, actual native Exec and three-OS checks; integration CI pending |
| B Windows lifecycle | BLOCKED | Review original private-file ACL / signed Node / Scheduled Task recovery changes, port with negative tests, then verify native SID/session and owned-window behavior |
| C macOS lifecycle | BLOCKED | Add stable bundle packaging/signing configuration and TCC readiness checks; run native acceptance when macOS is available |
| D Distribution/onboarding | NOT RUN | Bundle verified Node on each target, native packages, protected credential storage, rotation and offline runtime updates |
| E Multi-user isolation | NOT RUN | Separate native accounts and Gateway realms; adversarial identity, process, GUI and revocation tests |
| F Reliability | NOT RUN | Signed health-gated activation, owner-scoped metrics, crash/reconnect tests and 24-hour soak |
| G ChatGPT | NOT RUN | Deterministic readiness/discovery tools and actual account-side onboarding acceptance |
| H RC | NOT RUN | SBOM/licenses/provenance, signed artifacts, physical evidence and final assessment |

Each implementation milestone requires its own coherent commit and actual test
receipts. PASS applies only to the tested layer/environment. Skipped native
operations remain NOT RUN or BLOCKED. Missing credentials do not block
independent code changes. Never replay an uncertain mutation.
