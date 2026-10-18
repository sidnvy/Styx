# VNext acceptance matrix — 2026-10-19 Asia/Shanghai

Implementation code: `17fd0e0683431bd1c557a06e2fdb2356e9aa1385`. The final documentation commit is discoverable
from this file's Git history; CI and exact observed final head are recorded in
this task's output report and draft PR37. Original developer worktrees preserved.

| Gate | Status | Exact evidence / boundary |
| --- | --- | --- |
| Locate legitimate development lineage | PASS | Original /tmp/styx-cua-session-doc-audit-20261018 atb51cfb0; latest baseline2128143 descends1736a10 |
| Locked dependency audit | PASS | MCP SDK 1.32.1 / Ajv8.20.0, full npm audit zero reported vulnerabilities |
| Fixture/protocol/Host regressions | PASS | 213 total:201 passed,12 explicit platform skips, clean Linux source17fd0e0 under Node22.23.3 |
| Real native Linux Exec | PASS | 19 passed, zero skipped on17fd0e0 including late-output-before-EOF regression |
| Native Cua portable contract | PASS | Fixed0.36.0 schema checks, real native OS CI; GUI not implied |
| Signed bundled native runtime | PASS | Actual Node/Codex/Cua packaging/staging/runtime/tamper tests on Linux/macOS/Windows CI |
| Windows native credential privacy | PASS | Six new actual Windows ACL/storage tests, fresh restricted creation, existing broad/foreign/junction refusal |
| Windows physical lifecycle/GUI | BLOCKED | No authorized independent native Windows pilot in this run; parsing and package CI are insufficient |
| macOS native owner/liveness/attribution | PASS | Native27.0.1 own scratch compile, SIGKILL/EOF cleanup, LaunchServices parent identity, read-only host attribution and teardown |
| macOS signed GUI/TCC | BLOCKED | AX and Screen Recording false; only Apple Development identity, no eligible Developer ID/notary credentials |
| Linux installed managed Host | PASS | Fresh signed Node22/Codex/Cua start/restart/cgroup crash recovery/upgrade/rollback/GUI/uninstall/secret cleanup on56458aa |
| Owner-recovery/revocation negatives | PASS | Wrong realm/id/fingerprint/generation, retired key/invitation, live lane close, persistence/save failure fixture tests |
| Strong physical two-account isolation | NOT RUN | Separate native accounts/session contexts and GUI evidence still required |
| Preactivation health failure retention | PASS | Bounded trusted local callback, signed candidate/bootstrap/helper checks, exact old pointer retention and race/timeout tests |
| Post-switch health rollback/offline runtime switch | PASS | Linux owned-service pilot: two actual official Node versions, controlled health rejection, exact signed prior-byte/pointer restoration, timeout no replay and explicit stopped recovery; Windows/macOS physical behavior NOT RUN |
| JavaScript SBOM/top-level native notices | PASS | npm CycloneDX 1.5,93 components; signed pinned Cua/Codex/Styx notices, Node full upstream LICENSE |
| Complete native binary SBOM/license review | BLOCKED | 2116 source lock entries,9170 resolved edges,18 Git license declarations and bounded verified archives; full binary-equivalence/native/system/build provenance remain unproven |
| Independent cold install/publisher trust | NOT RUN | Pilot uses existing machine/session and ephemeral publisher trust |
| Actual ChatGPT account integration | BLOCKED | Local SDK/status tool tests do not establish account authorization; manual checklist included |
| 24-hour final-code Exec component soak | NOT RUN | Running immutablefb7f0aa under Node 22.23.3; no completion inferred |
| Installed-service/Exec/resource24h soak | NOT RUN | Running immutable17fd0e0 since2026-10-19 01:59:37 Asia/Shanghai, independent owned Linux unit; no completion inferred |
| Full-platform 24-hour service/GUI soak | NOT RUN | Component and service/Exec sampling do not establish full GUI/session or other OS gates |
| Final integration CI | NOT RUN | Pending at documentation snapshot; see PR37/current task report for actual run completion |

All receipts are scoped to their tested source/environment. Physical macOS
permission attribution does not mean permissions were granted. No production
endpoint, tunnel, Charon/Coder installation or unrelated service was changed.
