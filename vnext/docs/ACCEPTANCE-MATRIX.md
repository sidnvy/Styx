# VNext acceptance matrix — 2026-10-19 Asia/Shanghai

Implementation code: `fb7f0aae9b4f2bb15c71a0f904f2b27000159b2f`. The final documentation commit is discoverable
from this file's Git history; CI and exact observed final head are recorded in
this task's output report and draft PR37. Original developer worktrees preserved.

| Gate | Status | Exact evidence / boundary |
| --- | --- | --- |
| Locate legitimate development lineage | PASS | Original /tmp/styx-cua-session-doc-audit-20261018 atb51cfb0; latest baseline2128143 descends1736a10 |
| Locked dependency audit | PASS | MCP SDK 1.32.1 / Ajv8.20.0, full npm audit zero reported vulnerabilities |
| Fixture/protocol/Host regressions | PASS | 182 total:171 passed,11 explicit skipped, Linux receipt56458aa; final test-only schedule fixes onfb7f0aa |
| Real native Linux Exec | PASS | 19 passed, zero skipped including late-output-before-EOF regression |
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
| Post-switch automatic health rollback/offline runtime switch | NOT RUN | Preactivation API does not implement a service update orchestrator |
| JavaScript SBOM/top-level native notices | PASS | npm CycloneDX 1.5,93 components; signed pinned Cua/Codex/Styx notices, Node full upstream LICENSE |
| Complete native transitive SBOM/license review | NOT RUN | Top-level notices are not a full native dependency audit |
| Independent cold install/publisher trust | NOT RUN | Pilot uses existing machine/session and ephemeral publisher trust |
| Actual ChatGPT account integration | BLOCKED | Local SDK/status tool tests do not establish account authorization; manual checklist included |
| 24-hour final-code Exec component soak | NOT RUN | Running immutablefb7f0aa under Node 22.23.3; no completion inferred |
| Full-platform 24-hour service/GUI soak | NOT RUN | Exec component soak does not cover these gates |
| Final integration CI | NOT RUN | Pending at documentation snapshot; see PR37/current task report for actual run completion |

All receipts are scoped to their tested source/environment. Physical macOS
permission attribution does not mean permissions were granted. No production
endpoint, tunnel, Charon/Coder installation or unrelated service was changed.
