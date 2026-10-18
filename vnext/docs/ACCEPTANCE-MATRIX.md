# Release acceptance matrix

Baseline `212814388967cf748030c2315de9f3442e0b01c8`.
Client date 2026-10-19. These statuses refer to this engineering run;
older pilot evidence remains qualified in acceptance.md.

| Gate | Status | Environment / evidence |
| --- | --- | --- |
| GitHub baseline three-OS CI | PASS | upstream run 39143276897, baseline SHA only |
| Baseline full local tests | PASS | native Linux, actual Codex 0.163.0; some explicit skips |
| Updated fixture/protocol regressions | PASS | Linux Node 26.5.0; 128 passes, 9 skips, receipt logs |
| Updated native Exec | PASS | Linux pinned Codex 0.163.0: 18 passed, zero skipped |
| Cua portable 0.36.0 native schema | PASS | freshly checksum-verified Linux binary, 64 native tools |
| Dependency advisory audit | PASS | full npm audit: zero reported vulnerabilities |
| Owned native Linux GUI | PASS | 7/7 native tests after inheriting real existing systemd Hyprland session; screenshot/AX/click/readback |
| Native Windows lifecycle/GUI | BLOCKED | no Windows execution backend in this chat |
| Native macOS owner/liveness/attribution | PASS | own scratch compile, SIGKILL/EOF cleanup, LaunchServices parent attribution and teardown on native arm64 |
| Native macOS signed GUI/TCC grants | BLOCKED | AX and Screen Recording absent; Developer ID Application identity unavailable |
| Signed/notarized production distribution | BLOCKED | publisher/platform signing identities not supplied |
| Independent cold install | NOT RUN | native product packaging incomplete |
| Distinct-account physical isolation | NOT RUN | needs separate native OS users/session contexts |
| Actual ChatGPT authorization/onboarding | BLOCKED | account-side product integration not supplied |
| 24-hour per-platform soak | NOT RUN | requires stable isolated native deployment and elapsed runtime |
| Focused feature-branch three-OS CI | PASS | PR27, PR28, PR31, PR32 native jobs; macOS owner PR29 compile/liveness PASS |
| Integration-branch CI | NOT RUN | pending publication/run |

Same native account installations provide logical separation only. Mocked
launchctl, fixture binaries, compilation and schema-only smoke never satisfy
physical service recovery, signed-app consent or GUI action acceptance.
