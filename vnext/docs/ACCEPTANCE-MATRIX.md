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
| Owned native Linux GUI | BLOCKED | native_wayland_session_required in current native command environment |
| Native Windows lifecycle/GUI | BLOCKED | no Windows execution backend in this chat |
| Native macOS lifecycle/TCC | BLOCKED | no macOS execution backend in this chat |
| Signed/notarized production distribution | BLOCKED | publisher/platform signing identities not supplied |
| Independent cold install | NOT RUN | native product packaging incomplete |
| Distinct-account physical isolation | NOT RUN | needs separate native OS users/session contexts |
| Actual ChatGPT authorization/onboarding | BLOCKED | account-side product integration not supplied |
| 24-hour per-platform soak | NOT RUN | requires stable isolated native deployment and elapsed runtime |
| Feature-branch three-OS CI | NOT RUN | pending PR run |

Same native account installations provide logical separation only. Mocked
launchctl, fixture binaries, compilation and schema-only smoke never satisfy
physical service recovery, signed-app consent or GUI action acceptance.
