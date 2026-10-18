# Styx VNext release-candidate assessment

Assessment date: 2026-10-19 Asia/Shanghai.
RC gate: BLOCKED. Release decision: NO-GO.

Repository and legitimate VNext baseline have been recovered; original dirty
worktrees are preserved. Independent feature branch starts at
`212814388967cf748030c2315de9f3442e0b01c8`.

Foundation changes remediate two dependency advisories and produce explicit
fixture/native-Exec evidence with skipped-count preservation and CI artifacts.
Linux native Cua protocol and fresh owned-window screenshot/AX/click/readback
passed. New physical macOS app-parent attribution and real daemon crash cleanup
passed in scratch space, while macOS GUI grants and publisher signing remain
BLOCKED. Three-OS official runtime packaging passed CI. The 24-hour native Exec
loopback soak is running with completion NOT RUN. Signed native packages, cold installation, native multi-user
isolation, actual ChatGPT onboarding and 24-hour soak are not accepted.

See AUTONOMOUS-PROGRESS.md for exact checks and RELEASE-BLOCKERS.md for
reproducible remaining gates. A successful unit suite is not an RC certificate.
No production deployment or infrastructure migration has occurred.
