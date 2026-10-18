# Release blockers

Production RC status: BLOCKED. Production cutover remains outside authorization.

| Gate | Status | Reproduction / resolution |
| --- | --- | --- |
| Linux GUI | PASS | Current logged-in Hyprland user environment inherited from systemd; 7/7 native tests and independent owned-window readback passed |
| Windows native lifecycle | BLOCKED | On a permitted interactive Windows user device test install/status/enable/disable/start/stop/remove, restart, signed rollback, locked/logout refusal and exact owned-window UIA readback; never Session 0 |
| macOS signed app | BLOCKED | Supply reviewed stable bundle identity and signing/notary configuration, build Styx.app owning Embedded Cua, obtain user TCC consent, verify signed upgrade and rollback on native macOS |
| Publisher trusted artifacts | BLOCKED | Configure independent publisher trust and platform credentials; ephemeral developer keys prove only staging/signature mechanics |
| Cold install / bundled runtime | NOT RUN | Build per-OS packages containing locked runtime and pinned upstreams; install without old managed agent, then pair/execute/revoke/recover |
| Strong native-account isolation | NOT RUN | Execute docs/multi-user-isolation.md negative gates with two actual OS accounts and separate Gateway realms |
| Runtime health and soak | NOT RUN | First establish isolated signed stable Host service, then persist 24h resource/reconnect receipts; never infer elapsed soak from unit tests |
| ChatGPT product acceptance | BLOCKED | Register isolated Gateway using actual account authorization, explicitly select device, verify readiness and end-to-end execution; local MCP SDK is insufficient |

Independent implementation is still available for Windows/macOS packaging,
protected state/ACL, native readiness, update health checks, negative isolation
and observability. These external gates do not justify stopping that work.
