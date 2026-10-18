# VNext observed platform matrix

This is tested scope, not a claim of production support or minimum-OS validation.
Pinned components: Styx0.1.0 developer preview, Node 22.23.3, Codex 0.163.0,
Cua 0.36.0, ws 8.22.0, Gateway MCP SDK 1.32.1.

| Target | Status | Actual evidence and remaining boundary |
| --- | --- | --- |
| Linux x64 | PASS | Arch kernel 7.1.5 native signed user-service lifecycle, crash recovery, upgrade/rollback, GUI screenshot/AX/click/readback; ubuntu 24.04 native protocol/package CI |
| macOS arm64 | PASS | Native27.0.1 scratch app compile, Cua EOF cleanup and LaunchServices host attribution; headless macOS CI; GUI and publisher release gates remain BLOCKED |
| Windows x64 | PASS | Windows 2025 CI official runtime packaging, real NTFS checks, PowerShell parsing and Cua protocol; interactive physical task/session/GUI remains BLOCKED |
| macOS x64 | NOT RUN | Node preparer exists and app can target native x64, but full physical Host acceptance and pinned executor provisioning are not established |
| Linux/Windows arm64 | NOT RUN | No admitted pinned full-runtime build/physical acceptance in this program |

PASS applies to the evidence column only, not an independently installed RC.
The app's compile/deployment target macOS 13.0 is not proof that every bundled
runtime supports that minimum. Supported minimum OS/library versions require
separate clean-device testing. Same-account logical instances are not strongly
OS-isolated; distinct OS users/session contexts are required for that gate.
