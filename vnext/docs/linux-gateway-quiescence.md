# Linux Gateway offline observation

The 2026-10-21 native update stopped at `gateway_process_quiescence_unknown`.
The deployment's real user unit was absent, inactive and PID 0, but five
unrelated current-user processes denied `/proc/PID/exe`. Requiring that link
from every process made an ordinary desktop unable to establish an offline
Gateway. A user/PID namespace was not a repair: it lost the real user systemd
bus and also refused the update.

The Linux production observer now combines two independent observations:

1. Enumerate the private installation, reject symlinks and nonregular members,
   and hold nontruncating write-open descriptors for every executable file.
   This includes the stable service Node and every retained generation's Node.
   Linux returns `ETXTBSY` if an inode is currently used as an executable image.
   The code uses numeric `O_WRONLY | O_NOFOLLOW | O_NONBLOCK`, without `O_CREAT`,
   `O_TRUNC`, or a write call. It checks each opened inode against its path again
   before closing. See [Linux open(2)](https://man7.org/linux/man-pages/man2/open.2.html).
2. Inspect every same-user process's complete, NUL-terminated command line.
   A state-directory or installation argument refuses the observation even
   under an external interpreter or after an old executable was unlinked.
   A readable executable path inside the installation also refuses it. A denied
   executable link is resolved only by the independently held inode exclusions
   and complete unrelated arguments. PID start time and argument bytes must
   remain stable during the observation.

An unreadable or malformed command line, a changed PID identity, an executable
probe permission error, an uncertain file inventory, or a failed real systemd
query still produces `gateway_process_quiescence_unknown` or
`gateway_service_quiescence_unknown`. A missing per-process file is ignored
only after the process itself has disappeared. A zombie thread-group leader
with live worker threads cannot stand in for a terminated process.

The real unit must remain `LoadState=not-found`, `ActiveState=inactive`,
`MainPID=0`, with no on-disk unit definition (including a dangling symlink).
No alternate bus, policy change, unrelated process termination, or fake
systemd result is used in native acceptance.

## Startup and evidence boundary

`assertGatewayRuntimeStartAllowed` reads the existing Core advance lock,
Gateway runtime recovery guard and runtime-change journal. It never creates,
adopts or deletes them. An unfinished or malformed journal blocks startup even
when its original process died. Only Core's own in-process advance may allow
its empty advance file; a runtime-change or foreign record remains blocked.
Core and the signed runner check the guard before opening their listeners.

The returned observation names its scope as current installed executable
inodes and supported fixed-argument entrypoints, and explicitly records
`continuousExclusion: false`. Kernel descriptors are held during the process
scan, then closed. The shared operation lock and official startup interlock
serialize product operations; this is not a security boundary against arbitrary
malicious same-user programs that replace inodes and forge their argument
memory. An external or unlinked runtime with uninspectable arguments remains
unknown and cannot authorize an update.

## Native proof

Task output `linux-update-20261021-kernel-proof-20261022/receipt.json` records
actual Arch Linux 7.1.5 results using the official Node 22.23.3 binary:

- A task-owned non-dumpable installed Node denied its executable link with
  `EACCES` and was still refused by the kernel executable check.
- A protected external Node carrying the deployment argument was refused.
- A protected old Node whose inode was unlinked and replaced was refused while
  its fixed deployment argument remained present.
- The five existing protected processes and an unrelated protected task child
  were resolved using complete arguments and independent inode exclusion.
- Node bytes retained SHA256
  `fde6a4bf8d0562f7751d1a2d6cb9b417c4cfe107bbcb0aa3e9a24e125e348f48`.
  The fixture used no write or truncation call on the probed payload.
- All task child processes exited, and private proof files were removed.

Focused tests additionally verify unchanged payload size, modification time
and change time on the same tested inode, retained-generation coverage,
unreadable arguments, live thread groups, malformed observations, PID reuse,
foreign guards and unfinished journals. These are separate from successful
signed application update, rollback and interruption recovery acceptance.


The full changed-application transaction also passed on the ordinary workstation:
`linux-update-20261021-run3-20261022/receipt.json` records historical `4c91cfc`
application sources to the current application (14 changed payload paths),
actual old/new/rollback/recovered TLS MCP startups, offline rollback, real
installer SIGKILL after pointer commit, verified recovery, exact nine-file
preservation and independent cleanup. Node was unchanged at 22.23.3; no reboot
or production publisher acceptance is claimed.
