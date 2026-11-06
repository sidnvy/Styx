# Styx workspace

The authoritative source is `develop` in `/home/sid/Developer/Styx`. GitHub remote `origin` is `git@github.com:sidnvy/Styx.git`. Product source is only `src/`.

| Purpose | Workstation location |
|---|---|
| Integration source | `/home/sid/Developer/Styx` |
| Shared Git metadata (bare, no source checkout) | `/home/sid/Developer/worktrees/Styx/repository.git` |
| Explicitly retained historical S, detached f112bf1 | `/home/sid/Developer/worktrees/Styx/retained-capability-lifecycle` |
| Future build/evidence output | `/home/sid/Developer/Artifacts/Styx` |
| Current full handoff and new-agent prompt | `/home/sid/Developer/Archives/Styx/handoff-20261027` |
| Private historical refs, patches, verified tar backups and preserved directories | `/home/sid/Developer/Archives/Styx/workspace-20261027` |

Use one integration checkout. A temporary worktree needs a real conflict/isolation reason, a named owner, disjoint file/device leases, and a retirement outcome. Keep at most two extra worktrees, counting retained S. Builds and candidates do not need worktrees. Do not create source checkouts in Documents/Codex conversation directories.

The 2026-10-27 inventory covered 85 registered trees across three related repositories. It consolidated development to two source worktrees and one bare Git database. All 82 retired trees have verified local tar backups. With explicit owner approval, 81 redundant directory copies were deleted. The rust-styx-architecture copy remains because a live Codex executor uses it; do not stop that process for cleanup. The former Git owner's source files and the small extra /tmp copy were outside this deletion list and remain preserved. Historical refs were retained, with older repositories imported under refs/archive/legacy and refs/archive/android. The archive is private and may contain browser/test data: do not push it.

Historical dirty Windows dependency files already match develop; old Windows build and Mac signing changes have successor implementations. The failed Cua experiment remains research history. These were preserved without restoring legacy JS management code. `legacy-local` is only a reference to the archived legacy.bundle, never the publishing destination.

Product scope follows `src/docs/rust-core-rewrite/REDUCED-SCOPE.md`. The old external handoff is historical device/path evidence, not current progress. Candidate 37 closed the reduced v1 journey on 2026-10-29; b31a4dd added the later four-machine desktop/lifecycle acceptance on 2026-11-05. Those changes are now integrated into develop. On 2026-11-07 the owner requested native GUI completion and full Custom MCP end-to-end delivery; see `src/docs/rust-core-rewrite/GUI-CONVERGENCE.md`. November 6 icon/setup test packages are narrower than the full product. Stable remains NO-GO; historical or focused acceptance must not be presented as final-candidate acceptance.

Existing evidence, Rust toolchain and Cargo caches referenced by the handoff retain their established paths. Do not rebuild, move signed installations, change identity/pairing, or replay unknown operations merely because the source directory moved.

No active Codex worktree leases. Retired: `codex-hub-links` (2026-10-29) merged and removed. Post-v1 branches `codex/computers` and `codex/upgrade` merged into develop after v1 (candidate 37) closed; their worktrees were already removed.

Retired: `codex-join-retry` (2026-10-29) merged and removed.

Retired: `codex-computer-busy` (2026-10-29) merged and removed.

Retired: `codex-mcp-sessions` (2026-10-29) merged and removed.

Retired: `codex-styx-setup` (2026-10-29) merged as e693a81 and removed.

Retired: `codex-gateway-networks` (2026-10-28) merged as c98e768 and removed.

Retired: `codex-retire-js-core` (2026-10-28) merged and removed.

Retired: `codex-app-lan-setup` (2026-10-28) merged as 6540762 and removed.

Retired: `codex-macos-browser-cleanup` (2026-10-28) merged as 0b6ebcf and removed.

Retired: `codex-windows-revalidate` (2026-10-28) merged and removed.

Retired: `codex-gateway-lan` (2026-10-28) merged and removed.

Retired: `codex-linux-computer` (2026-10-28) merged as f6f9a42 and removed.

Retired: `codex-role-switch` (2026-10-28) merged as 08b4750 and removed.
Retired: `codex-gateway-tunnel` (2026-10-28) merged as 5186c49 and removed.

Earlier: the 2026-10-27 leases `codex-native-ui-migration-removal` (197351d) and `codex-store-legacy-removal` were merged into develop and retired.
