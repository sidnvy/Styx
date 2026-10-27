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

Read `HANDOFF.md` and `NEW_AGENT_PROMPT.txt` in the current handoff directory before resuming product work. The feature goal remains paused in the old conversation; sending the prompt to a new agent explicitly resumes work there. The product checkpoint is 2d6fef4; the workspace-only documentation change adds no product implementation or acceptance. Stable remains NO-GO. Windows first local Host+Gateway connection at 111.13 seconds is not accepted performance; same-metric Mac/Linux timings and service/login/update/install journeys remain open.

Existing evidence, Rust toolchain and Cargo caches referenced by the handoff retain their established paths. Do not rebuild, move signed installations, change identity/pairing, or replay unknown operations merely because the source directory moved.
