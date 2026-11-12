# Styx workspace

This file maps durable locations and development entry points. It is not a delivery log.
Git is the source authority; live device state and acceptance require current receipts.
Read the relevant section rather than the historical record before every edit.

## Projects and caches

| Machine | Product checkout | Native Cargo target | Tools and evidence |
| --- | --- | --- | --- |
| Workstation | /home/sid/Developer/Styx (develop) | /home/sid/Developer/Styx/target | /home/sid/Developer/Artifacts/Styx |
| PilotMac | /Users/it-bootstrap/Developer/Styx/source | /Users/it-bootstrap/Developer/Styx/cache/cargo-target | Persistent project tools/, inputs/, artifacts/, tasks/, scratch/ |
| NAB5 | `D:\Developer\Styx\source` | `D:\Developer\Styx\cache\cargo-target` | Persistent project tools/, inputs/, artifacts/, tasks/, scratch/ |

Origin is git@github.com:sidnvy/Styx.git. Integrate shared changes in the workstation checkout.
Native owners reuse their existing project, source checkout and chat; Git synchronization must preserve leased local changes.
Do not create a checkout, toolchain or cache per candidate. Frozen outputs belong in artifacts.
Use the newest relocation receipts when an old artifact references a former path.

## Local development

On the workstation, use the existing wrapper; it sets cwd and the canonical native target:

    python3 -I -B src/ci/dev-env.py cargo check --locked --offline -p <affected-crate>
    python3 -I -B src/ci/dev-env.py cargo test --locked --offline -p <affected-crate> <case>

Root npm aliases route to src/; useful entry points are test:unit -- --package <crate>,
test:contracts, test:hub-recovery (explicit signed fixture inputs), and quality.
Inspect src/ci/local-tests.py --help for the selected test profile rather than defaulting to npm test.

On native devices, use the persistent project's tools/dev-env or tools/dev-env.cmd.
Reuse its pinned SDK/tool paths and one Cargo cache. PilotMac's logical Swift PCM path
may alias the same physical cache; changing that path can invalidate PCM files.
The Debian container uses a separate pinned environment.

Use check-only for syntax/type diagnosis and real App/Core execution for runtime behavior.
A directly built desktop App still needs its valid full Runtime, original signing identity
and normal qualification checks. Source, caches and outputs live in Developer; the trusted
installed execution path may remain in /Applications or AppData. A DMG/Inno producer is
not required for every development run. Do not overwrite a sealed Runtime to inject a binary.

## Preserved runtime and historical paths

Live profiles in macOS Library, Windows AppData and Linux state directories are runtime
data, not stray build caches. Preserve profiles/keys/pairing, registered MSVC/Xcode and
Codex-managed executors. Signing identity files remain on their original machines.
Do not relocate these as a side effect of source cleanup.

The worktree base is /home/sid/Developer/worktrees/Styx; retained-capability-lifecycle
is historical, not an active development source. The bare repository.git there is shared
Git metadata. Durable historical backups are under /home/sid/Developer/Archives/Styx.
Before cleanup, distinguish tracked source from unique uncommitted work, caches, secrets,
live runtime data and process-referenced paths; Git does not recover all of those.

## Task context

- Current delivery exits and verified evidence: newest checkpoint in
  [END-TO-END-DELIVERY-PLAN.md](src/docs/rust-core-rewrite/END-TO-END-DELIVERY-PLAN.md).
  Stable remains NO-GO until explicit release gates close.
- Architecture and scope: [Rust baseline](src/docs/rust-core-rewrite/README.md).
- Workspace migration receipts and exceptions:
  /home/sid/Developer/Artifacts/Styx/workspace-consolidation-20261111.
- Earlier workspace snapshots, paths and retirement records:
  [historical workspace](src/docs/rust-core-rewrite/WORKSPACE-HISTORY-20261112.md).
  Consult it only for an old path/receipt; its dated commands and status are not current instructions.
