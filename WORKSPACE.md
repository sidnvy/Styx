# Styx workspace

This file maps durable locations and development entry points. It is not a delivery log.
Git is the source authority; live device state and acceptance require current receipts.
Read the relevant section rather than the historical record before every edit.

## Projects and caches

| Machine | Product checkout | Native Cargo target | Tools and evidence |
| --- | --- | --- | --- |
| Workstation | /home/sid/Developer/Styx (shared checkout; PRs target main) | /home/sid/Developer/Styx/target | /home/sid/Developer/Artifacts/Styx |
| PilotMac | /Users/it-bootstrap/Developer/Styx/source | /Users/it-bootstrap/Developer/Styx/cache/cargo-target | Persistent project tools/, inputs/, artifacts/, tasks/, scratch/ |
| NAB5 | `D:\Developer\Styx\source` | `D:\Developer\Styx\cache\cargo-target` | Persistent project tools/, inputs/, artifacts/, tasks/, scratch/ |

Origin is git@github.com:sidnvy/Styx.git. Integrate shared changes into main through reviewed PRs.
Native owners reuse their existing project, source checkout and chat; Git synchronization must preserve leased local changes.
Do not create a checkout, toolchain or cache per candidate. Frozen outputs belong in artifacts.
Use the newest relocation receipts when an old artifact references a former path.

## Output storage

Keep worker inputs, signed runtimes, installers, native build outputs and acceptance
receipts under `/home/sid/Developer/Artifacts/Styx`. Do not use `/tmp` for these
large or reusable files; tmpfs consumes memory and has a separate user quota.
Use `/tmp` only for small disposable files. Native service fixtures also need
short socket paths; use a short fixture directory under the artifact root rather
than placing persistent test data in tmpfs.

The 2026-11-15 retirement of inactive `/tmp` outputs is recorded in
`/home/sid/Developer/Archives/Styx/tmp-20261115/relocation.json`. Historical paths
in old receipts are not current output instructions; use the recorded destination.
The old local test Gateway and Host services have been stopped and removed. Their
profiles are retained under the same archive root in
`styx-host-capabilities-native-20261114/test-gateway`. The default user installation
is intentionally unconfigured for owner-led first installation. Do not move live
profiles to reclaim space.

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

On NAB5, `tools/dev-env.cmd` sets environment variables only; it does not run its
arguments. In the same `cmd.exe` invocation, call it, then call
`"%STYX_VCVARS64%"`, then run Cargo from `source/`. Reuse
`--release --target x86_64-pc-windows-msvc` for the existing native artifacts.
Check Cargo's actual output and exit code; a successful environment setup is not a build.

Native chats open the parent project, outside the source/ Git root. Its AGENTS.md is
the thin pointer in src/ci/native-project-AGENTS.md; its .agents/skills links to
source/.agents/skills (symlink on Mac, junction on Windows). Read source/AGENTS.md
when taking over an existing chat. Resolve skill references in that source checkout.
Do not assume instructions in a child repository are loaded from a parent cwd.

Use check-only for syntax/type diagnosis and real App/Core execution for runtime behavior.
The macOS main window and Settings menu reuse the one `ProductWindowController` window in
`src/host/macos/product-ui/ProductViews.swift`; configured settings content is `ProductSettingsView`
in `ProductSettingsViews.swift`. Native capability changes use `ProductHostCapabilitySettings`.
Verify navigation from the main window, app menu and status menu when changing settings, including
window identity after onboarding and close/reopen. Rendering the same view twice is not one window;
calling Core directly does not prove that the user entry point is connected.
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

- Current delivery status:
  [END-TO-END-DELIVERY-PLAN.md](src/docs/rust-core-rewrite/END-TO-END-DELIVERY-PLAN.md).
- Architecture and scope: [Rust baseline](src/docs/rust-core-rewrite/README.md).
- Workspace migration receipts and exceptions:
  /home/sid/Developer/Artifacts/Styx/workspace-consolidation-20261111.

## Distribution

`src/docs/RELEASING.md` is the single publication procedure. Local native builds
are debug/test inputs only. Distribute versioned GitHub Release assets from the
one tag-triggered GitHub workflow; do not deploy development-branch Actions
artifacts or locally sealed packages as a routine update. Historical artifact
paths above remain evidence/caches, not alternative release channels.
