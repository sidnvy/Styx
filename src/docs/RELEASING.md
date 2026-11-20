# Releasing Styx

## One source, one build, one distribution

`feature branch -> reviewed PR -> main -> new version tag -> Styx release CI -> GitHub Release`

Local Rust/Cua/App builds are for development and tests. They do not become normal
installation inputs. The macOS compile workflow checks code only; it cannot sign
or publish a competing quick-build package. `develop` is no longer a distribution
source. Existing historical outputs and working profiles are not deleted.

## Cut a release

1. Merge the intended PRs into `main` after required CI/review and affected real
   behavior checks. An unverified feature remains a draft PR; do not hide it by
   changing release gates. Confirm `main` contains the intended commits.
2. In a PR, set the workspace version in `Cargo.toml` and all workspace
   package versions in `Cargo.lock`. Use a new version for changed source. Do not
   replace the existing `v0.4.2` tag/assets with any later 0.4.2 debug build.
   Use an explicit prerelease version when the stable acceptance gates are open.
   Update `src/docs/github-release-notes.md` to describe the actual changes and
   upgrade requirements for this version before tagging.
3. Tag that merged commit with exactly `v<workspace version>` and push the tag.
   Alternatively rerun the same workflow on that tag after inspecting a known
   failed build. Manual dispatch on `main`, `develop` or a feature branch is
   rejected before signing. No branch-only installer publishing is supported.
4. One CI source job checks tag/version/commit/main ancestry before any signing
   environment job runs. The shared gate, public dependencies, three native
   builds, existing signatures and four installers are then produced together.
5. All platforms must succeed before publication. The immutable GitHub Release
   contains Linux desktop, Linux Gateway, Windows and macOS packages, checksums
   and public publisher material. Release notes identify the exact commit and
   CI run. Existing releases are never overwritten. Actions artifacts are CI
   intermediates, not a second distribution channel.

The `release` GitHub Environment accepts version tags (`v*`) only; it does not
permit `develop` signing. Main ancestry is enforced by the existing metadata
producer. Signing identities/pins are unchanged; no private key is transferred.
Windows preview installers are not Authenticode-signed; Runtime publisher
verification still applies. Do not describe that as Windows OS code signing.

## Install and verify

Download every machine's installer from the same GitHub Release. Verify its
published SHA-256, preserve the original configuration and use the existing
platform updater. Serialize shared Gateway and Host replacement so a separate
recovery path remains available. Never re-pair to conceal an upgrade failure.

A copy or completed installer is not deployment acceptance. Record the Release
tag, source SHA, artifact hash, selected Runtime manifest and actual running
binary/Core for each machine. Then verify the affected capability. Gateway and
Host can share a release but use different signed manifests. `0.4.x` alone is
not an identity. Keep the prior working release for rollback.

An unknown update result is inspected, not replayed. Fix an installation failure
in source and cut a new release if needed; do not switch to local recompilation
or manually patch a sealed payload. Do not delete previous evidence, profiles,
keys or a still-used task's working files as "release cleanup".
