# Install Styx

Styx is a Developer Preview. Start with [fresh native onboarding](src/docs/fresh-onboarding.md), [macOS preview installation](src/docs/macos-preview-install.md), or [Linux CLI](src/docs/linux-cli-preview.md). Windows distribution and lifecycle constraints are documented in the [platform service model](src/docs/platform-service-model.md).

For ordinary macOS installation, use the DMG and drag Styx.app into Applications. A service PKG is an explicit advanced installation or repair path, not an App prerequisite.

The native Apps and CLI manage the same Core. A joining device uses an invitation from an existing Gateway; it does not create another Gateway or plugin. Preserve device identity, pairing credentials and publisher trust during upgrades.

Source checkout commands use `src/`. Already-built signed packages keep their existing internal layout and must not be edited or relabeled. The repository-root legacy server/plugin was retired; use the native product package and its generated plugin.

See [release convergence](src/docs/release-convergence.md) for signing, first-account and physical-lifecycle gates that remain unaccepted.
