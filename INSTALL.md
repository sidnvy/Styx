# Install Styx

Start with the [Stable 0.4.0 setup guide](src/docs/stable-setup.md) or [guided CLI onboarding](src/docs/rust-core-rewrite/CLI-ONBOARDING.md).

For ordinary macOS installation, use the DMG and drag Styx.app into Applications. A service PKG is an explicit advanced installation or repair path, not an App prerequisite.

The native Apps and CLI manage the same Core. A joining device uses an invitation from an existing Gateway; it does not create another Gateway or plugin. Preserve device identity, pairing credentials and publisher trust during upgrades.

Source checkout commands use `src/`. Already-built signed packages keep their existing internal layout and must not be edited or relabeled. The repository-root legacy server/plugin was retired; use the native product package and its generated plugin.

See [REDUCED-SCOPE.md](src/docs/rust-core-rewrite/REDUCED-SCOPE.md) for v1 scope boundaries and deferred capabilities.
