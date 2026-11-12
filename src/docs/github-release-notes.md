Styx Gateway runs centrally on moedeu-apps; Windows, macOS and Linux computers join it
as Hosts. Create one Styx connection in ChatGPT for that Gateway.

Choose the installer/runtime matching your system. Runtime payloads are signed with
the fixed Styx publisher; SHA256SUMS covers the downloadable packages. Packages contain
no device profile, pairing or private signing key. Preserve your existing configuration
and identity when upgrading.

Platform signing: the Windows installer currently has no Authenticode signature. The
macOS App uses the existing local certificate and is not Developer ID notarized.
These packages do not claim OS publisher trust. Automated builds do not by themselves
establish new device/account acceptance or formal Stable approval.

Build and release setup: src/docs/github-actions-release.md in the tagged source.
