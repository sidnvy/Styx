# Install the precompiled macOS preview

Choose the release asset explicitly labeled for your Mac architecture. An arm64
build is for Apple silicon; it is not an Intel or universal build. The source
archives are optional developer materials, not the end-user installer.

1. Download the Styx disk image or application archive and its published checksum
   from the same official release. The checksum checks file integrity, not an
   Apple-verified publisher identity.
2. Open the disk image, or extract the archive. Quit an existing Styx app before
   replacing it and preserve its private state. Drag Styx.app into Applications.
   Do not run it from the read-only disk image or a temporary download directory.
3. Open Styx from Applications. This preview is not notarized. If macOS refuses
   an unidentified developer, inspect System Settings → Privacy & Security and
   use Open Anyway for this app only if you trust its source. macOS may ask for
   local authentication. Do not disable Gatekeeper for the whole machine.
4. Styx's menu bar provides setup/settings. Its local browser interface is started
   by the app with bundled Node and bundled software; you do not compile anything
   or install a development environment. Keep the private setup link private.
5. Choose a local Gateway plus Host, or join an existing reachable Gateway. Review
   the device name and desired capabilities. Use the explicit setup actions to
   prepare, pair and verify the device. Bundled artifact paths are prefilled.
6. For desktop control, use Styx → Request macOS permissions, then grant
   Accessibility and Screen Recording in System Settings. Quit and reopen Styx
   if macOS requests it. Permission approval is never automated by Codex.
7. Enable desired user services in settings. Stop a foreground Gateway before
   switching it to a background service. Keep Styx open for desktop control.
   Background Host/Gateway service status and app/desktop readiness are separate.

A local setup success does not connect an account plugin automatically. Codex
can guide the separate independent Gateway reachability and account/plugin
connection flow. Local-only Gateway access is not public Internet access.

## Preview limits

This build has no Apple Developer ID publisher identity or notarization. An
ad-hoc signature can change when upgrading; macOS permissions may need to be
approved again after a changed build. Uninstalling/replacing an app must not
silently erase user data or pretend to preserve grants across builds.

The packaged software includes native execution capabilities. Select only the
capabilities intended for this device. Generated local development TLS
certificates last 30 days; automatic production renewal is not implemented.
Do not expose the local settings server publicly.

## Stop or remove

Use settings to stop and disable the installed Host and Gateway user services
first. Quit Styx to stop its desktop helper and local settings process. Removing
the app alone does not uninstall a separately installed user service or erase
private deployment state. Preserve that state for recovery or explicitly remove
only the confirmed Styx-owned state after a private backup. Keep unrelated apps,
SSH configuration, Codex settings and shared runtimes.
