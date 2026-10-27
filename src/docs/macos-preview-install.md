# Install the native macOS preview

The default macOS download is a DMG containing Styx.app and an Applications link.
Choose the asset for your architecture: arm64 for Apple silicon, x64 for Intel.
Source archives and ZIPs used for internal build transport are not the normal
installation journey.

1. Download the DMG and its published checksum from the same release. A checksum
   checks file integrity; use the release handoff to check the publisher and
   signing identity.
2. Quit the existing Styx app before replacing it. Preserve its private
   configuration, identity and pairing materials.
3. Open the DMG and drag Styx.app onto Applications. Eject the image, then open
   Styx from Applications. Do not run it from the mounted image or a temporary
   download directory.
4. Use Styx setup to create a local Gateway plus Host, or join the existing
   Gateway with its invitation. A joining device does not create another
   Gateway or plugin. Keep setup links and invitation material private.
5. Enable only the capabilities intended for this device. For desktop control,
   grant the requested Accessibility and Screen Recording permissions in System
   Settings to the original signed Styx app. A CLI connection or successful
   pairing does not grant desktop permissions.

A PKG is an explicit advanced path for a persistent system service or its
same-identity repair. It may require local administrator authentication because
it registers a service outside the App. It is not a prerequisite for ordinary
App installation. Removing or replacing Styx.app does not remove a separately
registered service or its private state.

## Development preview limits

Current development candidates use the retained local development signing
identity and publisher. They are not Apple Developer ID notarized releases.
If Gatekeeper blocks the app, inspect System Settings → Privacy & Security and
use Open Anyway only if you trust that candidate. Do not disable Gatekeeper for
the machine. Permission approval is a local user action.

The native Rust App packaging path now defaults to DMG. Its actual drag-and-drop
installation journey, normal Quit, login recovery and outer App update remain
acceptance gates; packaging code or a successful isolated service PKG does not
establish that these journeys passed. Consult the candidate-specific handoff
for what was built, installed and verified. Preserve the original signing
identity when upgrading; do not treat a new signature as proof that TCC grants
survive.

Account/plugin connection, Gateway ingress, persistent services and headless CLI
operation have separate setup and acceptance. See [fresh native onboarding](fresh-onboarding.md)
for the CLI journey. Installing the app does not connect an account or expose a
Gateway to the Internet automatically.

## Stop or remove

Use the App’s explicit Quit action and require its owned components to stop.
Closing a settings window alone is not Quit. Independently managed CLI or
persistent services have their own stop and removal operations; do not terminate
unrelated processes or delete configuration to make an installation appear
healthy. Preserve private state for recovery, and back it up before any explicit
removal.
