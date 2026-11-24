# Installing & Upgrading Styx

Download signed release bundles and `SHA256SUMS` from [GitHub Releases](https://github.com/sidnvy/Styx/releases/latest) and verify checksums before installing:

```sh
sha256sum -c SHA256SUMS
```

---

## Deployment Roles

Every Styx deployment uses **one Gateway** paired with one or more **Hosts**:

- **Gateway (`gateway`)**: Exposes the MCP endpoint (ChatGPT Secure MCP Tunnel and/or `PublicMcp` HTTPS/OIDC), authenticates callers, manages device invitations/approvals, and routes tool calls. Does not run Host capabilities unless combined with a Host on the same machine.
- **Host (`host`)**: Initiates outbound mTLS/WSS connections to the paired Gateway and runs only the capabilities enabled locally (`Exec`, `Browser`, `Computer Use`, `Android`, opt-in `browser-cdp`).

---

## Platform Setup

### macOS (`Styx-<version>-macos-arm64.dmg`)

1. Open the DMG and copy `Styx.app` to `/Applications`.
2. Launch `Styx.app` and select either **Set up Gateway + Host** or **Join an existing Gateway**.
3. For **Computer Use**, grant **Accessibility** and **Screen Recording** permissions in **System Settings → Privacy & Security**.

### Windows (`Styx-<version>-windows-x64.exe`)

1. Run the installer (note: the installer is not Authenticode signed; Styx verifies payload integrity with its embedded publisher key during install).
2. Open Styx from the Start menu and either initialize a local Gateway or join an existing Gateway with an invitation code.
3. Closing the window minimizes Styx to the system tray; **Quit Styx** stops local Host and Gateway processes.

### Linux Desktop (`styx-<version>-linux-x86_64-desktop.tar.gz`)

1. Extract the archive and run the installer from inside the extracted folder:

   ```sh
   tar -xzf styx-<version>-linux-x86_64-desktop.tar.gz
   cd styx-<version>-linux-x86_64-desktop
   ./install.sh
   ```

2. Follow `styx setup` in a graphical desktop terminal to create a local Gateway or join an existing one. Browser and Computer Use require an active XWayland/Wayland graphical user session.
3. Manage the local user service with `styx status`, `styx quit`, `styx start`, and `styx uninstall` (uninstall stops and removes the systemd user services while preserving configuration and profiles).

### Linux Headless Gateway (`styx-<version>-linux-x86_64-gateway-only.tar.gz`)

1. Extract and run `./install.sh` on the server host.
2. When prompted during setup (or via `loginctl enable-linger "$USER"`), enable systemd user linger so the Gateway service stays active after SSH logout.

### Android (`Styx-<version>-android-arm64.apk`)

1. Install the APK (`adb install -r Styx-<version>-android-arm64.apk` or install on-device).
2. Open **Styx**, enter the Gateway address, invitation short code, and device label, and pair.
3. Enable **Styx Android control** in system Accessibility settings, allow notifications/unrestricted background activity if desired, and tap **Start Host**.

---

## Pairing a New Device

1. On the Gateway, run:

   ```sh
   styx invite
   ```

   *(or open the Invitations panel in the desktop app)* to generate a one-use pairing code.
2. On the joining Host, enter the Gateway URL and pairing code.
3. Compare and approve the pending device on the Gateway.
4. Enable only the capabilities (`Exec`, `Browser`, `Computer Use`, `Android`) that Host should expose.

## Opt-In Existing Chrome CDP Mode (Desktop Hosts)

By default, Browser automation launches an isolated managed Chromium profile per session (`mode: "managed"`). To also allow explicit attachment to an already running Chrome instance (`browser_session_id: "existing-browser"`):

1. In Chrome 144+, open `chrome://inspect/#remote-debugging` and enable remote debugging.
2. On the Host, explicitly enable local CDP mode (via the app Settings toggle or CLI):

   ```sh
   styx host browser-cdp enable
   ```

3. Use `styx host browser-cdp status` or `styx host browser-cdp disable` to inspect or turn it off locally.

---

## In-Place Upgrades

When upgrading, update the Gateway first, then upgrade paired Hosts. Existing device identities, pairings, persisted Browser profiles, and publisher pins are preserved automatically:

- **macOS / Windows**: Quit Styx completely (**Quit Styx** / `styx quit`), install the new package (backup `/Applications/Styx.app` if desired on macOS), and reopen Styx.
- **Linux**: Run `./install.sh` from the new extracted release tarball, or run `styx upgrade --payload <bundle>/payload --publisher-file <bundle>/publisher.pem --expected-publisher bbb49c2626c3d4ef3cf9e1679db5305b100cee4a8c41c29c958ede82fb868bed --yes`.
- **Android**: Tap **Stop Host** (optional for clean drain), install the new release APK in place (`adb install -r`), reopen the app, and tap **Start Host**. All release APKs share the same signing certificate (`a83c569e96981ce31d6ad50dace6094c1f644be7b0a09c3fe84addc74af4b7b3`).
