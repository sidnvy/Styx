// Styx owns its embedded Cua lifetime. Native Host supervision is explicit opt-in;
// macOS TCC responsibility still requires measurement on the signed installed App.
import AppKit
import ApplicationServices
import CoreGraphics
import Darwin
import WebKit

let bundleID = "app.styx.host"
enum HostError: Error { case unsafeRuntime, alreadyRunning, socketPath, daemonUnavailable }

// An exclusive lock prevents competing generations. Reject symlinks and directories
// owned by another account before opening any runtime files. Same-UID code is trusted.
final class RuntimeDirectory {
    let path: String
    let lock: Int32
    var socket: String { path + "/cua.sock" }
    var descriptor: String { path + "/connection.json" }
    init(path: String = "/tmp/styx-cua-\(getuid())") throws {
        self.path = path
        if mkdir(path, 0o700) != 0 && errno != EEXIST { throw HostError.unsafeRuntime }
        var info = stat()
        guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == getuid(), info.st_mode & 0o077 == 0 else { throw HostError.unsafeRuntime }
        lock = Darwin.open(path + "/owner.lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard lock >= 0 else { throw HostError.unsafeRuntime }
        var lockInfo = stat()
        guard fstat(lock, &lockInfo) == 0, lockInfo.st_mode & S_IFMT == S_IFREG,
              lockInfo.st_uid == getuid(), lockInfo.st_mode & 0o077 == 0 else {
            close(lock); throw HostError.unsafeRuntime
        }
        guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { close(lock); throw HostError.alreadyRunning }
    }
    func clear() { unlink(descriptor); unlink(socket); unlink(path + "/cua.pid") }
    deinit { close(lock) }
}

// Socket existence is insufficient: acceptability is a transport-only boundary,
// never proof of MCP initialization, TCC attribution, or successful GUI actions.
func socketAccepts(_ path: String) -> Bool {
    var addr = sockaddr_un()
    let bytes = Array(path.utf8CString)
    guard bytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else { return false }
    addr.sun_family = sa_family_t(AF_UNIX)
    addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    withUnsafeMutableBytes(of: &addr.sun_path) { raw in
        for (i, byte) in bytes.enumerated() { raw[i] = UInt8(bitPattern: byte) }
    }
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return false }
    defer { close(fd) }
    // Never block AppKit while a peer is stuck or its backlog is full.
    _ = fcntl(fd, F_SETFL, O_NONBLOCK)
    return withUnsafePointer(to: &addr) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) == 0
        }
    }
}

// Pinned Cua 0.36.0 cli.rs exports this internal host contract; serve.rs
// waits for embedded stdin EOF and shuts down its runtime. The sole writer
// stays in Styx: process death closes it without a PID watchdog or guessed API.
func makeEmbeddedDaemon(driver: URL, socketPath: String, pidFile: String) -> (Process, Pipe) {
    let child = Process(), lifetime = Pipe()
    child.executableURL = driver
    child.arguments = ["serve", "--embedded", "--parent-liveness-stdio",
        "--socket", socketPath, "--pid-file", pidFile]
    child.environment = ["PATH": "/usr/bin:/bin", "HOME": NSHomeDirectory(),
        "TMPDIR": NSTemporaryDirectory(), "CUA_DRIVER_EMBEDDED": "1",
        "CUA_DRIVER_HOST_BUNDLE_ID": bundleID, "CUA_DRIVER_PERMISSION_MODE": "standard",
        "DO_NOT_TRACK": "1", "CUA_DRIVER_RS_TELEMETRY_ENABLED": "false"]
    child.standardInput = lifetime
    child.standardOutput = FileHandle.nullDevice
    child.standardError = FileHandle.nullDevice
    return (child, lifetime)
}

// The same signed native executable can supervise Host without starting AppKit,
// Cua, onboarding, or requesting any permission. This changes the process tree;
// it is NOT evidence that macOS attributes Exec/Automation requests to Styx.
struct NativeHostInvocation {
    let teamID: String
    let node: String
    let installRoot: String
    let hostConfig: String
    let publisherKey: String
    var launchScript: String { installRoot + "/launch.mjs" }
}
func nativeHostInvocation(_ args: [String]) throws -> NativeHostInvocation? {
    guard args.count > 1, args[1] == "--host-service" else { return nil }
    guard args.count == 7,
          args[2].count == 10, args[2].allSatisfy({ "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".contains($0) }) else { throw HostError.unsafeRuntime }
    for value in args[3...] {
        guard value.hasPrefix("/"), URL(fileURLWithPath: value).standardizedFileURL.path == value,
              !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) || $0.value == 0xfffe || $0.value == 0xffff }) else { throw HostError.unsafeRuntime }
    }
    guard args[3].hasPrefix(args[4] + "/") else { throw HostError.unsafeRuntime }
    return NativeHostInvocation(teamID: args[2], node: args[3], installRoot: args[4], hostConfig: args[5], publisherKey: args[6])
}
func requireNativeHostFile(_ path: String, privateFile: Bool) throws {
    var info = stat()
    guard lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
          info.st_uid == getuid(), info.st_mode & 0o022 == 0,
          !privateFile || info.st_mode & 0o077 == 0 else { throw HostError.unsafeRuntime }
}
func runNativeHost(_ invocation: NativeHostInvocation) throws -> Never {
    // A stable Team ID is required. Never accept the ad-hoc preview as a stable
    // permission identity, and verify again after login/reboot before execution.
    guard Bundle.main.bundleURL.standardizedFileURL.path == "/Applications/Styx.app",
          Bundle.main.bundleIdentifier == bundleID else { throw HostError.unsafeRuntime }
    let check = Process()
    check.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
    check.arguments = ["--verify", "--deep", "--strict", "-R",
        "=anchor apple generic and identifier \"\(bundleID)\" and certificate leaf[subject.OU] = \"\(invocation.teamID)\"",
        Bundle.main.bundleURL.path]
    check.standardInput = FileHandle.nullDevice
    check.standardOutput = FileHandle.nullDevice
    check.standardError = FileHandle.nullDevice
    try check.run(); check.waitUntilExit()
    guard check.terminationReason == .exit, check.terminationStatus == 0 else { throw HostError.unsafeRuntime }
    var rootInfo = stat()
    guard lstat(invocation.installRoot, &rootInfo) == 0, rootInfo.st_mode & S_IFMT == S_IFDIR,
          rootInfo.st_uid == getuid(), rootInfo.st_mode & 0o077 == 0 else { throw HostError.unsafeRuntime }
    for file in [invocation.launchScript, invocation.hostConfig, invocation.publisherKey] {
        try requireNativeHostFile(file, privateFile: true)
    }
    try requireNativeHostFile(invocation.node, privateFile: false)
    guard FileManager.default.isExecutableFile(atPath: invocation.node) else { throw HostError.unsafeRuntime }
    let child = Process()
    child.executableURL = URL(fileURLWithPath: invocation.node)
    child.arguments = [invocation.launchScript, invocation.installRoot, invocation.hostConfig, invocation.publisherKey]
    child.currentDirectoryURL = URL(fileURLWithPath: invocation.installRoot)
    child.standardInput = FileHandle.nullDevice
    child.standardOutput = FileHandle.standardOutput
    child.standardError = FileHandle.standardError
    // Do not allow dynamic-loader or Node bootstrap injection into this fixed
    // service entry point. These values are process diagnostics, not TCC proof.
    var environment = ProcessInfo.processInfo.environment.filter {
        !$0.key.hasPrefix("DYLD_") && !$0.key.hasPrefix("LD_") && !["NODE_OPTIONS", "NODE_PATH"].contains($0.key)
    }
    environment["STYX_NATIVE_LAUNCHER_PID"] = String(getpid())
    environment["STYX_NATIVE_BUNDLE_ID"] = bundleID
    environment["STYX_TCC_ATTRIBUTION"] = "NOT RUN"
    child.environment = environment
    var stopping = false
    var signals: [DispatchSourceSignal] = []
    for number in [SIGTERM, SIGINT] {
        signal(number, SIG_IGN)
        let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
        source.setEventHandler {
            guard !stopping else { return }; stopping = true
            if child.isRunning { kill(child.processIdentifier, number) }
            // launchd cleans remaining members of this job's process group.
            // PTY/detached process groups still require upstream Exec lifetime
            // acceptance; this supervisor does not claim to contain them.
            DispatchQueue.main.asyncAfter(deadline: .now() + 8) {
                if child.isRunning { kill(child.processIdentifier, SIGKILL) }
            }
        }
        source.resume(); signals.append(source)
    }
    child.terminationHandler = { terminated in
        DispatchQueue.main.async {
            exit(stopping ? 0 : terminated.terminationReason == .exit ? terminated.terminationStatus : 1)
        }
    }
    try child.run()
    // Keep the supervisor alive until Node exits; never re-pair, rewrite Host
    // identity, or retry an interrupted request here. launchd restarts failures.
    return withExtendedLifetime(signals) { dispatchMain() }
}

// Accept only the one private loopback bootstrap message from our owned child.
func setupSessionURL(_ line: String) -> URL? {
    guard line.hasPrefix("STYX_SETUP_URL\t"),
          let parts = URLComponents(string: String(line.dropFirst(15))),
          parts.scheme == "http", parts.host == "127.0.0.1", let port = parts.port,
          (1...65535).contains(port), parts.path == "/", parts.query == nil,
          parts.user == nil, parts.password == nil,
          let fragment = parts.fragment, fragment.hasPrefix("session="),
          fragment.dropFirst(8).count == 43,
          fragment.dropFirst(8).allSatisfy({ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-".contains($0) }) else { return nil }
    return parts.url
}

// Only the owned loopback origin is rendered inside the settings window. Account
// and OS links require a user click and native confirmation; redirects cannot
// turn a setup response into an external browser launch or file/protocol access.
enum SetupNavigation { case local, external, blocked }
func setupNavigation(_ url: URL, origin: URL, userActivated: Bool) -> SetupNavigation {
    guard let target = URLComponents(url: url, resolvingAgainstBaseURL: false),
          target.user == nil, target.password == nil else { return .blocked }
    if target.scheme == "http", target.host == "127.0.0.1", target.port == origin.port {
        return .local
    }
    guard userActivated else { return .blocked }
    if target.scheme == "https", let host = target.host, !host.isEmpty { return .external }
    if target.scheme == "x-apple.systempreferences",
       target.path == "com.apple.preference.security",
       ["Privacy_Accessibility", "Privacy_ScreenCapture"].contains(target.query ?? "") { return .external }
    return .blocked
}

final class SetupWindowController: NSWindowController, WKNavigationDelegate, WKUIDelegate {
    let origin: URL
    let webView: WKWebView
    init(sessionURL: URL) {
        origin = sessionURL
        let configuration = WKWebViewConfiguration()
        // Session credentials never enter the user's browser profile or disk cache.
        configuration.websiteDataStore = .nonPersistent()
        webView = WKWebView(frame: .zero, configuration: configuration)
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1040, height: 760),
            styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Styx — Setup & Settings"
        window.minSize = NSSize(width: 760, height: 560)
        window.isReleasedWhenClosed = false
        window.contentView = webView
        window.center()
        super.init(window: window)
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.load(URLRequest(url: sessionURL))
    }
    required init?(coder: NSCoder) { fatalError("Programmatic settings window only") }
    func present() {
        showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }
    func confirmExternal(_ url: URL) {
        let alert = NSAlert()
        alert.messageText = url.scheme == "https" ? "Continue in your browser?" : "Open macOS Settings?"
        // Show the destination origin, never query strings containing credentials.
        alert.informativeText = url.scheme == "https"
            ? "Styx will open \(url.host ?? "the selected site") in your default browser."
            : "Styx will open the selected privacy settings. You decide whether to grant access."
        alert.addButton(withTitle: "Continue"); alert.addButton(withTitle: "Cancel")
        if alert.runModal() == .alertFirstButtonReturn { NSWorkspace.shared.open(url) }
    }
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = navigationAction.request.url else { decisionHandler(.cancel); return }
        switch setupNavigation(url, origin: origin, userActivated: navigationAction.navigationType == .linkActivated) {
        case .local:
            // Keep target=_blank local links in the same owned window.
            if navigationAction.targetFrame == nil {
                decisionHandler(.cancel); webView.load(navigationAction.request)
            } else { decisionHandler(.allow) }
        case .external:
            decisionHandler(.cancel); confirmExternal(url)
        case .blocked: decisionHandler(.cancel)
        }
    }
    func webView(_ webView: WKWebView, decidePolicyFor navigationResponse: WKNavigationResponse,
                 decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        guard let url = navigationResponse.response.url,
              setupNavigation(url, origin: origin, userActivated: false) == .local,
              navigationResponse.canShowMIMEType else { decisionHandler(.cancel); return }
        decisionHandler(.allow)
    }
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration,
                 for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? { nil }
    func trustedFrame(_ frame: WKFrameInfo) -> Bool {
        frame.isMainFrame && frame.securityOrigin.protocol == "http"
            && frame.securityOrigin.host == "127.0.0.1" && frame.securityOrigin.port == origin.port
    }
    // WKWebView does not display JavaScript dialogs itself. Preserve the setup
    // core's explicit approval boundaries using App-owned confirmation dialogs.
    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        guard trustedFrame(frame) else { completionHandler(false); return }
        let alert = NSAlert(); alert.messageText = "Styx — Confirm change"
        alert.informativeText = message
        alert.addButton(withTitle: "Continue"); alert.addButton(withTitle: "Cancel")
        completionHandler(alert.runModal() == .alertFirstButtonReturn)
    }
    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        if trustedFrame(frame) {
            let alert = NSAlert(); alert.messageText = "Styx"; alert.informativeText = message
            alert.runModal()
        }
        completionHandler()
    }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        if (error as NSError).code == NSURLErrorCancelled { return }
        window?.title = "Styx — Settings unavailable; reopen Settings"
    }
}

final class StyxDelegate: NSObject, NSApplicationDelegate {
    var setupProcess: Process?
    var setupInput: Pipe?
    var setupOutput: Pipe?
    var setupURL: URL?
    var setupWindow: SetupWindowController?
    var setupBuffer = ""
    var setupOpenRequested = false
    var setupStatusLine: NSMenuItem?
    let setupPreference = "Styx.SetupWindowOpened.v1"
    var runtime: RuntimeDirectory?
    var daemon: Process?
    var lifetimeWriter: FileHandle?
    var timer: Timer?
    var statusItem: NSStatusItem?
    var statusLine: NSMenuItem?
    var phase = "stopped"
    var generation = UUID().uuidString
    var deadline = Date()
    var lastGrants: String?
    var signalSources: [DispatchSourceSignal] = []

    func applicationDidFinishLaunching(_ notification: Notification) {
        for number in [SIGTERM, SIGINT] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { NSApp.terminate(nil) }
            source.resume(); signalSources.append(source)
        }
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        item.button?.title = "Styx"
        let menu = NSMenu()
        statusLine = menu.addItem(withTitle: "Starting…", action: nil, keyEquivalent: "")
        menu.addItem(withTitle: "Setup / Settings…", action: #selector(openSettings), keyEquivalent: ",")
        setupStatusLine = menu.addItem(withTitle: "Local setup is not running", action: nil, keyEquivalent: "")
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Request macOS permissions…", action: #selector(requestPermissions), keyEquivalent: "")
        menu.addItem(withTitle: "Restart embedded Cua", action: #selector(restart), keyEquivalent: "r")
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Quit Styx", action: #selector(quit), keyEquivalent: "q")
        for entry in menu.items { entry.target = self }
        item.menu = menu; statusItem = item
        if let resources = Bundle.main.resourceURL,
           FileManager.default.isExecutableFile(atPath: resources.appendingPathComponent("runtime/node").path),
           Bundle.main.bundleURL.standardizedFileURL.path != "/Applications/Styx.app" {
            let alert = NSAlert(); alert.messageText = "Move Styx to Applications first"
            alert.informativeText = "Drag the complete Styx.app to /Applications, then open it there. Do not replace an existing Styx installation without reviewing it first. Settings and permissions need a stable app location."
            alert.runModal(); NSApp.terminate(nil); return
        }
        do { runtime = try RuntimeDirectory(); try start() }
        catch { phase = "blocked"; statusLine?.title = "Blocked: \(error)" }
        // A competing Cua owner does not prevent opening this app's setup UI.
        if let resources = Bundle.main.resourceURL,
           FileManager.default.isExecutableFile(atPath: resources.appendingPathComponent("runtime/node").path) {
            do { try startSetup(openWindow: !UserDefaults.standard.bool(forKey: setupPreference)) }
            catch { setupStatusLine?.title = "Local setup unavailable; reopen Settings" }
        }
    }
    func startSetup(openWindow: Bool) throws {
        setupOpenRequested = setupOpenRequested || openWindow
        if let url = setupURL { if setupOpenRequested { showSetup(url) }; return }
        guard setupProcess == nil else { return }
        guard let resources = Bundle.main.resourceURL else { throw HostError.daemonUnavailable }
        let node = resources.appendingPathComponent("runtime/node")
        let launcher = resources.appendingPathComponent("onboarding/vnext/host/macos/setup-launcher.mjs")
        guard FileManager.default.isExecutableFile(atPath: node.path),
              FileManager.default.fileExists(atPath: launcher.path) else { throw HostError.daemonUnavailable }
        let child = Process(), input = Pipe(), output = Pipe()
        child.executableURL = node; child.arguments = [launcher.path, resources.path]
        child.environment = ["PATH": "/usr/bin:/bin", "HOME": NSHomeDirectory(),
            "TMPDIR": NSTemporaryDirectory(), "LANG": "en_US.UTF-8"]
        child.standardInput = input; child.standardOutput = output; child.standardError = FileHandle.nullDevice
        setupBuffer = ""; setupStatusLine?.title = "Local setup is starting…"
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; return }
            DispatchQueue.main.async {
                guard let owner = self, owner.setupProcess === child else { return }
                guard let text = String(data: data, encoding: .utf8), owner.setupBuffer.utf8.count + data.count <= 4096 else {
                    owner.stopSetup(); owner.setupStatusLine?.title = "Local setup protocol unavailable"; return
                }
                owner.setupBuffer += text
                while let newline = owner.setupBuffer.firstIndex(of: "\n") {
                    let line = String(owner.setupBuffer[..<newline])
                    owner.setupBuffer.removeSubrange(...newline)
                    guard owner.setupURL == nil, let url = setupSessionURL(line) else {
                        owner.stopSetup(); owner.setupStatusLine?.title = "Local setup protocol unavailable"; return
                    }
                    owner.setupURL = url; owner.setupStatusLine?.title = "Local setup ready"
                    if owner.setupOpenRequested { owner.showSetup(url) }
                }
            }
        }
        child.terminationHandler = { [weak self] terminated in
            DispatchQueue.main.async {
                guard let owner = self, owner.setupProcess === terminated else { return }
                owner.setupOutput?.fileHandleForReading.readabilityHandler = nil
                try? owner.setupInput?.fileHandleForWriting.close()
                owner.setupProcess = nil; owner.setupInput = nil; owner.setupOutput = nil; owner.setupURL = nil
                owner.setupWindow?.close(); owner.setupWindow = nil
                owner.setupStatusLine?.title = "Local setup stopped; reopen Settings"
            }
        }
        setupProcess = child; setupInput = input; setupOutput = output
        do { try child.run() }
        catch { stopSetup(); throw error }
        try? input.fileHandleForReading.close(); try? output.fileHandleForWriting.close()
    }
    func showSetup(_ url: URL) {
        if setupWindow == nil { setupWindow = SetupWindowController(sessionURL: url) }
        setupWindow?.present()
        setupOpenRequested = false
        UserDefaults.standard.set(true, forKey: setupPreference)
    }
    @objc func openSettings() {
        do { try startSetup(openWindow: true) }
        catch {
            let alert = NSAlert(); alert.messageText = "Styx local setup is unavailable"
            alert.informativeText = "Keep the complete Styx.app bundle together and reopen Settings. No global Node installation is needed."
            alert.runModal()
        }
    }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openSettings(); return true
    }
    func stopSetup() {
        setupWindow?.close(); setupWindow = nil
        setupOutput?.fileHandleForReading.readabilityHandler = nil
        try? setupInput?.fileHandleForWriting.close()
        if let child = setupProcess {
            child.terminationHandler = nil
            if child.isRunning {
                let limit = Date().addingTimeInterval(6)
                while child.isRunning && Date() < limit { Thread.sleep(forTimeInterval: 0.02) }
                if child.isRunning { child.terminate() }
                let termLimit = Date().addingTimeInterval(2)
                while child.isRunning && Date() < termLimit { Thread.sleep(forTimeInterval: 0.02) }
                if child.isRunning { kill(child.processIdentifier, SIGKILL) }
                child.waitUntilExit()
            }
        }
        setupProcess = nil; setupInput = nil; setupOutput = nil; setupURL = nil; setupBuffer = ""
    }
    func start() throws {
        guard let runtime = runtime, daemon == nil else { return }
        // A released owner lock does not prove a prior crashed owner's child
        // exited. Never unlink an existing endpoint to replace a live daemon.
        if FileManager.default.fileExists(atPath: runtime.socket) {
            unlink(runtime.descriptor)
            throw HostError.daemonUnavailable
        }
        runtime.clear(); generation = UUID().uuidString; lastGrants = nil
        guard let driver = Bundle.main.url(forAuxiliaryExecutable: "cua-driver") else {
            throw HostError.daemonUnavailable
        }
        let (child, lifetime) = makeEmbeddedDaemon(driver: driver,
            socketPath: runtime.socket, pidFile: runtime.path + "/cua.pid")
        child.terminationHandler = { [weak self] terminated in
            DispatchQueue.main.async {
                guard let owner = self, owner.daemon === terminated else { return }
                try? owner.lifetimeWriter?.close(); owner.lifetimeWriter = nil
                owner.daemon = nil; owner.timer?.invalidate(); owner.runtime?.clear()
                owner.phase = "daemon_exited"
                owner.statusLine?.title = "Cua exited; reconnect after restart"
                // Never replay an interrupted GUI action or silently restart a generation.
            }
        }
        do { try child.run() }
        catch { try? lifetime.fileHandleForWriting.close(); try? lifetime.fileHandleForReading.close(); throw error }
        try? lifetime.fileHandleForReading.close()
        lifetimeWriter = lifetime.fileHandleForWriting
        daemon = child; phase = "starting"
        deadline = Date().addingTimeInterval(15)
        timer = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self] _ in self?.poll() }
    }
    func poll() {
        guard let runtime = runtime, let daemon = daemon, daemon.isRunning else { return }
        let ax = AXIsProcessTrusted(), screen = CGPreflightScreenCaptureAccess()
        let grants = "\(ax):\(screen)"
        if let previous = lastGrants, previous != grants {
            stop(); statusLine?.title = "Permissions changed; quit and reopen Styx"; return
        }
        lastGrants = grants
        if socketAccepts(runtime.socket) {
            phase = "socket_accepting"
            let descriptor: [String: Any] = ["schema": 1, "generation": generation,
                "owner_pid": getpid(), "daemon_pid": daemon.processIdentifier,
                "bundle_id": bundleID, "socket": runtime.socket,
                "transport": "socket_accepting", "host_accessibility": ax,
                "host_screen_recording": screen, "native_gui_acceptance": "NOT RUN",
                "mcp_attribution": "NOT RUN"]
            do {
                let data = try JSONSerialization.data(withJSONObject: descriptor, options: [.sortedKeys])
                try data.write(to: URL(fileURLWithPath: runtime.descriptor), options: .atomic)
                chmod(runtime.descriptor, 0o600)
            } catch { runtime.clear(); stop(); statusLine?.title = "Connection descriptor failed"; return }
            statusLine?.title = ax && screen ? "Cua socket available; GUI check required" : "Cua socket available; permissions required"
        } else if phase == "socket_accepting" || Date() > deadline {
            stop(); statusLine?.title = "Cua unavailable; restart required"
        }
    }
    func stop() {
        timer?.invalidate(); timer = nil
        // Withdraw the advertised generation before terminating its daemon.
        if let runtime = runtime { unlink(runtime.descriptor) }
        let ownedChild = daemon != nil
        // Prefer upstream orderly EOF shutdown. Fall back only on this owned child.
        try? lifetimeWriter?.close(); lifetimeWriter = nil
        if let child = daemon {
            child.terminationHandler = nil
            if child.isRunning {
                let limit = Date().addingTimeInterval(3)
                while child.isRunning && Date() < limit { Thread.sleep(forTimeInterval: 0.02) }
                if child.isRunning {
                    child.terminate()
                    let termLimit = Date().addingTimeInterval(1)
                    while child.isRunning && Date() < termLimit { Thread.sleep(forTimeInterval: 0.02) }
                    if child.isRunning { kill(child.processIdentifier, SIGKILL) }
                }
                child.waitUntilExit()
            }
        }
        daemon = nil
        if ownedChild { runtime?.clear() }
        phase = "stopped"
    }
    @objc func requestPermissions() {
        // Only an explicit local menu action can trigger OS-owned permission UI.
        _ = AXIsProcessTrustedWithOptions(["AXTrustedCheckOptionPrompt": true] as CFDictionary)
        _ = CGRequestScreenCaptureAccess()
        let alert = NSAlert()
        alert.messageText = "Allow Styx in macOS Privacy & Security"
        alert.informativeText = "Enable Accessibility and Screen Recording for Styx. Quit and reopen Styx after changing grants; reconnect clients to the new generation. A grant alone does not verify capture or actions. Explicit application scripts may separately request Automation approval for the target application."
        alert.runModal()
    }
    @objc func restart() {
        stop()
        do { try start() } catch { statusLine?.title = "Restart blocked: \(error)" }
    }
    @objc func quit() { NSApp.terminate(nil) }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        stopSetup(); stop(); return .terminateNow
    }
}

#if STYX_TESTING
// Opt-in native WebKit acceptance against a fresh private test server only.
if CommandLine.arguments.count == 4 && CommandLine.arguments[1] == "--setup-window-fixture" {
    let input = URL(fileURLWithPath: CommandLine.arguments[2])
    let snapshot = URL(fileURLWithPath: CommandLine.arguments[3])
    guard let line = try? String(contentsOf: input, encoding: .utf8),
          let sessionURL = setupSessionURL("STYX_SETUP_URL\t" + line.trimmingCharacters(in: .whitespacesAndNewlines)) else { exit(2) }
    let application = NSApplication.shared
    application.setActivationPolicy(.accessory)
    let controller = SetupWindowController(sessionURL: sessionURL)
    controller.present()
    var attempts = 0
    let timer = Timer.scheduledTimer(withTimeInterval: 0.25, repeats: true) { timer in
        attempts += 1
        if attempts > 80 { fputs("Styx WebKit setup acceptance timed out\n", stderr); exit(2) }
        controller.webView.evaluateJavaScript("document.querySelector('#setup')?.hidden === false && location.hash === ''") { result, error in
            guard error == nil, result as? Bool == true else { return }
            timer.invalidate()
            controller.webView.takeSnapshot(with: nil) { image, error in
                guard error == nil, let image = image, let tiff = image.tiffRepresentation,
                      let bitmap = NSBitmapImageRep(data: tiff), let png = bitmap.representation(using: .png, properties: [:]) else { exit(2) }
                do { try png.write(to: snapshot); print("Styx WebKit authenticated setup and fragment removal PASS"); exit(0) }
                catch { exit(2) }
            }
        }
    }
    withExtendedLifetime((controller,timer)) { application.run() }
    exit(2)
}

// CI-only headless harness uses the exact production launch and lifetime
// pipe, but creates no NSApplication, requests no TCC and invokes no GUI tool.
if CommandLine.arguments.count == 4 && CommandLine.arguments[1] == "--liveness-owner-fixture" {
    let driver = URL(fileURLWithPath: CommandLine.arguments[2])
    let socketPath = CommandLine.arguments[3]
    let (child, lifetime) = makeEmbeddedDaemon(driver: driver,
        socketPath: socketPath, pidFile: socketPath + ".pid")
    do {
        try child.run(); try lifetime.fileHandleForReading.close()
        let data = try JSONSerialization.data(withJSONObject: ["daemon_pid": child.processIdentifier])
        FileHandle.standardOutput.write(data + Data([10]))
        withExtendedLifetime(lifetime) {
            while child.isRunning { Thread.sleep(forTimeInterval: 0.05) }
        }
        exit(child.terminationStatus)
    } catch { fputs("Styx lifetime harness failed: \(error)\n", stderr); exit(1) }
}

// Runs without starting NSApplication, a daemon, or permission prompts in CI.
if CommandLine.arguments.contains("--self-test") {
    // Parser-only assertions: no code signature checks, files, Host child,
    // NSApplication, Cua, or OS permission APIs are reached by these cases.
    let service = ["Styx", "--host-service", "ABCDEFGHIJ", "/private/styx/node", "/private/styx", "/private/host.json", "/private/publisher.pem"]
    for valid in [service, ["Styx", "--host-service", "0123456789", "/private/用户 🧭 & <Styx> \"' $(literal);/releases/v1/bin/node", "/private/用户 🧭 & <Styx> \"' $(literal);", "/private/Host 用户 &.json", "/private/publisher.pem"]] {
        guard let invocation = try? nativeHostInvocation(valid),
              invocation.teamID == valid[2], invocation.node == valid[3],
              invocation.installRoot == valid[4], invocation.hostConfig == valid[5],
              invocation.publisherKey == valid[6], invocation.launchScript == valid[4] + "/launch.mjs" else { fatalError("native Host argv was changed or rejected") }
    }
    for ordinary in [[], ["Styx"], ["Styx", "--self-test"], ["Styx", "--other-mode"]] {
        do { guard try nativeHostInvocation(ordinary) == nil else { fatalError("ordinary App argv selected Host mode") } }
        catch { fatalError("ordinary App argv rejected by Host parser") }
    }
    func expectNativeHostRefused(_ invalid: [String]) {
        do { _ = try nativeHostInvocation(invalid); fatalError("unsafe native Host argv accepted") }
        catch HostError.unsafeRuntime { }
        catch { fatalError("unexpected native Host parser error") }
    }
    for invalid in [Array(service.prefix(2)), Array(service.dropLast()), service + ["extra"]] { expectNativeHostRefused(invalid) }
    for badTeam in ["", "adhoc", "ABCDEFGHI", "ABCDEFGHIJK", "ABCDEFGHIJ\n", "ABCDE-FGHI", "ABCDEFGHIJ\" or true"] {
        var invalid = service; invalid[2] = badTeam; expectNativeHostRefused(invalid)
    }
    for badNode in ["/tmp/foreign-node", "/private/styx-other/node", "/private/styx", "/private/styx/../node"] {
        var invalid = service; invalid[3] = badNode; expectNativeHostRefused(invalid)
    }
    for index in 3...6 {
        for badPath in ["", "relative/path", "/private/../outside", "/private/./file", "/private//file", "/private/file\0", "/private/file\n", "/private/file\r", "/private/file\t", "/private/file\u{7f}", "/private/file\u{85}", "/private/file\u{fffe}", "/private/file\u{ffff}"] {
            var invalid = service; invalid[index] = badPath; expectNativeHostRefused(invalid)
        }
    }
    let token = String(repeating: "a", count: 43)
    guard setupSessionURL("STYX_SETUP_URL\thttp://127.0.0.1:1234/#session=" + token) != nil else { fatalError("setup bootstrap rejected") }
    for bad in ["STYX_SETUP_URL\thttps://example.com/#session=" + token,
                "STYX_SETUP_URL\thttp://127.0.0.1:0/#session=" + token,
                "STYX_SETUP_URL\thttp://127.0.0.1:1234/?secret=bad#session=" + token,
                "STYX_SETUP_URL\thttp://user@127.0.0.1:1234/#session=" + token,
                "STYX_SETUP_URL\thttp://127.0.0.1:1234/#session=bad"] {
        guard setupSessionURL(bad) == nil else { fatalError("unsafe setup bootstrap accepted") }
    }

    let origin = URL(string: "http://127.0.0.1:1234/")!
    for local in ["http://127.0.0.1:1234/", "http://127.0.0.1:1234/#progress", "http://127.0.0.1:1234/api/state"] {
        guard setupNavigation(URL(string: local)!, origin: origin, userActivated: false) == .local else { fatalError("local navigation rejected") }
    }
    for bad in ["http://127.0.0.1:4321/", "http://localhost:1234/", "http://127.0.0.1:1234@example.com/", "file:///etc/passwd", "javascript:alert(1)", "data:text/html,hello", "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles", "https://user:secret@example.com/"] {
        guard setupNavigation(URL(string: bad)!, origin: origin, userActivated: true) == .blocked else { fatalError("unsafe navigation accepted") }
    }
    for external in ["https://accounts.example.com/login", "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility", "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture"] {
        let url = URL(string: external)!
        guard setupNavigation(url, origin: origin, userActivated: true) == .external,
              setupNavigation(url, origin: origin, userActivated: false) == .blocked else { fatalError("external navigation requires explicit activation") }
    }

    let dir = NSTemporaryDirectory() + "styx-owner-test-" + UUID().uuidString
    do {
        var owner: RuntimeDirectory? = try RuntimeDirectory(path: dir)
        guard owner != nil else { fatalError("missing owner") }
        let privateFile = dir + "/native-host-config.json"
        try Data("{}".utf8).write(to: URL(fileURLWithPath: privateFile)); chmod(privateFile, 0o600)
        try requireNativeHostFile(privateFile, privateFile: true)
        chmod(privateFile, 0o644)
        do { try requireNativeHostFile(privateFile, privateFile: true); fatalError("public native Host config accepted") }
        catch HostError.unsafeRuntime { }
        // Executable payloads need integrity verification by the signed release
        // facade; this native guard permits read/execute bits, never other-user write.
        try requireNativeHostFile(privateFile, privateFile: false)
        chmod(privateFile, 0o622)
        do { try requireNativeHostFile(privateFile, privateFile: false); fatalError("writable native Host runtime accepted") }
        catch HostError.unsafeRuntime { }
        chmod(privateFile, 0o600)
        let fileLink = dir + "/native-host-config-link"
        try FileManager.default.createSymbolicLink(atPath: fileLink, withDestinationPath: privateFile)
        for invalidFile in [fileLink, dir] {
            do { try requireNativeHostFile(invalidFile, privateFile: true); fatalError("nonregular native Host config accepted") }
            catch HostError.unsafeRuntime { }
        }
        try FileManager.default.removeItem(atPath: fileLink)
        try FileManager.default.removeItem(atPath: privateFile)
        do { _ = try RuntimeDirectory(path: dir); fatalError("duplicate ownership") }
        catch HostError.alreadyRunning { }
        guard !socketAccepts(dir + "/absent.sock") else { fatalError("false socket readiness") }
        owner = nil
        owner = try RuntimeDirectory(path: dir)
        owner = nil
        let link = dir + "-link"
        try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: dir)
        do { _ = try RuntimeDirectory(path: link); fatalError("symlink runtime accepted") }
        catch HostError.unsafeRuntime { }
        try FileManager.default.removeItem(atPath: link)
        chmod(dir, 0o755)
        do { _ = try RuntimeDirectory(path: dir); fatalError("public runtime accepted") }
        catch HostError.unsafeRuntime { }
        chmod(dir, 0o700)
        try FileManager.default.removeItem(atPath: dir)
        print("Styx native ownership and settings navigation self-test passed; GUI and TCC NOT RUN")
        exit(0)
    } catch { fputs("Styx self-test failed: \(error)\n", stderr); exit(1) }
}
#endif
// This branch runs before NSApplication initialization: Gateway-only/headless
// processes never acquire a Cua runtime merely by sharing the native executable.
do {
    if let invocation = try nativeHostInvocation(CommandLine.arguments) {
        try runNativeHost(invocation)
    }
} catch {
    fputs("Styx native Host supervisor refused its signed runtime configuration.\n", stderr)
    exit(2)
}
let app = NSApplication.shared
let delegate = StyxDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
