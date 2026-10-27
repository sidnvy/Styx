// Styx owns its embedded Cua lifetime. Native Host supervision is explicit opt-in;
// macOS TCC responsibility still requires measurement on the signed installed App.
import AppKit
import ApplicationServices
import CoreGraphics
import Darwin
import WebKit
import UniformTypeIdentifiers
import CryptoKit

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

let pluginExportHandlerName = "styxPluginExport"
let pluginExportMaximumBytes = 2 * 1024 * 1024
enum PluginExportError: Error { case refused }
func pluginExportArchive(_ body: Any) throws -> Data {
    guard let message = body as? [String: Any], message.count == 1,
          let encoded = message["base64"] as? String, !encoded.isEmpty,
          encoded.utf8.count <= ((pluginExportMaximumBytes + 2) / 3) * 4,
          let bytes = Data(base64Encoded: encoded), bytes.count <= pluginExportMaximumBytes,
          bytes.base64EncodedString() == encoded,
          bytes.starts(with: [0x50, 0x4b, 0x03, 0x04]) else { throw PluginExportError.refused }
    return bytes
}
func pluginExportPage(_ url: URL?, origin: URL) -> Bool {
    guard let url = url else { return false }
    return setupNavigation(url, origin: origin, userActivated: false) == .local
}
func pluginExportContext(origin: URL, currentURL: URL?, frameURL: URL?, isMainFrame: Bool,
                         securityProtocol: String, securityHost: String, securityPort: Int) -> Bool {
    origin.scheme == "http" && origin.host == "127.0.0.1" && origin.user == nil && origin.password == nil
        && origin.port != nil && isMainFrame && securityProtocol == "http" && securityHost == "127.0.0.1"
        && securityPort == origin.port && pluginExportPage(frameURL, origin: origin) && pluginExportPage(currentURL, origin: origin)
}
// This URL comes only from the user's native picker, never from JavaScript.
// Core validates the complete PNG structure, dimensions and pixels afterward.
func pluginIconFile(_ url: URL) throws -> URL {
    guard url.isFileURL, url.pathExtension.lowercased() == "png",
          UTType(filenameExtension: url.pathExtension.lowercased())?.conforms(to: .png) == true else { throw PluginExportError.refused }
    var info = stat()
    guard lstat(url.path, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
          info.st_size >= 8, info.st_size <= 256 * 1024 else { throw PluginExportError.refused }
    let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard fd >= 0 else { throw PluginExportError.refused }
    defer { Darwin.close(fd) }
    var opened = stat()
    guard fstat(fd, &opened) == 0, opened.st_dev == info.st_dev, opened.st_ino == info.st_ino,
          opened.st_mode & S_IFMT == S_IFREG, opened.st_size == info.st_size else { throw PluginExportError.refused }
    var header = [UInt8](repeating: 0, count: 8)
    let count = header.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
    guard count == 8, header == [137, 80, 78, 71, 13, 10, 26, 10] else { throw PluginExportError.refused }
    return url
}
// WebKit retains its handler. This proxy must not retain the window/controller.
final class PluginExportBridge: NSObject, WKScriptMessageHandlerWithReply {
    weak var owner: SetupWindowController?
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage,
                               replyHandler: @escaping (Any?, String?) -> Void) {
        guard let owner = owner else { replyHandler(nil, "plugin_export_unavailable"); return }
        owner.savePluginExport(message, replyHandler: replyHandler)
    }
}

final class SetupWindowController: NSWindowController, WKNavigationDelegate, WKUIDelegate, NSWindowDelegate {
    let origin: URL
    let webView: WKWebView
    private let pluginExportBridge = PluginExportBridge()
    private var pluginExportRegistered = false
    private var pluginFilePanelInProgress = false
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
        window.delegate = self
        enablePluginExport()
        webView.load(URLRequest(url: sessionURL))
    }
    required init?(coder: NSCoder) { fatalError("Programmatic settings window only") }
    func present() {
        enablePluginExport()
        showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
        window?.makeKeyAndOrderFront(nil)
    }
    private func enablePluginExport() {
        guard !pluginExportRegistered else { return }
        pluginExportBridge.owner = self
        webView.configuration.userContentController.addScriptMessageHandler(pluginExportBridge, contentWorld: .page, name: pluginExportHandlerName)
        pluginExportRegistered = true
    }
    func windowWillClose(_ notification: Notification) {
        webView.configuration.userContentController.removeScriptMessageHandler(forName: pluginExportHandlerName, contentWorld: .page)
        pluginExportBridge.owner = nil
        pluginExportRegistered = false
    }
    private func trustedPluginFrame(_ frame: WKFrameInfo) -> Bool {
        pluginExportRegistered && pluginExportContext(origin: origin, currentURL: webView.url, frameURL: frame.request.url,
            isMainFrame: frame.isMainFrame, securityProtocol: frame.securityOrigin.protocol,
            securityHost: frame.securityOrigin.host, securityPort: frame.securityOrigin.port)
    }
    private func trustedPluginExport(_ message: WKScriptMessage) -> Bool {
        message.name == pluginExportHandlerName && message.webView === webView && trustedPluginFrame(message.frameInfo)
    }
    func savePluginExport(_ message: WKScriptMessage, replyHandler: @escaping (Any?, String?) -> Void) {
        guard trustedPluginExport(message), !pluginFilePanelInProgress, let window = window,
              let bytes = try? pluginExportArchive(message.body) else { replyHandler(nil, "plugin_export_refused"); return }
        pluginFilePanelInProgress = true
        let panel = NSSavePanel()
        panel.title = "Export Styx plugin"
        panel.nameFieldStringValue = "styx-native.zip"
        panel.allowedContentTypes = [.zip]
        panel.allowsOtherFileTypes = false
        panel.beginSheetModal(for: window) { [weak self] response in
            guard let owner = self else { replyHandler(nil, "plugin_export_unavailable"); return }
            owner.pluginFilePanelInProgress = false
            guard response == .OK else { replyHandler(["status": "cancelled"], nil); return }
            // A closed window or page outside the owned origin loses authority.
            // JavaScript never supplies a path, URL, or filename.
            guard owner.trustedPluginExport(message), let destination = panel.url,
                  destination.isFileURL, destination.pathExtension.lowercased() == "zip" else {
                replyHandler(nil, "plugin_export_refused"); return
            }
            do {
                var info = stat()
                if lstat(destination.path, &info) == 0 && info.st_mode & S_IFMT != S_IFREG { throw PluginExportError.refused }
                try bytes.write(to: destination, options: .atomic)
                replyHandler(["status": "saved"], nil)
            } catch { replyHandler(nil, "plugin_export_save_failed") }
        }
    }
    func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping ([URL]?) -> Void) {
        guard webView === self.webView, trustedPluginFrame(frame), !pluginFilePanelInProgress,
              !parameters.allowsDirectories, !parameters.allowsMultipleSelection, let window = window else { completionHandler(nil); return }
        pluginFilePanelInProgress = true
        let panel = NSOpenPanel()
        panel.title = "Choose Styx plugin icon"
        panel.message = "Choose one square PNG image, up to 256 KiB."
        panel.allowedContentTypes = [.png]
        panel.allowsOtherFileTypes = false
        panel.canChooseFiles = true; panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false; panel.resolvesAliases = false
        panel.beginSheetModal(for: window) { [weak self] response in
            guard let owner = self else { completionHandler(nil); return }
            owner.pluginFilePanelInProgress = false
            guard response == .OK, owner.trustedPluginFrame(frame), panel.urls.count == 1,
                  let selected = panel.urls.first, let accepted = try? pluginIconFile(selected) else { completionHandler(nil); return }
            completionHandler([accepted])
        }
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

@MainActor func styxApplicationMenu(actionTarget: StyxDelegate? = nil) -> NSMenu {
    let chinese = (Locale.preferredLanguages.first ?? "en").hasPrefix("zh")
    func text(_ zh: String, _ en: String) -> String { chinese ? zh : en }
    let main = NSMenu()
    let appItem = NSMenuItem(title: "Styx", action: nil, keyEquivalent: ""); main.addItem(appItem)
    let appMenu = NSMenu(title: "Styx"); appItem.submenu = appMenu
    appMenu.addItem(withTitle: text("打开 Styx…", "Open Styx…"), action: #selector(StyxDelegate.openSettings), keyEquivalent: "o").target = actionTarget
    #if STYX_PRODUCT_UI
    appMenu.addItem(withTitle: text("设置…", "Settings…"), action: #selector(StyxDelegate.openProductPreferences), keyEquivalent: ",").target = actionTarget
    actionTarget?.platformUpdate?.appendMenuItem(to: appMenu)
    #endif
    appMenu.addItem(NSMenuItem.separator())
    appMenu.addItem(withTitle: text("退出 Styx", "Quit Styx"), action: #selector(StyxDelegate.quit), keyEquivalent: "q").target = actionTarget
    let fileItem = NSMenuItem(title: text("文件", "File"), action: nil, keyEquivalent: ""); main.addItem(fileItem)
    let fileMenu = NSMenu(title: text("文件", "File")); fileItem.submenu = fileMenu
    // AppKit routes Close to the key window; closing a window does not quit Styx.
    fileMenu.addItem(withTitle: text("关闭窗口", "Close Window"), action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
    let editItem = NSMenuItem(title: text("编辑", "Edit"), action: nil, keyEquivalent: ""); main.addItem(editItem)
    let edit = NSMenu(title: text("编辑", "Edit")); editItem.submenu = edit
    edit.addItem(withTitle: text("撤销", "Undo"), action: Selector(("undo:")), keyEquivalent: "z")
    edit.addItem(withTitle: text("重做", "Redo"), action: Selector(("redo:")), keyEquivalent: "z").keyEquivalentModifierMask = [.command, .shift]
    edit.addItem(NSMenuItem.separator())
    // Nil targets deliberately use AppKit's responder chain. Secure fields keep
    // their native copy/cut restrictions; Styx never handles clipboard contents.
    edit.addItem(withTitle: text("剪切", "Cut"), action: #selector(NSText.cut(_:)), keyEquivalent: "x")
    edit.addItem(withTitle: text("复制", "Copy"), action: #selector(NSText.copy(_:)), keyEquivalent: "c")
    edit.addItem(withTitle: text("粘贴", "Paste"), action: #selector(NSText.paste(_:)), keyEquivalent: "v")
    edit.addItem(withTitle: text("全选", "Select All"), action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
    return main
}

// A template mask adapts the same brand glyph to the menu bar appearance.
func styxStatusItemImage(source: NSImage) -> NSImage? {
    guard let image = styxBrandGlyph(source: source) else { return nil }
    image.isTemplate = true
    return image
}

#if STYX_PRODUCT_UI
func productComputerUseRequested(_ status: ProductJSON, guiAvailable: Bool) -> Bool {
    if status["mode"].string == "rust_host" || status["desktop_intent"] != .null {
        let intent = status["desktop_intent"]
        return guiAvailable && status["schema"] == .number(1) && status["mode"].string == "rust_host" &&
            status["admission_fenced"] == .bool(false) &&
            ["started", "connected"].contains(status["foreground"]["status"].string ?? "") &&
            intent["schema"] == .number(1) && intent["source"] == .string("approved_host_configuration") &&
            intent["computer_requested"] == .bool(true)
    }
    guard guiAvailable, status["deployment"]["roles"]["host"].string == "local" else { return false }
    let change = status["deviceCapabilities"]
    if ["running", "uncertain"].contains(change["status"].string ?? "") { return false }
    if change["status"].string == "updated", change["phase"].string == "complete", change["computer"] == .bool(false) { return false }
    // The deployment expresses intent; only the approved Host configuration
    // reported by its authenticated owner can enable an App-owned component.
    let foreground = status["foreground"]
    return ["authenticated_foreground_owner", "current_process"].contains(foreground["observation"].string ?? "") &&
        ["started", "connected", "using_service"].contains(foreground["status"].string ?? "") &&
        ["foreground", "service"].contains(foreground["host"].string ?? "") && foreground["computerRequested"] == .bool(true)
}
// Match the existing owned Core operation budget. Expiry withdraws descriptor
// availability only; it never kills/replaces the daemon or retries a mutation.
let productDesktopIntentMaxAge: TimeInterval = 150
func productDesktopIntentFresh(_ observed: TimeInterval?, now: TimeInterval) -> Bool {
    guard let observed = observed, observed.isFinite, now.isFinite else { return false }
    let elapsed = now - observed
    return elapsed >= 0 && elapsed <= productDesktopIntentMaxAge
}
func productSystemQuitReason(_ reason: OSType?) -> Bool {
    guard let reason = reason else { return false }
    return [OSType(kAEQuitAll), OSType(kAEShutDown), OSType(kAERestart), OSType(kAEReallyLogOut)].contains(reason)
}
#endif

// Synchronous original-child wait runs off AppKit. A forced exit is reported as
// unknown native cleanup, even though the original OS process has been reaped.
private func stopAndWaitForOwnedDaemon(_ child: Process) -> Bool {
    var forced = false
    if child.isRunning {
        let limit = ProcessInfo.processInfo.systemUptime + 3
        while child.isRunning && ProcessInfo.processInfo.systemUptime < limit { Thread.sleep(forTimeInterval: 0.02) }
        if child.isRunning {
            forced = true; child.terminate()
            let termLimit = ProcessInfo.processInfo.systemUptime + 1
            while child.isRunning && ProcessInfo.processInfo.systemUptime < termLimit { Thread.sleep(forTimeInterval: 0.02) }
            if child.isRunning { kill(child.processIdentifier, SIGKILL) }
        }
    }
    child.waitUntilExit()
    return forced || child.terminationReason != .exit || child.terminationStatus != 0
}

@MainActor final class StyxDelegate: NSObject, NSApplicationDelegate {
    var setupProcess: Process?
    var setupInput: Pipe?
    var setupOutput: Pipe?
    var setupURL: URL?
    #if STYX_PRODUCT_UI
    var setupWindow: ProductWindowController?
    #else
    var setupWindow: SetupWindowController?
    #endif
    #if STYX_PRODUCT_UI
    var nativeCore: ProductOwnedCore?
    var nativeCoreStarting = false
    var nativeCoreAttempted = false
    var componentTimer: Timer?
    var componentObservationPending = false
    var nativeComponentObservation: UUID?
    var nativeDesktopIntentObservedAt: TimeInterval?
    var computerPermissionRecoveryRequired = false
    var computerUseRequested = false
    #endif
    var terminationPreservesRecovery = false
    var terminationPending = false
    var terminationApproved = false
    var setupBuffer = ""
    var setupOpenRequested = false
    #if STYX_PRODUCT_UI
    var platformUpdate: ProductPlatformUpdate?
    #endif
    var setupStatusLine: NSMenuItem?
    let setupPreference = "Styx.SetupWindowOpened.v1"
    var runtime: RuntimeDirectory?
    var daemon: Process?
    var daemonStopTask: Task<Void, Never>?
    var lifetimeWriter: FileHandle?
    var timer: Timer?
    var statusItem: NSStatusItem?
    #if STYX_PRODUCT_UI
    var menuOpenRequested = false
    #endif
    var statusLine: NSMenuItem?
    var phase = "stopped"
    var generation = UUID().uuidString
    var deadline = Date()
    var lastGrants: String?
    var signalSources: [DispatchSourceSignal] = []

    func applicationDidFinishLaunching(_ notification: Notification) {
        // SMAppService.mainApp uses the launch Apple Event, not a command-line
        // flag. Login startup stays in the menu bar, including a first launch.
        let launchEvent = NSAppleEventManager.shared().currentAppleEvent
        let launchedAtLogin = launchEvent?.eventID == AEEventID(kAEOpenApplication)
            && launchEvent?.paramDescriptor(forKeyword: AEKeyword(keyAEPropData))?.enumCodeValue == OSType(keyAELaunchedAsLogInItem)
        #if STYX_PRODUCT_UI
        platformUpdate = ProductPlatformUpdate.configured()
        #endif
        NSApp.mainMenu = styxApplicationMenu(actionTarget: self)
        for number in [SIGTERM, SIGINT] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { [weak self] in
                self?.terminationPreservesRecovery = true
                #if STYX_PRODUCT_UI
                productScheduleApplicationTermination()
                #else
                NSApp.terminate(nil)
                #endif
            }
            source.resume(); signalSources.append(source)
        }
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let root = Bundle.main.resourceURL,
           let source = NSImage(contentsOf: root.appendingPathComponent("brand/styx-icon-light-source.jpg")),
           let image = styxStatusItemImage(source: source) {
            item.button?.image = image; item.button?.imagePosition = .imageOnly; item.button?.title = ""
        } else { item.button?.title = "Styx" }
        item.button?.setAccessibilityLabel("Styx"); item.button?.toolTip = "Styx"
        let menu = NSMenu()
        statusLine = menu.addItem(withTitle: "Starting…", action: nil, keyEquivalent: "")
        menu.addItem(withTitle: "Open Styx…", action: #selector(openSettings), keyEquivalent: "o")
        #if STYX_PRODUCT_UI
        menu.addItem(withTitle: "Settings…", action: #selector(openProductPreferences), keyEquivalent: ",")
        #endif
        setupStatusLine = menu.addItem(withTitle: "Local setup is not running", action: nil, keyEquivalent: "")
        menu.addItem(NSMenuItem.separator())
        #if STYX_PRODUCT_UI
        menu.addItem(withTitle: productText("Computer Use 权限…", "Computer Use permissions…"), action: #selector(requestPermissions), keyEquivalent: "")
        #else
        menu.addItem(withTitle: "Request macOS permissions…", action: #selector(requestPermissions), keyEquivalent: "")
        #endif
        menu.addItem(withTitle: "Restart embedded Cua", action: #selector(restart), keyEquivalent: "r")
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Quit Styx", action: #selector(quit), keyEquivalent: "q")
        for entry in menu.items { entry.target = self }
        #if STYX_PRODUCT_UI
        item.button?.target = self
        item.button?.action = #selector(toggleProductPanel)
        #else
        item.menu = menu
        #endif
        statusItem = item
        if let resources = Bundle.main.resourceURL,
           FileManager.default.isExecutableFile(atPath: bundledCoreExecutable(resources).path),
           Bundle.main.bundleURL.standardizedFileURL.path != "/Applications/Styx.app" {
            let alert = NSAlert(); alert.messageText = "Move Styx to Applications first"
            alert.informativeText = "Drag the complete Styx.app to /Applications, then open it there. Do not replace an existing Styx installation without reviewing it first. Settings and permissions need a stable app location."
            alert.runModal(); terminationPreservesRecovery = true; NSApp.terminate(nil); return
        }
        #if STYX_PRODUCT_UI
        statusLine?.title = "Computer Use is not enabled"
        #else
        do { runtime = try RuntimeDirectory(); try start() }
        catch { phase = "blocked"; statusLine?.title = "Blocked: \(error)" }
        #endif
        // Product startup is exclusively Rust. Missing native metadata is a
        // refusal, never an implicit selection of the historical Node helper.
        #if STYX_PRODUCT_UI
        do { try startSetup(openWindow: !launchedAtLogin && !UserDefaults.standard.bool(forKey: setupPreference)) }
        catch { setupStatusLine?.title = "Native Host settings unavailable; original identity retained" }
        #else
        // A competing Cua owner does not prevent opening this app's setup UI.
        if let resources = Bundle.main.resourceURL,
           (FileManager.default.isExecutableFile(atPath: bundledCoreExecutable(resources).path) || FileManager.default.fileExists(atPath: resources.appendingPathComponent("macos-runtime.json").path)) {
            do { try startSetup(openWindow: !launchedAtLogin && !UserDefaults.standard.bool(forKey: setupPreference)) }
            catch { setupStatusLine?.title = "Local setup unavailable; reopen Settings" }
        }
        #endif
    }
    private func bundledCoreExecutable(_ resources: URL) -> URL {
        let helper = resources.deletingLastPathComponent().appendingPathComponent("Helpers/Styx Core.app")
        if FileManager.default.fileExists(atPath: helper.path) {
            return helper.appendingPathComponent("Contents/MacOS/Styx Core")
        }
        return resources.appendingPathComponent("runtime/node")
    }
    func startSetup(openWindow: Bool) throws {
        setupOpenRequested = setupOpenRequested || openWindow
        if let url = setupURL { if setupOpenRequested { showSetup(url) }; return }
        guard setupProcess == nil else { return }
        guard let resources = Bundle.main.resourceURL else { throw HostError.daemonUnavailable }
        #if STYX_PRODUCT_UI
        ProductNativeDiagnostics.lifecycle(.bootstrapEntered)
        nativeCoreAttempted = true
        if let _ = nativeCore { setupWindow?.present(); return }
        guard !nativeCoreStarting else { return }; nativeCoreStarting = true
        Task { [self] in
            defer { nativeCoreStarting = false }
            do {
                let core = try await Task.detached { try ProductOwnedCore.open(resources: resources) }.value
                guard !terminationPending else { core.requestEOF(); return }
                nativeCore = core
                ProductNativeDiagnostics.lifecycle(.coreAdopted)
                let model = ProductModel(owned: core)
                model.recoverComputerUse = { [weak self, weak core] in
                    guard let owner = self, let original = core else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
                    try await owner.recoverComputerUseAfterPermissions(original)
                }
                setupWindow = ProductWindowController(model: model)
                ProductNativeDiagnostics.lifecycle(.windowCreated)
                await model.bootstrap()
                guard model.loaded else { core.requestEOF(); nativeCore = nil; throw ProductOwnedCoreError.unavailable }
                ProductNativeDiagnostics.lifecycle(.bootstrapCompleted)
                observeProductComponents(core)
                setupStatusLine?.title = "Native Host settings ready"
                if setupOpenRequested { setupWindow?.present(); setupOpenRequested = false }
            } catch { ProductNativeDiagnostics.lifecycle(.bootstrapFailed); setupStatusLine?.title = "Native package unavailable; original identity retained" }
        }
        return
        #else
        let node = bundledCoreExecutable(resources)
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
            guard let owner = self else { return }
            DispatchQueue.main.async {
                guard owner.setupProcess === child else { return }
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
                    #if STYX_PRODUCT_UI
                    owner.observeProductComponents(url)
                    if owner.setupWindow == nil { owner.setupWindow = owner.makeProductWindow(url) }
                    if let model = owner.setupWindow?.model {
                        Task {
                            await model.bootstrap()
                            if model.status["nativeStartup"]["status"].string == "reconciliation_required", model.error != nil {
                                owner.setupWindow?.showSettings(.general)
                            }
                        }
                    }
                    if owner.menuOpenRequested { owner.toggleProductPanel() }
                    #endif
                    if owner.setupOpenRequested { owner.showSetup(url) }
                }
            }
        }
        child.terminationHandler = { [weak self] terminated in
            guard let owner = self else { return }
            DispatchQueue.main.async {
                guard owner.setupProcess === terminated else { return }
                owner.setupOutput?.fileHandleForReading.readabilityHandler = nil
                try? owner.setupInput?.fileHandleForWriting.close()
                owner.setupProcess = nil; owner.setupInput = nil; owner.setupOutput = nil; owner.setupURL = nil
                owner.setupWindow?.close(); owner.setupWindow = nil
                #if STYX_PRODUCT_UI
                owner.componentTimer?.invalidate(); owner.componentTimer = nil
                owner.computerUseRequested = false; owner.stop()
                #endif
                owner.setupStatusLine?.title = "Local setup stopped; reopen Settings"
            }
        }
        setupProcess = child; setupInput = input; setupOutput = output
        do { try child.run() }
        catch { stopSetup(); throw error }
        try? input.fileHandleForReading.close(); try? output.fileHandleForWriting.close()
        #endif
    }
    func showSetup(_ url: URL) {
        if setupWindow == nil {
            #if STYX_PRODUCT_UI
            setupWindow = makeProductWindow(url)
            #else
            setupWindow = SetupWindowController(sessionURL: url)
            #endif
        }
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
    #if STYX_PRODUCT_UI
    @objc func toggleProductPanel() {
        if nativeCore != nil { setupWindow?.present(); return }
        menuOpenRequested = true
        do {
            try startSetup(openWindow: false)
            guard let url = setupURL, let button = statusItem?.button else { return }
            menuOpenRequested = false
            if setupWindow == nil { setupWindow = makeProductWindow(url) }
            setupWindow?.toggleMenu(relativeTo: button, quit: { [weak self] in self?.quit() })
        } catch { openSettings() }
    }
    func makeProductWindow(_ url: URL) -> ProductWindowController {
        let controller = ProductWindowController(sessionURL: url)
        controller.model.recoverComputerUse = { [weak self] in
            guard let owner = self else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
            try await owner.recoverComputerUseAfterPermissions(url)
        }
        controller.model.launchPayloadUpdater = { [weak self] ticket in
            guard let owner = self, !owner.terminationPending,
                  ticket.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil,
                  let bundled = Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("StyxUpdater") else { throw HostError.unsafeRuntime }
            let root = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support/Styx/Setup")
            let state = root.appendingPathComponent("deployment").path
            let binding = SHA256.hash(data: Data(state.utf8)).map { String(format: "%02x", $0) }.joined().prefix(16)
            let stages = root.appendingPathComponent("host-payload-updaters"), group = stages.appendingPathComponent(String(binding)), directory = group.appendingPathComponent(ticket), helper = directory.appendingPathComponent("StyxUpdater")
            for url in [root, stages, group, directory, helper] {
                let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
                guard attributes[.type] as? FileAttributeType == (url == helper ? .typeRegular : .typeDirectory),
                      (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
                      let mode = attributes[.posixPermissions] as? NSNumber, mode.intValue & 0o077 == 0 else { throw HostError.unsafeRuntime }
            }
            guard SHA256.hash(data: try Data(contentsOf: helper)) == SHA256.hash(data: try Data(contentsOf: bundled)) else { throw HostError.unsafeRuntime }
            let process = Process(); process.executableURL = helper; process.arguments = [ticket]
            process.standardInput = FileHandle.nullDevice; process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
            process.environment = ["HOME": NSHomeDirectory(), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": NSTemporaryDirectory()]
            try process.run()
            productScheduleApplicationTermination()
        }
        controller.showMenuInvitation = { [weak self] in
            self?.toggleProductPanel()
            self?.setupWindow?.model.beginDeviceInvitation()
        }
        return controller
    }
    func recoverComputerUseAfterPermissions(_ url: URL) async throws {
        guard setupURL == url, !terminationPending else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
        let status = try await ProductCoreClient(sessionURL: url).read("native-status")
        let session = CGSessionCopyCurrentDictionary() as? [String: Any]
        guard setupURL == url, !terminationPending,
              productComputerUseRequested(status, guiAvailable: session?[kCGSessionOnConsoleKey as String] as? Bool == true),
              AXIsProcessTrusted(), CGPreflightScreenCaptureAccess() else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
        // Observe a change before accepting Continue, even if the 200ms poll
        // has not run yet. Only this explicit action may restore this stop cause.
        poll()
        if phase == "permissions_changed" || computerPermissionRecoveryRequired {
            await stopAndJoin()
            guard computerUseRequested, daemon == nil else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
            computerPermissionRecoveryRequired = false
            do { try start() }
            catch { computerPermissionRecoveryRequired = true; throw error }
        }
        guard daemon?.isRunning == true else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
        // A live owned child is not native GUI or chat-account acceptance.
    }
    @objc func openProductPreferences() {
        openSettings()
        setupWindow?.showPreferences()
    }
    #endif
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openSettings(); return true
    }
    #if STYX_PRODUCT_UI
    func withdrawNativeComputerUse(_ message: String) {
        nativeDesktopIntentObservedAt = nil
        computerUseRequested = false
        stop()
        statusLine?.title = message
    }
    func checkNativeComponentAvailability(_ core: ProductOwnedCore) {
        guard nativeCore === core else { return }
        if !core.isRunning {
            withdrawNativeComputerUse("Core connection stopped; Computer Use unavailable")
        } else if !productDesktopIntentFresh(nativeDesktopIntentObservedAt, now: ProcessInfo.processInfo.systemUptime) {
            // A busy Core is not a capability revocation. Keep custody of the
            // original daemon, but expose no descriptor while its intent is stale.
            if let runtime = runtime { unlink(runtime.descriptor) }
        }
    }
    func observeProductComponents(_ core: ProductOwnedCore) {
        componentTimer?.invalidate()
        nativeComponentObservation = nil; nativeDesktopIntentObservedAt = nil
        componentTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self, weak core] _ in
            guard let owner = self, let original = core else { return }
            Task { @MainActor in
                owner.checkNativeComponentAvailability(original)
                await owner.refreshProductComponents(original)
            }
        }
        Task { @MainActor in await refreshProductComponents(core) }
    }
    func refreshProductComponents(_ core: ProductOwnedCore) async {
        guard nativeCore === core, nativeComponentObservation == nil, !terminationPending else { return }
        checkNativeComponentAvailability(core)
        guard core.isRunning, setupWindow?.model.busy != true else { return }
        let observation = UUID(), requestedAt = ProcessInfo.processInfo.systemUptime
        nativeComponentObservation = observation
        defer { if nativeComponentObservation == observation { nativeComponentObservation = nil } }
        do {
            let status = try await core.call("status")
            guard nativeCore === core, nativeComponentObservation == observation, !terminationPending else { return }
            guard core.isRunning else { withdrawNativeComputerUse("Core connection stopped; Computer Use unavailable"); return }
            guard productDesktopIntentFresh(requestedAt, now: ProcessInfo.processInfo.systemUptime) else {
                nativeDesktopIntentObservedAt = nil
                if let runtime = runtime { unlink(runtime.descriptor) }
                return
            }
            guard status["mode"].string == "rust_host" else { withdrawNativeComputerUse("Core status invalid; Computer Use unavailable"); return }
            nativeDesktopIntentObservedAt = requestedAt
            let session = CGSessionCopyCurrentDictionary() as? [String: Any]
            let requested = productComputerUseRequested(status, guiAvailable: session?[kCGSessionOnConsoleKey as String] as? Bool == true)
            let changed = requested != computerUseRequested
            computerUseRequested = requested
            if requested {
                // Daemon exits and permission changes still require an explicit
                // recovery action; a periodic read is not a restart policy.
                if changed && !computerPermissionRecoveryRequired {
                    if runtime == nil { runtime = try RuntimeDirectory() }
                    try start()
                }
            } else { stop(); statusLine?.title = "Computer Use is not enabled in this session" }
        } catch {
            guard nativeCore === core, nativeComponentObservation == observation else { return }
            withdrawNativeComputerUse("Core status unavailable; Computer Use withdrawn")
        }
    }
    func recoverComputerUseAfterPermissions(_ core: ProductOwnedCore) async throws {
        guard nativeCore === core, core.isRunning, !terminationPending else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
        let requestedAt = ProcessInfo.processInfo.systemUptime
        let status: ProductJSON
        do { status = try await core.call("status") }
        catch {
            if nativeCore === core { withdrawNativeComputerUse("Core status unavailable; Computer Use withdrawn") }
            throw error
        }
        let session = CGSessionCopyCurrentDictionary() as? [String: Any]
        guard nativeCore === core, !terminationPending else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
        guard core.isRunning, status["mode"].string == "rust_host",
              productComputerUseRequested(status, guiAvailable: session?[kCGSessionOnConsoleKey as String] as? Bool == true) else {
            withdrawNativeComputerUse("Computer Use is not enabled in this session")
            throw ProductWorkflowError.computerPermissionRecoveryRequired
        }
        guard productDesktopIntentFresh(requestedAt, now: ProcessInfo.processInfo.systemUptime),
              AXIsProcessTrusted(), CGPreflightScreenCaptureAccess() else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
        nativeDesktopIntentObservedAt = requestedAt
        computerUseRequested = true
        poll()
        if computerPermissionRecoveryRequired {
            await stopAndJoin()
            guard nativeCore === core, core.isRunning, !terminationPending else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
            computerPermissionRecoveryRequired = false
            do { try start() }
            catch { computerPermissionRecoveryRequired = true; throw error }
        }
        guard daemon?.isRunning == true, daemonStopTask == nil else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
        // Permission recovery remains distinct from native effect acceptance.
    }
    func observeProductComponents(_ url: URL) {
        componentTimer?.invalidate()
        componentTimer = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            guard let owner = self else { return }
            Task { @MainActor in await owner.refreshProductComponents(url) }
        }
        Task { @MainActor in await refreshProductComponents(url) }
    }
    func refreshProductComponents(_ url: URL) async {
        guard setupURL == url, !componentObservationPending, !terminationPending else { return }
        componentObservationPending = true
        defer { componentObservationPending = false }
        do {
            let client = try ProductCoreClient(sessionURL: url)
            let status = try await client.read("native-status")
            guard setupURL == url, !terminationPending else { return }
            let session = CGSessionCopyCurrentDictionary() as? [String: Any]
            let requested = productComputerUseRequested(status, guiAvailable: session?[kCGSessionOnConsoleKey as String] as? Bool == true)
            guard requested != computerUseRequested else { return }
            computerUseRequested = requested
            if requested {
                if runtime == nil { runtime = try RuntimeDirectory() }
                try start()
            } else { stop(); statusLine?.title = "Computer Use is not enabled in this session" }
        } catch {
            // A failed read is not a new capability decision. Keep the last
            // scoped state; a terminated Core separately withdraws its child.
            setupStatusLine?.title = "Component status unavailable; reopen Settings"
        }
    }
    #endif
    func stopSetup() {
        #if STYX_PRODUCT_UI
        nativeCore?.requestEOF(); nativeCore = nil
        nativeComponentObservation = nil; nativeDesktopIntentObservedAt = nil
        componentTimer?.invalidate(); componentTimer = nil; computerUseRequested = false
        stop()
        #endif
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
        #if STYX_PRODUCT_UI
        let session = CGSessionCopyCurrentDictionary() as? [String: Any]
        guard computerUseRequested, !computerPermissionRecoveryRequired,
              session?[kCGSessionOnConsoleKey as String] as? Bool == true else { throw HostError.daemonUnavailable }
        if nativeCoreAttempted {
            guard nativeCore?.isRunning == true,
                  productDesktopIntentFresh(nativeDesktopIntentObservedAt, now: ProcessInfo.processInfo.systemUptime) else { throw HostError.daemonUnavailable }
        }
        #endif
        guard daemonStopTask == nil else { throw HostError.daemonUnavailable }
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
            guard let owner = self else { return }
            DispatchQueue.main.async {
                guard owner.daemon === terminated else { return }
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
        timer = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self] _ in
            guard let owner = self else { return }
            Task { @MainActor in owner.poll() }
        }
    }
    func poll() {
        guard let runtime = runtime, let daemon = daemon, daemon.isRunning, daemonStopTask == nil else { return }
        #if STYX_PRODUCT_UI
        if nativeCoreAttempted {
            guard let core = nativeCore, core.isRunning else { withdrawNativeComputerUse("Core connection stopped; Computer Use unavailable"); return }
            guard computerUseRequested,
                  productDesktopIntentFresh(nativeDesktopIntentObservedAt, now: ProcessInfo.processInfo.systemUptime) else { unlink(runtime.descriptor); return }
        }
        let session = CGSessionCopyCurrentDictionary() as? [String: Any]
        guard session?[kCGSessionOnConsoleKey as String] as? Bool == true else {
            computerUseRequested = false; stop(); statusLine?.title = "Computer Use is not available in this session"; return
        }
        #endif
        let ax = AXIsProcessTrusted(), screen = CGPreflightScreenCaptureAccess()
        let grants = "\(ax):\(screen)"
        if let previous = lastGrants, previous != grants {
            #if STYX_PRODUCT_UI
            computerPermissionRecoveryRequired = true
            #endif
            stop(); phase = "permissions_changed"
            statusLine?.title = "Permissions changed; review Computer Use permissions in Styx"; return
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
        // Withdraw synchronously, before asking the original child to drain.
        if let runtime = runtime { unlink(runtime.descriptor) }
        guard daemonStopTask == nil else { return }
        try? lifetimeWriter?.close(); lifetimeWriter = nil
        guard let child = daemon else {
            if phase != "cleanup_unknown" { phase = "stopped" }
            return
        }
        child.terminationHandler = nil
        phase = "stopping"
        daemonStopTask = Task { [self] in
            // AppKit must remain free to consume native cleanup/frame callbacks.
            // Custody stays with this exact Process until its actual wait ends.
            let forced = await Task.detached { stopAndWaitForOwnedDaemon(child) }.value
            if daemon === child {
                daemon = nil; runtime?.clear()
                if forced { phase = "cleanup_unknown"; statusLine?.title = "Cua exited; native cleanup was not confirmed" }
                else if phase == "stopping" { phase = "stopped" }
            }
            daemonStopTask = nil
        }
    }
    func stopAndJoin() async {
        stop()
        await daemonStopTask?.value
    }
    @objc func requestPermissions() {
        #if STYX_PRODUCT_UI
        // The product view owns each explicit permission action. A menu click
        // only opens that view; it must not raise two OS prompts and an alert.
        openSettings()
        if let model = setupWindow?.model {
            model.observePermissions()
            model.page = model.computerApproved || nativeCore != nil && computerUseRequested ? .permissions : .settings
        }
        #else
        // Only an explicit local menu action can trigger OS-owned permission UI.
        _ = AXIsProcessTrustedWithOptions(["AXTrustedCheckOptionPrompt": true] as CFDictionary)
        _ = CGRequestScreenCaptureAccess()
        let alert = NSAlert()
        alert.messageText = "Allow Styx in macOS Privacy & Security"
        alert.informativeText = "Enable Accessibility and Screen Recording for Styx. Quit and reopen Styx after changing grants; reconnect clients to the new generation. A grant alone does not verify capture or actions. Explicit application scripts may separately request Automation approval for the target application."
        alert.runModal()
        #endif
    }
    @objc func restart() {
        Task {
            await stopAndJoin()
            do { try start() } catch { statusLine?.title = "Restart blocked: \(error)" }
        }
    }
    @objc func quit() {
        terminationPreservesRecovery = false
        #if STYX_PRODUCT_UI
        productScheduleApplicationTermination()
        #else
        NSApp.terminate(nil)
        #endif
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        #if STYX_PRODUCT_UI
        ProductNativeDiagnostics.lifecycle(.terminateEntered)
        #endif
        if terminationPending {
            #if STYX_PRODUCT_UI
            ProductNativeDiagnostics.lifecycle(.terminatePending)
            #endif
            return .terminateLater
        }
        #if STYX_PRODUCT_UI
        if nativeCoreAttempted {
            // Original bootstrap worker still owns its child until it completes.
            // A UI close cannot make an in-flight verified launch ownerless.
            if nativeCoreStarting { ProductNativeDiagnostics.lifecycle(.terminateCancelStarting); return .terminateCancel }
            guard let _ = nativeCore else {
                guard daemon != nil || daemonStopTask != nil else { ProductNativeDiagnostics.lifecycle(.terminateNow); return .terminateNow }
                terminationPending = true
                ProductNativeDiagnostics.lifecycle(.terminateLater)
                Task { await stopAndJoin(); terminationPending = false; ProductNativeDiagnostics.lifecycle(.terminateReply, ok: true); sender.reply(toApplicationShouldTerminate: true) }
                return .terminateLater
            }
            // A live owner without its UI coordinator cannot reply to the
            // deferred termination request. Refuse this quit, retaining custody.
            guard let window = setupWindow else {
                terminationPending = false
                ProductNativeDiagnostics.lifecycle(.terminateCancelNoWindow)
                return .terminateCancel
            }
            terminationPending = true
            ProductNativeDiagnostics.lifecycle(.terminateLater)
            window.prepareToQuit { [weak self] approved in
                ProductNativeDiagnostics.lifecycle(.terminateAdmission, ok: approved)
                guard let owner = self else { ProductNativeDiagnostics.lifecycle(.terminateReply, ok: false); sender.reply(toApplicationShouldTerminate: false); return }
                if approved {
                    owner.nativeCore = nil
                    owner.nativeComponentObservation = nil; owner.nativeDesktopIntentObservedAt = nil
                    owner.componentTimer?.invalidate(); owner.componentTimer = nil
                    Task {
                        await owner.stopAndJoin()
                        owner.terminationPending = false
                        ProductNativeDiagnostics.lifecycle(.terminateReply, ok: true)
                        sender.reply(toApplicationShouldTerminate: true)
                    }
                } else {
                    owner.terminationPending = false
                    ProductNativeDiagnostics.lifecycle(.terminateReply, ok: false)
                    sender.reply(toApplicationShouldTerminate: false)
                }
            }
            return .terminateLater
        }
        let reason = NSAppleEventManager.shared().currentAppleEvent?.paramDescriptor(forKeyword: AEKeyword(kAEQuitReason))?.enumCodeValue
        let userQuit = !terminationPreservesRecovery && !productSystemQuitReason(reason)
        if userQuit && !terminationApproved && setupURL == nil {
            let alert = NSAlert()
            alert.messageText = "Styx could not finish quitting"
            alert.informativeText = "The local control connection is unavailable, so login recovery cannot yet be checked. Reopen Styx settings and retry Quit."
            alert.runModal()
            return .terminateCancel
        }
        if userQuit && !terminationApproved, let url = setupURL {
            if setupWindow == nil { setupWindow = makeProductWindow(url) }
            terminationPending = true
            setupWindow?.prepareToQuit { [weak self] approved in
                guard let owner = self else { sender.reply(toApplicationShouldTerminate: false); return }
                owner.terminationApproved = approved
                if approved {
                    owner.stopSetup()
                    Task {
                        await owner.stopAndJoin()
                        owner.terminationPending = false
                        sender.reply(toApplicationShouldTerminate: true)
                    }
                } else {
                    owner.terminationPending = false
                    sender.reply(toApplicationShouldTerminate: false)
                }
            }
            return .terminateLater
        }
        #endif
        stopSetup()
        guard daemon != nil || daemonStopTask != nil else { return .terminateNow }
        terminationPending = true
        Task {
            await stopAndJoin()
            terminationPending = false
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}

#if STYX_TESTING
#if STYX_PRODUCT_UI
if CommandLine.arguments.count == 4 && CommandLine.arguments[1] == "--invitation-self-test" {
    MainActor.assumeIsolated {
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        Task { @MainActor in
            do {
                let value = try String(contentsOfFile: CommandLine.arguments[2], encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
                guard let url = URL(string: value) else { throw ProductCoreError.invalidBootstrap }
                try await productInvitationSelfTest(sessionURL: url, mode: CommandLine.arguments[3]); exit(0)
            } catch { fputs("Styx invitation self-test failed: \(error)\n", stderr); exit(1) }
        }
        application.run()
    }
}
if CommandLine.arguments.count == 4 && CommandLine.arguments[1] == "--automatic-update-self-test" {
    MainActor.assumeIsolated {
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        Task { @MainActor in
            do {
                let value = try String(contentsOfFile: CommandLine.arguments[2], encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
                guard let url = URL(string: value) else { throw ProductCoreError.invalidBootstrap }
                try await productAutomaticUpdateSelfTest(sessionURL: url, mode: CommandLine.arguments[3]); exit(0)
            } catch { fputs("Styx automatic update self-test failed: \(error)\n", stderr); exit(1) }
        }
        application.run()
    }
}
if CommandLine.arguments.count == 3 && CommandLine.arguments[1] == "--observation-self-test" {
    MainActor.assumeIsolated {
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        Task { @MainActor in
            do {
                let value = try String(contentsOfFile: CommandLine.arguments[2], encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
                guard let url = URL(string: value) else { throw ProductCoreError.invalidBootstrap }
                try await productObservationSelfTest(sessionURL: url); exit(0)
            } catch { fputs("Styx observation self-test failed: \(error)\n", stderr); exit(1) }
        }
        application.run()
    }
}
if CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--ui-preview" {
    MainActor.assumeIsolated {
        do { try productPresentationSnapshots(directory: nil); exit(0) }
        catch { fputs("Styx UI preview failed\n", stderr); exit(1) }
    }
}
// Allow process-local AppKit preferences (e.g. -AppleLanguages) without
// accidentally falling through to the real App when rendering a fixture.
if CommandLine.arguments.count >= 3 && CommandLine.arguments[1] == "--presentation-snapshots" {
    MainActor.assumeIsolated {
        do { try productPresentationSnapshots(directory: URL(fileURLWithPath: CommandLine.arguments[2])); exit(0) }
        catch { fputs("Styx presentation render failed\n", stderr); exit(1) }
    }
}
if CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--permission-state-self-test" {
    MainActor.assumeIsolated {
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        Task { @MainActor in
            do { try await productPermissionStateSelfTest(); exit(0) }
            catch { fputs("Styx isolated permission-state self-test failed: \(error)\n", stderr); exit(1) }
        }
        application.run()
    }
}
if CommandLine.arguments.count >= 2 && CommandLine.arguments[1] == "--edit-menu-self-test" {
    MainActor.assumeIsolated {
        do { try productEditMenuSelfTest(withMenu: !CommandLine.arguments.contains("--without-menu")); exit(0) }
        catch { fputs("Styx isolated edit-menu self-test failed\n", stderr); exit(1) }
    }
}
if CommandLine.arguments.count == 4 && ["--product-window-fixture", "--product-zip-window-fixture"].contains(CommandLine.arguments[1]) {
    let input = URL(fileURLWithPath: CommandLine.arguments[2])
    let snapshot = URL(fileURLWithPath: CommandLine.arguments[3])
    guard let line = try? String(contentsOf: input, encoding: .utf8),
          let sessionURL = setupSessionURL("STYX_SETUP_URL\t" + line.trimmingCharacters(in: .whitespacesAndNewlines)) else { exit(2) }
    MainActor.assumeIsolated { ProductWindowController.runIsolatedSmoke(sessionURL: sessionURL, snapshot: snapshot, pluginZIP: CommandLine.arguments[1] == "--product-zip-window-fixture") }
}
#endif
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
    #if STYX_PRODUCT_UI
    try productCoreSelfTest()
    let requestedStatus: ProductJSON = .object(["deployment": .object(["roles": .object(["host": .string("local"), "computer": .string("requested")])])])
    precondition(!productComputerUseRequested(requestedStatus, guiAvailable: true))
    let approvedForeground: ProductJSON = .object(["status": .string("connected"), "observation": .string("authenticated_foreground_owner"), "host": .string("foreground"), "computerRequested": .bool(true)])
    let approvedStatus: ProductJSON = .object(["deployment": requestedStatus["deployment"], "foreground": approvedForeground])
    precondition(productComputerUseRequested(approvedStatus, guiAvailable: true))
    precondition(!productComputerUseRequested(approvedStatus, guiAvailable: false))
    let deniedStatus: ProductJSON = .object(["deployment": requestedStatus["deployment"], "foreground": .object(["status": .string("connected"), "observation": .string("authenticated_foreground_owner"), "host": .string("foreground"), "computerRequested": .bool(false)])])
    precondition(!productComputerUseRequested(deniedStatus, guiAvailable: true))
    let uncertainStatus: ProductJSON = .object(["deployment": requestedStatus["deployment"], "foreground": .object(["status": .string("needs_attention"), "observation": .string("authenticated_foreground_owner"), "host": .string("foreground"), "computerRequested": .bool(true)])])
    precondition(!productComputerUseRequested(uncertainStatus, guiAvailable: true))
    precondition(!productComputerUseRequested(.object([:]), guiAvailable: true))
    let disabledStatus: ProductJSON = .object(["deployment": requestedStatus["deployment"], "foreground": approvedForeground, "deviceCapabilities": .object(["status": .string("updated"), "phase": .string("complete"), "computer": .bool(false)])])
    precondition(!productComputerUseRequested(disabledStatus, guiAvailable: true))
    let nativeApproved: ProductJSON = .object(["schema": .number(1), "mode": .string("rust_host"),
        "admission_fenced": .bool(false), "foreground": .object(["status": .string("connected")]), "desktop_intent": .object([
        "schema": .number(1), "source": .string("approved_host_configuration"), "computer_requested": .bool(true)])])
    precondition(productComputerUseRequested(nativeApproved, guiAvailable: true))
    precondition(!productComputerUseRequested(nativeApproved, guiAvailable: false))
    let invalidNativeIntents: [ProductJSON] = [.null, .object([:]), .object(["schema": .number(1), "source": .string("requestJoin"), "computer_requested": .bool(true)]),
                                      .object(["schema": .number(1), "source": .string("approved_host_configuration"), "computer_requested": .bool(false)]),
                                      .object(["schema": .number(2), "source": .string("approved_host_configuration"), "computer_requested": .bool(true)]),
                                      .object(["schema": .number(1), "source": .string("approved_host_configuration"), "computer_requested": .string("true")])]
    for invalidIntent in invalidNativeIntents {
        var invalid = nativeApproved.object
        invalid["desktop_intent"] = invalidIntent
        invalid["deployment"] = requestedStatus["deployment"]
        invalid["foreground"] = approvedForeground
        precondition(!productComputerUseRequested(.object(invalid), guiAvailable: true))
    }
    let inconsistentNativeFields: [(String, ProductJSON)] = [
        ("schema", .number(2)), ("schema", .null), ("admission_fenced", .bool(true)),
        ("admission_fenced", .null), ("admission_fenced", .string("false")),
        ("foreground", .object(["status": .string("not_running")])), ("foreground", .null)]
    for (key, value) in inconsistentNativeFields {
        var invalid = nativeApproved.object; invalid[key] = value
        precondition(!productComputerUseRequested(.object(invalid), guiAvailable: true))
    }
    precondition(productDesktopIntentFresh(10, now: 160))
    precondition(!productDesktopIntentFresh(10, now: 160.001))
    precondition(!productDesktopIntentFresh(nil, now: 10))
    precondition(!productDesktopIntentFresh(11, now: 10))
    precondition(!productDesktopIntentFresh(0, now: .infinity))
    precondition(!productSystemQuitReason(nil))
    precondition(productSystemQuitReason(OSType(kAEReallyLogOut)))
    precondition(productSystemQuitReason(OSType(kAERestart)))
    #endif
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
    let archive = Data([0x50, 0x4b, 0x03, 0x04, 0x00])
    guard (try? pluginExportArchive(["base64": archive.base64EncodedString()])) == archive else { fatalError("bounded ZIP export rejected") }
    func expectPluginExportRefused(_ input: Any) {
        do { _ = try pluginExportArchive(input); fatalError("unsafe plugin export accepted") }
        catch PluginExportError.refused { }
        catch { fatalError("unexpected plugin export validation error") }
    }
    let invalidPluginExports: [Any] = [[:], ["base64": 123], ["base64": ""], ["path": "/tmp/no-write.zip"],
                         ["base64": archive.base64EncodedString(), "filename": "chosen-by-page.zip"],
                         ["base64": "UEsDBB=="], ["base64": "UEsDBA"], ["base64": "UEsDBA==\n"],
                         ["base64": Data([0x50, 0x4b, 0x05, 0x06]).base64EncodedString()],
                         ["base64": Data("not a ZIP".utf8).base64EncodedString()],
                         ["base64": String(repeating: "A", count: ((pluginExportMaximumBytes + 2) / 3) * 4 + 4)]]
    for invalid in invalidPluginExports {
        expectPluginExportRefused(invalid)
    }
    var largestArchive = Data([0x50, 0x4b, 0x03, 0x04])
    largestArchive.append(Data(repeating: 0, count: pluginExportMaximumBytes - 4))
    guard (try? pluginExportArchive(["base64": largestArchive.base64EncodedString()])) == largestArchive else { fatalError("ZIP export size boundary rejected") }
    largestArchive.append(0)
    expectPluginExportRefused(["base64": largestArchive.base64EncodedString()])
    func exportContext(_ current: URL? = origin, _ frame: URL? = origin, _ main: Bool = true,
                       _ scheme: String = "http", _ host: String = "127.0.0.1", _ port: Int = 1234) -> Bool {
        pluginExportContext(origin: origin, currentURL: current, frameURL: frame, isMainFrame: main,
                            securityProtocol: scheme, securityHost: host, securityPort: port)
    }
    guard exportContext() else { fatalError("owned main-frame export context rejected") }
    guard !exportContext(origin, origin, false), !exportContext(nil), !exportContext(origin, nil),
          !exportContext(origin, origin, true, "https"), !exportContext(origin, origin, true, "http", "localhost"),
          !exportContext(origin, origin, true, "http", "127.0.0.1", 4321) else { fatalError("foreign export frame accepted") }
    for bad in ["https://example.com/", "http://127.0.0.1:4321/", "http://user@127.0.0.1:1234/", "file:///tmp/plugin.zip", "blob:http://127.0.0.1:1234/arbitrary"] {
        let target = URL(string: bad)!
        guard !exportContext(target), !exportContext(origin, target) else { fatalError("unowned page authorized export") }
    }
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
        let icon = URL(fileURLWithPath: dir + "/plugin-icon.png")
        let pngHeader = Data([137, 80, 78, 71, 13, 10, 26, 10])
        try pngHeader.write(to: icon)
        guard try pluginIconFile(icon) == icon else { fatalError("selected PNG rejected") }
        func expectIconRefused(_ url: URL) {
            do { _ = try pluginIconFile(url); fatalError("unsafe icon file accepted") }
            catch PluginExportError.refused { }
            catch { fatalError("unexpected icon validation error") }
        }
        let iconLink = URL(fileURLWithPath: dir + "/plugin-icon-link.png")
        try FileManager.default.createSymbolicLink(atPath: iconLink.path, withDestinationPath: icon.path)
        expectIconRefused(iconLink)
        try FileManager.default.removeItem(at: iconLink)
        expectIconRefused(URL(fileURLWithPath: dir + "/missing.png"))
        expectIconRefused(URL(fileURLWithPath: dir))
        expectIconRefused(URL(string: "https://example.com/icon.png")!)
        try Data("not a PNG".utf8).write(to: icon); expectIconRefused(icon)
        var largestIcon = pngHeader
        largestIcon.append(Data(repeating: 0, count: 256 * 1024 - pngHeader.count))
        try largestIcon.write(to: icon)
        guard try pluginIconFile(icon) == icon else { fatalError("PNG size boundary rejected") }
        largestIcon.append(0); try largestIcon.write(to: icon); expectIconRefused(icon)
        try FileManager.default.removeItem(at: icon)
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
        print("Styx native ownership, settings navigation, ZIP export and PNG picker validation self-test passed; GUI file dialogs and TCC NOT RUN")
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
MainActor.assumeIsolated {
    let app = NSApplication.shared
    let delegate = StyxDelegate()
    app.delegate = delegate
    app.setActivationPolicy(.accessory)
    withExtendedLifetime(delegate) { app.run() }
}
