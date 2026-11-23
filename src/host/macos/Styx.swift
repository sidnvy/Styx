// Styx owns its embedded Cua lifetime and runs the Rust payload directly;
// macOS TCC responsibility still requires measurement on the signed installed App.
import AppKit
import ApplicationServices
import CoreGraphics
import Darwin
import UniformTypeIdentifiers

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
    func publishDescriptor(_ data: Data) throws {
        let url = URL(fileURLWithPath: descriptor)
        // The Rust reader retains file identity across its observation. Replacing
        // identical bytes during a read can fence an otherwise unchanged source.
        if (try? Data(contentsOf: url)) == data { return }
        let temporary = path + "/.connection-" + UUID().uuidString
        try data.write(to: URL(fileURLWithPath: temporary), options: .withoutOverwriting)
        defer { unlink(temporary) }
        guard chmod(temporary, 0o600) == 0,
              rename(temporary, descriptor) == 0 else { throw HostError.unsafeRuntime }
    }
    func prepareForLaunch() throws {
        var info = stat()
        if lstat(socket, &info) == 0 {
            // A crashed App can leave the socket after its embedded child exits.
            // The owner lock is held; reclaim only a dead child with no listener.
            guard info.st_mode & S_IFMT == S_IFSOCK,
                  let raw = try? String(contentsOfFile: path + "/cua.pid", encoding: .utf8),
                  let pid = pid_t(raw.trimmingCharacters(in: .whitespacesAndNewlines)), pid > 0,
                  kill(pid, 0) == -1, errno == ESRCH,
                  socketConnectionError(socket) == ECONNREFUSED else {
                unlink(descriptor)
                throw HostError.daemonUnavailable
            }
        } else if errno != ENOENT {
            throw HostError.daemonUnavailable
        }
        clear()
    }
    func clear() { unlink(descriptor); unlink(socket); unlink(path + "/cua.pid") }
    deinit { close(lock) }
}

// Socket existence is insufficient: acceptability is a transport-only boundary,
// never proof of MCP initialization, TCC attribution, or successful GUI actions.
func socketAccepts(_ path: String) -> Bool { socketConnectionError(path) == nil }
func socketConnectionError(_ path: String) -> Int32? {
    var addr = sockaddr_un()
    let bytes = Array(path.utf8CString)
    guard bytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else { return ENAMETOOLONG }
    addr.sun_family = sa_family_t(AF_UNIX)
    addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    withUnsafeMutableBytes(of: &addr.sun_path) { raw in
        for (i, byte) in bytes.enumerated() { raw[i] = UInt8(bitPattern: byte) }
    }
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return errno }
    defer { close(fd) }
    // Never block AppKit while a peer is stuck or its backlog is full.
    _ = fcntl(fd, F_SETFL, O_NONBLOCK)
    return withUnsafePointer(to: &addr) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) == 0 ? nil : errno
        }
    }
}

// Pinned official Cua cli.rs exposes the embedded host contract; serve.rs
// waits for embedded stdin EOF and shuts down its runtime. The sole writer
// stays in Styx: process death closes it without a PID watchdog or guessed API.
func makeEmbeddedDaemon(driver: URL, socketPath: String, pidFile: String) -> (Process, Pipe) {
    let child = Process(), lifetime = Pipe()
    child.executableURL = driver
    child.arguments = ["serve", "--embedded", "--parent-liveness-stdio",
        "--grant", "existing-profile", "--socket", socketPath, "--pid-file", pidFile]
    child.environment = ["PATH": "/usr/bin:/bin", "HOME": NSHomeDirectory(),
        "TMPDIR": NSTemporaryDirectory(), "CUA_DRIVER_EMBEDDED": "1",
        "CUA_DRIVER_HOST_BUNDLE_ID": bundleID, "CUA_DRIVER_PERMISSION_MODE": "standard",
        "DO_NOT_TRACK": "1", "CUA_DRIVER_RS_TELEMETRY_ENABLED": "false"]
    child.standardInput = lifetime
    child.standardOutput = FileHandle.nullDevice
    child.standardError = FileHandle.nullDevice
    return (child, lifetime)
}

enum PluginExportError: Error { case refused }
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
func styxApplicationMenu(actionTarget: StyxDelegate? = nil) -> NSMenu {
    let chinese = (Locale.preferredLanguages.first ?? "en").hasPrefix("zh")
    func text(_ zh: String, _ en: String) -> String { chinese ? zh : en }
    let main = NSMenu()
    let appItem = NSMenuItem(title: "Styx", action: nil, keyEquivalent: ""); main.addItem(appItem)
    let appMenu = NSMenu(title: "Styx"); appItem.submenu = appMenu
    appMenu.addItem(withTitle: text("打开 Styx…", "Open Styx…"), action: #selector(StyxDelegate.openSettings), keyEquivalent: "o").target = actionTarget
    appMenu.addItem(withTitle: text("设置…", "Settings…"), action: #selector(StyxDelegate.openProductPreferences), keyEquivalent: ",").target = actionTarget
    // Updates live in General, shared with the main window and status menu.
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

func productComputerUseRequested(_ status: ProductJSON, guiAvailable: Bool, retainingSource: Bool = false) -> Bool {
    let intent = status["desktop_intent"]
    return guiAvailable && status["schema"] == .number(1) && status["mode"].string == "rust_host" &&
        status["admission_fenced"] == .bool(false) &&
        ["started", "connected"].contains(status["foreground"]["status"].string ?? "") &&
        intent["schema"] == .number(1) && intent["source"] == .string("approved_host_configuration") &&
        (intent["computer_requested"] == .bool(true) ||
         (retainingSource && intent["computer_requested"] == .bool(false)))
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
    var setupWindow: ProductWindowController?
    var nativeCore: ProductOwnedCore?
    var nativeCoreStarting = false
    var nativeCoreAttempted = false
    var componentTimer: Timer?
    var nativeComponentObservation: UUID?
    var nativeDesktopIntentObservedAt: TimeInterval?
    var computerPermissionRecoveryRequired = false
    var nativeComputerRecoveryInProgress = false
    var computerUseRequested = false
    var terminationPending = false
    var setupOpenRequested = false
    var runtime: RuntimeDirectory?
    var daemon: Process?
    var daemonStopTask: Task<Void, Never>?
    var lifetimeWriter: FileHandle?
    var timer: Timer?
    var statusItem: NSStatusItem?
    var menuOpenRequested = false
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
        NSApp.mainMenu = styxApplicationMenu(actionTarget: self)
        for number in [SIGTERM, SIGINT] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler {
                productScheduleApplicationTermination()
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
        item.button?.target = self
        item.button?.action = #selector(toggleProductPanel)
        statusItem = item
        if let resources = Bundle.main.resourceURL,
           FileManager.default.isExecutableFile(atPath: bundledCoreExecutable(resources).path),
           Bundle.main.bundleURL.standardizedFileURL.path != "/Applications/Styx.app" {
            let alert = NSAlert(); alert.messageText = "Move Styx to Applications first"
            alert.informativeText = "Drag the complete Styx.app to /Applications, then open it there. Do not replace an existing Styx installation without reviewing it first. Settings and permissions need a stable app location."
            alert.runModal(); NSApp.terminate(nil); return
        }
        // Product startup is exclusively Rust. Missing native metadata is a
        // refusal, never an implicit selection of the historical Node helper.
        do { try startSetup(openWindow: !launchedAtLogin) }
        catch { openSettings() }
    }
    private func bundledCoreExecutable(_ resources: URL) -> URL {
        resources.deletingLastPathComponent().appendingPathComponent("Helpers/Styx Core.app/Contents/MacOS/Styx Core")
    }
    func startSetup(openWindow: Bool) throws {
        setupOpenRequested = setupOpenRequested || openWindow
        guard let resources = Bundle.main.resourceURL else { throw HostError.daemonUnavailable }
        ProductNativeDiagnostics.lifecycle(.bootstrapEntered)
        nativeCoreAttempted = true
        if let _ = nativeCore { if setupOpenRequested { setupWindow?.present(); setupOpenRequested = false }; return }
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

                if setupOpenRequested { setupWindow?.present(); setupOpenRequested = false }
                else if menuOpenRequested { toggleProductPanel() }
            } catch {
                ProductNativeDiagnostics.lifecycle(.bootstrapFailed)

                // A status item without its panel must not hide startup failure.
                // AppKit owns this feedback; no Core connection is required.
                let alert = NSAlert()
                alert.messageText = productText("无法启动 Styx", "Styx could not start")
                alert.informativeText = productText(
                    "无法加载现有设置。你的配置和配对已保留，请勿删除或重新配对。",
                    "Your existing settings could not be loaded. Configuration and pairing have been preserved; do not delete them or pair again.")
                alert.addButton(withTitle: productText("好", "OK"))
                NSApp.activate(ignoringOtherApps: true)
                alert.runModal()
            }
        }
        return
    }
    @objc func openSettings() {
        do { try startSetup(openWindow: true) }
        catch {
            let alert = NSAlert(); alert.messageText = "Styx local setup is unavailable"
            alert.informativeText = "Keep the complete Styx.app bundle together and reopen Settings."
            alert.runModal()
        }
    }
    @objc func toggleProductPanel() {
        if nativeCore != nil, let controller = setupWindow, let button = statusItem?.button {
            menuOpenRequested = false
            controller.toggleMenu(relativeTo: button, quit: { [weak self] in self?.quit() })
            return
        }
        menuOpenRequested = true
        do {
            try startSetup(openWindow: false)
        } catch { openSettings() }
    }
    @objc func openProductPreferences() {
        openSettings()
        setupWindow?.showPreferences()
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        openSettings(); return true
    }
    func withdrawNativeComputerUse() {
        nativeDesktopIntentObservedAt = nil
        computerUseRequested = false
        if let runtime = runtime { unlink(runtime.descriptor) }
        // A live Core may still be draining this exact daemon, including after
        // its request pipe has closed. Only stop after its actual process exit.
        if nativeCore?.hasLiveProcess != true { stop() }

    }
    func checkNativeComponentAvailability(_ core: ProductOwnedCore) {
        guard nativeCore === core, !nativeComputerRecoveryInProgress else { return }
        if !core.isRunning {
            withdrawNativeComputerUse()
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
        guard nativeCore === core, nativeComponentObservation == nil, !terminationPending, !nativeComputerRecoveryInProgress else { return }
        checkNativeComponentAvailability(core)
        // Computer bootstrap needs the original Core's configured intent while
        // first-run UI work is still busy. Its serial request queue orders this
        // read after the mutation; delaying it through the UI's extra reloads
        // can exhaust Rust's bounded discovery-publication window.
        guard core.isRunning else { return }
        let observation = UUID(), requestedAt = ProcessInfo.processInfo.systemUptime
        nativeComponentObservation = observation
        defer { if nativeComponentObservation == observation { nativeComponentObservation = nil } }
        do {
            let status = try await core.call("status")
            guard nativeCore === core, nativeComponentObservation == observation, !terminationPending, !nativeComputerRecoveryInProgress else { return }
            guard core.isRunning else { withdrawNativeComputerUse(); return }
            guard productDesktopIntentFresh(requestedAt, now: ProcessInfo.processInfo.systemUptime) else {
                nativeDesktopIntentObservedAt = nil
                if let runtime = runtime { unlink(runtime.descriptor) }
                return
            }
            guard status["mode"].string == "rust_host" else { withdrawNativeComputerUse(); return }
            nativeDesktopIntentObservedAt = requestedAt
            let session = CGSessionCopyCurrentDictionary() as? [String: Any]
            // Rust stops disabled capability tasks and retains its original Cua
            // source. Keep that source discoverable for the same live Host;
            // withdrawing it here permanently fences a later re-enable. This
            // never starts a disabled component or grants a native operation.
            let requested = productComputerUseRequested(status,
                guiAvailable: session?[kCGSessionOnConsoleKey as String] as? Bool == true,
                retainingSource: daemon?.isRunning == true)
            let changed = requested != computerUseRequested
            computerUseRequested = requested
            if requested {
                // Daemon exits and permission changes still require an explicit
                // recovery action; a periodic read is not a restart policy.
                if changed && !computerPermissionRecoveryRequired {
                    if runtime == nil { runtime = try RuntimeDirectory() }
                    try start()
                }
            } else {
                // A fenced or disconnected Host can still own native FDs.
                // Withdraw discovery while its original Core settles them.
                withdrawNativeComputerUse()
            }
        } catch {
            guard nativeCore === core, nativeComponentObservation == observation, !nativeComputerRecoveryInProgress else { return }
            withdrawNativeComputerUse()
        }
    }
    func recoverComputerUseAfterPermissions(_ core: ProductOwnedCore) async throws {
        guard nativeCore === core, core.isRunning, !terminationPending, !nativeComputerRecoveryInProgress else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
        nativeComputerRecoveryInProgress = true
        defer { nativeComputerRecoveryInProgress = false }
        let requestedAt = ProcessInfo.processInfo.systemUptime
        let status: ProductJSON
        do { status = try await core.call("status") }
        catch {
            if nativeCore === core { withdrawNativeComputerUse() }
            throw error
        }
        let session = CGSessionCopyCurrentDictionary() as? [String: Any]
        guard nativeCore === core, !terminationPending else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
        guard core.isRunning, status["mode"].string == "rust_host",
              productComputerUseRequested(status, guiAvailable: session?[kCGSessionOnConsoleKey as String] as? Bool == true) else {
            withdrawNativeComputerUse()
            throw ProductWorkflowError.computerPermissionRecoveryRequired
        }
        guard productDesktopIntentFresh(requestedAt, now: ProcessInfo.processInfo.systemUptime),
              AXIsProcessTrusted(), CGPreflightScreenCaptureAccess() else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
        nativeDesktopIntentObservedAt = requestedAt
        computerUseRequested = true
        poll()
        if computerPermissionRecoveryRequired {
            // The Host must drain its original native transports before the
            // App replaces the daemon. No interrupted action is replayed.
            _ = try await core.call("disconnect")
            guard nativeCore === core, core.isRunning, !terminationPending else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
            await stopAndJoin()
            guard nativeCore === core, core.isRunning, !terminationPending else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
            guard phase != "cleanup_unknown" else { throw ProductOwnedCoreError.cleanupUnknown }
            nativeDesktopIntentObservedAt = ProcessInfo.processInfo.systemUptime
            computerPermissionRecoveryRequired = false
            do { try start() }
            catch { computerPermissionRecoveryRequired = true; throw error }
            _ = try await core.call("connect")
        }
        guard daemon?.isRunning == true, daemonStopTask == nil else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
        // Permission recovery remains distinct from native effect acceptance.
    }
    func stopSetup() {
        nativeCore?.requestEOF(); nativeCore = nil
        nativeComponentObservation = nil; nativeDesktopIntentObservedAt = nil
        componentTimer?.invalidate(); componentTimer = nil; computerUseRequested = false
        stop()
        setupWindow?.close(); setupWindow = nil
    }
    func start() throws {
        let session = CGSessionCopyCurrentDictionary() as? [String: Any]
        guard computerUseRequested, !computerPermissionRecoveryRequired,
              session?[kCGSessionOnConsoleKey as String] as? Bool == true else { throw HostError.daemonUnavailable }
        if nativeCoreAttempted {
            guard nativeCore?.isRunning == true,
                  productDesktopIntentFresh(nativeDesktopIntentObservedAt, now: ProcessInfo.processInfo.systemUptime) else { throw HostError.daemonUnavailable }
        }
        guard daemonStopTask == nil else { throw HostError.daemonUnavailable }
        guard let runtime = runtime, daemon == nil else { return }
        try runtime.prepareForLaunch()
        generation = UUID().uuidString; lastGrants = nil
        guard let driver = Bundle.main.url(forAuxiliaryExecutable: "cua-driver") else {
            throw HostError.daemonUnavailable
        }
        let (child, lifetime) = makeEmbeddedDaemon(driver: driver,
            socketPath: runtime.socket, pidFile: runtime.path + "/cua.pid")
        child.terminationHandler = { [weak self] terminated in
            guard let owner = self else { return }
            DispatchQueue.main.async {
                owner.ownedDaemonDidExit(terminated)
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
    func ownedDaemonDidExit(_ terminated: Process) {
        guard daemon === terminated else { return }
        try? lifetimeWriter?.close(); lifetimeWriter = nil
        daemon = nil; timer?.invalidate(); runtime?.clear()
        if nativeCoreAttempted { computerPermissionRecoveryRequired = true }
        phase = "daemon_exited"

        // Explicit Continue must drain the original Core before replacing this
        // generation. Never replay an action or silently restart the daemon.
    }
    func poll() {
        guard let runtime = runtime, let daemon = daemon, daemon.isRunning, daemonStopTask == nil else { return }
        if nativeCoreAttempted {
            guard let core = nativeCore, core.isRunning else { withdrawNativeComputerUse(); return }
            guard computerUseRequested,
                  productDesktopIntentFresh(nativeDesktopIntentObservedAt, now: ProcessInfo.processInfo.systemUptime) else { unlink(runtime.descriptor); return }
        }
        let session = CGSessionCopyCurrentDictionary() as? [String: Any]
        guard session?[kCGSessionOnConsoleKey as String] as? Bool == true else {
            if nativeCoreAttempted {
                computerPermissionRecoveryRequired = true
                withdrawNativeComputerUse()
            } else { computerUseRequested = false; stop() }
            return
        }
        if nativeCoreAttempted && computerPermissionRecoveryRequired { unlink(runtime.descriptor); return }
        let ax = AXIsProcessTrusted(), screen = CGPreflightScreenCaptureAccess()
        let grants = "\(ax):\(screen)"
        if let previous = lastGrants, previous != grants {
            computerPermissionRecoveryRequired = true
            if nativeCoreAttempted {
                // Withdraw admission, but leave the original daemon available
                // for Rust's transport drain during recovery or normal Quit.
                unlink(runtime.descriptor); phase = "permissions_changed"

                return
            }
            stop(); phase = "permissions_changed"; return

        }
        lastGrants = grants
        if socketAccepts(runtime.socket) {
            phase = "socket_accepting"
            let consoleSession = CGSessionCopyCurrentDictionary() as? [String: Any]
            let descriptor: [String: Any] = ["schema": 1, "generation": generation,
                "owner_pid": getpid(), "daemon_pid": daemon.processIdentifier,
                "bundle_id": bundleID, "socket": runtime.socket,
                "host_on_console": consoleSession?[kCGSessionOnConsoleKey as String] as? Bool == true,
                "host_session_locked": consoleSession?["CGSSessionScreenIsLocked"] as? Bool ?? false,
                "transport": "socket_accepting", "host_accessibility": ax,
                "host_screen_recording": screen, "native_gui_acceptance": "NOT RUN",
                "mcp_attribution": "NOT RUN"]
            do {
                let data = try JSONSerialization.data(withJSONObject: descriptor, options: [.sortedKeys])
                try runtime.publishDescriptor(data)
            } catch { runtime.clear(); stop(); return }

        } else if phase == "socket_accepting" || Date() > deadline {
            stop()
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
                if forced { phase = "cleanup_unknown" }
                else if phase == "stopping" { phase = "stopped" }
            }
            daemonStopTask = nil
        }
    }
    func stopAndJoin() async {
        stop()
        await daemonStopTask?.value
    }
    @objc func quit() {
        productScheduleApplicationTermination()
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        ProductNativeDiagnostics.lifecycle(.terminateEntered)
        if terminationPending {
            ProductNativeDiagnostics.lifecycle(.terminatePending)
            return .terminateLater
        }
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
                    Task {
                        await owner.stopAndJoin()
                        // prepareToQuit already joined the original Core.
                        owner.nativeCore = nil
                        owner.nativeComponentObservation = nil; owner.nativeDesktopIntentObservedAt = nil
                        owner.componentTimer?.invalidate(); owner.componentTimer = nil
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
if CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--native-model-self-test" {
    MainActor.assumeIsolated {
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        Task { @MainActor in
            do { try await productObservationSelfTest(); exit(0) }
            catch { fputs("Styx native model self-test failed: \(error)\n", stderr); exit(1) }
        }
        application.run()
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
    try productCoreSelfTest()
    let nativeApproved: ProductJSON = .object(["schema": .number(1), "mode": .string("rust_host"),
        "admission_fenced": .bool(false), "foreground": .object(["status": .string("connected")]), "desktop_intent": .object([
        "schema": .number(1), "source": .string("approved_host_configuration"), "computer_requested": .bool(true)])])
    precondition(productComputerUseRequested(nativeApproved, guiAvailable: true))
    precondition(!productComputerUseRequested(nativeApproved, guiAvailable: false))
    var nativeDisabled = nativeApproved.object
    nativeDisabled["desktop_intent"] = .object(["schema": .number(1),
        "source": .string("approved_host_configuration"), "computer_requested": .bool(false)])
    precondition(!productComputerUseRequested(.object(nativeDisabled), guiAvailable: true))
    precondition(productComputerUseRequested(.object(nativeDisabled), guiAvailable: true, retainingSource: true))
    precondition(!productComputerUseRequested(.object(nativeDisabled), guiAvailable: false, retainingSource: true))
    let invalidNativeIntents: [ProductJSON] = [.null, .object([:]), .object(["schema": .number(1), "source": .string("requestJoin"), "computer_requested": .bool(true)]),
                                      .object(["schema": .number(1), "source": .string("approved_host_configuration"), "computer_requested": .bool(false)]),
                                      .object(["schema": .number(2), "source": .string("approved_host_configuration"), "computer_requested": .bool(true)]),
                                      .object(["schema": .number(1), "source": .string("approved_host_configuration"), "computer_requested": .string("true")])]
    for invalidIntent in invalidNativeIntents {
        var invalid = nativeApproved.object
        invalid["desktop_intent"] = invalidIntent
        precondition(!productComputerUseRequested(.object(invalid), guiAvailable: true))
    }
    let inconsistentNativeFields: [(String, ProductJSON)] = [
        ("schema", .number(2)), ("schema", .null), ("admission_fenced", .bool(true)),
        ("admission_fenced", .null), ("admission_fenced", .string("false")),
        ("foreground", .object(["status": .string("not_running")])), ("foreground", .null)]
    for (key, value) in inconsistentNativeFields {
        var invalid = nativeApproved.object; invalid[key] = value
        precondition(!productComputerUseRequested(.object(invalid), guiAvailable: true))
        precondition(!productComputerUseRequested(.object(invalid), guiAvailable: true, retainingSource: true))
    }
    precondition(productDesktopIntentFresh(10, now: 160))
    precondition(!productDesktopIntentFresh(10, now: 160.001))
    precondition(!productDesktopIntentFresh(nil, now: 10))
    precondition(!productDesktopIntentFresh(11, now: 10))
    precondition(!productDesktopIntentFresh(0, now: .infinity))
    precondition(!productSystemQuitReason(nil))
    precondition(productSystemQuitReason(OSType(kAEReallyLogOut)))
    precondition(productSystemQuitReason(OSType(kAERestart)))
    let dir = NSTemporaryDirectory() + "styx-owner-test-" + UUID().uuidString
    do {
        var owner: RuntimeDirectory? = try RuntimeDirectory(path: dir)
        guard owner != nil else { fatalError("missing owner") }
        let publication = Data("{\"generation\":\"original\"}".utf8)
        try owner!.publishDescriptor(publication)
        var originalPublication = stat(), repeatedPublication = stat()
        guard lstat(owner!.descriptor, &originalPublication) == 0 else { fatalError("missing publication") }
        for _ in 0..<8 { try owner!.publishDescriptor(publication) }
        guard lstat(owner!.descriptor, &repeatedPublication) == 0,
              originalPublication.st_ino == repeatedPublication.st_ino,
              originalPublication.st_mtimespec.tv_sec == repeatedPublication.st_mtimespec.tv_sec,
              originalPublication.st_mtimespec.tv_nsec == repeatedPublication.st_mtimespec.tv_nsec else {
            fatalError("unchanged publication replaced its file identity")
        }
        let changedPublication = Data("{\"generation\":\"changed\"}".utf8)
        try owner!.publishDescriptor(changedPublication)
        guard try Data(contentsOf: URL(fileURLWithPath: owner!.descriptor)) == changedPublication else {
            fatalError("changed publication retained old contents")
        }
        unlink(owner!.descriptor)
        try owner!.publishDescriptor(changedPublication)
        guard lstat(owner!.descriptor, &repeatedPublication) == 0,
              repeatedPublication.st_mode & 0o777 == 0o600,
              try Data(contentsOf: URL(fileURLWithPath: owner!.descriptor)) == changedPublication else {
            fatalError("withdrawn publication did not return privately")
        }
        unlink(owner!.descriptor)
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
        print("Styx native ownership and PNG picker validation self-test passed; GUI file dialogs and TCC NOT RUN")
        exit(0)
    } catch { fputs("Styx self-test failed: \(error)\n", stderr); exit(1) }
}
#endif
MainActor.assumeIsolated {
    let app = NSApplication.shared
    let delegate = StyxDelegate()
    app.delegate = delegate
    app.setActivationPolicy(.accessory)
    withExtendedLifetime(delegate) { app.run() }
}
