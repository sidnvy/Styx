// Styx owns the native responsibility chain. No daemon is launched by a Gateway.
import AppKit
import ApplicationServices
import CoreGraphics
import Darwin

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
    func clear() { unlink(descriptor); unlink(socket) }
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

final class StyxDelegate: NSObject, NSApplicationDelegate {
    var runtime: RuntimeDirectory?
    var daemon: Process?
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
        menu.addItem(withTitle: "Request macOS permissions…", action: #selector(requestPermissions), keyEquivalent: "")
        menu.addItem(withTitle: "Restart embedded Cua", action: #selector(restart), keyEquivalent: "r")
        menu.addItem(NSMenuItem.separator())
        menu.addItem(withTitle: "Quit Styx", action: #selector(quit), keyEquivalent: "q")
        for entry in menu.items { entry.target = self }
        item.menu = menu; statusItem = item
        do { runtime = try RuntimeDirectory(); try start() }
        catch { phase = "blocked"; statusLine?.title = "Blocked: \(error)" }
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
        let child = Process()
        child.executableURL = Bundle.main.url(forAuxiliaryExecutable: "cua-driver")
        guard child.executableURL != nil else { throw HostError.daemonUnavailable }
        child.arguments = ["serve", "--embedded", "--socket", runtime.socket]
        // Do not inherit arbitrary permission-mode, loader, or agent-controlled env.
        child.environment = ["PATH": "/usr/bin:/bin", "HOME": NSHomeDirectory(),
            "TMPDIR": NSTemporaryDirectory(), "CUA_DRIVER_EMBEDDED": "1",
            "CUA_DRIVER_HOST_BUNDLE_ID": bundleID, "CUA_DRIVER_PERMISSION_MODE": "standard",
            "DO_NOT_TRACK": "1", "CUA_DRIVER_RS_TELEMETRY_ENABLED": "false"]
        child.standardInput = FileHandle.nullDevice
        child.standardOutput = FileHandle.nullDevice
        child.standardError = FileHandle.nullDevice
        child.terminationHandler = { [weak self] terminated in
            DispatchQueue.main.async {
                guard let owner = self, owner.daemon === terminated else { return }
                owner.daemon = nil; owner.timer?.invalidate(); owner.runtime?.clear()
                owner.phase = "daemon_exited"
                owner.statusLine?.title = "Cua exited; reconnect after restart"
                // Never replay an interrupted GUI action or silently restart a generation.
            }
        }
        try child.run(); daemon = child; phase = "starting"
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
                "host_screen_recording": screen, "native_gui_acceptance": "NOT_RUN",
                "mcp_attribution": "NOT_VERIFIED"]
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
        if let child = daemon {
            child.terminationHandler = nil
            if child.isRunning {
                child.terminate()
                let limit = Date().addingTimeInterval(3)
                while child.isRunning && Date() < limit { Thread.sleep(forTimeInterval: 0.02) }
                if child.isRunning { kill(child.processIdentifier, SIGKILL) }
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
        alert.informativeText = "Enable Accessibility and Screen Recording for Styx. Quit and reopen Styx after changing grants; reconnect clients to the new generation. A grant alone does not verify capture or actions."
        alert.runModal()
    }
    @objc func restart() {
        stop()
        do { try start() } catch { statusLine?.title = "Restart blocked: \(error)" }
    }
    @objc func quit() { NSApp.terminate(nil) }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        stop(); return .terminateNow
    }
}

// Runs without starting NSApplication, a daemon, or permission prompts in CI.
if CommandLine.arguments.contains("--self-test") {
    let dir = NSTemporaryDirectory() + "styx-owner-test-" + UUID().uuidString
    do {
        var owner: RuntimeDirectory? = try RuntimeDirectory(path: dir)
        guard owner != nil else { fatalError("missing owner") }
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
        print("Styx native ownership self-test passed; GUI and TCC NOT RUN")
        exit(0)
    } catch { fputs("Styx self-test failed: \(error)\n", stderr); exit(1) }
}
let app = NSApplication.shared
let delegate = StyxDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
