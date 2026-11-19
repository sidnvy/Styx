// Test-only, self-expiring AppKit window. Never included in Styx.app.
import AppKit

final class OwnedFixture: NSObject, NSApplicationDelegate {
    var window: NSWindow?
    let title: String
    let readback: URL
    let text = NSTextField(string: "initial")
    var textChanges = 0
    var clicks = 0
    var lastText = "initial"
    var sampler: Timer?
    init(title: String, readback: URL) { self.title = title; self.readback = readback }
    func applicationDidFinishLaunching(_ note: Notification) {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 460, height: 210),
            styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = title; window.center(); window.isReleasedWhenClosed = false
        let label = NSTextField(labelWithString: "Only this owned test window is an automation target.")
        label.frame = NSRect(x: 20, y: 160, width: 420, height: 25)
        text.frame = NSRect(x: 20, y: 105, width: 420, height: 28)
        text.setAccessibilityLabel("Styx Test Text")
        let button = NSButton(title: "Styx Verify Click", target: self, action: #selector(clicked))
        button.frame = NSRect(x: 100, y: 40, width: 220, height: 35)
        window.contentView?.addSubview(label); window.contentView?.addSubview(text)
        window.contentView?.addSubview(button)
        self.window = window; window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        record()
        sampler = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
            guard let self, self.text.stringValue != self.lastText else { return }
            self.textChanges += 1; self.lastText = self.text.stringValue; self.record()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 300) { NSApp.terminate(nil) }
    }
    func record() {
        let result: [String: Any] = ["schema": 1, "scope": "fixture_observations",
            "button": "Styx Verify Click", "pid": ProcessInfo.processInfo.processIdentifier,
            "title": title, "value": text.stringValue, "observedTextChanges": textChanges, "clicks": clicks]
        do {
            let data = try JSONSerialization.data(withJSONObject: result)
            try data.write(to: readback, options: [.atomic])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: readback.path)
        } catch { exit(3) }
    }
    @objc func clicked() {
        if text.stringValue != lastText { textChanges += 1; lastText = text.stringValue }
        clicks += 1; record(); sampler?.invalidate()
        // Keep the AX responder alive until AXPress has returned to Cua.
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { NSApp.terminate(nil) }
    }
}
guard CommandLine.arguments.count == 3,
      CommandLine.arguments[1].hasPrefix("STYX_OWNED_GUI_"),
      CommandLine.arguments[2].hasPrefix("/"),
      !FileManager.default.fileExists(atPath: CommandLine.arguments[2]) else { exit(2) }
let readback = URL(fileURLWithPath: CommandLine.arguments[2])
let parent = try FileManager.default.attributesOfItem(atPath: readback.deletingLastPathComponent().path)
guard parent[.ownerAccountID] as? UInt32 == getuid(),
      (parent[.posixPermissions] as? UInt16).map({ $0 & 0o077 == 0 }) == true else { exit(2) }
let app = NSApplication.shared
let delegate = OwnedFixture(title: CommandLine.arguments[1], readback: readback)
app.delegate = delegate; app.setActivationPolicy(.regular); app.run()
