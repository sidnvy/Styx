// Test-only, self-expiring AppKit window. Never included in Styx.app.
import AppKit

final class OwnedFixture: NSObject, NSApplicationDelegate {
    var window: NSWindow?
    let title: String
    let readback: URL
    init(title: String, readback: URL) { self.title = title; self.readback = readback }
    func applicationDidFinishLaunching(_ note: Notification) {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 420, height: 160),
            styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = title; window.center(); window.isReleasedWhenClosed = false
        let label = NSTextField(labelWithString: "Only this owned test window is an automation target.")
        label.frame = NSRect(x: 20, y: 110, width: 390, height: 25)
        let button = NSButton(title: "Styx Verify Click", target: self, action: #selector(clicked))
        button.frame = NSRect(x: 100, y: 40, width: 220, height: 35)
        window.contentView?.addSubview(label); window.contentView?.addSubview(button)
        self.window = window; window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        DispatchQueue.main.asyncAfter(deadline: .now() + 35) { NSApp.terminate(nil) }
    }
    @objc func clicked() {
        let result: [String: Any] = ["schema": 1, "status": "PASS", "button": "Styx Verify Click",
            "pid": ProcessInfo.processInfo.processIdentifier, "title": title]
        do {
            let data = try JSONSerialization.data(withJSONObject: result)
            try data.write(to: readback, options: [.withoutOverwriting])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: readback.path)
            // Keep the AX responder alive until AXPress has returned to Cua.
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) { NSApp.terminate(nil) }
        } catch { exit(3) }
    }
}
guard CommandLine.arguments.count == 3,
      CommandLine.arguments[1].hasPrefix("STYX_OWNED_GUI_"),
      CommandLine.arguments[2].hasPrefix("/private/tmp/styx-local-dev-") else { exit(2) }
let app = NSApplication.shared
let delegate = OwnedFixture(title: CommandLine.arguments[1], readback: URL(fileURLWithPath: CommandLine.arguments[2]))
app.delegate = delegate; app.setActivationPolicy(.regular); app.run()
