import AppKit
import Sparkle

// Isolated platform experiment; never embeds or launches a Styx Core/Host.
final class ProbeDelegate: NSObject, NSApplicationDelegate, SPUUpdaterDelegate {
    var controller: SPUStandardUpdaterController!
    var window: NSWindow!
    func record(_ event: String) {
        let dir = Bundle.main.object(forInfoDictionaryKey: "StyxProbeOutput") as! String
        let value: [String: Any] = ["event": event, "version": Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion")!, "pid": getpid(), "bundle": Bundle.main.bundlePath, "time": Date().timeIntervalSince1970]
        let data = try! JSONSerialization.data(withJSONObject: value)
        let path = dir + "/events.jsonl"
        if !FileManager.default.fileExists(atPath: path) { FileManager.default.createFile(atPath: path, contents: nil) }
        let file = FileHandle(forWritingAtPath: path)!; file.seekToEndOfFile(); file.write(data); file.write(Data("\n".utf8)); try? file.close()
    }
    func applicationDidFinishLaunching(_ note: Notification) {
        record("launched")
        controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: self, userDriverDelegate: nil)
        window = NSWindow(contentRect: NSRect(x: 0,y: 0,width: 460,height: 180),styleMask: [.titled,.closable],backing: .buffered,defer: false)
        window.title = "Styx isolated Sparkle probe"
        let text = NSTextField(labelWithString: "Isolated update fixture · version \(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion")!)")
        text.frame = NSRect(x: 24,y: 115,width: 410,height: 30);window.contentView?.addSubview(text)
        let button = NSButton(title: "Check for Updates…",target: controller,action: #selector(SPUStandardUpdaterController.checkForUpdates(_:)))
        button.frame = NSRect(x: 24,y: 50,width: 220,height: 36);window.contentView?.addSubview(button)
        window.center();window.makeKeyAndOrderFront(nil);NSApp.activate(ignoringOtherApps: true)
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        record("termination_requested")
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 50_000_000)
            self.record("termination_admitted")
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
    func updater(_ updater: SPUUpdater, didFindValidUpdate item: SUAppcastItem) { record("valid_update_found") }
    func updater(_ updater: SPUUpdater, willInstallUpdate item: SUAppcastItem) { record("will_install") }
    func updaterWillRelaunchApplication(_ updater: SPUUpdater) { record("will_relaunch") }
    func updater(_ updater: SPUUpdater, didAbortWithError error: Error) { record("abort_\((error as NSError).code)") }
}
let app = NSApplication.shared
let delegate = ProbeDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
