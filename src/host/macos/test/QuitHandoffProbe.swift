import AppKit
import Foundation
final class Delegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        Task { @MainActor in
            if CommandLine.arguments.contains("--deferred") {
                productScheduleApplicationTermination()
            } else { NSApp.terminate(nil) }
        }
    }
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 50_000_000)
            FileHandle.standardOutput.write(Data("quit-admitted\n".utf8))
            sender.reply(toApplicationShouldTerminate: true)
        }
        return .terminateLater
    }
}
let delegate = Delegate()
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
app.delegate = delegate
DispatchQueue.global().asyncAfter(deadline: .now() + 5) {
    FileHandle.standardError.write(Data("quit-task-timeout\n".utf8)); exit(73)
}
app.run()
