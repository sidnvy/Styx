import AppKit
import Foundation

// Native packages must never dispatch the legacy Node ticket protocol. The
// original App/Core handoff is a prerequisite, not a timer or process-absence
// inference. Enablement awaits the actual correlated owned-pipe contract.
if CommandLine.arguments.count == 2 && CommandLine.arguments[1] == "--native-update-status" {
    let result: [String: Any] = ["schema": 1, "status": "blocked", "reason": "native_owned_handoff_unavailable", "operations_replayed": false]
    if let data = try? JSONSerialization.data(withJSONObject: result), var line = String(data: data, encoding: .utf8) { line += "\n"; FileHandle.standardOutput.write(Data(line.utf8)) }
    exit(2)
}
let nativeApplication = NSApplication.shared
nativeApplication.setActivationPolicy(.accessory)
let nativeAlert = NSAlert()
nativeAlert.messageText = "Update needs the original Styx owner"
nativeAlert.informativeText = "This native package cannot confirm the original App and Core handoff. No runtime selection or application files have been changed. Return to Styx to inspect the original update operation."
nativeAlert.addButton(withTitle: "Close")
nativeAlert.runModal()
exit(2)
