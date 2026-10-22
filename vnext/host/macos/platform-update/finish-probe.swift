import AppKit
let path = CommandLine.arguments[1]
precondition(path.hasPrefix("/private/tmp/styx-sparkle-") && path.hasSuffix("/probe/installed/StyxSparkleProbe.app/Contents/MacOS/Probe"))
let apps = NSRunningApplication.runningApplications(withBundleIdentifier: "app.styx.platform-update-probe.20261022").filter { $0.executableURL?.path == path }
for app in apps { print("probe_normal_quit_requested=\(app.terminate()) pid=\(app.processIdentifier)") }
