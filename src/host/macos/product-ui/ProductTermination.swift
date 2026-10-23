import AppKit

@MainActor
func productScheduleApplicationTermination() {
    // terminateLater runs a nested AppKit loop. Calling it synchronously from
    // a Swift Task holds that task's executor while prepareToQuit needs it.
    // An ordinary run-loop selector releases the Task before requesting quit.
    NSApp.perform(#selector(NSApplication.terminate(_:)), with: nil, afterDelay: 0)
}
