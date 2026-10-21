#if STYX_TESTING
import AppKit
import SwiftUI

@MainActor private final class ProductPasteActionProbe: NSObject {
    var calls = 0
    @objc func paste(_ sender: Any?) { calls += 1 }
}
@MainActor private final class ProductEditTestState {
    var outcome: Result<Void, Error>?
    var checkTimer: Timer?
}

// Tests the actual hosted Tunnel/SecureField controls. It neither reads nor
// writes the general pasteboard: real field editors consume a unique private
// pasteboard, while a probe separately checks the standard Command-V route.
@MainActor func productEditMenuSelfTest(withMenu: Bool) throws {
    func require(_ value: Bool) throws { if !value { throw ProductCoreError.invalidResponse } }
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    let prior = app.mainMenu
    let menu = withMenu ? styxApplicationMenu() : NSMenu()
    for submenu in menu.items.compactMap(\.submenu) {
        submenu.autoenablesItems = false
        for item in submenu.items { item.isEnabled = item.action == #selector(NSText.paste(_:)) }
    }
    app.mainMenu = menu
    let model = try ProductModel(sessionURL: URL(string: "http://127.0.0.1:1/#session=" + String(repeating: "a", count: 43))!)
    model.loaded = true; model.page = .chat
    model.status = .object(["deployment": .object(["mode": .string("create-local"), "steps": .array([])])])
    model.journey = .object(["steps": .array([.object(["id": .string("local_setup"), "status": .string("completed")])]), "tunnel": .object(["status": .string("not_configured")])])
    model.session = .object(["tunnelSupported": .bool(true)])
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 820, height: 720), styleMask: [.titled, .closable], backing: .buffered, defer: false)
    window.isReleasedWhenClosed = false
    let host = NSHostingView(rootView: ProductTunnelEditor(model: model))
    window.contentView = host; window.makeKeyAndOrderFront(nil); app.activate(ignoringOtherApps: true)
    let board = NSPasteboard.withUniqueName()
    defer { model.runtimeKey = ""; model.tunnelID = ""; window.close(); app.mainMenu = prior; board.releaseGlobally() }
    @MainActor func checkEditing() throws {
        func fields(_ view: NSView) -> [NSTextField] {
            (view as? NSTextField).map { $0.isEditable ? [$0] : [] } ?? view.subviews.flatMap(fields)
        }
        let controls = fields(host)
        print("EDIT_TEST: editable controls \(controls.count); secure controls \(controls.filter { $0 is NSSecureTextField }.count)")
        guard let normal = controls.first(where: { !($0 is NSSecureTextField) }),
              let secure = controls.first(where: { $0 is NSSecureTextField }),
              let edit = menu.items.compactMap(\.submenu).first(where: { $0.items.contains(where: { $0.action == #selector(NSText.paste(_:)) }) }),
              let paste = edit.items.first(where: { $0.action == #selector(NSText.paste(_:)) }) else { throw ProductCoreError.invalidResponse }
        try require(paste.target == nil && paste.keyEquivalent == "v" && paste.keyEquivalentModifierMask == .command)
        print("EDIT_TEST: standard paste item configured")
        // AppKit validates paste against the user's general pasteboard in normal
        // operation. Disable validation only in this fixture, avoiding even that
        // clipboard inspection; production retains the standard auto-enabling.
        edit.autoenablesItems = false
        paste.isEnabled = true
        for (field, sample) in [(normal, "styx-private-tunnel-test"), (secure, "styx-private-key-test")] {
            try require(window.makeFirstResponder(field))
            guard let editor = field.currentEditor() as? NSTextView else { throw ProductCoreError.invalidResponse }
            print("EDIT_TEST: focused \(field === normal ? "normal" : "secure") field")
            let recipient = app.target(forAction: #selector(NSText.paste(_:)), to: nil, from: paste) as AnyObject?
            print("EDIT_TEST: recipient \(recipient.map { String(describing: type(of: $0)) } ?? "none"); editor \(type(of: editor)); key \(window.isKeyWindow); active \(app.isActive)")
            try require(recipient === editor)
            print("EDIT_TEST: responder resolved")
            let probe = ProductPasteActionProbe()
            paste.target = probe
            guard let event = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: .command, timestamp: 0, windowNumber: window.windowNumber, context: nil, characters: "v", charactersIgnoringModifiers: "v", isARepeat: false, keyCode: 9) else { throw ProductCoreError.invalidResponse }
            try require(menu.performKeyEquivalent(with: event) && probe.calls == 1)
            print("EDIT_TEST: Command-V dispatched")
            paste.target = nil
            board.clearContents(); try require(board.setString(sample, forType: .string))
            editor.selectAll(nil); try require(editor.readSelection(from: board, type: .string))
            print("EDIT_TEST: private pasteboard read")
            _ = window.makeFirstResponder(nil)
            RunLoop.current.run(until: Date().addingTimeInterval(0.05))
            try require(field.stringValue == sample)
            try require(model.runtimeKey.isEmpty)
        }
        try require(secure is NSSecureTextField)
        print("PASS: hosted Tunnel and secure Runtime Key fields accept private-pasteboard input; Command-V routes through the standard edit menu. General clipboard, credentials, permissions and network untouched.")
    }
    let runState = ProductEditTestState()
    func stop() {
        app.stop(nil)
        if let event = NSEvent.otherEvent(with: .applicationDefined, location: .zero, modifierFlags: [], timestamp: 0, windowNumber: window.windowNumber, context: nil, subtype: 0, data1: 0, data2: 0) { app.postEvent(event, atStart: false) }
    }
    let activation = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: false) { _ in
        MainActor.assumeIsolated {
            window.makeKeyAndOrderFront(nil); app.activate(ignoringOtherApps: true)
            runState.checkTimer = Timer.scheduledTimer(withTimeInterval: 0.3, repeats: false) { _ in
                MainActor.assumeIsolated {
                    do { try checkEditing(); runState.outcome = .success(()) }
                    catch { runState.outcome = .failure(error) }
                    stop()
                }
            }
        }
    }
    let timeout = Timer.scheduledTimer(withTimeInterval: 8, repeats: false) { _ in
        MainActor.assumeIsolated { runState.outcome = .failure(ProductCoreError.unavailable); stop() }
    }
    app.run()
    activation.invalidate(); runState.checkTimer?.invalidate(); timeout.invalidate()
    guard let outcome = runState.outcome else { throw ProductCoreError.unavailable }
    try outcome.get()
}
#endif
