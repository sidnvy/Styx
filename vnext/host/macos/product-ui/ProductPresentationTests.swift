#if STYX_TESTING
import AppKit
import SwiftUI

// Actual AppKit/SwiftUI rendering with synthetic state. This deliberately has no
// delegate, permission requests, running Core, stored identities or account.
@MainActor func productPresentationSnapshots(directory: URL?) throws {
    let app = NSApplication.shared
    app.setActivationPolicy(directory == nil ? .regular : .accessory)
    // Ask only this fixture process to materialize SwiftUI's accessibility tree.
    // This does not request Accessibility permission or alter any TCC state.
    let enhancedUI = NSSelectorFromString("accessibilitySetValue:forAttribute:")
    if app.responds(to: enhancedUI) { app.perform(enhancedUI, with: NSNumber(value: true), with: "AXEnhancedUserInterface") }
    let model = try ProductModel(sessionURL: URL(string: "http://127.0.0.1:1/#session=" + String(repeating: "a", count: 43))!, permissionReader: { (false, false) }, permissionActions: ProductPermissionActions(request: { _ in }, openSettings: { _ in }))
    model.loaded = true
    model.testSuppressObservations = true
    model.testPreview = true
    model.status = .object(["deployment": .object(["mode": .string("create-local"), "steps": .array([])]),
                            "foreground": .object(["status": .string("connected"), "computerRequested": .bool(true)])])
    model.journey = .object(["steps": .array([.object(["id": .string("local_setup"), "status": .string("completed")])]),
                             "tunnel": .object(["status": .string("running"), "transport": .string("ready")])])
    model.acceptance = .object(["complete": .bool(true)])
    model.devices = [
        ProductDevice(.object(["device_id": .string("online"), "label": .string("MacBook Air"), "online": .bool(true)]))!,
        ProductDevice(.object(["device_id": .string("offline"), "label": .string("Windows PC"), "platform": .string("win32"), "online": .bool(false)]))!
    ]
    model.plugin = .object(["connection": .object(["tunnelId": .string("tunnel_" + String(repeating: "a", count: 32))])])
    model.settingsSection = .computers
    model.loginStartup = "disabled"
    model.createdInvitation = .object(["link": .string("https://preview.invalid/invitation-not-valid")])
    model.pending = [.object(["request_id": .string("preview-request"), "fingerprint": .string("PREVIEW-IDENTITY-NOT-A-REAL-DEVICE"), "label": .string("Preview computer")])]
    let menu = NSMenu()
    let appMenu = NSMenuItem(); menu.addItem(appMenu); appMenu.submenu = NSMenu()
    appMenu.submenu?.addItem(withTitle: "Quit UI Preview", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
    let editMenu = NSMenuItem(); menu.addItem(editMenu); editMenu.submenu = NSMenu(title: "Edit")
    editMenu.submenu?.addItem(withTitle: "Paste", action: #selector(NSText.paste(_:)), keyEquivalent: "v")
    editMenu.submenu?.addItem(withTitle: "Select All", action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")
    app.mainMenu = menu
    let panel = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 332, height: 370), styleMask: [.borderless], backing: .buffered, defer: false)
    panel.isReleasedWhenClosed = false
    let material = NSVisualEffectView()
    material.material = .popover; material.blendingMode = .behindWindow; material.state = .active
    let hostedPanel = NSHostingView(rootView: ProductDailyPanel(model: model, controller: nil, quit: { app.terminate(nil) }))
    hostedPanel.translatesAutoresizingMaskIntoConstraints = false; material.addSubview(hostedPanel)
    NSLayoutConstraint.activate([hostedPanel.leadingAnchor.constraint(equalTo: material.leadingAnchor), hostedPanel.trailingAnchor.constraint(equalTo: material.trailingAnchor), hostedPanel.topAnchor.constraint(equalTo: material.topAnchor), hostedPanel.bottomAnchor.constraint(equalTo: material.bottomAnchor)])
    panel.contentView = material
    let settings = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 700, height: 580), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
    settings.isReleasedWhenClosed = false; settings.title = "Styx UI PREVIEW — synthetic state, no Core"
    settings.contentView = NSHostingView(rootView: ProductSettingsView(model: model, controller: nil))
    panel.setFrameOrigin(NSPoint(x: 50, y: 150)); settings.center(); panel.orderFront(nil); settings.makeKeyAndOrderFront(nil)
    app.activate(ignoringOtherApps: true)
    if directory == nil {
        print("UI PREVIEW: synthetic state only. No Core, identity, credentials or TCC changes. Quit with Cmd-Q.")
        app.run(); panel.close(); settings.close(); return
    }
    guard let directory = directory else { return }
    var failure: Error?
    Task { @MainActor in
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            func require(_ value: Bool, _ message: String) throws {
                if !value { throw NSError(domain: "Styx.PresentationTest", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
            }
            @MainActor func capture(_ window: NSWindow, _ name: String) throws {
                guard let view = window.contentView else { throw ProductCoreError.invalidResponse }
                view.layoutSubtreeIfNeeded()
                guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { throw ProductCoreError.invalidResponse }
                view.cacheDisplay(in: view.bounds, to: bitmap)
                // Sheets contain transparent material. Composite against the
                // system window background so exported PNGs remain readable.
                let image = NSImage(size: view.bounds.size)
                image.lockFocus()
                NSColor.windowBackgroundColor.setFill(); NSRect(origin: .zero, size: image.size).fill()
                let captured = NSImage(size: image.size); captured.addRepresentation(bitmap)
                captured.draw(at: .zero, from: .zero, operation: .sourceOver, fraction: 1)
                image.unlockFocus()
                guard let tiff = image.tiffRepresentation, let rendered = NSBitmapImageRep(data: tiff),
                      let png = rendered.representation(using: .png, properties: [:]) else { throw ProductCoreError.invalidResponse }
                try png.write(to: directory.appendingPathComponent(name + ".png"))
            }
            @MainActor func find(_ object: Any, _ identifier: String, depth: Int = 0) -> AnyObject? {
                guard depth < 30 else { return nil }
                // SwiftUI AccessibilityNode implements selectors without adopting
                // the full NSAccessibilityProtocol. Use Objective-C optional dispatch.
                let element = object as AnyObject
                if element.accessibilityIdentifier?() == identifier { return element }
                let children: [Any] = (element.accessibilityChildren?() ?? nil ?? []) + ((object as? NSView)?.subviews ?? [])
                for child in children {
                    if let found = find(child, identifier, depth: depth + 1) { return found }
                }
                return nil
            }
            @MainActor func press(_ window: NSWindow, _ identifier: String) throws {
                guard let element = find(window, identifier), element.isAccessibilityEnabled?() != false, element.accessibilityPerformPress?() == true else {
                    throw NSError(domain: "Styx.PresentationTest", code: 2, userInfo: [NSLocalizedDescriptionKey: "Control unavailable: " + identifier])
                }
            }
            @MainActor func views<T: NSView>(_ view: NSView, _ type: T.Type) -> [T] {
                ((view as? T).map { [$0] } ?? []) + view.subviews.flatMap { views($0, type) }
            }
            try await Task.sleep(nanoseconds: 300_000_000)
            try capture(panel, "panel")
            // Reproduce the recorded menu jitter: a blocked invitation must not
            // be replaced by a smaller spinner during unrelated busy changes.
            let savedInvitation = model.createdInvitation
            model.invitationExpanded = true
            model.createdInvitation = .null
            model.ingress = .object(["blockers": .array([.string("entry_unreachable")])])
            try await Task.sleep(nanoseconds: 200_000_000)
            material.layoutSubtreeIfNeeded()
            let blockedSize = hostedPanel.fittingSize
            try capture(panel, "menu-invitation-blocked")
            for active in [true, false, true, false] {
                model.busy = active
                try await Task.sleep(nanoseconds: 120_000_000)
                material.layoutSubtreeIfNeeded()
                try require(hostedPanel.fittingSize == blockedSize, "Unrelated busy state replaced invitation content and moved menu rows")
                try require(views(hostedPanel, NSProgressIndicator.self).isEmpty, "Unrelated operation displayed an invitation spinner")
            }
            model.busy = true
            try await Task.sleep(nanoseconds: 120_000_000)
            try capture(panel, "menu-invitation-unrelated-busy")
            model.busy = false
            model.invitationExpanded = false
            model.createdInvitation = savedInvitation
            model.ingress = .null
            try require(views(settings.contentView!, NSTableView.self).isEmpty, "Settings still has sidebar table")
            for section in [ProductSettingsSection.computers, .chat, .general] {
                model.requestSettings(section)
                try await Task.sleep(nanoseconds: 200_000_000)
                try capture(settings, "settings-" + section.rawValue)
            }
            model.requestSettings(.computers)
            try await Task.sleep(nanoseconds: 200_000_000)
            try press(settings, "styx-settings-add-computer")
            try await Task.sleep(nanoseconds: 300_000_000)
            guard let invitationSheet = settings.attachedSheet else { throw ProductCoreError.invalidResponse }
            try capture(invitationSheet, "invitation-sheet")
            try press(invitationSheet, "styx-invitation-done")
            try await Task.sleep(nanoseconds: 300_000_000)
            model.requestSettings(.chat)
            try await Task.sleep(nanoseconds: 200_000_000)
            try press(settings, "styx-settings-edit-tunnel")
            try await Task.sleep(nanoseconds: 300_000_000)
            guard let editor = settings.attachedSheet else { throw ProductCoreError.invalidResponse }
            let fields = views(editor.contentView!, NSTextField.self).filter { $0.isEditable }
            guard let field = fields.first else { throw ProductCoreError.invalidResponse }
            field.stringValue = "tunnel_unsaved_draft"; editor.makeFirstResponder(field)
            let responder = editor.firstResponder
            let scroll = views(settings.contentView!, NSScrollView.self).first
            let offset = scroll?.contentView.bounds.origin
            model.publish(\.journey, .object(["steps": model.journey["steps"], "tunnel": .object(["status": .string("configured"), "transport": .string("unavailable")])]))
            try await Task.sleep(nanoseconds: 200_000_000)
            try require(field.stringValue == "tunnel_unsaved_draft" && editor.firstResponder === responder, "Observation reset editor text or focus")
            try require(scroll?.contentView.bounds.origin == offset, "Observation reset settings scroll position")
            try capture(editor, "tunnel-editor")
            try press(editor, "styx-tunnel-cancel")
            try await Task.sleep(nanoseconds: 300_000_000)
            model.page = .chat; model.busy = true
            let onboarding = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 680, height: 640), styleMask: [.titled, .closable], backing: .buffered, defer: false)
            onboarding.isReleasedWhenClosed = false
            onboarding.contentView = NSHostingView(rootView: ProductView(model: model, controller: nil))
            onboarding.makeKeyAndOrderFront(nil)
            defer { onboarding.close() }
            try await Task.sleep(nanoseconds: 200_000_000)
            try press(onboarding, "styx-onboarding-edit-tunnel")
            try await Task.sleep(nanoseconds: 300_000_000)
            guard let onboardingEditor = onboarding.attachedSheet else { throw ProductCoreError.invalidResponse }
            try capture(onboardingEditor, "onboarding-editor")
            try press(onboardingEditor, "styx-tunnel-cancel")
            model.busy = false
            try await Task.sleep(nanoseconds: 300_000_000)
            try press(onboarding, "styx-reconnect")
            try require(model.error == "UI preview: connection operations are disabled.", "Reconnect button did not dispatch its action")
            try capture(onboarding, "onboarding-chat")
            print("PASS: native settings section navigation, local invitation sheet, connection editor, retained focus/input/scroll, and menu rendered. Synthetic state; no real connection or account acceptance.")
        } catch { print("PRESENTATION FAILURE:", error); failure = error }
        app.stop(nil)
        if let event = NSEvent.otherEvent(with: .applicationDefined, location: .zero, modifierFlags: [], timestamp: 0, windowNumber: 0, context: nil, subtype: 0, data1: 0, data2: 0) { app.postEvent(event, atStart: false) }
    }
    app.run(); panel.close(); settings.close()
    if let failure = failure { throw failure }
}
#endif
