#if STYX_TESTING
import AppKit
import SwiftUI

// Actual AppKit/SwiftUI rendering with synthetic state. This deliberately has no
// delegate, permission requests, running Core, stored identities or account.
@MainActor func productPresentationSnapshots(directory: URL) throws {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    let model = try ProductModel(sessionURL: URL(string: "http://127.0.0.1:1/#session=" + String(repeating: "a", count: 43))!, permissionReader: { (false, false) })
    model.loaded = true
    model.testSuppressObservations = true
    model.status = .object(["deployment": .object(["mode": .string("create-local"), "steps": .array([])]),
                            "foreground": .object(["status": .string("connected")])])
    model.journey = .object(["steps": .array([.object(["id": .string("local_setup"), "status": .string("completed")])]),
                             "tunnel": .object(["status": .string("running"), "transport": .string("ready")])])
    model.acceptance = .object(["complete": .bool(true)])
    model.devices = [
        ProductDevice(.object(["device_id": .string("online"), "label": .string("MacBook Air"), "online": .bool(true)]))!,
        ProductDevice(.object(["device_id": .string("offline"), "label": .string("Windows PC"), "platform": .string("win32"), "online": .bool(false)]))!
    ]
    model.plugin = .object(["connection": .object(["tunnelId": .string("tunnel_" + String(repeating: "a", count: 32))])])
    model.settingsSection = .chat
    let panel = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 332, height: 370), styleMask: [.borderless], backing: .buffered, defer: false)
    panel.isReleasedWhenClosed = false
    let material = NSVisualEffectView()
    material.material = .popover; material.blendingMode = .behindWindow; material.state = .active
    let hostedPanel = NSHostingView(rootView: ProductDailyPanel(model: model, controller: nil, quit: {}))
    hostedPanel.translatesAutoresizingMaskIntoConstraints = false; material.addSubview(hostedPanel)
    NSLayoutConstraint.activate([hostedPanel.leadingAnchor.constraint(equalTo: material.leadingAnchor), hostedPanel.trailingAnchor.constraint(equalTo: material.trailingAnchor), hostedPanel.topAnchor.constraint(equalTo: material.topAnchor), hostedPanel.bottomAnchor.constraint(equalTo: material.bottomAnchor)])
    panel.contentView = material
    let settings = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 700, height: 580), styleMask: [.titled, .closable], backing: .buffered, defer: false)
    settings.isReleasedWhenClosed = false; settings.title = "Styx UI fixture"
    settings.contentView = NSHostingView(rootView: ProductSettingsView(model: model, controller: nil))
    panel.center(); settings.center(); panel.orderFront(nil); settings.makeKeyAndOrderFront(nil)
    app.activate(ignoringOtherApps: true)
    var failure: Error?
    let timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: false) { _ in
        MainActor.assumeIsolated {
            do {
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
                func tableRows(_ view: NSView) -> [Int] {
                    let own = (view as? NSTableView).map { [$0.numberOfRows] } ?? []
                    return own + view.subviews.flatMap(tableRows)
                }
                print("RENDER: sidebar table row counts", settings.contentView.map(tableRows) ?? [])
                for (window, name) in [(panel, "panel"), (settings, "settings")] {
                    guard let view = window.contentView else { throw ProductCoreError.invalidResponse }
                    view.layoutSubtreeIfNeeded()
                    guard let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { throw ProductCoreError.invalidResponse }
                    view.cacheDisplay(in: view.bounds, to: bitmap)
                    guard let png = bitmap.representation(using: .png, properties: [:]) else { throw ProductCoreError.invalidResponse }
                    try png.write(to: directory.appendingPathComponent(name + ".png"))
                }
                print("PASS: native menu material and settings controls rendered from synthetic state. Core, clipboard, TCC, services and account untouched.")
            } catch { failure = error }
            app.stop(nil)
            if let event = NSEvent.otherEvent(with: .applicationDefined, location: .zero, modifierFlags: [], timestamp: 0, windowNumber: 0, context: nil, subtype: 0, data1: 0, data2: 0) { app.postEvent(event, atStart: false) }
        }
    }
    app.run(); timer.invalidate(); panel.close(); settings.close()
    if let failure = failure { throw failure }
}
#endif
