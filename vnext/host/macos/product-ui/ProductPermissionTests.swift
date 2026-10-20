#if STYX_TESTING
import AppKit
import SwiftUI

// Isolated UI/lifecycle checks with injected permission observations. Never
// grants permissions, starts Core/Cua or touches a real deployment.
@MainActor func productPermissionStateSelfTest() async throws {
    func require(_ value: Bool, _ message: String) throws {
        if !value { throw NSError(domain: "Styx.PermissionTest", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    }
    var observation = (accessibility: false, screenRecording: false)
    var checks = 0, recoveries = 0
    let model = try ProductModel(sessionURL: URL(string: "http://127.0.0.1:1/#session=" + String(repeating: "a", count: 43))!, permissionReader: {
        checks += 1; return observation
    })
    model.recoverComputerUse = { recoveries += 1 }
    model.loaded = true; model.page = .permissions; model.busy = true
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 820, height: 720), styleMask: [.titled], backing: .buffered, defer: false)
    window.isReleasedWhenClosed = false
    window.contentView = NSHostingView(rootView: ProductView(model: model, controller: nil))
    window.orderFront(nil)
    defer { window.close() }
    try await Task.sleep(nanoseconds: 150_000_000)
    observation = (true, false)
    let prior = checks
    NotificationCenter.default.post(name: NSApplication.didBecomeActiveNotification, object: NSApplication.shared)
    try await Task.sleep(nanoseconds: 100_000_000)
    try require(checks > prior && model.axGranted && !model.screenGranted, "Returning to App left the hosted permission view stale")
    model.busy = false
    do { try await model.verifyPermissionsAndRecover(); throw ProductCoreError.invalidResponse }
    catch ProductWorkflowError.computerPermissionRecoveryRequired { }
    try require(recoveries == 0, "Partial permission restored Computer Use")
    observation = (true, true)
    try await model.verifyPermissionsAndRecover()
    try require(recoveries == 1, "Explicit Continue did not recover exactly once")
    model.recoverComputerUse = { throw ProductCoreError.unavailable }
    do { try await model.verifyPermissionsAndRecover(); throw ProductCoreError.invalidResponse }
    catch ProductCoreError.unavailable { }
    observation = (false, false)
    await model.refresh() // Intentionally unavailable loopback Core, no deployment.
    try require(!model.axGranted && !model.screenGranted && model.error != nil, "Core failure hid fresh native permission observations")
    model.recoverComputerUse = { recoveries += 1 }
    do { try await model.verifyPermissionsAndRecover(); throw ProductCoreError.invalidResponse }
    catch ProductWorkflowError.computerPermissionRecoveryRequired { }
    try require(recoveries == 1, "Revoked permission permitted recovery")
    observation = (true, true)
    model.recoverComputerUse = nil
    do { try await model.verifyPermissionsAndRecover(); throw ProductCoreError.invalidResponse }
    catch ProductWorkflowError.computerPermissionRecoveryRequired { }
    print("PASS: hosted permission view refreshes on App activation; partial/revoked permissions block recovery; explicit Continue calls recovery once; Core failure does not hide native observations. Injected permission states only; real TCC, Cua and account acceptance NOT RUN.")
}
#endif
