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
    var requests: [Bool] = [], settings: [Bool] = []
    let actions = ProductPermissionActions(request: { requests.append($0) }, openSettings: { settings.append($0) })
    let sessionURL = URL(string: "http://127.0.0.1:1/#session=" + String(repeating: "a", count: 43))!
    let model = try ProductModel(sessionURL: sessionURL, permissionReader: {
        checks += 1; return observation
    }, permissionActions: actions)
    model.tunnelAttempt = .connecting
    var polls = 0
    await model.monitorTunnel(check: {
        polls += 1
        model.journey = .object(["tunnel": .object(["status": .string("running"), "transport": .string(polls == 3 ? "ready" : "unavailable")])])
    }, pause: {}).value
    try require(polls == 3 && model.tunnelConnection == .connected && model.tunnelAttempt == .idle, "Delayed readiness did not finish reconnect feedback")
    try require(!model.accepted, "A ready tunnel became chat account verification")
    model.tunnelAttempt = .connecting; polls = 0
    await model.monitorTunnel(check: {
        polls += 1; model.journey = .object(["tunnel": .object(["status": .string("running"), "transport": .string("unavailable")])])
    }, pause: {}).value
    try require(polls == 20 && model.tunnelAttempt == .timedOut, "Unready connection remained an indefinite spinner or false success")
    model.tunnelAttempt = .idle
    let brand: ProductJSON = .object(["mimeType": .string("image/png"), "dataBase64": .string("test-only-brand")])
    model.preparePluginDraft(defaultIcon: brand)
    try require(model.pluginIcon == brand && model.pluginDraftEdited, "Opening the optional ZIP editor omitted its displayed default icon")
    let custom: ProductJSON = .object(["mimeType": .string("image/png"), "dataBase64": .string("test-only-custom")])
    model.pluginIcon = custom; model.pluginDraftEdited = false
    model.preparePluginDraft(defaultIcon: brand)
    try require(model.pluginIcon == custom && !model.pluginDraftEdited, "Opening the optional ZIP editor replaced a saved custom icon")
    model.plugin = .object(["presentation": .object(["displayName": .string("Saved name"), "shortDescription": .string("Saved description"), "icon": custom])])
    model.pluginName = "Saved name"; model.pluginDescription = "Saved description"
    model.observePluginDraftEdit()
    try require(!model.pluginDraftEdited, "Hydrating saved plugin details made the exported draft look edited")
    model.pluginName = "Edited name"; model.observePluginDraftEdit()
    try require(model.pluginDraftEdited, "An actual plugin edit retained stale export-ready feedback")
    try require(!model.permissionWasRequested(false) && !model.permissionWasRequested(true), "A fresh process claimed a permission request")
    model.requestPermission(true)
    try require(requests == [true] && settings.isEmpty, "Screen permission action both requested and opened System Settings")
    try require(model.permissionWasRequested(true) && !model.permissionWasRequested(false), "Screen request changed the wrong permission history")
    try require(!model.axGranted && !model.screenGranted, "Requesting permission was treated as an OS grant")
    model.requestPermission(true)
    model.openPermission(true)
    try require(requests == [true] && settings == [true], "A declined screen prompt was requested repeatedly instead of using Settings")
    model.openPermission(false)
    try require(requests == [true] && !model.permissionWasRequested(false), "Opening Accessibility settings requested permission")
    model.requestPermission(false)
    model.requestPermission(false)
    try require(requests == [true, false] && settings == [true, false], "Accessibility action requested a different permission, opened Settings or looped")
    let reopenedModel = try ProductModel(sessionURL: sessionURL, permissionReader: { observation }, permissionActions: actions)
    reopenedModel.requestPermission(true); reopenedModel.requestPermission(false)
    try require(reopenedModel.permissionWasRequested(true) && reopenedModel.permissionWasRequested(false) && requests == [true, false], "Recreating a window repeated declined permission requests")
    let grantedActions = ProductPermissionActions(request: { requests.append($0) }, openSettings: { settings.append($0) })
    let grantedModel = try ProductModel(sessionURL: sessionURL, permissionReader: { (true, true) }, permissionActions: grantedActions)
    grantedModel.requestPermission(true); grantedModel.requestPermission(false)
    try require(requests == [true, false] && !grantedModel.permissionWasRequested(true) && !grantedModel.permissionWasRequested(false), "An existing OS grant raised or fabricated a permission request")
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
    try require(!model.axGranted && !model.screenGranted && model.observationError != nil, "Core failure hid fresh native permission observations")
    model.recoverComputerUse = { recoveries += 1 }
    do { try await model.verifyPermissionsAndRecover(); throw ProductCoreError.invalidResponse }
    catch ProductWorkflowError.computerPermissionRecoveryRequired { }
    try require(recoveries == 1, "Revoked permission permitted recovery")
    observation = (true, true)
    model.recoverComputerUse = nil
    do { try await model.verifyPermissionsAndRecover(); throw ProductCoreError.invalidResponse }
    catch ProductWorkflowError.computerPermissionRecoveryRequired { }
    print("PASS: each explicit permission action requests only its matching OS prompt once per process; settings navigation never requests; decline, retry and window recreation do not loop; requests never imply grants. Hosted permission view refreshes on App activation; partial/revoked permissions block recovery; explicit Continue calls recovery once; Core failure does not hide native observations. Injected permission actions and states only; real TCC, Cua and account acceptance NOT RUN.")
}
#endif
