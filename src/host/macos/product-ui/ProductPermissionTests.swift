#if STYX_TESTING
import AppKit
import SwiftUI

// Isolated UI/lifecycle checks with injected permission observations. Never
// grants permissions, starts Core/Cua or touches a real deployment.
@MainActor func productPermissionStateSelfTest() async throws {
    func require(_ value: Bool, _ message: String) throws {
        if !value { throw NSError(domain: "Styx.PermissionTest", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    }
    let owner = StyxDelegate()
    let originalDaemon = Process()
    owner.nativeCoreAttempted = true
    owner.daemon = originalDaemon
    owner.phase = "socket_accepting"
    owner.ownedDaemonDidExit(Process())
    try require(owner.daemon === originalDaemon && !owner.computerPermissionRecoveryRequired && owner.phase == "socket_accepting", "An unrelated child exit changed original daemon custody or recovery admission")
    owner.ownedDaemonDidExit(originalDaemon)
    try require(owner.daemon == nil && owner.computerPermissionRecoveryRequired && owner.phase == "daemon_exited", "Original daemon exit did not require explicit Continue recovery")
    var observation = (accessibility: false, screenRecording: false)
    var checks = 0, recoveries = 0
    var requests: [Bool] = [], settings: [Bool] = []
    let actions = ProductPermissionActions(request: { requests.append($0) }, openSettings: { settings.append($0) })
    let sessionURL = URL(string: "http://127.0.0.1:1/#session=" + String(repeating: "a", count: 43))!
    // New model/defaults instances represent the OS-owned relaunch. This suite
    // stores one UI boolean only; no Core/Cua, real profile or TCC is involved.
    let resumeSuite = "Styx.PermissionResumeTest." + UUID().uuidString
    let resumeDefaults = UserDefaults(suiteName: resumeSuite)!
    defer { resumeDefaults.removePersistentDomain(forName: resumeSuite) }
    let checkpoint = ProductPermissionResume(profileScope: "original-profile", defaults: resumeDefaults)
    var resumeObservation = (accessibility: true, screenRecording: false)
    var resumeRecoveries = 0
    let nativeStatus: ProductJSON = .object([
        "mode": .string("rust_host"), "configuration": .object(["computer": .bool(true)]),
        "desktop_intent": .object(["computer_requested": .bool(true)]), "admission_fenced": .bool(false)
    ])
    func newResumeModel(_ scope: String = "original-profile") throws -> ProductModel {
        try ProductModel(sessionURL: sessionURL, permissionReader: { resumeObservation },
                         permissionActions: ProductPermissionActions(request: { _ in }, openSettings: { _ in }),
                         permissionResume: ProductPermissionResume(profileScope: scope, defaults: UserDefaults(suiteName: resumeSuite)!))
    }
    let beforeOSReopen = try newResumeModel()
    try beforeOSReopen.applyNative(nativeStatus)
    try require(beforeOSReopen.page == .permissions && checkpoint.pending, "Native startup skipped missing OS permissions or failed to retain the unfinished step")
    resumeObservation = (true, true)
    let afterOSReopen = try newResumeModel()
    try afterOSReopen.applyNative(nativeStatus)
    try require(afterOSReopen.page == .permissions && afterOSReopen.axGranted && afterOSReopen.screenGranted && checkpoint.pending,
                "OS Quit and Reopen lost the permission step once the grants became true")
    let otherProfile = try newResumeModel("different-profile")
    try otherProfile.applyNative(nativeStatus)
    try require(otherProfile.page == .overview && checkpoint.pending, "One profile's permission step changed another profile")
    try require(resumeRecoveries == 0, "Restoring a UI step automatically recovered Computer Use")
    afterOSReopen.recoverComputerUse = { throw ProductCoreError.rejected }
    do { try await afterOSReopen.verifyPermissionsAndRecover(); throw ProductCoreError.invalidResponse }
    catch ProductCoreError.rejected { }
    try require(checkpoint.pending, "Core refusal erased the unfinished permission step")
    afterOSReopen.recoverComputerUse = { resumeObservation = (true, false) }
    do { try await afterOSReopen.verifyPermissionsAndRecover(); throw ProductCoreError.invalidResponse }
    catch ProductWorkflowError.computerPermissionRecoveryRequired { }
    try require(checkpoint.pending, "A missing post-recovery OS grant erased the unfinished permission step")
    resumeObservation = (true, true)
    afterOSReopen.recoverComputerUse = { resumeRecoveries += 1 }
    try await afterOSReopen.verifyPermissionsAndRecover()
    try require(resumeRecoveries == 1 && !checkpoint.pending, "Explicit successful recovery did not complete exactly one retained UI step")
    let completedReopen = try newResumeModel()
    try completedReopen.applyNative(nativeStatus)
    try require(completedReopen.page == .overview, "A completed permission step reappeared on later startup")
    resumeObservation = (true, false)
    completedReopen.requestPermission(true)
    try require(checkpoint.pending, "A permission request from an existing setup did not retain its UI step before OS relaunch")
    let freshProfile = try newResumeModel()
    try freshProfile.applyNative(.object(["mode": .string("rust_host"), "admission_fenced": .bool(false)]))
    try require(freshProfile.page == .welcome && !checkpoint.pending, "A retired/unconfigured profile inherited an old permission step")
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
    print("PASS: native permission UI step survives OS relaunch with newly granted permissions, stays profile scoped, preserves Core refusal/missing-grant recovery, and clears only after successful explicit recovery or an unconfigured profile. Each explicit action requests only its matching OS prompt once per process; settings navigation never requests; requests never imply grants. Hosted permission view refreshes on App activation; partial/revoked permissions block recovery; explicit Continue calls recovery once; Core failure does not hide native observations. Injected permission actions and states only; real TCC, Cua and account acceptance NOT RUN.")
}
#endif
