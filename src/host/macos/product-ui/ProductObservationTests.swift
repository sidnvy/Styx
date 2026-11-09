#if STYX_TESTING
import AppKit
import Combine

@MainActor func productObservationSelfTest(sessionURL: URL) async throws {
    func require(_ value: Bool, _ message: String) throws {
        if !value { throw NSError(domain: "Styx.ObservationTest", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    }
    let knownCodes = ["native_management_invalid_input", "native_management_conflict", "native_management_unavailable", "native_management_unsupported", "native_management_unknown_inspect", "native_management_busy", "app_scope_changed", "app_instance_changed", "app_scope_invalid", "app_service_original_operation_unknown", "app_runtime_update_pending", "app_cleanup_unknown", "app_gateway_fenced", "app_quit_admitted", "join_http_invalid_input", "native_gateway_rejection_binding_mismatch", "native_gateway_admin_rejected", "native_gateway_admin_result_unknown"]
    for code in knownCodes {
        try require(ProductNativeDiagnostics.rejectionCode(.object(["error": .string(code)])) == code, "Known rejection code was lost")
    }
    let unsafeErrors: [ProductJSON] = [.string("https://example.invalid/fake-secret"), .string("fake-test-secret"), .string("unknown_code"), .number(7), .null]
    for error in unsafeErrors {
        let response: ProductJSON = .object(["error": error, "result": .string("native_management_busy"), "body": .string("fake-test-secret")])
        try require(ProductNativeDiagnostics.rejectionCode(response) == "other", "Rejection diagnostic disclosed or borrowed response data")
    }
    try require(ProductNativeDiagnostics.rejectionCode(.object(["result": .object(["error": .string("native_management_busy")])])) == "other", "Rejection diagnostic used result")
    let firstFault: ProductJSON = .object(["stage": .string("session_binding"), "cause": .string("console_epoch_changed")])
    let firstFaultStatus: ProductJSON = .object(["foreground": .object(["computerRuntimeFirstFault": firstFault])])
    try require(ProductNativeDiagnostics.computerRuntimeFirstFault(firstFaultStatus) == "computer_runtime_first_fault stage=session_binding cause=console_epoch_changed", "Closed runtime fault was lost without a startup probe")
    let invalidFaults: [ProductJSON] = [
        .null, .string("fake-test-secret"),
        .object(["stage": .string("unknown_stage"), "cause": .string("fenced")]),
        .object(["stage": .string("session_binding"), "cause": .string("unknown_cause")]),
        .object(["stage": .string("fake-test-secret"), "cause": .string("fenced")]),
        .object(["stage": .string("session_binding"), "cause": .string("https://example.invalid/fake-secret")]),
        .object(["stage": .string("session_binding")]),
        .object(["cause": .string("fenced")]),
        .object(["stage": .number(1), "cause": .string("fenced")]),
        .object(["stage": .string("session_binding"), "cause": .bool(true)])
    ]
    for fault in invalidFaults {
        let status: ProductJSON = .object(["foreground": .object(["computerRuntimeFirstFault": fault, "computerStartupProbe": firstFault])])
        try require(ProductNativeDiagnostics.computerRuntimeFirstFault(status) == nil, "Runtime fault disclosed an invalid value or borrowed the startup probe")
    }
    let wrongLayerStatuses: [ProductJSON] = [
        .object(["computerRuntimeFirstFault": firstFault]),
        .object(["result": firstFaultStatus]),
        .object(["foreground": .object(["computerStartupProbe": firstFault])])
    ]
    for status in wrongLayerStatuses {
        try require(ProductNativeDiagnostics.computerRuntimeFirstFault(status) == nil, "Runtime fault borrowed a field from the wrong layer")
    }
    let extraPrivateStatus: ProductJSON = .object(["foreground": .object(["computerRuntimeFirstFault": .object(["stage": .string("session_binding"), "cause": .string("console_epoch_changed"), "body": .string("fake-test-secret")])])])
    try require(ProductNativeDiagnostics.computerRuntimeFirstFault(extraPrivateStatus) == ProductNativeDiagnostics.computerRuntimeFirstFault(firstFaultStatus), "Runtime fault copied unrelated response fields")
    let model = try ProductModel(sessionURL: sessionURL, permissionReader: { (false, false) })
    await model.bootstrap()
    try require(model.loaded && !model.busy, "Isolated Core bootstrap failed")
    model.page = .chat
    model.computer = true; model.browser = true
    model.pluginName = "Unsaved draft"; model.pluginDraftEdited = true
    model.invite = "unsaved invitation input"; model.runtimeKey = "unsaved test input"
    model.createdInvitation = .object(["link": .string("https://preview.invalid/not-valid")])
    model.invitationCopied = true
    model.requestSettings(.chat)
    let navigation = model.settingsNavigationID
    var busyEvents = 0
    let busySubscription = model.$busy.dropFirst().sink { _ in busyEvents += 1 }
    // Server delays its authoritative read. A button action must remain usable
    // throughout that read, including when two surfaces request it at once.
    let read = Task { await model.refresh() }
    try await Task.sleep(nanoseconds: 100_000_000)
    try require(model.observationInFlight && !model.busy, "Background observation disables connection buttons")
    await model.refresh()
    model.startTunnel()
    try require(model.tunnelAttempt == .connecting, "Reconnect click was silently discarded during a read")
    await read.value
    for _ in 0..<100 {
        if !model.busy && model.tunnelAttempt != .connecting { break }
        try await Task.sleep(nanoseconds: 20_000_000)
    }
    try require(model.tunnelAttempt == .failed && model.error != nil, "Rejected reconnect has no persistent feedback")
    let operationError = model.error
    await model.refresh()
    try require(model.error == operationError, "Background refresh erased the reconnect failure")
    try require(model.computer && model.browser && model.pluginName == "Unsaved draft" && model.runtimeKey == "unsaved test input" && model.invite == "unsaved invitation input", "Refresh replaced unsaved inputs")
    try require(model.invitationCopied && model.createdInvitation["link"].string != nil && model.settingsNavigationID == navigation, "Refresh reset invitation feedback or section navigation")
    busySubscription.cancel()
    try require(busyEvents == 2, "Read-only refresh pulsed busy; only reconnect may enter and leave busy")
    var publications = 0
    let subscription = model.objectWillChange.sink { publications += 1 }
    await model.refresh()
    try require(publications == 0, "Identical observations repeatedly publish UI updates")
    subscription.cancel()
    model.requestSettings(.chat)
    try require(model.settingsNavigationID != navigation, "Reopening the same settings section does not navigate")
    model.testSuppressObservations = true
    let menuObserver = Task { await model.observePresentation() }
    let settingsObserver = Task { await model.observePresentation() }
    try await Task.sleep(nanoseconds: 50_000_000)
    try require(model.testObservationConsumerCount == 2 && model.testObservationLoopStarts == 1, "Two visible surfaces started duplicate polling loops")
    menuObserver.cancel(); await menuObserver.value
    try require(model.testObservationConsumerCount == 1 && model.testObservationLoopRunning, "Closing menu stopped visible settings observation")
    settingsObserver.cancel(); await settingsObserver.value
    try require(model.testObservationConsumerCount == 0 && !model.testObservationLoopRunning, "Closing all surfaces left polling active")
    print("PASS: isolated Core HTTP read stays interactive; overlapping reads coalesce; reconnect is sent during a slow read, rejected with persistent feedback; unchanged data does not publish; drafts, invitation feedback and settings navigation survive refresh.")
}
#endif
