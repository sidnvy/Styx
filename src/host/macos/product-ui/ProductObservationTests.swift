#if STYX_TESTING
import AppKit
import Combine

@MainActor func productObservationSelfTest() async throws {
    func require(_ value: Bool, _ message: String) throws {
        if !value { throw NSError(domain: "Styx.ObservationTest", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    }
    let knownCodes = ["native_management_invalid_input", "native_management_conflict", "native_management_unavailable", "native_management_unsupported", "native_management_unknown_inspect", "native_management_busy", "app_scope_changed", "app_instance_changed", "app_scope_invalid", "app_cleanup_unknown", "app_gateway_fenced", "app_quit_admitted", "join_http_invalid_input", "native_gateway_rejection_binding_mismatch", "native_gateway_admin_rejected", "native_gateway_admin_result_unknown"]
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
    // Inject the current Rust request boundary. The production model, state
    // projection and user actions remain the same; no HTTP backend is involved.
    let configured: ProductJSON = .object([
        "schema": .number(1), "mode": .string("rust_host"), "admission_fenced": .bool(false),
        "configuration": .object([:]), "desktop_intent": .object(["computer_requested": .bool(false)]),
        "foreground": .object(["status": .string("connected"), "execConnection": .string("connected")]),
        "supportedOperations": .array([.string("connect"), .string("hostCapabilities")])
    ])
    var calls: [String] = [], delayRead = false
    let model = ProductModel(testRequest: { operation, _ in
        calls.append(operation)
        switch operation {
        case "startupStatus": return configured
        case "status":
            if delayRead { delayRead = false; try await Task.sleep(nanoseconds: 200_000_000) }
            return configured
        case "connect": throw ProductCoreError.rejected
        default: throw ProductCoreError.invalidResponse
        }
    })
    func settled(_ target: ProductModel) async throws {
        for _ in 0..<200 {
            if !target.busy { return }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        throw ProductCoreError.unavailable
    }
    await model.bootstrap()
    try require(model.loaded && !model.busy && model.page == .overview && model.localIndicator == .connected, "Rust startup status did not restore the configured UI")
    model.page = .chat
    model.computer = true; model.browser = true
    model.pluginName = "Unsaved draft"; model.pluginDraftEdited = true
    model.invite = "unsaved invitation input"; model.setupTunnelKey = "unsaved test input"
    model.createdInvitation = .object(["link": .string("https://preview.invalid/not-valid")])
    model.invitationCopied = true
    model.requestSettings(.chat)
    let navigation = model.settingsNavigationID
    var busyEvents = 0
    let busySubscription = model.$busy.dropFirst().sink { _ in busyEvents += 1 }
    delayRead = true
    let read = Task { await model.refresh() }
    try await Task.sleep(nanoseconds: 50_000_000)
    try require(model.observationInFlight && !model.busy, "Background observation disabled the UI")
    await model.refresh()
    try require(calls.filter { $0 == "status" }.count == 1, "Overlapping observations duplicated the request")
    model.resumeForeground()
    try require(model.busy && !calls.contains("connect"), "Mutation did not wait for the existing observation")
    await read.value; try await settled(model)
    try require(calls.filter { $0 == "connect" }.count == 1 && model.error != nil, "A refused action was retried or lost its feedback")
    let operationError = model.error
    await model.refresh()
    try require(model.error == operationError, "Background refresh erased the action failure")
    try require(model.computer && model.browser && model.pluginName == "Unsaved draft" && model.setupTunnelKey == "unsaved test input" && model.invite == "unsaved invitation input", "Observation replaced unsaved inputs")
    try require(model.invitationCopied && model.createdInvitation["link"].string != nil && model.settingsNavigationID == navigation, "Observation reset invitation feedback or navigation")
    busySubscription.cancel()
    try require(busyEvents == 2, "Read-only observation changed mutation busy state")
    var publications = 0
    let subscription = model.objectWillChange.sink { publications += 1 }
    await model.refresh()
    try require(publications == 0, "Identical observations repeatedly published UI updates")
    subscription.cancel()
    model.requestSettings(.chat)
    try require(model.settingsNavigationID != navigation, "Reopening the same settings section did not navigate")
    model.testSuppressObservations = true
    let menuObserver = Task { await model.observePresentation() }
    let settingsObserver = Task { await model.observePresentation() }
    try await Task.sleep(nanoseconds: 20_000_000)
    try require(model.testObservationConsumerCount == 2 && model.testObservationLoopStarts == 1, "Two visible surfaces started duplicate polling loops")
    menuObserver.cancel(); await menuObserver.value
    try require(model.testObservationConsumerCount == 1 && model.testObservationLoopRunning, "Closing menu stopped visible settings observation")
    settingsObserver.cancel(); await settingsObserver.value
    try require(model.testObservationConsumerCount == 0 && !model.testObservationLoopRunning, "Closing all surfaces left polling active")

    var current = configured.object
    current["gateway"] = .object(["lan": .object(["enabled": .bool(true)])])
    current["capabilities"] = .object(["configured": .object(["exec": .bool(true), "browser": .bool(false), "computer": .bool(false)]), "applied": .bool(true)])
    current["browserExtension"] = .object(["installed": .bool(false), "connected": .bool(false), "extensionId": .string("cncjpfhbbnibdjkcheeimdfklfiknibl")])
    current["supportedOperations"] = .array(["computers", "hostCapabilities", "hostBrowserExtension", "inviteComputer"].map(ProductJSON.string))
    var hubCalls: [(String, [String: ProductJSON])] = [], invitationFails = false
    let savedTunnel: ProductJSON = .object(["status": .string("running"), "transport": .string("ready"), "tunnelId": .string("tunnel_fixture1234")])
    let hub = ProductModel(testRequest: { operation, input in
        hubCalls.append((operation, input))
        switch operation {
        case "startupStatus", "status": return .object(current)
        case "computers": return .object(["devices": .array([])])
        case "tunnelStatus": return savedTunnel
        case "tunnelSave": return .object([:])
        case "hostCapabilities":
            guard input == ["computer": .bool(true)] else { throw ProductCoreError.invalidResponse }
            current["capabilities"] = .object(["configured": .object(["exec": .bool(true), "browser": .bool(false), "computer": .bool(true)]), "applied": .bool(true)])
            return .object(["applied": .bool(true)])
        case "hostBrowserExtension":
            guard input == ["action": .string("install")] else { throw ProductCoreError.invalidResponse }
            let next: ProductJSON = .object(["installed": .bool(true), "connected": .bool(true), "extensionId": .string("cncjpfhbbnibdjkcheeimdfklfiknibl"), "extensionPath": .string("/tmp/styx/browser-extension"), "browser": .string("Chrome/158.0.0.0")])
            current["browserExtension"] = next
            return .object(["applied": .bool(true), "browserExtension": next])
        case "inviteComputer":
            if invitationFails { throw ProductOwnedCoreRejection(response: .object(["error": .string("native_management_unknown_inspect")])) }
            return .object(["link": .string("styx://isolated-invitation"), "expiresAt": .number(Date().addingTimeInterval(300).timeIntervalSince1970 * 1000)])
        default: throw ProductCoreError.invalidResponse
        }
    })
    await hub.bootstrap(); await hub.refresh()
    hub.setHostCapability("computer", enabled: true); hub.setHostCapability("computer", enabled: true)
    try await settled(hub)
    try require(hubCalls.filter { $0.0 == "hostCapabilities" }.count == 1 && hub.status["capabilities"]["configured"]["computer"].bool, "Capability change was duplicated or failed to use the Rust observation")
    hub.setBrowserExtension(action: "install"); try await settled(hub)
    try require(hubCalls.filter { $0.0 == "hostBrowserExtension" }.count == 1 && hub.status["browserExtension"]["installed"].bool && hub.status["browserExtension"]["connected"].bool, "Browser extension bridge install failed to sync the Rust observation")
    hub.beginDeviceInvitation(); hub.beginDeviceInvitation(); try await settled(hub)
    hub.beginDeviceInvitation()
    try require(hubCalls.filter { $0.0 == "inviteComputer" }.count == 1 && hub.createdInvitation["link"].string != nil, "A valid invitation was regenerated when its surface reopened")
    var closed = false
    hub.closeDeviceInvitation { closed = true }
    try require(closed && !hub.invitationExpanded && hub.createdInvitation == .null, "Closing the invitation retained its displayed secret")
    invitationFails = true
    hub.beginDeviceInvitation(); try await settled(hub); await hub.refresh()
    try require(hubCalls.filter { $0.0 == "inviteComputer" }.count == 2 && hub.invitationError != nil && hub.createdInvitation == .null, "Unconfirmed invitation was retried or displayed as success")
    try await hub.saveTunnel(id: " tunnel_fixture1234 ", newKey: nil)
    let saves = hubCalls.filter { $0.0 == "tunnelSave" }
    try require(saves.count == 1 && saves[0].1 == ["authorize": .bool(true), "tunnelId": .string("tunnel_fixture1234")], "Saving a Tunnel replayed the operation or replaced the retained key")
    try require(hub.tunnelConnection == .connected && hub.hasSavedRuntimeKey, "Rust Tunnel readiness was not presented")
    await hub.monitorTunnel(check: {}, pause: {}).value

    var joinCalls: [(String, [String: ProductJSON])] = []
    let fresh: ProductJSON = .object(["mode": .string("rust_host"), "admission_fenced": .bool(false), "supportedOperations": .array([.string("createLocal"), .string("inspectJoin"), .string("join")])])
    let preview: ProductJSON = .object(["origin": .string("https://192.0.2.10:22022"), "caSha256": .string(String(repeating: "a", count: 64))])
    let joining = ProductModel(testRequest: { operation, input in
        joinCalls.append((operation, input))
        switch operation {
        case "startupStatus", "status": return fresh
        case "inspectJoin": return .object(["preview": preview])
        case "join": return .object(["status": .string("ready_to_connect")])
        default: throw ProductCoreError.invalidResponse
        }
    })
    await joining.bootstrap()
    joining.invite = "isolated-invitation"; joining.inspectInvitation(); try await settled(joining)
    try require(joining.invite.isEmpty && joining.inspection["preview"] == preview, "Invitation inspection retained the input or lost the Rust trust preview")
    joining.acceptInvitation()
    try require(joining.page == .capabilities && joining.joinAcceptance == preview, "Explicit invitation review did not retain the reviewed origin and certificate")
    joining.createAndPrepare(); joining.createAndPrepare(); try await settled(joining)
    let submissions = joinCalls.filter { $0.0 == "join" }
    try require(submissions.count == 1 && submissions[0].1["approvedGatewayOrigin"] == preview["origin"] && submissions[0].1["approvedCaSha256"] == preview["caSha256"], "Join omitted reviewed identity or duplicated submission")
    try require(joining.joinAcceptance == .null && joining.inspection == .null, "Completed join retained invitation review state")

    for outcome in ["awaiting_approval", "rejected", "ready_to_connect"] {
        var observedJoin = fresh
        var submissions = 0
        let report: ProductJSON = .object(["schema": .number(1), "status": .string(outcome), "request_id": .string("original-computer-request"), "selected_features": .object(["computer": .bool(true), "browser": .bool(false)])])
        let computerJoin = ProductModel(testRequest: { operation, _ in
            if operation == "join" {
                submissions += 1
                var current = configured.object
                current["enrollment"] = report
                current["desktop_intent"] = .object(["computer_requested": .bool(outcome == "ready_to_connect")])
                if outcome != "ready_to_connect" { current["configuration"] = .null; current["foreground"] = .null }
                observedJoin = .object(current)
                return report
            }
            guard ["startupStatus", "status"].contains(operation) else { throw ProductCoreError.invalidResponse }
            return observedJoin
        })
        await computerJoin.bootstrap()
        computerJoin.inspection = .object(["preview": preview]); computerJoin.acceptInvitation()
        computerJoin.computer = true
        computerJoin.createAndPrepare(); computerJoin.createAndPrepare(); try await settled(computerJoin)
        let expectedPage: ProductPage = outcome == "ready_to_connect" ? .permissions : .overview
        try require(submissions == 1 && computerJoin.page == expectedPage && computerJoin.status["enrollment"] == report,
                    "Computer Use selection sent an unfinished or rejected join into permission recovery, or replayed its original request")
    }

    var enrollment = configured.object
    enrollment["configuration"] = .null
    enrollment["supportedOperations"] = .array([.string("claimJoin"), .string("retireRole")])
    let originalRequest: ProductJSON = .object(["status": .string("awaiting_approval"), "request_id": .string("original-request")])
    enrollment["enrollment"] = originalRequest
    var claims = 0
    let waiting = ProductModel(testRequest: { operation, _ in
        if operation == "claimJoin" {
            claims += 1
            enrollment["enrollment"] = .object(["status": .string("rejected"), "request_id": originalRequest["request_id"]])
            return enrollment["enrollment"]!
        } else if !["startupStatus", "status"].contains(operation) { throw ProductCoreError.invalidResponse }
        return .object(enrollment)
    })
    await waiting.bootstrap()
    try require(waiting.page == .overview && waiting.status["enrollment"] == originalRequest && waiting.nativeSupportsOperation("retireRole"), "Pending join did not remain available in current Settings with cancellation")
    waiting.nativeClaim(); waiting.nativeClaim(); try await settled(waiting)
    try require(claims == 1 && waiting.status["enrollment"]["status"].string == "rejected" && waiting.status["enrollment"]["request_id"] == originalRequest["request_id"], "Checking the original join duplicated a claim or discarded its rejected record")

    let archive = Data([0x50, 0x4b, 0x03, 0x04, 0x00])
    var exportResponse: ProductJSON = .object(["archiveBase64": .string(archive.base64EncodedString())])
    let exporter = ProductCoreClient(testRequest: { operation, input in
        guard operation == "pluginExport", input == ["authorize": .bool(true)] else { throw ProductCoreError.invalidResponse }
        return exportResponse
    })
    let exported = try await exporter.exportPlugin()
    try require(exported == archive, "The current native ZIP export contract changed")
    for response in [ProductJSON.null, .object(["archiveBase64": .string("invalid")]), .object(["archiveBase64": .string(Data("not ZIP".utf8).base64EncodedString())]), .object(["archiveBase64": .string(String(repeating: "A", count: 1_400_001))])] {
        exportResponse = response
        do { _ = try await exporter.exportPlugin(); throw ProductCoreError.rejected }
        catch ProductCoreError.invalidResponse { }
    }
    print("PASS: one native model preserves drafts and action errors, coalesces observations, shares visible-surface polling, submits capabilities/invitations/join/Tunnel changes once, retains reviewed pairing identity and saved keys, and validates bounded native ZIP responses. Real Core pipes and quit custody are covered separately.")
}
#endif
