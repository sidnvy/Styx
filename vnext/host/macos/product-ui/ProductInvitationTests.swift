#if STYX_TESTING
import AppKit

// Real native model/client and private HTTP server, synthetic isolated Core.
// No user settings, certificates, sockets outside loopback or OS grants.
@MainActor func productInvitationSelfTest(sessionURL: URL, mode: String) async throws {
    func require(_ value: Bool, _ message: String) throws {
        if !value { throw NSError(domain: "Styx.InvitationTest", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    }
    let model = try ProductModel(sessionURL: sessionURL, permissionReader: { (false, false) })
    await model.bootstrap()
    func settled() async throws {
        for _ in 0..<300 {
            if !model.busy { return }
            try await Task.sleep(nanoseconds: 20_000_000)
        }
        throw ProductCoreError.unavailable
    }
    model.beginDeviceInvitation(); try await settled()
    try require(model.ingressCandidates.count == 2 && model.createdInvitation == .null && !model.invitationWindowOpen, "Multiple interfaces opened an unselected listener")
    model.selectedIngressAddress = "0.0.0.0"
    model.beginDeviceInvitation(); try await settled()
    try require(model.selectedIngressAddress.isEmpty && model.createdInvitation == .null, "Unknown interface accepted")
    model.selectedIngressAddress = "192.0.2.10"
    model.beginDeviceInvitation(); try await settled()
    try require(model.ingressNeedsRecovery && model.invitationError != nil && model.createdInvitation == .null, "Failed preparation did not retain recovery feedback")
    model.beginDeviceInvitation(); try await settled()
    try require(model.ingressNeedsRecovery && model.createdInvitation == .null, "Uncertain preparation was automatically replayed")
    model.recoverDeviceInvitation(mode == "rollback" ? "rollback" : "retry"); try await settled()
    try require(!model.ingressNeedsRecovery && model.createdInvitation == .null && !model.invitationWindowOpen, "Recovery silently opened an invitation")
    if mode == "rollback" {
        try require(model.invitationClosed, "Rollback did not show completion")
        print("PASS: native invitation rollback is explicit and never opens a pairing window.")
        return
    }
    model.beginDeviceInvitation(); try await settled()
    try require(model.createdInvitation["link"].string != nil && model.invitationWindowOpen, "Recovered explicit create failed")
    model.loadPending(); try await settled()
    guard let request = model.pending.first else { throw ProductCoreError.invalidResponse }
    model.selectedPending = request
    model.comparisonConfirmation = ""; model.approvePending(); try await settled()
    model.comparisonConfirmation = "FFFF-FFFF-FFFF-FFFF"; model.approvePending(); try await settled()
    try require(ProductInvitationPolicy.approval(request, confirmation: "") == nil && ProductInvitationPolicy.approval(request, confirmation: "FFFF-FFFF-FFFF-FFFF") == nil, "Missing or wrong comparison permitted approval")
    model.comparisonConfirmation = request["comparison_code"].string ?? ""
    model.approvePending(); try await settled()
    try require(model.selectedPending == .null && model.comparisonConfirmation.isEmpty, "Confirmed request was not approved exactly once")
    var closed = false
    model.closeDeviceInvitation { closed = true }; try await settled()
    try require(!closed && model.invitationWindowOpen && model.invitationError != nil, "Failed close hid an open invitation")
    model.closeDeviceInvitation { closed = true }; try await settled()
    try require(closed && !model.invitationWindowOpen && model.invitationClosed && model.createdInvitation == .null, "Close did not clear invitation after authoritative confirmation")
    print("PASS: native interface selection, interrupted preparation, explicit recovery, identity confirmation and retryable close use shared Core routes; failed/unknown actions never become success.")
}
#endif
