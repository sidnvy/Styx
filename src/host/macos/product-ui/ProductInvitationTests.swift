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
    if mode == "join-rollback" {
        try require(model.joinRollbackRequired && model.page == .preparation, "Interrupted recovery was hidden by a failed snapshot")
        model.rollbackJoinRecovery(); try await settled()
        try require(!model.joinRollbackRequired && model.canRecoverJoin && model.page == .preparation, "Explicit rollback did not restore the retained setup")
        print("PASS: native joined recovery reads interrupted transaction independently and explicitly rolls back without recreating deployment.")
        return
    }
    if mode.hasPrefix("join-") {
        try require(model.deployment?.joined == true, "Recovery lost the existing joined deployment")
        model.createAndPrepare(); try await settled()
        try require(model.page == .preparation, "Existing deployment was sent to create")
        try require(model.canRecoverJoin, "Core recovery projection was not presented")
        model.beginJoinRecovery()
        try require(model.recoveringJoin && model.page == .invitation, "Recovery did not reuse invitation review")
        model.cancelInvitationReview()
        try require(!model.recoveringJoin && model.page == .preparation, "Cancel recovery escaped to fresh setup")
        model.beginJoinRecovery(); model.invite = "isolated-invitation"
        model.inspectInvitation(); try await settled()
        try require(model.invite.isEmpty && model.inspection["preview"]["origin"].string != nil, "Recovery invitation was not inspected")
        if mode == "join-denied" {
            model.joinRecovery = .object(["canRecover": .bool(false), "reason": .string("pending_request_exists")])
            model.acceptInvitation(); try await settled()
            try require(model.error != nil && model.page == .invitation, "Changed Core eligibility still accepted the invitation")
        } else {
            model.acceptInvitation(); try await settled()
            try require(model.error == nil && model.page == .preparation && !model.recoveringJoin, "Same-identity recovery did not return to retained preparation")
            try require(model.deployment?.steps.first(where: { $0.id == "host.prepare" })?.complete == true, "Recovery discarded prepared components")
            try require(model.deployment?.steps.first(where: { $0.id == "host.request" })?.status == "pending", "Recovery implicitly replayed a request")
            model.continuePreparation(); try await settled()
            try require(model.deployment?.steps.first(where: { $0.id == "host.claim" })?.status == "awaiting_approval", "Explicit continuation did not reach existing claim wait")
        }
        print("PASS: native joined recovery uses inspect, explicit trust, same-deployment recovery and separately authorized continuation; cancellation and changed eligibility never create a deployment.")
        return
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
    if mode == "lost-create" {
        try require(model.createdInvitation == .null && model.invitationWindowOpen && model.invitationError != nil, "Lost create response hid a potentially open pairing window")
    } else {
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
    }
    var closed = false
    model.closeDeviceInvitation { closed = true }; try await settled()
    try require(!closed && model.invitationWindowOpen && model.invitationError != nil, "Failed close hid an open invitation")
    model.closeDeviceInvitation { closed = true }; try await settled()
    try require(closed && !model.invitationWindowOpen && model.invitationClosed && model.createdInvitation == .null, "Close did not clear invitation after authoritative confirmation")
    print("PASS: native interface selection, interrupted preparation, explicit recovery, identity confirmation and retryable close use shared Core routes; failed/unknown actions never become success.")
}
#endif
