#if STYX_TESTING
import AppKit

@MainActor func productAutomaticUpdateSelfTest(sessionURL: URL, mode: String) async throws {
    func require(_ value: Bool, _ message: String) throws {
        if !value { throw NSError(domain: "Styx.AutomaticUpdateTest", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    }
    let model = try ProductModel(sessionURL: sessionURL, permissionReader: { (false, false) })
    var launches = 0
    model.launchPayloadUpdater = { ticket in
        try require(ticket == String(repeating: "a", count: 32), "Unbound helper ticket")
        launches += 1
        if mode == "launch-failed" { throw ProductCoreError.unavailable }
    }
    await model.bootstrap()
    try require(model.loaded && !model.busy, "Bootstrap did not finish")
    // Reopening surfaces and fresh observations cannot replay the attempt.
    await model.bootstrap(); await model.refresh()
    try require(launches == (["success", "previous-success", "launch-failed"].contains(mode) ? 1 : 0), "Automatic update launched an incorrect number of helpers")
    if ["prepare-failed", "launch-failed", "raced-cancel"].contains(mode) {
        try require(model.error != nil, "Update failure lost its recovery feedback")
        let error = model.error
        await model.refresh()
        try require(model.error == error, "A refresh erased update failure")
    } else { try require(model.error == nil, "Unexpected bootstrap failure") }
    print("PASS: automatic Host update authority, single attempt and recovery feedback")
}
#endif
