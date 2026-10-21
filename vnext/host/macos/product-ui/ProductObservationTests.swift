#if STYX_TESTING
import AppKit
import Combine

@MainActor func productObservationSelfTest(sessionURL: URL) async throws {
    func require(_ value: Bool, _ message: String) throws {
        if !value { throw NSError(domain: "Styx.ObservationTest", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    }
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
