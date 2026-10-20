import Foundation
import AppKit

// Called by the signed executable's existing --self-test path. These are
// protocol/decoding checks, not native permission or account acceptance claims.
func productCoreSelfTest() throws {
    func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() { throw NSError(domain: "Styx.ProductSelfTest", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    }
    let token = String(repeating: "a", count: 43)
    let valid = URL(string: "http://127.0.0.1:12345/#session=" + token)!
    let parsed = ProductCoreClient.bootstrap(valid)
    try require(parsed?.origin.absoluteString == "http://127.0.0.1:12345/", "Bootstrap must strip secret fragment")
    try require(parsed?.token == token, "Bootstrap credential changed")
    for input in [
        "https://127.0.0.1:12345/#session=" + token,
        "http://localhost:12345/#session=" + token,
        "http://127.0.0.2:12345/#session=" + token,
        "http://127.0.0.1/#session=" + token,
        "http://127.0.0.1:0/#session=" + token,
        "http://owner@127.0.0.1:12345/#session=" + token,
        "http://127.0.0.1:12345/api/#session=" + token,
        "http://127.0.0.1:12345/?copy=1#session=" + token,
        "http://127.0.0.1:12345/#session=" + token + "&other=1",
        "http://127.0.0.1:12345/#session=short"
    ] {
        guard let url = URL(string: input) else { continue }
        try require(ProductCoreClient.bootstrap(url) == nil, "Unsafe bootstrap accepted")
    }
    let fixture = Data(#"{"mode":"join-existing","roles":{"computer":"requested","browser":"requested"},"steps":[{"id":"host.claim","status":"awaiting_approval"}]}"#.utf8)
    let projection = ProductDeployment(try JSONDecoder().decode(ProductJSON.self, from: fixture))
    try require(projection?.joined == true, "Joined Host changed to local Gateway")
    try require(projection?.steps.first?.status == "awaiting_approval", "Pending approval promoted to success")
    try require(projection?.browserRequested == true, "Requested Browser intent lost")
    try require(ProductDeployment(.object(["mode": .string("unknown")] )) == nil, "Unknown deployment became configured")
    try require(ProductJSON.string("true").bool == false, "String coerced to authorization")
    try require(ProductJSON.null["complete"].bool == false, "Missing proof promoted to complete")
    let roundTrip: ProductJSON = .object(["n": .number(1), "yes": .bool(true), "none": .null, "steps": .array([.string("pending")])])
    let decoded = try JSONDecoder().decode(ProductJSON.self, from: JSONEncoder().encode(roundTrip))
    try require(decoded == roundTrip, "JSON protocol roundtrip failed")
    try require(!ProductCoreClient.writes.contains("../status"), "Traversal route allowed")
    try require(!ProductCoreClient.reads.contains("connection-handoff"), "Secret handoff exposed as ordinary read")
    // A denied optional capability must not trap an approved Exec-only join.
    let deniedBrowser: ProductJSON = .object(["status": .string("not_approved"), "approved": .bool(false)])
    try require(ProductCapabilityPolicy.browserPreparation(requested: true, observation: deniedBrowser) == .notRequired, "Denied Browser blocked the approved Host")
    try require(ProductCapabilityPolicy.browserPreparation(requested: true, observation: .object(["status": .string("not_prepared"), "approved": .bool(true)])) == .prepare, "Approved Browser preparation was omitted")
    let unverifiedApproval: [ProductJSON] = [.null, .object(["status": .string("not_prepared")]), .object(["status": .string("not_approved"), "approved": .bool(true)]), .object(["status": .string("preparation_blocked"), "approved": .bool(true)])]
    for observation in unverifiedApproval {
        try require(ProductCapabilityPolicy.browserPreparation(requested: true, observation: observation) == .needsReview, "Unknown or inconsistent approval became preparation authority")
    }
    try require(!ProductCapabilityPolicy.computerApproved(.object(["computerRequested": .string("true")])), "Untrusted requested text became Computer Use permission authority")
    try require(!ProductCapabilityPolicy.computerApproved(.object(["computerRequested": .bool(false)])), "Denied Computer Use led to a permission prompt")
    try require(ProductCapabilityPolicy.computerApproved(.object(["computerRequested": .bool(true)])), "Approved Computer Use lost its permission step")
    let owned: ProductJSON = .object(["status": .string("connected"), "observation": .string("current_process"), "host": .string("foreground")])
    let live: ProductJSON = .object(["status": .string("connected"), "observation": .string("authenticated_foreground_owner")])
    let stopped: ProductJSON = .object(["status": .string("not_running"), "observation": .string("current_process")])
    try require(ProductCapabilityPolicy.foregroundTransition(owner: owned, observed: live) == .owned, "App-owned connection cannot enter reviewed capability change")
    try require(ProductCapabilityPolicy.foregroundTransition(owner: stopped, observed: stopped) == .stopped, "Verified offline state requires an unrelated stop")
    try require(ProductCapabilityPolicy.foregroundTransition(owner: stopped, observed: live) == .needsReview, "Foreign live owner was treated as stopped")
    let foreignOwners: [ProductJSON] = [.null, live, .object(["status": .string("connected"), "observation": .string("current_process"), "host": .string("service")]), .object(["status": .string("needs_attention"), "observation": .string("current_process"), "host": .string("foreground")])]
    for foreign in foreignOwners {
        try require(ProductCapabilityPolicy.foregroundTransition(owner: foreign, observed: live) == .needsReview, "Unknown, foreign or service owner became App stop authority")
    }
    try require(ProductCapabilityPolicy.foregroundTransition(owner: owned, observed: .object(["status": .string("needs_attention")])) == .needsReview, "Failed owner observation permitted a stop")
    let stalledJSON = Data(#"{"mode":"create-local","roles":{"computer":"requested","browser":"requested"},"steps":[{"id":"gateway.prepare","status":"succeeded"},{"id":"gateway.start","status":"succeeded"},{"id":"gateway.verify","status":"succeeded"},{"id":"host.prepare","status":"succeeded"},{"id":"host.pair","status":"succeeded"},{"id":"host.doctor","status":"blocked","blockers":["codex_executor_unavailable","https://private.invalid/secret"],"retryable":true}]}"#.utf8)
    let stalled = ProductDeployment(try JSONDecoder().decode(ProductJSON.self, from: stalledJSON))
    let stages = ProductPreparationPolicy.stages(stalled, browser: .null, activity: nil)
    try require(stages.map(\.id) == [.components, .connection, .browser], "Preparation exposed implementation steps instead of the selected user stages")
    try require(stages[0].state == .completed && stages[1].state == .blocked && stages[2].state == .pending, "A failed command check lost the already completed installation")
    guard let retry = ProductPreparationPolicy.retryableCommandCheck(stalled) else { throw ProductCoreError.invalidResponse }
    try require(retry.blockers == ["codex_executor_unavailable"], "Untrusted doctor details reached the user projection")
    let commandMessage = ProductPreparationPolicy.commandCheckMessage(retry).lowercased()
    try require(!commandMessage.contains("permission") && !commandMessage.contains("权限"), "A command startup failure was presented as an OS permission requirement")
    let checking = ProductPreparationPolicy.stages(stalled, browser: .null, activity: .connection)
    try require(checking[1].state == .working, "Explicit read-only recheck still appeared idle and blocked")
    for unsafe in [#"{"id":"host.pair","status":"blocked","retryable":true}"#, #"{"id":"host.doctor","status":"uncertain","retryable":true}"#, #"{"id":"host.doctor","status":"blocked","retryable":"true"}"#] {
        let step = ProductStep(try JSONDecoder().decode(ProductJSON.self, from: Data(unsafe.utf8)))
        try require(step?.retryable == false, "An unsafe or unconfirmed step was admitted as a read-only retry")
    }
    for (id, state, allowed) in [("host.claim", "blocked", true), ("host.claim", "awaiting_approval", true), ("host.claim", "uncertain", false), ("host.request", "blocked", false), ("host.pair", "blocked", false)] {
        let joinedCheck: ProductJSON = .object(["mode": .string("join-existing"), "steps": .array([.object(["id": .string("host.prepare"), "status": .string("succeeded")]), .object(["id": .string(id), "status": .string(state)])])])
        try require(ProductPreparationPolicy.canCheckOwnerApproval(ProductDeployment(joinedCheck)) == allowed, "Approval recheck either trapped a read-only claim or replayed an unsafe pairing step")
    }
    let noBrowser = ProductDeployment(try JSONDecoder().decode(ProductJSON.self, from: Data(#"{"mode":"create-local","roles":{"computer":"requested","browser":"disabled"},"steps":[{"id":"host.prepare","status":"succeeded"},{"id":"host.pair","status":"succeeded"},{"id":"host.doctor","status":"succeeded"}]}"#.utf8)))
    try require(ProductPreparationPolicy.stages(noBrowser, browser: .null, activity: nil).map(\.id) == [.components, .connection], "An unselected Browser stage reached onboarding")
    let preparedBrowser: ProductJSON = .object(["status": .string("prepared"), "approved": .bool(true)])
    let approvedForeground: ProductJSON = .object(["status": .string("connected"), "observation": .string("authenticated_foreground_owner"), "host": .string("foreground"), "computerRequested": .bool(true)])
    try require(ProductRestorationPolicy.page(deployment: stalled, localPrepared: true, browser: .object(["status": .string("not_prepared"), "approved": .bool(true)]), foreground: approvedForeground, accepted: false, accessibility: true, screenRecording: true) == .preparation, "Recovery skipped the unprepared selected Browser")
    try require(ProductRestorationPolicy.page(deployment: stalled, localPrepared: true, browser: preparedBrowser, foreground: stopped, accepted: true, accessibility: true, screenRecording: true) == .preparation, "Past account acceptance hid a stopped connection")
    try require(ProductRestorationPolicy.page(deployment: stalled, localPrepared: true, browser: preparedBrowser, foreground: approvedForeground, accepted: true, accessibility: true, screenRecording: false) == .permissions, "Recovery skipped revoked Screen Recording permission")
    try require(ProductRestorationPolicy.page(deployment: stalled, localPrepared: true, browser: preparedBrowser, foreground: approvedForeground, accepted: false, accessibility: true, screenRecording: true) == .chat, "Prepared authorized recovery incorrectly restarted registration")
    let noLiveConnection = ProductPreparationPolicy.stages(noBrowser, browser: .null, foreground: stopped, activity: nil)
    try require(noLiveConnection[1].state == .pending, "Completed pairing was presented as an observed live connection")
    try require(ProductRestorationPolicy.page(deployment: stalled, localPrepared: true, browser: preparedBrowser, foreground: .object(["status": .string("needs_attention")]), accepted: true, accessibility: true, screenRecording: true) == .preparation, "Uncertain connection recovery skipped review")
    try productStatusImageSelfTest()
    print("Styx native product protocol self-test passed; GUI, TCC and account acceptance NOT RUN")
}

private func productStatusImageSelfTest() throws {
    // Deterministic alpha-mask fixture: outer card border must be ignored, and
    // an interior white gap must survive. This never replaces the bundled art.
    guard let source = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 64, pixelsHigh: 64,
                                        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                                        isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 256, bitsPerPixel: 32),
          let bytes = source.bitmapData else { throw ProductCoreError.invalidResponse }
    for y in 0..<64 {
        for x in 0..<64 {
            let disk = (x - 32) * (x - 32) + (y - 32) * (y - 32) < 18 * 18 && abs(y - 32) > 2
            let card = x == 2 || x == 61 || y == 2 || y == 61
            let offset = y * 256 + x * 4, value: UInt8 = disk || card ? 0 : 255
            bytes[offset] = value; bytes[offset + 1] = value; bytes[offset + 2] = value; bytes[offset + 3] = 255
        }
    }
    let fixture = NSImage(size: NSSize(width: 64, height: 64)); fixture.addRepresentation(source)
    guard let icon = styxStatusItemImage(source: fixture), icon.isTemplate, icon.size == NSSize(width: 18, height: 18),
          let mask = icon.representations.first as? NSBitmapImageRep, mask.hasAlpha,
          let corner = mask.colorAt(x: 0, y: 0),
          let gap = mask.colorAt(x: mask.pixelsWide / 2, y: mask.pixelsHigh / 2),
          let glyph = mask.colorAt(x: mask.pixelsWide / 2, y: mask.pixelsHigh / 4),
          corner.alphaComponent < 0.05, gap.alphaComponent < 0.05, glyph.alphaComponent > 0.95 else { throw ProductCoreError.invalidResponse }
    if let root = Bundle.main.resourceURL {
        let url = root.appendingPathComponent("brand/styx-icon-light-source.jpg")
        if FileManager.default.fileExists(atPath: url.path) {
            guard let artwork = NSImage(contentsOf: url), let icon = styxStatusItemImage(source: artwork), icon.isTemplate else { throw ProductCoreError.invalidResponse }
        }
    }
}

#if STYX_TESTING

extension ProductWindowController {
    // Window rendering only. The harness has no StyxDelegate, Cua child, system
    // permission prompts, installed services or deployment mutation path.
    @MainActor static func runIsolatedSmoke(sessionURL: URL, snapshot: URL) -> Never {
        guard ProductCoreClient.bootstrap(sessionURL) != nil, snapshot.isFileURL else { exit(2) }
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        let controller = ProductWindowController(sessionURL: sessionURL)
        controller.present()
        var attempts = 0
        let timer = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { _ in
            Task { @MainActor in
                attempts += 1
                guard attempts <= 100 else { fputs("Styx native product window smoke timed out\n", stderr); exit(2) }
                guard controller.model.loaded, !controller.model.busy else { return }
                guard controller.model.error == nil, controller.model.deployment == nil,
                      controller.model.page == .welcome,
                      let view = controller.window?.contentView,
                      let bitmap = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
                    fputs("Styx native window smoke requires a fresh isolated configuration\n", stderr); exit(2)
                }
                view.cacheDisplay(in: view.bounds, to: bitmap)
                guard let png = bitmap.representation(using: .png, properties: [:]) else { exit(2) }
                do {
                    try png.write(to: snapshot, options: .atomic)
                    try exportStatusIconSnapshot(beside: snapshot)
                }
                catch { fputs("Styx native window snapshot write failed\n", stderr); exit(2) }
                print("PASS: native welcome window rendered through authenticated Core reads; UI-only evidence. Cua, permissions, install and account acceptance NOT RUN")
                exit(0)
            }
        }
        withExtendedLifetime((controller, timer)) { application.run() }
        exit(2)
    }
    @MainActor private static func exportStatusIconSnapshot(beside snapshot: URL) throws {
        guard let root = Bundle.main.resourceURL,
              let artwork = NSImage(contentsOf: root.appendingPathComponent("brand/styx-icon-light-source.jpg")),
              let icon = styxStatusItemImage(source: artwork) else { throw ProductCoreError.invalidResponse }
        var rect = NSRect(origin: .zero, size: icon.size)
        guard let image = icon.cgImage(forProposedRect: &rect, context: nil, hints: nil),
              let bitmap = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 36, pixelsHigh: 36,
                                           bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                                           isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 144, bitsPerPixel: 32),
              let context = CGContext(data: bitmap.bitmapData, width: 36, height: 36, bitsPerComponent: 8,
                                      bytesPerRow: 144, space: CGColorSpaceCreateDeviceRGB(),
                                      bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { throw ProductCoreError.invalidResponse }
        context.clear(CGRect(x: 0, y: 0, width: 36, height: 36)); context.interpolationQuality = .high
        context.draw(image, in: CGRect(x: 0, y: 0, width: 36, height: 36))
        bitmap.size = NSSize(width: 18, height: 18)
        guard let png = bitmap.representation(using: .png, properties: [:]) else { throw ProductCoreError.invalidResponse }
        try png.write(to: URL(fileURLWithPath: snapshot.path + ".status-icon.png"), options: .atomic)
    }
}
#endif
