import Foundation

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
    print("Styx native product protocol self-test passed; GUI, TCC and account acceptance NOT RUN")
}

#if STYX_TESTING
import AppKit

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
                do { try png.write(to: snapshot, options: .atomic) }
                catch { fputs("Styx native window snapshot write failed\n", stderr); exit(2) }
                print("PASS: native welcome window rendered through authenticated Core reads; UI-only evidence. Cua, permissions, install and account acceptance NOT RUN")
                exit(0)
            }
        }
        withExtendedLifetime((controller, timer)) { application.run() }
        exit(2)
    }
}
#endif
