#if STYX_TESTING
import Foundation
import AppKit
import SwiftUI

// Called by the signed executable's existing --self-test path. These are
// protocol/decoding checks, not native permission or account acceptance claims.
func productCoreSelfTest() throws {
    // These assertions run in both production and explicitly compiled local
    // mode. Arbitrary CLI/env values cannot select another package or profile.
    let expectedPackage = ProductNativeLaunchScope.appPath
    precondition(ProductNativeLaunchScope.acceptsPackagePath(expectedPackage, identifier: "app.styx.host"))
    for invalid in [expectedPackage + "/", expectedPackage + "/../Styx.app", "/tmp/Styx.app", "relative/Styx.app"] {
        precondition(!ProductNativeLaunchScope.acceptsPackagePath(invalid, identifier: "app.styx.host"))
    }
    precondition(!ProductNativeLaunchScope.acceptsPackagePath(expectedPackage, identifier: "other.app"))
    precondition(expectedPackage == "/Applications/Styx.app")
    precondition(!ProductNativeLaunchScope.acceptsPackagePath("/Users/it-bootstrap/Developer/Styx/artifacts/native-development/macos/Styx.app", identifier: "app.styx.host"))
    #if STYX_LOCAL_DEVELOPMENT
    precondition(ProductNativeLaunchScope.support.path == ProductNativeLaunchScope.developmentSupport)
    #else
    precondition(ProductNativeLaunchScope.support.path == NSHomeDirectory() + "/Library/Application Support/Styx")
    #endif
    func require(_ condition: @autoclosure () -> Bool, _ message: String) throws {
        if !condition() { throw NSError(domain: "Styx.ProductSelfTest", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
    }
    #if STYX_TESTING
    try require(ProductNativeDiagnostics.coreStderrCode(Data("{\"error\":\"app_runtime_input_changed\",\"schema\":1}".utf8)) == "app_runtime_input_changed", "Closed historical runtime-input failure code was lost")
    try require(ProductNativeDiagnostics.coreStderrCode(Data("{\"error\":\"app_role_retire_unknown\",\"schema\":1}".utf8)) == "app_role_retire_unknown", "Closed role-retirement fence failure code was lost")
    let invalidCoreLines = [
        "{\"error\":\"fake-test-secret\",\"schema\":1}",
        "{\"error\":\"app_scope_refused\",\"schema\":1,\"body\":\"fake-test-secret\"}",
        "{\"error\":\"app_scope_refused\",\"error\":\"app_scope_refused\",\"schema\":1}",
        "{\"error\":\"app_scope_refused\",\"schema\":true}",
        "{\"error\":7,\"schema\":1}"
    ]
    for line in invalidCoreLines {
        try require(ProductNativeDiagnostics.coreStderrCode(Data(line.utf8)) == nil, "Invalid Core stderr was accepted")
    }
    var splitScanner = ProductCoreStderrScanner()
    splitScanner.consume(Data(repeating: 65, count: 300))
    splitScanner.consume(Data(repeating: 65, count: 300))
    splitScanner.consume(Data("\n{\"error\":\"app_scope_".utf8))
    splitScanner.consume(Data("refused\",\"schema\":1}".utf8))
    try require(splitScanner.code == nil, "Unterminated Core stderr was accepted")
    splitScanner.consume(Data("\n".utf8))
    try require(splitScanner.code == "app_scope_refused", "Split Core stderr or oversized-line recovery failed")
    let child = Process(), childError = Pipe()
    defer { try? childError.fileHandleForReading.close() }
    child.executableURL = URL(fileURLWithPath: "/bin/sh")
    child.arguments = ["-c", "printf '%0700d\\n' 0 >&2; printf '%s\\n' '{\"error\":\"fake-test-secret\",\"schema\":1}' '{\"error\":\"app_scope_refused\",\"schema\":1}' '{\"error\":\"app_scope_changed\",\"schema\":1}' >&2; exit 2"]
    child.standardInput = FileHandle.nullDevice; child.standardOutput = FileHandle.nullDevice; child.standardError = childError
    try child.run()
    try childError.fileHandleForWriting.close()
    var scanner = ProductCoreStderrScanner()
    while true {
        let data = childError.fileHandleForReading.availableData
        if data.isEmpty { break }
        scanner.consume(data)
    }
    child.waitUntilExit()
    try require(child.terminationReason == .exit && child.terminationStatus == 2 && scanner.code == "app_scope_refused", "Core stderr drain or actual child exit was lost")
    #endif
    try require(ProductTunnelInputPolicy.tunnelError("https://example.com") != nil, "A server URL became a Tunnel ID")
    try require(ProductTunnelInputPolicy.tunnelError(" tunnel_12345678 ") == nil, "Valid pasted Tunnel ID rejected")
    try require(ProductTunnelInputPolicy.keyError("", saved: true) == nil, "Saved key required secret readback")
    for code in ["join_http_connect_failed", "join_http_tls_rejected"] {
        try require(ProductNativeDiagnostics.rejectionCode(.object(["error": .string(code), "detail": .string("private-canary")])) == code, "A fixed join transport diagnosis was discarded")
    }
    try require(ProductNativeDiagnostics.rejectionCode(.object(["error": .string("private-canary"), "code": .string("join_http_connect_failed")])) == "other", "An arbitrary error or alternate field escaped diagnostic redaction")
    try require(ProductTunnelInputPolicy.keyError("", saved: false) != nil, "Missing runtime key allowed on first setup")
    try require(ProductTunnelInputPolicy.keyError("sk-valid_" + String(repeating: "a", count: 32), saved: false) == nil, "Valid runtime key rejected")
    for observed in [ProductJSON.null, .string("true")] {
        let device = ProductDevice(.object(["device_id": .string("test"), "label": .string("Mac"), "online": observed]))
        try require(device?.indicator == .unknown, "Absent or mistyped observation became online")
    }
    for connected in [true, false] {
        let device = ProductDevice(.object(["device_id": .string("test"), "label": .string("Mac"), "online": .bool(connected)]))
        try require(device?.indicator == (connected ? .connected : .offline), "Observed connection state was lost")
    }
    try require(ProductSettingsSection.allCases.count == 3, "Local and other computers split into overlapping settings")
    try require(ProductJSON.string("true").bool == false, "String coerced to authorization")
    try require(ProductJSON.null["complete"].bool == false, "Missing observation promoted to complete")
    let roundTrip: ProductJSON = .object(["n": .number(1), "yes": .bool(true), "none": .null, "steps": .array([.string("pending")])])
    let decoded = try JSONDecoder().decode(ProductJSON.self, from: JSONEncoder().encode(roundTrip))
    try require(decoded == roundTrip, "JSON protocol roundtrip failed")
    try productStatusImageSelfTest()
    print("Styx native product protocol self-test passed; GUI, TCC and account acceptance NOT RUN")
}

private func productStatusImageSelfTest() throws {
    // Deterministic alpha-mask fixture: outer white margin stays transparent, and
    // an interior white gap must survive. This never replaces the bundled art.
    guard let source = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 64, pixelsHigh: 64,
                                        bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true,
                                        isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 256, bitsPerPixel: 32),
          let bytes = source.bitmapData else { throw ProductCoreError.invalidResponse }
    for y in 0..<64 {
        for x in 0..<64 {
            let disk = (x - 32) * (x - 32) + (y - 32) * (y - 32) < 28 * 28 && abs(y - 32) > 2
            let offset = y * 256 + x * 4, value: UInt8 = disk ? 0 : 255
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

#endif
