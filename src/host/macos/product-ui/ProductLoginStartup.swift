import AppKit
import CryptoKit
import ServiceManagement

// The signed main App is the OS adapter, never a second preference store.
// Core admits one intent; the adapter observes, compares, acts once, and reports
// the real OS state. It does not modify Host/Gateway autostart or legacy agents.
enum ProductLoginStartup {
    struct Observation: Equatable, Sendable {
        let status: String
        let fingerprint: String
        var wire: ProductJSON {
            .object(["schema": .number(1), "platform": .string("macos"),
                     "status": .string(status), "fingerprint": .string(fingerprint)])
        }
    }
    struct Result: Sendable {
        let outcome: String
        let observation: Observation
    }
    @MainActor static func observe() -> Observation {
        let bundle = Bundle.main
        let app = bundle.bundleURL.standardizedFileURL
        let executable = bundle.executableURL?.standardizedFileURL
        let legacy = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/app.styx.desktop-login.plist")
        let legacyExists = FileManager.default.fileExists(atPath: legacy.path)
            || (try? FileManager.default.destinationOfSymbolicLink(atPath: legacy.path)) != nil
        let status: String
        if legacyExists {
            // Preserve the old registration for manual removal or review.
            // Registering another owner would hide an unresolved login runner.
            status = "foreign"
        } else if bundle.bundleIdentifier != "app.styx.host"
                    || app.path != "/Applications/Styx.app"
                    || app.resolvingSymlinksInPath() != app
                    || executable != app.appendingPathComponent("Contents/MacOS/Styx") {
            status = "not_found"
        } else {
            switch SMAppService.mainApp.status {
            case .enabled: status = "enabled"
            case .notRegistered: status = "not_registered"
            case .requiresApproval: status = "requires_approval"
            case .notFound: status = "not_found"
            @unknown default: status = "unknown"
            }
        }
        // Fixed local identity and actual OS status bind even an absent entry.
        // These paths remain local; the Core pipe receives only this digest.
        let material = ProductJSON.array([.number(1), .string("macos"),
            .string(bundle.bundleIdentifier ?? ""), .string(app.path),
            .string(executable?.path ?? ""), .bool(legacyExists), .string(status)])
        let digest: String
        if let encoded = try? JSONEncoder().encode(material) {
            digest = SHA256.hash(data: encoded).map { String(format: "%02x", $0) }.joined()
        } else {
            // ProductJSON above has no fallible floating-point data. If its
            // codec nevertheless fails, no mutation may use this observation.
            return Observation(status: "unknown", fingerprint: String(repeating: "0", count: 64))
        }
        return Observation(status: status, fingerprint: digest)
    }
    @MainActor static func apply(enabled: Bool, before: Observation) -> Result {
        let current = observe()
        guard current == before,
              !["foreign", "unknown", "not_found"].contains(current.status) else {
            return Result(outcome: "failed", observation: current)
        }
        // An explicit OS denial requires the user's System Settings decision.
        // Repeated register calls must not work around that decision.
        if enabled && ["enabled", "requires_approval"].contains(current.status)
            || !enabled && current.status == "not_registered" {
            return Result(outcome: "succeeded", observation: current)
        }
        do {
            if enabled { try SMAppService.mainApp.register() }
            else { try SMAppService.mainApp.unregister() }
        } catch {
            // OS calls can have effects before returning an error. Observe the
            // result, but never reissue the mutation or invent cancellation.
            return Result(outcome: "unknown", observation: observe())
        }
        let after = observe()
        let reached = enabled
            ? ["enabled", "requires_approval"].contains(after.status)
            : ["disabled", "not_registered"].contains(after.status)
        return Result(outcome: reached ? "succeeded" : "unknown", observation: after)
    }
    @MainActor static func openSettings() { SMAppService.openSystemSettingsLoginItems() }
}
