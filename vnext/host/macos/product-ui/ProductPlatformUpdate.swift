import AppKit
#if canImport(Sparkle)
import Sparkle
#endif

// Sparkle owns its standard UI, App replacement and relaunch. The existing
// applicationShouldTerminate remains the single task/lifecycle admission gate.
@MainActor
final class ProductPlatformUpdate {
    #if canImport(Sparkle)
    private let controller: SPUStandardUpdaterController
    private init() {
        controller = SPUStandardUpdaterController(startingUpdater: true, updaterDelegate: nil, userDriverDelegate: nil)
    }
    #endif
    static func configured() -> ProductPlatformUpdate? {
        #if canImport(Sparkle)
        guard Bundle.main.object(forInfoDictionaryKey: "StyxUpdateRelease") as? Bool == true,
              let source = Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") as? String,
              let url = URL(string: source), url.user == nil, url.password == nil,
              let key = Bundle.main.object(forInfoDictionaryKey: "SUPublicEDKey") as? String,
              Data(base64Encoded: key)?.count == 32 else { return nil }
        let isolated = Bundle.main.object(forInfoDictionaryKey: "StyxIsolatedPlatformUpdateProbe") as? Bool == true
            && Bundle.main.bundlePath.hasPrefix("/private/tmp/styx-platform-update-")
        guard url.scheme == "https" || (isolated && url.scheme == "http" && url.host == "127.0.0.1") else { return nil }
        return ProductPlatformUpdate()
        #else
        return nil
        #endif
    }
    func appendMenuItem(to menu: NSMenu) {
        #if canImport(Sparkle)
        let item = menu.addItem(withTitle: productText("检查更新…", "Check for Updates…"), action: #selector(SPUStandardUpdaterController.checkForUpdates(_:)), keyEquivalent: "")
        item.target = controller
        #endif
    }
}
