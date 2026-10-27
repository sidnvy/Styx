import AppKit
#if canImport(Sparkle)
import Sparkle
#endif

// Sparkle owns App replacement/relaunch. This bridge owns only one live Core
// admission; neither a version string nor a prepared ticket proves full drain.
@MainActor
final class ProductPlatformUpdate: NSObject {
    private enum Phase { case idle, preparing, prepared, cancelling, unknown, ownerJoined }
    private var phase: Phase = .idle
    private var client: ProductCoreClient?
    private var report: ((String) -> Void)?
    private var ticket: String?
    private var installationScheduled = false
    private var selectedVersion: String?
    #if canImport(Sparkle)
    private var controller: SPUStandardUpdaterController?
    private var sparkleStarted = false
    private var cycleActive = false
    #endif
    private init(sparkle: Bool) {
        super.init()
        #if canImport(Sparkle)
        if sparkle {
            // Even a previously downloaded update must not resume before the
            // original live Core has admitted this installation-root boundary.
            controller = SPUStandardUpdaterController(startingUpdater: false, updaterDelegate: self, userDriverDelegate: nil)
        }
        #endif
    }
    static func configured() -> ProductPlatformUpdate? {
        #if canImport(Sparkle)
        if Bundle.main.object(forInfoDictionaryKey: "StyxUpdateRelease") as? Bool == true,
           let source = Bundle.main.object(forInfoDictionaryKey: "SUFeedURL") as? String,
           let url = URL(string: source), url.user == nil, url.password == nil,
           let key = Bundle.main.object(forInfoDictionaryKey: "SUPublicEDKey") as? String,
           Data(base64Encoded: key)?.count == 32 {
            let isolated = Bundle.main.object(forInfoDictionaryKey: "StyxIsolatedPlatformUpdateProbe") as? Bool == true
                && Bundle.main.bundlePath.hasPrefix("/private/tmp/styx-platform-update-")
            if url.scheme == "https" || (isolated && url.scheme == "http" && url.host == "127.0.0.1") {
                return ProductPlatformUpdate(sparkle: true)
            }
        }
        #endif
        // Ordinary DMG delivery still needs the same live admission and full
        // normal Quit before the user replaces the App. No copying runs here.
        guard let resources = Bundle.main.resourceURL,
              FileManager.default.fileExists(atPath: resources.appendingPathComponent("macos-runtime.json").path) else { return nil }
        return ProductPlatformUpdate(sparkle: false)
    }
    func bind(client: ProductCoreClient, report: @escaping (String) -> Void) {
        guard client.isNativeHost, self.client == nil || self.client === client else { return }
        self.client = client; self.report = report
    }
    func appendMenuItem(to menu: NSMenu) {
        #if canImport(Sparkle)
        if controller != nil {
            let check = menu.addItem(withTitle: productText("检查更新…", "Check for Updates…"), action: #selector(checkForUpdates(_:)), keyEquivalent: "")
            check.target = self
        }
        #endif
        let manual = menu.addItem(withTitle: productText("准备手动更新 App…", "Prepare manual App update…"), action: #selector(prepareManualUpdate(_:)), keyEquivalent: "")
        manual.target = self
    }
    private func attention(_ message: String) {
        if let report { report(message) }
        else {
            let alert = NSAlert(); alert.messageText = productText("App 更新需要检查", "App update needs attention")
            alert.informativeText = message; alert.addButton(withTitle: productText("好", "OK")); alert.runModal()
        }
    }
    private var unknownMessage: String {
        productText("App 更新准备的结果尚未确认，不会自动重试。请保留当前 App 和原设置，先检查状态。", "App update preparation is unconfirmed and will not retry automatically. Keep the current App and original profile, and review the state first.")
    }
    private func prepare() async throws {
        guard phase == .idle, let client else { throw ProductCoreError.unavailable }
        #if canImport(Sparkle)
        guard !cycleActive else { throw ProductCoreError.workInProgress }
        #endif
        phase = .preparing
        let request = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        do {
            let prepared = try await client.prepareNativeAppMaintenance(requestId: request)
            guard phase == .preparing, let ticket = prepared["ticketId"].string else { throw ProductCoreError.invalidResponse }
            self.ticket = ticket; phase = .prepared
        } catch let rejection as ProductOwnedCoreRejection {
            phase = rejection.response["error"].string?.contains("unknown") == true ? .unknown : .idle
            throw rejection
        } catch { phase = .unknown; throw error }
    }
    @objc private func prepareManualUpdate(_ sender: Any?) {
        guard phase == .idle else { attention(unknownMessage); return }
        let alert = NSAlert()
        alert.messageText = productText("准备更新并退出 Styx？", "Prepare the update and quit Styx?")
        alert.informativeText = productText("Styx 会先检查运行组件是否独立于 App，再正常结束本 App 的连接。完全退出后，请按原 DMG 方式替换 /Applications/Styx.app 并重新打开。身份、配对和权限会保留。", "Styx will check that runtime components are independent of the App, then normally end this App’s connections. After it fully quits, replace /Applications/Styx.app using the usual DMG process and reopen it. Identity, pairing and permissions are preserved.")
        alert.addButton(withTitle: productText("检查并退出", "Check and quit")); alert.addButton(withTitle: productText("取消", "Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        Task {
            do { try await prepare(); installationScheduled = true; productScheduleApplicationTermination() }
            catch { showPreparationFailure() }
        }
    }
    private func showPreparationFailure() {
        attention(phase == .unknown ? unknownMessage : productText("App 更新准备未通过。请先在通用设置中准备并完成原生运行组件更新，再重新检查。现有设置没有被替换。", "App update preparation did not pass. First stage and finish the native runtime update in General settings, then check again. The existing profile has not been replaced."))
    }
    // All termination paths, including Sparkle install-on-quit paths that omit
    // shouldPostponeRelaunch, still cross the original AppKit lifecycle gate.
    func permitsApplicationQuit() -> Bool {
        guard phase != .preparing, phase != .cancelling, phase != .unknown else {
            attention(unknownMessage); return false
        }
        return true
    }
    func nativeOwnerDidJoin(clean: Bool) -> Bool {
        guard phase == .prepared || phase == .ownerJoined else { return phase == .idle }
        guard clean else { phase = .unknown; attention(unknownMessage); return false }
        phase = .ownerJoined
        return true
    }
    private func cancelPreparation() {
        guard phase == .prepared, let ticket, let client else { return }
        phase = .cancelling
        Task {
            do {
                try await client.cancelNativeAppMaintenance(ticketId: ticket)
                // Only this original ticket's confirmed cancellation clears the
                // transient bridge state. Duplicate delegate callbacks do not
                // send another cancel, prepare, or update request.
                self.ticket = nil; selectedVersion = nil; installationScheduled = false; phase = .idle
            } catch { phase = .unknown; attention(unknownMessage) }
        }
    }
    #if canImport(Sparkle)
    @objc private func checkForUpdates(_ sender: Any?) {
        guard let controller, phase == .idle, !cycleActive,
              !sparkleStarted || controller.updater.canCheckForUpdates else { attention(unknownMessage); return }
        Task {
            do {
                try await prepare()
                cycleActive = true
                if !sparkleStarted { sparkleStarted = true; controller.startUpdater() }
                controller.checkForUpdates(sender)
            } catch { showPreparationFailure() }
        }
    }
    private func requirePreparedUpdate() throws {
        guard phase == .prepared else {
            throw NSError(domain: "app.styx.platform-update", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: unknownMessage])
        }
    }
    #endif
}

#if canImport(Sparkle)
extension ProductPlatformUpdate: SPUUpdaterDelegate {
    func updater(_ updater: SPUUpdater, mayPerform updateCheck: SPUUpdateCheck) throws {
        try requirePreparedUpdate()
    }
    func updater(_ updater: SPUUpdater, shouldProceedWithUpdate updateItem: SUAppcastItem, updateCheck: SPUUpdateCheck) throws {
        try requirePreparedUpdate()
        if let selectedVersion, selectedVersion != updateItem.versionString {
            throw NSError(domain: "app.styx.platform-update", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: productText("更新目标已改变，请结束这次检查后再试。", "The update target changed. Finish this check before trying again.")])
        }
        selectedVersion = updateItem.versionString
    }
    func updater(_ updater: SPUUpdater, userDidMake choice: SPUUserUpdateChoice, forUpdate updateItem: SUAppcastItem, state: SPUUserUpdateState) {
        if choice == .install || state.stage == .installing { installationScheduled = true }
        else { cancelPreparation() }
    }
    func updater(_ updater: SPUUpdater, willInstallUpdate item: SUAppcastItem) {
        installationScheduled = true // observation only; never a drain receipt
    }
    func updater(_ updater: SPUUpdater, willInstallUpdateOnQuit item: SUAppcastItem, immediateInstallationBlock immediateInstallHandler: @escaping () -> Void) -> Bool {
        installationScheduled = true
        if phase != .prepared { phase = .unknown }
        return false // Sparkle retains its own standard installation lifecycle
    }
    func userDidCancelDownload(_ updater: SPUUpdater) { cancelPreparation() }
    func updater(_ updater: SPUUpdater, didAbortWithError error: Error) { cancelPreparation() }
    func updaterDidNotFindUpdate(_ updater: SPUUpdater) { cancelPreparation() }
    func updater(_ updater: SPUUpdater, didFinishUpdateCycleFor updateCheck: SPUUpdateCheck, error: Error?) {
        cycleActive = false
        if !installationScheduled || error != nil { cancelPreparation() }
    }
}
#endif
