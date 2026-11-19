import AppKit
import ApplicationServices
import SwiftUI
import UniformTypeIdentifiers

func productText(_ chinese: String, _ english: String) -> String {
    (Locale.preferredLanguages.first ?? "en").hasPrefix("zh") ? chinese : english
}

enum ProductPage: String, CaseIterable { case welcome, invitation, capabilities, permissions, chat, overview, computers, settings }
enum ProductTunnelConnection: Equatable {
    case notConfigured, connected, connecting, stopped, unavailable, unknown
    static func observed(_ tunnel: ProductJSON) -> Self {
        if tunnel["status"].string == "not_configured" { return .notConfigured }
        switch tunnel["transport"].string {
        case "ready": return ["running", "configured"].contains(tunnel["status"].string ?? "") ? .connected : .unknown
        case "starting": return .connecting
        case "not_running": return .stopped
        case "unavailable": return .unavailable
        default: return .unknown
        }
    }
}

// A request is only a local UI event, never evidence of an OS grant. Keep the
// history in this process so declining a prompt cannot cause a prompt loop,
// including if the product window is recreated. Nothing is persisted to Core.
@MainActor final class ProductPermissionActions {
    static let system = ProductPermissionActions(request: { screen in
        if screen { _ = CGRequestScreenCaptureAccess() }
        else { _ = AXIsProcessTrustedWithOptions(["AXTrustedCheckOptionPrompt": true] as CFDictionary) }
    }, openSettings: { screen in
        let value = screen ? "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture" : "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"
        if let url = URL(string: value) { NSWorkspace.shared.open(url) }
    })
    private var requested: Set<Bool> = []
    private let request: (Bool) -> Void
    private let openSettings: (Bool) -> Void

    init(request: @escaping (Bool) -> Void, openSettings: @escaping (Bool) -> Void) {
        self.request = request; self.openSettings = openSettings
    }
    func wasRequested(_ screen: Bool) -> Bool { requested.contains(screen) }
    func requestOnce(_ screen: Bool) {
        guard requested.insert(screen).inserted else { return }
        request(screen)
    }
    func open(_ screen: Bool) { openSettings(screen) }
}

// Keep only the unfinished UI step across the OS-owned Quit and Reopen action.
// Core still owns configuration/approval, and macOS still owns both grants.
struct ProductPermissionResume {
    let defaults: UserDefaults
    private let key: String
    init(profileScope: String, defaults: UserDefaults = .standard) {
        self.defaults = defaults
        key = "Styx.nativePermissionStep.v1." + profileScope
    }
    var pending: Bool { defaults.bool(forKey: key) }
    func begin() { defaults.set(true, forKey: key) }
    func complete() { defaults.removeObject(forKey: key) }
}

enum ProductWorkflowError: Error { case computerPermissionRecoveryRequired, roleChangeNeedsRestart }

@MainActor final class ProductModel: ObservableObject {
    let client: ProductCoreClient
    func nativeSupportsOperation(_ operation: String) -> Bool {
        status["supportedOperations"].array.contains { $0.string == operation }
    }
    func nativeClaim() { perform { [self] in _ = try await client.native("claimJoin") } }
    func nativeChangeRole() {
        guard nativeSupportsOperation("retireRole") else { return }
        let alert = NSAlert()
        alert.messageText = productText("更改这台电脑的角色…", "Change this computer's role…")
        alert.informativeText = productText("这台电脑将停止连接、备份现有设置并重新配对。", "This computer will disconnect, back up its current settings, and be paired again.")
        alert.addButton(withTitle: productText("继续", "Continue"))
        alert.addButton(withTitle: productText("取消", "Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        perform { [self] in
            let stopped = try await client.native("quitAdmission")
            guard stopped["quit"]["status"].string == "ready_to_quit" else { throw ProductCoreError.invalidResponse }
            let result: ProductJSON
            do { result = try await client.native("retireRole", ["allowOtherDevices": .bool(false)]) }
            catch let failure as ProductOwnedCoreRejection {
                if failure.response["error"].string == "app_cleanup_unknown" { throw ProductWorkflowError.roleChangeNeedsRestart }
                guard failure.response["error"].string == "role_retire_gateway_has_devices" else { throw failure }
                let devices = failure.response["retirement"]["otherDevices"].array
                guard !devices.isEmpty else { throw ProductCoreError.invalidResponse }
                let confirmation = NSAlert()
                confirmation.messageText = productText("断开这些设备的连接？", "Disconnect these devices too?")
                confirmation.informativeText = devices.map { ($0["label"].string ?? "") + " (" + ($0["deviceId"].string ?? "") + ")" }.joined(separator: "\n")
                confirmation.addButton(withTitle: productText("同时断开这些设备", "Disconnect these devices too"))
                confirmation.addButton(withTitle: productText("取消", "Cancel"))
                guard confirmation.runModal() == .alertFirstButtonReturn else { return }
                result = try await client.native("retireRole", ["allowOtherDevices": .bool(true)])
            }
            guard result["retirement"]["restartRequired"] == .bool(false) else { throw ProductCoreError.invalidResponse }
            try applyNative(result)
            nativeLocalSetupSubmitted = false
            inspection = .null; joinAcceptance = .null; joining = false
            permissionResume?.complete()
            page = .welcome
        }
    }

    #if STYX_TESTING
    var testSuppressObservations = false
    var testObservationLoopStarts = 0
    var testObservationConsumerCount: Int { observationConsumers.count }
    var testObservationLoopRunning: Bool { observationTask != nil }
    #endif
    @Published var page: ProductPage = .welcome {
        didSet {
            if page == .permissions { permissionResume?.begin() }
            if page != oldValue { ProductNativeDiagnostics.event("page " + String(describing: page)) }
        }
    }
    @Published var busy = false
    @Published var loaded = false
    @Published var loadingMessage = productText("正在连接本机 Styx…", "Connecting to Styx on this Mac…")
    @Published var error: String?
    @Published var observationError: String?
    @Published var status: ProductJSON = .null
    @Published var plugin: ProductJSON = .null
    @Published var tunnel: ProductJSON = .null
    @Published var devices: [ProductDevice] = []
    @Published var exec = true
    @Published var computer = false
    @Published var browser = false
    @Published var label = ""
    @Published var allowRemoteHosts = false
    @Published var lanAddress = ""
    @Published var networkInterfaces: ProductJSON = .null
    @Published var networkDiscoveryLoading = false
    @Published var networkDiscoveryError: String?
    func discoverNetworkInterfaces() {
        guard nativeSupportsOperation("networkInterfaces"), !networkDiscoveryLoading else { return }
        networkDiscoveryLoading = true; networkDiscoveryError = nil
        Task { [self] in
            defer { networkDiscoveryLoading = false }
            do {
                let value = try await client.native("networkInterfaces")
                networkInterfaces = value
                if lanAddress.isEmpty { lanAddress = value["recommendedAddress"].string ?? "" }
                if value["interfaces"].array.isEmpty {
                    networkDiscoveryError = productText("未发现可用的局域网或 VPN 网络。连接网络后重新检测，或暂时关闭其他电脑加入。", "No available LAN or VPN network was found. Connect a network and detect again, or turn off joining for now.")
                }
            } catch {
                networkDiscoveryError = productText("暂时无法读取这台电脑的网络接口。请重新检测。", "This computer’s network interfaces could not be read. Detect again.")
            }
        }
    }

    @Published var invite = ""
    @Published var inspection: ProductJSON = .null
    @Published var joinAcceptance: ProductJSON = .null
    @Published var joining = false
    // UI duplicate-submit guard only. Core remains the durable setup authority.
    @Published private(set) var nativeLocalSetupSubmitted = false
    // Native Mac setup: Browser uses the system Google Chrome; Computer Use needs the
    // owner's Accessibility and Screen Recording grants (Permissions page).
    var nativeBrowserChoice: [String: ProductJSON] {
        browser ? ["browser": .bool(true), "browserChannel": .string("chrome")] : ["browser": .bool(false), "browserChannel": .null]
    }
    /// With Computer Use chosen, ask for the two macOS grants before the overview.
    var afterSetupPage: ProductPage {
        computer && !(axGranted && screenGranted) ? .permissions : .overview
    }
    var nativeLanJoinNotice: String? {
        guard status["gateway"]["lan"]["enabled"].bool,
              let origin = status["gateway"]["lan"]["origin"].string else { return nil }
        return productText("其他电脑加入地址：\(origin)\n选择“添加电脑”来创建邀请。", "Address for other computers to join: \(origin)\nChoose Add computer to create an invitation.")
    }
    var nativeCanCreateLocal: Bool {
        !nativeLocalSetupSubmitted && status["admission_fenced"] == .bool(false)
        && status["configuration"] == .null && status["enrollment"] == .null && status["gateway"] == .null
        && status["supportedOperations"].array.contains { $0.string == "createLocal" }
    }
    var nativeCanResumeLocal: Bool {
        !nativeLocalSetupSubmitted
        && status["enrollment"]["status"].string == "local_setup_pre_invite"
        && status["enrollment"]["can_resume_local"] == .bool(true)
        && status["supportedOperations"].array.contains { $0.string == "resumeLocal" }
    }
    var setupTunnelInput: ProductJSON? {
        guard ProductTunnelInputPolicy.tunnelError(setupTunnelID) == nil,
              ProductTunnelInputPolicy.keyError(setupTunnelKey, saved: false) == nil else { return nil }
        return .object(["tunnelId": .string(setupTunnelID.trimmingCharacters(in: .whitespacesAndNewlines)),
                        "apiKey": .string(setupTunnelKey)])
    }
    @Published var setupTunnelID = ""
    @Published var setupTunnelKey = ""
    func resumeLocalSetup() {
        guard nativeCanResumeLocal, !busy else { return }
        let name = label.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty, let origin = status["gateway"]["origin"].string,
              let port = URLComponents(string: origin)?.port else { return }
        perform { [self] in
            guard nativeCanResumeLocal, let tunnel = setupTunnelInput else { throw ProductCoreError.rejected }
            nativeLocalSetupSubmitted = true
            // Explicit confirmation only; a failed or lost response is never replayed.
            var choice: [String: ProductJSON] = ["label": .string(name), "exec": .bool(exec), "computer": .bool(computer), "persistLogin": .bool(false), "port": .number(Double(port))]
            choice.merge(nativeBrowserChoice) { _, chosen in chosen }
            choice["tunnel"] = tunnel; setupTunnelKey = ""
            do {
                try applyNative(try await client.native("resumeLocal", choice))
                page = afterSetupPage
            } catch {
                self.error = productText("继续设置的结果尚未确认。原有设置已保留，请刷新检查；不会自动重试配对。", "The continuation result is unconfirmed. Your settings are retained. Refresh to review; pairing will not retry automatically.")
            }
        }
    }
    @Published var tunnelID = ""
    @Published var pluginIdentity = "styx"
    @Published var pluginLongDescription = ""
    @Published var pluginName = "Styx"
    @Published var pluginDescription = productText("连接你的电脑", "Connect your computers")
    @Published var pluginIcon: ProductJSON = .null
    @Published var pluginDraftEdited = false
    @Published var exportedPluginURL: URL?
    @Published var exportCompletionID: UUID?
    @Published var axGranted = false
    @Published var screenGranted = false
    @Published var createdInvitation: ProductJSON = .null
    @Published var invitationError: String?
    @Published var tunnelObservationStale = false
    @Published var tunnelAttempt: ProductTunnelAttempt = .idle
    private var tunnelMonitor: Task<Void, Never>?
    @Published var settingsSection: ProductSettingsSection = .general
    @Published var settingsNavigationID = UUID()
    @Published var settingsVisible = false
    @Published var onboardingVisible = false
    @Published var invitationCopied = false
    @Published var invitationInFlight = false
    var observationInFlight = false
    var mutationRevision = 0
    private var observationTask: Task<Void, Never>?
    private var observationConsumers: Set<UUID> = []
    func requestSettings(_ section: ProductSettingsSection) {
        settingsSection = section
        settingsNavigationID = UUID()
    }
    func publish<Value: Equatable>(_ keyPath: ReferenceWritableKeyPath<ProductModel, Value>, _ value: Value) {
        if self[keyPath: keyPath] != value { self[keyPath: keyPath] = value }
    }
    // All visible surfaces share one polling task. Closing the last surface
    // cancels it; a reconnect monitor temporarily owns the faster snapshot reads.
    func observePresentation() async {
        let id = UUID(); observationConsumers.insert(id)
        if observationTask == nil {
            #if STYX_TESTING
            testObservationLoopStarts += 1
            #endif
            observationTask = Task { [weak self] in
                while !Task.isCancelled {
                    guard let self = self else { return }
                    await self.bootstrap()
                    await self.refresh()
                    do { try await Task.sleep(nanoseconds: 3_000_000_000) } catch { return }
                }
            }
        }
        defer {
            observationConsumers.remove(id)
            if observationConsumers.isEmpty { observationTask?.cancel(); observationTask = nil }
        }
        while !Task.isCancelled {
            do { try await Task.sleep(nanoseconds: 60_000_000_000) } catch { return }
        }
    }
    @Published var menuVisible = false
    @Published var invitationExpanded = false
    @Published var loginStartup = "unknown"
    @Published var loginOperation = "observed"
    var loginEnabled: Bool { ["enabled", "requires_approval"].contains(loginStartup) }
    var loginPreferenceKnown: Bool { ["enabled", "disabled", "not_installed", "not_registered", "requires_approval"].contains(loginStartup) }
    var loginChangeAllowed: Bool { loginPreferenceKnown && !["pending", "unknown"].contains(loginOperation) && client.nativeLoginChangeAllowed }
    var loginNotice: String? {
        if loginOperation == "unknown" {
            return productText("上次更改的结果未确认，Styx 不会重复执行。可在系统设置中核对，或退出后重新打开以读取系统状态。", "The last change is unconfirmed and will not be repeated. Check System Settings, or quit and reopen Styx to read the system state.")
        }
        switch loginStartup {
        case "requires_approval": return productText("已登记登录启动，仍需在系统设置中允许。", "Login startup is registered and needs approval in System Settings.")
        case "foreign": return productText("已有登录启动项需要核对；Styx 保留了该启动项。", "An existing login entry needs review. Styx has preserved it.")
        case "not_found": return productText("无法确认已安装的 Styx App，登录启动未更改。", "The installed Styx app could not be confirmed. Login startup was not changed.")
        case "unknown": return productText("暂时无法读取登录启动状态。", "Login startup could not be observed.")
        default: return nil
        }
    }
    private var copiedCredential: String?
    private var copiedCredentialChangeCount: Int?
    private var restoredPage = false
    private let permissionReader: () -> (accessibility: Bool, screenRecording: Bool)
    private let permissionActions: ProductPermissionActions
    private let permissionResume: ProductPermissionResume?
    var recoverComputerUse: (() async throws -> Void)?

    var computerApproved: Bool { status["desktop_intent"]["computer_requested"].bool }
    var connectionTunnelID: String { plugin["connection"]["tunnelId"].string ?? tunnelID }
    var tunnelConnection: ProductTunnelConnection { tunnelObservationStale ? .unknown : ProductTunnelConnection.observed(tunnel) }
    init(owned: ProductOwnedCore) {
        client = ProductCoreClient(owned: owned)
        permissionResume = ProductPermissionResume(profileScope: owned.uiPreferenceScope)
        permissionReader = { (AXIsProcessTrusted(), CGPreflightScreenCaptureAccess()) }
        permissionActions = .system
        exec = true; computer = false; browser = false; joining = false
    }
    func applyNative(_ value: ProductJSON) throws {
        guard value["mode"].string == "rust_host" else { throw ProductCoreError.invalidResponse }
        publish(\.status, value)
        if !restoredPage {
            restoredPage = true
            observePermissions()
            let unconfigured = value["configuration"] == .null && value["enrollment"] == .null && value["gateway"] == .null && value["admission_fenced"] == .bool(false)
            if unconfigured {
                permissionResume?.complete()
                page = .welcome
            } else if permissionResume?.pending == true || value["desktop_intent"]["computer_requested"].bool && !(axGranted && screenGranted) {
                // A grant observed after relaunch does not complete the user's
                // explicit Continue/recovery step or repeat setup/pairing.
                page = .permissions
            } else { page = .overview }
        }
    }
    #if STYX_TESTING
    init(testRequest: @escaping (String, [String: ProductJSON]) async throws -> ProductJSON,
         permissionReader: @escaping () -> (accessibility: Bool, screenRecording: Bool) = { (false, false) },
         permissionActions: ProductPermissionActions? = nil, permissionResume: ProductPermissionResume? = nil) {
        client = ProductCoreClient(testRequest: testRequest)
        self.permissionReader = permissionReader
        self.permissionActions = permissionActions ?? ProductPermissionActions(request: { _ in }, openSettings: { _ in })
        self.permissionResume = permissionResume
    }

    #endif
    func bootstrap() async {
        #if STYX_TESTING
        if testSuppressObservations { return }
        #endif
        observePermissions()
        guard !loaded && !busy else { return }
        busy = true
        defer { busy = false }
        do {
            try applyNative(try await client.native("startupStatus"))
            await refreshNativeLogin()
            label = Host.current().localizedName ?? "Mac"
            loaded = true
        } catch { reportFailure(error) }
    }
    func refresh() async {
        observePermissions()
        #if STYX_TESTING
        if testSuppressObservations { return }
        #endif
        guard !busy, !observationInFlight else { return }
        observationInFlight = true; defer { observationInFlight = false }
        let revision = mutationRevision
        do {
            try await reload()
            if revision == mutationRevision { publish(\.observationError, nil) }
        } catch {
            if revision == mutationRevision && !Task.isCancelled {
                publish(\.observationError, productText("暂时无法刷新连接状态。可以继续编辑，稍后重试。", "Connection status could not refresh. You can keep editing and retry."))
            }
        }
    }
    private func reload() async throws {
        try applyNative(try await client.native("status"))
        if nativeSupportsOperation("computers") {
            publish(\.devices, try await client.native("computers")["devices"].array.compactMap(ProductDevice.init))
            publish(\.tunnel, try await client.native("tunnelStatus"))
            publish(\.tunnelObservationStale, false)
            publish(\.tunnelID, tunnel["tunnelId"].string ?? "")
        }
        await refreshNativeLogin()
    }
    private func refreshNativeLogin() async {
        guard status["supportedOperations"].array.contains(where: { $0.string == "appLifecycle" }) else {
            publish(\.loginStartup, "unknown"); return
        }
        do {
            let result = try await client.lifecycle()
            let lifecycle = result["lifecycle"]
            guard lifecycle["schema"] == .number(1), lifecycle["platform"].string == "macos",
                  let observed = lifecycle["status"].string,
                  ["enabled", "disabled", "not_registered", "requires_approval", "not_found", "registered_unverified", "foreign", "unknown"].contains(observed),
                  let operation = result["login"]["status"].string,
                  ["pending", "unknown", "observed"].contains(operation) else { throw ProductCoreError.invalidResponse }
            publish(\.loginStartup, observed); publish(\.loginOperation, operation)
        } catch { publish(\.loginStartup, "unknown") }
    }
    func openLoginSettings() { ProductLoginStartup.openSettings() }
    private func reportFailure(_ failure: Error? = nil) {
        ProductNativeDiagnostics.event("operation_failed page=" + String(describing: page))
        if let rejected = failure as? ProductOwnedCoreRejection,
           rejected.response["retryable"] == .bool(true), rejected.response["uncertain"] == .bool(false) {
            error = productText("配对请求尚未发送。请检查这台 Mac 的“系统设置 → 隐私与安全性 → 本地网络”是否允许 Styx，并确认两台电脑网络可达、网关允许传入连接。处理后粘贴新邀请，再核对并提交；不会自动重试。", "The pairing request was not sent. Check Styx in this Mac’s System Settings → Privacy & Security → Local Network, network access between the computers, and incoming connections on the hub. Then paste a new invitation, review it and submit again. Styx will not retry automatically.")
            return
        }
        if let core = failure as? ProductCoreError, case .loginChangeUnconfirmed = core {
            loginOperation = "unknown"
            error = productText("登录启动更改的结果未确认，Styx 不会重复执行。请在系统设置中核对当前状态。", "The login startup change is unconfirmed and will not be repeated. Check its current state in System Settings.")
            return
        }
        // Never interpolate raw transport errors, response bodies or secrets.
        switch failure as? ProductWorkflowError {
        case .roleChangeNeedsRestart:
            error = productText("这台电脑已停止连接，但网关尚未确认清理。请退出并重新打开 Styx，再更改角色并配对；不会重复重置设置。", "This computer has stopped, but the Gateway did not confirm cleanup. Quit and reopen Styx, then change its role to pair again. No settings reset was repeated.")
        case .computerPermissionRecoveryRequired:
            error = productText("还无法操作电脑。请检查 Styx 的辅助功能和屏幕录制权限；若刚开启权限，请退出并重新打开 Styx。", "Computer interaction is not available. Check Styx Accessibility and Screen Recording permissions. If you just enabled them, quit and reopen Styx.")
        default:
            error = productText("操作未完成。请检查当前状态后重试；结果未确认的操作不会自动重复。", "The operation did not finish. Check the current state before retrying; unconfirmed operations are not repeated automatically.")
        }
    }
    private func waitForObservation() async throws {
        while observationInFlight { try await Task.sleep(nanoseconds: 20_000_000) }
    }
    func perform(_ operation: @escaping () async throws -> Void) {
        guard !busy else { return }
        mutationRevision += 1
        busy = true; error = nil
        Task {
            do { try await waitForObservation(); try await operation(); try await reload() }
            catch { reportFailure(error); try? await reload() }
            busy = false
        }
    }

    func createAndPrepare() {
        guard !busy else { return }
        let name = label.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !name.isEmpty else { return }
        let joinExisting = joining
        if !joinExisting && !nativeCanCreateLocal { page = .overview; return }
        perform { [self] in
            // Selecting Computer Use never grants desktop permission or invents
            // readiness; the Permissions page asks the owner for both grants.
            var choice: [String: ProductJSON] = ["label": .string(name), "exec": .bool(exec), "computer": .bool(computer), "persistLogin": .bool(false)]
            choice.merge(nativeBrowserChoice) { _, chosen in chosen }
            if joinExisting {
                guard let origin = joinAcceptance["origin"].string,
                      let ca = joinAcceptance["caSha256"].string else { throw ProductCoreError.rejected }
                choice["approvedGatewayOrigin"] = .string(origin)
                choice["approvedCaSha256"] = .string(ca)
                let report = try await client.native("join", choice)
                joinAcceptance = .null; inspection = .null
                // An unfinished or rejected original request belongs in Settings.
                // Selecting Computer Use alone does not admit permission recovery.
                page = report["status"].string == "ready_to_connect" ? afterSetupPage : .overview
            } else {
                guard nativeCanCreateLocal, let tunnel = setupTunnelInput else { throw ProductCoreError.rejected }
                choice["tunnel"] = tunnel; setupTunnelKey = ""
                choice["allowRemoteHosts"] = .bool(allowRemoteHosts)
                if allowRemoteHosts && !lanAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { choice["lanAddress"] = .string(lanAddress.trimmingCharacters(in: .whitespacesAndNewlines)) }
                nativeLocalSetupSubmitted = true
                defer { if nativeLocalSetupSubmitted { page = afterSetupPage } }
                // One request; omitted port uses Core's fixed default 22022.
                // perform refreshes status after failure, never this mutation.
                do { try applyNative(try await client.native("createLocal", choice)) }
                catch {
                    if let failure = error as? ProductOwnedCoreRejection,
                       ["app_lan_address_invalid", "app_network_interface_changed", "app_network_interface_required", "app_network_interfaces_unavailable", "tunnel_client_unavailable"].contains(failure.response["error"].string ?? "") {
                        // Core refused before publishing any setup input.
                        nativeLocalSetupSubmitted = false
                        if failure.response["error"].string == "tunnel_client_unavailable" {
                            self.error = productText("请使用包含 Tunnel 客户端的 Gateway 安装包。", "Use a Gateway package that includes the Tunnel client.")
                            return
                        }
                        self.error = productText("请选择可用的局域网或 VPN 网络。若网络已变化，请重新检测；设置尚未提交。", "Select an available LAN or VPN network. If the network changed, detect networks again. Setup was not submitted.")
                        return
                    }
                    self.error = productText("上次设置结果尚未确认，请刷新状态查看；原配置已保留。", "The last setup result is unconfirmed. Refresh status to review it; your existing settings have been retained.")
                    return
                }
            }
        }; return
    }
    func observePermissions() {
        let observation = permissionReader()
        publish(\.axGranted, observation.accessibility); publish(\.screenGranted, observation.screenRecording)
    }
    func verifyPermissionsAndRecover() async throws {
        observePermissions()
        guard axGranted && screenGranted, let recover = recoverComputerUse else {
            throw ProductWorkflowError.computerPermissionRecoveryRequired
        }
        try await recover()
        observePermissions()
        guard axGranted && screenGranted else { throw ProductWorkflowError.computerPermissionRecoveryRequired }
        permissionResume?.complete()
    }
    func continueAfterPermissions() {
        perform { [self] in
            try await verifyPermissionsAndRecover()
            page = .overview
        }
    }
    func permissionWasRequested(_ screen: Bool) -> Bool { permissionActions.wasRequested(screen) }
    func requestPermission(_ screen: Bool) {
        observePermissions()
        guard !(screen ? screenGranted : axGranted) else { return }
        permissionResume?.begin()
        // Only the matching explicit action requests permission. macOS owns
        // this prompt and any navigation from its Open System Settings button.
        permissionActions.requestOnce(screen)
        observePermissions()
    }
    func openPermission(_ screen: Bool) {
        observePermissions()
        if !(screen ? screenGranted : axGranted) { permissionResume?.begin() }
        permissionActions.open(screen)
    }
    func cancelInvitationReview() {
        invite = ""; inspection = .null; joinAcceptance = .null
        page = nativeCanCreateLocal ? .welcome : .overview
    }
    func inspectInvitation() {
        let input = invite; invite = ""; inspection = .null; joinAcceptance = .null
        perform { [self] in inspection = try await client.native("inspectJoin", ["link": .string(input)]) }
    }
    func acceptInvitation() {
        guard inspection["preview"]["origin"].string != nil, inspection["preview"]["caSha256"].string != nil else { error = productText("需要核对证书", "Certificate confirmation required"); return }
        joinAcceptance = inspection["preview"]; joining = true; page = .capabilities; return
    }
    func saveTunnel(id: String, newKey: String?) async throws {
        guard !busy else { throw ProductCoreError.unavailable }
        let normalized = id.trimmingCharacters(in: .whitespacesAndNewlines)
        guard ProductTunnelInputPolicy.tunnelError(normalized) == nil,
              ProductTunnelInputPolicy.keyError(newKey ?? "", saved: hasSavedRuntimeKey) == nil else {
            throw ProductCoreError.rejected
        }
        tunnelMonitor?.cancel(); tunnelObservationStale = true; tunnelAttempt = .connecting
        mutationRevision += 1
        busy = true; error = nil
        defer { busy = false }
        try await waitForObservation()

        var payload: [String: ProductJSON] = ["authorize": .bool(true), "tunnelId": .string(normalized)]
        if let newKey = newKey { payload["apiKey"] = .string(newKey) }
        _ = try await client.native("tunnelSave", payload)
        tunnelID = normalized
        try await reload(); monitorTunnel(); return
    }
    @discardableResult func monitorTunnel(check: (() async -> Void)? = nil, pause: (() async throws -> Void)? = nil) -> Task<Void, Never> {
        tunnelMonitor?.cancel()
        tunnelMonitor = Task { [weak self] in
            for _ in 0..<20 {
                guard !Task.isCancelled, let self = self else { return }
                if let check = check { await check() } else { await self.refresh() }
                guard !Task.isCancelled else { return }
                if self.tunnelConnection == .connected { self.tunnelAttempt = .idle; return }
                do { if let pause = pause { try await pause() } else { try await Task.sleep(nanoseconds: 1_000_000_000) } } catch { return }
            }
            guard !Task.isCancelled else { return }
            self?.tunnelAttempt = .timedOut
        }
        return tunnelMonitor!
    }
    func selectIcon() {
        let panel = NSOpenPanel(); panel.allowedContentTypes = [.png]; panel.allowsMultipleSelection = false; panel.canChooseDirectories = false
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let valid = try pluginIconFile(url), bytes = try Data(contentsOf: valid)
            guard bytes.count <= 256 * 1024 else { throw ProductCoreError.rejected }
            pluginIcon = .object(["mimeType": .string("image/png"), "dataBase64": .string(bytes.base64EncodedString())]); pluginDraftEdited = true
        } catch { self.error = productText("请选择不超过 256 KB 的方形 PNG 图片（48–1024 像素）。", "Choose a square PNG, 48–1024 pixels and no larger than 256 KB.") }
    }
    func clearSecrets() {
        setupTunnelKey = ""; invite = ""
        createdInvitation = .null; invitationCopied = false
        if let copied = copiedCredential, copiedCredentialChangeCount == NSPasteboard.general.changeCount,
           NSPasteboard.general.string(forType: .string) == copied { NSPasteboard.general.clearContents() }
        copiedCredential = nil; copiedCredentialChangeCount = nil
    }
    func copy(_ value: String, secret: Bool = false) {
        guard !value.isEmpty else { return }
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(value, forType: .string)
        if secret { copiedCredential = value; copiedCredentialChangeCount = NSPasteboard.general.changeCount }
    }
    func revokeDevice(_ device: ProductDevice) {
        let alert = NSAlert()
        alert.messageText = productText("撤销这台电脑的访问？", "Revoke this computer's access?")
        alert.informativeText = device.label + "\n" + productText("该电脑将无法继续访问，需要新的邀请才能加入。", "This computer will lose access and need a new invitation to join again.")
        alert.addButton(withTitle: productText("撤销访问", "Revoke access"))
        alert.addButton(withTitle: productText("取消", "Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        perform { [self] in
            _ = try await client.native("revokeComputer", ["authorize": .bool(true), "deviceId": .string(device.id)])
        }
    }
    func setLoginEnabled(_ enabled: Bool) {
        perform { [self] in _ = try await client.changeLogin(["authorize": .bool(true), "enabled": .bool(enabled)]) }
    }
    func setHostCapability(_ name: String, enabled: Bool) {
        perform { [self] in
            let result = try await client.native("hostCapabilities", [name: .bool(enabled)])
            guard result["applied"].bool else { throw ProductCoreError.rejected }
        }
    }
    func resumeForeground() {
        guard nativeSupportsOperation("connect") else { return }
        perform { [self] in _ = try await client.native("connect") }
    }
    func openOfficial(_ value: String) {
        guard let url = URL(string: value), let c = URLComponents(url: url, resolvingAgainstBaseURL: false), c.user == nil, c.password == nil else { return }
        let official = c.scheme == "https" && ["platform.openai.com", "chatgpt.com", "developers.openai.com"].contains(c.host ?? "") && c.port == nil
        let system = c.scheme == "x-apple.systempreferences" && ["com.apple.preference.security", "com.apple.Localization-Settings.extension"].contains(c.path)
        guard official || system else { return }
        NSWorkspace.shared.open(url)
    }
}
