import AppKit
import ApplicationServices
import SwiftUI
import UniformTypeIdentifiers

func productText(_ chinese: String, _ english: String) -> String {
    (Locale.preferredLanguages.first ?? "en").hasPrefix("zh") ? chinese : english
}

enum ProductPage: String, CaseIterable { case welcome, invitation, capabilities, preparation, permissions, chat, overview, computers, settings }
enum ProductTunnelConnection: Equatable {
    case notConfigured, connected, connecting, stopped, unavailable, unknown
    static func observed(_ tunnel: ProductJSON) -> Self {
        if tunnel["status"].string == "not_configured" { return .notConfigured }
        switch tunnel["transport"].string {
        case "ready": return tunnel["status"].string == "running" ? .connected : .unknown
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

enum ProductPreparationPhase: String { case components, connection, browser }
struct ProductPreparationStage: Identifiable {
    enum State: Equatable { case pending, working, completed, blocked, awaitingApproval, needsReview, notApproved }
    let id: ProductPreparationPhase
    let state: State
    var title: String {
        switch id {
        case .components: return productText("安装组件", "Install components")
        case .connection: return productText("连接本机", "Connect this computer")
        case .browser: return productText("准备 Browser", "Prepare Browser")
        }
    }
}
enum ProductPreparationPolicy {
    static func stages(_ deployment: ProductDeployment?, browser: ProductJSON, foreground: ProductJSON = .null, nativeStartup: ProductJSON = .null, activity: ProductPreparationPhase?) -> [ProductPreparationStage] {
        guard let deployment = deployment else { return [] }
        func state(_ ids: Set<String>, phase: ProductPreparationPhase) -> ProductPreparationStage.State {
            let steps = deployment.steps.filter { ids.contains($0.id) }
            if steps.contains(where: { ["uncertain", "failed"].contains($0.status) }) { return .needsReview }
            if activity == phase && steps.contains(where: { $0.retryable }) { return .working }
            if steps.contains(where: { $0.status == "blocked" }) { return .blocked }
            if steps.contains(where: { $0.status == "awaiting_approval" }) { return .awaitingApproval }
            if !steps.isEmpty && steps.allSatisfy(\.complete) { return .completed }
            return activity == phase || steps.contains(where: { $0.status == "running" }) ? .working : .pending
        }
        var connection = state(["host.invite", "host.pair", "host.request", "host.claim", "host.doctor"], phase: .connection)
        if connection == .completed && foreground != .null {
            switch foreground["status"].string {
            case "needs_attention": connection = .needsReview
            case "started", "stopping": connection = .working
            case "connected", "using_service": break
            default: connection = activity == .connection ? .working : .pending
            }
        }
        if nativeStartup["status"].string == "reconciliation_required" { connection = .needsReview }
        var result = [ProductPreparationStage(id: .components, state: state(["gateway.runtime.prepare", "gateway.prepare", "gateway.start", "gateway.verify", "host.prepare"], phase: .components)),
                      ProductPreparationStage(id: .connection, state: connection)]
        if deployment.browserRequested {
            let browserState: ProductPreparationStage.State
            switch browser["status"].string {
            case "prepared": browserState = browser["approved"] == .bool(true) ? .completed : .needsReview
            case "not_approved": browserState = browser["approved"] == .bool(false) ? .notApproved : .needsReview
            case "preparation_blocked": browserState = .needsReview
            default: browserState = activity == .browser ? .working : .pending
            }
            result.append(ProductPreparationStage(id: .browser, state: browserState))
        }
        return result
    }
    static func retryableCommandCheck(_ deployment: ProductDeployment?) -> ProductStep? {
        guard let next = deployment?.steps.first(where: { !$0.complete }), next.retryable else { return nil }
        return next
    }
    static func blockingStep(_ deployment: ProductDeployment?) -> ProductStep? {
        deployment?.steps.first { !$0.id.hasPrefix("host.service.") && ["blocked", "uncertain", "failed", "awaiting_approval"].contains($0.status) }
    }
    static func canCheckOwnerApproval(_ deployment: ProductDeployment?) -> Bool {
        guard deployment?.joined == true, let next = deployment?.steps.first(where: { !$0.complete }) else { return false }
        return next.id == "host.claim" && ["blocked", "awaiting_approval"].contains(next.status)
    }
    static func commandCheckMessage(_ step: ProductStep) -> String {
        if step.blockers.contains("codex_executor_unavailable") {
            return productText("命令组件暂未能启动。请再次检查。", "The command component could not start. Check again.")
        }
        if step.blockers.contains("host_credential_unavailable") {
            return productText("电脑连接凭据暂不可用。请重新检查现有配置；不要删除身份或重新配对。", "The computer's connection credential is unavailable. Recheck the existing configuration; preserve its identity and pairing.")
        }
        if step.blockers.contains("signed_install_unavailable") || step.blockers.contains("signed_computer_runtime_unavailable") {
            return productText("尚未能确认已安装组件的完整性。请重新检查；仍有问题时需要检查安装记录。", "Installed components could not be verified. Check again; if it persists, review the installation record.")
        }
        if step.blockers.contains("invalid_host_configuration") || step.blockers.contains("macos_requires_embedded_cua_socket") {
            return productText("电脑组件配置尚未通过检查。请重新检查现有设置；无需重新配对。", "The computer's component configuration has not passed its check. Recheck the existing settings; pairing does not need to be repeated.")
        }
        return productText("命令组件检查尚未通过。请重新检查；已有的安装和配对会保留。", "The command component check did not pass. Check again; existing installation and pairing will be preserved.")
    }
}

enum ProductBrowserPreparation: Equatable { case notRequired, prepare, needsReview }
enum ProductForegroundTransition: Equatable { case stopped, owned, needsReview }
enum ProductWorkflowError: Error { case browserPreparationNeedsReview, capabilityNeedsOfflineReview, foregroundStopUnconfirmed, capabilityChangeInterrupted, foregroundRecoveryRequired, computerPermissionRecoveryRequired }

// Desired selection does not grant a capability. These decisions use Core's
// current approved Host projection and refuse absent or uncertain observations.
enum ProductCapabilityPolicy {
    static func browserPreparation(requested: Bool, observation: ProductJSON) -> ProductBrowserPreparation {
        guard requested else { return .notRequired }
        switch observation["status"].string {
        case "not_approved": return observation["approved"] == .bool(false) ? .notRequired : .needsReview
        case "prepared": return observation["approved"] == .bool(true) ? .notRequired : .needsReview
        case "not_prepared": return observation["approved"] == .bool(true) ? .prepare : .needsReview
        default: return .needsReview
        }
    }
    static func foregroundTransition(owner: ProductJSON, observed: ProductJSON) -> ProductForegroundTransition {
        guard owner["observation"].string == "current_process" else { return .needsReview }
        if owner["status"].string == "not_running", observed["status"].string == "not_running" { return .stopped }
        if owner["host"].string == "foreground", ["started", "connected"].contains(owner["status"].string ?? ""),
           ["started", "connected"].contains(observed["status"].string ?? "") { return .owned }
        return .needsReview
    }
    static func computerApproved(_ foreground: ProductJSON) -> Bool {
        foreground["computerRequested"] == .bool(true)
    }
}

enum ProductRestorationPolicy {
    static func page(deployment: ProductDeployment?, localPrepared: Bool, browser: ProductJSON, foreground: ProductJSON,
                     accepted: Bool, accessibility: Bool, screenRecording: Bool) -> ProductPage {
        guard let deployment = deployment else { return .welcome }
        guard localPrepared else { return .preparation }
        if deployment.browserRequested {
            guard ProductCapabilityPolicy.browserPreparation(requested: true, observation: browser) == .notRequired else { return .preparation }
        }
        guard ["current_process", "authenticated_foreground_owner"].contains(foreground["observation"].string ?? ""),
              ["started", "connected", "using_service"].contains(foreground["status"].string ?? ""),
              ["foreground", "service"].contains(foreground["host"].string ?? "") else { return .preparation }
        if ProductCapabilityPolicy.computerApproved(foreground) && (!accessibility || !screenRecording) { return .permissions }
        return accepted || deployment.joined ? .overview : .chat
    }
}

@MainActor final class ProductModel: ObservableObject {
    let client: ProductCoreClient
    #if STYX_TESTING
    var testSuppressObservations = false
    var testPreview = false
    var testObservationLoopStarts = 0
    var testObservationConsumerCount: Int { observationConsumers.count }
    var testObservationLoopRunning: Bool { observationTask != nil }
    #endif
    @Published var page: ProductPage = .welcome { didSet { if page != oldValue { ProductNativeDiagnostics.event("page " + String(describing: page)) } } }
    @Published var busy = false
    @Published var signingUpgrade: ProductJSON = .null
    @Published var signingUpgradeState: ProductJSON = .null
    @Published var loaded = false
    @Published var loadingMessage = productText("正在连接本机 Styx…", "Connecting to Styx on this Mac…")
    @Published var error: String?
    @Published var observationError: String?
    @Published var status: ProductJSON = .null
    @Published var journey: ProductJSON = .null
    @Published var acceptance: ProductJSON = .null
    @Published var session: ProductJSON = .null
    @Published var plugin: ProductJSON = .null
    @Published var browserObservation: ProductJSON = .null
    @Published var foregroundRecoveryNeeded = false
    @Published var preparationActivity: ProductPreparationPhase?
    @Published var devices: [ProductDevice] = []
    @Published var computer = true
    @Published var browser = true
    @Published var label = ""
    @Published var invite = ""
    @Published var inspection: ProductJSON = .null
    @Published var joinAcceptance: ProductJSON = .null
    @Published var joining = false
    @Published var tunnelID = ""
    @Published var runtimeKey = ""
    @Published var pluginMode = "create"
    @Published var pluginName = "Styx"
    @Published var pluginDescription = productText("连接你的电脑", "Connect your computers")
    @Published var accountLabel = ""
    @Published var pluginURL = ""
    @Published var pluginIcon: ProductJSON = .null
    @Published var pluginDraftEdited = false
    @Published var exportedPluginURL: URL?
    @Published var exportCompletionID: UUID?
    @Published var handoffCredential = ""
    @Published var handoffTarget = ""
    @Published var desktopValue = ""
    @Published var axGranted = false
    @Published var screenGranted = false
    @Published var ingress: ProductJSON = .null
    @Published var createdInvitation: ProductJSON = .null
    @Published var pending: [ProductJSON] = []
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
                    if self.tunnelAttempt != .connecting { await self.refreshMenu() }
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
    @Published var selectedDeviceID: String?
    @Published var menuVisible = false
    @Published var invitationExpanded = false
    @Published var menuObservationFailed = false
    @Published var selectedPending: ProductJSON = .null
    @Published var fingerprintConfirmation = ""
    @Published var approveComputer = false
    @Published var approveBrowser = false
    @Published var loginStartup = "unknown"
    var loginEnabled: Bool { loginStartup == "enabled" }
    var loginPreferenceKnown: Bool { ["enabled", "disabled", "not_installed"].contains(loginStartup) }
    private var handoffTimer: Timer?
    private var copiedCredential: String?
    private var copiedCredentialChangeCount: Int?
    private var restoredPage = false
    private let permissionReader: () -> (accessibility: Bool, screenRecording: Bool)
    private let permissionActions: ProductPermissionActions
    var recoverComputerUse: (() async throws -> Void)?

    var deployment: ProductDeployment? { ProductDeployment(status["deployment"]) }
    var localPrepared: Bool { journey["steps"].array.contains { $0["id"].string == "local_setup" && $0["status"].string == "completed" } }
    var joined: Bool { deployment?.joined ?? joining }
    var accepted: Bool { acceptance["complete"].bool }
    var browserNotApproved: Bool { browserObservation["status"].string == "not_approved" && browserObservation["approved"] == .bool(false) }
    var computerNotApproved: Bool { joined && deployment?.computerRequested == true && status["foreground"]["computerRequested"] == .bool(false) }
    var computerApproved: Bool { ProductCapabilityPolicy.computerApproved(status["foreground"]) }
    var preparationStages: [ProductPreparationStage] { ProductPreparationPolicy.stages(deployment, browser: browserObservation, foreground: status["foreground"], nativeStartup: status["nativeStartup"], activity: preparationActivity) }
    var signingUpgradeIncomplete: Bool { !signingUpgradeNeedsReview && (signingUpgradeState["status"].string == "required" || status["nativeStartup"]["reason"].string == "native_signing_registration_required") }
    var signingUpgradeNeedsReview: Bool { signingUpgradeState["status"].string == "needs_review" || status["nativeStartup"]["reason"].string == "native_signing_upgrade_requires_review" }
    var connectionReviewMessage: String {
        switch status["nativeStartup"]["reason"].string {
        case "existing_service_requires_review": return productText("检测到已有后台服务，但尚未确认可安全复用。请核对旧服务的安装与运行状态；Styx 不会自动停止或替换它。", "Existing background services could not be verified for safe reuse. Review their installation and running state; Styx will not stop or replace them automatically.")
        case "connection_owned_elsewhere": return productText("已有其他进程连接这台电脑。请先确认该连接的用途；Styx 不会重复连接或接管它。", "Another process already owns this computer's connection. Review that connection before continuing; Styx will not duplicate or take it over.")
        case "interrupted_operation_requires_review": return productText("上次操作尚未确认完成。请先核对执行记录，再恢复连接；不会自动重试安装或配对。", "A previous operation is unconfirmed. Review its record before resuming; installation and pairing are not replayed automatically.")
        default: return productText("本机连接未能恢复。可以重试连接；若仍失败，请保留现有设置并检查诊断记录。", "This computer's connection could not resume. Retry the connection; if it still fails, preserve your settings and inspect diagnostics.")
        }
    }
    var retryableCommandCheck: ProductStep? { ProductPreparationPolicy.retryableCommandCheck(deployment) }
    var preparationBlocker: ProductStep? { ProductPreparationPolicy.blockingStep(deployment) }
    var preparationConnectionNeedsReview: Bool {
        guard localPrepared else { return false }
        let observed = status["foreground"]["status"].string ?? "unknown"
        return ["needs_attention", "stopping"].contains(observed) || observed == "not_running" && status["nativeStartup"]["status"].string == "reconciliation_required"
    }
    var connectionTunnelID: String { plugin["connection"]["tunnelId"].string ?? (!tunnelID.isEmpty ? tunnelID : handoffTarget) }
    var tunnelConnection: ProductTunnelConnection { tunnelObservationStale ? .unknown : ProductTunnelConnection.observed(journey["tunnel"]) }
    var challengeID: String? { acceptance["challenge"]["id"].string }
    var targetProofReady: Bool {
        acceptance["requestProof"]["status"].string == "verified"
        && ["verified", "not_required"].contains(acceptance["desktop"]["status"].string ?? "")
        && ["verified", "not_required"].contains(acceptance["browser"]["status"].string ?? "")
    }
    init(sessionURL: URL, permissionReader: @escaping () -> (accessibility: Bool, screenRecording: Bool) = {
        (AXIsProcessTrusted(), CGPreflightScreenCaptureAccess())
    }, permissionActions: ProductPermissionActions? = nil) throws {
        client = try ProductCoreClient(sessionURL: sessionURL)
        self.permissionReader = permissionReader
        self.permissionActions = permissionActions ?? .system
    }

    func bootstrap() async {
        #if STYX_TESTING
        if testSuppressObservations { return }
        #endif
        observePermissions()
        guard !loaded && !busy else { return }
        busy = true
        defer { busy = false }
        do {
            loadingMessage = productText("正在连接本机 Styx…", "Connecting to Styx on this Mac…")
            session = try await client.read("session")
            label = session["defaults"]["label"].string ?? Host.current().localizedName ?? "Mac"
            try await reload()
            loaded = true
        } catch { reportFailure() }
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
    func reviewSigningUpgrade() {
        signingUpgrade = .null
        perform { [self] in signingUpgrade = try await client.write("native-signing/plan", [:])["upgrade"] }
    }
    func completeSigningUpgrade() {
        guard signingUpgrade["status"].string == "reviewable", let planID = signingUpgrade["planId"].string else { return }
        signingUpgrade = .null
        perform { [self] in
            _ = try await client.write("native-signing/apply", ["authorize": .bool(true), "planId": .string(planID)])
            restoredPage = false
        }
    }
    private func reload() async throws {
        // Native permission observation must not depend on a successful Core read.
        observePermissions()
        let revision = mutationRevision
        if !loaded { publish(\.loadingMessage, productText("正在核对连接状态…", "Checking current connections…")) }
        if session["nativeSigningUpgradeSupported"].bool {
            let upgrade = try await client.read("native-signing/status")["upgrade"]
            guard revision == mutationRevision, !Task.isCancelled else { return }
            publish(\.signingUpgradeState, upgrade)
        }
        let snapshot: ProductJSON
        do { snapshot = try await client.read("snapshot") }
        catch {
            if signingUpgradeNeedsReview { page = .preparation; loaded = true; return }
            throw error
        }
        guard revision == mutationRevision, !Task.isCancelled else { return }
        applySnapshot(snapshot)
    }
    func applySnapshot(_ snapshot: ProductJSON) {
        publish(\.status, snapshot["status"])
        publish(\.journey, snapshot["journey"]); publish(\.tunnelObservationStale, false)
        if deployment != nil {
            if localPrepared && deployment?.browserRequested == true {
                // A Browser observation failure does not hide Exec or the rest
                // of the App. Preparation takes a fresh authoritative reading.
                publish(\.browserObservation, snapshot["browser"])
            } else { publish(\.browserObservation, .null) }
            let latest = snapshot["acceptance"]
            if latest["challenge"]["id"] != acceptance["challenge"]["id"] { desktopValue = "" }
            publish(\.acceptance, latest)
            if !joined {
                publish(\.plugin, snapshot["plugin"])
                if !pluginDraftEdited {
                    publish(\.pluginMode, plugin["selection"]["mode"].string ?? "create")
                    publish(\.pluginName, plugin["presentation"]["displayName"].string ?? "Styx")
                    publish(\.pluginDescription, plugin["presentation"]["shortDescription"].string ?? productText("连接你的电脑", "Connect your computers"))
                    publish(\.accountLabel, plugin["selection"]["accountLabel"].string ?? "")
                    publish(\.pluginURL, plugin["selection"]["pluginUrl"].string ?? "")
                    publish(\.pluginIcon, plugin["presentation"]["icon"])
                }
            }
        }
        if session["nativeAppLifecycleSupported"].bool {
            // Startup observation is independent of setup readiness. A legacy
            // recovery definition or temporarily unavailable launchd must not
            // prevent opening the rest of the App to inspect and recover it.
            let observed = snapshot["lifecycle"]["loginAtStartup"].string ?? "unknown"
            publish(\.loginStartup, ["enabled", "disabled", "not_installed"].contains(observed) ? observed : "unknown")
        } else { publish(\.loginStartup, "unknown") }
        observePermissions()
        if !restoredPage {
            restoredPage = true
            if let deployment = deployment {
                computer = deployment.computerRequested; browser = deployment.browserRequested
                page = ProductRestorationPolicy.page(deployment: deployment, localPrepared: localPrepared,
                                                     browser: browserObservation, foreground: status["foreground"],
                                                     accepted: accepted, accessibility: axGranted, screenRecording: screenGranted)
            }
        }
    }
    private func reportFailure(_ failure: Error? = nil) {
        ProductNativeDiagnostics.event("operation_failed page=" + String(describing: page))
        // Never interpolate raw transport errors, response bodies or secrets.
        switch failure as? ProductWorkflowError {
        case .browserPreparationNeedsReview:
            error = productText("Browser 准备状态需要检查。请刷新状态，确认主台审批及浏览器准备记录后继续。", "Browser preparation needs review. Refresh and check owner approval and browser preparation before continuing.")
        case .capabilityNeedsOfflineReview:
            error = productText("更改 Browser 前，需要先停止并核对现有 Host 服务或其他管理入口的连接。Styx 不会替你停止这些组件；请完成对账后重试。", "Before changing Browser, stop and reconcile Host services or connections owned by another manager. Styx will not stop those components. Retry after reconciliation.")
        case .foregroundStopUnconfirmed:
            error = productText("本次连接是否停止尚未确认，能力尚未更改。请刷新并核对组件状态，避免重复操作。", "Connection shutdown is unconfirmed; capabilities have not been changed. Refresh and reconcile component state before trying again.")
        case .capabilityChangeInterrupted:
            error = productText("能力更改未能确认完成。请先检查组件状态并恢复事务，再选择恢复连接；不会自动重试更改。", "Capability changes could not be confirmed. Inspect component state and recover the transaction before resuming. Changes will not be replayed.")
        case .foregroundRecoveryRequired:
            error = productText("能力更改已完成，但连接恢复尚未确认。请刷新状态后选择“恢复本次连接”。", "Capabilities were updated, but connection recovery is unconfirmed. Refresh, then choose Resume this connection.")
        case .computerPermissionRecoveryRequired:
            error = productText("Computer Use 尚未恢复。请确认系统权限已开启；若刚修改权限，请退出并重新打开 Styx 后重试。", "Computer Use has not resumed. Confirm the system permissions; if you just changed them, quit and reopen Styx, then try again.")
        default:
            error = productText("操作未完成。请刷新状态后检查；结果不确定的操作不会自动重试。", "The operation did not complete. Refresh to inspect its state; uncertain operations are not replayed.")
        }
    }
    private func waitForObservation() async throws {
        while observationInFlight { try await Task.sleep(nanoseconds: 20_000_000) }
    }
    func perform(_ operation: @escaping () async throws -> Void) {
        #if STYX_TESTING
        if testPreview { error = "UI preview: no Core operation was performed."; return }
        #endif
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
        perform { [self] in
            let defaults = session["defaults"]
            var host = defaults.object.filter { ["bundle", "publisherKeyFile", "publisherSha256", "baseDir"].contains($0.key) }
            guard host.count == 4, !label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw ProductCoreError.unavailable }
            host["label"] = .string(label); host["computer"] = .bool(computer)
            host["browser"] = .object(["enabled": .bool(browser), "headless": .bool(false)])
            let gatewayURL = joining ? joinAcceptance["origin"].string : defaults["gatewayUrl"].string
            guard let gatewayURL = gatewayURL else { throw ProductCoreError.unavailable }
            var payload: [String: ProductJSON] = ["schema": .number(1), "mode": .string(joining ? "join-existing" : "create-local"), "gateway": .object(["url": .string(gatewayURL)]), "host": .object(host)]
            if joining {
                guard let id = joinAcceptance["joinLinkId"].string else { throw ProductCoreError.rejected }
                payload["joinLinkId"] = .string(id)
            }
            _ = try await client.write("create", payload)
            page = .preparation
            try await reload()
            try await prepare()
        }
    }
    private func prepare() async throws {
        defer { preparationActivity = nil }
        preparationActivity = retryableCommandCheck == nil ? .components : .connection
        if joined {
            // Retry only the claim/doctor checks that Core marks safely blocked.
            // Uncertain preparation/request mutations are never replayed.
            let safe: Set<String> = ["host.prepare", "host.request", "host.claim", "host.doctor"]
            let retryableChecks: Set<String> = ["host.claim", "host.doctor"]
            for _ in 0..<4 {
                guard let next = deployment?.steps.first(where: { $0.status != "succeeded" && $0.status != "skipped" }),
                      safe.contains(next.id),
                      ["pending", "awaiting_approval"].contains(next.status) ||
                        (next.status == "blocked" && retryableChecks.contains(next.id)) else { break }
                _ = try await client.write("advance", ["authorize": .array([.string(next.id)])])
                try await reload()
                guard deployment?.steps.first(where: { $0.id == next.id })?.status == "succeeded" else { break }
            }
        } else if !localPrepared {
            var scope = status["ownerPairingScope"].object
            guard !scope.isEmpty else { throw ProductCoreError.unavailable }
            scope["approve"] = .bool(true)
            _ = try await client.write("local-setup", ["ownerApproval": .object(scope)])
            try await reload()
        }
        guard localPrepared else { return }
        if deployment?.browserRequested == true {
            preparationActivity = .browser
            browserObservation = try await client.read("browser")["browser"]
            switch ProductCapabilityPolicy.browserPreparation(requested: true, observation: browserObservation) {
            case .prepare: browserObservation = try await client.write("browser/prepare", ["authorize": .bool(true)])["browser"]
            case .notRequired: break
            case .needsReview: throw ProductWorkflowError.browserPreparationNeedsReview
            }
        }
        preparationActivity = .connection
        let foreground = try await client.write("foreground", ["authorize": .bool(true)])["foreground"]
        foregroundRecoveryNeeded = false
        page = ProductCapabilityPolicy.computerApproved(foreground) ? .permissions : joined ? .overview : .chat
    }
    func continuePreparation() { perform { [self] in try await prepare() } }
    func recheckCommandComponent() {
        guard retryableCommandCheck != nil else { return }
        // Core admits only this explicit read-only blocked doctor retry. It
        // retains completed installation/pairing and refuses uncertain steps.
        perform { [self] in try await prepare() }
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
    }
    func continueAfterPermissions() {
        perform { [self] in
            try await verifyPermissionsAndRecover()
            page = joined ? .overview : .chat
        }
    }
    func permissionWasRequested(_ screen: Bool) -> Bool { permissionActions.wasRequested(screen) }
    func requestPermission(_ screen: Bool) {
        observePermissions()
        guard !(screen ? screenGranted : axGranted) else { return }
        // Only the matching explicit action requests permission. macOS owns
        // this prompt and any navigation from its Open System Settings button.
        permissionActions.requestOnce(screen)
        observePermissions()
    }
    func openPermission(_ screen: Bool) { permissionActions.open(screen) }
    func inspectInvitation() {
        let input = invite; invite = ""; inspection = .null; joinAcceptance = .null
        perform { [self] in inspection = try await client.write("pairing-link/inspect", ["link": .string(input)]) }
    }
    func acceptInvitation() {
        perform { [self] in
            let p = inspection["preview"]
            var payload: [String: ProductJSON] = ["inspectionId": inspection["inspectionId"], "approvedGatewayOrigin": p["origin"]]
            if p["caSha256"].string != nil { payload["approvedCaSha256"] = p["caSha256"] }
            joinAcceptance = try await client.write("pairing-link/accept", payload)
            inspection = .null; joining = true; page = .capabilities
        }
    }
    func configureTunnel() {
        let key = runtimeKey
        guard !busy else { return }
        Task {
            do { try await saveTunnel(id: tunnelID, newKey: key); runtimeKey = "" }
            catch { tunnelAttempt = .failed; reportFailure(error); try? await reload() }
        }
    }
    func saveTunnel(id: String, newKey: String?) async throws {
        #if STYX_TESTING
        if testPreview { throw ProductCoreError.unavailable }
        #endif
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
        // The Core keeps the stored key private. Omitting apiKey deliberately
        // retains it; the App never reads it back into a password field.
        if journey["tunnel"]["status"].string == "running" {
            _ = try await client.write("tunnel/stop", ["authorize": .bool(true)])
        }
        var payload: [String: ProductJSON] = ["authorize": .bool(true), "autoStart": .bool(true), "tunnelId": .string(normalized)]
        if let newKey = newKey { payload["apiKey"] = .string(newKey) }
        _ = try await client.write("tunnel/configure", payload)
        _ = try await client.write("tunnel/start", ["authorize": .bool(true)])
        tunnelID = normalized
        try await reload()
        monitorTunnel()
    }
    func startTunnel() {
        #if STYX_TESTING
        if testPreview { error = "UI preview: connection operations are disabled."; return }
        #endif
        guard !busy, tunnelAttempt != .connecting else { return }
        tunnelMonitor?.cancel(); tunnelObservationStale = true; tunnelAttempt = .connecting
        mutationRevision += 1
        busy = true; error = nil
        Task {
            do {
                try await waitForObservation()
                _ = try await client.write("tunnel/start", ["authorize": .bool(true)])
                busy = false; monitorTunnel()
            } catch { busy = false; tunnelAttempt = .failed; reportFailure(error) }
        }
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
    func revealHandoff() {
        clearSecrets()
        perform { [self] in
            let handoff = try await client.write("connection-handoff", ["authorize": .bool(true)])["handoff"]
            guard handoff["status"].string == "prepared", handoff["authentication"]["type"].string == "bearer",
                  let secret = handoff["authentication"]["modelCredential"].string,
                  let expiry = handoff["expiresAt"].number, expiry > Date().timeIntervalSince1970 * 1000 else { throw ProductCoreError.unavailable }
            handoffCredential = secret
            handoffTarget = handoff["connection"]["tunnelId"].string ?? handoff["connection"]["url"].string ?? ""
            handoffTimer = Timer.scheduledTimer(withTimeInterval: min(60, expiry / 1000 - Date().timeIntervalSince1970), repeats: false) { [weak self] _ in
                Task { @MainActor in self?.clearSecrets() }
            }
        }
    }
    func clearSecrets() {
        handoffTimer?.invalidate(); handoffTimer = nil
        handoffCredential = ""; handoffTarget = ""; runtimeKey = ""; invite = ""
        createdInvitation = .null; invitationCopied = false
        if let copied = copiedCredential, copiedCredentialChangeCount == NSPasteboard.general.changeCount,
           NSPasteboard.general.string(forType: .string) == copied { NSPasteboard.general.clearContents() }
        copiedCredential = nil; copiedCredentialChangeCount = nil
    }
    func copy(_ value: String, secret: Bool = false) {
        #if STYX_TESTING
        if testPreview { return }
        #endif
        guard !value.isEmpty else { return }
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(value, forType: .string)
        if secret { copiedCredential = value; copiedCredentialChangeCount = NSPasteboard.general.changeCount }
    }
    func beginAcceptance() { perform { [self] in _ = try await client.write("acceptance/begin", ["authorize": .bool(true)]) } }
    func confirmChat() {
        guard targetProofReady, let id = challengeID else { return }
        perform { [self] in _ = try await client.write("acceptance/confirm", ["authorize": .bool(true), "challengeId": .string(id), "observedInTargetChat": .bool(true)]) }
    }
    func loadDevices() {
        perform { [self] in devices = try await client.write("devices", [:])["devices"].array.compactMap(ProductDevice.init) }
    }
    func setDefault(_ id: String) { perform { [self] in _ = try await client.write("default-device", ["authorize": .bool(true), "deviceId": .string(id)]); devices = try await client.write("devices", [:])["devices"].array.compactMap(ProductDevice.init) } }
    func revokeDevice(_ device: ProductDevice) {
        let alert = NSAlert()
        alert.messageText = productText("撤销这台电脑的访问？", "Revoke this computer's access?")
        alert.informativeText = device.label + "\n" + productText("该电脑将无法继续访问，需要主台重新审核才能加入。", "This computer will lose access and require a new owner review before joining again.")
        alert.addButton(withTitle: productText("撤销访问", "Revoke access"))
        alert.addButton(withTitle: productText("取消", "Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        perform { [self] in
            _ = try await client.write("device/revoke", ["authorize": .bool(true), "deviceId": .string(device.id)])
            devices = try await client.write("devices", [:])["devices"].array.compactMap(ProductDevice.init)
        }
    }
    func setLoginEnabled(_ enabled: Bool) {
        perform { [self] in _ = try await client.write("app/login", ["authorize": .bool(true), "enabled": .bool(enabled)]) }
    }
    func checkIngress() { perform { [self] in ingress = try await client.write("device-ingress/plan", [:])["ingress"] } }
    func createInvitation() { perform { [self] in createdInvitation = try await client.write("pairing-link/create", ["authorize": .bool(true)]) } }
    func loadPending() { perform { [self] in pending = try await client.write("pending/list", ["authorize": .bool(true)])["pending"].array } }
    func approvePending() {
        perform { [self] in
            _ = try await client.write("pending/approve", ["authorize": .bool(true), "requestId": selectedPending["request_id"], "fingerprintConfirmation": .string(fingerprintConfirmation), "enableComputer": .bool(approveComputer), "enableBrowser": .bool(approveBrowser)])
            selectedPending = .null; fingerprintConfirmation = ""
            pending = try await client.write("pending/list", ["authorize": .bool(true)])["pending"].array
        }
    }
    func updateCapabilities() {
        perform { [self] in
            guard !joined else { throw ProductCoreError.rejected }
            status = try await client.read("status")
            var payload: [String: ProductJSON] = ["authorize": .bool(true), "computer": .bool(computer)]
            let currentBrowser = status["deviceCapabilities"]["browser"] == .null ? deployment?.browserRequested == true : status["deviceCapabilities"]["browser"].bool
            var stoppedOwnedForeground = false
            if browser != currentBrowser {
                payload["browser"] = .bool(browser)
                switch ProductCapabilityPolicy.foregroundTransition(owner: status["ownedForeground"], observed: status["foreground"]) {
                case .stopped: break
                case .needsReview: throw ProductWorkflowError.capabilityNeedsOfflineReview
                case .owned:
                    let alert = NSAlert()
                    alert.messageText = productText("暂停本次连接并更改能力？", "Pause this connection and change capabilities?")
                    alert.informativeText = productText("这会停止本次 Styx App 管理的 CLI、Browser 和 Computer Use 连接。请先完成正在进行的操作。更改成功后会恢复连接。", "This pauses CLI, Browser and Computer Use connections managed by this Styx App. Finish active work first. Connections resume after successful changes.")
                    alert.addButton(withTitle: productText("暂停并更改", "Pause and change"))
                    alert.addButton(withTitle: productText("取消", "Cancel"))
                    guard alert.runModal() == .alertFirstButtonReturn else { return }
                    let stopped: ProductJSON
                    do { stopped = try await client.write("foreground/stop", ["authorize": .bool(true)])["foreground"] }
                    catch { throw ProductWorkflowError.foregroundStopUnconfirmed }
                    guard stopped["status"].string == "stopped", stopped["observation"].string == "current_process", stopped["foregroundRestartRequired"] == .bool(true) else { throw ProductWorkflowError.foregroundStopUnconfirmed }
                    stoppedOwnedForeground = true; foregroundRecoveryNeeded = true
                }
            }
            let result: ProductJSON
            do { result = try await client.write("capabilities", payload)["capabilities"] }
            catch {
                if stoppedOwnedForeground { throw ProductWorkflowError.capabilityChangeInterrupted }
                // Computer-only updates can also stop the owned connection
                // before a lost response. Observe and recover; never replay.
                foregroundRecoveryNeeded = true
                throw ProductWorkflowError.capabilityChangeInterrupted
            }
            guard result["status"].string == "updated", result["phase"].string == "complete" else {
                foregroundRecoveryNeeded = stoppedOwnedForeground || result["foregroundRestartRequired"].bool
                throw ProductWorkflowError.capabilityChangeInterrupted
            }
            if stoppedOwnedForeground || result["foregroundRestartRequired"] == .bool(true) {
                foregroundRecoveryNeeded = true
                do {
                    _ = try await client.write("foreground", ["authorize": .bool(true)])
                    foregroundRecoveryNeeded = false
                } catch { throw ProductWorkflowError.foregroundRecoveryRequired }
            }
        }
    }
    func resumeForeground() {
        perform { [self] in
            _ = try await client.write("foreground", ["authorize": .bool(true)])
            foregroundRecoveryNeeded = false
            if page == .preparation { restoredPage = false }
        }
    }
    func openOfficial(_ value: String) {
        #if STYX_TESTING
        if testPreview { return }
        #endif
        guard let url = URL(string: value), let c = URLComponents(url: url, resolvingAgainstBaseURL: false), c.user == nil, c.password == nil else { return }
        let official = c.scheme == "https" && ["platform.openai.com", "chatgpt.com", "developers.openai.com"].contains(c.host ?? "") && c.port == nil
        let system = c.scheme == "x-apple.systempreferences" && ["com.apple.preference.security", "com.apple.Localization-Settings.extension"].contains(c.path)
        guard official || system else { return }
        NSWorkspace.shared.open(url)
    }
}
