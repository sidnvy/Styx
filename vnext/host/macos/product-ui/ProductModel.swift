import AppKit
import ApplicationServices
import SwiftUI
import UniformTypeIdentifiers

func productText(_ chinese: String, _ english: String) -> String {
    (Locale.preferredLanguages.first ?? "en").hasPrefix("zh") ? chinese : english
}

enum ProductPage: String, CaseIterable { case welcome, invitation, capabilities, preparation, permissions, chat, overview, computers, settings }

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
    static func stages(_ deployment: ProductDeployment?, browser: ProductJSON, foreground: ProductJSON = .null, activity: ProductPreparationPhase?) -> [ProductPreparationStage] {
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
        deployment?.steps.first { ["blocked", "uncertain", "failed", "awaiting_approval"].contains($0.status) }
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
enum ProductWorkflowError: Error { case browserPreparationNeedsReview, capabilityNeedsOfflineReview, foregroundStopUnconfirmed, capabilityChangeInterrupted, foregroundRecoveryRequired }

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
    @Published var page: ProductPage = .welcome
    @Published var busy = false
    @Published var loaded = false
    @Published var error: String?
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
    @Published var handoffCredential = ""
    @Published var handoffTarget = ""
    @Published var desktopValue = ""
    @Published var axGranted = false
    @Published var screenGranted = false
    @Published var ingress: ProductJSON = .null
    @Published var createdInvitation: ProductJSON = .null
    @Published var pending: [ProductJSON] = []
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

    var deployment: ProductDeployment? { ProductDeployment(status["deployment"]) }
    var localPrepared: Bool { journey["steps"].array.contains { $0["id"].string == "local_setup" && $0["status"].string == "completed" } }
    var joined: Bool { deployment?.joined ?? joining }
    var accepted: Bool { acceptance["complete"].bool }
    var browserNotApproved: Bool { browserObservation["status"].string == "not_approved" && browserObservation["approved"] == .bool(false) }
    var computerNotApproved: Bool { joined && deployment?.computerRequested == true && status["foreground"]["computerRequested"] == .bool(false) }
    var computerApproved: Bool { ProductCapabilityPolicy.computerApproved(status["foreground"]) }
    var preparationStages: [ProductPreparationStage] { ProductPreparationPolicy.stages(deployment, browser: browserObservation, foreground: status["foreground"], activity: preparationActivity) }
    var retryableCommandCheck: ProductStep? { ProductPreparationPolicy.retryableCommandCheck(deployment) }
    var preparationBlocker: ProductStep? { ProductPreparationPolicy.blockingStep(deployment) }
    var preparationConnectionNeedsReview: Bool {
        guard localPrepared else { return false }
        let observed = status["foreground"]["status"].string ?? "unknown"
        return ["needs_attention", "stopping"].contains(observed) || observed == "not_running" && status["nativeStartup"]["status"].string == "reconciliation_required"
    }
    var connectionTunnelID: String { plugin["connection"]["tunnelId"].string ?? (!tunnelID.isEmpty ? tunnelID : handoffTarget) }
    var challengeID: String? { acceptance["challenge"]["id"].string }
    var targetProofReady: Bool {
        acceptance["requestProof"]["status"].string == "verified"
        && ["verified", "not_required"].contains(acceptance["desktop"]["status"].string ?? "")
        && ["verified", "not_required"].contains(acceptance["browser"]["status"].string ?? "")
    }
    init(sessionURL: URL) throws { client = try ProductCoreClient(sessionURL: sessionURL) }

    func bootstrap() async {
        guard !loaded && !busy else { return }
        busy = true
        defer { busy = false }
        do {
            session = try await client.read("session")
            label = session["defaults"]["label"].string ?? Host.current().localizedName ?? "Mac"
            try await reload()
            loaded = true
        } catch { reportFailure() }
    }
    func refresh() async {
        guard !busy else { return }
        busy = true; defer { busy = false }
        do { try await reload(); error = nil } catch { reportFailure() }
    }
    private func reload() async throws {
        status = try await client.read("status")
        journey = try await client.read("journey")["journey"]
        if deployment != nil {
            if localPrepared && deployment?.browserRequested == true {
                // A Browser observation failure does not hide Exec or the rest
                // of the App. Preparation takes a fresh authoritative reading.
                browserObservation = (try? await client.read("browser")["browser"]) ?? .null
            } else { browserObservation = .null }
            let latest = try await client.read("acceptance")["acceptance"]
            if latest["challenge"]["id"] != acceptance["challenge"]["id"] { desktopValue = "" }
            acceptance = latest
            if !joined {
                plugin = try await client.read("plugin")["plugin"]
                if !pluginDraftEdited {
                    pluginMode = plugin["selection"]["mode"].string ?? "create"
                    pluginName = plugin["presentation"]["displayName"].string ?? "Styx"
                    pluginDescription = plugin["presentation"]["shortDescription"].string ?? productText("连接你的电脑", "Connect your computers")
                    accountLabel = plugin["selection"]["accountLabel"].string ?? ""
                    pluginURL = plugin["selection"]["pluginUrl"].string ?? ""
                    pluginIcon = plugin["presentation"]["icon"]
                }
            }
        }
        if session["nativeAppLifecycleSupported"].bool {
            // Startup observation is independent of setup readiness. A legacy
            // recovery definition or temporarily unavailable launchd must not
            // prevent opening the rest of the App to inspect and recover it.
            do {
                let lifecycle = try await client.read("app/lifecycle")["lifecycle"]
                let observed = lifecycle["loginAtStartup"].string ?? "unknown"
                loginStartup = ["enabled", "disabled", "not_installed"].contains(observed) ? observed : "unknown"
            } catch { loginStartup = "unknown" }
        } else { loginStartup = "unknown" }
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
        default:
            error = productText("操作未完成。请刷新状态后检查；结果不确定的操作不会自动重试。", "The operation did not complete. Refresh to inspect its state; uncertain operations are not replayed.")
        }
    }
    func perform(_ operation: @escaping () async throws -> Void) {
        guard !busy else { return }
        busy = true; error = nil
        Task {
            do { try await operation(); try await reload() }
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
        axGranted = AXIsProcessTrusted(); screenGranted = CGPreflightScreenCaptureAccess()
    }
    func openPermission(_ screen: Bool) {
        // Separate OS-owned prompts, only after the matching explicit action.
        if screen { _ = CGRequestScreenCaptureAccess() }
        else { _ = AXIsProcessTrustedWithOptions(["AXTrustedCheckOptionPrompt": true] as CFDictionary) }
        openOfficial(screen ? "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture" : "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility")
    }
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
        let key = runtimeKey; runtimeKey = ""
        perform { [self] in
            _ = try await client.write("tunnel/configure", ["authorize": .bool(true), "autoStart": .bool(true), "tunnelId": .string(tunnelID.trimmingCharacters(in: .whitespacesAndNewlines)), "apiKey": .string(key)])
            _ = try await client.write("tunnel/start", ["authorize": .bool(true)])
        }
    }
    func startTunnel() { perform { [self] in _ = try await client.write("tunnel/start", ["authorize": .bool(true)]) } }
    func savePlugin() {
        perform { [self] in
            var icon = pluginIcon
            if icon == .null, let path = Bundle.main.resourceURL?.appendingPathComponent("brand/styx-plugin-icon.png"),
               let bytes = try? Data(contentsOf: path), bytes.count <= 256 * 1024 {
                icon = .object(["mimeType": .string("image/png"), "dataBase64": .string(bytes.base64EncodedString())])
            }
            let long = plugin["presentation"]["longDescription"].string ?? productText("通过 Styx 连接你的电脑，使用 CLI、Browser Automation 和 Computer Use。", "Connect your computers with Styx for CLI, Browser Automation and Computer Use.")
            _ = try await client.write("plugin/profile", ["authorize": .bool(true), "presentation": .object(["displayName": .string(pluginName), "shortDescription": .string(pluginDescription), "longDescription": .string(long), "icon": icon]), "selection": .object(["mode": .string(pluginMode), "accountLabel": .string(accountLabel), "pluginUrl": .string(pluginURL)])])
            pluginDraftEdited = false
        }
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
    func exportPluginIcon() {
        let bytes: Data?
        if let encoded = pluginIcon["dataBase64"].string { bytes = Data(base64Encoded: encoded) }
        else if let url = Bundle.main.resourceURL?.appendingPathComponent("brand/styx-plugin-icon.png") { bytes = try? Data(contentsOf: url) }
        else { bytes = nil }
        guard let bytes = bytes, bytes.count <= 256 * 1024 else { reportFailure(); return }
        let panel = NSSavePanel(); panel.allowedContentTypes = [.png]; panel.nameFieldStringValue = "styx-icon.png"
        guard panel.runModal() == .OK, let destination = panel.url else { return }
        do { try bytes.write(to: destination, options: .atomic) } catch { reportFailure() }
    }
    func confirmPluginInstallation() {
        perform { [self] in
            var payload: [String: ProductJSON] = ["authorize": .bool(true), "stage": .string("installation")]
            if !pluginURL.isEmpty { payload["pluginUrl"] = .string(pluginURL) }
            _ = try await client.write("plugin/record", payload)
        }
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
        createdInvitation = .null
        if let copied = copiedCredential, copiedCredentialChangeCount == NSPasteboard.general.changeCount,
           NSPasteboard.general.string(forType: .string) == copied { NSPasteboard.general.clearContents() }
        copiedCredential = nil; copiedCredentialChangeCount = nil
    }
    func copy(_ value: String, secret: Bool = false) {
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
        }
    }
    func openOfficial(_ value: String) {
        guard let url = URL(string: value), let c = URLComponents(url: url, resolvingAgainstBaseURL: false), c.user == nil, c.password == nil else { return }
        let official = c.scheme == "https" && ["platform.openai.com", "chatgpt.com", "developers.openai.com"].contains(c.host ?? "") && c.port == nil
        let system = c.scheme == "x-apple.systempreferences" && ["com.apple.preference.security", "com.apple.Localization-Settings.extension"].contains(c.path)
        guard official || system else { return }
        NSWorkspace.shared.open(url)
    }
}
