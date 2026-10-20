import AppKit
import ApplicationServices
import SwiftUI
import UniformTypeIdentifiers

func productText(_ chinese: String, _ english: String) -> String {
    (Locale.preferredLanguages.first ?? "en").hasPrefix("zh") ? chinese : english
}

enum ProductPage: String, CaseIterable { case welcome, invitation, capabilities, preparation, permissions, chat, overview, computers, settings }

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
    @Published var loginEnabled = false
    private var handoffTimer: Timer?
    private var copiedCredential: String?
    private var copiedCredentialChangeCount: Int?
    private var restoredPage = false

    var deployment: ProductDeployment? { ProductDeployment(status["deployment"]) }
    var localPrepared: Bool { journey["steps"].array.contains { $0["id"].string == "local_setup" && $0["status"].string == "completed" } }
    var joined: Bool { deployment?.joined ?? joining }
    var accepted: Bool { acceptance["complete"].bool }
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
            let lifecycle = try await client.read("app/lifecycle")["lifecycle"]
            loginEnabled = lifecycle["loginAtStartup"].string == "enabled"
        }
        observePermissions()
        if !restoredPage {
            restoredPage = true
            if let deployment = deployment {
                computer = deployment.computerRequested; browser = deployment.browserRequested
                page = !localPrepared ? .preparation : accepted || deployment.joined ? .overview : .chat
            }
        }
    }
    private func reportFailure() {
        // Never interpolate raw transport errors, response bodies or secrets.
        error = productText("操作未完成。请刷新状态后检查；结果不确定的操作不会自动重试。", "The operation did not complete. Refresh to inspect its state; uncertain operations are not replayed.")
    }
    func perform(_ operation: @escaping () async throws -> Void) {
        guard !busy else { return }
        busy = true; error = nil
        Task {
            do { try await operation(); try await reload() }
            catch { reportFailure(); try? await reload() }
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
        if joined {
            // Only advance documented safe pending steps. A failed/uncertain
            // mutation is never replayed; remote approval remains independent.
            let safe: Set<String> = ["host.prepare", "host.request", "host.claim", "host.doctor"]
            for _ in 0..<4 {
                guard let next = deployment?.steps.first(where: { $0.status != "succeeded" && $0.status != "skipped" }),
                      safe.contains(next.id), ["pending", "awaiting_approval"].contains(next.status) else { break }
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
            _ = try await client.write("browser/prepare", ["authorize": .bool(true)])
        }
        _ = try await client.write("foreground", ["authorize": .bool(true)])
        page = deployment?.computerRequested == true ? .permissions : joined ? .overview : .chat
    }
    func continuePreparation() { perform { [self] in try await prepare() } }
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
            var payload: [String: ProductJSON] = ["authorize": .bool(true), "computer": .bool(computer)]
            let currentBrowser = status["deviceCapabilities"]["browser"] == .null ? deployment?.browserRequested == true : status["deviceCapabilities"]["browser"].bool
            if browser != currentBrowser { payload["browser"] = .bool(browser) }
            _ = try await client.write("capabilities", payload)
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
