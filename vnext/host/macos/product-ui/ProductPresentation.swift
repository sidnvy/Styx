import AppKit
import SwiftUI

enum ProductSettingsSection: String, CaseIterable, Identifiable {
    case general, computers, chat
    var id: String { rawValue }
    var title: String {
        switch self {
        case .general: return productText("通用", "General")
        case .computers: return productText("电脑", "Computers")
        case .chat: return "ChatGPT"
        }
    }
    var symbol: String {
        switch self {
        case .general: return "gearshape"
        case .computers: return "desktopcomputer"
        case .chat: return "globe"
        }
    }
}
enum ProductConnectionIndicator: Equatable {
    case connected, offline, attention, unknown
    var label: String {
        switch self {
        case .connected: return productText("已连接", "Connected")
        case .offline: return productText("未连接", "Disconnected")
        case .attention: return productText("需要处理", "Needs attention")
        case .unknown: return productText("暂时无法获取状态", "Status unavailable")
        }
    }
}
extension ProductDevice {
    var indicator: ProductConnectionIndicator { online.map { $0 ? .connected : .offline } ?? .unknown }
}
struct ProductConnectionDot: View {
    let state: ProductConnectionIndicator
    var body: some View {
        Group {
            switch state {
            case .connected: Circle().fill(Color.green).frame(width: 7, height: 7)
            case .offline: Circle().stroke(Color.secondary, lineWidth: 1.5).frame(width: 7, height: 7)
            case .attention: Image(systemName: "exclamationmark.circle").foregroundStyle(.orange).font(.system(size: 12))
            case .unknown: Image(systemName: "questionmark.circle").foregroundStyle(.secondary).font(.system(size: 11))
            }
        }.frame(width: 12, height: 14).help(state.label).accessibilityLabel(state.label)
    }
}
enum ProductCapabilityKind {
    case cli, computer, browser
    var title: String {
        switch self {
        case .cli: return productText("命令行（CLI）", "Command line (CLI)")
        case .computer: return productText("操作电脑（Computer Use）", "Computer Use")
        case .browser: return productText("浏览器自动化", "Browser Automation")
        }
    }
    var detail: String {
        switch self {
        case .cli: return productText("运行命令和脚本 · 始终包含", "Run commands and scripts · Always included")
        case .computer: return productText("查看屏幕、点击和输入", "View the screen, click and type")
        case .browser: return productText("打开网页、点击和填写表单", "Open websites, click and fill in forms")
        }
    }
    var symbol: String {
        switch self { case .cli: return "terminal"; case .computer: return "hand.point.up.left"; case .browser: return "globe" }
    }
}
struct ProductCapabilityLabel: View {
    let kind: ProductCapabilityKind
    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label(kind.title, systemImage: kind.symbol)
            Text(kind.detail).font(.caption).foregroundStyle(.secondary)
        }
    }
}
enum ProductTunnelInputPolicy {
    static func tunnelError(_ value: String) -> String? {
        let value = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard value.range(of: #"^tunnel_[A-Za-z0-9_-]{8,128}$"#, options: .regularExpression) != nil else {
            return productText("请从 OpenAI Platform 复制以 tunnel_ 开头的 Tunnel ID，而不是网址。", "Copy the tunnel_ identifier from OpenAI Platform, rather than a URL.")
        }
        return nil
    }
    static func keyError(_ value: String, saved: Bool) -> String? {
        if value.isEmpty && saved { return nil }
        guard value.range(of: #"^sk-[A-Za-z0-9_-]{16,512}$"#, options: .regularExpression) != nil else {
            return productText("请粘贴完整的 OpenAI 运行密钥。", "Paste the complete OpenAI runtime API key.")
        }
        return nil
    }
}
enum ProductChatVerification: Equatable {
    case pending, partial, verified, confirmed, expired, contextChanged
    static func observed(_ acceptance: ProductJSON, contextChanged: Bool) -> Self {
        if contextChanged || acceptance["status"].string == "acceptance_context_changed" { return .contextChanged }
        if acceptance["complete"].bool { return .confirmed }
        if acceptance["status"].string == "acceptance_expired" { return .expired }
        let exec = acceptance["requestProof"]["status"].string == "verified"
        let browser = acceptance["browser"]["status"].string ?? ""
        let desktop = acceptance["desktop"]["status"].string ?? ""
        if exec && ["verified", "not_required"].contains(browser) && ["verified", "not_required"].contains(desktop) { return .verified }
        if exec || browser == "verified" || desktop == "verified" { return .partial }
        return .pending
    }
    var hasRequest: Bool { [.partial, .verified, .confirmed].contains(self) }
    var proofComplete: Bool { self == .verified || self == .confirmed }
    var label: String {
        switch self {
        case .verified, .confirmed: return productText("各项功能测试通过", "All feature tests passed")
        case .partial: return productText("部分测试已完成", "Some tests completed")
        case .expired: return productText("这条测试消息已过期", "This test message has expired")
        case .contextChanged: return productText("请先更新插件的连接信息", "Update the plugin connection first")
        case .pending: return productText("从 ChatGPT 试用这台电脑", "Try this computer from ChatGPT")
        }
    }
}
extension ProductModel {
    var chatVerification: ProductChatVerification { .observed(acceptance, contextChanged: plugin["contextChanged"].bool) }
    var needsPluginSetup: Bool {
        chatVerification == .contextChanged || (chatVerification == .pending && plugin["accountActions"]["installation"].string != "user_confirmed")
    }
    var chatReady: Bool {
        chatIndicator == .connected && localIndicator == .connected && chatVerification.proofComplete
            && (!computerApproved || axGranted && screenGranted)
    }
    var chatStatusTitle: String {
        if chatIndicator == .unknown { return productText("暂时无法获取连接状态", "Connection status unavailable") }
        if chatReady { return productText("已就绪", "Ready to use") }
        if chatIndicator == .connected { return productText("连接已建立", "Connection established") }
        if tunnelConnection == .connected && chatVerification == .contextChanged { return productText("插件连接需要更新", "Plugin connection needs updating") }
        return tunnelFeedback
    }
    var chatNextStep: String {
        if observationError != nil { return productText("暂时无法获取最新状态，请点击“重新检查”。", "The latest state is unavailable. Select Check again.") }
        if localIndicator != .connected { return productText("这台电脑尚未就绪，请先完成“电脑”中的设置。", "Finish setting up this computer in Computers first.") }
        if computerApproved && (!axGranted || !screenGranted) { return productText("操作电脑需要系统权限。请在“电脑”中开启辅助功能和屏幕录制。", "Computer interaction needs system permissions. Enable Accessibility and Screen Recording in Computers.") }
        switch chatVerification {
        case .confirmed, .verified: return productText("在 ChatGPT 中选择 Styx，即可使用这台电脑。", "Select Styx in ChatGPT to use this computer.")
        case .partial: return productText("ChatGPT 已成功使用部分功能。打开“试用 Styx”查看进度。", "ChatGPT has used some features successfully. Open Try Styx to see progress.")
        case .expired: return productText("在 ChatGPT 中选择 Styx。需要检查各项功能时，可以重新试用。", "Select Styx in ChatGPT. You can run a new test to check its features.")
        case .contextChanged: return productText("连接信息已更改。请在 ChatGPT 中更新已有 Styx 的连接。", "Connection details changed. Update the existing Styx connection in ChatGPT.")
        case .pending:
            if !needsPluginSetup { return productText("打开“试用 Styx”，从 ChatGPT 检查这台电脑的功能。", "Open Try Styx to test this computer from ChatGPT.") }
            return productText("接下来在 ChatGPT 安装 Styx。已经安装的话，可以直接试用。", "Next, install Styx in ChatGPT. If it is already installed, you can try it now.")
        }
    }
    var localIndicator: ProductConnectionIndicator {
        guard loaded, observationError == nil else { return .unknown }
        guard localPrepared else { return .attention }
        switch status["foreground"]["status"].string {
        case "connected", "using_service": return .connected
        case "not_running": return .offline
        case "needs_attention", "stopping": return .attention
        default: return .unknown
        }
    }
    var chatIndicator: ProductConnectionIndicator {
        if observationError != nil { return .unknown }
        if tunnelAttempt == .connecting { return .attention }
        if tunnelConnection == .unknown { return .unknown }
        // This dot reports the current connection, not the lifetime of a test
        // challenge or whether the user has confirmed seeing its results.
        if tunnelConnection == .connected && chatVerification != .contextChanged { return .connected }
        if tunnelConnection == .notConfigured { return .offline }
        return .attention
    }
    var chatMenuTitle: String {
        if tunnelConnection == .notConfigured { return productText("连接 ChatGPT", "Connect ChatGPT") }
        if tunnelConnection == .connected && chatVerification == .contextChanged { return productText("更新 ChatGPT 连接", "Update ChatGPT connection") }
        // Keep navigation stable while reconnecting or when a read fails. The
        // adjacent indicator and Settings explain the current connection state.
        return "ChatGPT"
    }
    var hasSavedRuntimeKey: Bool {
        ["configured", "running", "interrupted"].contains(journey["tunnel"]["status"].string ?? "")
    }
    var ingressCandidates: [String] { ingress["candidates"].array.compactMap(\.string) }
    var ingressNeedsRecovery: Bool { ["preparing", "running", "needs_reconciliation"].contains(ingressSetup["status"].string ?? "") }
    var ingressRecoveryBlocked: Bool { ["recovery_guard", "observation_unavailable"].contains(ingressSetup["phase"].string ?? "") }
    var joiningComparisonCode: String? {
        status["deployment"]["steps"].array.first(where: { $0["id"].string == "host.request" })?["comparison_code"].string
    }
    func invitationOperation(_ operation: @escaping () async throws -> Void) {
        perform { [self] in
            invitationInFlight = true; invitationError = nil
            defer { invitationInFlight = false }
            do { try await operation() }
            catch {
                // A timed-out write is uncertain. Read its journal before showing
                // recovery; never replay preparation or publish an old invitation.
                createdInvitation = .null; invitationCopied = false
                if let observed = try? await client.write("device-ingress/status", [:])["setup"] { ingressSetup = observed }
                else { ingressSetup = .object(["status": .string("needs_reconciliation"), "phase": .string("observation_unavailable")]) }
                invitationError = productText("未能完成。请检查网络后重试；如果准备中断，请先恢复或撤回。", "Could not finish. Check your network and try again. If preparation was interrupted, resume or undo it first.")
            }
        }
    }
    func readInvitationPlan() async throws {
        ingressSetup = try await client.write("device-ingress/status", [:])["setup"]
        ingress = try await client.write("device-ingress/plan", [:])["ingress"]
        if !ingressCandidates.contains(selectedIngressAddress) { selectedIngressAddress = "" }
    }
    func beginDeviceInvitation() {
        invitationExpanded = true
        guard !busy else { return }
        if let expiry = createdInvitation["expiresAt"].number, expiry > Date().timeIntervalSince1970 * 1000 { return }
        invitationOperation { [self] in
            invitationClosed = false; createdInvitation = .null; invitationCopied = false
            try await readInvitationPlan()
            guard !ingressNeedsRecovery, ingress["blockers"].array.isEmpty else { return }
            if ingress["requiresInterfaceChoice"].bool && !ingressCandidates.contains(selectedIngressAddress) { return }
            var options: [String: ProductJSON] = ["authorize": .bool(true)]
            if ingress["requiresInterfaceChoice"].bool { options["listenHost"] = .string(selectedIngressAddress) }
            if ingress["nextAction"].string == "prepare_additional_entry" {
                _ = try await client.write("device-ingress/prepare", options)
                ingressSetup = try await client.write("device-ingress/status", [:])["setup"]
                guard ingressSetup["status"].string == "applied" else { throw ProductCoreError.unavailable }
            }
            createdInvitation = try await client.write("pairing-link/create", options)
            invitationWindowOpen = true
        }
    }
    func recoverDeviceInvitation(_ action: String) {
        guard ["retry", "rollback"].contains(action), !ingressRecoveryBlocked else { return }
        invitationOperation { [self] in
            ingressSetup = try await client.write("device-ingress/recover", ["authorize": .bool(true), "action": .string(action)])["setup"]
            try await readInvitationPlan()
            if action == "rollback" { invitationClosed = true; invitationWindowOpen = false }
            // Recovery never silently creates a new invitation.
        }
    }
    func confirmIngressRollback() {
        let alert = NSAlert()
        alert.messageText = productText("撤回这次连接准备？", "Undo this connection setup?")
        alert.informativeText = productText("使用这个新增入口的电脑会断开。原聊天连接和这台 Mac 的连接不受影响。", "Computers using this added connection will disconnect. Your existing chat connection and this Mac's connection remain available.")
        alert.addButton(withTitle: productText("撤回准备", "Undo setup")); alert.addButton(withTitle: productText("取消", "Cancel"))
        if alert.runModal() == .alertFirstButtonReturn { recoverDeviceInvitation("rollback") }
    }
    func closeDeviceInvitation(completion: @escaping () -> Void = {}) {
        guard !busy else { return }
        if !invitationWindowOpen { invitationExpanded = false; completion(); return }
        invitationOperation { [self] in
            let result = try await client.write("pairing-link/close", ["authorize": .bool(true)])
            guard result["ingress"]["pairing"]["status"].string == "closed" else { throw ProductCoreError.invalidResponse }
            createdInvitation = .null; invitationCopied = false; invitationWindowOpen = false
            invitationClosed = true; invitationExpanded = false; completion()
        }
    }
    func confirmPendingIdentity(_ request: ProductJSON) {
        guard !busy, let code = request["comparison_code"].string else { return }
        let alert = NSAlert()
        alert.messageText = productText("两台电脑的配对码是否一致？", "Do both computers show the same pairing code?")
        alert.informativeText = (request["label"].string ?? "Styx") + "\n\n" + code
        alert.addButton(withTitle: productText("一致，连接", "Match — connect"))
        alert.addButton(withTitle: productText("不一致或取消", "Do not match or cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        selectedPending = request; comparisonConfirmation = code
        approvePending()
    }

}

struct ProductMenuRow: View {
    let title: String
    var symbol: String? = nil
    var state: ProductConnectionIndicator? = nil
    var disclosure = false
    var shortcut = ""
    let action: () -> Void
    @State private var hovered = false
    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                if let symbol = symbol { Image(systemName: symbol).frame(width: 18) }
                Text(title)
                Spacer(minLength: 12)
                if let state = state { ProductConnectionDot(state: state) }
                if disclosure { Image(systemName: "chevron.right").font(.system(size: 9, weight: .medium)).foregroundStyle(.secondary) }
                if !shortcut.isEmpty { Text(shortcut).font(.system(size: 12)).foregroundStyle(.secondary) }
            }.font(.system(size: 13)).padding(.horizontal, 10).frame(minHeight: 32)
                .contentShape(Rectangle())
                .background(hovered ? Color.primary.opacity(0.08) : Color.clear, in: RoundedRectangle(cornerRadius: 6))
        }.buttonStyle(.plain).onHover { hovered = $0 }
            .accessibilityLabel(title + (state.map { ", " + $0.label } ?? ""))
    }
}
struct ProductDailyPanel: View {
    @ObservedObject var model: ProductModel
    weak var controller: ProductWindowController?
    let quit: () -> Void
    private func showSettings(_ section: ProductSettingsSection) {
        if let controller = controller { controller.showSettings(section) }
        else { model.requestSettings(section) }
    }
    var body: some View {
        VStack(spacing: 0) {
            if !model.loaded {
                ProgressView(model.loadingMessage).padding(16)
                if model.error != nil { Button(productText("重试", "Retry")) { Task { await model.bootstrap() } } }
            } else if model.deployment == nil {
                ProductMenuRow(title: productText("开始设置", "Get started"), symbol: "sparkles") { controller?.showOnboarding() }
                ProductMenuRow(title: productText("加入已有 Styx", "Join an existing Styx"), symbol: "link") {
                    model.joining = true; model.page = .invitation; controller?.showOnboarding()
                }
            } else {
                ProductMenuRow(title: productText("这台 Mac", "This Mac"), symbol: "laptopcomputer", state: model.localIndicator, disclosure: true) { showSettings(.computers) }
                Divider().padding(.vertical, 5)
                if model.joined {
                    ProductMenuRow(title: productText("管理电脑连接", "Main computer"), symbol: "link", state: model.localIndicator, disclosure: true) { showSettings(.computers) }
                } else {
                    Text(productText("电脑", "Computers")).font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 10).padding(.vertical, 5)
                    ForEach(model.devices.filter { !$0.isLocal }) { device in
                        ProductMenuRow(title: device.label, symbol: device.platform == "win32" ? "desktopcomputer" : "laptopcomputer", state: model.menuObservationFailed ? .unknown : device.indicator, disclosure: true) {
                            model.selectedDeviceID = device.id; showSettings(.computers)
                        }
                    }
                    ProductMenuRow(title: productText("添加电脑", "Add computer"), symbol: "plus") {
                        if model.invitationExpanded { model.closeDeviceInvitation() }
                        else { model.beginDeviceInvitation() }
                    }.foregroundStyle(Color.accentColor)
                    if model.invitationExpanded { ProductInvitationView(model: model); ProductPendingIdentities(model: model) }
                    Divider().padding(.vertical, 5)
                    ProductMenuRow(title: model.chatMenuTitle, symbol: "globe", state: model.chatIndicator, disclosure: true) { showSettings(.chat) }
                }
                if model.localIndicator != .connected && !model.localPrepared {
                    ProductMenuRow(title: productText("继续设置", "Continue setup"), symbol: "arrow.right") { controller?.showOnboarding() }
                }
            }
            Divider().padding(.vertical, 5)
            ProductMenuRow(title: productText("设置", "Settings"), shortcut: "⌘,") { showSettings(.general) }.keyboardShortcut(",", modifiers: .command)
            Divider().padding(.vertical, 3)
            ProductMenuRow(title: productText("退出 Styx", "Quit Styx"), shortcut: "⌘Q", action: quit).keyboardShortcut("q", modifiers: .command)
        }.padding(8).frame(width: 332)
            .task(id: model.menuVisible) { if model.menuVisible { await model.observePresentation() } }
    }
}
struct ProductInvitationView: View {
    @ObservedObject var model: ProductModel
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            if model.invitationInFlight {
                HStack { ProgressView().controlSize(.small); Text(productText("正在准备邀请…", "Preparing invitation…")).font(.caption) }
            } else if let value = model.createdInvitation["link"].string {
                TimelineView(.periodic(from: .now, by: 1)) { context in
                    if let expiry = model.createdInvitation["expiresAt"].number, expiry <= context.date.timeIntervalSince1970 * 1000 {
                        Text(productText("邀请已过期", "Invitation expired")).font(.caption)
                        Button(productText("生成新邀请", "Create new invitation")) { model.beginDeviceInvitation() }
                    } else {
                        Text(productText("在另一台电脑的 Styx 中选择“加入已有”，粘贴此邀请。", "In Styx on the other computer, choose Join an existing Styx and paste this invitation.")).font(.caption)
                        Button { model.copy(value, secret: true); model.invitationCopied = true } label: { Label(model.invitationCopied ? productText("邀请已复制", "Invitation copied") : productText("复制邀请链接", "Copy invitation link"), systemImage: "doc.on.doc").frame(maxWidth: .infinity) }
                        Text(productText("邀请有效期为 10 分钟", "Invitations expire after 10 minutes")).font(.caption2).foregroundStyle(.secondary)
                    }
                }
            } else if model.ingressNeedsRecovery {
                Text(productText("连接准备中断", "Connection setup was interrupted")).font(.caption.weight(.semibold))
                if model.ingressRecoveryBlocked {
                    Text(productText("上次恢复未完成，需要检查后才能继续。请联系 Styx 维护者。", "The previous recovery did not finish and needs inspection. Contact the Styx maintainer.")).font(.caption)
                    Button(productText("重新检查", "Check again")) { model.beginDeviceInvitation() }
                } else {
                    Text(productText("可以继续准备，或撤回这次网络连接更改。", "Resume preparation or undo this network connection change.")).font(.caption).foregroundStyle(.secondary)
                    HStack {
                        Button(productText("继续准备", "Resume setup")) { model.recoverDeviceInvitation("retry") }
                        Button(productText("撤回准备", "Undo setup")) { model.confirmIngressRollback() }
                    }
                }
            } else if !model.ingress["blockers"].array.isEmpty {
                Text(productText("暂时无法邀请其他电脑", "Cannot invite another computer yet")).font(.caption.weight(.semibold))
                Text(ProductInvitationPolicy.blockerMessage(model.ingress)).font(.caption).foregroundStyle(.secondary)
                Button(productText("重新检查", "Check again")) { model.beginDeviceInvitation() }
            } else if model.ingress["requiresInterfaceChoice"].bool {
                Text(productText("选择另一台电脑能够访问的网络地址。", "Choose the network address the other computer can reach.")).font(.caption)
                Picker(productText("网络地址", "Network address"), selection: $model.selectedIngressAddress) {
                    Text(productText("选择地址", "Choose an address")).tag("")
                    ForEach(model.ingressCandidates, id: \.self) { Text($0).tag($0) }
                }
                Button(productText("创建邀请", "Create invitation")) { model.beginDeviceInvitation() }.disabled(!model.ingressCandidates.contains(model.selectedIngressAddress))
            } else if model.invitationClosed {
                Text(productText("邀请已关闭", "Invitation closed")).font(.caption)
                Button(productText("创建新邀请", "Create new invitation")) { model.beginDeviceInvitation() }
            } else {
                Button(productText("创建邀请", "Create invitation")) { model.beginDeviceInvitation() }
            }
            if let error = model.invitationError { Text(error).font(.caption).foregroundStyle(.red) }
            if model.invitationWindowOpen {
                Button(productText("关闭邀请", "Close invitation")) { model.closeDeviceInvitation() }
                Text(productText("已连接的电脑仍可使用。", "Connected computers remain available.")).font(.caption2).foregroundStyle(.secondary)
            }
        }.padding(10).accessibilityIdentifier("styx-invitation-content").disabled(model.busy)
    }
}
struct ProductPendingIdentities: View {
    @ObservedObject var model: ProductModel
    var body: some View {
        ForEach(model.pending.compactMap(ProductPendingIdentity.init)) { identity in
            let request = identity.value
            VStack(alignment: .leading, spacing: 8) {
                Text(productText("连接", "Connect") + " " + (request["label"].string ?? productText("新电脑", "New computer")) + "?").font(.headline)
                Text(productText("核对另一台电脑上显示的配对码。", "Compare the pairing code shown on the other computer.")).font(.caption).foregroundStyle(.secondary)
                if let code = request["comparison_code"].string {
                    Text(code).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                    Button(productText("核对配对码", "Verify pairing code")) { model.confirmPendingIdentity(request) }.buttonStyle(.borderedProminent).disabled(model.busy)
                } else {
                    Text(productText("等待配对码，请重新检查。", "Waiting for the pairing code. Check again.")).font(.caption)
                    Button(productText("重新检查", "Check again")) { model.loadPending() }.disabled(model.busy)
                }
            }.padding(10)
        }
    }
}
struct ProductPendingIdentity: Identifiable {
    let id: String
    let value: ProductJSON
    init?(_ value: ProductJSON) {
        guard let request = value["request_id"].string, let fingerprint = value["fingerprint"].string else { return nil }
        id = request + ":" + fingerprint; self.value = value
    }
}
extension ProductModel {
    func refreshMenu() async {
        #if STYX_TESTING
        if testSuppressObservations { return }
        #endif
        guard !busy, loaded, deployment != nil else { return }
        guard !observationInFlight else { return }
        await refresh()
        guard !busy, !observationInFlight else { return }
        let revision = mutationRevision
        observationInFlight = true; defer { observationInFlight = false }
        guard observationError == nil else { publish(\.menuObservationFailed, true); return }
        guard !busy, !joined else { return }
        // A read operation against the current owner; never creates pairing or
        // infers online from desired configuration.
        do {
            let observedDevices = try await client.write("devices", [:])["devices"].array.compactMap(ProductDevice.init)
            let observedPending = invitationExpanded ? try await client.write("pending/list", ["authorize": .bool(true)])["pending"].array : pending
            guard revision == mutationRevision, !Task.isCancelled else { return }
            publish(\.devices, observedDevices); publish(\.pending, observedPending)
        } catch { publish(\.menuObservationFailed, true); return }
        publish(\.menuObservationFailed, false)
    }
}

// Attempt feedback is separate from observed transport and account acceptance.
enum ProductTunnelAttempt: Equatable { case idle, connecting, failed, timedOut }
struct ProductTunnelStatus: View {
    @ObservedObject var model: ProductModel
    var showNextStep = true
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                if model.tunnelAttempt == .connecting { ProgressView().controlSize(.small) }
                else { Image(systemName: model.tunnelConnection == .connected ? "globe" : "exclamationmark.circle").foregroundStyle(model.tunnelConnection == .connected ? Color.green : Color.secondary) }
                Text(model.tunnelFeedback).font(.callout)
            }.accessibilityElement(children: .combine)
            if showNextStep && model.tunnelConnection == .connected {
                Text(model.chatNextStep).font(.caption).foregroundStyle(.secondary)
            } else if model.tunnelAttempt == .failed || model.tunnelAttempt == .timedOut || model.tunnelConnection == .unavailable {
                Text(productText("请检查网络；也可以编辑 Tunnel ID 和运行密钥后再试。", "Check the network, or edit the Tunnel ID and runtime key, then retry.")).font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}
extension ProductModel {
    var tunnelFeedback: String {
        if tunnelAttempt == .connecting { return productText("正在连接到 OpenAI…", "Connecting to OpenAI…") }
        if tunnelConnection == .connected { return productText("已连接到 OpenAI", "Connected to OpenAI") }
        switch tunnelAttempt {
        case .connecting: return productText("正在连接到 OpenAI…", "Connecting to OpenAI…")
        case .failed: return productText("连接未能完成", "Connection did not complete")
        case .timedOut: return productText("未能确认连接，请检查后重试", "Connection could not be confirmed. Check and retry")
        case .idle:
            switch tunnelConnection {
            case .notConfigured: return productText("尚未设置 OpenAI 连接", "OpenAI connection is not configured")
            case .connecting: return productText("正在连接到 OpenAI…", "Connecting to OpenAI…")
            case .stopped: return productText("OpenAI 连接已停止", "OpenAI connection is stopped")
            case .unavailable: return productText("OpenAI 连接尚未就绪", "OpenAI connection is not ready")
            default: return productText("暂时无法确认连接状态", "Connection status could not be confirmed")
            }
        }
    }
}
