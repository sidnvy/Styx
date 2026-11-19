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
        case .cli: return productText("运行命令和脚本", "Run commands and scripts")
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
extension ProductModel {
    var localIndicator: ProductConnectionIndicator {
        guard loaded, observationError == nil else { return .unknown }
        if status["admission_fenced"].bool { return .attention }
        switch status["foreground"]["execConnection"].string {
        case "connected": return .connected
        case "disconnected": return .offline
        case "connecting": return .attention
        default: return .unknown
        }
    }
    var hasSavedRuntimeKey: Bool {
        ["configured", "running", "interrupted"].contains(tunnel["status"].string ?? "")
    }
    func beginDeviceInvitation() {
        invitationExpanded = true
        guard !busy else { return }
        if let expiry = createdInvitation["expiresAt"].number, expiry > Date().timeIntervalSince1970 * 1000 { return }
        perform { [self] in
            invitationInFlight = true; invitationError = nil
            createdInvitation = .null; invitationCopied = false
            defer { invitationInFlight = false }
            guard status["gateway"]["lan"]["enabled"].bool else {
                invitationError = productText("此管理电脑尚未启用局域网。首次设置时选择允许其他电脑加入并填写本机的私有网络地址。", "LAN joining is not configured. During setup, enable other computers to join and enter this hub's private network address.")
                return
            }
            do { createdInvitation = try await client.native("inviteComputer", ["authorize": .bool(true)]) }
            catch {
                invitationError = productText("邀请未能完成。请检查连接状态；不会自动重新发送。", "The invitation did not complete. Check the connection status; it will not be resent automatically.")
            }
        }
    }
    func closeDeviceInvitation(completion: @escaping () -> Void = {}) {
        guard !busy else { return }
        clearSecrets(); invitationExpanded = false; completion()
    }
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
    @ViewBuilder private var nativeRows: some View {
        if model.status["configuration"] == .null && model.status["enrollment"] == .null && model.status["gateway"] == .null {
            ProductMenuRow(title: productText("开始设置", "Get started"), symbol: "sparkles") { controller?.showOnboarding() }
                .disabled(!model.nativeCanCreateLocal)
            ProductMenuRow(title: productText("加入已有 Styx", "Join an existing Styx"), symbol: "link") {
                model.joining = true; model.page = .invitation; controller?.showOnboarding()
            }.disabled(!model.nativeSupportsOperation("inspectJoin"))
        } else {
            ProductMenuRow(title: productText("这台 Mac", "This Mac"), symbol: "laptopcomputer", state: model.localIndicator, disclosure: true) {
                showSettings(.computers)
            }
            Divider().padding(.vertical, 5)
            if model.status["gateway"] == .null {
                ProductMenuRow(title: productText("管理电脑连接", "Main computer"), symbol: "link", state: model.localIndicator, disclosure: true) {
                    showSettings(.computers)
                }
            } else {
                ForEach(model.devices.filter { !$0.isLocal }) { device in
                    ProductMenuRow(title: device.label, symbol: "desktopcomputer", state: device.indicator, disclosure: true) { showSettings(.computers) }
                }

            }
            ProductMenuRow(title: "ChatGPT", symbol: "globe", disclosure: true) { showSettings(.chat) }
        }
    }
    var body: some View {
        VStack(spacing: 0) {
            if !model.loaded {
                ProgressView(model.loadingMessage).padding(16)
                if model.error != nil { Button(productText("重试", "Retry")) { Task { await model.bootstrap() } } }
            } else { nativeRows }
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
                        if model.createdInvitation["code"].string != nil { Text(value).font(.body.monospaced()).textSelection(.enabled) }
                        Button { model.copy(value, secret: true); model.invitationCopied = true } label: { Label(model.invitationCopied ? productText("邀请已复制", "Invitation copied") : productText("复制邀请", "Copy invitation"), systemImage: "doc.on.doc").frame(maxWidth: .infinity) }
                        Text(productText("邀请有效期为 10 分钟", "Invitations expire after 10 minutes")).font(.caption2).foregroundStyle(.secondary)
                        Text(productText("等待另一台电脑加入", "Waiting for the other computer")).font(.caption).foregroundStyle(.secondary)
                        DisclosureGroup(productText("另一台电脑连不上？", "Can't connect from the other computer?")) {
                            Text(productText("如果 macOS 询问是否允许 styx 接受传入连接，请亲自选择。允许后，在另一台电脑继续加入；拒绝后，可以关闭邀请，稍后再试。", "If macOS asks whether styx can accept incoming connections, make your choice in that system alert. After allowing it, continue joining on the other computer. If you decline, close this invitation and try later.")).font(.caption).foregroundStyle(.secondary)
                            Text(productText("没有出现提示时，请确认另一台电脑能访问所选网络地址。创建邀请不代表对方已经连通。", "If no alert appears, check that the other computer can reach the selected network address. An invitation does not confirm that connection.")).font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            } else {
                Button(productText("创建邀请", "Create invitation")) { model.beginDeviceInvitation() }
            }
            if let error = model.invitationError { Text(error).font(.caption).foregroundStyle(.red) }
            if model.invitationExpanded {
                Button(productText("关闭面板", "Close panel")) { model.closeDeviceInvitation() }
                Text(productText("已连接的电脑仍可使用。", "Connected computers remain available.")).font(.caption2).foregroundStyle(.secondary)
            }
        }.padding(10).accessibilityIdentifier("styx-invitation-content").disabled(model.busy)
    }
}

enum ProductTunnelAttempt: Equatable { case idle, connecting, failed, timedOut }
struct ProductTunnelStatus: View {
    @ObservedObject var model: ProductModel
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                if model.tunnelAttempt == .connecting { ProgressView().controlSize(.small) }
                else { Image(systemName: model.tunnelConnection == .connected ? "globe" : "exclamationmark.circle").foregroundStyle(model.tunnelConnection == .connected ? Color.green : Color.secondary) }
                Text(model.tunnelFeedback).font(.callout)
            }.accessibilityElement(children: .combine)
            if model.tunnelAttempt == .failed || model.tunnelAttempt == .timedOut || model.tunnelConnection == .unavailable {
                Text(productText("请检查网络；也可以编辑 Tunnel ID 和运行密钥后再试。", "Check the network, or edit the Tunnel ID and runtime key, then retry.")).font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}
