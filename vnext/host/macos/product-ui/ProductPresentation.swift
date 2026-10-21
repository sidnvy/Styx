import AppKit
import SwiftUI

enum ProductSettingsSection: String, CaseIterable, Identifiable {
    case general, local, computers, chat
    var id: String { rawValue }
    var title: String {
        switch self {
        case .general: return productText("通用", "General")
        case .local: return productText("这台 Mac", "This Mac")
        case .computers: return productText("电脑", "Computers")
        case .chat: return "ChatGPT"
        }
    }
    var symbol: String {
        switch self {
        case .general: return "gearshape"
        case .local: return "laptopcomputer"
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
        case .unknown: return productText("状态尚未确认", "Status not observed")
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
        guard loaded, error == nil else { return .unknown }
        guard localPrepared else { return .attention }
        switch status["foreground"]["status"].string {
        case "connected", "using_service": return .connected
        case "not_running": return .offline
        case "needs_attention", "stopping": return .attention
        default: return .unknown
        }
    }
    var chatIndicator: ProductConnectionIndicator {
        if error != nil { return .unknown }
        if tunnelConnection == .connected && accepted && !plugin["contextChanged"].bool { return .connected }
        if tunnelConnection == .notConfigured { return .offline }
        return .attention
    }
    var chatMenuTitle: String {
        if chatIndicator == .connected { return "ChatGPT" }
        if tunnelConnection == .notConfigured { return productText("连接 ChatGPT", "Connect ChatGPT") }
        if tunnelConnection == .connected { return productText("完成 ChatGPT 连接", "Finish ChatGPT setup") }
        return productText("修复 ChatGPT 连接", "Fix ChatGPT connection")
    }
    var hasSavedRuntimeKey: Bool {
        ["configured", "running", "interrupted"].contains(journey["tunnel"]["status"].string ?? "")
    }
    func beginDeviceInvitation() {
        invitationExpanded = true
        guard createdInvitation == .null else { return }
        perform { [self] in
            ingress = try await client.write("device-ingress/plan", [:])["ingress"]
            guard ingress["blockers"].array.isEmpty else { return }
            createdInvitation = try await client.write("pairing-link/create", ["authorize": .bool(true)])
        }
    }
    func approveSelectedIdentity() {
        fingerprintConfirmation = selectedPending["fingerprint"].string ?? ""
        approveComputer = selectedPending["computer_requested"].bool
        approveBrowser = selectedPending["browser_requested"].bool
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
                ProductMenuRow(title: productText("这台 Mac", "This Mac"), symbol: "laptopcomputer", state: model.localIndicator, disclosure: true) { controller?.showSettings(.local) }
                Divider().padding(.vertical, 5)
                if model.joined {
                    ProductMenuRow(title: productText("主台连接", "Main computer"), symbol: "link", state: model.localIndicator, disclosure: true) { controller?.showSettings(.computers) }
                } else {
                    Text(productText("电脑", "Computers")).font(.system(size: 11, weight: .medium)).foregroundStyle(.secondary).frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 10).padding(.vertical, 5)
                    ForEach(model.devices) { device in
                        ProductMenuRow(title: device.label, symbol: device.platform == "win32" ? "desktopcomputer" : "laptopcomputer", state: model.menuObservationFailed ? .unknown : device.indicator, disclosure: true) {
                            model.selectedDeviceID = device.id; controller?.showSettings(.computers)
                        }
                    }
                    ProductMenuRow(title: productText("添加电脑", "Add computer"), symbol: "plus") {
                        if model.invitationExpanded { model.invitationExpanded = false }
                        else { model.beginDeviceInvitation() }
                    }.foregroundStyle(Color.accentColor)
                    if model.invitationExpanded { invitation }
                    ForEach(Array(model.pending.enumerated()), id: \.offset) { _, request in
                        VStack(alignment: .leading, spacing: 8) {
                            Text(productText("连接", "Connect") + " " + (request["label"].string ?? productText("新电脑", "New computer")) + "?").font(.headline)
                            Text(productText("请确认这是你刚刚邀请的电脑。", "Confirm this is the computer you just invited.")).font(.caption).foregroundStyle(.secondary)
                            DisclosureGroup(productText("设备身份", "Device identity")) { Text(request["fingerprint"].string ?? "").font(.system(.caption2, design: .monospaced)).textSelection(.enabled) }
                            Button(productText("连接", "Connect")) { model.selectedPending = request; model.approveSelectedIdentity() }.buttonStyle(.borderedProminent)
                        }.padding(10)
                    }
                    Divider().padding(.vertical, 5)
                    ProductMenuRow(title: model.chatMenuTitle, symbol: "globe", state: model.chatIndicator, disclosure: true) { controller?.showSettings(.chat) }
                }
                if model.localIndicator != .connected && !model.localPrepared {
                    ProductMenuRow(title: productText("继续设置", "Continue setup"), symbol: "arrow.right") { controller?.showOnboarding() }
                }
            }
            Divider().padding(.vertical, 5)
            ProductMenuRow(title: productText("设置", "Settings"), shortcut: "⌘,") { controller?.showSettings(.general) }.keyboardShortcut(",", modifiers: .command)
            Divider().padding(.vertical, 3)
            ProductMenuRow(title: productText("退出 Styx", "Quit Styx"), shortcut: "⌘Q", action: quit).keyboardShortcut("q", modifiers: .command)
        }.padding(8).frame(width: 332)
            .task { await model.bootstrap(); await model.refreshMenu() }
            .task(id: model.menuVisible) { guard model.menuVisible else { return }; while !Task.isCancelled { try? await Task.sleep(nanoseconds: 5_000_000_000); if !Task.isCancelled { await model.refreshMenu() } } }
    }
    @ViewBuilder private var invitation: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let value = model.createdInvitation["link"].string {
                Text(productText("在另一台电脑打开邀请链接", "Open the invitation on the other computer")).font(.caption)
                Button { model.copy(value, secret: true); copied = true } label: { Label(copied ? productText("邀请已复制", "Invitation copied") : productText("复制邀请链接", "Copy invitation link"), systemImage: "doc.on.doc").frame(maxWidth: .infinity) }
                Text(productText("邀请将在 10 分钟后过期", "Invitation expires in 10 minutes")).font(.caption2).foregroundStyle(.secondary)
            } else if model.busy { ProgressView().controlSize(.small) }
            else if !model.ingress["blockers"].array.isEmpty {
                Text(productText("当前连接入口还不能供另一台电脑访问。", "The current connection entry is not reachable from another computer.")).font(.caption)
                Button(productText("查看连接设置", "Review connection settings")) { controller?.showSettings(.computers) }
            } else if model.error != nil {
                Text(productText("邀请未能生成。请重试。", "The invitation could not be created. Try again.")).font(.caption)
                Button(productText("重试", "Retry")) { model.beginDeviceInvitation() }
            }
        }.padding(10)
    }
    @State private var copied = false
}
extension ProductModel {
    func refreshMenu() async {
        #if STYX_TESTING
        if testSuppressObservations { return }
        #endif
        guard !busy, loaded, deployment != nil else { return }
        await refresh()
        guard error == nil else { menuObservationFailed = true; return }
        guard !busy, !joined else { return }
        // A read operation against the current owner; never creates pairing or
        // infers online from desired configuration.
        do {
            devices = try await client.write("devices", [:])["devices"].array.compactMap(ProductDevice.init)
            if invitationExpanded { pending = try await client.write("pending/list", ["authorize": .bool(true)])["pending"].array }
        } catch { menuObservationFailed = true; return }
        menuObservationFailed = false
    }
}
