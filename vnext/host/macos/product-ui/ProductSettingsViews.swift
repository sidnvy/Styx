import AppKit
import SwiftUI

struct ProductSettingsView: View {
    @ObservedObject var model: ProductModel
    weak var controller: ProductWindowController?
    @State private var editTunnel = false
    @State private var editPackage = false
    @State private var setupChat = false
    var body: some View {
        NavigationSplitView {
            List(ProductSettingsSection.allCases, selection: Binding<ProductSettingsSection?>(get: { model.settingsSection }, set: { if let section = $0 { model.settingsSection = section } })) { item in
                Label(item.title, systemImage: item.symbol).tag(item)
            }.navigationSplitViewColumnWidth(min: 140, ideal: 156, max: 180)
        } detail: {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Text(model.settingsSection.title).font(.title2.weight(.semibold))
                    switch model.settingsSection {
                    case .general: general
                    case .computers: computers
                    case .chat: chat
                    }
                    if let error = model.error {
                        Text(error).font(.callout).foregroundStyle(.red).textSelection(.enabled)
                        Button(productText("重新检查", "Check again")) { Task { await model.refresh() } }
                    }
                }.padding(24).frame(maxWidth: .infinity, alignment: .leading)
            }.background(Color(nsColor: .windowBackgroundColor))
        }.frame(minWidth: 640, minHeight: 500)
            .sheet(isPresented: $editTunnel) { ProductTunnelEditor(model: model) }
            .sheet(isPresented: $editPackage) { ProductPackageEditor(model: model) }
            .sheet(isPresented: $setupChat) {
                ProductView(model: model, controller: controller, showPluginPackage: false)
                    .frame(width: 660, height: 640)
                    .toolbar { Button(productText("完成", "Done")) { setupChat = false } }
            }
            .onReceive(NotificationCenter.default.publisher(for: NSWindow.willCloseNotification)) { notification in
                guard let window = notification.object as? NSWindow,
                      window.identifier?.rawValue == "Styx.SettingsWindow" else { return }
                editTunnel = false; editPackage = false; setupChat = false
            }
            .task {
                await model.bootstrap(); await model.refreshMenu()
                while !Task.isCancelled {
                    try? await Task.sleep(nanoseconds: 3_000_000_000)
                    if !Task.isCancelled { await model.refreshMenu() }
                }
            }
    }
    private var general: some View {
        Form {
            Section {
                LabeledContent(productText("语言", "Language"), value: productText("跟随系统", "System default"))
                Button(productText("语言与地区", "Language & Region")) { model.openOfficial("x-apple.systempreferences:com.apple.Localization-Settings.extension") }
            }
            Section {
                Toggle(productText("登录时启动 Styx", "Open Styx at login"), isOn: Binding(get: { model.loginEnabled }, set: { model.setLoginEnabled($0) }))
                    .disabled(!model.loginPreferenceKnown || model.busy)
                Text(productText("关闭窗口后继续运行；选择“退出 Styx”才结束本次运行。", "Closing a window keeps Styx running. Choose Quit Styx to end this run.")).font(.caption).foregroundStyle(.secondary)
            }
            Section { LabeledContent(productText("版本", "Version"), value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—") }
        }.formStyle(.grouped)
    }
    private var local: some View {
        Form {
            Section(productText("能力", "Capabilities")) {
                Label("CLI", systemImage: "terminal")
                Toggle("Computer Use", isOn: $model.computer).disabled(model.joined)
                Toggle("Browser Automation", isOn: $model.browser).disabled(model.joined)
                if !model.joined {
                    Button(productText("应用更改", "Apply changes")) { model.updateCapabilities() }.disabled(model.busy)
                } else {
                    Text(productText("当前版本可在加入时选择能力；已加入设备的能力变更仍需主台同步。", "Choose capabilities when joining. Changes on joined devices still require synchronization with the main computer.")).font(.caption).foregroundStyle(.secondary)
                }
            }
            if model.computerApproved {
                Section(productText("系统权限", "System permissions")) {
                    permission(productText("辅助功能", "Accessibility"), model.axGranted, false)
                    permission(productText("屏幕录制", "Screen Recording"), model.screenGranted, true)
                }
            }
            if !model.localPrepared || model.foregroundRecoveryNeeded {
                Button(productText("继续设置", "Continue setup")) { controller?.showOnboarding() }
            }
        }.formStyle(.grouped)
    }
    private func permission(_ label: String, _ granted: Bool, _ screen: Bool) -> some View {
        HStack {
            Text(label); Spacer()
            Text(granted ? productText("已允许", "Allowed") : productText("未允许", "Not allowed")).foregroundStyle(.secondary)
            Button(productText("管理", "Manage")) { granted || model.permissionWasRequested(screen) ? model.openPermission(screen) : model.requestPermission(screen) }
        }
    }
    @ViewBuilder private var computers: some View {
        GroupBox(productText("这台 Mac", "This Mac")) { local.padding(8) }
        if model.joined {
            Label(productText("由主台管理电脑连接", "Computer connections are managed on the main computer"), systemImage: "link")
        } else {
            ForEach(model.devices.filter { !$0.isLocal }) { device in
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack { Label(device.label, systemImage: device.platform == "win32" ? "desktopcomputer" : "laptopcomputer"); Spacer(); ProductConnectionDot(state: device.indicator) }
                        Text(device.indicator.label).font(.caption).foregroundStyle(.secondary)
                        HStack {
                            if !device.isDefault { Button(productText("设为默认", "Set as default")) { model.setDefault(device.id) } }
                            Spacer()
                            Button(productText("移除这台电脑", "Remove computer"), role: .destructive) { model.revokeDevice(device) }
                        }
                    }.padding(8)
                }
            }
            Button(productText("添加电脑", "Add computer")) { controller?.showMenuInvitation?() }
            if !model.ingress["blockers"].array.isEmpty {
                Text(productText("当前入口仅能由本机访问。局域网入口的自动配置尚未接入此预览版；已有可达入口可继续邀请。", "The current entry is local-only. Automatic LAN entry preparation is not integrated in this preview. Invitations work with an existing reachable entry.")).font(.callout).foregroundStyle(.secondary)
            }
        }
    }
    private var chat: some View {
        VStack(alignment: .leading, spacing: 16) {
            if model.joined {
                Label(productText("聊天连接由主台管理", "Chat is managed on the main computer"), systemImage: "globe")
            } else {
                GroupBox {
                    VStack(spacing: 12) {
                        HStack { Text(productText("聊天验证", "Chat verification")); Spacer(); ProductConnectionDot(state: model.chatIndicator); Text(model.chatIndicator == .connected ? productText("已验证", "Verified") : productText("待验证", "Verification needed")).foregroundStyle(.secondary) }
                        ProductTunnelStatus(model: model)
                    }.padding(8)
                }
                HStack {
                    Button(model.tunnelConnection != .connected ? productText("修复连接", "Fix connection") : model.accepted ? productText("重新验证", "Verify again") : productText("继续连接 ChatGPT", "Continue ChatGPT setup")) { model.page = .chat; setupChat = true }
                    Button(productText("在 ChatGPT 中管理", "Manage in ChatGPT")) { model.openOfficial("https://chatgpt.com/plugins") }
                }
                Divider()
                Text(productText("连接资料", "Connection details")).font(.headline)
                if !model.connectionTunnelID.isEmpty {
                    HStack {
                        Text("Tunnel ID").foregroundStyle(.secondary)
                        Text(model.connectionTunnelID).font(.system(.caption, design: .monospaced)).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                        Button { model.copy(model.connectionTunnelID) } label: { Image(systemName: "doc.on.doc") }.help(productText("复制 Tunnel ID", "Copy Tunnel ID"))
                    }
                }
                Button(productText("编辑连接信息", "Edit connection details")) { editTunnel = true }
                Divider()
                DisclosureGroup(productText("高级", "Advanced")) {
                    Text(productText("ZIP 导入尚未完成账号兼容性验收。日常连接请使用“添加自建 MCP 服务器”。", "ZIP import compatibility is unverified. Use Add custom MCP server for normal setup.")).font(.caption).foregroundStyle(.secondary)
                    Button(productText("导出实验性插件包…", "Export experimental plugin package…")) { editPackage = true }
                }
            }
        }
    }
    private var tunnelTitle: String {
        switch model.tunnelConnection {
        case .connected: return productText("运行中", "Running")
        case .notConfigured: return productText("未设置", "Not configured")
        case .connecting: return productText("正在连接", "Connecting")
        case .stopped: return productText("已停止", "Stopped")
        case .unavailable: return productText("连接失败", "Connection failed")
        case .unknown: return productText("状态尚未确认", "Not observed")
        }
    }
}

struct ProductTunnelEditor: View {
    @ObservedObject var model: ProductModel
    @Environment(\.dismiss) private var dismiss
    @State private var tunnel = ""
    @State private var key = ""
    @State private var replaceKey = false
    @State private var reveal = false
    @State private var help = false
    @State private var attempted = false
    @State private var saving = false
    @State private var failure: String?
    private var tunnelError: String? { ProductTunnelInputPolicy.tunnelError(tunnel) }
    private var keyError: String? { ProductTunnelInputPolicy.keyError(key, saved: model.hasSavedRuntimeKey && !replaceKey) }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(productText("编辑连接信息", "Edit connection details")).font(.headline)
            Text(productText("从 OpenAI Platform 复制通道信息。", "Copy the connection details from OpenAI Platform.")).font(.callout).foregroundStyle(.secondary)
            DisclosureGroup(productText("如何获取这些信息", "Where to find these values"), isExpanded: $help) {
                VStack(alignment: .leading, spacing: 8) {
                    Text(productText("确认 Platform 组织，在 Tunnels 中创建或选择通道，并关联目标 ChatGPT 工作区。复制 Tunnel ID，并创建具备通道使用权限的 Runtime API key，返回此处粘贴。", "Select your Platform organization, create or select a tunnel in Tunnels, and associate the target ChatGPT workspace. Copy the Tunnel ID and create a runtime API key with permission to use tunnels, then return here.")).font(.caption)
                    Button(productText("打开 OpenAI Platform", "Open OpenAI Platform")) { model.openOfficial("https://platform.openai.com/settings/organization/tunnels") }
                }
            }
            VStack(alignment: .leading, spacing: 5) {
                Text("Tunnel ID").font(.caption).foregroundStyle(.secondary)
                TextField("tunnel_…", text: $tunnel).textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("styx-tunnel-id")
                if attempted, let message = tunnelError { Text(message).font(.caption).foregroundStyle(.red) }
            }
            if model.hasSavedRuntimeKey && !replaceKey {
                HStack {
                    Text(productText("运行密钥", "Runtime API key")); Spacer()
                    Text(productText("已保存", "Saved")).foregroundStyle(.secondary)
                    Button(productText("更换密钥", "Replace key")) { replaceKey = true }
                }
            } else {
                VStack(alignment: .leading, spacing: 5) {
                    Text(productText("运行密钥（Runtime API key）", "Runtime API key")).font(.caption).foregroundStyle(.secondary)
                    HStack {
                        if reveal { TextField(productText("粘贴运行密钥", "Paste runtime API key"), text: $key) }
                        else { SecureField(productText("粘贴运行密钥", "Paste runtime API key"), text: $key) }
                        Button(reveal ? productText("隐藏", "Hide") : productText("显示", "Show")) { reveal.toggle() }
                    }.textFieldStyle(.roundedBorder)
                    if attempted, let message = keyError { Text(message).font(.caption).foregroundStyle(.red) }
                }
            }
            Text(productText("更换 Tunnel ID 后，需要在 ChatGPT 中选择同一通道。", "After changing the Tunnel ID, select the same tunnel in ChatGPT.")).font(.caption).foregroundStyle(.secondary)
            if let failure = failure { Text(failure).font(.callout).foregroundStyle(.red) }
            HStack {
                Button(productText("取消", "Cancel")) { key = ""; dismiss() }.keyboardShortcut(.cancelAction).disabled(saving)
                Spacer()
                if saving { ProgressView().controlSize(.small) }
                Button(productText("保存并连接", "Save and connect")) { save() }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                    .disabled(saving || model.busy || attempted && (tunnelError != nil || keyError != nil))
            }
        }.padding(24).frame(width: 484)
            .onAppear { tunnel = model.connectionTunnelID }
            .onDisappear { key = "" }
            .interactiveDismissDisabled(saving)
    }
    private func save() {
        attempted = true; failure = nil
        guard tunnelError == nil, keyError == nil else { return }
        saving = true
        Task { @MainActor in
            do {
                try await model.saveTunnel(id: tunnel, newKey: replaceKey || !model.hasSavedRuntimeKey ? key : nil)
                key = ""; saving = false; dismiss()
            } catch {
                saving = false; model.tunnelAttempt = .failed
                failure = productText("连接未能完成。检查网络、密钥和通道权限后重试；输入仍保留。", "The connection did not complete. Check the network, key and tunnel permissions, then retry. Your entries are retained.")
            }
        }
    }
}
struct ProductPackageEditor: View {
    @ObservedObject var model: ProductModel
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var description = ""
    @State private var priorIcon: ProductJSON = .null
    @State private var exported = false
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(productText("插件包", "Plugin package")).font(.headline)
            VStack(alignment: .leading, spacing: 5) { Text(productText("名称", "Name")).font(.caption); TextField("Styx", text: $name) }
            VStack(alignment: .leading, spacing: 5) {
                Text(productText("简短介绍", "Short description")).font(.caption)
                TextField(productText("显示在插件列表中的介绍", "Description shown in the plugin list"), text: $description)
                if description.count > 30 { Text(productText("最多 30 个字符。", "Use up to 30 characters.")).font(.caption).foregroundStyle(.red) }
            }
            HStack {
                if let data = model.pluginIcon["dataBase64"].string.flatMap({ Data(base64Encoded: $0) }), let image = NSImage(data: data) {
                    Image(nsImage: image).resizable().scaledToFit().frame(width: 40, height: 40)
                } else { ProductBrand(size: 40) }
                Text(productText("插件图标", "Plugin icon")); Spacer()
                Button(productText("选择图片", "Choose image")) { model.selectIcon() }
            }
            Text(productText("PNG · 正方形 · 48–1024 像素 · 不超过 256 KB", "Square PNG · 48–1024 pixels · up to 256 KB")).font(.caption).foregroundStyle(.secondary)
            Text(productText("连接通道沿用已保存的 Tunnel ID。更改资料后，需重新导出并在 ChatGPT 中更新。", "The saved Tunnel ID is included automatically. After changes, export again and update the package in ChatGPT.")).font(.caption).foregroundStyle(.secondary)
            if let url = model.exportedPluginURL, exported {
                Label(productText("插件包已保存", "Plugin package saved"), systemImage: "doc.zipper")
                Text(url.path).font(.caption).textSelection(.enabled)
                HStack {
                    Button(productText("在 Finder 中显示", "Show in Finder")) { NSWorkspace.shared.activateFileViewerSelecting([url]) }
                    Button(productText("打开 ChatGPT", "Open ChatGPT")) { model.openOfficial("https://chatgpt.com/plugins") }
                }
            }
            if model.connectionTunnelID.isEmpty {
                Text(productText("先返回 ChatGPT 设置并保存连接信息，再导出插件包。", "Return to ChatGPT settings and save the connection details before exporting.")).font(.caption).foregroundStyle(.secondary)
            }
            Text(productText("Tunnel 插件包的账号导入兼容性仍待验收。导出不代表已安装或连接。", "Account import compatibility for tunnel packages remains unverified. Exporting does not install or connect the plugin.")).font(.caption).foregroundStyle(.secondary)
            if let error = model.error { Text(error).font(.caption).foregroundStyle(.red) }
            HStack {
                Button(exported ? productText("完成", "Done") : productText("取消", "Cancel")) {
                    if !exported {
                        model.pluginName = model.plugin["presentation"]["displayName"].string ?? "Styx"
                        model.pluginDescription = model.plugin["presentation"]["shortDescription"].string ?? productText("连接你的电脑", "Connect your computers")
                        model.pluginIcon = model.plugin["presentation"]["icon"]
                        model.observePluginDraftEdit()
                    }
                    dismiss()
                }.keyboardShortcut(.cancelAction)
                Spacer()
                if model.busy { ProgressView().controlSize(.small) }
                Button(productText("导出 ZIP", "Export ZIP")) {
                    model.pluginName = name; model.pluginDescription = description; model.observePluginDraftEdit()
                    model.exportPluginPackage()
                }.buttonStyle(.borderedProminent)
                    .disabled(model.busy || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || name.count > 64 || description.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || description.count > 30 || model.connectionTunnelID.isEmpty)
            }
        }.textFieldStyle(.roundedBorder).padding(24).frame(width: 484)
            .onAppear { name = model.pluginName; description = model.pluginDescription; priorIcon = model.pluginIcon; model.preparePluginDraft() }
            .onChange(of: model.exportCompletionID) { _ in exported = model.exportedPluginURL != nil }
            .interactiveDismissDisabled(model.busy)
    }
}
