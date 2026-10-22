import AppKit
import SwiftUI

struct ProductPluginCompatibilityNote: View {
    var body: some View {
        DisclosureGroup(productText("上传方式与兼容性", "Upload availability and compatibility")) {
            Text(productText("上传入口取决于 ChatGPT 账号或工作区权限。目前已验证的是用 ZIP 更新已有网页插件；新账号首次仅通过 ZIP 安装尚未完成验证。", "Upload availability depends on your ChatGPT account or workspace. Updating an existing web plugin with a ZIP has been tested; a first installation using only a ZIP on a new account has not yet been verified."))
        }.font(.caption).foregroundStyle(.secondary)
    }
}

struct ProductSettingsView: View {
    @ObservedObject var model: ProductModel
    weak var controller: ProductWindowController?
    @State private var editTunnel = false
    @State private var editPackage = false
    @State private var setupChat = false
    @State private var tryChat = false
    @State private var addComputer = false
    var body: some View {
        GeometryReader { viewport in
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    settingsGroup(.computers) { computers }
                    settingsGroup(.chat) { chat }
                    settingsGroup(.general) { general }
                        .frame(minHeight: max(0, viewport.size.height - 48), alignment: .top)
                    if let error = model.error ?? model.observationError {
                        Text(error).font(.callout).foregroundStyle(.red).textSelection(.enabled)
                        Button(productText("重新检查", "Check again")) { Task { await model.refresh() } }
                    }
                }.padding(24).frame(maxWidth: .infinity, alignment: .leading)
            }.background(Color(nsColor: .windowBackgroundColor))
                .onAppear { proxy.scrollTo(model.settingsSection, anchor: .top) }
                .onChange(of: model.settingsNavigationID) { _ in proxy.scrollTo(model.settingsSection, anchor: .top) }
        }
        }.frame(minWidth: 640, minHeight: 500)
            .sheet(isPresented: $addComputer) {
                VStack(alignment: .leading, spacing: 16) {
                    Text(productText("添加电脑", "Add computer")).font(.title2.weight(.semibold))
                    ProductInvitationView(model: model)
                    ProductPendingIdentities(model: model)
                    HStack { Spacer(); Button(productText("完成", "Done")) { model.closeDeviceInvitation { addComputer = false } }.disabled(model.busy).accessibilityIdentifier("styx-invitation-done").keyboardShortcut(.cancelAction) }
                }.padding(24).frame(width: 460)
            }
            .sheet(isPresented: $editTunnel) { ProductTunnelEditor(model: model) }
            .sheet(isPresented: $editPackage) { ProductPackageEditor(model: model) }
            .sheet(isPresented: $setupChat) {
                ProductView(model: model, controller: controller)
                    .frame(width: 660, height: 640)
                    .toolbar { Button(productText("完成", "Done")) { setupChat = false } }
            }
            .sheet(isPresented: $tryChat) {
                VStack(alignment: .leading, spacing: 16) {
                    ScrollView { ProductTryoutView(model: model, controller: controller).padding(24) }
                    HStack { Spacer(); Button(productText("关闭", "Close")) { tryChat = false }.accessibilityIdentifier("styx-tryout-close").keyboardShortcut(.cancelAction) }.padding([.horizontal, .bottom], 24)
                }.frame(width: 580, height: 560)
            }
            .onReceive(NotificationCenter.default.publisher(for: NSWindow.willCloseNotification)) { notification in
                guard let window = notification.object as? NSWindow,
                      window.identifier?.rawValue == "Styx.SettingsWindow" else { return }
                editTunnel = false; editPackage = false; setupChat = false; tryChat = false; addComputer = false
            }
            .task(id: model.settingsVisible) {
                if model.settingsVisible { await model.observePresentation() }
            }
    }
    private func settingsGroup<Content: View>(_ section: ProductSettingsSection, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 14) {
            Label(section.title, systemImage: section.symbol).font(.title2.weight(.semibold))
            content()
        }.padding(.top, 12).frame(maxWidth: .infinity, alignment: .leading).id(section)
    }
    private var general: some View {
        VStack(alignment: .leading, spacing: 16) {
            Section {
                LabeledContent(productText("语言", "Language"), value: productText("跟随系统", "System default"))
                Button(productText("语言与地区", "Language & Region")) { model.openOfficial("x-apple.systempreferences:com.apple.Localization-Settings.extension") }
            }
            Section {
                Toggle(productText("登录时启动 Styx", "Open Styx at login"), isOn: Binding(get: { model.loginEnabled }, set: { model.setLoginEnabled($0) }))
                    .disabled(!model.loginPreferenceKnown || model.busy)
                Text(productText("关闭窗口后，Styx 会在菜单栏继续运行。退出 Styx 后，ChatGPT 将无法使用这台电脑。", "Styx keeps running in the menu bar when you close a window. Quitting Styx makes this computer unavailable to ChatGPT.")).font(.caption).foregroundStyle(.secondary)
            }
            Section { LabeledContent(productText("版本", "Version"), value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—") }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
    private var local: some View {
        VStack(alignment: .leading, spacing: 16) {
            Section(productText("允许 ChatGPT 在这台电脑上做什么", "What ChatGPT can do on this computer")) {
                ProductCapabilityLabel(kind: .cli)
                Toggle(isOn: $model.computer) { ProductCapabilityLabel(kind: .computer) }.disabled(model.joined)
                Toggle(isOn: $model.browser) { ProductCapabilityLabel(kind: .browser) }.disabled(model.joined)
                if !model.joined {
                    Button(productText("应用更改", "Apply changes")) { model.updateCapabilities() }.disabled(model.busy)
                } else {
                    Text(productText("这些功能在加入时选定。如需更改，请在发出邀请的电脑上管理。", "These features were selected when joining. Manage changes on the computer that sent the invitation.")).font(.caption).foregroundStyle(.secondary)
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
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
    private func permission(_ label: String, _ granted: Bool, _ screen: Bool) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Label(label, systemImage: screen ? "record.circle" : "accessibility")
                Text(screen ? productText("让 Styx 查看屏幕内容", "Let Styx view the screen") : productText("让 Styx 点击和输入", "Let Styx click and type")).font(.caption).foregroundStyle(.secondary)
            }; Spacer()
            Text(granted ? productText("已允许", "Allowed") : productText("未允许", "Not allowed")).foregroundStyle(.secondary)
            Button(granted || model.permissionWasRequested(screen) ? productText("系统设置…", "System Settings…") : productText("允许…", "Allow…")) { granted || model.permissionWasRequested(screen) ? model.openPermission(screen) : model.requestPermission(screen) }
        }
    }
    @ViewBuilder private var computers: some View {
        GroupBox(productText("这台 Mac", "This Mac")) { local.padding(8) }
        if model.joined {
            Label(productText("由管理电脑管理电脑连接", "Computer connections are managed on the main computer"), systemImage: "link")
        } else {
            Button(productText("添加电脑", "Add computer")) { addComputer = true; model.beginDeviceInvitation() }
                .accessibilityIdentifier("styx-settings-add-computer").disabled(model.busy)
            ForEach(model.devices.filter { !$0.isLocal }) { device in
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack { Label(device.label, systemImage: device.platform == "win32" ? "desktopcomputer" : "laptopcomputer"); Spacer(); ProductConnectionDot(state: device.indicator) }
                        Text(device.indicator.label).font(.caption).foregroundStyle(.secondary)
                        HStack {
                            if !device.isDefault { Button(productText("设为默认", "Set as default")) { model.setDefault(device.id) }.disabled(model.busy) }
                            Spacer()
                            Button(productText("移除这台电脑", "Remove computer"), role: .destructive) { model.revokeDevice(device) }.disabled(model.busy)
                        }
                    }.padding(8)
                }
            }
            if !model.ingress["blockers"].array.isEmpty {
                Text(productText("暂时无法添加其他电脑：电脑之间的网络连接尚未配置。此版本暂不支持在 App 中完成这项配置。", "Other computers cannot be added until the network connection between them is configured. This version cannot configure it in the app.")).font(.callout).foregroundStyle(.secondary)
            }
        }
    }
    private var chat: some View {
        VStack(alignment: .leading, spacing: 16) {
            if model.joined {
                Label(productText("聊天连接由管理电脑管理", "Chat is managed on the main computer"), systemImage: "globe")
            } else {
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack { ProductConnectionDot(state: model.chatIndicator); Text(model.chatStatusTitle).font(.headline); Spacer() }
                        if model.tunnelConnection == .connected {
                            Text(model.chatNextStep).font(.callout).foregroundStyle(.secondary)
                        } else {
                            Text(productText("连接后，ChatGPT 才能通过 Styx 使用这台电脑。", "Connect to let ChatGPT use this computer through Styx.")).font(.callout).foregroundStyle(.secondary)
                            Button(model.tunnelConnection == .notConfigured ? productText("填写连接信息", "Enter connection details") : productText("重新连接", "Reconnect")) {
                                if model.tunnelConnection == .notConfigured { editTunnel = true } else { model.startTunnel() }
                            }.disabled(model.busy || model.tunnelAttempt == .connecting)
                        }
                    }.padding(8)
                }
                HStack {
                    Button(productText("试用 Styx", "Try Styx")) { tryChat = true }.accessibilityIdentifier("styx-settings-tryout")
                    if model.needsPluginSetup {
                        Button(productText("安装指引", "Installation guide")) { model.page = .chat; setupChat = true }
                    }
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
                Button(productText("编辑连接信息", "Edit connection details")) { editTunnel = true }.accessibilityIdentifier("styx-settings-edit-tunnel")
                Divider()
                Text(productText("ChatGPT 中的 Styx", "Styx in ChatGPT")).font(.headline)
                Text(productText("插件 ZIP 包含内置技能、连接配置、名称和图标。更改后，请在 ChatGPT 中更新已有 Styx。", "The plugin ZIP includes built-in skills, connection settings, its name and icon. After making changes, update the existing Styx in ChatGPT.")).font(.caption).foregroundStyle(.secondary)
                Button(productText("名称、图标与插件 ZIP…", "Name, icon and plugin ZIP…")) { editPackage = true }
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
                Button(productText("取消", "Cancel")) { key = ""; dismiss() }.accessibilityIdentifier("styx-tunnel-cancel").keyboardShortcut(.cancelAction).disabled(saving)
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
            Text(productText("名称、图标与插件 ZIP", "Name, icon and plugin ZIP")).font(.headline)
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
            Text(productText("保存后，在 ChatGPT 打开已有 Styx，选择上传新版本。名称、图标和技能会随 ZIP 一起更新。", "After saving, open the existing Styx in ChatGPT and upload a new version. The ZIP updates its name, icon and skills together.")).font(.caption).foregroundStyle(.secondary)
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
            ProductPluginCompatibilityNote()
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
