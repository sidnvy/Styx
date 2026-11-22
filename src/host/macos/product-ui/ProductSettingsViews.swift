import AppKit
import SwiftUI

struct ProductHostCapabilitySettings: View {
    @ObservedObject var model: ProductModel
    var body: some View {
        if model.status["capabilities"] != .null {
            ForEach(["exec", "browser", "computer"], id: \.self) { name in
                Toggle(isOn: Binding(
                    get: { model.status["capabilities"]["configured"][name].bool },
                    set: { model.setHostCapability(name, enabled: $0) }
                )) {
                    ProductCapabilityLabel(kind: name == "exec" ? .cli : name == "browser" ? .browser : .computer)
                }.disabled(model.busy).accessibilityIdentifier("styx-capability-" + name)
            }
            Text(productText("关闭一项能力会停止它的任务，其他能力保持运行。", "Turning off a capability stops its tasks. Other capabilities keep running.")).font(.caption).foregroundStyle(.secondary)
            if !model.status["capabilities"]["applied"].bool {
                Text(productText("设置尚未完全生效，请刷新状态查看。", "The settings have not fully applied. Refresh to check their status.")).foregroundStyle(.secondary)
            }
        } else {
            Text(productText("完成本机设置并连接后，可在这里更改能力。", "Finish setup and connect this computer to change its capabilities here.")).font(.caption).foregroundStyle(.secondary)
        }
    }
}

struct ProductPluginCompatibilityNote: View {
    var body: some View {
        DisclosureGroup(productText("上传方式与兼容性", "Upload availability and compatibility")) {
            Text(productText("已复现 ZIP 插件安装后图标被 ChatGPT 占位图替换。请使用 Custom MCP → Tunnel，并单独上传 Styx 图标。ZIP 导出仅保留给高级用途，不作为推荐安装方式。", "ZIP-installed plugins can replace the Styx logo with a ChatGPT placeholder. Use Custom MCP → Tunnel and upload the Styx icon separately. ZIP export remains available for advanced use and is not the recommended installation path."))
        }.font(.caption).foregroundStyle(.secondary)
    }
}

struct ProductSettingsView: View {
    @ObservedObject var model: ProductModel
    weak var controller: ProductWindowController?
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
                }.padding(24).frame(maxWidth: .infinity, alignment: .leading)
            }.background(Color(nsColor: .windowBackgroundColor))
                .onAppear { proxy.scrollTo(model.settingsSection, anchor: .top) }
                .onChange(of: model.settingsNavigationID) { _ in proxy.scrollTo(model.settingsSection, anchor: .top) }
        }
        }.safeAreaInset(edge: .bottom, spacing: 0) {
            if let error = model.error ?? model.observationError {
                VStack(alignment: .leading, spacing: 8) {
                    Divider()
                    Text(error).font(.callout).foregroundStyle(.red).textSelection(.enabled)
                    Button(productText("重新检查", "Check again")) { Task { await model.refresh() } }
                }.padding(.horizontal, 24).padding(.bottom, 16)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(nsColor: .windowBackgroundColor))
                    .accessibilityIdentifier("styx-settings-operation-error")
            }
        }.frame(minWidth: 640, minHeight: 500)
            .sheet(isPresented: $addComputer) {
                VStack(alignment: .leading, spacing: 16) {
                    Text(productText("添加电脑", "Add computer")).font(.title2.weight(.semibold))
                    ProductInvitationView(model: model)
                    HStack { Spacer(); Button(productText("完成", "Done")) { model.closeDeviceInvitation { addComputer = false } }.disabled(model.busy).accessibilityIdentifier("styx-invitation-done").keyboardShortcut(.cancelAction) }
                }.padding(24).frame(width: 460)
            }
            .onReceive(NotificationCenter.default.publisher(for: NSWindow.willCloseNotification)) { notification in
                guard let window = notification.object as? NSWindow,
                      window.identifier?.rawValue == "Styx.SettingsWindow" else { return }
                addComputer = false
            }
            .task(id: model.settingsVisible || model.onboardingVisible) {
                if model.settingsVisible || model.onboardingVisible { await model.observePresentation() }
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
                    .disabled(!model.loginChangeAllowed || model.busy)
                if let notice = model.loginNotice {
                    Text(notice).font(.caption).foregroundStyle(.secondary)
                    Button(productText("登录项设置…", "Login Items settings…")) { model.openLoginSettings() }
                }
                Text(productText("关闭窗口后，Styx 会在菜单栏继续运行。退出 Styx 后，ChatGPT 将无法使用这台电脑。", "Styx keeps running in the menu bar when you close a window. Quitting Styx makes this computer unavailable to ChatGPT.")).font(.caption).foregroundStyle(.secondary)
            }
            Section { LabeledContent(productText("版本", "Version"), value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—") }

            if model.nativeSupportsOperation("retireRole") {
                Button(productText("更改这台电脑的角色…", "Change this computer's role…")) { model.nativeChangeRole() }.disabled(model.busy)
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
    private var local: some View {
        VStack(alignment: .leading, spacing: 16) {
            Section(productText("允许 ChatGPT 在这台电脑上做什么", "What ChatGPT can do on this computer")) {
                ProductHostCapabilitySettings(model: model)
            }
            if model.computerApproved {
                Section(productText("系统权限", "System permissions")) {
                    permission(productText("辅助功能", "Accessibility"), model.axGranted, false)
                    permission(productText("屏幕录制", "Screen Recording"), model.screenGranted, true)
                }
            }
            if model.nativeCanCreateLocal || model.nativeCanResumeLocal {
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
        GroupBox(productText("这台 Mac", "This Mac")) {
            VStack(alignment: .leading, spacing: 16) {
                Label(model.localIndicator.label, systemImage: "desktopcomputer")
                if model.status["enrollment"]["status"].string == "awaiting_approval" {
                    Text(productText("正在完成加入。检查原申请的结果不会重新发送配对请求。", "Joining is still in progress. Checking the original result does not send another pairing request.")).font(.callout)
                    HStack {
                        if model.nativeSupportsOperation("claimJoin") {
                            Button(productText("检查加入结果", "Check join result")) { model.nativeClaim() }.disabled(model.busy)
                        }
                        if model.nativeSupportsOperation("retireRole") {
                            Button(productText("取消加入…", "Cancel joining…")) { model.nativeChangeRole() }.disabled(model.busy)
                        }
                    }
                } else if model.status["enrollment"]["status"].string == "rejected" {
                    Text(productText("管理电脑拒绝了此次申请，未授予访问权限。请更改这台电脑的角色，再使用新邀请加入。", "The Gateway rejected this request. No access was granted. Change this computer's role, then join with a new invitation.")).font(.callout)
                } else if model.status["foreground"]["error"].string == "gateway_wss_admission_refused" {
                    Text(productText("网关拒绝了这台电脑的访问。请更改这台电脑的角色并重新配对。", "The Gateway refused this computer's access. Change this computer's role to pair again.")).font(.callout)
                }
                if model.status["admission_fenced"].bool || model.status["gateway"]["admission_fenced"].bool {
                    Text(productText("上次操作的结果尚未确认。请刷新状态查看；现有设置已保留。", "The last operation is unconfirmed. Refresh to review its state; existing settings are retained.")).font(.callout)
                }
                if model.status["foreground"]["computerStartupError"].string != nil {
                    Text(productText("Computer Use 未能启动。请正常退出 Styx 后重新打开。", "Computer Use could not start. Quit Styx normally, then reopen it.")).font(.callout)
                }
                if model.localIndicator != .connected && model.status["foreground"]["status"].string != "started" && model.nativeSupportsOperation("connect") {
                    Button(productText("重新连接", "Reconnect")) { model.resumeForeground() }.disabled(model.busy || model.status["admission_fenced"].bool)
                }
                local
            }.padding(8)
        }
        if let notice = model.nativeLanJoinNotice { Text(notice).font(.callout).textSelection(.enabled) }
        if model.status["gateway"] == .null {
            Label(productText("由管理电脑管理电脑连接", "Computer connections are managed on the main computer"), systemImage: "link")
        } else {
            Button(productText("添加电脑", "Add computer")) { addComputer = true; model.beginDeviceInvitation() }
                .accessibilityIdentifier("styx-settings-add-computer").disabled(model.busy)
            ForEach(model.devices.filter { !$0.isLocal }) { device in
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack { Label(device.label, systemImage: device.platformSymbol); Spacer(); ProductConnectionDot(state: device.indicator) }
                        Text(device.version.map { device.indicator.label + " · v" + $0 } ?? device.indicator.label).font(.caption).foregroundStyle(.secondary)
                        HStack {
                            Spacer()
                            Button(productText("移除这台电脑", "Remove computer"), role: .destructive) { model.revokeDevice(device) }.disabled(model.busy)
                        }
                    }.padding(8)
                }
            }
        }
    }
    private var chat: some View { ProductNativeChatView(model: model) }
}

// The same field guide is used by first-run and Settings. All external setup
// stays with the user; these buttons only open ChatGPT, copy an ID or save art.
struct ProductChatGPTConnectionSteps: View {
    @ObservedObject var model: ProductModel
    var identifierPrefix = "styx-custom-mcp"
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(productText("一个 Gateway 只需添加一个 Styx 插件；Windows、Mac 和 Linux Host 加入同一 Gateway 后共用它。", "Add one Styx plugin for each Gateway. Windows, Mac and Linux Hosts that join it use that same connection.")).font(.callout).foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 6) {
                Text(productText("1. 打开 ChatGPT 插件页", "1. Open ChatGPT Plugins")).font(.headline)
                Text(productText("使用目标账号和工作区。已有这个 Gateway 的 Styx 连接时直接复用；首次添加时，点「添加 → 添加自定义 MCP 服务器」。", "Use the intended account and workspace. Reuse this Gateway’s existing Styx connection, or select Add → Add custom MCP server to add it for the first time."))
                Button(productText("打开 ChatGPT Plugins", "Open ChatGPT Plugins")) { model.openOfficial("https://chatgpt.com/plugins") }
                    .accessibilityIdentifier(identifierPrefix + "-open")
            }
            VStack(alignment: .leading, spacing: 6) {
                Text(productText("2. 按下表填写", "2. Enter these values")).font(.headline)
                LabeledContent(productText("名称 (Name)", "Name"), value: "Styx")
                LabeledContent(productText("连接 (Connection)", "Connection"), value: productText("隧道 (Tunnel)", "Tunnel"))
                HStack {
                    Text(productText("隧道 ID (Tunnel ID)", "Tunnel ID")).foregroundStyle(.secondary)
                    Spacer()
                    if model.connectionTunnelID.isEmpty {
                        Text(productText("先在管理电脑配置 Tunnel", "Configure the tunnel on the Gateway first")).font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text(model.connectionTunnelID).font(.system(.caption, design: .monospaced)).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                        Button(productText("复制 Tunnel ID", "Copy Tunnel ID")) { model.copy(model.connectionTunnelID) }
                    }
                }
                LabeledContent(productText("身份验证 (Authentication)", "Authentication"), value: productText("无身份验证（从默认的 OAuth 切换）", "No authentication (switch from default OAuth)"))
                Text(productText("运行密钥（Runtime API key）只保存在管理电脑的 Styx 中，不要填入 ChatGPT。页面下方也可以直接点选已关联的通道。", "Keep the runtime API key in Styx on the Gateway; do not enter it in ChatGPT. Associated tunnels also appear as quick-select chips below the Tunnel ID field.")).font(.caption).foregroundStyle(.secondary)
            }
            VStack(alignment: .leading, spacing: 6) {
                Text(productText("3. 保存并上传图标", "3. Save and upload the icon")).font(.headline)
                Text(productText("先保存 Styx PNG，再在 ChatGPT 的图标选择处上传这个文件。", "Save the Styx PNG, then upload that file using ChatGPT’s icon picker."))
                Button(productText("保存 Styx 图标…", "Save Styx icon…")) { model.saveBrandIcon() }.accessibilityIdentifier(identifierPrefix + "-save-icon")
            }
            VStack(alignment: .leading, spacing: 6) {
                Text(productText("4. 创建并使用 Styx", "4. Create and use Styx")).font(.headline)
                Text(productText("阅读页面提示，选择 I understand and want to continue，再点 Create as a plugin，按页面提示完成安装或 Connect。在聊天中选择 @Styx，发送“列出我的 Styx 电脑”，确认显示已加入的电脑。", "Review the notice, select I understand and want to continue, then Create as a plugin. Follow the page to install or Connect. Select @Styx in a chat and ask it to list your Styx computers."))
                Text(productText("如果没有添加入口，请检查开发者模式和工作区权限。设置由你在 ChatGPT 中完成，Styx 不会自动创建插件。", "If Add is unavailable, check Developer mode and workspace permissions. You complete setup in ChatGPT; Styx does not create a plugin automatically.")).font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

// Both first-run and Settings use the same Rust-backed connection editor.
struct ProductNativeChatView: View {
    @ObservedObject var model: ProductModel
    @State private var editTunnel = false
    @State private var editPackage = false
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(productText("ChatGPT 中的 Styx", "Styx in ChatGPT")).font(.headline)
            if model.nativeSupportsOperation("tunnelSave") {
                Text(productText("只在管理电脑（Gateway）上配置 Tunnel。先等待连接就绪，再按下面四步添加到 ChatGPT。", "Configure the tunnel only on the Gateway. Wait for it to connect, then follow the four steps below."))
                ProductTunnelStatus(model: model)
                Button(productText("配置 Tunnel…", "Configure Tunnel…")) { editTunnel = true }.disabled(model.busy)
                Text(productText("保存时会短暂断开本 App 管理的连接，随后自动恢复。请先完成正在运行的任务。", "Saving briefly pauses connections managed by this App, then reconnects. Finish active tasks first.")).font(.caption)
                ProductChatGPTConnectionSteps(model: model, identifierPrefix: "styx-native-custom-mcp")
            } else if model.status["configuration"] != .null {
                Text(productText("这台 Mac 作为 Host 加入管理电脑（Gateway），无需配置自己的 Tunnel 或另建 ChatGPT 插件。", "This Mac joins a Gateway as a Host. It does not need its own tunnel or a separate ChatGPT plugin."))
                Text(productText("请在管理电脑完成一次 ChatGPT 设置，然后在已有的 Styx 聊天中选择这台 Mac。所有已加入的电脑共用同一个 Styx 连接。", "Complete ChatGPT setup once on the Gateway, then choose this Mac in a chat using the existing Styx plugin. All joined computers share that connection."))
                Button(productText("打开 ChatGPT Plugins", "Open ChatGPT Plugins")) { model.openOfficial("https://chatgpt.com/plugins") }
            } else {
                Text(productText("先完成这台 Mac 的设置。已有管理电脑（Gateway）时选择加入，Tunnel 和 ChatGPT 插件在管理电脑设置一次即可。", "Finish setting up this Mac first. If you already have a Gateway, join it; configure the tunnel and ChatGPT plugin once on that Gateway."))
                Button(productText("打开 ChatGPT Plugins", "Open ChatGPT Plugins")) { model.openOfficial("https://chatgpt.com/plugins") }
            }
            DisclosureGroup(productText("高级：ZIP 导出", "Advanced: ZIP export")) {
                ProductPluginCompatibilityNote()
                if model.nativeSupportsOperation("pluginRead") {
                    Text(productText("预览并导出这台管理电脑的插件名称、描述和图标。保存后在 ChatGPT 更新已有插件。", "Preview and export this hub’s plugin name, descriptions and icon. Then update the existing plugin in ChatGPT."))
                    Button(productText("名称、图标与插件 ZIP…", "Name, icon and plugin ZIP…")) {
                        model.perform {
                            let current = try await model.client.native("pluginRead")["plugin"]
                            model.plugin = current
                            model.pluginIdentity = current["selection"]["pluginId"].string ?? "styx"
                            model.pluginName = current["presentation"]["displayName"].string ?? "Styx"
                            model.pluginDescription = current["presentation"]["shortDescription"].string ?? ""
                            model.pluginLongDescription = current["presentation"]["longDescription"].string ?? ""
                            model.pluginIcon = current["presentation"]["icon"]
                            editPackage = true
                        }
                    }.disabled(model.busy)
                }
            }
        }
        .sheet(isPresented: $editTunnel) { ProductTunnelEditor(model: model) }
        .sheet(isPresented: $editPackage) { ProductPackageEditor(model: model) }
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
    @State private var longDescription = ""
    @State private var priorIcon: ProductJSON = .null
    @State private var exported = false
    var body: some View {
        ScrollView { VStack(alignment: .leading, spacing: 16) {
            Text(productText("名称、图标与插件 ZIP", "Name, icon and plugin ZIP")).font(.headline)
            VStack(alignment: .leading, spacing: 5) { Text(productText("名称", "Name")).font(.caption); TextField("Styx", text: $name) }
            VStack(alignment: .leading, spacing: 5) {
                Text(productText("简短介绍", "Short description")).font(.caption)
                TextField(productText("显示在插件列表中的介绍", "Description shown in the plugin list"), text: $description)
                if description.unicodeScalars.count > 30 { Text(productText("最多 30 个字符。", "Use up to 30 characters.")).font(.caption).foregroundStyle(.red) }
            }
            HStack {
                if let data = model.pluginIcon["dataBase64"].string.flatMap({ Data(base64Encoded: $0) }), let image = NSImage(data: data) {
                    Image(nsImage: image).resizable().scaledToFit().frame(width: 96, height: 96)
                } else { ProductBrand(size: 96) }
                Text(productText("插件图标", "Plugin icon")); Spacer()
                Button(productText("选择图片", "Choose image")) { model.selectIcon() }
            }
            Button(productText("恢复 Styx 默认图标", "Restore Styx logo")) { model.pluginIcon = .null; model.preparePluginDraft(); model.observePluginDraftEdit() }
            HStack {
                if let data = model.pluginIcon["dataBase64"].string.flatMap({ Data(base64Encoded: $0) }), let image = NSImage(data: data) {
                    Image(nsImage: image).resizable().scaledToFit().frame(width: 24, height: 24)
                }
                Text(productText("大图与小图使用同一张图片", "The large and small icons use the same image")).font(.caption)
            }
            Text(productText("完整描述", "Full description"))
            TextEditor(text: $longDescription).frame(height: 78)
            TextField(productText("插件身份", "Plugin identity"), text: $model.pluginIdentity).disabled(model.plugin["profileSaved"].bool)
            Text(productText("更新已有插件时，请保留其身份；更改显示名称不会更改此身份。", "Keep the existing plugin identity when updating. Changing the display name does not change its identity.")).font(.caption)
            Text(productText("PNG · 正方形 · 48–1024 像素 · 不超过 256 KB", "Square PNG · 48–1024 pixels · up to 256 KB")).font(.caption).foregroundStyle(.secondary)
            Text(productText("ZIP 包含技能和展示信息，但安装后图标可能被替换。推荐返回连接指引，使用 Custom MCP 并单独上传图标。", "The ZIP contains skills and presentation metadata, but its icon may be replaced after installation. Use the Custom MCP connection guide and upload the icon separately.")).font(.caption).foregroundStyle(.secondary)
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
                        model.pluginLongDescription = model.plugin["presentation"]["longDescription"].string ?? ""
                        model.pluginIdentity = model.plugin["selection"]["pluginId"].string ?? "styx"
                        model.pluginIcon = model.plugin["presentation"]["icon"]
                        model.observePluginDraftEdit()
                    }
                    dismiss()
                }.keyboardShortcut(.cancelAction)
                Spacer()
                if model.busy { ProgressView().controlSize(.small) }
                Button(productText("导出 ZIP", "Export ZIP")) {
                    model.pluginName = name; model.pluginDescription = description; model.pluginLongDescription = longDescription; model.observePluginDraftEdit()
                    model.exportPluginPackage()
                }.buttonStyle(.borderedProminent)
                    .disabled(model.busy || name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || name.unicodeScalars.count > 64 || description.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || description.unicodeScalars.count > 30 || longDescription.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || longDescription.unicodeScalars.count > 2000 || model.connectionTunnelID.isEmpty)
            }
        }.textFieldStyle(.roundedBorder).padding(24) }.frame(width: 520, height: 720)
            .onAppear { name = model.pluginName; description = model.pluginDescription; longDescription = model.pluginLongDescription.isEmpty ? model.plugin["presentation"]["longDescription"].string ?? "" : model.pluginLongDescription; priorIcon = model.pluginIcon; model.preparePluginDraft() }
            .onChange(of: model.exportCompletionID) { _ in exported = model.exportedPluginURL != nil }
            .interactiveDismissDisabled(model.busy)
    }
}
