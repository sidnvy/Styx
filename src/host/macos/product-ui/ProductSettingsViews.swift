import AppKit
import SwiftUI

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
                    .disabled(!model.loginChangeAllowed || model.busy)
                if let notice = model.loginNotice {
                    Text(notice).font(.caption).foregroundStyle(.secondary)
                    Button(productText("登录项设置…", "Login Items settings…")) { model.openLoginSettings() }
                }
                Text(model.nativeHost ? model.nativeQuitDescription : productText("关闭窗口后，Styx 会在菜单栏继续运行。退出 Styx 后，ChatGPT 将无法使用这台电脑。", "Styx keeps running in the menu bar when you close a window. Quitting Styx makes this computer unavailable to ChatGPT.")).font(.caption).foregroundStyle(.secondary)
            }
            Section { LabeledContent(productText("版本", "Version"), value: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "—") }
            if model.nativeHost {
                if model.nativeSupportsOperation("retireRole") {
                    Button(productText("更改这台电脑的角色…", "Change this computer's role…")) { model.nativeChangeRole() }.disabled(model.busy)
                }
                if model.nativeSupportsOperation("stageRuntime") || model.nativeSupportsOperation("recoverRuntimeUpdate") {
                    DisclosureGroup(productText("高级：运行组件更新", "Advanced: runtime component updates")) {
                        VStack(alignment: .leading, spacing: 8) {
                            Text(productText("使用此 App 随附的运行组件更新本机。身份、配对和设置会保留；完成后请重新连接。", "Update this computer with the runtime components included in this App. Identity, pairing and settings are kept; reconnect after updating.")).font(.caption).foregroundStyle(.secondary)
                            HStack {
                                Button(productText("准备更新", "Prepare update")) { model.nativeStageRuntime() }.disabled(model.busy || ![nil, "not_started", "committed"].contains(model.nativeRuntimeUpdate["status"].string))
                                Button(productText("更新组件…", "Update components…")) { model.nativeUpdateRuntime() }.disabled(model.busy || model.nativeRuntimeUpdate["status"].string != "staged")
                                Button(productText("检查更新状态", "Check update status")) { model.nativeCheckRuntimeUpdate() }.disabled(model.busy)
                                if model.nativeRuntimeUpdate["can_recover"] == .bool(true) {
                                    Button(productText("恢复更新", "Recover update")) { model.nativeRecoverRuntimeUpdate() }.disabled(model.busy)
                                }
                            }
                            Text(runtimeUpdateDescription).font(.caption).foregroundStyle(.secondary)
                        }.padding(.top, 8)
                    }
                }
                if model.nativeSupportsOperation("transferToService") || model.nativeHasServiceState {
                    ProductServiceSettings(model: model)
                }
            } else {
            if let notice = componentNotice {
                Label(notice, systemImage: "exclamationmark.circle")
                    .font(.callout).foregroundStyle(.secondary)
                    .accessibilityIdentifier("styx-component-update-notice")
            }
                HStack {
                    if ["publisher_changed", "update_available"].contains(model.status["components"]["host"]["status"].string ?? "") {
                        Button(productText("完成更新…", "Finish update…")) { model.finishPayloadUpdate() }.disabled(model.busy)
                    }
                    if ["awaiting_exit", "blocked", "needs_recovery", "applied_stopped"].contains(model.payloadUpdateStatus["status"].string ?? "") {
                        Button(productText("继续更新检查…", "Continue update check…")) { model.finishPayloadUpdate(resume: true) }.disabled(model.busy)
                    }
                    Button(productText("检查更新状态", "Check update status")) { model.checkPayloadUpdate() }.disabled(model.busy)
                    if ["preparing", "awaiting_exit", "blocked", "needs_recovery"].contains(model.payloadUpdateStatus["status"].string ?? "") {
                        Button(productText("取消尚未执行的更新", "Cancel pending update")) { model.cancelPayloadUpdate() }.disabled(model.busy)
                    }
                }
                if let state = model.payloadUpdateStatus["status"].string {
                    Text(state == "cancelled" ? productText("已取消，当前组件未更改。", "Cancelled. The current components were not changed.") : state == "applied_stopped" ? productText("组件已更新。", "Components updated.") : state == "rolled_back" ? productText("已恢复更新前的组件。", "Previous components restored.") : state == "not_started" ? productText("尚未开始更新。", "The update has not started.") : productText("更新尚未完成。可重试或取消尚未执行的更新；若已经开始更改，请使用更新窗口中的恢复入口。", "The update has not finished. Retry or cancel a pending update; if changes have started, use recovery in the updater window.")).font(.caption).foregroundStyle(.secondary)
                }
            }
        }.frame(maxWidth: .infinity, alignment: .leading)
    }
    private var runtimeUpdateDescription: String {
        switch model.nativeRuntimeUpdate["status"].string {
        case nil, "not_started": return productText("尚未开始组件更新。", "No component update has started.")
        case "staging": return productText("正在准备更新…", "Preparing the update…")
        case "staged": return productText("更新已准备好。请选择“更新组件”继续。", "The update is prepared. Choose Update components to continue.")
        case "updating": return productText("正在更新组件…", "Updating components…")
        case "committed": return productText("组件已更新，可以重新连接。", "Components are updated. You can reconnect.")
        default: return productText("更新状态需要检查。请先检查更新状态；如显示恢复按钮，可继续恢复更新。", "The update needs review. Check update status, then use Recover update if it is available.")
        }
    }
    private var componentNotice: String? {
        switch model.status["components"]["host"]["status"].string {
        case "publisher_changed": return productText("运行组件尚未更新。完成更新后继续使用；现有设置和配对会保留。", "Runtime components have not been updated. Finish the update to continue; settings and pairing will be preserved.")
        case "update_available": return productText("App 与运行组件的版本不同。当前仍使用已安装的运行组件。", "The App and runtime components have different versions. The installed runtime is still selected.")
        case "same_version_conflict", "candidate_unverified", "unavailable", "needs_recovery": return productText("无法确认运行组件更新状态。请检查安装或恢复记录；不要重新配对。", "Runtime update status needs review. Check the installation or recovery record; pairing does not need to be reset.")
        default: return nil
        }
    }
    private var local: some View {
        VStack(alignment: .leading, spacing: 16) {
            Section(productText("允许 ChatGPT 在这台电脑上做什么", "What ChatGPT can do on this computer")) {
                ProductCapabilityLabel(kind: .cli)
                if model.nativeHost {
                    ProductNativeOptionalCapabilities(selected: model.status["enrollment"]["selected_features"], unconfigured: model.nativeCanCreateLocal)
                    Text(productText("功能在首次设置或加入时选择，不代表已获网关批准或系统权限。此版本更改功能需通过“更改这台电脑的角色”重新设置并配对。", "Features are selected during setup or joining; selection does not confirm Gateway approval or system permissions. To change features in this version, use Change this computer’s role, set up again and re-pair.")).font(.caption).foregroundStyle(.secondary)
                } else {
                    Toggle(isOn: $model.computer) { ProductCapabilityLabel(kind: .computer) }.disabled(model.joined)
                    Toggle(isOn: $model.browser) { ProductCapabilityLabel(kind: .browser) }.disabled(model.joined)
                    if !model.joined {
                        Button(productText("应用更改", "Apply changes")) { model.updateCapabilities() }.disabled(model.busy)
                    } else {
                        Text(productText("这些功能在加入时选定。如需更改，请在发出邀请的电脑上管理。", "These features were selected when joining. Manage changes on the computer that sent the invitation.")).font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            if model.computerApproved {
                Section(productText("系统权限", "System permissions")) {
                    permission(productText("辅助功能", "Accessibility"), model.axGranted, false)
                    permission(productText("屏幕录制", "Screen Recording"), model.screenGranted, true)
                }
            }
            if model.nativeHost ? (model.nativeCanCreateLocal || model.nativeCanResumeLocal) : (!model.localPrepared || model.foregroundRecoveryNeeded) {
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
        if let notice = model.nativeLanJoinNotice { Text(notice).font(.callout).textSelection(.enabled) }
        if model.joined || (model.nativeHost && model.status["gateway"] == .null) {
            Label(productText("由管理电脑管理电脑连接", "Computer connections are managed on the main computer"), systemImage: "link")
        } else {
            Button(productText("添加电脑", "Add computer")) { addComputer = true; model.beginDeviceInvitation() }
                .accessibilityIdentifier("styx-settings-add-computer").disabled(model.busy)
            if model.nativeHost {
                Button(productText("检查待连接的电脑", "Check waiting computers")) { model.loadPending() }
                    .accessibilityIdentifier("styx-settings-check-pending-computers")
                    .disabled(model.busy || !model.nativeSupportsOperation("pendingComputers"))
                ProductPendingIdentities(model: model)
                    .disabled(!model.nativeSupportsOperation("pendingComputers"))
            }
            ForEach(model.devices.filter { !$0.isLocal }) { device in
                GroupBox {
                    VStack(alignment: .leading, spacing: 12) {
                        HStack { Label(device.label, systemImage: device.platform == "win32" ? "desktopcomputer" : "laptopcomputer"); Spacer(); ProductConnectionDot(state: device.indicator) }
                        Text(device.indicator.label).font(.caption).foregroundStyle(.secondary)
                        HStack {
                            if !model.nativeHost && !device.isDefault { Button(productText("设为默认", "Set as default")) { model.setDefault(device.id) }.disabled(model.busy) }
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
            if model.nativeHost {
                ProductNativeChatView(model: model)
            } else if model.joined {
                Label(productText("聊天连接由管理电脑管理", "Chat is managed on the main computer"), systemImage: "globe")
                Text(productText("这台电脑只需加入管理电脑（Gateway）。Tunnel 和 ChatGPT 插件只在管理电脑设置一次，所有已加入的电脑共用该 Styx 连接。", "This computer only needs to join the Gateway. Set up the tunnel and ChatGPT plugin once on that Gateway; all joined computers use the same Styx connection.")).font(.callout).foregroundStyle(.secondary)
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
                    Button(productText("Custom MCP 连接指引", "Custom MCP connection guide")) { model.page = .chat; setupChat = true }
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
                Text(productText("使用 Custom MCP → Tunnel。名称和图标在 ChatGPT 中设置；运行密钥只保存在 Styx。", "Use Custom MCP → Tunnel. Set the name and icon in ChatGPT; keep the runtime key only in Styx.")).font(.caption).foregroundStyle(.secondary)
                Button(productText("保存 Styx 上传图标…", "Save Styx upload icon…")) { model.saveBrandIcon() }
                DisclosureGroup(productText("高级：旧版 ZIP 导出", "Advanced: legacy ZIP export")) {
                    ProductPluginCompatibilityNote()
                    Button(productText("导出旧版插件 ZIP…", "Export legacy plugin ZIP…")) { editPackage = true }
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

// The same field guide is used by first-run and Settings. All external setup
// stays with the user; these buttons only open ChatGPT, copy an ID or save art.
struct ProductChatGPTConnectionSteps: View {
    @ObservedObject var model: ProductModel
    var identifierPrefix = "styx-custom-mcp"
    var requireReadyToOpen = false
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(productText("一个 Gateway 只需添加一个 Styx 插件；Windows、Mac 和 Linux Host 加入同一 Gateway 后共用它。", "Add one Styx plugin for each Gateway. Windows, Mac and Linux Hosts that join it use that same connection.")).font(.callout).foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 6) {
                Text(productText("1. 打开 ChatGPT 插件页", "1. Open ChatGPT Plugins")).font(.headline)
                Text(productText("使用目标账号和工作区。已有这个 Gateway 的 Styx 连接时直接复用；首次添加时，点 ＋ → Add custom MCP server。", "Use the intended account and workspace. Reuse this Gateway’s existing Styx connection, or select + → Add custom MCP server to add it for the first time."))
                Button(productText("打开 ChatGPT Plugins", "Open ChatGPT Plugins")) { model.openOfficial("https://chatgpt.com/plugins") }
                    .disabled(requireReadyToOpen && model.tunnelConnection != .connected)
                    .accessibilityIdentifier(identifierPrefix + "-open")
            }
            VStack(alignment: .leading, spacing: 6) {
                Text(productText("2. 按下表填写", "2. Enter these values")).font(.headline)
                LabeledContent("Name", value: "Styx")
                LabeledContent("Connection", value: "Tunnel")
                HStack {
                    Text("Tunnel ID").foregroundStyle(.secondary)
                    Spacer()
                    if model.connectionTunnelID.isEmpty {
                        Text(productText("先在管理电脑配置 Tunnel", "Configure the tunnel on the Gateway first")).font(.caption).foregroundStyle(.secondary)
                    } else {
                        Text(model.connectionTunnelID).font(.system(.caption, design: .monospaced)).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                        Button(productText("复制 Tunnel ID", "Copy Tunnel ID")) { model.copy(model.connectionTunnelID) }
                    }
                }
                LabeledContent("Authentication", value: "No authentication")
                Text(productText("运行密钥（Runtime API key）只保存在管理电脑的 Styx 中，不要填入 ChatGPT。", "Keep the runtime API key in Styx on the Gateway; do not enter it in ChatGPT.")).font(.caption).foregroundStyle(.secondary)
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
                ProductTunnelStatus(model: model, showNextStep: false)
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
            DisclosureGroup(productText("高级：旧版 ZIP 导出", "Advanced: legacy ZIP export")) {
                ProductPluginCompatibilityNote()
                if model.nativeSupportsOperation("pluginRead") {
                    Text(productText("预览并导出这台管理电脑的插件名称、描述和图标。保存后在 ChatGPT 更新已有插件。", "Preview and export this hub’s plugin name, descriptions and icon. Then update the existing plugin in ChatGPT."))
                    Button(productText("名称、图标与插件 ZIP…", "Name, icon and plugin ZIP…")) {
                        model.perform {
                            let current = try await model.client.read("plugin")["plugin"]
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
            if model.nativeHost {
                TextField(productText("插件身份", "Plugin identity"), text: $model.pluginIdentity).disabled(model.plugin["profileSaved"].bool)
                Text(productText("更新已有插件时，请保留其身份；更改显示名称不会更改此身份。", "Keep the existing plugin identity when updating. Changing the display name does not change its identity.")).font(.caption)
            }
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
