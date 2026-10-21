import AppKit
import SwiftUI

@MainActor private enum ProductBrandGlyphAsset {
    // Bundle artwork is immutable. Decode/extract once, not on every view update.
    static let glyph: NSImage? = {
        guard let root = Bundle.main.resourceURL else { return nil }
        if let prepared = NSImage(contentsOf: root.appendingPathComponent("brand/styx-plugin-icon.png")) { return prepared }
        guard let source = NSImage(contentsOf: root.appendingPathComponent("brand/styx-icon-light-source.jpg")) else { return nil }
        return styxBrandGlyph(source: source)
    }()
}
struct ProductBrand: View {
    var size: CGFloat = 68
    var body: some View {
        if let image = ProductBrandGlyphAsset.glyph {
            Image(nsImage: image).renderingMode(.template).resizable().scaledToFit()
                .foregroundStyle(Color.primary).frame(width: size, height: size).accessibilityLabel("Styx")
        }
    }
}
struct ProductPanel<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content
    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 14, content: content)
                .padding(8).frame(maxWidth: .infinity, alignment: .leading)
        } label: { Text(title).font(.headline) }
    }
}
struct ProductView: View {
    @ObservedObject var model: ProductModel
    weak var controller: ProductWindowController?
    @State private var usePluginPackage = true
    @State private var editTunnel = false
    init(model: ProductModel, controller: ProductWindowController?, showPluginPackage: Bool = true) {
        self.model = model; self.controller = controller
        _usePluginPackage = State(initialValue: showPluginPackage)
    }
    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    if !model.loaded {
                        ProductBrand(size: 56).frame(maxWidth: .infinity)
                        ProgressView(model.loadingMessage).frame(maxWidth: .infinity)
                        if model.error != nil { Button(productText("重试读取", "Retry reading")) { Task { await model.bootstrap() } } }
                    } else {
                        switch model.page {
                        case .welcome: welcome
                        case .invitation: invitation
                        case .capabilities: capabilities
                        case .preparation: preparation
                        case .permissions: permissions
                        case .chat: chat
                        case .overview: overview
                        case .computers: computers
                        case .settings: settings
                        }
                    }
                    if let error = model.error ?? model.observationError {
                        Text(error).foregroundStyle(.red).font(.callout).textSelection(.enabled)
                        Button(productText("重新检查", "Check again")) { Task { await model.refresh() } }
                    }
                }.frame(maxWidth: 560, alignment: .leading).padding(28).frame(maxWidth: .infinity)
            }
        }.background(Color(nsColor: .windowBackgroundColor))
            .frame(minWidth: 580, minHeight: 500)
            .sheet(isPresented: $editTunnel) { ProductTunnelEditor(model: model) }
            .task(id: model.onboardingVisible || model.settingsVisible) {
                if model.onboardingVisible || model.settingsVisible { await model.observePresentation() }
            }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in model.observePermissions() }
            .onChange(of: model.page) { _ in model.observePermissions() }
    }
    private func nav(_ page: ProductPage, _ text: String) -> some View {
        Button(text) { model.page = page; if page == .computers { model.loadDevices() } }
            .buttonStyle(.plain).font(.system(size: 13, weight: model.page == page ? .semibold : .regular))
            .foregroundStyle(model.page == page ? Color.accentColor : Color.primary)
    }
    private func heading(_ title: String, _ subtitle: String = "") -> some View {
        VStack(alignment: .leading, spacing: 9) {
            Text(title).font(.system(size: 23, weight: .semibold))
            if !subtitle.isEmpty { Text(subtitle).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
        }
    }
    private var welcome: some View {
        VStack(spacing: 24) {
            ProductBrand(size: 100).padding(.top, 40)
            Text(productText("欢迎使用 Styx", "Welcome to Styx")).font(.system(size: 32, weight: .semibold))
            Text(productText("把你的电脑连接到聊天。", "Connect your computer to your chat.")).foregroundStyle(.secondary)
            Button(productText("开始设置", "Get started")) { model.joining = false; model.page = .capabilities }.buttonStyle(.borderedProminent).controlSize(.large)
            Button(productText("加入已有 Styx", "Join an existing Styx")) { model.joining = true; model.page = .invitation }.buttonStyle(.link)
        }.frame(maxWidth: .infinity).padding(.bottom, 50)
    }
    private var capabilities: some View {
        VStack(alignment: .leading, spacing: 20) {
            heading(productText("这台电脑能做什么？", "What can this computer do?"))
            ProductPanel(title: productText("能力", "Capabilities")) {
                Label("CLI", systemImage: "terminal").font(.headline)
                Text(productText("已包含", "Included")).font(.caption).foregroundStyle(.secondary)
                Divider()
                Toggle(isOn: $model.computer) { Label("Computer Use", systemImage: "hand.point.up.left") }
                Divider()
                Toggle(isOn: $model.browser) { Label("Browser Automation", systemImage: "globe") }
                Text(productText("自动准备专用浏览器；网站登录时由你确认。", "A dedicated browser is prepared for you. Sign in to websites when needed.")).font(.caption).foregroundStyle(.secondary)
            }
            TextField(productText("电脑名称", "Computer name"), text: $model.label)
            HStack {
                Button(productText("返回", "Back")) { model.page = model.joining ? .invitation : .welcome }
                Spacer()
                Button(productText("继续", "Continue")) { model.createAndPrepare() }.buttonStyle(.borderedProminent)
                    .disabled(model.label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || model.session["defaults"]["bundle"].string == nil)
            }
        }
    }
    private var preparation: some View {
        VStack(alignment: .leading, spacing: 20) {
            heading(productText("准备电脑", "Prepare your computer"), productText("Styx 会自动完成以下步骤。需要你操作时，会在这里说明。", "Styx completes these steps automatically and lets you know when you need to act."))
            approvalNotice
            ProductPanel(title: productText("设置进度", "Setup progress")) {
                ForEach(model.preparationStages) { stage in
                    HStack(spacing: 12) {
                        if stage.state == .working { ProgressView().controlSize(.small).frame(width: 20) }
                        else { Image(systemName: stage.state == .completed ? "checkmark.circle.fill" : stage.state == .blocked || stage.state == .needsReview ? "exclamationmark.circle" : "circle").frame(width: 20).foregroundStyle(stage.state == .completed ? Color.accentColor : Color.secondary) }
                        Text(stage.title)
                        Spacer()
                        Text(preparationStateTitle(stage.state)).font(.callout).foregroundStyle(.secondary)
                    }.padding(.vertical, 4)
                }
            }
            if model.signingUpgradeIncomplete {
                Text(productText("发现旧版设置。先核对本次升级，再保留设置并恢复连接。", "Settings from an earlier version were found. Review this upgrade, then preserve your settings and resume the connection.")).foregroundStyle(.secondary)
                if model.signingUpgrade["status"].string == "reviewable" {
                    Text(productText("本次只更新 App 的签名登记，并保存回滚记录。电脑身份、配对、聊天凭据和系统权限保持不变；不会替换或停止已有后台服务。", "This updates only the App signing registration and saves a rollback record. Computer identity, pairing, chat credentials and system permissions are preserved. Existing background services are not replaced or stopped.")).font(.callout)
                    Button(productText("保留设置并完成升级", "Keep settings and finish upgrade")) { model.completeSigningUpgrade() }.buttonStyle(.borderedProminent)
                } else {
                    Button(productText("核对本次升级", "Review this upgrade")) { model.reviewSigningUpgrade() }.buttonStyle(.borderedProminent)
                }
            } else if model.signingUpgradeNeedsReview {
                Text(productText("升级未能确认完成，执行记录已保留。请先检查并恢复这次事务；不要清空设置或反复点击升级。", "Upgrade completion is unconfirmed and its execution record is retained. Inspect and recover this transaction before continuing; do not reset settings or repeatedly apply the upgrade.")).foregroundStyle(.secondary)
            } else if let check = model.retryableCommandCheck {
                Text(ProductPreparationPolicy.commandCheckMessage(check)).foregroundStyle(.secondary)
                Button(productText("重新检查命令组件", "Check command component again")) { model.recheckCommandComponent() }.buttonStyle(.borderedProminent)
            } else if model.preparationConnectionNeedsReview {
                Text(model.connectionReviewMessage).foregroundStyle(.secondary)
                Button(productText("重试本机连接", "Retry this computer's connection")) { model.resumeForeground() }
            } else if let blocked = model.preparationBlocker {
                if blocked.status == "awaiting_approval" || ProductPreparationPolicy.canCheckOwnerApproval(model.deployment) {
                    Text(productText("请在主台核对并批准这台电脑，然后检查连接。", "Review and approve this computer on the main computer, then check the connection.")).foregroundStyle(.secondary)
                    Button(productText("检查主台批准", "Check owner approval")) { model.continuePreparation() }.buttonStyle(.borderedProminent)
                } else {
                    Text(blocked.status == "uncertain" ? productText("上次准备的结果尚未确认。请刷新并核对详细信息；安装和配对不会自动重试。", "The previous setup result is unconfirmed. Refresh and review details; installation and pairing will not be retried automatically.") : productText("准备暂时停止。请刷新状态并核对详细信息，再继续处理。", "Setup has paused. Refresh the status and review details before continuing.")).foregroundStyle(.secondary)
                }
            } else if !model.busy {
                Button(productText("继续准备", "Continue setup")) { model.continuePreparation() }.buttonStyle(.borderedProminent)
            }
            DisclosureGroup(productText("详细信息", "Details")) {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(model.deployment?.steps.filter { !$0.id.contains("service") } ?? []) { step in
                        HStack { Text(step.id).font(.system(.caption, design: .monospaced)); Spacer(); Text(stateTitle(step.status)).font(.caption).foregroundStyle(.secondary) }
                        if let fingerprint = model.status["deployment"]["steps"].array.first(where: { $0["id"].string == step.id })?["fingerprint"].string {
                            Text(fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        }
                    }
                }.padding(.top, 10)
            }.font(.callout).foregroundStyle(.secondary)
        }
    }
    private func preparationStateTitle(_ state: ProductPreparationStage.State) -> String {
        switch state {
        case .pending: return productText("等待准备", "Waiting")
        case .working: return productText("正在准备", "Preparing")
        case .completed: return productText("已准备", "Prepared")
        case .blocked: return productText("需要检查", "Needs checking")
        case .awaitingApproval: return productText("等待主台批准", "Awaiting owner approval")
        case .needsReview: return productText("需要核对", "Needs review")
        case .notApproved: return productText("尚未获主台批准", "Not approved by the owner")
        }
    }
    private var permissions: some View {
        VStack(alignment: .leading, spacing: 20) {
            heading(productText("允许 Computer Use", "Allow Computer Use"), productText("以下权限需要你在 macOS 中亲自开启。", "Grant these permissions yourself in macOS."))
            ProductPanel(title: productText("系统权限", "System permissions")) {
                permissionRow(productText("辅助功能", "Accessibility"), granted: model.axGranted, screen: false)
                Divider()
                permissionRow(productText("屏幕录制", "Screen Recording"), granted: model.screenGranted, screen: true)
                Text(productText("修改权限后可能需要退出并重新打开 Styx。应用脚本可能另外请求 Automation 授权。", "After changing permissions, you may need to quit and reopen Styx. Application scripts can separately require Automation permission.")).font(.caption).foregroundStyle(.secondary)
            }
            if !model.axGranted || !model.screenGranted {
                DisclosureGroup(productText("开关已开启，但这里仍未识别？", "Enabled in System Settings but still not recognized?")) {
                    Text(productText("请确认授权的是“应用程序”中的 Styx。开发预览版更新后，旧授权可能仍显示开启：在对应权限列表中移除旧 Styx，再添加 /Applications/Styx.app 并开启，然后退出并重新打开。已有设置和电脑连接会保留。", "Confirm the permission belongs to Styx in Applications. After a development preview update, an old grant may still look enabled: remove the old Styx entry, add /Applications/Styx.app and enable it, then quit and reopen. Existing settings and computer connections are retained.")).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
            Button(productText("重新检查权限", "Check permissions again")) { model.observePermissions() }
            Button(productText("继续", "Continue")) { model.continueAfterPermissions() }.buttonStyle(.borderedProminent).disabled(!model.axGranted || !model.screenGranted)
        }
    }
    private func permissionRow(_ title: String, granted: Bool, screen: Bool) -> some View {
        HStack {
            Label(title, systemImage: screen ? "record.circle" : "accessibility")
            Spacer()
            Text(granted ? productText("已允许", "Allowed") : productText("需要允许", "Permission needed")).foregroundStyle(.secondary)
            if granted || model.permissionWasRequested(screen) {
                Button(productText("打开系统设置", "Open System Settings")) { model.openPermission(screen) }
            } else {
                Button(productText("允许…", "Allow…")) { model.requestPermission(screen) }
            }
        }
    }
    private var invitation: some View {
        VStack(alignment: .leading, spacing: 20) {
            heading(productText("加入已有 Styx", "Join an existing Styx"), productText("在主台选择“电脑 → 添加电脑”，取得一次性邀请。", "On the main computer, choose Computers → Add computer to create an invitation."))
            SecureField(productText("粘贴邀请", "Paste invitation"), text: $model.invite)
            Button(productText("检查邀请", "Inspect invitation")) { model.inspectInvitation() }.disabled(model.invite.isEmpty)
            if let origin = model.inspection["preview"]["origin"].string {
                ProductPanel(title: productText("核对主台身份", "Verify the main computer")) {
                    Text(origin).textSelection(.enabled)
                    if let fingerprint = model.inspection["preview"]["caSha256"].string { Text(fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled) }
                    Text(productText("请通过可信渠道与主台核对。下一步仍须验证连接并等待主台独立批准。", "Compare these details with the main computer through a trusted channel. Connection verification and independent approval are still required.")).font(.callout).foregroundStyle(.secondary)
                    Button(productText("已核对，继续", "Details match — continue")) { model.acceptInvitation() }.buttonStyle(.borderedProminent)
                }
            }
            Button(productText("返回", "Back")) { model.page = .welcome; model.invite = "" }
        }
    }
    private var chat: some View {
        VStack(alignment: .leading, spacing: 20) {
            heading(productText("连接 ChatGPT", "Connect ChatGPT"))
            if model.joined {
                ProductPanel(title: productText("由主台管理", "Managed on the main computer")) {
                    Text(productText("回到原来的聊天，选择这台电脑进行实际调用。此处无需新建插件或聊天入口。", "Return to the existing chat and select this computer for a real tool call. Its plugin and chat connection are managed on the main computer."))
                    approvalNotice
                }
            } else if !model.localPrepared {
                Button(productText("先完成电脑准备", "Finish computer setup")) { model.page = .preparation }
            } else {
                tunnelPanel
                officialPanel
                if usePluginPackage { pluginUploadPanel }
                if model.plugin["accountActions"]["installation"].string == "user_confirmed" { acceptancePanel }
            }
        }
    }
    private var tunnelPanel: some View {
        ProductPanel(title: productText("1. 电脑端连接", "1. Connection on this computer")) {
            ProductTunnelStatus(model: model)
            Button(model.tunnelConnection == .notConfigured ? productText("填写连接信息", "Enter connection details") : productText("编辑连接信息", "Edit connection details")) { editTunnel = true }.accessibilityIdentifier("styx-onboarding-edit-tunnel")
            if model.tunnelConnection != .connected && model.tunnelConnection != .notConfigured {
                Button(productText("重新连接", "Reconnect")) { model.startTunnel() }.disabled(model.busy || model.tunnelAttempt == .connecting).accessibilityIdentifier("styx-reconnect")
            }
        }
    }
    private var pluginPackageContent: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(productText("插件包含连接配置、内置技能及下方设置的名称、描述和图标。保存 ZIP 后到 ChatGPT 安装。", "The plugin includes connection settings, built-in skills, and the name, description and icon below. Save the ZIP, then install it in ChatGPT."))
            Button(productText("导出插件 ZIP…", "Export plugin ZIP…")) { model.exportPluginPackage() }.buttonStyle(.borderedProminent)
                .disabled(model.tunnelConnection != .connected || model.connectionTunnelID.isEmpty || model.plugin["contextChanged"].bool || model.pluginName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || model.pluginName.count > 64 || model.pluginDescription.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || model.pluginDescription.count > 30)
            if model.connectionTunnelID.isEmpty {
                Text(productText("先完成上方的第 1 步，再导出插件 ZIP。", "Complete step 1 above before exporting the plugin ZIP.")).foregroundStyle(.secondary)
            }
            if let location = model.exportedPluginURL, !model.pluginDraftEdited {
                Label(productText("文件已保存", "File saved"), systemImage: "checkmark.circle.fill")
                Text(location.path).font(.caption).textSelection(.enabled)
                Button(productText("在 Finder 中显示 ZIP", "Show ZIP in Finder")) { NSWorkspace.shared.activateFileViewerSelecting([location]) }
            }
            GroupBox(productText("插件名称、描述和图标", "Plugin name, description and icon")) {
                VStack(alignment: .leading, spacing: 12) {
                TextField(productText("插件名称", "Plugin name"), text: $model.pluginName).onChange(of: model.pluginName) { _ in model.observePluginDraftEdit() }
                TextField(productText("简短描述（最多 30 字）", "Short description (up to 30 characters)"), text: $model.pluginDescription).onChange(of: model.pluginDescription) { _ in model.observePluginDraftEdit() }
                HStack {
                    if let encoded = model.pluginIcon["dataBase64"].string, let bytes = Data(base64Encoded: encoded), let image = NSImage(data: bytes) {
                        Image(nsImage: image).resizable().scaledToFit().frame(width: 40, height: 40)
                    } else { ProductBrand(size: 40) }
                    Button(productText("更换插件图标…", "Choose plugin icon…")) { model.selectIcon() }
                }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }
    private var officialPanel: some View {
        ProductPanel(title: usePluginPackage ? productText("2. 保存插件 ZIP", "2. Save the plugin ZIP") : productText("2. 在 ChatGPT 添加 Styx", "2. Add Styx in ChatGPT")) {
            if usePluginPackage {
                pluginPackageContent
            } else {
                Text(productText("打开 ChatGPT 插件页 → ＋ → 添加自建 MCP 服务器。", "Open ChatGPT Plugins → + → Add custom MCP server."))
                Text(productText("名称填 Styx；Connection 选 Tunnel，粘贴下方 ID；Authentication 选 No authentication。", "Name: Styx. Connection: Tunnel, then paste the ID below. Authentication: No authentication."))
                if !model.connectionTunnelID.isEmpty {
                    HStack { Text(model.connectionTunnelID).font(.caption).textSelection(.enabled); Button(productText("复制 Tunnel ID", "Copy Tunnel ID")) { model.copy(model.connectionTunnelID) } }
                }
                Text(productText("确认提示，点“创建为插件”，然后安装 Styx。", "Confirm the notice, select Create as a plugin, then install Styx."))
                Button(productText("保存 Styx 图标…", "Save Styx icon…")) { model.saveBrandIcon() }
                Button(productText("打开 ChatGPT 添加 Styx", "Open ChatGPT to add Styx")) { model.openOfficial("https://chatgpt.com/plugins") }
                Button(productText("我已添加并安装 Styx", "I added and installed Styx")) { model.confirmPluginInstallation() }.disabled(model.plugin["contextChanged"].bool || model.connectionTunnelID.isEmpty)
            }
            if model.plugin["contextChanged"].bool {
                Text(productText("连接信息已变化，请先核对当前连接。", "Connection details changed. Review the current connection first."))
                Button(productText("核对当前连接…", "Review current connection…")) { model.rebindPluginConnection() }
            }
        }
    }
    private var pluginUploadPanel: some View {
        ProductPanel(title: productText("3. 上传到 ChatGPT", "3. Upload to ChatGPT")) {
            if model.exportedPluginURL != nil && !model.pluginDraftEdited {
                Text(productText("在 ChatGPT 的插件管理中选择“上传插件”，导入刚保存的 styx-native.zip 后安装。已有 Styx 时优先上传新版本。上传入口是否可用取决于账号或工作区权限。", "In ChatGPT plugin management, choose Upload plugin, import the saved styx-native.zip, then install it. For an existing Styx plugin, prefer Upload new version. Upload availability depends on account or workspace permissions."))
                Button(productText("打开 ChatGPT 上传 ZIP", "Open ChatGPT to upload ZIP")) { model.openOfficial("https://chatgpt.com/plugins") }.buttonStyle(.borderedProminent)
                Button(productText("我已上传并安装 Styx", "I uploaded and installed Styx")) { model.confirmPluginInstallation() }
                    .disabled(model.plugin["contextChanged"].bool || model.plugin["export"]["status"].string != "exported")
            } else {
                Text(productText("先保存上方的插件 ZIP，再到 ChatGPT 插件管理中上传并安装。", "First save the plugin ZIP above, then upload and install it in ChatGPT plugin management.")).foregroundStyle(.secondary)
            }
        }
    }

    private var acceptancePanel: some View {
        ProductPanel(title: productText("最后，试用 Styx", "Finally, try Styx")) {
            Text(productText("在 ChatGPT 新聊天中用 @ 选择 Styx，发送下方的测试请求。", "In a new ChatGPT conversation, select Styx with @ and send the test request below."))
            Button(productText("生成测试请求", "Generate test request")) { model.beginAcceptance() }
            if let prompt = model.acceptance["challenge"]["prompt"].string {
                Text(prompt).font(.system(.callout, design: .monospaced)).textSelection(.enabled)
                Button(productText("复制到目标聊天", "Copy for your target chat")) { model.copy(prompt) }
                if model.acceptance["challenge"]["desktopValue"].string != nil {
                    Text(productText("桌面验证输入框（由聊天里的 Computer Use 操作）", "Desktop verification field (operated by Computer Use from chat)")).font(.caption)
                    ProductAcceptanceField(model: model, owner: controller).frame(height: 30)
                }
                statusRow("CLI", model.acceptance["requestProof"]["status"].string)
                statusRow("Browser Automation", model.acceptance["browser"]["status"].string)
                statusRow("Computer Use", model.acceptance["desktop"]["status"].string)
                Button(productText("我在目标聊天看到了结果", "I saw the results in the target chat")) { model.confirmChat() }.disabled(!model.targetProofReady)
            }
            if model.accepted { Button(productText("完成设置", "Finish setup")) { model.page = .overview }.buttonStyle(.borderedProminent) }
        }
    }
    private var overview: some View {
        VStack(alignment: .leading, spacing: 20) {
            heading("Styx", model.accepted ? productText("聊天验证已完成。", "Chat verification completed.") : productText("各项状态来自本次实际检查。", "These states come from observed checks."))
            ProductPanel(title: productText("这台电脑", "This computer")) {
                statusRow("CLI", model.journey["readiness"]["exec"]["status"].string)
                statusRow("Browser Automation", model.browserNotApproved ? "not_approved" : model.journey["readiness"]["browser"]["status"].string)
                statusRow("Computer Use", model.computerNotApproved ? "not_approved" : model.journey["readiness"]["desktop"]["status"].string)
                approvalNotice
                if !model.localPrepared { Button(productText("继续设置", "Continue setup")) { model.page = .preparation } }
                if model.computerApproved && (!model.axGranted || !model.screenGranted) { Button(productText("检查系统权限", "Review system permissions")) { model.page = .permissions } }
                if model.foregroundRecoveryNeeded { Button(productText("恢复本次连接", "Resume this connection")) { model.resumeForeground() } }
            }
            ProductPanel(title: productText("聊天连接", "Chat connection")) {
                Text(model.joined ? productText("由主台管理", "Managed on the main computer") : model.accepted ? productText("已收到真实工具结果与目标聊天确认", "Real tool results and target-chat confirmation received") : productText("尚未完成目标聊天验证", "Target-chat verification is incomplete"))
                Button(productText("查看聊天连接", "View chat connection")) { model.page = .chat }
            }
        }
    }
    private var computers: some View {
        VStack(alignment: .leading, spacing: 20) {
            heading(productText("电脑", "Computers"))
            ProductPanel(title: productText("已批准的电脑", "Approved computers")) {
                if model.devices.isEmpty { Text(productText("尚未读取到电脑。", "No computers have been read yet.")).foregroundStyle(.secondary) }
                ForEach(model.devices) { device in
                    HStack {
                        Text(device.label)
                        Spacer()
                        if device.isDefault { Text(productText("默认", "Default")).foregroundStyle(.secondary) }
                        else { Button(productText("设为默认", "Set as default")) { model.setDefault(device.id) } }
                        if !model.joined { Button(productText("撤销访问", "Revoke access")) { model.revokeDevice(device) } }
                    }
                }
                Button(productText("刷新电脑", "Refresh computers")) { model.loadDevices() }
            }
            if !model.joined {
                ProductPanel(title: productText("添加电脑", "Add computer")) {
                    Text(productText("另一台电脑安装 Styx 后选择“加入已有”。先检查电脑间的安全入口。", "Install Styx on the other computer and choose Join existing. First check the secure connection between computers."))
                    Button(productText("检查连接入口", "Check connection entry")) { model.checkIngress() }
                    if model.ingress != .null {
                        if model.ingress["status"].string == "loopback_only" {
                            Text(productText("当前只允许本机连接。需要先在主台准备获准的网络入口，再邀请其他电脑。", "This connection currently accepts only this computer. Prepare an authorized network entry on the main computer before inviting another computer.")).font(.callout)
                        } else {
                            Text(productText("新电脑仍需验证可达性与 TLS；聊天 Tunnel 不代替电脑间入口。", "The joining computer must verify reachability and TLS; the chat tunnel is not a computer connection entry.")).font(.caption).foregroundStyle(.secondary)
                        }
                        Button(productText("生成限时邀请", "Create a temporary invitation")) { model.createInvitation() }.disabled(!model.ingress["blockers"].array.isEmpty)
                    }
                    if let link = model.createdInvitation["link"].string {
                        Button(productText("复制邀请", "Copy invitation")) { model.copy(link, secret: true) }
                        Text(productText("请只交给要加入的电脑；已批准设备不会因关闭窗口断开。", "Share only with the joining computer. Closing this window does not disconnect approved devices.")).font(.caption)
                    }
                    Button(productText("检查待批准请求", "Check pending requests")) { model.loadPending() }
                    ForEach(Array(model.pending.enumerated()), id: \.offset) { _, row in
                        Button(row["label"].string ?? productText("新电脑", "New computer")) { model.selectedPending = row; model.approveComputer = false; model.approveBrowser = false; model.fingerprintConfirmation = "" }
                    }
                    if model.selectedPending != .null {
                        Text(model.selectedPending["fingerprint"].string ?? "").font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                        TextField(productText("输入新电脑显示的身份指纹", "Enter the fingerprint shown on the new computer"), text: $model.fingerprintConfirmation)
                        Toggle("Computer Use", isOn: $model.approveComputer).disabled(!model.selectedPending["computer_requested"].bool)
                        Toggle("Browser Automation", isOn: $model.approveBrowser).disabled(!model.selectedPending["browser_requested"].bool)
                        Button(productText("批准这台电脑", "Approve this computer")) { model.approvePending() }.disabled(model.fingerprintConfirmation.isEmpty)
                    }
                }
            }
        }
    }
    private var settings: some View {
        VStack(alignment: .leading, spacing: 20) {
            heading(productText("设置", "Settings"))
            if model.deployment == nil { Button(productText("返回开始设置", "Back to setup")) { model.page = .welcome } }
            ProductPanel(title: productText("语言", "Language")) {
                Text(productText("跟随系统；可在系统设置中选择 Styx 的语言。", "Follows the system. Choose Styx's language in System Settings."))
                Button(productText("打开语言与地区", "Open Language & Region")) { model.openOfficial("x-apple.systempreferences:com.apple.Localization-Settings.extension") }
            }
            if model.session["nativeAppLifecycleSupported"].bool {
                ProductPanel(title: productText("启动", "Startup")) {
                    Toggle(productText("登录时启动 Styx", "Open Styx at login"), isOn: Binding(get: { model.loginEnabled }, set: { model.setLoginEnabled($0) }))
                        .disabled(!model.loginPreferenceKnown)
                    if !model.loginPreferenceKnown {
                        Text(productText("登录启动状态尚未确认。请刷新状态后重试。", "Startup status could not be confirmed. Refresh status to check again.")).font(.caption).foregroundStyle(.secondary)
                    }
                    Text(productText("关闭窗口后继续运行；选择“退出 Styx”才结束本次运行。", "Closing the window keeps Styx running. Choose Quit Styx to end this run.")).font(.caption).foregroundStyle(.secondary)
                }
            }
            if model.deployment != nil {
                ProductPanel(title: productText("这台电脑的能力", "This computer's capabilities")) {
                    Label("CLI", systemImage: "terminal")
                    if model.joined {
                        Text(productText("可选能力由主台审批。请在主台核对当前授权；这里不会自行扩大权限。", "Optional capabilities are approved on the main computer. Review authorization there; this computer cannot expand it itself.")).font(.callout).foregroundStyle(.secondary)
                        approvalNotice
                    } else {
                        Toggle(isOn: $model.computer) { Label("Computer Use", systemImage: "hand.point.up.left") }
                        Toggle(isOn: $model.browser) { Label("Browser Automation", systemImage: "globe") }
                        Text(productText("更改能力会暂停本次 App 管理的连接，请先完成正在进行的操作。其他服务或管理入口的连接需要先停止并对账。", "Changes pause connections managed by this App. Finish active work first. Stop and reconcile connections owned by other services or managers separately.")).font(.caption).foregroundStyle(.secondary)
                        Button(productText("应用更改", "Apply changes")) { model.updateCapabilities() }
                    }
                    if model.foregroundRecoveryNeeded { Button(productText("恢复本次连接", "Resume this connection")) { model.resumeForeground() } }
                }
            }
        }
    }
    private func statusRow(_ title: String, _ status: String?) -> some View {
        HStack { Text(title); Spacer(); Text(stateTitle(status ?? "not_observed")).foregroundStyle(.secondary) }
    }
    @ViewBuilder private var approvalNotice: some View {
        if model.browserNotApproved {
            Text(productText("Browser Automation 尚未获主台批准；已批准的 CLI 等能力仍可连接。", "Browser Automation was not approved on the main computer. Approved capabilities, including CLI, can still connect.")).font(.callout).foregroundStyle(.secondary)
        }
        if model.computerNotApproved {
            Text(productText("Computer Use 尚未获主台批准；此处无需为它开启系统权限。", "Computer Use was not approved on the main computer. System permissions for it are not needed here.")).font(.callout).foregroundStyle(.secondary)
        }
    }
    private func stateTitle(_ status: String) -> String {
        switch status {
        case "succeeded", "completed": return productText("已完成", "Completed")
        case "connected", "ready": return productText("已连接，待实际验证", "Connected; verification separate")
        case "verified": return productText("实际验证通过", "Verified by execution")
        case "not_requested", "not_required", "skipped": return productText("未启用或无需检查", "Not enabled or not required")
        case "not_approved": return productText("尚未获主台批准", "Not approved by the owner")
        case "running", "starting", "connecting": return productText("正在处理", "In progress")
        case "awaiting_approval": return productText("等待主台批准", "Awaiting approval")
        case "preflight_passed": return productText("基础检查通过", "Preflight passed")
        case "failed", "uncertain", "blocked", "needs_attention": return productText("需要检查", "Needs attention")
        case "session_unavailable": return productText("需要图形登录会话", "Graphical login required")
        default: return productText("尚未确认", "Not yet verified")
        }
    }
    private func stepTitle(_ id: String) -> String {
        switch id {
        case "gateway.runtime.prepare", "gateway.prepare": return productText("准备本机连接", "Prepare local connection")
        case "gateway.start", "gateway.verify": return productText("检查本机连接", "Check local connection")
        case "host.prepare": return productText("准备所选能力", "Prepare selected capabilities")
        case "host.invite", "host.pair", "host.request", "host.claim": return productText("连接这台电脑", "Connect this computer")
        case "host.doctor": return productText("检查这台电脑", "Check this computer")
        default: return productText("准备组件", "Prepare components")
        }
    }
}

// NSView-backed text is used for acceptance so the readback is taken from the
// visible AppKit control, not from an arbitrary JavaScript or model echo.
struct ProductAcceptanceField: NSViewRepresentable {
    @ObservedObject var model: ProductModel
    weak var owner: ProductWindowController?
    func makeNSView(context: Context) -> NSTextField {
        let field = NSTextField(string: "")
        field.identifier = NSUserInterfaceItemIdentifier("styx-acceptance-target")
        field.setAccessibilityIdentifier("styx-acceptance-target")
        field.setAccessibilityLabel(productText("桌面验收输入框", "Desktop acceptance field"))
        field.delegate = context.coordinator
        owner?.acceptanceField = field
        return field
    }
    func updateNSView(_ field: NSTextField, context: Context) {
        if context.coordinator.challengeID != model.challengeID {
            field.stringValue = ""; context.coordinator.challengeID = model.challengeID
        }
        owner?.acceptanceField = field
    }
    func makeCoordinator() -> Coordinator { Coordinator() }
    final class Coordinator: NSObject, NSTextFieldDelegate {
        var challengeID: String?
    }
}

@MainActor final class ProductWindowController: NSWindowController, NSWindowDelegate, NSPopoverDelegate {
    let model: ProductModel
    weak var acceptanceField: NSTextField?
    let ownerAppPID = Int(ProcessInfo.processInfo.processIdentifier)
    private var observationTimer: Timer?
    private var settingsWindow: NSWindow?
    private var menuPopover: NSPopover?
    private var menuSizeTimer: Timer?
    var showMenuInvitation: (() -> Void)?

    init(sessionURL: URL) {
        // Bootstrap was already checked by the App's child-pipe parser; keep a
        // failable client construction here so tests can cover its own boundary.
        do { model = try ProductModel(sessionURL: sessionURL) }
        catch { preconditionFailure("Invalid owned Styx bootstrap") }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 680, height: 640), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Styx"; window.minSize = NSSize(width: 620, height: 560)
        super.init(window: window)
        window.delegate = self; window.contentView = NSHostingView(rootView: ProductView(model: model, controller: self))
        window.center(); window.setFrameAutosaveName("Styx.ProductWindow.v6")
        observationTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.observeDesktopReadback() }
        }
    }
    required init?(coder: NSCoder) { nil }
    func present() { model.onboardingVisible = true; model.observePermissions(); window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true) }
    func showPreferences() { showSettings(.general) }
    func showOnboarding() {
        menuPopover?.performClose(nil)
        if model.page == .overview { model.page = model.localPrepared ? (model.accepted ? .overview : .chat) : .preparation }
        present()
    }
    func showSettings(_ section: ProductSettingsSection) {
        menuPopover?.performClose(nil)
        model.requestSettings(section); model.settingsVisible = true; model.observePermissions()
        if settingsWindow == nil {
            let preferences = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 680, height: 560), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
            preferences.title = productText("Styx 设置", "Styx Settings")
            preferences.isReleasedWhenClosed = false
            preferences.identifier = NSUserInterfaceItemIdentifier("Styx.SettingsWindow")
            preferences.delegate = self
            preferences.contentView = NSHostingView(rootView: ProductSettingsView(model: model, controller: self))
            preferences.minSize = NSSize(width: 640, height: 500)
            preferences.center(); preferences.setFrameAutosaveName("Styx.SettingsWindow.v1")
            settingsWindow = preferences
        }
        settingsWindow?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
    }
    func toggleMenu(relativeTo button: NSStatusBarButton, quit: @escaping () -> Void) {
        if menuPopover?.isShown == true { menuPopover?.performClose(nil); return }
        let popover = NSPopover()
        popover.behavior = .transient; popover.animates = true; popover.delegate = self
        let host = NSHostingController(rootView: ProductDailyPanel(model: model, controller: self, quit: quit))
        popover.contentViewController = host
        popover.contentSize = NSSize(width: 332, height: 300)
        menuPopover = popover; model.menuVisible = true
        popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        menuSizeTimer?.invalidate()
        menuSizeTimer = Timer.scheduledTimer(withTimeInterval: 0.2, repeats: true) { [weak self, weak popover] _ in
            Task { @MainActor in
                guard let self = self, let popover = popover, popover.isShown else { return }
                let size = host.view.fittingSize
                let target = NSSize(width: 332, height: min(720, max(120, size.height)))
                if abs(popover.contentSize.height - target.height) > 1 { popover.contentSize = target }
                _ = self
            }
        }
    }
    func popoverDidClose(_ notification: Notification) {
        model.menuVisible = false; menuSizeTimer?.invalidate(); menuSizeTimer = nil
    }

    func windowWillClose(_ notification: Notification) {
        if let closing = notification.object as? NSWindow {
            if closing === settingsWindow { model.settingsVisible = false }
            if closing === window { model.onboardingVisible = false }
        }
        if !model.settingsVisible && !model.onboardingVisible { model.clearSecrets() }
    }
    func currentDesktopReadback(challengeID: String) -> String? {
        guard model.challengeID == challengeID, let field = acceptanceField,
              field.window === window, window?.isVisible == true, !field.isHiddenOrHasHiddenAncestor,
              let expires = model.acceptance["challenge"]["expiresAt"].number,
              expires > Date().timeIntervalSince1970 * 1000 else { return nil }
        return field.stringValue
    }
    private func observeDesktopReadback() async {
        guard !model.busy, let id = model.challengeID,
              let window = window, window.windowNumber > 0,
              let actual = currentDesktopReadback(challengeID: id),
              let expected = model.acceptance["challenge"]["desktopValue"].string,
              actual == expected, model.acceptance["desktop"]["status"].string != "verified" else { return }
        // The Core still requires authenticated Cua before/action/after evidence
        // bound to this App. Typed text alone can never produce acceptance.
        do {
            _ = try await model.client.write("acceptance/desktop-readback", ["authorize": .bool(true), "challengeId": .string(id), "value": .string(actual), "pid": .number(Double(ownerAppPID)), "windowId": .number(Double(window.windowNumber))])
            await model.refresh()
        } catch { /* No untrusted error text or fabricated success. Refresh remains available. */ }
    }
    func prepareToQuit(completion: @escaping (Bool) -> Void) {
        model.clearSecrets()
        Task {
            do {
                if !model.loaded { await model.bootstrap() }
                guard model.session["nativeAppLifecycleSupported"].bool else { throw ProductCoreError.unavailable }
                _ = try await model.client.write("app/quit", ["authorize": .bool(true)])
                observationTimer?.invalidate(); observationTimer = nil
                menuSizeTimer?.invalidate(); menuSizeTimer = nil; menuPopover?.performClose(nil); settingsWindow?.close()
                completion(true)
            } catch {
                let alert = NSAlert()
                alert.messageText = productText("暂时无法安全退出 Styx", "Styx could not finish quitting")
                alert.informativeText = productText("组件停止状态尚未确认。请刷新状态后重试退出。", "Component shutdown has not been confirmed. Refresh status and try quitting again.")
                alert.runModal(); completion(false)
            }
        }
    }
}
