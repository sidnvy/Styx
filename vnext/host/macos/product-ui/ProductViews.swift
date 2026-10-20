import AppKit
import SwiftUI

@MainActor private enum ProductBrandAsset {
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
        if let image = ProductBrandAsset.glyph {
            Image(nsImage: image).renderingMode(.template).resizable().scaledToFit()
                .foregroundStyle(Color.primary).frame(width: size, height: size).accessibilityLabel("Styx")
        }
    }
}
struct ProductPanel<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text(title).font(.headline)
            content()
        }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor), in: RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(Color.primary.opacity(0.07)))
    }
}
struct ProductView: View {
    @ObservedObject var model: ProductModel
    weak var controller: ProductWindowController?
    var body: some View {
        VStack(spacing: 0) {
            if model.deployment != nil && (model.accepted || model.joined && model.localPrepared || [.overview, .computers, .settings].contains(model.page)) {
                HStack(spacing: 18) {
                    ProductBrand(size: 27)
                    nav(.overview, productText("概览", "Overview"))
                    nav(.computers, productText("电脑", "Computers"))
                    nav(.chat, productText("聊天连接", "Chat connections"))
                    Spacer()
                    Button { model.page = .settings } label: { Image(systemName: "gearshape") }.help(productText("设置", "Settings"))
                }.padding(.horizontal, 28).padding(.vertical, 16)
                Divider()
            }
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
                    if let error = model.error {
                        Text(error).foregroundStyle(.red).font(.callout).textSelection(.enabled)
                    }
                }.frame(maxWidth: 680, alignment: .leading).padding(36).frame(maxWidth: .infinity)
            }
            Divider()
            HStack {
                if model.busy { ProgressView().controlSize(.small); Text(productText("正在处理…", "Working…")).font(.caption).foregroundStyle(.secondary) }
                Spacer()
                if model.loaded { Button(productText("刷新状态", "Refresh status")) { Task { await model.refresh() } }.disabled(model.busy) }
            }.padding(12)
        }.background(Color(nsColor: .windowBackgroundColor))
            .frame(minWidth: 620, minHeight: 560)
            .disabled(model.busy)
            .task { await model.bootstrap() }
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
            Text(title).font(.system(size: 28, weight: .semibold))
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
                Toggle("Computer Use", isOn: $model.computer)
                Divider()
                Toggle("Browser Automation", isOn: $model.browser)
                Text(productText("自动准备专用浏览器；网站登录时由你确认。", "A dedicated browser is prepared for you. Sign in to websites when needed.")).font(.caption).foregroundStyle(.secondary)
            }
            TextField(productText("电脑名称", "Computer name"), text: $model.label)
            HStack {
                Button(productText("返回", "Back")) { model.page = model.joining ? .invitation : .welcome }
                Spacer()
                Button(productText("准备这台电脑", "Prepare this computer")) { model.createAndPrepare() }.buttonStyle(.borderedProminent)
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
            if let check = model.retryableCommandCheck {
                Text(ProductPreparationPolicy.commandCheckMessage(check)).foregroundStyle(.secondary)
                Button(productText("重新检查命令组件", "Check command component again")) { model.recheckCommandComponent() }.buttonStyle(.borderedProminent)
            } else if let blocked = model.preparationBlocker {
                if blocked.status == "awaiting_approval" || ProductPreparationPolicy.canCheckOwnerApproval(model.deployment) {
                    Text(productText("请在主台核对并批准这台电脑，然后检查连接。", "Review and approve this computer on the main computer, then check the connection.")).foregroundStyle(.secondary)
                    Button(productText("检查主台批准", "Check owner approval")) { model.continuePreparation() }.buttonStyle(.borderedProminent)
                } else {
                    Text(blocked.status == "uncertain" ? productText("上次准备的结果尚未确认。请刷新并核对详细信息；安装和配对不会自动重试。", "The previous setup result is unconfirmed. Refresh and review details; installation and pairing will not be retried automatically.") : productText("准备暂时停止。请刷新状态并核对详细信息，再继续处理。", "Setup has paused. Refresh the status and review details before continuing.")).foregroundStyle(.secondary)
                    Button(productText("刷新并检查状态", "Refresh and inspect status")) { Task { await model.refresh() } }
                }
            } else if model.preparationConnectionNeedsReview {
                Text(productText("现有连接状态尚未确认。请刷新并核对详细信息；不会重复启动或接管其他连接。", "The existing connection needs review. Refresh and inspect details; Styx will not start duplicates or take over other connections.")).foregroundStyle(.secondary)
                Button(productText("刷新并检查连接", "Refresh and inspect connection")) { Task { await model.refresh() } }
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
            Label(title, systemImage: granted ? "checkmark.circle.fill" : "circle")
            Spacer()
            Text(granted ? productText("已允许", "Allowed") : productText("需要允许", "Permission needed")).foregroundStyle(.secondary)
            Button(productText("打开系统设置", "Open System Settings")) { model.openPermission(screen) }
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
                if ["configured", "running", "interrupted"].contains(model.journey["tunnel"]["status"].string ?? "") { pluginPanel }
                if model.plugin["profileSaved"].bool { officialPanel }
                if model.plugin["accountActions"]["installation"].string == "user_confirmed" { acceptancePanel }
            }
        }
    }
    private var tunnelPanel: some View {
        ProductPanel(title: productText("1. 准备安全连接", "1. Prepare a secure connection")) {
            Text(productText("前往官方平台，确认账号与工作区，创建专用 Tunnel 和具有 Read/Use 权限的运行 Key。", "Open the official platform, confirm your account and workspace, then create a dedicated Tunnel and a runtime key with Read/Use permissions."))
            Button(productText("前往官方平台", "Open the official platform")) { model.openOfficial("https://platform.openai.com/settings/organization/tunnels") }
            if model.journey["tunnel"]["status"].string == "not_configured" {
                TextField("Tunnel ID", text: $model.tunnelID)
                SecureField(productText("运行 Key", "Runtime key"), text: $model.runtimeKey)
                Text(productText("将平台生成的这两项填回 Styx。运行 Key 不要粘贴到聊天或插件认证字段。", "Paste these two values from the platform into Styx. Do not paste the runtime key into chat or plugin authentication.")).font(.caption).foregroundStyle(.secondary)
                Button(productText("保存并连接", "Save and connect")) { model.configureTunnel() }.disabled(model.tunnelID.isEmpty || model.runtimeKey.isEmpty || !model.session["tunnelSupported"].bool)
            } else {
                statusRow(productText("本机连接", "Local connection"), model.journey["tunnel"]["transport"].string)
                if model.journey["tunnel"]["status"].string == "configured" { Button(productText("启动连接", "Start connection")) { model.startTunnel() } }
                Text(productText("本机连接正常后，还需在目标聊天完成验证。", "A local connection still needs verification in your target chat.")).font(.caption).foregroundStyle(.secondary)
            }
        }
    }
    private var pluginPanel: some View {
        ProductPanel(title: productText("2. 你的 Styx 插件", "2. Your Styx plugin")) {
            Picker(productText("插件", "Plugin"), selection: $model.pluginMode) {
                Text(productText("创建新插件", "Create a plugin")).tag("create")
                Text(productText("关联已有插件", "Use an existing plugin")).tag("reuse")
            }.pickerStyle(.segmented).onChange(of: model.pluginMode) { _ in model.pluginDraftEdited = true }
            TextField(productText("插件名称", "Plugin name"), text: $model.pluginName).onChange(of: model.pluginName) { _ in model.pluginDraftEdited = true }
            TextField(productText("简短描述（最多 30 字）", "Short description (up to 30 characters)"), text: $model.pluginDescription).onChange(of: model.pluginDescription) { _ in model.pluginDraftEdited = true }
            HStack { ProductBrand(size: 32); Button(productText("更换图标…", "Choose icon…")) { model.selectIcon() }; if model.pluginIcon != .null { Text(productText("已选择图标", "Icon selected")).font(.caption) } }
            DisclosureGroup(productText("账号备注和插件链接（可选）", "Account note and plugin link (optional)")) {
                TextField(productText("账号／工作区备注", "Account / workspace note"), text: $model.accountLabel).onChange(of: model.accountLabel) { _ in model.pluginDraftEdited = true }
                TextField(productText("官方插件链接", "Official plugin link"), text: $model.pluginURL).onChange(of: model.pluginURL) { _ in model.pluginDraftEdited = true }
            }
            Button(productText("保存插件资料", "Save plugin details")) { model.savePlugin() }.disabled(model.pluginName.isEmpty || model.pluginName.count > 64 || model.pluginDescription.isEmpty || model.pluginDescription.count > 30)
        }
    }
    private var officialPanel: some View {
        ProductPanel(title: productText("3. 在 ChatGPT 完成连接", "3. Finish connecting in ChatGPT")) {
            Text(productText("① 打开 ChatGPT 插件页面，确认目标账号和工作区。", "① Open ChatGPT plugins and confirm the intended account and workspace."))
            Text(model.pluginMode == "reuse" ? productText("② 打开已有的 Styx 插件，检查它连接的是下面这个 Tunnel。", "② Open your existing Styx plugin and check that it uses the Tunnel below.") : productText("② 点击“＋”→“添加自建 MCP 服务器”（Add custom MCP server），填写上面的名称和描述。", "② Select + → Add custom MCP server, then enter the name and description above."))
            Text(productText("③ Connection 选择 Tunnel，选择或粘贴下面的 Tunnel ID；Authentication 选择 No authentication。运行 Key 只填在 Styx App 中。", "③ Under Connection, choose Tunnel and select or paste the Tunnel ID below. For Authentication choose No authentication. Enter the runtime key only in the Styx App."))
            Text(model.pluginMode == "reuse" ? productText("④ 保存已有插件的连接设置，确认已安装，然后在新聊天中用 @ 选择这个 Styx 插件。", "④ Save the existing plugin's connection settings, confirm it is installed, then select that Styx plugin with @ in a new chat.") : productText("④ 核对后点击“创建为插件”（Create as a plugin），打开生成的插件并安装。然后在新聊天中用 @ 选择 Styx。", "④ Review the details and select Create as a plugin. Open the resulting plugin and install it, then select Styx with @ in a new chat."))
            Text(productText("登录、MFA 和工作区审批需要你亲自完成。", "Complete any sign-in, MFA and workspace approval yourself.")).font(.caption).foregroundStyle(.secondary)
            HStack {
                Button(productText("复制名称", "Copy name")) { model.copy(model.pluginName) }
                Button(productText("复制描述", "Copy description")) { model.copy(model.pluginDescription) }
                Button(productText("保存图标…", "Save icon…")) { model.exportPluginIcon() }
            }
            if !model.connectionTunnelID.isEmpty {
                HStack { Text(model.connectionTunnelID).font(.system(.caption, design: .monospaced)).textSelection(.enabled); Button(productText("复制 Tunnel ID", "Copy Tunnel ID")) { model.copy(model.connectionTunnelID) } }
            } else {
                Button(productText("刷新连接信息", "Refresh connection details")) { Task { await model.refresh() } }
            }
            Button(productText("打开 ChatGPT 插件", "Open ChatGPT plugins")) { model.openOfficial("https://chatgpt.com/plugins") }
            DisclosureGroup(productText("另外两个入口是做什么的？", "What are the other two options for?")) {
                Text(productText("“创建插件”用于从需求编写技能或组合功能；“上传插件压缩包”用于导入已打包的插件与技能。连接这台 Styx 电脑，先选“添加自建 MCP 服务器”，它会创建可安装的插件。", "Create a plugin helps author skills and combined workflows. Upload plugin ZIP imports an existing package with its skills. To connect this Styx computer, start with Add custom MCP server; it creates an installable plugin.")).font(.callout).foregroundStyle(.secondary)
                Text(productText("ZIP 可作为包含 Styx 引导技能的可选完整包，仍需完成账号侧连接与真实调用验证。", "A ZIP can optionally include the Styx onboarding skill. Account connection and a real tool-call check are still required.")).font(.caption).foregroundStyle(.secondary)
            }
            Button(productText("我已完成安装和连接", "I finished installation and connection")) { model.confirmPluginInstallation() }.disabled(model.pluginDraftEdited)
            Text(productText("这只记录你的确认；下一步会检查真实工具调用。", "This records your confirmation. The next step verifies real tool calls.")).font(.caption).foregroundStyle(.secondary)
        }
    }
    private var acceptancePanel: some View {
        ProductPanel(title: productText("4. 在真实聊天中验证", "4. Verify in your real chat")) {
            Button(productText("生成验证请求", "Generate verification request")) { model.beginAcceptance() }
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
                        Toggle("Computer Use", isOn: $model.computer)
                        Toggle("Browser Automation", isOn: $model.browser)
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

@MainActor final class ProductWindowController: NSWindowController, NSWindowDelegate {
    let model: ProductModel
    weak var acceptanceField: NSTextField?
    let ownerAppPID = Int(ProcessInfo.processInfo.processIdentifier)
    private var observationTimer: Timer?
    init(sessionURL: URL) {
        // Bootstrap was already checked by the App's child-pipe parser; keep a
        // failable client construction here so tests can cover its own boundary.
        do { model = try ProductModel(sessionURL: sessionURL) }
        catch { preconditionFailure("Invalid owned Styx bootstrap") }
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 820, height: 720), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Styx"; window.minSize = NSSize(width: 650, height: 600)
        super.init(window: window)
        window.delegate = self; window.contentView = NSHostingView(rootView: ProductView(model: model, controller: self))
        window.center(); window.setFrameAutosaveName("Styx.ProductWindow.v6")
        observationTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in await self?.observeDesktopReadback() }
        }
    }
    required init?(coder: NSCoder) { nil }
    func present() { model.observePermissions(); window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true) }
    func showPreferences() { model.page = .settings; present() }
    func windowWillClose(_ notification: Notification) { model.clearSecrets() }
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
