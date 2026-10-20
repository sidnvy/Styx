import AppKit
import SwiftUI

struct ProductBrand: View {
    @Environment(\.colorScheme) private var scheme
    var size: CGFloat = 68
    var body: some View {
        let filename = scheme == .dark ? "styx-icon-dark-source.jpg" : "styx-icon-light-source.jpg"
        if let root = Bundle.main.resourceURL, let image = NSImage(contentsOf: root.appendingPathComponent("brand/" + filename)) {
            Image(nsImage: image).resizable().scaledToFill().frame(width: size, height: size).clipped().clipShape(RoundedRectangle(cornerRadius: size * 0.2)).accessibilityLabel("Styx")
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
                        ProgressView(productText("正在读取 Styx…", "Reading Styx…")).frame(maxWidth: .infinity)
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
            heading(productText("准备电脑", "Prepare your computer"), model.joined ? productText("请在主台核对并批准这台电脑。", "Review and approve this computer on the main computer.") : productText("Styx 会准备所选能力，并保留已有设置。", "Styx prepares your selected capabilities and preserves existing settings."))
            ProductPanel(title: productText("设置进度", "Setup progress")) {
                ForEach(model.deployment?.steps.filter { !$0.id.contains("service") } ?? []) { step in
                    HStack { Text(stepTitle(step.id)); Spacer(); Text(stateTitle(step.status)).foregroundStyle(.secondary) }
                    if let fingerprint = model.status["deployment"]["steps"].array.first(where: { $0["id"].string == step.id })?["fingerprint"].string {
                        Text(fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    }
                }
            }
            Button(model.localPrepared ? productText("启动所选能力", "Start selected capabilities") : productText("继续准备", "Continue setup")) { model.continuePreparation() }.buttonStyle(.borderedProminent)
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
            Button(productText("重新检查权限", "Check permissions again")) { model.observePermissions() }
            Button(productText("继续", "Continue")) { model.page = model.joined ? .overview : .chat }.buttonStyle(.borderedProminent).disabled(!model.axGranted || !model.screenGranted)
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
            Text(model.pluginMode == "reuse" ? productText("② 选择已有的 Styx 插件，核对其名称与连接。", "② Select your existing Styx plugin and review its name and connection.") : productText("② 创建私有插件，填写上面的名称、描述与图标。", "② Create a private plugin using the name, description and icon above."))
            Text(productText("③ 连接方式选择 Tunnel，填写同一个 Tunnel ID。若页面要求 Bearer Token，再从下方读取 Styx 专用凭据。", "③ Choose a Tunnel connection and enter the same Tunnel ID. If the form requests a Bearer Token, reveal the dedicated Styx credential below."))
            Text(productText("④ 按页面提示保存、安装并启用连接，再回到这里确认。平台登录、MFA 和工作区审批需要你完成。", "④ Save, install and enable the connection as prompted, then return here. Complete any sign-in, MFA and workspace approval yourself."))
            HStack {
                Button(productText("复制名称", "Copy name")) { model.copy(model.pluginName) }
                Button(productText("复制描述", "Copy description")) { model.copy(model.pluginDescription) }
                Button(productText("保存图标…", "Save icon…")) { model.exportPluginIcon() }
            }
            if !model.connectionTunnelID.isEmpty {
                HStack { Text(model.connectionTunnelID).font(.system(.caption, design: .monospaced)).textSelection(.enabled); Button(productText("复制 Tunnel ID", "Copy Tunnel ID")) { model.copy(model.connectionTunnelID) } }
            } else {
                Button(productText("读取本次连接填写信息", "Read connection details")) { model.revealHandoff() }
            }
            Button(productText("打开 ChatGPT 插件", "Open ChatGPT plugins")) { model.openOfficial("https://chatgpt.com/plugins") }
            DisclosureGroup(productText("页面要求 Bearer Token？", "Does the form request a Bearer Token?")) {
                Button(productText("显示 Styx 专用凭据（60 秒）", "Reveal Styx credential (60 seconds)")) { model.revealHandoff() }
                if !model.handoffCredential.isEmpty {
                    Text(model.handoffTarget).textSelection(.enabled)
                    SecureField("Bearer Token", text: .constant(model.handoffCredential))
                    HStack { Button(productText("复制 Token", "Copy token")) { model.copy(model.handoffCredential, secret: true) }; Button(productText("清除", "Clear")) { model.clearSecrets() } }
                }
                Text(productText("这是 Styx→ChatGPT 的认证信息，与平台→Styx 的运行 Key 不同。不要发送到聊天。", "This Styx→ChatGPT credential is different from the platform→Styx runtime key. Never send it in chat.")).font(.caption).foregroundStyle(.secondary)
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
                statusRow("Browser Automation", model.journey["readiness"]["browser"]["status"].string)
                statusRow("Computer Use", model.journey["readiness"]["desktop"]["status"].string)
                if !model.localPrepared { Button(productText("继续设置", "Continue setup")) { model.page = .preparation } }
                if model.deployment?.computerRequested == true && (!model.axGranted || !model.screenGranted) { Button(productText("检查系统权限", "Review system permissions")) { model.page = .permissions } }
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
                    Toggle("Computer Use", isOn: $model.computer)
                    Toggle("Browser Automation", isOn: $model.browser)
                    Text(productText("更改能力可能短暂重启连接，请先完成正在进行的操作。", "Changing capabilities may briefly restart the connection. Finish active operations first.")).font(.caption).foregroundStyle(.secondary)
                    Button(productText("应用更改", "Apply changes")) { model.updateCapabilities() }
                }
            }
        }
    }
    private func statusRow(_ title: String, _ status: String?) -> some View {
        HStack { Text(title); Spacer(); Text(stateTitle(status ?? "not_observed")).foregroundStyle(.secondary) }
    }
    private func stateTitle(_ status: String) -> String {
        switch status {
        case "succeeded", "completed": return productText("已完成", "Completed")
        case "connected", "ready": return productText("已连接，待实际验证", "Connected; verification separate")
        case "verified": return productText("实际验证通过", "Verified by execution")
        case "not_requested", "not_required", "skipped": return productText("未启用或无需检查", "Not enabled or not required")
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
    func present() { window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true) }
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
