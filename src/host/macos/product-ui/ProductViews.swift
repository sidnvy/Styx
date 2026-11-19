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
    let isMainWindow: Bool
    init(model: ProductModel, controller: ProductWindowController?, isMainWindow: Bool = false) {
        self.model = model; self.controller = controller
        self.isMainWindow = isMainWindow
    }
    var body: some View {
        if (isMainWindow && model.settingsVisible) || ([.overview, .computers, .settings].contains(model.page)) {
            ProductSettingsView(model: model, controller: controller)
        } else {
            onboardingBody
        }
    }
    private var onboardingBody: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 22) {
                    if !model.loaded {
                        ProductBrand(size: 56).frame(maxWidth: .infinity)
                        ProgressView(model.loadingMessage).frame(maxWidth: .infinity)
                        if model.error != nil { Button(productText("重试读取", "Retry reading")) { Task { await model.bootstrap() } } }
                    } else if model.nativeCanResumeLocal {
                        resumeLocalSetup
                    } else {
                        if model.status["enrollment"]["error"].string == "original_runtime_selection_required" {
                            Text(productText("此设置仍绑定原已签名运行组件。请保留原 App 和设置；此版本不能以新组件替换后继续设置。", "This setup still requires its original signed runtime. Keep the original App and settings; this version cannot replace that runtime to continue setup.")).foregroundStyle(.secondary)
                        }
                        switch model.page {
                        case .welcome: welcome
                        case .invitation: invitation
                        case .capabilities: capabilities
                        case .permissions: permissions
                        case .chat: chat
                        case .overview, .computers, .settings: ProductSettingsView(model: model, controller: controller)
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
            .task(id: model.onboardingVisible || model.settingsVisible) {
                if model.onboardingVisible || model.settingsVisible { await model.observePresentation() }
            }
            .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in model.observePermissions() }
            .onChange(of: model.page) { _ in model.observePermissions() }
    }
    private func heading(_ title: String, _ subtitle: String = "") -> some View {
        VStack(alignment: .leading, spacing: 9) {
            Text(title).font(.system(size: 23, weight: .semibold))
            if !subtitle.isEmpty { Text(subtitle).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
        }
    }
    private var setupTunnelFields: some View {
        Group {
            Text(productText("连接 ChatGPT", "Connect ChatGPT")).font(.headline)
            TextField("Tunnel ID", text: $model.setupTunnelID)
            SecureField(productText("Tunnel 运行密钥", "Tunnel runtime API key"), text: $model.setupTunnelKey)
        }.onDisappear { model.setupTunnelKey = "" }
    }
    private var resumeLocalSetup: some View {
        VStack(alignment: .leading, spacing: 20) {
            heading(productText("继续本机设置", "Continue local setup"), productText("原管理端已准备完成，配对尚未开始。继续将保留原身份、证书和运行组件。", "The original Gateway is prepared and pairing has not started. Continuing preserves its identity, certificates and runtime."))
            if let notice = model.nativeLanJoinNotice { Text(notice).font(.callout).textSelection(.enabled) }
            TextField(productText("电脑名称", "Computer name"), text: $model.label)
            Toggle(isOn: $model.exec) { ProductCapabilityLabel(kind: .cli) }
            Toggle(isOn: $model.computer) { ProductCapabilityLabel(kind: .computer) }
            Toggle(isOn: $model.browser) { ProductCapabilityLabel(kind: .browser) }
            Text(productText("将保存你选择的本机能力。确认后仅提交一次配对。", "This saves your chosen capabilities for this computer. Confirming submits pairing once.")).font(.callout).foregroundStyle(.secondary)
            setupTunnelFields
            Button(productText("确认并继续设置", "Confirm and continue setup")) { model.resumeLocalSetup() }
                .buttonStyle(.borderedProminent)
                .disabled(model.busy || model.setupTunnelInput == nil || model.label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
    }
    private var welcome: some View {
        VStack(spacing: 24) {
            ProductBrand(size: 100).padding(.top, 40)
            Text(productText("欢迎使用 Styx", "Welcome to Styx")).font(.system(size: 32, weight: .semibold))
            Text(productText("在 ChatGPT 中使用你的电脑。", "Use your computer from ChatGPT.")).foregroundStyle(.secondary)
            Button(productText("开始设置", "Get started")) { model.joining = false; model.page = .capabilities }.buttonStyle(.borderedProminent).controlSize(.large).disabled(!model.nativeCanCreateLocal)
            Button(productText("加入已有 Styx", "Join an existing Styx")) { model.joining = true; model.page = .invitation }.buttonStyle(.link)
        }.frame(maxWidth: .infinity).padding(.bottom, 50)
    }
    private var capabilities: some View {
        VStack(alignment: .leading, spacing: 20) {
            heading(productText("允许 ChatGPT 做什么？", "What can ChatGPT do?"), productText("选择 ChatGPT 可以在这台电脑上使用的功能。", "Choose the features ChatGPT can use on this computer."))
            ProductPanel(title: productText("这台电脑的功能", "Features on this computer")) {
                Toggle(isOn: $model.exec) { ProductCapabilityLabel(kind: .cli) }
                Divider()
                Toggle(isOn: $model.computer) { ProductCapabilityLabel(kind: .computer) }
                Text(productText("需要你在系统设置中授予“辅助功能”和“屏幕录制”权限；下一步会引导你完成。", "Needs Accessibility and Screen Recording permission in System Settings; the next step guides you.")).font(.caption).foregroundStyle(.secondary)
                Divider()
                Toggle(isOn: $model.browser) { ProductCapabilityLabel(kind: .browser) }
                Text(productText("自动准备专用浏览器；网站登录时由你确认。", "A dedicated browser is prepared for you. Sign in to websites when needed.")).font(.caption).foregroundStyle(.secondary)
            }
            TextField(productText("电脑名称", "Computer name"), text: $model.label)
            if !model.joining {
                setupTunnelFields
                Toggle(productText("允许网络上的其他电脑加入此网关", "Let other computers on my network join this Gateway"), isOn: $model.allowRemoteHosts)
                if model.allowRemoteHosts {
                    if model.networkDiscoveryLoading { ProgressView(productText("正在检测网络…", "Detecting networks…")) }
                    Picker(productText("用于其他电脑加入的网络", "Network for other computers"), selection: $model.lanAddress) {
                        Text(productText("自动选择", "Automatic")).tag("")
                        ForEach(model.networkInterfaces["interfaces"].array.indices, id: \.self) { index in
                            let interface = model.networkInterfaces["interfaces"].array[index]
                            let address = interface["address"].string ?? ""
                            Text((interface["name"].string ?? "") + " · " + address).tag(address)
                        }
                        if !model.lanAddress.isEmpty && !model.networkInterfaces["interfaces"].array.contains(where: { $0["address"].string == model.lanAddress }) {
                            Text(productText("手动地址：", "Manual address: ") + model.lanAddress).tag(model.lanAddress)
                        }
                    }
                    Text(productText("自动发现这台电脑当前可用的局域网或 VPN 地址。其他电脑需能通过所选网络访问本机。", "Available LAN and VPN addresses are detected automatically. Other computers need access to the selected network.")).font(.caption).foregroundStyle(.secondary)
                    if let error = model.networkDiscoveryError { Text(error).font(.caption).foregroundStyle(.secondary) }
                    Button(productText("重新检测网络", "Detect networks again")) { model.discoverNetworkInterfaces() }.disabled(model.networkDiscoveryLoading)
                    DisclosureGroup(productText("高级：手动地址", "Advanced: manual address")) {
                        TextField(productText("这台电脑现有接口的 IPv4 地址", "IPv4 address of an existing interface"), text: $model.lanAddress)
                    }.font(.caption)
                }
            }
            HStack {
                Button(productText("返回", "Back")) { model.page = model.joining ? .invitation : .welcome }
                Spacer()
                Button(productText("继续", "Continue")) { model.createAndPrepare() }.buttonStyle(.borderedProminent)
                    .disabled(model.busy || (!model.joining && model.allowRemoteHosts && model.networkDiscoveryLoading) || model.label.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || (!model.joining && (!model.nativeCanCreateLocal || model.setupTunnelInput == nil)) || (!model.session["defaults"]["bundle"].string == nil))
            }
        }.task(id: model.allowRemoteHosts) {
            if !model.joining && model.allowRemoteHosts { model.discoverNetworkInterfaces() }
        }
    }
    private var permissions: some View {
        VStack(alignment: .leading, spacing: 20) {
            heading(productText("允许 Styx 操作电脑", "Allow Styx to use this computer"), productText("请在 macOS 中为 Styx 开启以下权限。", "Enable these permissions for Styx in macOS."))
            ProductPanel(title: productText("系统权限", "System permissions")) {
                permissionRow(productText("辅助功能", "Accessibility"), granted: model.axGranted, screen: false)
                Divider()
                permissionRow(productText("屏幕录制", "Screen Recording"), granted: model.screenGranted, screen: true)
                Text(productText("修改权限后可能需要退出并重新打开 Styx。应用脚本可能另外请求 Automation 授权。", "After changing permissions, you may need to quit and reopen Styx. Application scripts can separately require Automation permission.")).font(.caption).foregroundStyle(.secondary)
            }
            if !model.axGranted || !model.screenGranted {
                DisclosureGroup(productText("开关已开启，但这里仍未识别？", "Enabled in System Settings but still not recognized?")) {
                    Text(productText("请确认系统设置中开启的是“应用程序”里的 Styx，然后退出并重新打开 Styx，再点击“重新检查权限”。", "Confirm that System Settings grants access to Styx in Applications. Quit and reopen Styx, then select Check permissions again.")).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                }
            }
            Button(productText("重新检查权限", "Check permissions again")) { model.observePermissions() }
            Button(productText("继续", "Continue")) { model.continueAfterPermissions() }.buttonStyle(.borderedProminent).disabled(!model.axGranted || !model.screenGranted)
        }
    }
    private func permissionRow(_ title: String, granted: Bool, screen: Bool) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Label(title, systemImage: screen ? "record.circle" : "accessibility")
                Text(screen ? productText("查看屏幕内容", "View screen content") : productText("点击、滚动和输入", "Click, scroll and type")).font(.caption).foregroundStyle(.secondary)
            }
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
            heading(productText("加入已有 Styx", "Join an existing Styx"), productText("在已经设置好 Styx 的电脑上打开“设置 → 电脑 → 添加电脑”，获取地址和配对码。", "On the computer where Styx is already set up, open Settings → Computers → Add computer to get the address and pairing code."))
            SecureField(productText("网关地址和配对码（也可粘贴邀请）", "Gateway address and code (or paste invitation)"), text: $model.invite)
            Button(productText("检查邀请", "Inspect invitation")) { model.inspectInvitation() }.disabled(model.invite.isEmpty)
            if let origin = model.inspection["preview"]["origin"].string {
                ProductPanel(title: productText("核对管理电脑身份", "Verify the main computer")) {
                    Text(origin).textSelection(.enabled)
                    if let fingerprint = model.inspection["preview"]["caSha256"].string { Text(fingerprint).font(.system(.caption, design: .monospaced)).textSelection(.enabled) }
                    Text(productText("确认这是你要加入的网关。", "Confirm that this is the Gateway you want to join.")).font(.callout).foregroundStyle(.secondary)
                    Button(productText("已核对，继续", "Details match — continue")) { model.acceptInvitation() }.buttonStyle(.borderedProminent)
                }
            }
            Button(productText("返回", "Back")) { model.cancelInvitationReview() }
        }
    }
    private var chat: some View { ProductNativeChatView(model: model) }

}

@MainActor final class ProductWindowController: NSWindowController, NSWindowDelegate, NSPopoverDelegate {
    let model: ProductModel
    private var menuPopover: NSPopover?
    private var menuSizeTimer: Timer?

    init(model: ProductModel) {
        self.model = model
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 680, height: 640), styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        window.title = "Styx"; window.minSize = NSSize(width: 620, height: 560)
        window.isReleasedWhenClosed = false
        window.identifier = NSUserInterfaceItemIdentifier("Styx.SettingsWindow")
        super.init(window: window)
        window.delegate = self; window.contentView = NSHostingView(rootView: ProductView(model: model, controller: self, isMainWindow: true))
        window.center(); window.setFrameAutosaveName("Styx.ProductWindow.v6")
    }
    required init?(coder: NSCoder) { nil }
    func present() {
        if [.overview, .computers, .settings].contains(model.page) {
            showSettings(.computers); return
        }
        menuPopover?.performClose(nil); model.settingsVisible = false; model.onboardingVisible = true; model.observePermissions(); window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true) }
    func showPreferences() { showSettings(.general) }
    func showOnboarding() {
        menuPopover?.performClose(nil)
        if model.nativeCanResumeLocal || model.nativeCanCreateLocal && [.overview, .computers, .settings].contains(model.page) { model.page = .welcome }
        present()
    }
    func showSettings(_ section: ProductSettingsSection) {
        menuPopover?.performClose(nil)
        model.requestSettings(section); model.settingsVisible = true; model.onboardingVisible = false; model.observePermissions()
        window?.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true)
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
            guard let owner = self, let panel = popover else { return }
            Task { @MainActor in
                guard panel.isShown else { return }
                let size = host.view.fittingSize
                let target = NSSize(width: 332, height: min(720, max(120, size.height)))
                if abs(panel.contentSize.height - target.height) > 1 { panel.contentSize = target }
                _ = owner
            }
        }
    }
    func popoverDidClose(_ notification: Notification) {
        model.menuVisible = false; menuSizeTimer?.invalidate(); menuSizeTimer = nil
    }

    func windowWillClose(_ notification: Notification) {
        if let closing = notification.object as? NSWindow {
            if closing === window { model.settingsVisible = false; model.onboardingVisible = false }
        }
        if !model.settingsVisible && !model.onboardingVisible { model.clearSecrets() }
    }
    func prepareToQuit(completion: @escaping (Bool) -> Void) {
        model.clearSecrets()
        Task {
            do {
                try await model.client.quitNative()
                menuSizeTimer?.invalidate(); menuSizeTimer = nil; menuPopover?.performClose(nil)
                completion(true)
            } catch {
                completion(false)
                let alert = NSAlert()
                alert.messageText = productText("暂时无法安全退出 Styx", "Styx could not finish quitting")
                alert.informativeText = productText("尚未确认本机任务全部结束。请检查当前状态后再次选择“退出 Styx”。", "Local work has not been confirmed stopped. Check its current state, then choose Quit Styx again.")
                if let parent = window {
                    showWindow(nil); NSApp.activate(ignoringOtherApps: true)
                    alert.beginSheetModal(for: parent) { _ in }
                }
            }
        }
    }
}
