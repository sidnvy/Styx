import AppKit
import UniformTypeIdentifiers

// Direct connection does not need an editable local presentation step. Only an
// explicit account confirmation creates a missing default receipt profile.
// A saved profile (including a custom/reused one) is never replaced here.
enum ProductPluginWorkflow {
    static func defaultProfileIfMissing(_ current: ProductJSON) throws -> [String: ProductJSON]? {
        guard current["required"] == .bool(true), current["contextChanged"] == .bool(false) else { throw ProductCoreError.rejected }
        if current["profileSaved"].bool { return nil }
        guard current["profileSaved"] == .bool(false), !current["presentation"].object.isEmpty, !current["selection"].object.isEmpty else { throw ProductCoreError.invalidResponse }
        return ["authorize": .bool(true), "presentation": current["presentation"], "selection": current["selection"]]
    }
    static func reboundProfile(_ current: ProductJSON) throws -> [String: ProductJSON] {
        guard current["required"] == .bool(true), current["profileSaved"].bool,
              current["contextChanged"].bool, !current["presentation"].object.isEmpty,
              !current["selection"].object.isEmpty else { throw ProductCoreError.rejected }
        return ["authorize": .bool(true), "presentation": current["presentation"], "selection": current["selection"]]
    }
}

extension ProductModel {
    func observePluginDraftEdit() {
        pluginDraftEdited = pluginName != plugin["presentation"]["displayName"].string
            || pluginDescription != plugin["presentation"]["shortDescription"].string
            || pluginIcon != plugin["presentation"]["icon"]
    }
    // Entering the optional editor creates an unsaved draft. Only Save and
    // export persists it; direct connection never changes a saved profile.
    func preparePluginDraft(defaultIcon: ProductJSON? = nil) {
        guard pluginMode == "create", pluginIcon == .null else { return }
        var icon = defaultIcon ?? .null
        if icon == .null, let path = Bundle.main.resourceURL?.appendingPathComponent("brand/styx-plugin-icon.png"),
           let bytes = try? Data(contentsOf: path), bytes.count <= 256 * 1024 {
            icon = .object(["mimeType": .string("image/png"), "dataBase64": .string(bytes.base64EncodedString())])
        }
        if icon != .null { pluginIcon = icon; pluginDraftEdited = true }
    }
    func rebindPluginConnection() {
        let alert = NSAlert()
        alert.messageText = productText("重新核对聊天连接", "Review the changed chat connection")
        alert.informativeText = productText("请先在 ChatGPT 核对下方的 Tunnel。继续会保留插件资料，并要求重新确认安装和执行聊天验证；不会更改电脑身份或凭据。", "First check the Tunnel shown below in ChatGPT. Continuing preserves plugin details and requires new installation confirmation and chat verification. Computer identity and credentials are retained.")
        alert.addButton(withTitle: productText("已核对，更新记录", "Checked — update record"))
        alert.addButton(withTitle: productText("取消", "Cancel"))
        let expectedConnection = plugin["connection"]
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        perform { [self] in
            let current = try await client.read("plugin")["plugin"]
            guard current["connection"] == expectedConnection else { throw ProductCoreError.rejected }
            _ = try await client.write("plugin/profile", ProductPluginWorkflow.reboundProfile(current))
            exportedPluginURL = nil
        }
    }
    func exportPluginPackage() {
        let panel = NSSavePanel()
        panel.title = productText("导出 Styx 插件包", "Export Styx plugin package")
        panel.allowedContentTypes = [.zip]; panel.allowsOtherFileTypes = false
        panel.nameFieldStringValue = "styx-native.zip"
        guard panel.runModal() == .OK, let destination = panel.url,
              destination.isFileURL, destination.pathExtension.lowercased() == "zip" else { return }
        exportedPluginURL = nil
        perform { [self] in
            let current = try await client.read("plugin")["plugin"]
            guard current["required"] == .bool(true), current["contextChanged"] == .bool(false), current["selection"]["mode"].string == "create" else { throw ProductCoreError.rejected }
            if pluginDraftEdited || !current["profileSaved"].bool {
                var icon = pluginIcon
                if icon == .null, let path = Bundle.main.resourceURL?.appendingPathComponent("brand/styx-plugin-icon.png"),
                   let bytes = try? Data(contentsOf: path), bytes.count <= 256 * 1024 {
                    icon = .object(["mimeType": .string("image/png"), "dataBase64": .string(bytes.base64EncodedString())])
                }
                let long = plugin["presentation"]["longDescription"].string ?? productText("通过 Styx 连接你的电脑，使用 CLI、Browser Automation 和 Computer Use。", "Connect your computers with Styx for CLI, Browser Automation and Computer Use.")
                plugin = try await client.write("plugin/profile", ["authorize": .bool(true), "presentation": .object(["displayName": .string(pluginName), "shortDescription": .string(pluginDescription), "longDescription": .string(long), "icon": icon]), "selection": .object(["mode": .string("create"), "accountLabel": .string(accountLabel), "pluginUrl": .string(pluginURL)])])["plugin"]
                pluginMode = "create"; pluginDraftEdited = false
            }
            let archive = try await client.exportPlugin()
            var info = stat()
            if lstat(destination.path, &info) == 0 && info.st_mode & S_IFMT != S_IFREG { throw ProductCoreError.rejected }
            try archive.write(to: destination, options: .atomic)
            exportedPluginURL = destination
        }
    }

    func confirmPluginInstallation() {
        perform { [self] in
            let current = try await client.read("plugin")["plugin"]
            if let defaults = try ProductPluginWorkflow.defaultProfileIfMissing(current) {
                _ = try await client.write("plugin/profile", defaults)
            }
            // This is a user attestation, never a provider/API success claim.
            // Leave existing profile metadata, URLs and archive receipts intact.
            _ = try await client.write("plugin/record", ["authorize": .bool(true), "stage": .string("installation")])
        }
    }
}
