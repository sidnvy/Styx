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
        var presentation = current["presentation"].object
        if presentation["icon"] == nil || presentation["icon"] == .null, let icon = ProductBrandAsset.icon { presentation["icon"] = icon }
        return ["authorize": .bool(true), "presentation": .object(presentation), "selection": current["selection"]]
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
        guard pluginIcon == .null else { return }
        var icon = defaultIcon ?? .null
        if icon == .null, let path = Bundle.main.resourceURL?.appendingPathComponent("brand/styx-plugin-icon.png"),
           let bytes = try? Data(contentsOf: path), bytes.count <= 256 * 1024 {
            icon = .object(["mimeType": .string("image/png"), "dataBase64": .string(bytes.base64EncodedString())])
        }
        if icon != .null { pluginIcon = icon; pluginDraftEdited = true }
    }
    func rebindPluginConnection() {
        let alert = NSAlert()
        alert.messageText = productText("更新插件的连接信息？", "Update the plugin connection?")
        alert.informativeText = productText("请先确认 ChatGPT 中已有 Styx 使用的是设置页显示的 Tunnel ID。继续后会保留插件名称和图标，并重新进行安装确认与试用。", "First confirm that the existing Styx in ChatGPT uses the Tunnel ID shown in Settings. Continuing keeps its name and icon, and starts a new installation confirmation and test.")
        alert.addButton(withTitle: productText("已核对，继续", "Checked — continue"))
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
        panel.directoryURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
        guard panel.runModal() == .OK, let destination = panel.url,
              destination.isFileURL, destination.pathExtension.lowercased() == "zip" else { return }
        exportedPluginURL = nil
        perform { [self] in
            let current = try await client.read("plugin")["plugin"]
            guard current["required"] == .bool(true), current["contextChanged"] == .bool(false) else { throw ProductCoreError.rejected }
            if pluginDraftEdited || !current["profileSaved"].bool || current["presentation"]["icon"] == .null {
                var icon = pluginIcon
                if icon == .null, let path = Bundle.main.resourceURL?.appendingPathComponent("brand/styx-plugin-icon.png"),
                   let bytes = try? Data(contentsOf: path), bytes.count <= 256 * 1024 {
                    icon = .object(["mimeType": .string("image/png"), "dataBase64": .string(bytes.base64EncodedString())])
                }
                let long = plugin["presentation"]["longDescription"].string ?? productText("通过 Styx 连接你的电脑，使用 CLI、Browser Automation 和 Computer Use。", "Connect your computers with Styx for CLI, Browser Automation and Computer Use.")
                plugin = try await client.write("plugin/profile", ["authorize": .bool(true), "presentation": .object(["displayName": .string(pluginName), "shortDescription": .string(pluginDescription), "longDescription": .string(long), "icon": icon]), "selection": current["selection"]])["plugin"]
                pluginMode = current["selection"]["mode"].string ?? "create"; pluginDraftEdited = false
            }
            let archive = try await client.exportPlugin()
            var info = stat()
            if lstat(destination.path, &info) == 0 && info.st_mode & S_IFMT != S_IFREG { throw ProductCoreError.rejected }
            try archive.write(to: destination, options: .atomic)
            exportedPluginURL = destination; exportCompletionID = UUID()
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

enum ProductBrandAsset {
    static var data: Data? {
        guard let url = Bundle.main.resourceURL?.appendingPathComponent("brand/styx-plugin-icon.png"),
              let bytes = try? Data(contentsOf: url), bytes.count <= 256 * 1024 else { return nil }
        return bytes
    }
    static var icon: ProductJSON? {
        data.map { .object(["mimeType": .string("image/png"), "dataBase64": .string($0.base64EncodedString())]) }
    }
}
extension ProductModel {
    func saveBrandIcon() {
        guard let bytes = ProductBrandAsset.data else { return }
        let panel = NSSavePanel(); panel.allowedContentTypes = [.png]; panel.nameFieldStringValue = "Styx.png"
        panel.title = productText("保存 Styx 图标", "Save Styx icon")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try bytes.write(to: url, options: .atomic); NSWorkspace.shared.activateFileViewerSelecting([url]) }
        catch { self.error = productText("图标未能保存，请选择其他位置。", "The icon could not be saved. Choose another location.") }
    }
}
