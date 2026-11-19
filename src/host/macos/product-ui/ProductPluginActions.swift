import AppKit
import UniformTypeIdentifiers

extension ProductModel {
    func observePluginDraftEdit() {
        pluginDraftEdited = (!pluginLongDescription.isEmpty && pluginLongDescription != plugin["presentation"]["longDescription"].string) || pluginName != plugin["presentation"]["displayName"].string
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
            let current = try await client.native("pluginRead")["plugin"]
            guard current["required"] == .bool(true), current["contextChanged"] == .bool(false) else { throw ProductCoreError.rejected }
            if pluginDraftEdited || !current["profileSaved"].bool || current["presentation"]["icon"] == .null {
                var icon = pluginIcon
                if icon == .null, let path = Bundle.main.resourceURL?.appendingPathComponent("brand/styx-plugin-icon.png"),
                   let bytes = try? Data(contentsOf: path), bytes.count <= 256 * 1024 {
                    icon = .object(["mimeType": .string("image/png"), "dataBase64": .string(bytes.base64EncodedString())])
                }
                let long = !pluginLongDescription.isEmpty ? pluginLongDescription : plugin["presentation"]["longDescription"].string ?? productText("通过 Styx 连接你的电脑，使用 CLI、Browser Automation 和 Computer Use。", "Connect your computers with Styx for CLI, Browser Automation and Computer Use.")
                var selection = current["selection"]
                if !current["profileSaved"].bool {
                    selection = .object(["mode": .string("update"), "accountLabel": .string(""), "pluginUrl": .string(""), "revision": current["selection"]["revision"], "pluginId": .string(pluginIdentity)])
                }
                plugin = try await client.native("pluginSave", ["authorize": .bool(true), "presentation": .object(["displayName": .string(pluginName), "shortDescription": .string(pluginDescription), "longDescription": .string(long), "icon": icon]), "selection": selection])["plugin"]
                pluginDraftEdited = false
            }
            let archive = try await client.exportPlugin()
            var info = stat()
            if lstat(destination.path, &info) == 0 && info.st_mode & S_IFMT != S_IFREG { throw ProductCoreError.rejected }
            try archive.write(to: destination, options: .atomic)
            exportedPluginURL = destination; exportCompletionID = UUID()
        }
    }

}

enum ProductBrandAsset {
    static var customMCPIcon: Data? {
        guard let url = Bundle.main.resourceURL?.appendingPathComponent("brand/styx-custom-mcp-icon.png"),
              let bytes = try? Data(contentsOf: url), bytes.count <= 10_000 else { return nil }
        return bytes
    }
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
        guard let bytes = ProductBrandAsset.customMCPIcon else {
            self.error = productText("安装包缺少可上传的 Styx 图标，请修复安装。", "The upload icon is missing from this installation. Repair the installation.")
            return
        }
        let panel = NSSavePanel(); panel.allowedContentTypes = [.png]; panel.nameFieldStringValue = "Styx.png"
        panel.title = productText("保存 Styx 图标", "Save Styx icon")
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try bytes.write(to: url, options: .atomic); NSWorkspace.shared.activateFileViewerSelecting([url]) }
        catch { self.error = productText("图标未能保存，请选择其他位置。", "The icon could not be saved. Choose another location.") }
    }
}
