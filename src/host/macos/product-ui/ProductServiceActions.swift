#if STYX_PRODUCT_UI
import AppKit
import CryptoKit
import Darwin
import Foundation
import SwiftUI

// Export DATA only. UInt64 projections validate the original report without
// ever reconstructing it from ProductJSON's Double-valued presentation DTO.
struct ProductServiceReviewRequest: Sendable {
    let report: Data
    let definition: Data
    let transactionID: String
    private struct Projection: Decodable {
        let schema: UInt16
        let operation: String
        let configuration_only: Bool
        let operations_replayed: Bool
        let revision: UInt64
        let uid: UInt32
        let definition_plist: String
        let installation_request_v1: Request
        struct Request: Decodable {
            let schema: UInt16
            let kind: String
            let role: String
            let revision: UInt64
            let uid: UInt32
            let transaction_id: String
            let definition_plist: String
            let definition_sha256: String
            let state_root: Root
            struct Root: Decodable { let device: UInt64; let inode: UInt64; let uid: UInt32 }
        }
    }
    init(_ original: String) throws {
        let raw = Data(original.utf8)
        guard !raw.isEmpty, raw.count <= 256 * 1024 else { throw ProductCoreError.invalidResponse }
        let value = try JSONDecoder().decode(Projection.self, from: raw)
        let request = value.installation_request_v1
        let plist = Data(value.definition_plist.utf8)
        let digest = SHA256.hash(data: plist).map { String(format: "%02x", $0) }.joined()
        guard value.schema == 1, value.operation == "prepare_first_start",
              value.configuration_only, !value.operations_replayed,
              request.schema == 1, request.kind == "launchd_first_start", request.role == "host",
              value.revision == request.revision, value.uid == request.uid,
              request.state_root.uid == request.uid, request.uid > 0, request.state_root.inode > 0,
              request.definition_plist == value.definition_plist, !plist.isEmpty, plist.count <= 65536,
              request.definition_sha256 == digest,
              request.transaction_id.range(of: "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", options: .regularExpression) != nil else {
            throw ProductCoreError.invalidResponse
        }
        // Preserve the exact Rust serialization, including every integer digit.
        report = raw; definition = plist; transactionID = request.transaction_id
    }
    func writeNewDirectory(in parent: URL) throws -> URL {
        guard parent.isFileURL, parent.path == parent.standardizedFileURL.path else { throw ProductCoreError.rejected }
        let parentFD = open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard parentFD >= 0 else { throw ProductCoreError.rejected }
        defer { close(parentFD) }
        var parentBefore = stat()
        guard fstat(parentFD, &parentBefore) == 0, parentBefore.st_mode & S_IFMT == S_IFDIR else { throw ProductCoreError.rejected }
        let name = "Styx-Service-Request-" + transactionID + "-" + String(UUID().uuidString.lowercased().prefix(8))
        guard mkdirat(parentFD, name, mode_t(0o700)) == 0 else { throw ProductCoreError.rejected }
        let directoryFD = openat(parentFD, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directoryFD >= 0 else { throw ProductCoreError.rejected }
        defer { close(directoryFD) }
        var original = stat()
        guard fstat(directoryFD, &original) == 0, original.st_uid == getuid(), original.st_mode & 0o077 == 0 else { throw ProductCoreError.rejected }
        // Exclusive fixed filenames never replace an existing file or symlink.
        // Partial export output is preserved on error. Retrying Save exports
        // this same immutable DATA to a new folder; no Core call is performed.
        try Self.write(report, name: "installation-report.json", directory: directoryFD)
        try Self.write(definition, name: "definition.plist", directory: directoryFD)
        guard fsync(directoryFD) == 0, fsync(parentFD) == 0 else { throw ProductCoreError.rejected }
        var named = stat(), parentAfter = stat()
        guard fstatat(parentFD, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              named.st_dev == original.st_dev, named.st_ino == original.st_ino, named.st_mode & S_IFMT == S_IFDIR,
              lstat(parent.path, &parentAfter) == 0,
              parentAfter.st_dev == parentBefore.st_dev, parentAfter.st_ino == parentBefore.st_ino else { throw ProductCoreError.rejected }
        return parent.appendingPathComponent(name, isDirectory: true)
    }
    private static func write(_ data: Data, name: String, directory: Int32) throws {
        let fd = openat(directory, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
        guard fd >= 0 else { throw ProductCoreError.rejected }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close() }
        try handle.write(contentsOf: data)
        guard fsync(fd) == 0 else { throw ProductCoreError.rejected }
        try handle.seek(toOffset: 0)
        guard try handle.readToEnd() == data else { throw ProductCoreError.invalidResponse }
        var original = stat(), named = stat()
        guard fstat(fd, &original) == 0, original.st_mode & S_IFMT == S_IFREG,
              original.st_uid == getuid(), original.st_nlink == 1, original.st_mode & 0o077 == 0,
              fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) == 0,
              original.st_dev == named.st_dev, original.st_ino == named.st_ino else { throw ProductCoreError.rejected }
    }
}

extension ProductModel {
    func nativeSupportsOperation(_ operation: String) -> Bool {
        nativeHost && status["supportedOperations"].array.contains { $0.string == operation }
    }
    var nativeService: ProductJSON { status["service"] }
    var nativeHasServiceState: Bool { nativeHost && nativeService != .null }
    var nativeServiceUnconfirmed: Bool {
        nativeService["status"].string == "unknown" || !client.nativeServiceChangeAllowed
    }
    var nativeServiceHasPreparedRequest: Bool {
        nativeService["status"].string == "service_client"
        && nativeService["last_action"]["operation"].string == "prepare_first_start"
        && nativeService["last_action"]["installation_request_v1"]["kind"].string == "launchd_first_start"
        && nativeService["last_action_report_json"].string != nil
        && nativeService["last_action"]["transaction_observation"]["canonical_raw_sha256"].string != nil
        && nativeService["last_action"]["transaction_observation"]["canonical_raw_sha256"].string == nativeService["client"]["configuration"]["canonical_state_sha256"].string
    }
    var nativeServiceStatusText: String {
        if nativeServiceUnconfirmed { return productText("后台服务操作结果未确认。不会重复执行，请检查当前状态。", "The background service operation is unconfirmed and will not be repeated. Review its current state.") }
        switch nativeService["client"]["registration"].string {
        case "not_registered": return nativeServiceHasPreparedRequest
            ? productText("首次启动请求已准备；服务尚未注册。", "The first-start request is prepared; the service is not registered.")
            : productText("已转为后台管理；服务尚未注册。", "Transferred to background management; the service is not registered.")
        case "observed":
            return nativeService["client"]["os"]["pid"].number == nil
                ? productText("服务已注册；系统报告未运行。", "The service is registered; the system reports it is not running.")
                : productText("服务已注册；系统报告运行中。Exec 连接尚未验证。", "The service is registered; the system reports it is running. The Exec connection has not been verified.")
        default: return productText("后台服务状态尚未确认。", "The background service state has not been confirmed.")
        }
    }
    var nativeQuitDescription: String {
        if nativeService["status"].string == "unknown" {
            return productText("退出只结束此 App 的连接。后台服务操作结果仍未确认，退出不代表该操作成功。", "Quitting ends this App’s connections. The background service operation remains unconfirmed; quitting does not confirm its success.")
        }
        if nativeHasServiceState {
            return productText("退出 Styx App 不会停止后台服务。请查看服务状态，或明确停止服务。", "Quitting the Styx App does not stop the background service. Review its state, or stop the service explicitly.")
        }
        return productText("关闭窗口后，Styx 会在菜单栏继续运行。退出 Styx 会停止它管理的本机连接和网关。", "Styx keeps running in the menu bar when you close a window. Quitting Styx stops the local connection and gateway it manages.")
    }
    func nativeTransferToService() {
        guard !busy, nativeSupportsOperation("transferToService"), client.nativeServiceChangeAllowed else { return }
        let alert = NSAlert()
        alert.messageText = productText("转为后台服务管理？", "Transfer to background service management?")
        alert.informativeText = productText("Styx 将结束此 App 的当前连接，并将这份设置转为后台管理。身份、配对和权限会保留。转交后仍需准备、审核并安装服务。", "Styx will end this App’s current connections and transfer this profile to background management. Identity, pairing and permissions are preserved. Service preparation, review and installation are still required afterward.")
        alert.addButton(withTitle: productText("保留设置并转交", "Keep profile and transfer")); alert.addButton(withTitle: productText("取消", "Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        perform { [self] in try applyNative(try await client.changeNativeService("transferToService")) }
    }
    func nativeCheckService() {
        guard nativeSupportsOperation("serviceStatus") else { return }
        perform { [self] in try applyNative(try await client.native("serviceStatus")) }
    }
    func nativePrepareServiceFirstStart() {
        guard !busy, nativeSupportsOperation("prepareServiceFirstStart"), !nativeServiceHasPreparedRequest, client.nativeServiceChangeAllowed else { return }
        let alert = NSAlert()
        alert.messageText = productText("准备服务首次启动请求？", "Prepare the service first-start request?")
        alert.informativeText = productText("Styx 将准备首次启动的目标设置和管理员请求。此步骤不会安装或启动服务；请保存请求，供安装前审核。", "Styx will prepare the first-start settings and administrator request. This does not install or start the service. Save the request for review before installation.")
        alert.addButton(withTitle: productText("准备请求", "Prepare request")); alert.addButton(withTitle: productText("取消", "Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        nativeServiceExportURL = nil; nativeServiceExportError = nil
        perform { [self] in try applyNative(try await client.changeNativeService("prepareServiceFirstStart")) }
    }
    func nativeStopService() {
        guard !busy, nativeSupportsOperation("stopService"), client.nativeServiceChangeAllowed else { return }
        let alert = NSAlert()
        alert.messageText = productText("停止后台服务？", "Stop the background service?")
        alert.informativeText = productText("服务停止后，ChatGPT 将无法通过它使用这台电脑。Styx 将等待当前服务结束；身份和配对会保留。", "After the service stops, ChatGPT cannot use this computer through it. Styx will wait for the current service to finish. Identity and pairing are preserved.")
        alert.addButton(withTitle: productText("停止服务", "Stop service")); alert.addButton(withTitle: productText("取消", "Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        perform { [self] in try applyNative(try await client.changeNativeService("stopService")) }
    }
    func exportNativeServiceRequest() {
        guard !busy, !nativeServiceSaving, nativeServiceHasPreparedRequest,
              let original = nativeService["last_action_report_json"].string else { return }
        let request: ProductServiceReviewRequest
        do { request = try ProductServiceReviewRequest(original) }
        catch {
            nativeServiceExportError = productText("管理员请求尚未能验证，未导出。请保留当前状态；不要重复准备服务。", "The administrator request could not be verified and was not exported. Keep the current state; do not prepare the service again.")
            return
        }
        let panel = NSOpenPanel()
        panel.title = productText("保存服务审核请求", "Save service review request")
        panel.message = productText("选择保存位置。将创建一个新文件夹，包含原始管理员报告和服务定义；服务不会安装。", "Choose a location. A new folder will contain the original administrator report and service definition. The service will not be installed.")
        panel.prompt = productText("保存到此文件夹", "Save here")
        panel.canChooseDirectories = true; panel.canChooseFiles = false; panel.allowsMultipleSelection = false; panel.canCreateDirectories = true
        guard panel.runModal() == .OK, let parent = panel.url else { return }
        nativeServiceSaving = true; nativeServiceExportError = nil; nativeServiceExportURL = nil
        Task {
            defer { nativeServiceSaving = false }
            do {
                let destination = try await Task.detached(priority: .utility) { try request.writeNewDirectory(in: parent) }.value
                nativeServiceExportURL = destination
                NSWorkspace.shared.activateFileViewerSelecting([destination])
            } catch {
                // Saving is independent from the completed Core preparation.
                // A new Save exports the same DATA without another mutation.
                nativeServiceExportError = productText("审核请求未能完整保存。准备操作没有重试；可另选位置保存同一请求。", "The review request could not be fully saved. Preparation was not retried. Choose another location to save the same request.")
            }
        }
    }
}

struct ProductServiceSettings: View {
    @ObservedObject var model: ProductModel
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(productText("后台服务", "Background service")).font(.headline)
            if model.nativeHasServiceState {
                Text(model.nativeServiceStatusText).font(.caption).foregroundStyle(.secondary)
                HStack {
                    if model.nativeSupportsOperation("serviceStatus") {
                        Button(productText("检查服务状态", "Check service state")) { model.nativeCheckService() }.disabled(model.busy)
                    }
                    if model.nativeSupportsOperation("prepareServiceFirstStart"), model.nativeService["client"]["registration"].string == "not_registered" {
                        Button(productText("准备首次启动请求…", "Prepare first-start request…")) { model.nativePrepareServiceFirstStart() }
                            .disabled(model.busy || model.nativeServiceUnconfirmed || model.nativeServiceHasPreparedRequest)
                    }
                    if model.nativeSupportsOperation("stopService"), model.nativeService["client"]["registration"].string == "observed", model.nativeService["client"]["os"]["pid"].number != nil {
                        Button(productText("停止服务…", "Stop service…")) { model.nativeStopService() }.disabled(model.busy || model.nativeServiceUnconfirmed)
                    }
                }
                if model.nativeServiceHasPreparedRequest {
                    Text(productText("管理员请求可保存供审核。导出请求不会安装或启动服务。", "Save the administrator request for review. Exporting it does not install or start the service.")).font(.caption).foregroundStyle(.secondary)
                    Button(productText("保存审核请求…", "Save review request…")) { model.exportNativeServiceRequest() }.disabled(model.busy || model.nativeServiceSaving)
                }
                if let destination = model.nativeServiceExportURL {
                    Label(productText("审核请求已导出（导出不会安装服务）", "Review request exported; export does not install the service"), systemImage: "doc.badge.checkmark").font(.caption)
                    Button(productText("在 Finder 中显示", "Show in Finder")) { NSWorkspace.shared.activateFileViewerSelecting([destination]) }
                }
                if let error = model.nativeServiceExportError { Text(error).font(.caption).foregroundStyle(.red).textSelection(.enabled) }
            } else if model.nativeSupportsOperation("transferToService") {
                Text(productText("先在上方准备候选并完成运行组件更新，再转为后台管理。转交会保留身份、配对和权限；服务安装需另行审核。", "Stage the candidate above and complete the runtime update before transferring to background management. Identity, pairing and permissions are preserved. Service installation requires separate review.")).font(.caption).foregroundStyle(.secondary)
                Button(productText("转为后台管理…", "Transfer to background management…")) { model.nativeTransferToService() }.disabled(model.busy || !model.client.nativeServiceChangeAllowed)
            }
        }.accessibilityIdentifier("styx-background-service-settings")
    }
}
#endif
