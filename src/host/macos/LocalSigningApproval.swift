import AppKit
import Security
import CryptoKit

// Local developer setup only, launched through LaunchServices in Aqua. The
// user initiates the code-signing-only trust change and any OS authorization.
// This utility does not request TCC grants or touch the system trust domain.
@MainActor final class LocalSigningApproval: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    let status = NSTextField(wrappingLabelWithString: "")
    let root: URL
    let expected: String
    init(root: URL, expected: String) { self.root = root; self.expected = expected }
    func certificate() throws -> SecCertificate {
        let bytes = try Data(contentsOf: root.appendingPathComponent("certificate.der"))
        let digest = SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
        guard digest == expected, let cert = SecCertificateCreateWithData(nil, bytes as CFData) else {
            throw NSError(domain: "Styx.LocalSigning", code: 1)
        }
        return cert
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 620, height: 320), styleMask: [.titled, .closable], backing: .buffered, defer: false)
        window.title = "Styx 本地开发签名 / Local Development Signing"
        window.isReleasedWhenClosed = false
        let title = NSTextField(labelWithString: "允许 Styx 后续测试版本复用同一个签名身份")
        title.font = .boldSystemFont(ofSize: 17)
        let detail = NSTextField(wrappingLabelWithString: "证书：Styx Local Development\n范围：仅当前用户、仅代码签名；不更改网站证书信任、系统信任库或屏幕录制等权限。\n\n点击确认后，请亲自完成 macOS 的授权提示。此证书不代表 Apple Developer ID，也不用于对外发行。")
        let fingerprint = NSTextField(wrappingLabelWithString: "SHA-256: " + expected)
        fingerprint.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
        fingerprint.isSelectable = true
        let button = NSButton(title: "确认本地开发签名… / Confirm…", target: self, action: #selector(approve))
        let stack = NSStackView(views: [title, detail, fingerprint, button, status])
        stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 16
        stack.translatesAutoresizingMaskIntoConstraints = false
        window.contentView!.addSubview(stack)
        NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo: window.contentView!.leadingAnchor, constant: 24), stack.trailingAnchor.constraint(equalTo: window.contentView!.trailingAnchor, constant: -24), stack.topAnchor.constraint(equalTo: window.contentView!.topAnchor, constant: 24)])
        window.center(); window.makeKeyAndOrderFront(nil)
        NSApplication.shared.activate(ignoringOtherApps: true)
    }
    @objc func approve() {
        do {
            let cert = try certificate()
            guard let policy = SecPolicyCreateWithProperties(kSecPolicyAppleCodeSigning, nil) else { throw NSError(domain: "Styx.LocalSigning", code: 2) }
            let settings: [[String: Any]] = [[kSecTrustSettingsPolicy: policy, kSecTrustSettingsResult: SecTrustSettingsResult.trustRoot.rawValue]]
            let result = SecTrustSettingsSetTrustSettings(cert, .user, settings as CFTypeRef)
            guard result == errSecSuccess else {
                status.stringValue = "尚未完成，系统状态：\(result)。可以再次确认；不会改变系统权限。"
                return
            }
            let receipt: [String: Any] = ["schema": 1, "certificateSha256": expected, "userTrustPolicy": "codeSign_only", "systemTrustChanged": false, "tccChanged": false]
            let data = try JSONSerialization.data(withJSONObject: receipt, options: [.sortedKeys])
            try data.write(to: root.appendingPathComponent("user-trust-receipt.json"), options: .atomic)
            status.stringValue = "已完成本地代码签名信任，可以返回聊天继续验证。"
        } catch { status.stringValue = "证书或记录校验未完成；未更换任何身份。" }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { true }
}

guard CommandLine.arguments.count == 3,
      CommandLine.arguments[1].hasPrefix("/"),
      CommandLine.arguments[2].count == 64,
      CommandLine.arguments[2].allSatisfy({ "0123456789abcdef".contains($0) }) else { exit(2) }
MainActor.assumeIsolated {
    let app = NSApplication.shared
    app.setActivationPolicy(.regular)
    let delegate = LocalSigningApproval(root: URL(fileURLWithPath: CommandLine.arguments[1]), expected: CommandLine.arguments[2])
    app.delegate = delegate
    app.run()
}
