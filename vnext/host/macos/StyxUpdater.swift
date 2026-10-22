import AppKit
import Foundation

// Runs from the Core-created private ticket directory, never inside the App
// that must exit. Core owns authorization, publisher checks, journals and locks.
final class UpdateController: NSObject, NSApplicationDelegate {
    private var window: NSWindow?
    private let label = NSTextField(wrappingLabelWithString: "")
    private let detail = NSTextField(wrappingLabelWithString: "")
    private let spinner = NSProgressIndicator()
    private let button = NSButton(title: "", target: nil, action: nil)
    private let cancelButton = NSButton(title: "", target: nil, action: nil)
    private let rollbackButton = NSButton(title: "", target: nil, action: nil)
    private let openButton = NSButton(title: "", target: nil, action: nil)
    private let originalApp: URL
    private var running = false
    private let state: String
    private let ticket: String
    private let directory: URL
    private var started = Date()
    private let chinese = (Locale.preferredLanguages.first ?? "en").hasPrefix("zh")
    init(state: String, ticket: String, directory: URL, appPath: String) { self.state = state; self.ticket = ticket; self.directory = directory; originalApp = URL(fileURLWithPath: appPath) }
    private func text(_ zh: String, _ en: String) -> String { chinese ? zh : en }
    func applicationDidFinishLaunching(_ notification: Notification) {
        let panel = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 480, height: 230), styleMask: [.titled], backing: .buffered, defer: false)
        panel.title = "Styx"; panel.center(); panel.isReleasedWhenClosed = false
        label.font = .systemFont(ofSize: 17, weight: .semibold)
        detail.font = .systemFont(ofSize: 13); detail.textColor = .secondaryLabelColor
        spinner.style = .spinning; spinner.controlSize = .small
        button.target = self; button.action = #selector(retry); button.isHidden = true
        let top = NSStackView(views: [spinner, label]); top.orientation = .horizontal; top.spacing = 12
        cancelButton.title = text("取消更新", "Cancel update"); cancelButton.target = self; cancelButton.action = #selector(cancelUpdate); cancelButton.isHidden = true
        rollbackButton.title = text("恢复更新前的组件…", "Restore previous components…"); rollbackButton.target = self; rollbackButton.action = #selector(rollbackUpdate); rollbackButton.isHidden = true
        openButton.title = text("返回 Styx", "Return to Styx"); openButton.target = self; openButton.action = #selector(openApp); openButton.isHidden = true
        let actions = NSStackView(views: [button, cancelButton, rollbackButton, openButton]); actions.orientation = .horizontal; actions.spacing = 8
        let stack = NSStackView(views: [top, detail, actions]); stack.orientation = .vertical; stack.alignment = .leading; stack.spacing = 14; stack.translatesAutoresizingMaskIntoConstraints = false
        panel.contentView?.addSubview(stack)
        if let view = panel.contentView { NSLayoutConstraint.activate([stack.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 24), stack.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -24), stack.topAnchor.constraint(equalTo: view.topAnchor, constant: 26)]) }
        window = panel; panel.makeKeyAndOrderFront(nil); NSApp.activate(ignoringOtherApps: true); retry()
    }
    @objc private func retry() { guard !running else { return }; running = true; started = Date(); button.isHidden = true; cancelButton.isHidden = true; rollbackButton.isHidden = true; openButton.isHidden = true; spinner.startAnimation(nil); label.stringValue = text("正在完成更新", "Finishing the update"); detail.stringValue = text("正在等待 Styx 退出…", "Waiting for Styx to quit…"); execute() }
    private func command(_ arguments: [String], completion: @escaping (Int32, [String: Any]?) -> Void) {
        let executable = directory.appendingPathComponent("node"), cli = directory.appendingPathComponent("vnext/onboarding/cli.mjs")
        DispatchQueue.global(qos: .userInitiated).async {
            let process = Process(), output = Pipe(), errors = Pipe()
            process.executableURL = executable; process.arguments = [cli.path] + arguments
            process.environment = ["HOME": NSHomeDirectory(), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": NSTemporaryDirectory()]
            process.standardInput = FileHandle.nullDevice; process.standardOutput = output; process.standardError = errors
            // Drain both pipes; error text can contain local details and is never
            // placed in the interface. Core retains the private recovery record.
            errors.fileHandleForReading.readabilityHandler = { handle in _ = handle.availableData }
            do {
                try process.run(); let data = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit(); errors.fileHandleForReading.readabilityHandler = nil
                let value = data.count <= 2 * 1024 * 1024 ? (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] : nil
                DispatchQueue.main.async { completion(process.terminationStatus, value) }
            } catch { errors.fileHandleForReading.readabilityHandler = nil; DispatchQueue.main.async { completion(-1, nil) } }
        }
    }
    private func execute() {
        command(["host-payload-handoff-execute", state, ticket, "--authorize"]) { [weak self] code, value in
            guard let self = self else { return }
            let status = value?["status"] as? String
            if status == "waiting_for_exit" || (status == "blocked" && value?["reason"] as? String == "native_owned_process_present") {
                if Date().timeIntervalSince(self.started) < 120 { DispatchQueue.main.asyncAfter(deadline: .now() + 1) { self.execute() }; return }
                self.fail(self.text("Styx 尚未退出。请退出 Styx 后重试。", "Styx is still open. Quit Styx and try again.")); return
            }
            guard code == 0, status == "applied_stopped", let app = value?["appPath"] as? String, app.hasPrefix("/"), URL(fileURLWithPath: app).lastPathComponent == "Styx.app" else { self.fail(self.text("更新未能完成。现有身份和配对会保留；请重试或检查恢复记录。", "The update could not finish. Your identity and pairing are preserved. Retry or review the recovery record.")); return }
            self.detail.stringValue = self.text("正在检查运行组件…", "Checking runtime components…")
            self.command(["advance", self.state, "host.doctor"]) { code, _ in
                guard code == 0 else { self.fail(self.text("组件检查尚未通过。请重试；无需重新配对。", "The component check did not pass. Retry; pairing does not need to be repeated.")); return }
                let configuration = NSWorkspace.OpenConfiguration(); configuration.activates = true
                NSWorkspace.shared.openApplication(at: URL(fileURLWithPath: app), configuration: configuration) { _, error in
                    DispatchQueue.main.async { if error != nil { self.fail(self.text("更新已完成，请手动打开 Styx。", "The update finished. Open Styx manually.")) } else { NSApp.terminate(nil) } }
                }
            }
        }
    }
    @objc private func openApp() {
        NSWorkspace.shared.openApplication(at: originalApp, configuration: NSWorkspace.OpenConfiguration()) { _, error in
            DispatchQueue.main.async { if error == nil { NSApp.terminate(nil) } }
        }
    }
    @objc private func cancelUpdate() {
        guard !running else { return }; running = true
        command(["host-payload-handoff-cancel", state, ticket, "--authorize"]) { [weak self] code, value in
            guard let self = self else { return }; self.running = false
            if code == 0 && value?["status"] as? String == "cancelled" { self.detail.stringValue = self.text("更新已取消。可以返回 Styx。", "The update was cancelled. Return to Styx."); self.cancelButton.isHidden = true; self.rollbackButton.isHidden = true; self.button.isHidden = true }
            else { self.fail(self.text("组件可能已经开始更改，不能取消。请检查恢复操作。", "Components may already be changing. Cancellation is unavailable; review recovery.")) }
        }
    }
    @objc private func rollbackUpdate() {
        guard !running else { return }
        let alert = NSAlert(); alert.messageText = text("恢复更新前的运行组件？", "Restore the previous runtime components?")
        alert.informativeText = text("仅恢复这次更新的组件和记录。现有身份与配对会保留。", "Restores this update's components and records. Identity and pairing are preserved.")
        alert.addButton(withTitle: text("恢复", "Restore")); alert.addButton(withTitle: text("取消", "Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else { return }; running = true
        command(["host-payload-status", state]) { [weak self] code, value in
            guard let self = self else { return }
            guard code == 0, value?["handoffTicketId"] as? String == self.ticket, let transaction = value?["transactionId"] as? String,
                  transaction.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil else { self.fail(self.text("无法确认这次更新的恢复记录。请返回 Styx 检查。", "This update's recovery record could not be confirmed. Return to Styx to review.")); return }
            self.command(["host-payload-rollback", self.state, transaction, "--authorize"]) { code, value in
                self.running = false
                if code == 0 && value?["status"] as? String == "rolled_back" { self.detail.stringValue = self.text("已恢复更新前的组件。可以返回 Styx。", "The previous components were restored. Return to Styx."); self.button.isHidden = true; self.cancelButton.isHidden = true; self.rollbackButton.isHidden = true }
                else { self.fail(self.text("恢复未完成。请保留恢复记录，返回 Styx 检查。", "Recovery did not finish. Keep the recovery records and return to Styx to review.")) }
            }
        }
    }
    private func fail(_ message: String) { running = false; spinner.stopAnimation(nil); label.stringValue = text("更新需要检查", "Update needs attention"); detail.stringValue = message; button.title = text("重试", "Retry"); button.isHidden = false; cancelButton.isHidden = false; openButton.isHidden = false; window?.styleMask.insert(.closable)
        command(["host-payload-status", state]) { [weak self] code, value in
            guard let self = self else { return }; let ours = code == 0 && value?["handoffTicketId"] as? String == self.ticket && value?["status"] as? String != "rolled_back"
            self.rollbackButton.isHidden = !ours; self.cancelButton.isHidden = ours
        } }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { !running }
}
let arguments = CommandLine.arguments
if arguments.count != 2 || arguments[1].range(of: "^[a-f0-9]{32}$", options: .regularExpression) == nil { exit(2) }
let directory = URL(fileURLWithPath: arguments[0]).resolvingSymlinksInPath().deletingLastPathComponent()
let input = directory.appendingPathComponent("input.json")
guard let attributes = try? FileManager.default.attributesOfItem(atPath: input.path),
      attributes[.type] as? FileAttributeType == .typeRegular,
      let mode = attributes[.posixPermissions] as? NSNumber, mode.intValue & 0o077 == 0,
      let owner = attributes[.ownerAccountID] as? NSNumber, owner.uint32Value == getuid(),
      let data = try? Data(contentsOf: input), data.count < 4096,
      let record = (try? JSONSerialization.jsonObject(with: data)) as? [String: String],
      record["ticketId"] == arguments[1], let state = record["stateDir"], state.hasPrefix("/"),
      let appPath = record["appPath"], appPath.hasPrefix("/"), URL(fileURLWithPath: appPath).lastPathComponent == "Styx.app" else { exit(2) }
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let controller = UpdateController(state: state, ticket: arguments[1], directory: directory, appPath: appPath)
app.delegate = controller
app.run()
