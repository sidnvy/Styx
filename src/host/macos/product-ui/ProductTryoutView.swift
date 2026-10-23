import AppKit
import SwiftUI

// Shared by onboarding and the dedicated Settings sheet. Ordinary Settings
// must not mount a second input field for the same desktop challenge.
struct ProductTryoutView: View {
    @ObservedObject var model: ProductModel
    weak var controller: ProductWindowController?
    private var currentTest: Bool {
        model.challengeID != nil && model.chatVerification.usesCurrentTest
    }
    var body: some View {
        ProductPanel(title: productText("试用 Styx", "Try Styx")) {
            Text(model.chatVerification.label).font(.headline)
            if model.chatVerification == .expired {
                Text(productText("测试消息仅在限定时间内有效。你可以生成一条新消息；这不会更改连接设置。", "Test messages are valid for a limited time. Generate a new one without changing your connection settings.")).foregroundStyle(.secondary)
            } else if model.chatVerification == .needsRetest {
                Text(productText("之前的测试结果已失效。生成一条新测试消息即可，无需重新安装插件或更改连接设置。", "Previous test results are no longer current. Create a new test message; you do not need to reinstall the plugin or change its connection settings.")).foregroundStyle(.secondary)
            } else if model.chatVerification == .contextChanged {
                Text(productText("关闭此窗口，按安装指引更新已有插件的连接信息，再回来试用。", "Close this window and follow the installation guide to update the existing plugin connection, then try again.")).foregroundStyle(.secondary)
            }
            if model.chatVerification.allowsNewTest {
                Text(productText("在 ChatGPT 新建聊天，用 @ 选择 Styx。将测试消息粘贴并发送，ChatGPT 会依次试用你开启的功能。", "Start a new chat in ChatGPT and select Styx with @. Paste and send the test message to try each enabled feature."))
                if !currentTest {
                    Button(productText("生成测试消息", "Create test message")) { model.beginAcceptance() }
                        .accessibilityIdentifier("styx-tryout-create-message")
                        .disabled(model.busy || model.tunnelConnection != .connected || !model.localPrepared)
                }
                if model.tunnelConnection != .connected {
                    Text(productText("请先连接 ChatGPT，再生成测试消息。", "Connect ChatGPT before creating a test message.")).font(.caption).foregroundStyle(.secondary)
                }
            }
            if currentTest, let prompt = model.acceptance["challenge"]["prompt"].string {
                if !model.chatVerification.proofComplete {
                    Button(productText("复制测试消息", "Copy test message")) { model.copy(prompt) }.buttonStyle(.borderedProminent)
                    DisclosureGroup(productText("查看测试消息", "View test message")) {
                        Text(prompt).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                    }
                }
                testResult(.cli, model.acceptance["requestProof"]["status"].string)
                testResult(.browser, model.acceptance["browser"]["status"].string)
                testResult(.computer, model.acceptance["desktop"]["status"].string)
                if model.acceptance["challenge"]["desktopValue"].string != nil {
                    Divider()
                    Text(productText("电脑操作测试", "Computer interaction test")).font(.headline)
                    Text(productText("保持此窗口打开。ChatGPT 会在下面输入测试文字并读回，你无需手动填写。", "Keep this window open. ChatGPT will enter and read back test text below; leave the field for it to fill.")).font(.caption).foregroundStyle(.secondary)
                    // Retain this field after proof arrives so the chat can make
                    // its independent final observation. Never auto-confirm it.
                    ProductAcceptanceField(model: model, owner: controller).frame(height: 30)
                }
                if model.chatVerification.proofComplete && !model.accepted {
                    Text(productText("Styx 已收到各项测试结果。如果 ChatGPT 也显示完成，请确认。", "Styx has received all test results. Confirm when ChatGPT also shows that the test finished.")).font(.caption).foregroundStyle(.secondary)
                    Button(productText("我已在 ChatGPT 看到结果", "I saw the results in ChatGPT")) { model.confirmChat() }
                        .disabled(model.busy || !model.targetProofReady)
                }
            }
            if model.accepted && model.chatVerification.proofComplete {
                Text(productText("试用已完成，可以回到 ChatGPT 继续使用。", "The test is complete. You can continue using Styx in ChatGPT.")).foregroundStyle(.secondary)
            }
            if let error = model.error ?? model.observationError {
                Text(error).font(.callout).foregroundStyle(.red)
                Button(productText("重新检查", "Check again")) { Task { await model.refresh() } }
            }
        }
    }
    private func testResult(_ kind: ProductCapabilityKind, _ status: String?) -> some View {
        let passed = status == "verified"
        let unnecessary = status == "not_required"
        let failed = ["failed", "blocked", "uncertain"].contains(status ?? "")
        return HStack {
            Label(kind.title, systemImage: kind.symbol)
            Spacer()
            Text(passed ? productText("通过", "Passed") : unnecessary ? productText("无需测试", "Not required") : failed ? productText("未完成", "Incomplete") : productText("等待结果", "Waiting for results"))
                .foregroundStyle(passed ? Color.green : Color.secondary)
        }
    }
}
