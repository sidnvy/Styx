import Foundation

// Native presentation and confirmation only. Core owns addresses, transactions,
// handshake validation and authorization; no network trust is inferred here.
enum ProductInvitationPolicy {
    static func approval(_ request: ProductJSON, confirmation: String) -> [String: ProductJSON]? {
        guard let code = request["comparison_code"].string,
              code.range(of: "^[A-F0-9]{4}(?:-[A-F0-9]{4}){3}$", options: .regularExpression) != nil,
              confirmation == code,
              let requestID = request["request_id"].string,
              requestID.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil else { return nil }
        return ["authorize": .bool(true), "requestId": .string(requestID),
                "comparisonCodeConfirmation": .string(confirmation),
                "enableComputer": .bool(request["computer_requested"].bool),
                "enableBrowser": .bool(request["browser_requested"].bool)]
    }
    static func blockerMessage(_ ingress: ProductJSON) -> String {
        let blockers = ingress["blockers"].array.compactMap(\.string)
        if blockers.contains("device_ingress_network_unavailable") {
            return productText("请连接 Wi-Fi 或以太网，然后重新检查。", "Connect to Wi-Fi or Ethernet, then check again.")
        }
        if blockers.contains("device_ingress_address_changed") {
            return productText("这台 Mac 的网络地址已改变。请恢复原来的网络连接，再重新检查。", "This Mac's network address changed. Restore its previous network connection, then check again.")
        }
        if blockers.contains("gateway_certificate_not_currently_valid") {
            return productText("连接证书需要更新，请联系 Styx 维护者。", "The connection certificate needs updating. Contact the Styx maintainer.")
        }
        return productText("请先在这台 Mac 完成设置并恢复本机连接，再重新检查。", "Finish setup on this Mac and restore its local connection, then check again.")
    }
}
