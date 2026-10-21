import Foundation

// This client uses only the private bootstrap handed to the owning App by its
// Node child. Credentials stay in memory and never enter URLs after bootstrap.
indirect enum ProductJSON: Codable, Equatable {
    case object([String: ProductJSON]), array([ProductJSON]), string(String), number(Double), bool(Bool), null
    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode(Double.self) { self = .number(v) }
        else if let v = try? c.decode([String: ProductJSON].self) { self = .object(v) }
        else { self = .array(try c.decode([ProductJSON].self)) }
    }
    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .object(let v): try c.encode(v)
        case .array(let v): try c.encode(v)
        case .string(let v): try c.encode(v)
        case .number(let v): try c.encode(v)
        case .bool(let v): try c.encode(v)
        case .null: try c.encodeNil()
        }
    }
    subscript(_ key: String) -> ProductJSON {
        if case .object(let v) = self { return v[key] ?? .null }; return .null
    }
    var string: String? { if case .string(let v) = self { return v }; return nil }
    var bool: Bool { if case .bool(let v) = self { return v }; return false }
    var number: Double? { if case .number(let v) = self { return v }; return nil }
    var array: [ProductJSON] { if case .array(let v) = self { return v }; return [] }
    var object: [String: ProductJSON] { if case .object(let v) = self { return v }; return [:] }
}

enum ProductCoreError: Error { case invalidBootstrap, unavailable, rejected, invalidResponse }

final class ProductRedirectBlocker: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

final class ProductCoreClient {
    private let origin: URL
    private let token: String
    private var csrf: String?
    private let transport: URLSession
    private let redirectBlocker = ProductRedirectBlocker()
    static let reads: Set<String> = ["native-signing/status", "app/lifecycle", "session", "snapshot", "native-status", "status", "journey", "acceptance", "plugin", "browser", "diagnostics"]
    static let writes: Set<String> = ["native-signing/plan", "native-signing/apply", "app/quit", "app/login", "device/revoke", "create", "local-setup", "advance", "foreground", "foreground/stop", "browser/prepare", "capabilities", "tunnel/configure", "tunnel/start", "tunnel/stop", "plugin/profile", "plugin/record", "connection-handoff", "acceptance/begin", "acceptance/confirm", "acceptance/desktop-readback", "devices", "default-device", "device-ingress/plan", "device-ingress/verify", "pairing-link/inspect", "pairing-link/accept", "pairing-link/create", "pending/list", "pending/approve"]

    static func bootstrap(_ url: URL) -> (origin: URL, token: String)? {
        guard var c = URLComponents(url: url, resolvingAgainstBaseURL: false),
              c.scheme == "http", c.host == "127.0.0.1", let port = c.port,
              (1...65535).contains(port), c.path == "/", c.query == nil,
              c.user == nil, c.password == nil,
              let fragment = c.fragment, fragment.hasPrefix("session=") else { return nil }
        let token = String(fragment.dropFirst(8))
        guard token.count == 43, token.allSatisfy({ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-".contains($0) }) else { return nil }
        c.fragment = nil
        guard let origin = c.url else { return nil }
        return (origin, token)
    }

    init(sessionURL: URL) throws {
        guard let bootstrap = Self.bootstrap(sessionURL) else { throw ProductCoreError.invalidBootstrap }
        origin = bootstrap.origin; token = bootstrap.token
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil; config.urlCredentialStorage = nil
        config.connectionProxyDictionary = [:]
        config.urlCache = nil; config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 90; config.timeoutIntervalForResource = 300
        transport = URLSession(configuration: config, delegate: redirectBlocker, delegateQueue: nil)
    }
    deinit { transport.invalidateAndCancel() }
    func read(_ route: String) async throws -> ProductJSON {
        guard Self.reads.contains(route) else { throw ProductCoreError.rejected }
        return try await request(route, body: nil)
    }
    func write(_ route: String, _ body: [String: ProductJSON]) async throws -> ProductJSON {
        guard Self.writes.contains(route), csrf != nil else { throw ProductCoreError.rejected }
        return try await request(route, body: .object(body))
    }
    // ZIP export shares the owning App's loopback session and CSRF boundary.
    // The route and filename are fixed; no URL/path comes from web content.
    func exportPlugin() async throws -> Data {
        guard csrf != nil else { throw ProductCoreError.rejected }
        let data = try await response("plugin/export", body: .object(["authorize": .bool(true)]), mimeType: "application/zip")
        guard data.starts(with: [0x50, 0x4b, 0x03, 0x04]) else { throw ProductCoreError.invalidResponse }
        return data
    }
    private func request(_ route: String, body: ProductJSON?) async throws -> ProductJSON {
        let data = try await response(route, body: body, mimeType: "application/json")
        let value = try JSONDecoder().decode(ProductJSON.self, from: data)
        if route == "session" {
            guard let challenge = value["csrf"].string, challenge.count == 43 else { throw ProductCoreError.invalidResponse }
            csrf = challenge
        }
        return value
    }
    private func response(_ route: String, body: ProductJSON?, mimeType: String) async throws -> Data {
        let url = origin.appendingPathComponent("api/" + route)
        var request = URLRequest(url: url)
        request.httpMethod = body == nil ? "GET" : "POST"
        // A read failure returns to the native retry UI. Long, authorized
        // installation/preparation operations keep their existing deadline.
        request.timeoutInterval = body == nil ? 20 : 90
        request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        request.setValue("http://127.0.0.1:\(origin.port!)", forHTTPHeaderField: "Origin")
        request.setValue("no-store", forHTTPHeaderField: "Cache-Control")
        if let body = body {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.setValue(csrf, forHTTPHeaderField: "X-Styx-CSRF")
            request.httpBody = try JSONEncoder().encode(body)
        }
        let (data, response) = try await transport.data(for: request)
        guard let response = response as? HTTPURLResponse,
              response.url == url,
              response.statusCode == 200 else { throw ProductCoreError.rejected }
        // Match Core's existing 2 MiB response/archive contract.
        guard data.count <= 2 * 1024 * 1024,
              response.mimeType == mimeType else { throw ProductCoreError.invalidResponse }
        return data
    }
}

// Small typed projections keep protocol codes separate from user-facing labels.
struct ProductDeployment {
    let mode: String
    let steps: [ProductStep]
    let computerRequested: Bool
    let browserRequested: Bool
    init?(_ value: ProductJSON) {
        guard let mode = value["mode"].string, ["create-local", "join-existing"].contains(mode) else { return nil }
        self.mode = mode; steps = value["steps"].array.compactMap(ProductStep.init)
        computerRequested = value["roles"]["computer"].string == "requested"
        browserRequested = value["roles"]["browser"].string == "requested"
    }
    var joined: Bool { mode == "join-existing" }
}
struct ProductStep: Identifiable {
    let id: String; let status: String
    let blockers: [String]
    let retryable: Bool
    init?(_ value: ProductJSON) {
        guard let id = value["id"].string, let status = value["status"].string else { return nil }
        isLocal = value["is_local"] == .bool(true)
        self.id = id; self.status = status
        let allowed: Set<String> = ["signed_install_unavailable", "invalid_host_configuration", "host_credential_unavailable", "codex_executor_unavailable", "signed_computer_runtime_unavailable", "macos_requires_embedded_cua_socket", "host_doctor_failed"]
        blockers = id == "host.doctor" ? value["blockers"].array.compactMap(\.string).filter { allowed.contains($0) } : []
        retryable = id == "host.doctor" && status == "blocked" && value["retryable"] == .bool(true)
    }
    var complete: Bool { ["succeeded", "skipped"].contains(status) }
}
struct ProductDevice: Identifiable {
    let id: String
    let label: String
    let isDefault: Bool
    let platform: String
    let online: Bool?
    let isLocal: Bool
    init?(_ value: ProductJSON) {
        guard let id = value["device_id"].string, let label = value["label"].string else { return nil }
        isLocal = value["is_local"] == .bool(true)
        self.id = id; self.label = label; isDefault = value["is_default"].bool
        platform = value["platform"].string ?? ""
        online = value["online"] == .bool(true) ? true : value["online"] == .bool(false) ? false : nil
    }
}
