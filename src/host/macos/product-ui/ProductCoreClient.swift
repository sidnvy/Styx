import Foundation

// Opt-in local diagnostics: fixed route names and numeric results only.
// Never emit request/response bodies, session URLs, headers or credentials.
enum ProductNativeDiagnostics {
    // Closed lifecycle vocabulary. Optional operation is checked against the
    // private JSONL protocol; no arbitrary Error/body/path reaches this sink.
    enum LifecycleStage: String {
        case queued, admitted, requestWritten = "request_written", responseDecoded = "response_decoded"
        case deadlineEOF = "deadline_eof", eofRequested = "eof_requested", eofClosed = "eof_closed"
        case eofCloseFailed = "eof_close_failed", childJoined = "child_joined", callFailed = "call_failed"
        case bootstrapEntered = "bootstrap_entered", coreAdopted = "core_adopted", windowCreated = "window_created"
        case bootstrapCompleted = "bootstrap_completed", bootstrapFailed = "bootstrap_failed"
        case terminateEntered = "terminate_entered", terminatePending = "terminate_pending"
        case terminateCancelStarting = "terminate_cancel_starting", terminateCancelNoWindow = "terminate_cancel_no_window"
        case terminateNow = "terminate_now", terminateLater = "terminate_later", terminateAdmission = "terminate_admission", terminateReply = "terminate_reply"
    }
    static func lifecycle(_ stage: LifecycleStage, operation: String? = nil, id: Int? = nil, ok: Bool? = nil) {
        guard CommandLine.arguments.contains("--native-diagnostics") else { return }
        let operations: Set<String> = ["startupStatus", "status", "createLocal", "resumeLocal", "inspectJoin", "join", "requestJoin", "claimJoin", "inspectHost", "connect", "disconnect", "quitAdmission", "retireRole", "appLifecycle", "appLogin", "appLoginResult", "stageRuntime", "updateRuntime", "runtimeUpdateStatus", "recoverRuntimeUpdate", "transferToService", "serviceStatus", "prepareServiceFirstStart", "stopService", "prepareAppMaintenance", "appMaintenanceStatus", "cancelAppMaintenance"]
        if let operation { guard operations.contains(operation) else { return } }
        var message = "lifecycle stage=" + stage.rawValue
        if let operation { message += " operation=" + operation }
        if let id { message += " id=" + String(id) }
        if let ok { message += " ok=" + String(ok) }
        event(message)
    }
    static func event(_ message: String) {
        guard CommandLine.arguments.contains("--native-diagnostics") else { return }
        let line = "STYX_NATIVE " + message + "\n"
        FileHandle.standardError.write(Data(line.utf8))
    }
}

// This client uses only the private bootstrap handed to the owning App by its
// Node child. Credentials stay in memory and never enter URLs after bootstrap.
indirect enum ProductJSON: Codable, Equatable, Sendable {
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

enum ProductCoreError: Error { case invalidBootstrap, unavailable, rejected, invalidResponse, workInProgress, workStateUnknown, loginChangeUnconfirmed, serviceChangeUnconfirmed, servicePreparationRequired; case insufficientSpace(ProductJSON, Bool) }

final class ProductRedirectBlocker: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

final class ProductCoreClient {
    private let origin: URL?
    private let token: String?
    private let owned: ProductOwnedCore?
    var isNativeHost: Bool { owned != nil }
    // A transient no-replay guard, never a saved preference. Only the OS owns
    // the registration, and Core owns the one-shot intent ticket.
    private var nativeLoginUnconfirmed = false
    var nativeLoginChangeAllowed: Bool { !nativeLoginUnconfirmed }
    #if STYX_PRODUCT_UI
    // Process-local duplicate/unknown guard only. The original Rust Core owns
    // all manager facts, transaction custody and eligibility checks.
    private var nativeServiceUnconfirmed = false
    private var nativeServiceMutationInFlight = false
    var nativeServiceChangeAllowed: Bool { !nativeServiceUnconfirmed && !nativeServiceMutationInFlight && owned?.isRunning == true }
    #endif
    private var csrf: String?
    private let transport: URLSession?
    private let redirectBlocker = ProductRedirectBlocker()
    static let reads: Set<String> = ["join/recovery", "native-signing/status", "app/lifecycle", "session", "snapshot", "native-status", "status", "journey", "acceptance", "plugin", "browser", "diagnostics"]
    static let writes: Set<String> = ["join/recover", "join/rollback", "host-payload/handoff/prepare", "host-payload/handoff/status", "host-payload/handoff/cancel", "native-signing/plan", "native-signing/apply", "app/quit", "app/login", "device/revoke", "create", "local-setup", "advance", "foreground", "foreground/stop", "browser/prepare", "capabilities", "tunnel/configure", "tunnel/start", "tunnel/stop", "plugin/profile", "plugin/record", "connection-handoff", "acceptance/begin", "acceptance/confirm", "acceptance/desktop-readback", "devices", "default-device", "device-ingress/plan", "device-ingress/verify", "device-ingress/prepare", "device-ingress/status", "device-ingress/recover", "pairing-link/close", "pairing-link/inspect", "pairing-link/accept", "pairing-link/create", "pending/list", "pending/approve"]

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

    init(owned: ProductOwnedCore) { self.owned = owned; origin = nil; token = nil; transport = nil }
    func native(_ operation: String, _ input: [String: ProductJSON] = [:]) async throws -> ProductJSON {
        guard let owner = owned else { throw ProductCoreError.unavailable }; return try await owner.call(operation, input)
    }
    func quitNative() async throws { guard let owner = owned else { throw ProductCoreError.unavailable }; try await owner.quitAndJoin() }
    func prepareNativeAppMaintenance(requestId: String) async throws -> ProductJSON {
        guard let owner = owned else { throw ProductCoreError.unavailable }
        return try await owner.prepareAppMaintenance(requestId: requestId)
    }
    func cancelNativeAppMaintenance(ticketId: String) async throws {
        guard let owner = owned else { throw ProductCoreError.unavailable }
        try await owner.cancelAppMaintenance(ticketId: ticketId)
    }
    #if STYX_PRODUCT_UI
    func changeNativeService(_ operation: String) async throws -> ProductJSON {
        guard ["transferToService", "prepareServiceFirstStart", "stopService"].contains(operation) else { throw ProductCoreError.rejected }
        guard nativeServiceChangeAllowed else { throw ProductCoreError.serviceChangeUnconfirmed }
        nativeServiceMutationInFlight = true
        defer { nativeServiceMutationInFlight = false }
        let result: ProductJSON
        do { result = try await native(operation, ["authorize": .bool(true)]) }
        catch let failure as ProductOwnedCoreRejection {
            let code = failure.response["error"].string ?? ""
            if code == "native_management_unknown_inspect" || code == "app_service_original_operation_unknown" {
                nativeServiceUnconfirmed = true
                throw ProductCoreError.serviceChangeUnconfirmed
            }
            if operation == "transferToService", code == "native_management_invalid_input" {
                throw ProductCoreError.servicePreparationRequired
            }
            throw failure
        } catch {
            // A dispatched request may have committed before its reply was
            // lost. Never reopen the owner, resend, or clear this on a read.
            nativeServiceUnconfirmed = true
            throw ProductCoreError.serviceChangeUnconfirmed
        }
        guard result["mode"].string == "rust_host", result["service"]["status"].string == "service_client" else {
            nativeServiceUnconfirmed = true
            throw ProductCoreError.serviceChangeUnconfirmed
        }
        return result
    }
    #endif
    init(sessionURL: URL) throws {
        owned = nil
        guard let bootstrap = Self.bootstrap(sessionURL) else { throw ProductCoreError.invalidBootstrap }
        origin = bootstrap.origin; token = bootstrap.token
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil; config.urlCredentialStorage = nil
        config.connectionProxyDictionary = [:]
        config.urlCache = nil; config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForRequest = 90; config.timeoutIntervalForResource = 300
        transport = URLSession(configuration: config, delegate: redirectBlocker, delegateQueue: nil)
    }
    deinit { transport?.invalidateAndCancel(); owned?.requestEOF() }
    func read(_ route: String) async throws -> ProductJSON {
        if isNativeHost {
            #if STYX_PRODUCT_UI
            if route == "app/lifecycle" {
                let observed = await ProductLoginStartup.observe()
                let result = try await native("appLifecycle", ["observation": observed.wire])
                if result["login"]["status"].string == "unknown" { nativeLoginUnconfirmed = true }
                return result
            }
            #endif
            guard route == "status" || route == "native-status" else { throw ProductCoreError.rejected }; return try await native("status")
        }
        guard Self.reads.contains(route) else { throw ProductCoreError.rejected }
        return try await request(route, body: nil)
    }
    func write(_ route: String, _ body: [String: ProductJSON]) async throws -> ProductJSON {
        if isNativeHost {
            switch route {
            case "pairing-link/inspect": return try await native("inspectJoin", body)
            case "foreground": return try await native("connect")
            case "foreground/stop": return try await native("disconnect")
            #if STYX_PRODUCT_UI
            case "app/login": return try await changeNativeLogin(body)
            #endif
            default: throw ProductCoreError.rejected
            }
        }
        guard Self.writes.contains(route), csrf != nil else { throw ProductCoreError.rejected }
        return try await request(route, body: .object(body))
    }
    #if STYX_PRODUCT_UI
    private func changeNativeLogin(_ body: [String: ProductJSON]) async throws -> ProductJSON {
        guard nativeLoginChangeAllowed else { throw ProductCoreError.loginChangeUnconfirmed }
        guard body.count == 2, body["authorize"] == .bool(true),
              case .bool(let enabled)? = body["enabled"] else { throw ProductCoreError.rejected }
        let before = await ProductLoginStartup.observe()
        let prepared = try await native("appLogin", ["authorize": .bool(true), "enabled": .bool(enabled), "observation": before.wire])
        guard prepared["login"]["status"].string == "authorized",
              prepared["login"]["enabled"] == .bool(enabled),
              let ticket = prepared["login"]["ticketId"].string,
              ticket.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil else { throw ProductCoreError.invalidResponse }
        // apply reobserves on the main actor immediately before the one OS call.
        let applied = await ProductLoginStartup.apply(enabled: enabled, before: before)
        if applied.outcome == "unknown" { nativeLoginUnconfirmed = true }
        let result: ProductJSON
        do {
            result = try await native("appLoginResult", ["ticketId": .string(ticket),
                "outcome": .string(applied.outcome), "observation": applied.observation.wire])
        } catch {
            // A result acknowledgement may have been lost. Do not resend it
            // and do not repeat the already-dispatched OS mutation.
            nativeLoginUnconfirmed = true
            throw ProductCoreError.loginChangeUnconfirmed
        }
        if applied.outcome == "unknown" || result["login"]["status"].string == "unknown" {
            nativeLoginUnconfirmed = true
            throw ProductCoreError.loginChangeUnconfirmed
        }
        guard applied.outcome == "succeeded", result["login"]["status"].string == "succeeded" else { throw ProductCoreError.rejected }
        return result
    }
    #endif
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
        guard let origin = origin, let token = token, let transport = transport else { throw ProductCoreError.rejected }
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
        ProductNativeDiagnostics.event("request " + (body == nil ? "GET " : "POST ") + route)
        let data: Data
        let response: URLResponse
        do { (data, response) = try await transport.data(for: request) }
        catch {
            ProductNativeDiagnostics.event("transport_failure " + route + " code=" + String((error as NSError).code))
            throw error
        }
        ProductNativeDiagnostics.event("response " + route + " status=" + String((response as? HTTPURLResponse)?.statusCode ?? 0))
        guard let response = response as? HTTPURLResponse,
              response.url == url else { throw ProductCoreError.rejected }
        if response.statusCode == 409, data.count <= 4096, let failure = try? JSONDecoder().decode(ProductJSON.self, from: data) {
            if failure["error"].string == "host_payload_insufficient_space" { throw ProductCoreError.insufficientSpace(failure["budget"], route == "host-payload/handoff/prepare" && failure["preflight"].bool) }
            if failure["error"].string == "work_in_progress" { throw ProductCoreError.workInProgress }
            if failure["error"].string == "work_state_unknown" { throw ProductCoreError.workStateUnknown }
        }
        guard response.statusCode == 200 else { throw ProductCoreError.rejected }
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
        self.id = id; self.status = status
        let allowed: Set<String> = ["signed_install_unavailable", "invalid_host_configuration", "host_credential_unavailable", "codex_executor_unavailable", "signed_computer_runtime_unavailable", "macos_requires_embedded_cua_socket", "host_doctor_failed"]
        blockers = id == "host.doctor" ? value["blockers"].array.compactMap(\.string).filter { allowed.contains($0) } : []
        retryable = id == "host.doctor" && status == "blocked" && value["retryable"] == .bool(true)
    }
    var complete: Bool { ["succeeded", "skipped"].contains(status) }
}
struct ProductDevice: Identifiable, Equatable {
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
