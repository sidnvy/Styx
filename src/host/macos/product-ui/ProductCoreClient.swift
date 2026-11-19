import Foundation

// Opt-in local diagnostics: fixed route names, codes and numeric results only.
// Never emit request/response bodies, session URLs, headers or credentials.
enum ProductNativeDiagnostics {
    private static func operationIsDiagnosticName(_ operation: String) -> Bool {
        return ProductOwnedCore.diagnosticOperations.contains(operation)
    }
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
        if let operation { guard operationIsDiagnosticName(operation) else { return } }
        var message = "lifecycle stage=" + stage.rawValue
        if let operation { message += " operation=" + operation }
        if let id { message += " id=" + String(id) }
        if let ok { message += " ok=" + String(ok) }
        event(message)
    }
    // Only the error field can supply a code, and only these fixed Core codes
    // may reach the diagnostic sink. Unknown values never get echoed.
    static func rejectionCode(_ response: ProductJSON) -> String {
        let known: Set<String> = [
            "native_management_invalid_input", "native_management_conflict", "native_management_unavailable",
            "native_management_unsupported", "native_management_unknown_inspect", "native_management_busy",
            "app_scope_changed", "app_instance_changed", "app_scope_invalid",
            "app_scope_refused", "app_container_is_configuration", "app_instance_busy",
            "app_role_scope_conflict", "app_role_retire_unknown", "app_deployment_invalid", "app_runtime_selection_invalid",
            "app_host_binding_reader_failed", "app_runtime_original_input_invalid",
            "app_runtime_original_input_changed", "app_runtime_input_budget",
            "app_runtime_input_changed", "app_runtime_input_invalid", "app_runtime_input_writer_changed",
            "app_runtime_input_missing", "app_runtime_original_input_required", "app_runtime_original_scope_required",
            "app_runtime_storage_unknown",
            "app_startup_observation_changed", "app_not_configured", "app_response_invalid",
            "native_release_platform_unsupported", "native_release_input_invalid", "native_release_publisher_untrusted",
            "native_release_payload_integrity", "native_release_observation_changed", "native_release_input_unavailable",
            "native_release_capacity", "native_release_busy", "native_release_observation_unknown",
            "app_cleanup_unknown",
            "app_gateway_fenced", "app_quit_admitted", "join_http_invalid_input",
            "join_http_invalid_timeout", "join_http_connect_failed", "join_http_tls_rejected",
            "join_http_leaf_pin_mismatch", "join_http_deadline", "join_http_exchange_failed",
            "join_http_response_too_large", "join_http_redirect_refused",
            "native_gateway_rejection_binding_mismatch", "native_gateway_admin_rejected", "native_gateway_admin_result_unknown"
        ]
        guard let code = response["error"].string, known.contains(code) else { return "other" }
        return code
    }
    // The CLI serializes exactly these two fields in this canonical order.
    // Comparing the entire line also rejects duplicate keys and extra fields.
    static func coreStderrCode(_ line: Data) -> String? {
        guard line.count <= 512, let value = try? JSONDecoder().decode(ProductJSON.self, from: line),
              Set(value.object.keys) == Set(["schema", "error"]), value["schema"] == .number(1) else { return nil }
        let code = rejectionCode(value)
        guard code != "other", line == Data("{\"error\":\"\(code)\",\"schema\":1}".utf8) else { return nil }
        return code
    }
    static func coreStarted(pid: Int32) { event("core_started pid=" + String(pid)) }
    static func coreExited(pid: Int32, status: Int32, reason: Process.TerminationReason) {
        let label: String
        switch reason { case .exit: label = "exit"; case .uncaughtSignal: label = "signal"; @unknown default: label = "other" }
        event("core_exited pid=" + String(pid) + " status=" + String(status) + " reason=" + label)
    }
    static func rejection(operation: String, id: Int, response: ProductJSON) {
        guard CommandLine.arguments.contains("--native-diagnostics"), operationIsDiagnosticName(operation) else { return }
        event("rejection operation=" + operation + " id=" + String(id) + " code=" + rejectionCode(response))
    }
    private static let computerProbeStages: Set<String> = ["native_before_binding", "native_before_observation", "native_before_final_binding", "session_binding", "session_begin_exchange", "session_begin_reply", "list_windows_exchange", "list_windows_result", "list_windows_rows", "read_binding_after", "read_deadline", "native_after_binding", "native_after_observation", "native_after_final_binding", "console_match", "evidence_lookup", "coordinator_refresh", "observation_mutex", "control_mutex", "already_fenced"]
    private static let computerProbeCauses: Set<String> = ["not_published", "unavailable", "native_protocol", "invalid_hint", "image_pin", "signature", "peer", "fenced", "mutex_poisoned", "locked", "console_changed", "console_epoch_changed", "deadline", "evidence_missing", "evidence_expired", "coordinator_refused", "reply_json", "reply_refused", "reply_exit_code", "reply_missing_result", "begin_reply_shape", "windows_reply_is_error", "windows_array_missing", "windows_limit", "window_pid_invalid", "window_id_invalid"]
    static func computerRuntimeFirstFault(_ status: ProductJSON) -> String? {
        let fault = status["foreground"]["computerRuntimeFirstFault"]
        guard let stage = fault["stage"].string, computerProbeStages.contains(stage),
              let cause = fault["cause"].string, computerProbeCauses.contains(cause) else { return nil }
        return "computer_runtime_first_fault stage=" + stage + " cause=" + cause
    }
    // Closed opt-in startup facts only; never record a response body or echo
    // an arbitrary error string. This discriminates publication timeouts from
    // source-binding/probe failures on an actual first-run owner.
    static func computerStartup(_ status: ProductJSON) {
        guard CommandLine.arguments.contains("--native-diagnostics") else { return }
        let original = status["foreground"]["computerStartupError"].string
        let known: Set<String> = ["desktop_session_not_ready", "desktop_source_unavailable", "computer_source_probe_failed", "computer_bootstrap_changed"]
        let code = original.map { known.contains($0) ? $0 : "other" } ?? "none"
        event("computer_intent requested=" + String(status["desktop_intent"]["computer_requested"].bool) + " startup=" + code)
        if case .bool(let advanced) = status["foreground"]["computerInitialEpochAdvanced"] {
            event("computer_initial_probe epoch_advanced=" + String(advanced))
        }
        if let fault = computerRuntimeFirstFault(status) { event(fault) }
        let probe = status["foreground"]["computerStartupProbe"]
        guard let stage = probe["stage"].string, computerProbeStages.contains(stage),
              let cause = probe["cause"].string, computerProbeCauses.contains(cause),
              let elapsed = probe["elapsed_ms"].number, elapsed.isFinite, elapsed >= 0, elapsed <= 86_400_000 else { return }
        event("computer_probe stage=" + stage + " cause=" + cause + " elapsed_ms=" + String(UInt64(elapsed)) + " deadline_expired=" + String(probe["deadline_expired"].bool))
    }
    static func event(_ message: String) {
        guard CommandLine.arguments.contains("--native-diagnostics") else { return }
        let line = "STYX_NATIVE " + message + "\n"
        FileHandle.standardError.write(Data(line.utf8))
    }
}

// A bounded transient line buffer; oversized lines are discarded through their
// newline. Only the first approved code survives, never stderr bytes.
struct ProductCoreStderrScanner {
    private var line = Data()
    private var overflow = false
    private(set) var code: String?
    mutating func consume(_ data: Data) {
        guard code == nil else { return }
        for byte in data {
            if byte == 10 {
                if !overflow { code = ProductNativeDiagnostics.coreStderrCode(line) }
                line.removeAll(keepingCapacity: false); overflow = false
                if code != nil { return }
            } else if !overflow {
                if line.count < 512 { line.append(byte) }
                else { line.removeAll(keepingCapacity: false); overflow = true }
            }
        }
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

enum ProductCoreError: Error { case unavailable, rejected, invalidResponse, loginChangeUnconfirmed }

// One owned Rust Core supplies every product operation. The only injected
// boundary is a native request closure in tests; it uses the same wire data.
final class ProductCoreClient {
    private let owned: ProductOwnedCore?
    private var nativeLoginUnconfirmed = false
    var nativeLoginChangeAllowed: Bool { !nativeLoginUnconfirmed }
    #if STYX_TESTING
    private var testRequest: ((String, [String: ProductJSON]) async throws -> ProductJSON)?
    init(testRequest: @escaping (String, [String: ProductJSON]) async throws -> ProductJSON) {
        owned = nil
        self.testRequest = testRequest
    }
    #endif
    init(owned: ProductOwnedCore) { self.owned = owned }
    deinit { owned?.requestEOF() }
    func native(_ operation: String, _ input: [String: ProductJSON] = [:]) async throws -> ProductJSON {
        #if STYX_TESTING
        if let testRequest { return try await testRequest(operation, input) }
        #endif
        guard let owned else { throw ProductCoreError.unavailable }
        return try await owned.call(operation, input)
    }
    func quitNative() async throws {
        guard let owned else { throw ProductCoreError.unavailable }
        try await owned.quitAndJoin()
    }
    func lifecycle() async throws -> ProductJSON {
        let observed = await ProductLoginStartup.observe()
        let result = try await native("appLifecycle", ["observation": observed.wire])
        if result["login"]["status"].string == "unknown" { nativeLoginUnconfirmed = true }
        return result
    }
    func changeLogin(_ body: [String: ProductJSON]) async throws -> ProductJSON {
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
    func exportPlugin() async throws -> Data {
        let result = try await native("pluginExport", ["authorize": .bool(true)])
        guard let encoded = result["archiveBase64"].string, encoded.count <= 1400000,
              let bytes = Data(base64Encoded: encoded), bytes.starts(with: [0x50, 0x4b, 0x03, 0x04]) else { throw ProductCoreError.invalidResponse }
        return bytes
    }
}

struct ProductDevice: Identifiable, Equatable {
    let id: String
    let label: String
    let platform: String
    let online: Bool?
    let isLocal: Bool
    init?(_ value: ProductJSON) {
        guard let id = value["device_id"].string, let label = value["label"].string else { return nil }
        isLocal = value["is_local"] == .bool(true)
        self.id = id; self.label = label
        platform = value["platform"].string ?? ""
        online = value["online"] == .bool(true) ? true : value["online"] == .bool(false) ? false : nil
    }
}
