import Foundation
import CryptoKit
import Security
import Darwin

// Original rc12 publisher/certificate, independently recovered from retained
// signed delivery. Local-certificate preview is not Developer ID/notarization.
enum ProductOwnedCoreError: Error {
    case originalPackageRequired, invalidPackage, unavailable, unknownNoReplay, cleanupUnknown
}
private let productOriginalMacPublisher = "ebb36f9dff7022d8921443bdc30c6236d18dd0535aa2cdce838d1c5b327bab67"
private let productOriginalAppRequirement = "identifier \"app.styx.host\" and certificate leaf = H\"cb50cee601419f28b43756f4fc8aefdbf60abae2\""
private func productDigest(_ raw: Data) -> String { SHA256.hash(data: raw).map { String(format: "%02x", $0) }.joined() }

// Sole owned process and one serial JSON-line stream. Never HTTP/Node fallback.
final class ProductOwnedCore: @unchecked Sendable {
    private let child: Process
    private let input: FileHandle
    private let output: FileHandle
    private let stderr: FileHandle
    private let cliPin: FileHandle
    private let selectionPin: FileHandle
    private let queue = DispatchQueue(label: "app.styx.rust-owned-core")
    private let stopLock = NSLock()
    private let stderrJoined = DispatchGroup()
    private var eofRequested = false
    private var sequence = 0
    private var buffer = Data()
    private static let operations: Set<String> = ["startupStatus", "status", "inspectJoin", "join", "requestJoin", "claimJoin", "inspectHost", "connect", "disconnect", "quitAdmission"]

    // Only the fixed package bootstrap below can construct this owner.
    private init(cli: URL, selection: URL, state: URL, cliPin: FileHandle, selectionPin: FileHandle) throws {
        self.cliPin = cliPin; self.selectionPin = selectionPin
        child = Process(); let stdin = Pipe(), stdout = Pipe(), err = Pipe()
        input = stdin.fileHandleForWriting; output = stdout.fileHandleForReading; stderr = err.fileHandleForReading
        child.executableURL = cli; child.arguments = ["__app-core", "--state-dir", state.path, "--runtime-selection-file", selection.path]
        child.environment = ["HOME": NSHomeDirectory(), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": NSTemporaryDirectory(), "LANG": "en_US.UTF-8"]
        child.standardInput = stdin; child.standardOutput = stdout; child.standardError = err
        var started = false
        do {
            try child.run(); started = true
            try stdin.fileHandleForReading.close(); try stdout.fileHandleForWriting.close(); try err.fileHandleForWriting.close()
        } catch {
            if started {
                try? input.close(); try? stdin.fileHandleForReading.close()
                try? stdout.fileHandleForWriting.close(); try? err.fileHandleForWriting.close()
                let joined = DispatchGroup()
                for handle in [output, stderr] {
                    joined.enter(); DispatchQueue.global().async { defer { joined.leave() }; while !(handle.availableData.isEmpty) {} }
                }
                child.waitUntilExit(); joined.wait()
            }
            throw error
        }
        let handle = stderr, group = stderrJoined
        group.enter(); DispatchQueue.global().async {
            defer { group.leave() }
            while !(handle.availableData.isEmpty) {} // discard; never log bodies
        }
    }
    private func eof() {
        stopLock.lock(); let first = !eofRequested; eofRequested = true; stopLock.unlock()
        if first { try? input.close() }
    }
    private var closed: Bool { stopLock.lock(); defer { stopLock.unlock() }; return eofRequested }
    // Availability observation only. False withdraws discovery; neither value
    // is an executor-drain receipt or permission to replace this original child.
    var isRunning: Bool { !closed && child.isRunning }
    private func line() throws -> Data? {
        while true {
            if let end = buffer.firstIndex(of: 10) {
                let value = buffer[..<end]; buffer.removeSubrange(...end)
                guard value.count <= 2 * 1024 * 1024 else { throw ProductOwnedCoreError.unknownNoReplay }
                return Data(value)
            }
            guard buffer.count <= 2 * 1024 * 1024 else { throw ProductOwnedCoreError.unknownNoReplay }
            let data = output.availableData
            if data.isEmpty {
                guard buffer.isEmpty else { throw ProductOwnedCoreError.unknownNoReplay }
                return nil
            }
            buffer.append(data)
        }
    }
    func call(_ operation: String, _ body: [String: ProductJSON] = [:]) async throws -> ProductJSON {
        guard Self.operations.contains(operation) else { throw ProductCoreError.rejected }
        // This original queued job retains all child/pipe/pin ownership even if
        // its caller disappears. No cancellation retries or replacement child.
        return try await withCheckedThrowingContinuation { continuation in
            queue.async { [self] in
                do {
                    guard !closed, child.isRunning, sequence < Int.max else { throw ProductOwnedCoreError.unavailable }
                    sequence += 1; let id = sequence
                    let request = ProductJSON.object(["schema": .number(1), "id": .number(Double(id)), "operation": .string(operation), "input": .object(body)])
                    var raw = try JSONEncoder().encode(request)
                    guard raw.count <= 65536 else { throw ProductCoreError.rejected }; raw.append(10)
                    let timeout = DispatchWorkItem { [self] in eof() }
                    DispatchQueue.global().asyncAfter(deadline: .now() + 150, execute: timeout)
                    defer { timeout.cancel() }
                    try input.write(contentsOf: raw)
                    guard let response = try line(), !closed else { throw ProductOwnedCoreError.unknownNoReplay }
                    let value = try JSONDecoder().decode(ProductJSON.self, from: response)
                    guard value["id"].number == Double(id) else { throw ProductOwnedCoreError.unknownNoReplay }
                    guard value["ok"].bool else { continuation.resume(throwing: ProductCoreError.rejected); return }
                    continuation.resume(returning: value["result"])
                } catch {
                    // EOF requests original Rust cleanup. Retain/wait the same
                    // process; no timer is evidence that its role stopped.
                    eof(); while !(output.availableData.isEmpty) {}; child.waitUntilExit(); stderrJoined.wait()
                    continuation.resume(throwing: error)
                }
            }
        }
    }
    func quitAndJoin() async throws {
        let result = try await call("quitAdmission")
        guard result["quit"]["status"].string == "ready_to_quit",
              result["quit"]["ticketId"].string?.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil else { throw ProductOwnedCoreError.cleanupUnknown }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            queue.async { [self] in
                eof(); while !(output.availableData.isEmpty) {}; child.waitUntilExit(); stderrJoined.wait()
                if child.terminationReason == .exit && child.terminationStatus == 0 { continuation.resume() }
                else { continuation.resume(throwing: ProductOwnedCoreError.cleanupUnknown) }
            }
        }
    }
    // Async teardown without a completion claim; queued work retains custody.
    func requestEOF() { eof(); queue.async { [self] in eof(); while !(output.availableData.isEmpty) {}; child.waitUntilExit(); stderrJoined.wait() } }

    private static func privateDirectory(_ url: URL) throws {
        if mkdir(url.path, 0o700) != 0 && errno != EEXIST { throw ProductOwnedCoreError.invalidPackage }
        var st = stat()
        guard lstat(url.path, &st) == 0, st.st_mode & S_IFMT == S_IFDIR,
              st.st_uid == getuid(), st.st_mode & 0o077 == 0 else { throw ProductOwnedCoreError.invalidPackage }
    }
    private static func pinned(_ url: URL, limit: Int, privateFile: Bool = false) throws -> (FileHandle, Data) {
        let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw ProductOwnedCoreError.invalidPackage }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var st = stat()
        guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG, st.st_nlink == 1,
              st.st_uid == getuid(), st.st_mode & 0o022 == 0, st.st_size <= Int64(limit),
              !privateFile || st.st_mode & 0o077 == 0 else { try? handle.close(); throw ProductOwnedCoreError.invalidPackage }
        let raw = try handle.read(upToCount: limit + 1) ?? Data()
        guard raw.count == Int(st.st_size) else { try? handle.close(); throw ProductOwnedCoreError.invalidPackage }
        return (handle, raw)
    }
    static func open(resources: URL) throws -> ProductOwnedCore {
        guard Bundle.main.bundleURL.standardizedFileURL.path == "/Applications/Styx.app", Bundle.main.bundleIdentifier == "app.styx.host" else { throw ProductOwnedCoreError.originalPackageRequired }
        var code: SecStaticCode?, requirement: SecRequirement?
        guard SecStaticCodeCreateWithPath(Bundle.main.bundleURL as CFURL, [], &code) == errSecSuccess,
              SecRequirementCreateWithString(productOriginalAppRequirement as CFString, [], &requirement) == errSecSuccess,
              let originalCode = code, let originalRequirement = requirement,
              SecStaticCodeCheckValidity(originalCode, SecCSFlags(rawValue: kSecCSStrictValidate), originalRequirement) == errSecSuccess else { throw ProductOwnedCoreError.originalPackageRequired }
        // New native package metadata is mandatory. Never infer a publisher
        // from payload key bytes or use the old Node-backed App as a fallback.
        let (_, metadataRaw) = try pinned(resources.appendingPathComponent("macos-runtime.json"), limit: 16384)
        let metadata = try JSONDecoder().decode(ProductJSON.self, from: metadataRaw)["nativeRuntime"]
        guard metadata["schema"].number == 1, metadata["cli"].string == "native/bin/styx", metadata["payload"].string == "native", metadata["publisher"].string == "native-publisher.pem", metadata["publisherSpkiSha256"].string == productOriginalMacPublisher,
              let cliHash = metadata["cliSha256"].string, cliHash.range(of: "^[a-f0-9]{64}$", options: .regularExpression) != nil else { throw ProductOwnedCoreError.invalidPackage }
        let cli = resources.appendingPathComponent("native/bin/styx"), payload = resources.appendingPathComponent("native"), pub = resources.appendingPathComponent("native-publisher.pem")
        let (cliPin, cliRaw) = try pinned(cli, limit: 1024 * 1024 * 1024)
        guard productDigest(cliRaw) == cliHash else { throw ProductOwnedCoreError.invalidPackage }
        let verify = Process(), stdout = Pipe(), err = Pipe()
        verify.executableURL = cli; verify.arguments = ["release", "verify", "--payload-dir", payload.path, "--publisher-file", pub.path, "--expected-publisher", productOriginalMacPublisher, "--json", "--runtime-selection"]
        verify.environment = ["HOME": NSHomeDirectory(), "PATH": "/usr/bin:/bin", "TMPDIR": NSTemporaryDirectory()]
        verify.standardInput = FileHandle.nullDevice; verify.standardOutput = stdout; verify.standardError = err
        // Original verifier only; this worker runs off AppKit. It has no role,
        // credentials or OS permission prompts. Its stdout is bounded selection.
        let errors = DispatchGroup()
        var verifierStarted = false
        do {
            try verify.run(); verifierStarted = true
            try stdout.fileHandleForWriting.close(); try err.fileHandleForWriting.close()
        } catch {
            if verifierStarted {
                try? stdout.fileHandleForWriting.close(); try? err.fileHandleForWriting.close()
                if verify.isRunning { verify.terminate() }
                let joined = DispatchGroup()
                for handle in [stdout.fileHandleForReading, err.fileHandleForReading] {
                    joined.enter(); DispatchQueue.global().async { defer { joined.leave() }; while !(handle.availableData.isEmpty) {} }
                }
                verify.waitUntilExit(); joined.wait()
            }
            throw error
        }
        let deadlineHit = DispatchSemaphore(value: 0)
        let deadline = DispatchWorkItem { if verify.isRunning { deadlineHit.signal(); verify.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 150, execute: deadline)
        defer { deadline.cancel() }
        errors.enter(); DispatchQueue.global().async { defer { errors.leave() }; while !(err.fileHandleForReading.availableData.isEmpty) {} }
        var selection = Data(), overflow = false
        while true {
            let part = stdout.fileHandleForReading.availableData
            if part.isEmpty { break }
            if !overflow && selection.count + part.count <= 16384 { selection.append(part) }
            else if !overflow {
                overflow = true; selection.removeAll()
                if verify.isRunning { verify.terminate() }
            }
            // After overflow keep draining/discarding the original pipe. A
            // blocked writer must not prevent its original actual wait.
        }
        verify.waitUntilExit(); errors.wait()
        guard !overflow, deadlineHit.wait(timeout: .now()) == .timedOut,
              verify.terminationReason == .exit, verify.terminationStatus == 0 else { throw ProductOwnedCoreError.invalidPackage }
        let chosen = try JSONDecoder().decode(ProductJSON.self, from: selection)
        guard chosen["schema"].number == 1, chosen["publisher_spki_sha256"].string == productOriginalMacPublisher,
              chosen["manifest_sha256"].string == metadata["manifestSha256"].string,
              chosen["payload_path"].string == payload.path, chosen["publisher_file"].string == pub.path else { throw ProductOwnedCoreError.invalidPackage }
        let support = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support/Styx")
        guard FileManager.default.fileExists(atPath: support.path) else { throw ProductOwnedCoreError.invalidPackage }
        let container = support.appendingPathComponent("NativeRustHost-v1"); try privateDirectory(container)
        let selectionURL = container.appendingPathComponent("runtime-selection.json")
        if !FileManager.default.fileExists(atPath: selectionURL.path) {
            let fd = Darwin.open(selectionURL.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw ProductOwnedCoreError.invalidPackage }
            let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true); try handle.write(contentsOf: selection); try handle.synchronize(); try handle.close()
        }
        let (selectionPin, originalSelection) = try pinned(selectionURL, limit: 16384, privateFile: true)
        // This first bridge deliberately does not upgrade an existing App
        // profile's selected release. A changed selection requires migration.
        guard originalSelection == selection else { throw ProductOwnedCoreError.invalidPackage }
        // Existing legacy Setup/deployment is never adopted or rewritten.
        return try ProductOwnedCore(cli: cli, selection: selectionURL, state: container.appendingPathComponent("profile"), cliPin: cliPin, selectionPin: selectionPin)
    }
}
