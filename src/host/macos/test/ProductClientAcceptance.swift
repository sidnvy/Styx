import Foundation

// Standalone native client acceptance against an isolated loopback fixture.
// No App, desktop permissions, user deployment or account is involved.
@main struct ProductClientAcceptance {
    static func main() async throws {
        let input = URL(fileURLWithPath: CommandLine.arguments[1])
        let bootstrap = try String(contentsOf: input, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        let client = try ProductCoreClient(sessionURL: URL(string: bootstrap)!)
        do { _ = try await client.exportPlugin(); throw ProductCoreError.invalidResponse }
        catch ProductCoreError.rejected { }
        _ = try await client.read("session")
        // Ordinary JSON writes cannot turn into arbitrary/binary route access.
        do { _ = try await client.write("plugin/export", [:]); throw ProductCoreError.invalidResponse }
        catch ProductCoreError.rejected { }
        let expected = CommandLine.arguments[2]
        if expected == "work_in_progress" || expected == "work_state_unknown" {
            do { _ = try await client.write("host-payload/handoff/prepare", ["authorize": .bool(true)]); throw ProductCoreError.invalidResponse }
            catch ProductCoreError.workInProgress { guard expected == "work_in_progress" else { throw ProductCoreError.invalidResponse } }
            catch ProductCoreError.workStateUnknown { guard expected == "work_state_unknown" else { throw ProductCoreError.invalidResponse } }
            print("PASS: native maintenance admission case \(expected)")
            return
        }
        let archive: Data
        do { archive = try await client.exportPlugin() }
        catch {
            guard expected == "reject" else { throw error }
            print("PASS: native private-session ZIP transport case reject")
            return
        }
        guard expected == "accept", archive == Data([0x50, 0x4b, 0x03, 0x04, 1, 2, 3]) else { throw ProductCoreError.invalidResponse }
        print("PASS: native private-session ZIP transport case \(expected)")
    }
}
