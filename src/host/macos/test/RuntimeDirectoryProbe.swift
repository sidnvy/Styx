import Foundation
import Darwin

func expect(_ value: @autoclosure () -> Bool, _ message: String) {
    guard value() else { fatalError(message) }
}
func bindSocket(_ path: String, listening: Bool) -> Int32 {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    expect(fd >= 0, "socket")
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    let bytes = Array(path.utf8CString)
    expect(bytes.count <= MemoryLayout.size(ofValue: address.sun_path), "socket path")
    withUnsafeMutableBytes(of: &address.sun_path) { raw in
        for (index, byte) in bytes.enumerated() { raw[index] = UInt8(bitPattern: byte) }
    }
    let result = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    expect(result == 0, "bind")
    if listening { expect(listen(fd, 4) == 0, "listen") }
    return fd
}
func refused(_ directory: RuntimeDirectory) throws {
    do {
        try directory.prepareForLaunch()
        fatalError("live or unproven endpoint was removed")
    } catch HostError.daemonUnavailable {}
    expect(FileManager.default.fileExists(atPath: directory.socket), "endpoint retained")
}

@main struct RuntimeDirectoryProbe {
    static func main() throws {
        let path = CommandLine.arguments[1]
        let directory = try RuntimeDirectory(path: path)
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try child.run(); child.waitUntilExit()
        let deadPID = child.processIdentifier
        expect(kill(deadPID, 0) == -1 && errno == ESRCH, "dead child")
        func record(_ pid: pid_t) throws {
            try String(pid).write(toFile: path + "/cua.pid", atomically: true, encoding: .utf8)
            try "old descriptor".write(toFile: directory.descriptor, atomically: true, encoding: .utf8)
        }

        // Actual crash residue: the child and listener are both gone.
        close(bindSocket(directory.socket, listening: false))
        try record(deadPID)
        expect(socketConnectionError(directory.socket) == ECONNREFUSED, "stale socket")
        try directory.prepareForLaunch()
        for file in [directory.socket, directory.descriptor, path + "/cua.pid"] {
            expect(!FileManager.default.fileExists(atPath: file), "crash residue removed")
        }

        // A live listener survives even when its PID file is stale.
        let listener = bindSocket(directory.socket, listening: true)
        try record(deadPID)
        try refused(directory)
        expect(socketAccepts(directory.socket), "live listener preserved")
        close(listener); directory.clear()

        // A live child in startup must not lose its not-yet-listening endpoint.
        let starting = bindSocket(directory.socket, listening: false)
        try record(getpid())
        try refused(directory)
        close(starting); directory.clear()

        do {
            _ = try RuntimeDirectory(path: path)
            fatalError("second owner acquired the runtime")
        } catch HostError.alreadyRunning {}
        try directory.prepareForLaunch()
        print("PASS stale socket recovery; live listener, live child and exclusive owner preserved")
    }
}
