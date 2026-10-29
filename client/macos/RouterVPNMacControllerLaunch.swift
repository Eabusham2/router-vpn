import Foundation
#if canImport(Darwin)
import Darwin
import Security

extension RouterVPNMacPathACL {
    static func validate(_ path: String) throws {
        var before = stat(), after = stat(), attributes = attrlist()
        var data = Data(repeating: 0, count: 4096)
        attributes.bitmapcount = UInt16(ATTR_BIT_MAP_COUNT)
        attributes.commonattr = UInt32(ATTR_CMN_EXTENDED_SECURITY)
        guard lstat(path, &before) == 0 else { throw failure() }
        let result = data.withUnsafeMutableBytes { bytes in
            getattrlist(path, &attributes, bytes.baseAddress!, bytes.count, numericCast(FSOPT_NOFOLLOW))
        }
        guard result == 0, accepts(data, privateAuthority: before.st_mode & 0o077 == 0), lstat(path, &after) == 0,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino,
              before.st_mode == after.st_mode, before.st_uid == after.st_uid,
              before.st_gid == after.st_gid, before.st_nlink == after.st_nlink,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw failure() }
    }
    private static func failure() -> NSError {
        RouterVPNMacLocalAuthorization.failure("The installed supervisor path has unsafe or unverified ACL permissions.")
    }
}

private final class RouterVPNMacSupervisorSocket {
    static let directory = "/private/var/run/router-vpn"
    static let path = directory + "/controller.sock"
    private(set) var descriptor: Int32

    init() throws {
        guard getuid() != 0, getuid() == geteuid() else {
            throw RouterVPNMacLocalAuthorization.failure("Open Router VPN as the desktop user authorized during installation.")
        }
        var parent = Self.directory
        while true {
            var info = stat()
            guard lstat(parent, &info) == 0, info.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR),
                  info.st_uid == 0, info.st_mode & 0o022 == 0 else {
                throw RouterVPNMacLocalAuthorization.failure("The installed supervisor directory is not exclusively root-owned.")
            }
            try RouterVPNMacPathACL.validate(parent)
            if parent == "/" { break }
            parent = URL(fileURLWithPath: parent).deletingLastPathComponent().path
        }
        var socketInfo = stat()
        guard lstat(Self.path, &socketInfo) == 0, socketInfo.st_mode & mode_t(S_IFMT) == mode_t(S_IFSOCK),
              socketInfo.st_mode & 0o777 == 0o600, socketInfo.st_uid == getuid(), socketInfo.st_nlink == 1 else {
            throw RouterVPNMacLocalAuthorization.failure("The installed controller supervisor is unavailable or belongs to another desktop user. Run the native installer for this user.")
        }
        try RouterVPNMacPathACL.validate(Self.path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw RouterVPNMacLocalAuthorization.failure("The local supervisor socket could not be opened.") }
        descriptor = fd
        do {
            guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0, fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { throw Self.socketFailure() }
            var noSignal: Int32 = 1
            guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else { throw Self.socketFailure() }
            var address = sockaddr_un()
            address.sun_family = sa_family_t(AF_UNIX)
            address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
            let bytes = Array(Self.path.utf8)
            guard bytes.count < MemoryLayout.size(ofValue: address.sun_path) else { throw Self.socketFailure() }
            withUnsafeMutableBytes(of: &address.sun_path) { destination in
                destination.initializeMemory(as: UInt8.self, repeating: 0)
                for (index, byte) in bytes.enumerated() { destination[index] = byte }
            }
            let result = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
            }
            if result != 0 {
                guard errno == EINPROGRESS || errno == EAGAIN else { throw Self.socketFailure() }
                try wait(POLLOUT, until: Date().addingTimeInterval(5))
                var error: Int32 = 0, length = socklen_t(MemoryLayout<Int32>.size)
                guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0, error == 0 else { throw Self.socketFailure() }
            }
            // getpeereid reads XNU's LOCAL_PEERCRED; a pathname owner is not
            // evidence that the process serving the connection is privileged.
            var uid: uid_t = ~0, gid: gid_t = ~0
            var pid: pid_t = 0, size = socklen_t(MemoryLayout<pid_t>.size)
            guard getpeereid(fd, &uid, &gid) == 0, uid == 0, gid == 0,
                  getsockopt(fd, 0, 2, &pid, &size) == 0, size == socklen_t(MemoryLayout<pid_t>.size), pid > 0 else {
                throw RouterVPNMacLocalAuthorization.failure("The installed supervisor did not prove its kernel root identity.")
            }
        } catch {
            Darwin.close(fd); descriptor = -1
            throw error
        }
    }
    deinit { close() }
    func close() { if descriptor >= 0 { Darwin.close(descriptor); descriptor = -1 } }
    func retireWrite() { if descriptor >= 0 { _ = Darwin.shutdown(descriptor, SHUT_WR) } }
    private static func socketFailure() -> NSError {
        RouterVPNMacLocalAuthorization.failure("The authenticated local supervisor channel is unavailable.")
    }
    private func wait(_ events: Int32, until deadline: Date?) throws {
        while true {
            let remaining = deadline.map { $0.timeIntervalSinceNow }
            if let remaining, remaining <= 0 { throw Self.socketFailure() }
            let milliseconds: Int32 = remaining.map { Int32(min(1000, max(1, $0 * 1000))) } ?? 1000
            var descriptor = pollfd(fd: self.descriptor, events: Int16(events), revents: 0)
            let count = Darwin.poll(&descriptor, 1, milliseconds)
            if count > 0 {
                guard descriptor.revents & Int16(POLLNVAL) == 0 else { throw Self.socketFailure() }
                if descriptor.revents & Int16(events | POLLHUP | POLLERR) != 0 { return }
            } else if count < 0 && errno != EINTR { throw Self.socketFailure() }
        }
    }
    func writeFrame(_ frame: Data) throws {
        guard frame.count <= 384, frame.last == 10 else { throw Self.socketFailure() }
        let deadline = Date().addingTimeInterval(5)
        var offset = 0
        while offset < frame.count {
            try wait(POLLOUT, until: deadline)
            let count = frame.withUnsafeBytes { bytes in Darwin.write(descriptor, bytes.baseAddress!.advanced(by: offset), bytes.count - offset) }
            if count > 0 { offset += count }
            else if count < 0 && (errno == EINTR || errno == EAGAIN) { continue }
            else { throw Self.socketFailure() }
        }
    }
    func readFrame(until deadline: Date?) throws -> Data {
        var frame = Data()
        while frame.count < 4096 {
            try wait(POLLIN, until: deadline)
            var byte: UInt8 = 0
            let count = Darwin.read(descriptor, &byte, 1)
            if count == 1 {
                frame.append(byte)
                if byte == 10 { return frame }
            } else if count < 0 && (errno == EINTR || errno == EAGAIN) { continue }
            else { throw Self.socketFailure() }
        }
        throw RouterVPNMacLocalAuthorization.failure("The supervisor response exceeded its captured frame limit.")
    }
}

final class RouterVPNMacOwnedProcess: RouterVPNMacShutdownProcess, @unchecked Sendable {
    let processIdentifier: Int32
    let credentials: RouterVPNMacControllerCredentials
    private let lock = NSLock()
    private let channel: RouterVPNMacSupervisorSocket
    private var joined = false
    private var result: Int?
    private var failure: String?
    private var writeRetired = false
    private var ready = false

    var isRunning: Bool { lock.lock(); defer { lock.unlock() }; return !joined }
    var joinedSuccessfully: Bool { lock.lock(); defer { lock.unlock() }; return joined && result == 0 && failure == nil }
    var joinFailure: String? { lock.lock(); defer { lock.unlock() }; return failure }
    var retiredBeforeReady: Bool { lock.lock(); defer { lock.unlock() }; return writeRetired && !ready }
    var acceptsRequests: Bool { lock.lock(); defer { lock.unlock() }; return !joined && failure == nil && !writeRetired }

    private init(processID: Int32, credentials: RouterVPNMacControllerCredentials, channel: RouterVPNMacSupervisorSocket) {
        self.processIdentifier = processID; self.credentials = credentials; self.channel = channel
    }
    static func launch() throws -> RouterVPNMacOwnedProcess {
        func random(_ count: Int) throws -> String {
            var bytes = [UInt8](repeating: 0, count: count)
            let status = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
            guard status == errSecSuccess else { throw RouterVPNMacLocalAuthorization.failure("A private controller launch identity could not be generated.") }
            return bytes.map { String(format: "%02x", $0) }.joined()
        }
        let credentials = try RouterVPNMacControllerCredentials(accessToken: random(32), ownerToken: random(16))
        let channel = try RouterVPNMacSupervisorSocket()
        try channel.writeFrame(credentials.frame)
        let started = try channel.readFrame(until: Date().addingTimeInterval(10))
        guard let receipt = credentials.acceptsSupervisor(started, phase: "started") else {
            throw RouterVPNMacLocalAuthorization.failure("The privileged supervisor did not authenticate its captured child process.")
        }
        let owner = RouterVPNMacOwnedProcess(processID: receipt.pid, credentials: credentials, channel: channel)
        // The retained reader owns the descriptor through the actual joined
        // receipt or an honest lost-authority result; it never probes kill(pid,0).
        DispatchQueue.global(qos: .utility).async { owner.readJoined() }
        return owner
    }
    func markReady() throws {
        lock.lock(); defer { lock.unlock() }
        guard !joined, failure == nil, !writeRetired else { throw RouterVPNMacLocalAuthorization.failure("The captured controller retired during startup.") }
        ready = true
    }
    func retireBeforeReady() {
        lock.lock()
        guard !ready, !writeRetired, !joined else { lock.unlock(); return }
        writeRetired = true
        channel.retireWrite()
        lock.unlock()
    }
    private func readJoined() {
        do {
            let frame = try channel.readFrame(until: nil)
            guard let receipt = credentials.acceptsSupervisor(frame, phase: "joined", pid: processIdentifier) else {
                throw RouterVPNMacLocalAuthorization.failure("The supervisor did not authenticate this controller's actual process join.")
            }
            lock.lock()
            joined = true; result = receipt.exitCode
            if receipt.exitCode != 0 { failure = "The captured controller exited without a successful cleanup result. Router VPN cannot confirm a clean shutdown." }
            channel.close()
            lock.unlock()
        } catch {
            lock.lock()
            failure = "The privileged supervisor channel ended without proving the captured controller joined. Router VPN has retained an unconfirmed shutdown."
            channel.close()
            lock.unlock()
        }
        RouterVPNMacLocalAuthorization.shared.retire(processID: processIdentifier, owner: credentials.ownerToken)
    }
}
#endif
