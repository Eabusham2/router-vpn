import Foundation
import Libbox

final class RouterVPNLibboxEngine {
    private weak var tunnel: PacketTunnelProvider?
    private let platform: RouterVPNLibboxPlatform
    private var server: LibboxCommandServer?
    private var configContent = ""
    private var runtimeRoot: URL?

    init(tunnel: PacketTunnelProvider) {
        self.tunnel = tunnel
        self.platform = RouterVPNLibboxPlatform(tunnel: tunnel)
        platform.onLog = { [weak tunnel] message in tunnel?.writeLibboxLog(message) }
        platform.onStopService = { [weak self] in try self?.closeService() }
        platform.onReloadService = { [weak self] in try self?.reloadService() }
    }

    func start(files: [String: Data], strict: Bool) throws {
        try RouterVPNLibboxCompileProbe.verifyPinnedRuntime()
        guard server == nil else { throw error("Libbox service is already running") }
        let safeFiles = try validate(files)
        guard let config = safeFiles["sing-box.json"], let text = String(data: config, encoding: .utf8) else {
            throw error("Libbox profile is missing UTF-8 sing-box.json")
        }
        configContent = text
        platform.includeAllNetworksRequested = strict

        let fm = FileManager.default
        let base = fm.temporaryDirectory.appendingPathComponent("routervpn-libbox-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: base, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let work = base.appendingPathComponent("working", isDirectory: true)
        let temp = base.appendingPathComponent("temp", isDirectory: true)
        try fm.createDirectory(at: work, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        try fm.createDirectory(at: temp, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        for (name, data) in safeFiles {
            let destination = base.appendingPathComponent(name, isDirectory: false)
            try data.write(to: destination, options: [.atomic])
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path)
        }
        runtimeRoot = base

        let setup = LibboxSetupOptions()
        setup.basePath = base.path
        setup.workingPath = work.path
        setup.tempPath = temp.path
        setup.logMaxLines = 1000
        var setupError: NSError?
        LibboxSetup(setup, &setupError)
        if let setupError { throw error("Libbox setup failed: \(setupError.localizedDescription)") }
        LibboxSetMemoryLimit(true)

        var createError: NSError?
        let created = LibboxNewCommandServer(platform, platform, &createError)
        if let createError { throw error("Libbox command server creation failed: \(createError.localizedDescription)") }
        guard let created else { throw error("Libbox command server creation returned nil") }
        server = created
        do {
            try created.start()
            try startService()
        } catch {
            stop()
            throw error
        }
    }

    func stop() {
        if let server {
            try? server.closeService()
            server.close()
        }
        server = nil
        platform.reset()
        configContent = ""
        if let runtimeRoot { try? FileManager.default.removeItem(at: runtimeRoot) }
        runtimeRoot = nil
    }

    func pause() { server?.pause() }
    func wake() { server?.wake() }

    private func startService() throws {
        guard let server, !configContent.isEmpty else { throw error("Libbox service is not configured") }
        try server.startOrReloadService(configContent, options: LibboxOverrideOptions())
    }

    private func closeService() throws { try server?.closeService() }
    private func reloadService() throws { try startService() }

    private func validate(_ files: [String: Data]) throws -> [String: Data] {
        guard !files.isEmpty, files.count <= 64 else { throw error("Libbox profile file count is invalid") }
        let regex = try NSRegularExpression(pattern: "^[A-Za-z0-9._-]{1,128}$")
        var total = 0
        for (name, data) in files {
            let range = NSRange(name.startIndex..<name.endIndex, in: name)
            guard regex.firstMatch(in: name, range: range)?.range == range,
                  name != ".", name != "..", !name.contains("..") else { throw error("Unsafe Libbox asset name: \(name)") }
            guard data.count <= 4 * 1024 * 1024 else { throw error("Libbox asset too large: \(name)") }
            total += data.count
            guard total <= 12 * 1024 * 1024 else { throw error("Libbox profile exceeds total size limit") }
        }
        guard let config = files["sing-box.json"],
              let object = try? JSONSerialization.jsonObject(with: config), object is [String: Any] else {
            throw error("Libbox sing-box.json is not a JSON object")
        }
        return files
    }

    private func error(_ message: String) -> NSError {
        NSError(domain: "RouterVPN.LibboxEngine", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
