import Foundation
import Libbox

final class RouterVPNLibboxEngine {
    static let proofProxyPort = 1099
    private weak var tunnel: PacketTunnelProvider?
    private let platform: RouterVPNLibboxPlatform
    private var server: LibboxCommandServer?
    private var configContent = ""
    private var runtimeRoot: URL?
    private var multihop: LibboxRouterMultihop?
    private var multihopHealth: DispatchSourceTimer?
    private let ownershipLock = NSLock()
    private var ownershipGeneration = UUID()
    private var starting = false

    init(tunnel: PacketTunnelProvider) {
        self.tunnel = tunnel
        self.platform = RouterVPNLibboxPlatform(tunnel: tunnel)
        platform.onLog = { [weak tunnel] message in tunnel?.writeLibboxLog(message) }
        platform.onStopService = { [weak self] in try self?.closeService() }
        platform.onReloadService = { [weak self] in try self?.reloadService() }
    }

    func start(files: [String: Data], strict: Bool) throws {
        try start(files: files, strict: strict, multihopMetadata: nil)
    }

    func start(files: [String: Data], strict: Bool, multihopMetadata: String?) throws {
        try RouterVPNLibboxCompileProbe.verifyPinnedRuntime()
        ownershipLock.lock()
        guard server == nil, !starting else { ownershipLock.unlock(); throw error("Libbox service is already running") }
        starting = true
        let generation = ownershipGeneration
        ownershipLock.unlock()
        var adopted = false
        defer {
            ownershipLock.lock()
            if ownershipGeneration == generation { starting = false }
            ownershipLock.unlock()
            if !adopted { stopGeneration(generation) }
        }
        var safeFiles = try validateAndInjectProof(files)
        if let multihopMetadata {
            guard let raw = safeFiles["sing-box.json"], let text = String(data: raw, encoding: .utf8) else { throw error("Missing multihop graph") }
            var failure: NSError?
            guard let plan = LibboxNewRouterMultihop(text, multihopMetadata, &failure), failure == nil else { throw failure ?? error("Multihop controller could not be constructed") }
            ownershipLock.lock()
            guard ownershipGeneration == generation else { ownershipLock.unlock(); try? plan.close(); throw error("Libbox startup was cancelled") }
            multihop = plan
            ownershipLock.unlock()
            safeFiles["sing-box.json"] = Data(plan.config().utf8)
        }
        guard let config = safeFiles["sing-box.json"], let text = String(data: config, encoding: .utf8) else { throw error("Libbox profile is missing UTF-8 sing-box.json") }
        ownershipLock.lock()
        guard ownershipGeneration == generation else { ownershipLock.unlock(); throw error("Libbox startup was cancelled") }
        configContent = text
        ownershipLock.unlock()
        platform.includeAllNetworksRequested = strict
        let fm = FileManager.default
        let base = fm.temporaryDirectory.appendingPathComponent("routervpn-libbox-\(UUID().uuidString)", isDirectory: true)
        try fm.createDirectory(at: base, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        ownershipLock.lock()
        guard ownershipGeneration == generation else { ownershipLock.unlock(); try? fm.removeItem(at: base); throw error("Libbox startup was cancelled") }
        runtimeRoot = base
        ownershipLock.unlock()
        let work = base.appendingPathComponent("working", isDirectory: true), temp = base.appendingPathComponent("temp", isDirectory: true)
        try fm.createDirectory(at: work, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]); try fm.createDirectory(at: temp, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        for (name, data) in safeFiles { let destination = base.appendingPathComponent(name); try data.write(to: destination, options: [.atomic]); try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: destination.path) }
        let setup = LibboxSetupOptions(); setup.basePath = base.path; setup.workingPath = work.path; setup.tempPath = temp.path; setup.logMaxLines = 1000; setup.oomKillerEnabled = true; setup.commandServerSecret = UUID().uuidString
        var setupError: NSError?; LibboxSetup(setup, &setupError); if let setupError { throw error("Libbox setup failed: \(setupError.localizedDescription)") }
        var createError: NSError?; let created = LibboxNewCommandServer(platform, platform, &createError)
        if let createError { throw error("Libbox command server creation failed: \(createError.localizedDescription)") }
        guard let created else { throw error("Libbox command server creation returned nil") }
        ownershipLock.lock()
        guard ownershipGeneration == generation else { ownershipLock.unlock(); created.close(); throw error("Libbox startup was cancelled") }
        server = created
        ownershipLock.unlock()
        do {
            try created.start(); try startService()
            ownershipLock.lock()
            adopted = ownershipGeneration == generation && server === created
            ownershipLock.unlock()
            if !adopted { throw error("Libbox startup was cancelled") }
        } catch { stopGeneration(generation); throw error }
    }

    func stop() { stopGeneration(nil) }
    private func stopGeneration(_ expected: UUID?) {
        ownershipLock.lock()
        if let expected, expected != ownershipGeneration { ownershipLock.unlock(); return }
        ownershipGeneration = UUID()
        let plan = multihop, owned = server, health = multihopHealth, directory = runtimeRoot
        multihop = nil; server = nil; multihopHealth = nil; runtimeRoot = nil; configContent = ""; starting = false
        ownershipLock.unlock()
        health?.cancel()
        if let plan {
            do { try plan.close() }
            catch { tunnel?.writeLibboxLog("Server multihop cleanup was not confirmed; its bounded lease expiry remains in force.") }
        }
        if let owned { try? owned.closeService(); owned.close() }
        platform.reset()
        if let directory { try? FileManager.default.removeItem(at: directory) }
    }
    func completeMultihopExecution(_ completion: @escaping (Error?) -> Void) {
        ownershipLock.lock()
        let capturedPlan = multihop, capturedServer = server, generation = ownershipGeneration
        ownershipLock.unlock()
        guard let plan = capturedPlan, let owned = capturedServer else { completion(nil); return }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                try plan.run(owned)
                guard let self else { throw NSError(domain: "RouterVPN.Multihop", code: 1, userInfo: [NSLocalizedDescriptionKey: "Multihop owner was released."]) }
                let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
                timer.schedule(deadline: .now() + 1, repeating: 1)
                timer.setEventHandler { [weak self] in
                    guard let self else { return }
                    self.ownershipLock.lock()
                    let current = self.ownershipGeneration == generation && self.multihop === plan && self.server === owned
                    self.ownershipLock.unlock()
                    if current && !plan.healthy() {
                        self.tunnel?.cancelTunnelWithError(self.error("Multihop lease or network proof expired; reconnect to compare again."))
                    }
                }
                self.ownershipLock.lock()
                let current = self.ownershipGeneration == generation && self.server === owned && self.multihop === plan
                if current {
                    self.multihopHealth?.cancel()
                    self.multihopHealth = timer
                    // Resume before releasing ownership: Stop can never cancel a
                    // suspended source or leave a newly resumed orphan behind.
                    timer.resume()
                }
                self.ownershipLock.unlock()
                guard current else { timer.setEventHandler {}; timer.resume(); timer.cancel(); throw self.error("Multihop runtime changed before completion.") }
                completion(nil)
            } catch { completion(error) }
        }
    }
    func multihopProgress() -> Data? {
        ownershipLock.lock(); let plan = multihop; ownershipLock.unlock()
        guard let plan else { return nil }
        let data = Data(plan.progressJSON().utf8)
        return data.count <= 16384 ? data : nil
    }
    func invalidateMultihop() {
        ownershipLock.lock(); let plan = multihop; ownershipLock.unlock()
        plan?.networkChanged()
    }
    func pause() {
        ownershipLock.lock(); let plan = multihop, owned = server; ownershipLock.unlock()
        plan?.networkChanged(); owned?.pause()
    }
    func wake() { ownershipLock.lock(); let owned = server; ownershipLock.unlock(); owned?.wake() }
    private func startService() throws {
        ownershipLock.lock(); let owned = server, content = configContent; ownershipLock.unlock()
        guard let server = owned, !content.isEmpty else { throw error("Libbox service is not configured") }
        try server.startOrReloadService(content, options: LibboxOverrideOptions())
    }
    private func closeService() throws { ownershipLock.lock(); let owned = server; ownershipLock.unlock(); try owned?.closeService() }
    private func reloadService() throws {
        ownershipLock.lock(); let comparing = multihop != nil; ownershipLock.unlock()
        guard !comparing else { throw error("Multihop reload requires a fresh owned comparison") }
        try startService()
    }

    private func validateAndInjectProof(_ files: [String: Data]) throws -> [String: Data] {
        guard !files.isEmpty, files.count <= 64 else { throw error("Libbox profile file count is invalid") }
        let regex = try NSRegularExpression(pattern: "^[A-Za-z0-9._-]{1,128}$"); var total = 0; var result = files
        for (name, data) in files {
            let range = NSRange(name.startIndex..<name.endIndex, in: name)
            guard regex.firstMatch(in: name, range: range)?.range == range, name != ".", name != "..", !name.contains("..") else { throw error("Unsafe Libbox asset name: \(name)") }
            guard data.count <= 4 * 1024 * 1024 else { throw error("Libbox asset too large: \(name)") }
            total += data.count; guard total <= 12 * 1024 * 1024 else { throw error("Libbox profile exceeds total size limit") }
        }
        guard let config = files["sing-box.json"], var object = try JSONSerialization.jsonObject(with: config) as? [String: Any] else { throw error("Libbox sing-box.json is not a JSON object") }
        var inbounds = object["inbounds"] as? [[String: Any]] ?? []
        for inbound in inbounds {
            if (inbound["tag"] as? String) == "routervpn-proof" { throw error("Libbox profile reserves inbound tag routervpn-proof") }
            if (inbound["listen"] as? String) == "127.0.0.1", (inbound["listen_port"] as? Int) == Self.proofProxyPort { throw error("Libbox profile already uses Router VPN proof port \(Self.proofProxyPort)") }
        }
        inbounds.append(["type": "mixed", "tag": "routervpn-proof", "listen": "127.0.0.1", "listen_port": Self.proofProxyPort])
        object["inbounds"] = inbounds
        let patched = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        guard patched.count <= 4 * 1024 * 1024 else { throw error("Patched Libbox sing-box.json exceeds safety limit") }
        result["sing-box.json"] = patched
        return result
    }
    private func error(_ message: String) -> NSError { NSError(domain: "RouterVPN.LibboxEngine", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }
}
