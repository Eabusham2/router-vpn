import Foundation
import Libbox

/// One registered operation keeps its original plan, server and source through
/// failed construction and bounded native close. The registry accepts a cancel
/// before Open so delayed provider messages cannot create unowned work.
final class RouterVPNNodeCandidateSession: NSObject, LibboxRouterNodeChainCandidateCatalogProtocol, @unchecked Sendable {
    let epoch: String, request: String
    private let plan: LibboxRouterNodeChain
    private let server: LibboxCommandServer
    private let prefix: Int32
    private let source: IOSCandidateCatalogPublication.Capture
    private let currentOwner: () -> Bool
    private let publication: IOSCandidateCatalogPublication
    private let operation = NSLock(), state = NSLock()
    private var stopped = false, closed = false, attempted = false
    private var native: LibboxRouterNodeChainCandidateMeasurement?
    private var activeRequest = "", activeCandidate = ""
    init(plan: LibboxRouterNodeChain, server: LibboxCommandServer, prefix: Int32,
         epoch: String, source: IOSCandidateCatalogPublication.Capture,
         publication: IOSCandidateCatalogPublication = .shared, current: @escaping () -> Bool) {
        self.plan = plan; self.server = server; self.prefix = prefix; self.epoch = epoch
        self.source = source; self.request = source.request; self.currentOwner = current; self.publication = publication
    }
    func currentInventorySHA256() -> String {
        state.lock(); let available = !stopped && !closed; state.unlock()
        guard available, currentOwner(), publication.current(source) else { return "" }
        return source.inventorySHA256
    }
    func invalidate() {
        state.lock(); stopped = true; let probe = native; state.unlock()
        probe?.networkChanged()
    }
    private func issue() -> NSError { NSError(domain: "RouterVPN.CandidateSession", code: 1, userInfo: [NSLocalizedDescriptionKey: "The original candidate measurement owner is unavailable or still draining."]) }
    private func inventory() -> String { String(decoding: source.inventory.data, as: UTF8.self) }
    func open() throws -> String {
        guard operation.try() else { throw issue() }; defer { operation.unlock() }
        state.lock(); let available = !stopped && !closed; let existing = native; state.unlock()
        guard available, !currentInventorySHA256().isEmpty else { throw issue() }
        if let existing { return existing.metadata() }
        guard !attempted else { throw issue() }
        attempted = true
        var failure: NSError?
        let created = LibboxRouterNodeChainNewCandidateMeasurement(plan, server, prefix, inventory(), self, &failure)
        state.lock(); native = created; let adopt = !stopped && !closed; state.unlock()
        guard failure == nil, let created, adopt, !currentInventorySHA256().isEmpty else {
            created?.networkChanged(); throw failure ?? issue()
        }
        return created.metadata()
    }
    func start(request: String, candidate: String) throws -> String {
        guard operation.try() else { throw issue() }; defer { operation.unlock() }
        guard IOSCandidateCatalogPublication.validRequest(request), !candidate.isEmpty, candidate.utf8.count <= 128,
              !currentInventorySHA256().isEmpty else { throw issue() }
        state.lock(); let probe = native; state.unlock()
        guard let probe else { throw issue() }
        // Repeat delivery of this exact Start returns the original state; it
        // cannot acquire another worker or renew a completed receipt.
        if activeRequest != request {
            try probe.start(request, candidateID: candidate); activeRequest = request; activeCandidate = candidate
        }
        guard activeCandidate == candidate else { throw issue() }
        return probe.statusJSON()
    }
    func status(request: String) throws -> String {
        guard operation.try() else { throw issue() }; defer { operation.unlock() }
        state.lock(); let probe = native; state.unlock()
        guard let probe, activeRequest == request else { throw issue() }
        let raw = probe.statusJSON()
        guard !currentInventorySHA256().isEmpty else { probe.networkChanged(); throw issue() }
        return raw
    }
    func cancel(request: String) {
        state.lock(); let probe = native; state.unlock(); probe?.cancel(request)
    }
    func close() throws {
        invalidate()
        guard operation.try() else { throw issue() }; defer { operation.unlock() }
        state.lock(); let done = closed, probe = native; state.unlock()
        if done { return }
        if let probe { try probe.close() }
        else if attempted {
            var failure: NSError?
            guard LibboxRouterNodeChainCloseCandidateMeasurement(plan, prefix, inventory(), &failure), failure == nil else { throw failure ?? issue() }
        }
        // A foreign replacement is retained; successful native join, rather
        // than deletion of somebody else's file, releases this operation.
        try? publication.remove(source)
        state.lock(); closed = true; state.unlock()
    }
}

final class RouterVPNNodeCandidateRegistry: @unchecked Sendable {
    static let shared = RouterVPNNodeCandidateRegistry()
    private let lock = NSLock()
    private let publication: IOSCandidateCatalogPublication
    init(publication: IOSCandidateCatalogPublication = .shared) { self.publication = publication }
    private var owners: [String: RouterVPNNodeCandidateSession] = [:]
    private var completed = Set<String>()
    private func key(_ epoch: String, _ request: String) -> String { epoch + ":" + request }
    func retain(_ owner: RouterVPNNodeCandidateSession) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let key = key(owner.epoch, owner.request)
        guard !completed.contains(key), !publication.closed(epoch: owner.epoch, request: owner.request), owners[key] == nil, owners.count + completed.count < 256 else { return false }
        owners[key] = owner; return true
    }
    func close(epoch: String, request: String) -> Bool {
        let key = key(epoch, request)
        lock.lock()
        if completed.contains(key) { lock.unlock(); return true }
        guard let owner = owners[key] else {
            guard owners.count + completed.count < 256 else { lock.unlock(); return false }
            do { try publication.storeClosed(epoch: epoch, request: request) }
            catch { lock.unlock(); return false }
            completed.insert(key); lock.unlock(); return true
        }
        lock.unlock()
        do { try owner.close(); try publication.storeClosed(epoch: epoch, request: request) } catch { return false }
        lock.lock(); if owners[key] === owner { owners.removeValue(forKey: key); completed.insert(key) }; lock.unlock()
        return true
    }
    func isCompleted(epoch: String, request: String) -> Bool {
        lock.lock(); defer { lock.unlock() }; return completed.contains(key(epoch, request))
    }
}
