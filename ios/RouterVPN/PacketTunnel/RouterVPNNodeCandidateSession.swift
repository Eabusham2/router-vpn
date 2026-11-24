import Foundation
import Libbox

/// The native measurement owner is a closed family union. A typed live graph
/// cannot be replayed as an ordinary or independently prepared prefix owner.
enum RouterVPNNodeCandidateOwner {
    case ordinary(LibboxRouterNodeChain)
    case socks(LibboxRouterNodeChainSOCKS)
    case connect(LibboxRouterNodeChainCONNECT)
    case execution(LibboxRouterNodeChainExecution)

    func matches(_ other: Self) -> Bool {
        switch (self, other) {
        case (.ordinary(let a), .ordinary(let b)): return a === b
        case (.socks(let a), .socks(let b)): return a === b
        case (.connect(let a), .connect(let b)): return a === b
        case (.execution(let a), .execution(let b)): return a === b
        default: return false
        }
    }
    func open(server: LibboxCommandServer, prefix: Int32, inventory: String,
              catalog: LibboxRouterNodeChainCandidateCatalogProtocol,
              failure: inout NSError?) -> RouterVPNNodeCandidateHandle? {
        switch self {
        case .ordinary(let plan):
            return LibboxRouterNodeChainNewCandidateMeasurement(plan, server, prefix, inventory, catalog, &failure).map(RouterVPNNodeCandidateHandle.ordinary)
        case .socks(let plan):
            return LibboxRouterNodeChainSOCKSNewCandidateMeasurement(plan, server, prefix, inventory, catalog, &failure).map(RouterVPNNodeCandidateHandle.socks)
        case .connect(let plan):
            return LibboxRouterNodeChainCONNECTNewCandidateMeasurement(plan, server, prefix, inventory, catalog, &failure).map(RouterVPNNodeCandidateHandle.connect)
        case .execution(let plan):
            return LibboxRouterNodeChainExecutionNewCandidateMeasurement(plan, server, prefix, inventory, catalog, &failure).map(RouterVPNNodeCandidateHandle.execution)
        }
    }

}

enum RouterVPNNodeCandidateHandle {
    case ordinary(LibboxRouterNodeChainCandidateMeasurement)
    case socks(LibboxRouterNodeChainSOCKSCandidateMeasurement)
    case connect(LibboxRouterNodeChainCONNECTCandidateMeasurement)
    case execution(LibboxRouterNodeChainExecutionCandidateMeasurement)
    func prepare() throws { switch self { case .ordinary(let v): try v.prepare(); case .socks(let v): try v.prepare(); case .connect(let v): try v.prepare(); case .execution(let v): try v.prepare() } }
    func metadata() -> String { switch self { case .ordinary(let v): return v.metadata(); case .socks(let v): return v.metadata(); case .connect(let v): return v.metadata(); case .execution(let v): return v.metadata() } }
    func metadataPage(_ offset: Int32) -> String { switch self { case .ordinary(let v): return v.metadataPage(offset); case .socks(let v): return v.metadataPage(offset); case .connect(let v): return v.metadataPage(offset); case .execution(let v): return v.metadataPage(offset) } }
    func start(_ request: String, candidateID: String) throws { switch self { case .ordinary(let v): try v.start(request, candidateID: candidateID); case .socks(let v): try v.start(request, candidateID: candidateID); case .connect(let v): try v.start(request, candidateID: candidateID); case .execution(let v): try v.start(request, candidateID: candidateID) } }
    func statusJSON() -> String { switch self { case .ordinary(let v): return v.statusJSON(); case .socks(let v): return v.statusJSON(); case .connect(let v): return v.statusJSON(); case .execution(let v): return v.statusJSON() } }
    func cancel(_ request: String) { switch self { case .ordinary(let v): v.cancel(request); case .socks(let v): v.cancel(request); case .connect(let v): v.cancel(request); case .execution(let v): v.cancel(request) } }
    func networkChanged() { switch self { case .ordinary(let v): v.networkChanged(); case .socks(let v): v.networkChanged(); case .connect(let v): v.networkChanged(); case .execution(let v): v.networkChanged() } }
    func close() throws { switch self { case .ordinary(let v): try v.close(); case .socks(let v): try v.close(); case .connect(let v): try v.close(); case .execution(let v): try v.close() } }
}

/// One registered operation keeps its original plan, server and source through
/// failed construction and bounded native close. The registry accepts a cancel
/// before Open so delayed provider messages cannot create unowned work.
final class RouterVPNNodeCandidateSession: NSObject, LibboxRouterNodeChainCandidateCatalogProtocol, @unchecked Sendable {
    let epoch: String, request: String
    private let owner: RouterVPNNodeCandidateOwner
    private let server: LibboxCommandServer
    private let prefix: Int32
    private let source: IOSCandidateCatalogPublication.Capture
    private let currentOwner: () -> Bool
    private let publication: IOSCandidateCatalogPublication
    private let operation = NSLock(), state = NSLock()
    private var stopped = false, closed = false, attempted = false
    private var prepared = false // Protected by operation; failed preparation never reopens.
    private var native: RouterVPNNodeCandidateHandle?
    private var activeRequest = "", activeCandidate = ""
    convenience init(plan: LibboxRouterNodeChain, server: LibboxCommandServer, prefix: Int32,
         epoch: String, source: IOSCandidateCatalogPublication.Capture,
         publication: IOSCandidateCatalogPublication = .shared, current: @escaping () -> Bool) {
        self.init(owner: .ordinary(plan), server: server, prefix: prefix, epoch: epoch,
                  source: source, publication: publication, current: current)
    }
    init(owner: RouterVPNNodeCandidateOwner, server: LibboxCommandServer, prefix: Int32,
         epoch: String, source: IOSCandidateCatalogPublication.Capture,
         publication: IOSCandidateCatalogPublication = .shared, current: @escaping () -> Bool) {
        self.owner = owner; self.server = server; self.prefix = prefix; self.epoch = epoch
        self.source = source; self.request = source.request; self.currentOwner = current; self.publication = publication
    }
    func matches(owner: RouterVPNNodeCandidateOwner) -> Bool { self.owner.matches(owner) }
    func matches(owner: RouterVPNNodeCandidateOwner, server: LibboxCommandServer) -> Bool {
        self.owner.matches(owner) && self.server === server
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
        if let existing { guard prepared else { throw issue() }; return existing.metadata() }
        guard !attempted else { throw issue() }
        attempted = true
        var failure: NSError?
        let created = owner.open(server: server, prefix: prefix, inventory: inventory(), catalog: self, failure: &failure)
        state.lock(); native = created; let adopt = !stopped && !closed; state.unlock()
        guard failure == nil, let created, adopt, !currentInventorySHA256().isEmpty else {
            created?.networkChanged(); throw failure ?? issue()
        }
        // Connected factories return the unique reservation before foreign catalog
        // or service work. Never enter Prepare before retaining that handle.
        do { try created.prepare() }
        catch { created.networkChanged(); throw error }
        guard !currentInventorySHA256().isEmpty else { created.networkChanged(); throw issue() }
        prepared = true
        return created.metadata()
    }
    func metadataPage(_ offset: Int32) throws -> String {
        guard offset > 0, operation.try() else { throw issue() }; defer { operation.unlock() }
        state.lock(); let probe = !stopped && !closed ? native : nil; state.unlock()
        guard let probe, prepared, !currentInventorySHA256().isEmpty else { throw issue() }
        let page = probe.metadataPage(offset)
        guard !page.isEmpty, page.utf8.count <= 12 * 1024, !currentInventorySHA256().isEmpty else { throw issue() }
        return page
    }
    func start(request: String, candidate: String) throws -> String {
        guard operation.try() else { throw issue() }; defer { operation.unlock() }
        guard IOSCandidateCatalogPublication.validRequest(request), !candidate.isEmpty, candidate.utf8.count <= 128,
              !currentInventorySHA256().isEmpty else { throw issue() }
        state.lock(); let probe = native; state.unlock()
        guard let probe, prepared else { throw issue() }
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
        guard let probe, prepared, activeRequest == request else { throw issue() }
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
    private final class CompletedOwner {
        weak var value: RouterVPNNodeCandidateSession?
        init(_ value: RouterVPNNodeCandidateSession) { self.value = value }
    }
    private var completedOwners: [String: CompletedOwner] = [:]
    private func key(_ epoch: String, _ request: String) -> String { epoch + ":" + request }
    func retain(_ owner: RouterVPNNodeCandidateSession) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let key = key(owner.epoch, owner.request)
        guard !completed.contains(key), !publication.closed(epoch: owner.epoch, request: owner.request), owners[key] == nil, owners.count + completed.count < 256 else { return false }
        owners[key] = owner; return true
    }
    func close(original: RouterVPNNodeCandidateSession) -> Bool {
        let key = key(original.epoch, original.request)
        lock.lock()
        let retained = owners[key] === original || completedOwners[key]?.value === original
        lock.unlock()
        return retained && close(epoch: original.epoch, request: original.request)
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
        lock.lock(); if owners[key] === owner { owners.removeValue(forKey: key); completedOwners[key] = CompletedOwner(owner); completed.insert(key) }; lock.unlock()
        return true
    }
    func isCompleted(epoch: String, request: String) -> Bool {
        lock.lock(); defer { lock.unlock() }; return completed.contains(key(epoch, request))
    }
}
