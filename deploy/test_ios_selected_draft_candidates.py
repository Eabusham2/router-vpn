#!/usr/bin/env python3
"""Run the shipping Swift draft owner, editor controller, result parser and temporary manager lifecycle.

The NetworkExtension API, the source compiler and the native provider replies are
controlled boundaries. The source, selection, candidate IPC and post-DOWN checks
in the app execute normally. Native fifty-connection acceptance is a separate gate.
"""
from pathlib import Path
import subprocess
import tempfile

import test_ios_node_candidate_preparation_flow as FLOW
from test_ios_startup_policy import member

APP = FLOW.APP


def replace(source, before, after):
    if source.count(before) != 1:
        raise ValueError('selected draft fixture lost its original boundary: ' + before[:100])
    return source.replace(before, after)


BOUNDARY = r'''
typealias IOSSessionIdentity = Identity
struct IOSDeviceMTUPreference: Equatable {
    @MainActor static var generation = 1
    let revision: Int
    @MainActor static func current() throws -> Self { Self(revision: generation) }
    @MainActor func requireCurrent() throws { guard revision == Self.generation else { throw CancellationError() } }
}
@MainActor enum IOSNodeChainExecutionLastStore {
    static var data: Data? = Data("original Last".utf8)
    static func snapshot() throws -> Data? { data }
}
@MainActor struct ExecutionCapture {
    let requested: String
    let sourceSHA256 = Provider.hash, configSHA256 = String(repeating: "b", count: 64)
    var ordinaryLaunchInput: String { launchInput }
    var launchInput: String {
        let source = String(decoding: try! JSONSerialization.data(withJSONObject: ["execution": requested, "schema": Draft.schema], options: [.sortedKeys]), as: UTF8.self)
        let launch = ["source": source, "source_sha256": sourceSHA256, "config_sha256": configSHA256]
        return String(decoding: try! JSONSerialization.data(withJSONObject: launch, options: [.sortedKeys]), as: UTF8.self)
    }
    var isSOCKS: Bool { Draft.schema == 3 }
    var isCONNECT: Bool { Draft.schema == 4 }
    // SHIPPING_PACKET_POSITIONS
    // SHIPPING_HEX
    var members: [IOSNodeChainCapture.Member] {
        let graph: [(String, String)]
        switch Draft.schema {
        case 1: graph = [("entry", "wg"), ("middle", "awg2-fast"), ("final", "hysteria2")]
        case 6: graph = [("entry", "wg"), ("import", "shadowsocks"), ("middle", "wg"), ("final", "shadowsocks")]
        default:
            let mode = [2: "shadowsocks", 3: "socks5", 4: "http-connect", 5: "openvpn"][Draft.schema]!
            graph = [("entry", "wg"), ("middle", "awg2-strong"), ("import", mode), ("final", "shadowsocks")]
        }
        return graph.enumerated().map { position, node in
            .init(id: node.0, mode: node.1, profile: ["node_kind": node.0 == "import" ? "external" : "router-vpn",
                  "node_proof_id": node.0 == "import" ? "" : String(repeating: String(position), count: 64)])
        }
    }
    func close() throws {}
    static func reopen(_ input: String, selectedProfile: [String: Any]) throws -> Self {
        let value = Self(requested: Draft.requested)
        guard input == value.launchInput, selectedProfile["id"] as? String == "final" else { throw CancellationError() }
        return value
    }
}
@MainActor enum IOSOrderedRouteCapture {
    case ordinary(IOSNodeChainCapture), socks, connect, execution(ExecutionCapture)
    var launchInput: String { if case .execution(let v) = self { return v.launchInput }; return "" }
    func close() throws {}
}
@MainActor extension IOSRuntimeSelector {
    struct Selection { struct Engine { let rawValue = "multihop-libbox" }; let engine = Engine(); let rawProfileID = "shadowsocks" }
    static func selectNodeChain(_ route: IOSOrderedRouteCapture) throws -> Selection {
        guard case .execution = route else { throw CancellationError() }; return Selection()
    }
}
@MainActor final class NETunnelProviderProtocol {
    let providerBundleIdentifier = "com.eabusham.routervpn.PacketTunnel"
    var providerConfiguration: [String: Any]?
}
@MainActor final class NETunnelProviderManager {
    static var saved: NETunnelProviderManager?
    enum State { case disconnected, invalid, connected }
    final class Connection { var status: State = .disconnected }
    let connection = Connection()
    var protocolConfiguration: Any? = NETunnelProviderProtocol()
    var isOnDemandEnabled = false
    var onDemandRules: [NEOnDemandRuleConnect]? = []
    func saveToPreferences() async throws {
        Self.saved = self
        if isOnDemandEnabled && connection.status == .disconnected { Draft.unattendedStarts += 1; connection.status = .connected }
    }
    static func loadAllFromPreferences() async throws -> [NETunnelProviderManager] { saved.map { [$0] } ?? [] }
    func loadFromPreferences() async throws {}
    func removeFromPreferences() async throws {
        guard Self.saved === self else { throw CancellationError() }
        Self.saved = nil; Draft.removes += 1
    }
}
struct NEOnDemandRuleConnect {}
enum IOSNodeChainProviderCapture { static let executionKey = "nodeChainExecutionSource" }
@MainActor enum Draft {
    static var winner = "server", requested = "server", position = 2, schema = 6
    static var starts = 0, removes = 0, candidateStarts = 0, unattendedStarts = 0
    static var replacedRule = false
    static var wrongConfig = false, wrongProofs = false, wrongWinner = false, lastAtInfo = false, foreignReadback = false
    static var staged: ClientBundle?
    static let projected = String(repeating: "c", count: 64)
    static var input: String { ExecutionCapture(requested: requested).launchInput }
    static func reset(_ req: String, _ selected: String) {
        requested = req; winner = selected; position = 2; starts = 0; removes = 0; candidateStarts = 0; unattendedStarts = 0; replacedRule = false
        wrongConfig = false; wrongProofs = false; wrongWinner = false; lastAtInfo = false; foreignReadback = false
        staged = nil; NETunnelProviderManager.saved = nil; Provider.reset(); IOSSpeedLabTunnel.reset()
        IOSDeviceMTUPreference.generation = 1; IOSNodeChainExecutionLastStore.data = Data("original Last".utf8)
    }
}
@MainActor extension RouterVPNModel {
    var userDisconnectInProgress: Bool { iosUserDisconnectInProgress }
    func captureIOSOrderedRoute(_ bundle: ClientBundle) throws -> IOSOrderedRouteCapture {
        guard let requested = bundle.routerProfiles.first?.multihopExecution, ["server", "auto"].contains(requested) else { throw CancellationError() }
        return .execution(.init(requested: requested))
    }
    func start(manager: NETunnelProviderManager, bundle: ClientBundle, selection: IOSRuntimeSelector.Selection,
               candidateDraft: IOSNodeCandidateDraftExecution? = nil) async throws -> Bool {
        try IOSSpeedLabContext.candidateAdmission?()
        let source = try captureIOSOrderedRoute(bundle).launchInput
        let nodeChainSource = source
        var bundle = bundle
        if Draft.foreignReadback { bundle.routerProfiles[0].multihopExecution = "local" }
        guard NETunnelProviderManager.saved == nil, let owner = IOSSpeedLabContext.owner else { throw CancellationError() }
        let proto = manager.protocolConfiguration as! NETunnelProviderProtocol
        proto.providerConfiguration = [IOSSpeedLabContext.ownerKey: owner.uuidString, IOSNodeChainProviderCapture.executionKey: source]
        let strict = true
        // SHIPPING_DEMAND_POLICY
        try await manager.saveToPreferences()
        if Draft.replacedRule { manager.onDemandRules = [NEOnDemandRuleConnect()] }
        // SHIPPING_FINAL_FORM_READBACK
        guard manager.connection.status == .disconnected else { throw CancellationError() }
        manager.connection.status = .connected
        connected = true
        let identity = Identity(nodeChainSource: nil, nodeChainExecutionSource: Data(source.utf8))
        activeSessionIdentity = identity; orderedExecutionObservation = (identity, Draft.requested, Draft.winner)
        Draft.staged = bundle; Draft.starts += 1
        return true
    }
}
'''

TEST = r'''
@MainActor @main struct SelectedDraftFlow {
    static func run(_ requested: String, _ winner: String, _ invalid: String = "", schema: Int = 6) async throws {
        Draft.reset(requested, winner)
        Draft.schema = schema; Draft.position = schema == 6 ? 2 : 1
        let model = RouterVPNModel(), probe = IOSNodeCandidates()
        let saved = try IOSNodeUsage.canonical(model.bundle)
        var draft = model.bundle!
        draft.routerProfiles[0].multihopExecution = requested
        let last = IOSNodeChainExecutionLastStore.data
        if invalid == "config" { Draft.wrongConfig = true }
        if invalid == "proofs" { Draft.wrongProofs = true }
        if invalid == "winner" { Draft.wrongWinner = true }
        if invalid == "foreign-readback" { Draft.foreignReadback = true }
        if invalid == "foreign-rule" { Draft.replacedRule = true }
        if invalid == "Last" { Draft.lastAtInfo = true }
        try probe.startEditorPrefix(model: model, bundle: draft, position: Draft.position)
        let labels = ProductLabels(model)
        try check(labels.state() == "Testing" && IOSMTUMeasurementGate.held, "selected draft acquired no exclusive Testing owner")
        if invalid == "foreign-manager" {
            try await until { Provider.closeCalls > 0 || !probe.running }
            Provider.allowClose = true; try await until { IOSSpeedLabTunnel.stopEntered }
            let proto = NETunnelProviderManager.saved!.protocolConfiguration as! NETunnelProviderProtocol
            let source = proto.providerConfiguration!
            proto.providerConfiguration?[IOSSpeedLabContext.ownerKey] = UUID().uuidString
            IOSSpeedLabTunnel.allowStop = true
            try await until { model.message.contains("cleanup is still pending") || Draft.removes > 0 }
            try check(Draft.removes == 0 && IOSMTUMeasurementGate.held && probe.scores.isEmpty, "foreign manager was removed before original DOWN")
            proto.providerConfiguration = source; IOSSpeedLabTunnel.allowRestore = true
            try await until { !probe.scores.isEmpty }; probe.cancel(); try await until { !probe.running }
        } else if !invalid.isEmpty {
            IOSSpeedLabTunnel.allowStop = true; IOSSpeedLabTunnel.allowRestore = true; Provider.allowClose = true
            if invalid == "foreign-rule" {
                try await until { model.message.contains("cleanup is still pending") || Draft.starts > 0 }
                try check(Draft.starts == 0 && Draft.removes == 0 && IOSMTUMeasurementGate.held,
                          "foreign On Demand rule reached explicit selected start")
                NETunnelProviderManager.saved?.onDemandRules = []
            }
            try await until { !probe.running || Draft.candidateStarts > 0 }
            try check(Draft.candidateStarts == 0 && probe.scores.isEmpty && !probe.canSave, "changed selected source started candidate traffic")
            if invalid == "foreign-readback" || invalid == "foreign-rule" {
                try check(Draft.starts == 0, "foreign draft preference started a temporary system VPN")
            }
        } else {
            try await until { Provider.closeCalls > 0 || !probe.running || Draft.unattendedStarts > 0 }
            try check(Draft.unattendedStarts == 0, "unsaved selected graph started from On Demand during preference save")
            try check(Draft.starts == 1 && Draft.candidateStarts == 1 && probe.scores.isEmpty && IOSMTUMeasurementGate.held,
                      "selected draft bypassed original candidate close")
            Provider.allowClose = true; try await until { IOSSpeedLabTunnel.stopEntered }
            try check(probe.scores.isEmpty && IOSMTUMeasurementGate.held, "selected results escaped before native DOWN")
            IOSSpeedLabTunnel.allowStop = true; try await until { IOSSpeedLabTunnel.restoreEntered }
            try check(probe.scores.isEmpty && !model.connected && Draft.removes == 1, "temporary system preference survived native DOWN")
            IOSSpeedLabTunnel.allowRestore = true
            try await until { !probe.scores.isEmpty || !probe.running }
            try check(probe.editorScore(node: "candidate", after: Draft.position) == 2.4 && !probe.canPrepare && !probe.canSave,
                      "editor score gained Save authority or lost the captured packet stop")
            try check(IOSNodeChainExecutionLastStore.data == last, "selected trial changed original Last")
            probe.cancel(); try await until { !probe.running }
        }
        try check(Draft.unattendedStarts == 0, "unsaved selected graph started from On Demand during preference save")
        try check(try IOSNodeUsage.canonical(model.bundle) == saved && IOSConnectionProfileStore.writes == 0 &&
                  !model.connected && NETunnelProviderManager.saved == nil && !IOSMTUMeasurementGate.held,
                  "draft trial left a selected graph or saved profile behind")
    }
    static func main() async throws {
        for schema in 1...6 {
            Draft.schema = schema
            let actual = ExecutionCapture(requested: "auto").candidatePositions
            let expected = (schema == 3 || schema == 4) ? [0] : (schema == 6 ? [0, 2] : [0, 1])
            try check(actual == expected, "original typed packet position scope changed for schema " + String(schema))
        }
        for schema in [1, 2, 5] { try await run("auto", "local", schema: schema) }
        try await run("server", "server")
        try await run("auto", "server")
        try await run("auto", "server", "foreign-manager")
        try await run("auto", "local")
        for kind in ["config", "proofs", "winner", "Last", "foreign-readback", "foreign-rule"] { try await run("auto", "local", kind) }
        print("Apple selected draft candidate owner: \(checks) source, trial, private IPC and post-DOWN checks PASS")
    }
}
'''


def fixture():
    source = FLOW.fixture_boundary()
    source = replace(source, 'struct Profile:Codable', 'struct Profile:Codable,Equatable')
    source = replace(source, 'struct ClientBundle:Codable {', 'struct ClientBundle:Codable {var profiles:[String:String]=[:];')
    source = replace(source, member(source, '@MainActor final class IOSNodeCandidateDraftExecution'), '')
    source = replace(source, 'struct Identity {let engine="multihop-libbox";let nodeChainSource:Data?}',
                     'struct Identity:Equatable {let engine="multihop-libbox";let nodeChainSource:Data?;var nodeChainExecutionSource:Data?=nil}')
    source = replace(source, ' var activeRawProfile=',
                     ' var orderedExecutionObservation:(identity:Identity,requested:String,selected:String)?\n var activeRawProfile=')
    source = replace(source, 'let nodeChainExecutionSource:Data?=nil;let bundleData:Data',
                     'let nodeChainExecutionSource:Data?;let bundleData:Data')
    source = replace(source, 'Identity(nodeChainSource:Data("original-complete-local-input".utf8),bundleData:try IOSNodeUsage.canonical(model.bundle))',
                     'Identity(nodeChainSource:nil,nodeChainExecutionSource:model.activeSessionIdentity?.nodeChainExecutionSource,bundleData:try IOSNodeUsage.canonical(Draft.staged))')
    source = replace(source, 'func retireNewCandidateManager(model:RouterVPNModel,owner:UUID,input:String)async throws{throw Failure(message:"Local trial cannot retire a selected draft manager")}',
                     'let savedProtocol:NETunnelProviderProtocol?=nil\n static let ownerKey=IOSSpeedLabContext.ownerKey\n'
                     'static func ownedManager()async throws->NETunnelProviderManager?{NETunnelProviderManager.saved}\n'
                     'static func idle(_ m:NETunnelProviderManager)->Bool{m.connection.status == .disconnected}\n'
                     + member((APP/'IOSSpeedLabTunnel.swift').read_text(), '    func retireNewCandidateManager('))
    source = replace(source, 'model.connected=false;model.activeSessionIdentity=nil;model.iosConnectGeneration=UUID()',
                     'model.connected=false;model.activeSessionIdentity=nil;NETunnelProviderManager.saved?.connection.status = .disconnected;model.iosConnectGeneration=UUID()')
    source = replace(source, member(source, ' static func selectedPositions('),
                     member((APP/'IOSNodeCandidateProposal.swift').read_text(), '    static func selectedPositions(')
                     .replace('IOSNodeChainExecutionCapture.reopen', 'ExecutionCapture.reopen'))
    source = replace(source, next(line for line in source.splitlines() if 'let proofs:[[String:Any]]=' in line),
                     '''  let execution=ExecutionCapture(requested:Draft.requested)
  let proofs:[[String:Any]]=execution.members.enumerated().map{["position":$0.offset,"profile_id":$0.element.id,"node_id":$0.element.profile["node_proof_id"] as? String ?? "","mode":$0.element.mode]}
  if op=="candidate-start"{Draft.candidateStarts+=1}''')
    source = replace(source, next(line for line in source.splitlines() if 'if op=="candidate-info"' in line),
                     '''  if op=="candidate-info"{
   if Draft.lastAtInfo{IOSNodeChainExecutionLastStore.data=Data("replaced Last".utf8)}
   return try json(["request_id":request,"session_id":epoch,"mtu_session_id":mtu,"source_sha256":hash,"config_sha256":Draft.projected,
   "requested_execution":Draft.requested,"execution":Draft.wrongWinner ? "server" : Draft.winner,"candidate_positions":execution.candidatePositions,"proposal_source_sha256":hash,
   "proposal_config_sha256":Draft.wrongConfig ? hash : execution.configSHA256,"proofs":Draft.wrongProofs ? Array(proofs.reversed()) : proofs])}''')
    source = replace(source, next(line for line in source.splitlines() if 'if op=="candidate-open"' in line),
                     '''  if op=="candidate-open"{
  guard body["prefix"]==String(Draft.position) else{throw Failure(message:"selected draft opened a foreign packet stop")}
  reply["metadata"]=String(decoding:try json(["schema":1,"capture_sha256":hash,"prefix_position":Draft.position,"prefix_id":"middle",
  "source_sha256":hash,"config_sha256":Draft.projected,"preparation_source_sha256":hash,"preparation_config_sha256":Draft.projected,
  "requested_execution":Draft.requested,"execution":Draft.wrongWinner ? "server" : Draft.winner,"selection_epoch":17,"targets":[["id":"candidate","source_sha256":hash]]]),as:UTF8.self)}''')
    source = replace(source, '"capture_sha256":hash,"prefix_position":0,"prefix_id":"entry","candidate_id":"candidate"',
                     '"capture_sha256":hash,"prefix_position":Draft.position,"prefix_id":"middle","candidate_id":"candidate"')
    model = (APP/'RouterVPNModel.swift').read_text()
    connect = member(model, '    func connectCandidatePreparation(_ capture: IOSOrderedRouteCapture')
    execution = (APP/'IOSNodeChainExecutionCapture.swift').read_text()
    # The real generic launcher checks the persisted form for ordinary Connect.
    # Only an exact retained draft can stage different form bytes.
    start = model.index('        if let nodeChainSource {\n            if let candidateDraft {')
    first = model.index('            if let candidateDraft {', start)
    final_form = model[first:model.index('            guard !Task.isCancelled,', first)]
    capture = replace(BOUNDARY, '// SHIPPING_FINAL_FORM_READBACK', final_form)
    policy = model.index('        if strict && candidateDraft == nil {')
    capture = replace(capture, '// SHIPPING_DEMAND_POLICY', model[policy:model.index('        guard iosConnectGeneration', policy)])
    capture = replace(capture, '// SHIPPING_PACKET_POSITIONS', member(execution, '    var candidatePositions:'))
    capture = replace(capture, '// SHIPPING_HEX', member(execution, '    private static func hex('))
    return source + capture + '\n@MainActor extension RouterVPNModel {\n' + connect + '\n}\n' + TEST


def main():
    owner = (APP/'IOSNodeCandidates.swift').read_text()
    controller = owner[owner.index('private final class IOSCandidateReply:'):owner.index('struct IOSNodeCandidatesCard:')]
    controller += '\n'+member(owner, '@MainActor extension IOSNodeCandidates {')
    with tempfile.TemporaryDirectory(prefix='ios-selected-draft-') as folder:
        work = Path(folder)
        host, test, image = work/'Controller.swift', work/'Fixture.swift', work/'test'
        host.write_text('import Foundation\n'+controller)
        test.write_text(fixture())
        command = ['swiftc', '-j', '1', '-swift-version', '6', '-module-cache-path', str(work/'modules'), *FLOW.crypto_link_flags(),
                   *(str(APP/name) for name in ['IOSSpeedLabOwnership.swift', 'IOSMTUMeasurementGate.swift',
                     'IOSNodeCandidateResult.swift', 'IOSNodeCandidateDraftExecution.swift', 'IOSNodeCandidatePreparation.swift']),
                   str(host), str(test), '-o', str(image)]
        def exercise(build, witness=None, label=None):
            subprocess.run(build, check=True, timeout=120)
            result = subprocess.run([str(image)], capture_output=True, text=True, timeout=45)
            output = result.stdout + result.stderr
            if witness:
                assert result.returncode != 0 and witness in output, output[-3500:]
                print('Rejected selected draft defect: '+label, flush=True)
            else:
                assert result.returncode == 0, output[-3500:]
                print(result.stdout.strip(), flush=True)

        exercise(command)
        draft = APP/'IOSNodeCandidateDraftExecution.swift'
        changes = (
            ('foreign selected winner', draft, 'info.execution == winner,', '["local", "server"].contains(winner),', 'changed selected source started candidate traffic'),
            ('substituted unsaved preference', draft, 'try IOSNodeUsage.canonical(bundle) == draftBundle', 'true', 'changed selected source started candidate traffic'),
            ('autonomous On Demand', test, 'if strict && candidateDraft == nil {', 'if strict {', 'unsaved selected graph started from On Demand during preference save'),
            ('foreign On Demand readback', test, 'guard !manager.isOnDemandEnabled, (manager.onDemandRules ?? []).isEmpty else { throw CancellationError() }', '', 'foreign On Demand rule reached explicit selected start'),
            ('foreign manager retirement', test, 'configuration[Self.ownerKey] as? String == owner.uuidString,', '', 'foreign manager was removed before original DOWN'),
        )
        for label, original, before, after, witness in changes:
            altered = work/('Changed'+original.name)
            altered.write_text(replace(original.read_text(), before, after))
            exercise([str(altered) if argument == str(original) else argument for argument in command], witness, label)


if __name__ == '__main__':
    main()
