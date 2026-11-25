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
        let source = String(decoding: try! JSONSerialization.data(withJSONObject: ["execution": requested, "schema": [9,16,17].contains(Draft.schema) ? 6 : Draft.schema], options: [.sortedKeys]), as: UTF8.self)
        let launch = ["source": source, "source_sha256": sourceSHA256, "config_sha256": configSHA256]
        return String(decoding: try! JSONSerialization.data(withJSONObject: launch, options: [.sortedKeys]), as: UTF8.self)
    }
    var isSOCKS: Bool { Draft.schema == 3 }
    var isCONNECT: Bool { Draft.schema == 4 }
    // SHIPPING_PACKET_POSITIONS
 func responsePositions(for winner:String)->[Int] {
  guard Draft.response, (requested == "auto" && winner == "local" || ["server","auto"].contains(requested) && winner == "server") else {return []}
  return Array(1...members.count-2)
 }
 func candidatePositions(for winner:String)->[Int] { candidatePositions + responsePositions(for:winner) }
    // SHIPPING_HEX
    var members: [IOSNodeChainCapture.Member] {
        let graph: [(String, String)]
        switch Draft.schema {
        case 17: graph = [("entry", "wg")] + (1...14).map { ("import-"+String($0), "shadowsocks") } + [("final","shadowsocks")]
        case 16: graph = [("entry", "wg")] + (1...13).map { ("import-"+String($0), "shadowsocks") } + [("middle", "shadowsocks"), ("final", "shadowsocks")]
        case 9: graph = [("entry", "wg"), ("import", "shadowsocks"), ("middle", "shadowsocks"), ("final", "shadowsocks")]
        case 8: graph = [("entry", "wg"), ("middle", "shadowsocks"), ("final", "shadowsocks")]
        case 1: graph = [("entry", "wg"), ("middle", "awg2-fast"), ("final", "hysteria2")]
        case 6: graph = [("entry", "wg"), ("import", "shadowsocks"), ("middle", "wg"), ("final", "shadowsocks")]
        default:
            let mode = [2: "shadowsocks", 3: "socks5", 4: "http-connect", 5: "openvpn"][Draft.schema]!
            graph = [("entry", "wg"), ("middle", "awg2-strong"), ("import", mode), ("final", "shadowsocks")]
        }
        return graph.enumerated().map { position, node in
            .init(id: node.0, mode: node.1, profile: ["node_kind": (node.0.hasPrefix("import") || Draft.schema==8 && position==1) ? "external" : "router-vpn",
                  "node_proof_id": (node.0.hasPrefix("import") || Draft.schema==8 && position==1) ? "" : String(repeating: String(position), count: 64)])
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
    static var response: Bool { [8,9,16,17].contains(schema) }
    static var starts = 0, removes = 0, candidateStarts = 0, unattendedStarts = 0
    static var registry = "", target = ""
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
    static func run(_ requested: String, _ winner: String, _ invalid: String = "", schema: Int = 6, use: String = "") async throws {
        Draft.reset(requested, winner)
        Draft.registry = invalid.hasPrefix("registry-") ? invalid : ""; Draft.target = ""
        Draft.schema = schema; Draft.position = schema == 17 ? 12 : schema == 16 ? 14 : (schema == 6 || schema == 9 ? 2 : 1)
        let model = RouterVPNModel(), probe = IOSNodeCandidates()
        if use == "relinked" {
            IOSNodeBundleStore.shared.records["import-13"] = try JSONSerialization.data(withJSONObject: ["protocol":"shadowsocks","server":"198.51.100.13"])
        }
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
        } else if !Draft.registry.isEmpty && Draft.registry != "registry-missing" {
            IOSSpeedLabTunnel.allowStop = true; IOSSpeedLabTunnel.allowRestore = true; Provider.allowClose = true
            try await until { !probe.running || Draft.candidateStarts > 1 }
            try check(Draft.candidateStarts == 1 && probe.scores.isEmpty && !IOSMTUMeasurementGate.held,
                      "invalid Server response continued into the next target or retained cleanup")
        } else if !invalid.isEmpty && Draft.registry.isEmpty {
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
            try check(Draft.starts == 1 && Draft.candidateStarts == (Draft.registry.isEmpty ? 1:2) && probe.scores.isEmpty && IOSMTUMeasurementGate.held,
                      "selected draft bypassed original candidate close: "+String(schema)+"/"+requested+"/"+winner+" "+probe.text+" "+String(Draft.starts)+"/"+String(Draft.candidateStarts))
            Provider.allowClose = true; try await until { IOSSpeedLabTunnel.stopEntered }
            try check(probe.scores.isEmpty && IOSMTUMeasurementGate.held, "selected results escaped before native DOWN")
            IOSSpeedLabTunnel.allowStop = true; try await until { IOSSpeedLabTunnel.restoreEntered }
            try check(probe.scores.isEmpty && !model.connected && Draft.removes == 1, "temporary system preference survived native DOWN")
            IOSSpeedLabTunnel.allowRestore = true
            try await until { !probe.scores.isEmpty || !probe.running }
            try check(probe.editorScore(node: "candidate", after: Draft.position) == 2.4 && !probe.canSave,
                      "editor score lost the original stop or saved before explicit preparation")
            if !Draft.registry.isEmpty {
                try check(probe.scores.map(\.id) == ["candidate"], "absent registration acquired a score or hid the next registered target")
            }
            if !use.isEmpty {
                let row = probe.scores[0]
                try check(probe.draftInsertion(for: row) != nil && IOSConnectionProfileStore.writes == 0, "draft choice missing after original DOWN")
                if use == "stale" { model.iosConnectGeneration = UUID() }
                if use == "relinked" {
                    IOSNodeBundleStore.shared.records["import-13"] = try JSONSerialization.data(withJSONObject: ["protocol":"shadowsocks","server":"198.51.100.113"])
                }
                var applied = false
                do { try probe.useInDraft(row) { _ in applied = true } }
                catch { if use == "choose" { throw error } }
                try check(applied == (use == "choose") && IOSConnectionProfileStore.writes == 0, "draft adoption used expired authority or wrote a profile")
                if applied {
                    var replayed = false
                    try? probe.useInDraft(row) { _ in replayed = true }
                    try check(!replayed, "used draft receipt survived adoption")
                }
            } else if Draft.response {
                if schema==17 {try check(probe.editorScore(node:"candidate",after:1)==nil,"another eligible import borrowed this draft score")}
                try check(probe.canPrepare && IOSConnectionProfileStore.writes == 0, "joined private response lacked an explicit Prepare action")
                probe.prepare(probe.scores[0]); try await until { !probe.preparing }
                try check(probe.canSave && IOSConnectionProfileStore.writes == 0, "Choose wrote a profile or failed to retain the original response")
                probe.save(name:"Selected response final"); try await until { !probe.preparing }
                try check(IOSConnectionProfileStore.writes == 1 && !model.connected, "explicit response Save did not stay disconnected")
            } else { try check(!probe.canPrepare, "packet editor score gained a future-profile action") }
            try check(IOSNodeChainExecutionLastStore.data == last, "selected trial changed original Last")
            probe.cancel(); try await until { !probe.running }
        }
        try check(Draft.unattendedStarts == 0, "unsaved selected graph started from On Demand during preference save")
        try check(try IOSNodeUsage.canonical(model.bundle) == saved && IOSConnectionProfileStore.writes == (Draft.response && invalid.isEmpty && use.isEmpty ? 1:0) &&
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
        for registry in ["registry-missing","registry-invalidated","registry-foreign","registry-malformed"] {
            try await run("server","server",registry,schema:8,use:"choose")
        }
        try await run("auto","local",schema:8)
        try await run("auto","local",schema:8,use:"choose")
        try await run("auto","local",schema:17,use:"choose")
        try await run("auto","local",schema:17,use:"stale")
        try await run("auto","local",schema:17,use:"relinked")
        try await run("auto","server",schema:8)
        try await run("server","server",schema:8,use:"choose")
        try await run("auto","local",schema:9)
        try await run("auto","server",schema:9)
        try await run("server","server",schema:9,use:"choose")
        try await run("auto","local",schema:17)
        try await run("auto","server",schema:17)
        try await run("server","server",schema:17,use:"choose")
        try await run("auto","local","proofs",schema:17)
        try await run("auto","local",schema:16)
        try await run("auto","server",schema:16)
        try await run("server","server",schema:16,use:"choose")
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
    source = replace(source, 'let hopMeasurementRows=IOSMultihopNodeSelection.maximumNodes;',
                     'let hopMeasurementRows:Int;')
    source = replace(source, 'let nodeChainExecutionSource:Data?=nil;let bundleData:Data',
                     'let nodeChainExecutionSource:Data?;let bundleData:Data')
    source = replace(source, 'Identity(nodeChainSource:Data("original-complete-local-input".utf8),bundleData:try IOSNodeUsage.canonical(model.bundle))',
                     'Identity(hopMeasurementRows:ExecutionCapture(requested:Draft.requested).members.count,nodeChainSource:nil,nodeChainExecutionSource:model.activeSessionIdentity?.nodeChainExecutionSource,bundleData:try IOSNodeUsage.canonical(Draft.staged))')
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
  let proofs:[[String:Any]]=execution.members.enumerated().map{
   var value:[String:Any]=["position":$0.offset,"profile_id":$0.element.id,"node_id":$0.element.profile["node_proof_id"] as? String ?? "","mode":$0.element.mode]
   if execution.responsePositions(for:Draft.winner).contains($0.offset){value["measurement"]="routed-candidate-response"}
   return value
  }
  if op=="candidate-start"{Draft.candidateStarts+=1;Draft.target=body["candidate"] ?? ""}''')
    source = replace(source, next(line for line in source.splitlines() if 'if op=="candidate-info"' in line),
                     '''  if op=="candidate-info"{
   if Draft.lastAtInfo{IOSNodeChainExecutionLastStore.data=Data("replaced Last".utf8)}
   return try json(["request_id":request,"session_id":epoch,"mtu_session_id":mtu,"source_sha256":hash,"config_sha256":Draft.projected,
   "requested_execution":Draft.requested,"execution":Draft.wrongWinner ? "server" : Draft.winner,"candidate_positions":execution.candidatePositions(for:Draft.winner),"proposal_source_sha256":hash,
   "proposal_config_sha256":Draft.wrongConfig ? hash : execution.configSHA256,"proofs":Draft.wrongProofs ? Array(proofs.reversed()) : proofs])}''')
    source = replace(source, next(line for line in source.splitlines() if 'if op=="candidate-open"' in line),
                     '''  if op=="candidate-open"{
  guard body["prefix"]==String(Draft.position) else{throw Failure(message:"selected draft opened a foreign packet stop")}
  var metadata:[String:Any]=["schema":1,"capture_sha256":hash,"prefix_position":Draft.position,"prefix_id":ExecutionCapture(requested:Draft.requested).members[Draft.position].id,
  "source_sha256":hash,"config_sha256":Draft.projected,"preparation_source_sha256":hash,"preparation_config_sha256":Draft.projected,
  "requested_execution":Draft.requested,"execution":Draft.wrongWinner ? "server" : Draft.winner,"selection_epoch":17,"targets":[["id":"candidate","source_sha256":hash]]]
  if !Draft.registry.isEmpty{metadata["targets"]=[["id":"absent","source_sha256":String(repeating:"d",count:64)],["id":"candidate","source_sha256":hash]]}
  if Draft.response{metadata["measurement"]="routed-candidate-response"}
  reply["metadata"]=String(decoding:try json(metadata),as:UTF8.self)}''')
    source = replace(source, '"capture_sha256":hash,"prefix_position":0,"prefix_id":"entry","candidate_id":"candidate"',
                     '"capture_sha256":hash,"prefix_position":Draft.position,"prefix_id":ExecutionCapture(requested:Draft.requested).members[Draft.position].id,"candidate_id":"candidate"')
    source = replace(source, 'throw Failure(message:"unexpected Server/Compare handoff in a Local prefix test")',
                     'guard Draft.response, winner==Draft.winner, position==Draft.position, candidateID=="candidate", measuredInput=="measured original" else{throw Failure(message:"foreign selected response proposal")};return Self()')
    source = source.replace('"measurement":"routed-tcp-connect"', '"measurement":Draft.response ? "routed-candidate-response":"routed-tcp-connect"')
    source = source.replace('"kind":"tcp-connect"', '"kind":Draft.response ? "private-agent-response":"tcp-connect"')
    source = replace(source, 'rows:[Row(id:"candidate",name:"Original candidate",input:"measured original")]',
                     'rows:(Draft.registry.isEmpty ? [] : [Row(id:"absent",name:"Separate absent source",input:"absent original")])+[Row(id:"candidate",name:"Original candidate",input:"measured original")]')
    source = replace(source, '  if op=="candidate-close"{closeCalls+=1;', '''  if !Draft.registry.isEmpty && Draft.target=="absent", let raw=reply["status"] as? String {
   var status=try JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [String:Any]
   status["candidate_id"]="absent";status["candidate_source_sha256"]=String(repeating:"d",count:64)
   status["results"]=[["node_id":"absent","role":"candidate","kind":"private-agent-response","ready":false,"failure":"No registered original.","candidate_disposition":Draft.registry=="registry-malformed" ? "unknown":"not-registered"]]
   if Draft.registry=="registry-invalidated"{status["stage"]="invalidated";status["failure"]="Lost original lease"}
   if Draft.registry=="registry-foreign"{status["capture_sha256"]=String(repeating:"e",count:64)}
   reply["status"]=String(decoding:try json(status),as:UTF8.self)
  }
  if op=="candidate-close"{closeCalls+=1;''')
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
    view = (APP/'IOSNodeChainEditorView.swift').read_text()
    adoption = member(view, '                        IOSCandidateProfileChoices(probe: candidates, useInDraft:')
    for call in ('try candidates.useInDraft(score)', 'try draft.insertMeasured(score.id, after: position, compiled: compiled)', 'schedule(after: position + 1)'):
        assert call in adoption, 'The measured editor action lost '+call
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
            ('unbound Server terminal receipt', host, 'if metadata.execution == "server", metadata.metric == "routed-candidate-response" {',
             'if false {', 'invalid Server response continued into the next target or retained cleanup'),
            ('skipped detached receipt check', host, 'try preparation.requireSaved(token: score.token)\n        try apply(proposal)', 'try apply(proposal)', 'draft adoption used expired authority or wrote a profile'),
            ('borrowed first eligible response', host, '$0.position == position && $0.metric == "routed-candidate-response"', '$0.metric == "routed-candidate-response"', 'selected draft bypassed original candidate close: 17/auto/local'),
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
