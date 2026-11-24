#!/usr/bin/env python3
"""Replay encrypted peer receipts through the Swift transaction, store and app history."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile
import test_ios_ordered_latency_callbacks as callbacks


def receipt_rows(log, *, paired_stream=False):
    cases = {}
    for line in log.splitlines():
        match = re.search(r'QUALIFIED_ORIGINAL_(NODES|STATUS|RECEIPT) (9|16) (.+)$', line)
        if not match:
            continue
        kind, count, raw = match.groups()
        case = cases.setdefault(int(count), {'receipts': [], 'statuses': []})
        if kind == 'NODES':
            if 'nodes' in case:
                raise ValueError('Duplicate original peer inventory')
            case['nodes'] = json.loads(raw)
        else:
            case['receipts' if kind == 'RECEIPT' else 'statuses'].append(raw)
    expected = {9} if paired_stream else {9, 16}
    if set(cases) != expected:
        raise ValueError(f'Complete original peer inventories required at {sorted(expected)}')
    return cases


BOUNDARY = r'''
nonisolated(unsafe) var originalLaunch = "", originalSource = "", originalConfig = "", originalIDs = [String]()
nonisolated(unsafe) var nativeRoles = [String](), nativeCount = 0, originalPublicIDs = Set<String>()
nonisolated(unsafe) var displayedOrder = [String]()
struct OrdinaryCapture {
 let plan = NativePlan(), selectionExecution = "local"
 var launchInput: String { originalLaunch }
 var sourceSHA256: String { originalSource }
 var configSHA256: String { originalConfig }
 var members: [Member] { displayedOrder.map { Member(id: $0) } }
}
'''
TESTS = r'''
@main struct ExtendedLatencyAppTest {
 static func require(_ value: Bool, _ label: String) throws { if !value { throw NSError(domain:label,code:1) } }
 static func refuses(_ label:String, _ operation:() throws->Void) throws {
    do { try operation() } catch { return }
    try require(false,label)
 }
 @MainActor static func main() async throws {
  let input = try JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath:CommandLine.arguments[1]))) as! [[String:Any]]
  for data in input {
   let count=data["count"] as! Int, nodes=data["nodes"] as! [[String:Any]], raws=data["receipts"] as! [String]
   let url=URL(fileURLWithPath: data["original"] as! String)
   let bytes=try Data(contentsOf:url), launch=try JSONSerialization.jsonObject(with:bytes) as! [String:Any]
   originalLaunch=String(decoding:bytes,as:UTF8.self);originalSource=launch["source_sha256"] as! String;originalConfig=launch["config_sha256"] as! String
   originalIDs=nodes.map{$0["profile_id"] as! String};displayedOrder=originalIDs
   nativeRoles=nodes.map{$0["kind"] as? String ?? "private-node"}
   let inputs=launch["nodes"] as! [String],identities=launch["identity_sources"] as! [String]
   originalPublicIDs=[]
   for (position,input) in inputs.enumerated() {
    let member=try JSONSerialization.jsonObject(with:Data(input.utf8)) as! [String:Any]
    let isPublic=member["kind"] as? String=="routervpn-node-chain-imported-member"
    let profile:[String:Any]
    if isPublic {
     let captured=try JSONSerialization.jsonObject(with:Data((member["capture"] as! String).utf8)) as! [String:Any]
     profile=captured["profile"] as! [String:Any];originalPublicIDs.insert(profile["id"] as! String)
    }else{profile=try JSONSerialization.jsonObject(with:Data((member["profile_json"] as! String).utf8)) as! [String:Any]}
    try require(originalIDs[position]==profile["id"] as? String && identities[position].isEmpty==isPublic &&
                nativeRoles[position]==(isPublic ? "public-path":"private-node") &&
                (nodes[position]["node_id"] as? String ?? "")==(profile["node_proof_id"] as? String ?? ""),"retained member lost its independent public or private source")
   }
   let interiors=nativeRoles.dropFirst().dropLast()
   if data["paired_stream"] as? Bool==true {try require(interiors.contains("private-node") && interiors.contains("public-path"),"private stream replay requires both original interior types")}
   else {try require(interiors.allSatisfy{$0=="public-path"},"historical literal import source changed")}
   let capturedModes=nodes.map{$0["mode"] as! String}
   try require(capturedModes == ["wg"] + Array(repeating:"shadowsocks",count:count-1) && nodes.enumerated().allSatisfy{$0.offset == $0.element["position"] as? Int}, "peer inventory changed")
   nativeCount=count
   let identity=try IOSSessionIdentity(connectedAt:Date(),engine:"multihop-libbox",rawProfile:"shadowsocks",bundleData:Data([1]),entryBundleData:nil,nodeChainSource:bytes)
   try require(identity.hopMeasurementRows==count, "wrong original private session bound")
   let model=RouterVPNModel();model.activeSessionIdentity=identity
   let capture=try IOSOrderedLatencyCapture(model)
   try require(capture.ids==originalIDs && capture.extended?.ids==originalIDs && IOSOrderedLatency.supported(model), "original qualified route was unavailable")
   for (position, raw) in raws.enumerated() {
    let value=try JSONSerialization.jsonObject(with:Data(raw.utf8)) as! [String:Any], request=value["request_id"] as! String
    let node=originalIDs[position], response=(data["statuses"] as! [String])[position]
    let transaction=IOSOrderedLatencyTransaction(request:request,source:originalSource,config:originalConfig,node:node,position:position,
      extended:capture.extended, send:{ op in
       switch op {
       case "ordered-latency-open":return ["opened":true,"closed":false]
       case "ordered-latency-start":return ["status":response,"saved":raw]
       case "ordered-latency-close":return ["closed":true]
       default: throw fault()
       }
      })
    let record=try await transaction.run(current:{try capture.require(model)},update:{_ in})
    try IOSOrderedLatencyHistory.save(record,profile:capture.profile,current:{try capture.require(model)})
    let reopened=try IOSOrderedLatencyHistory.load(profile:capture.profile,source:capture.source,config:capture.config,position:position,node:node,extended:capture.extended)
    try require(reopened?.raw==raw && record.count==count, "original persisted receipt changed")
   }
   let display=IOSOrderedLatency();display.load(model)
   try require(display.ids==originalIDs && display.history.count==count && display.history.values.allSatisfy{$0.contains("50 successful responses, 0 failed")}, "fresh history display omitted an original member")
   let last=raws[count-1], lastID=originalIDs[count-1], lastRequest=(try JSONSerialization.jsonObject(with:Data(last.utf8)) as! [String:Any])["request_id"] as! String
   let before=IOSPrivateJSONStore.value
   try refuses("unqualified source accepted extended receipt"){_ = try IOSOrderedLatencyRecord(last)}
   try refuses("oversized receipt accepted"){_ = try IOSOrderedLatencyRecord(last+String(repeating:" ",count:8192),extended:capture.extended)}
   for field in ["source_sha256","node_id","position"] {
    var bad=try JSONSerialization.jsonObject(with:Data(last.utf8)) as! [String:Any]
    bad[field]=field=="position" ? 0 : field=="source_sha256" ? String(repeating:"0",count:64) : originalIDs[0]
    try refuses("other "+field+" accepted"){_ = try IOSOrderedLatencyRecord.completed(status:status(bad),saved:json(bad),source:originalSource,config:originalConfig,node:lastID,position:count-1,request:lastRequest,extended:capture.extended)}
   }
   if data["paired_stream"] as? Bool==true, let paired=nativeRoles.indices.first(where:{$0>0 && $0<count-1 && nativeRoles[$0]=="private-node"}),let imported=nativeRoles.firstIndex(of:"public-path"){
    nativeRoles.swapAt(paired,imported)
    try refuses("swapped native role inventory accepted"){_ = try IOSOrderedLatencyCapture(model)}
    nativeRoles.swapAt(paired,imported)
   }
   displayedOrder.swapAt(1,2)
   let reordered=IOSOrderedLatency();reordered.load(model)
   try require(reordered.history.isEmpty, "reordered members showed borrowed history")
   displayedOrder=originalIDs;nativeCount=0
   let ordinary=IOSOrderedLatency();ordinary.load(model)
   try require(ordinary.ids.isEmpty && before==IOSPrivateJSONStore.value,"unqualified native owner displayed or replaced extended history")
   print("iOS qualified Local: \(count) exact encrypted receipts through provider transaction, save, reopen and display; source, position, node, size, reordered and ordinary refusals PASS")
   IOSPrivateJSONStore.files=[:]
  }
 }
}
'''


def run(originals, log, *, paired_stream=False):
    cases = receipt_rows(log, paired_stream=paired_stream)
    fixture = []
    for count, case in sorted(cases.items()):
        if len(case['nodes']) != count or len(case['receipts']) != count or len(case['statuses']) != count:
            raise ValueError('Missing original rows')
        fixture.append(dict(case, count=count, paired_stream=paired_stream, original=str((originals / f'original-{count}.json').resolve(strict=True))))
    boundary = callbacks.BOUNDARY
    first = boundary.index('struct IOSSessionIdentity:')
    last = boundary.index('let boundaryTransport=', first)
    boundary = boundary[:first] + (callbacks.ROOT/'ios/RouterVPN/App/IOSSessionIdentity.swift').read_text() + '\n' + boundary[last:]
    boundary = boundary.replace(' ? boundaryTransport:"shadowsocks")', ' ? boundaryTransport:"shadowsocks",id:originalIDs[$0])')
    start = boundary.index('struct OrdinaryCapture{')
    end = boundary.index('struct ExecutionCapture{', start)
    boundary = boundary[:start] + BOUNDARY + boundary[end:]
    boundary = boundary.replace('func extendedLocalRolesJSON()->String{""}', 'func extendedLocalRolesJSON()->String{String(decoding:try! JSONEncoder().encode(nativeRoles),as:UTF8.self)}')
    boundary = boundary.replace('func extendedLocalNodeCount()->Int32{0}', 'func extendedLocalNodeCount()->Int32{Int32(nativeCount)}')
    boundary = boundary.replace('var connected=true,activeSessionIdentity:IOSSessionIdentity?=IOSSessionIdentity(nodeChainSource:Data("captured-source".utf8),connectedAt:Date(timeIntervalSince1970:1))','var connected=true,activeSessionIdentity:IOSSessionIdentity?')
    boundary = boundary.replace('return boundaryTransport == "socks5" ? .socks(SOCKSCapture()):.connect(CONNECTCapture())','return .ordinary(OrdinaryCapture())')
    boundary = boundary.replace('["node_kind":(id=="middle" || id.hasPrefix("custom-")) ? "external":"router-vpn"]','["node_kind":originalPublicIDs.contains(id) ? "external":"router-vpn"]')
    boundary = boundary.replace('static var ids:[String]{multiple ? ["entry","custom-1","paired","custom-3","final"]:["entry","middle","final"]}', 'static var ids:[String]{originalIDs}')
    with tempfile.TemporaryDirectory(prefix='ios-real-extended-fifty-') as tmp:
        folder = Path(tmp)
        source = folder/'Fixture.swift'
        source.write_text(callbacks.C.BOUNDARY.split('func request(')[0]+boundary+callbacks.sources()+TESTS)
        binary = folder/'fixture'
        subprocess.run(['swiftc','-j','1','-swift-version','6','-parse-as-library','-module-cache-path',str(folder/'modules'),str(source),'-o',str(binary)],check=True,timeout=90)
        raw = folder/'receipts.json'
        raw.write_text(json.dumps(fixture))
        subprocess.run([str(binary),str(raw)],check=True,timeout=60)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--originals', required=True, type=Path)
    parser.add_argument('--receipt-log', required=True, type=Path)
    parser.add_argument('--paired-stream', action='store_true', help='Replay the nine-member Local run with independent imported and private stream owners.')
    args = parser.parse_args()
    run(args.originals, args.receipt_log.read_text(), paired_stream=args.paired_stream)
