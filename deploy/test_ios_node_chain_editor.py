#!/usr/bin/env python3
"""Execute Apple ordered editor callbacks and real shared graph admission.

The production draft, save/owner callbacks, linked-node selection and native
compiler are unchanged. Private persistence and DNS preparation are explicit
boundaries; this test does not simulate tunnel readiness or device UI events.
The normal Xcode app target separately compiles the actual SwiftUI view.
"""
from pathlib import Path
import argparse
import importlib.util
import platform
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'ios/RouterVPN/App'
spec = importlib.util.spec_from_file_location('ordered_editor_launch', ROOT / 'deploy/test_ios_node_chain_launch.py')
L = importlib.util.module_from_spec(spec); spec.loader.exec_module(L)
C, S = L.C, L.S

GO = C.GO.replace(' case "chain-fixture":', ''' case "editor-digest":
  var raw []byte;raw,err=base64.StdEncoding.DecodeString(r.Source);if err==nil{sum:=sha256.Sum256(raw);value=hex.EncodeToString(sum[:])}
 case "chain-fixture":''', 1)
LIBBOX = C.LIBBOX + r'''
public func LibboxEditorDigest(_ data:Data)throws->String{try bridge(["Op":"editor-digest","Source":data.base64EncodedString()])}
'''

BOUNDARIES = r'''
import Foundation
import Libbox
// SHIPPING_SELECTION_TYPES
enum IOSRuntimeSelector {}
@MainActor enum IOSDNSRuntimePolicy {
 static var beforePatch:(()throws->Void)?
 // SHIPPING_SELECTED_PROFILE
 static func patch(_ value:ClientBundle)throws->ClientBundle {
  let callback=beforePatch;beforePatch=nil;try callback?();return value
 }
}
@MainActor final class IOSNodeBundleStore {
 static let shared=IOSNodeBundleStore()
 var records:[String:Data]=[:]
 func bundleData(containing id:String,current:ClientBundle?)->Data? {
  if let current,current.routerProfiles.contains(where:{$0.id==id}) {return try? JSONEncoder().encode(current)}
  return records[id]
 }
 func profiles(current:ClientBundle?)->[RouterProfile] {
  var result:[String:RouterProfile]=[:]
  for data in records.values {if let value=try? JSONDecoder().decode(ClientBundle.self,from:data){for profile in value.routerProfiles{result[profile.id]=profile}}}
  for profile in current?.routerProfiles ?? []{result[profile.id]=profile}
  return result.values.sorted{$0.id<$1.id}
 }
}
@MainActor final class RouterVPNModel {
 var bundle:ClientBundle?,profileMutationBlocked=false,message="",writes=0,attempts=0,failWrite=false
 let iosSpeedLabOwnership=IOSSpeedLabOwnership()
 var selectedNodeProfile:RouterProfile? {bundle.flatMap{IOSDNSRuntimePolicy.selectedProfile(in:$0)}}
 var allNodeProfiles:[RouterProfile]{IOSNodeBundleStore.shared.profiles(current:bundle)}
 static func iosStrategyDigest(_ data:Data)->String{try! LibboxEditorDigest(data)}
 func commitLinkedNodeBundle(_ data:Data)throws {
  attempts+=1;if failWrite{throw IOSMultihopNodeSelection.issue("persistence boundary refused commit")}
  let value=try JSONDecoder().decode(ClientBundle.self,from:data)
  IOSNodeBundleStore.shared.records[value.selectedRouterID]=data;bundle=value;writes+=1
 }
 // SHIPPING_LINK
 // SHIPPING_CHAIN_BUNDLES
}
'''

TESTS = r'''
@MainActor @main struct Tests {
 static var checks=0
 static func check(_ name:String,_ ok:@autoclosure ()throws->Bool)throws {
  guard try ok()else{throw IOSMultihopNodeSelection.issue("FAIL "+name)};checks+=1
 }
 static func reject(_ name:String,_ body:()throws->Void)throws {
  do{try body()}catch{checks+=1;return};throw IOSMultihopNodeSelection.issue("ACCEPTED "+name)
 }
 // ORIGINAL_COMPILER_SOURCES
 static func setup(_ count:Int=3,_ mixed:Bool=false,_ hysteriaPrefix:String="")throws->RouterVPNModel {
  IOSNodeBundleStore.shared.records=[:];IOSDNSRuntimePolicy.beforePatch=nil
  let nodes=try sources(count,mixed,hysteriaPrefix),model=RouterVPNModel();model.bundle=nodes.last!
  for node in nodes{IOSNodeBundleStore.shared.records[node.selectedRouterID]=try JSONEncoder().encode(node)}
  return model
 }
 static func editMiddle(_ action:(inout ClientBundle)->Void)throws {
  let id="chain-node-1"
  var value=try JSONDecoder().decode(ClientBundle.self,from:IOSNodeBundleStore.shared.records[id]!)
  action(&value);IOSNodeBundleStore.shared.records[id]=try JSONEncoder().encode(value)
 }
 static func main() {
  defer{LibboxTestClose()}
  do{try run();print("Apple ordered editor: PASS (\(checks) shipping Swift/shared Go checks; persistence boundary)")}
  catch{FileHandle.standardError.write(Data((error.localizedDescription+"\n").utf8));exit(1)}
 }
 static func run()throws {
  try runOriginal()
  for mode in ["wg","awg2-fast","awg2-strong"] {
   let model=try setup(3,false,mode),owner=try model.captureIOSNodeChainEditorOwner()
   var draft=IOSNodeChainDraft(saved:model.selectedNodeProfile!.multihopNodes,finalID:owner.controlID)
   try check("HY2 editor retains selected final and complete paired prefix",draft.canSave && draft.nodes.last?.mode=="hysteria2" && draft.nodes.first?.mode==mode)
   try draft.chooseFinalMode("shadowsocks");try draft.chooseFinalMode("hysteria2")
   try model.saveIOSNodeChain(draft.nodes,owner:owner)
   let captured=try model.captureIOSNodeChain(model.bundle!);defer{try? captured.plan.close()}
   try check("HY2 editor commits exact original transport",model.writes==1 && captured.members.last?.mode=="hysteria2" && captured.members.last?.id==owner.controlID)
   let stale=try model.captureIOSNodeChainEditorOwner()
   model.bundle!.profiles["hysteria2"]!["hy2-ca.pem"]=Data("changed original CA".utf8).base64EncodedString()
   try reject("HY2 editor changed original CA"){try model.saveIOSNodeChain(draft.nodes,owner:stale)}
  }
  var importedDraft=IOSNodeChainDraft(saved:[.init(id:"entry",mode:"wg"),.init(id:"custom",mode:"shadowsocks"),.init(id:"final",mode:"shadowsocks")],finalID:"final")
  try reject("HY2 final cannot adopt imported middle"){try importedDraft.chooseFinalMode("hysteria2")}
  for mode in ["wg","naive-h3","Hysteria2",""] {try reject("unsupported final chooser "+mode){try importedDraft.chooseFinalMode(mode)}}
 }
 static func runOriginal()throws {
  var draft=IOSNodeChainDraft(finalID:"final")
  try check("new draft pins independently selected final",draft.nodes==[.init(id:"",mode:"wg"),.init(id:"final",mode:"shadowsocks")] && !draft.canSave)
  try draft.choose("entry",at:0)
  try check("two-node draft is complete",draft.canSave)
  for mode in ["awg2-fast","awg2-strong","wg"] {
   try draft.chooseMode(mode,at:0)
   try check("editor preserves exact selected packet transport "+mode,draft.canSave && draft.nodes[0].mode==mode && draft.nodes[0].id=="entry")
  }
  for mode in ["awg","awg2-pq","wg-pq","shadowsocks",""] {
   try reject("unsupported ordered prefix transport "+mode){try draft.chooseMode(mode,at:0)}
  }
  try reject("transport change cannot replace final"){try draft.chooseMode("awg2-fast",at:1)}
  try reject("changing pinned final"){try draft.choose("replacement",at:1)}
  try reject("using final as prefix"){try draft.choose("final",at:0)}
  try reject("removing final"){try draft.remove(at:1)}
  try reject("moving final"){try draft.move(from:1,to:0)}
  try reject("moving prefix into final"){try draft.move(from:0,to:1)}
  try reject("removing minimum prefix"){try draft.remove(at:0)}
  for position in 1...6 {
   try draft.append()
   try check("append preserves pinned final \(position)",draft.nodes.last == .init(id:"final",mode:"shadowsocks") && draft.nodes[position].mode=="wg" && !draft.canSave)
   try draft.choose("middle-\(position)",at:position)
  }
  try check("eight-node draft keeps every explicit prefix",draft.canSave && draft.nodes.count==8)
  try reject("ninth node"){try draft.append()}
  try reject("duplicate middle"){try draft.choose("entry",at:2)}
  try reject("out-of-bounds selection"){try draft.choose("other",at:8)}
  try draft.move(from:2,to:0)
  try check("reorder preserves all exact transports",draft.nodes[0].id=="middle-2" && draft.nodes.dropLast().allSatisfy{$0.mode=="wg"} && draft.nodes.last?.id=="final")
  try draft.remove(at:1)
  try check("remove preserves original final",draft.nodes.count==7 && draft.nodes.last?.id=="final")
  for bad in ["bad/id", " id",String(repeating:"x",count:65)] {
   var invalid=IOSNodeChainDraft(finalID:"final");try invalid.choose(bad,at:0)
   try check("invalid reference cannot enable Save",!invalid.canSave)
  }
  let changed=IOSNodeChainDraft(saved:[.init(id:"entry",mode:"wg"),.init(id:"other",mode:"shadowsocks")],finalID:"final")
  try check("saved wrong final stays invalid",!changed.canSave)
  let wrongMode=IOSNodeChainDraft(saved:[.init(id:"entry",mode:"hysteria2"),.init(id:"final",mode:"shadowsocks")],finalID:"final")
  try check("saved transport is not silently rewritten",!wrongMode.canSave && wrongMode.nodes[0].mode=="hysteria2")

  do {
   let model=try setup(4,true),owner=try model.captureIOSNodeChainEditorOwner(),nodes=model.selectedNodeProfile!.multihopNodes!
   try model.saveIOSNodeChain(nodes,owner:owner)
   let capture=try model.captureIOSNodeChain(model.bundle!);defer{try? capture.plan.close()}
   try check("editor saves complete mixed AWG source without replacing raw variants",model.writes==1 && capture.members.map(\.mode)==["awg2-fast","awg2-strong","wg","shadowsocks"])
   let changedOwner=try model.captureIOSNodeChainEditorOwner()
   try editMiddle{$0.profiles["awg2-strong"]!["awg.conf"]=Data("relinked selected AWG source".utf8).base64EncodedString()}
   try reject("AWG editor cannot reuse relinked selected raw source"){try model.saveIOSNodeChain(nodes,owner:changedOwner)}
   try check("relinked AWG refusal performs no extra write",model.writes==1)
  }

  for count in [2,3,4,8] {
   let model=try setup(count),original=model.bundle!,nodes=model.selectedNodeProfile!.multihopNodes!,records=IOSNodeBundleStore.shared.records
   let owner=try model.captureIOSNodeChainEditorOwner()
   try check("owner captures selected control and every original record",owner.controlID==original.selectedRouterID && owner.fingerprints.count==count && owner.fingerprints.values.allSatisfy{$0.count==64})
   try model.saveIOSNodeChain(nodes,owner:owner)
   let saved=model.selectedNodeProfile!
   try check("one durable boundary receives complete order",model.writes==1 && model.attempts==1 && saved.multihopNodes==nodes && model.bundle!.selectedRouterID==owner.controlID)
   try check("one Local graph replaces legacy pair fields",saved.multihopEnabled==true && saved.multihopExecution=="local" && saved.multihopEntryID==nil && saved.multihopEntryMode==nil && saved.multihopExitID==nil && saved.multihopExitMode==nil)
   try check("final credentials raw assets and DNS stay original",saved.apiToken==original.routerProfiles[0].apiToken && saved.nodeProofID==original.routerProfiles[0].nodeProofID && model.bundle!.profiles==original.profiles && saved.dnsMode==original.routerProfiles[0].dnsMode && saved.adGuardIPv4==original.routerProfiles[0].adGuardIPv4)
   try check("all prefix private records stay separate",records.filter{$0.key != owner.controlID}==IOSNodeBundleStore.shared.records.filter{$0.key != owner.controlID})
   try check("success text contains no private credential",!model.message.contains(original.routerProfiles[0].apiToken))
  }
  do {
   let model=try setup(4)
   try editMiddle{$0.routerProfiles[0].mtuPolicy="fixed";$0.routerProfiles[0].manualMTU=1408}
   let owner=try model.captureIOSNodeChainEditorOwner(),nodes=model.selectedNodeProfile!.multihopNodes!
   try model.saveIOSNodeChain(nodes,owner:owner)
   let capture=try model.captureIOSNodeChain(model.bundle!);defer{try? capture.plan.close()}
   try check("fixed middle is preserved with final Auto",capture.members[1].profile["manual_mtu"] as? Int==1408 && capture.finalProfile["mtu_policy"] as? String=="auto" && model.writes==1)
  }
  for fault in ["middle-token","middle-assets","middle-policy","middle-removed","final-token","selected-final","busy","temporary-test"] {
   let model=try setup(),owner=try model.captureIOSNodeChainEditorOwner(),nodes=model.selectedNodeProfile!.multihopNodes!
   switch fault {
   case "middle-token":try editMiddle{$0.routerProfiles[0].apiToken="new-private-middle-token"}
   case "middle-assets":try editMiddle{let file=$0.profiles["wg"]!["wg.conf"]!;$0.profiles["wg"]!["wg.conf"]=Data((String(decoding:Data(base64Encoded:file)!,as:UTF8.self)+"\n").utf8).base64EncodedString()}
   case "middle-policy":try editMiddle{$0.routerProfiles[0].homeLANAccess=true}
   case "middle-removed":IOSNodeBundleStore.shared.records.removeValue(forKey:"chain-node-1")
   case "final-token":model.bundle!.routerProfiles[0].apiToken="new-final-private-token"
   case "selected-final":model.bundle=try JSONDecoder().decode(ClientBundle.self,from:IOSNodeBundleStore.shared.records["chain-node-0"]!)
   case "busy":model.profileMutationBlocked=true
   case "temporary-test":_ = try model.iosSpeedLabOwnership.begin(onSuperseded:{})
   default:fatalError()
   }
   let encoder=JSONEncoder();encoder.outputFormatting=[.sortedKeys]
   let before=IOSNodeBundleStore.shared.records,current=try encoder.encode(model.bundle)
   try reject("stale editor "+fault){try model.saveIOSNodeChain(nodes,owner:owner)}
   try check("stale editor preserves replacement sources "+fault,model.attempts==0 && IOSNodeBundleStore.shared.records==before && (try encoder.encode(model.bundle))==current)
  }
  for fault in ["middle-token","middle-removed","selected-final","busy"] {
   let model=try setup(),owner=try model.captureIOSNodeChainEditorOwner(),nodes=model.selectedNodeProfile!.multihopNodes!
   IOSDNSRuntimePolicy.beforePatch={
    switch fault {
    case "middle-token":try editMiddle{$0.routerProfiles[0].apiToken="changed-during-compile-preparation"}
    case "middle-removed":IOSNodeBundleStore.shared.records.removeValue(forKey:"chain-node-1")
    case "selected-final":model.bundle=try JSONDecoder().decode(ClientBundle.self,from:IOSNodeBundleStore.shared.records["chain-node-0"]!)
    case "busy":model.profileMutationBlocked=true
    default:fatalError()
    }
   }
   try reject("source changed during compile preparation "+fault){try model.saveIOSNodeChain(nodes,owner:owner)}
   try check("late preparation cannot reach publication "+fault,model.attempts==0)
  }
  for fault in ["duplicate","wrong-final","prefix-mode","final-mode","bad-assets","failed-write"] {
   let model=try setup();var nodes=model.selectedNodeProfile!.multihopNodes!
   if fault=="bad-assets" {try editMiddle{$0.profiles["wg"]!["wg.conf"]="malformed-not-base64"}}
   let owner=try model.captureIOSNodeChainEditorOwner(),before=IOSNodeBundleStore.shared.records
   switch fault {
   case "duplicate":nodes[1].id=nodes[0].id
   case "wrong-final":nodes.swapAt(0,2)
   case "prefix-mode":nodes[0].mode="hysteria2"
   case "final-mode":nodes[2].mode="wg"
   case "failed-write":model.failWrite=true
   default:break
   }
   try reject("invalid draft "+fault){try model.saveIOSNodeChain(nodes,owner:owner)}
   try check("failure leaves exact original private records "+fault,model.writes==0 && IOSNodeBundleStore.shared.records==before)
  }
 }
}
'''


def main(selected_mutations=None):
    runtime = (APP / 'IOSRuntimeSelection.swift').read_text()
    body = BOUNDARIES.replace('// SHIPPING_SELECTION_TYPES', runtime[runtime.index('enum IOSRuntimeEngine'):runtime.index('enum IOSRuntimeSelectionError')])
    body = body.replace('// SHIPPING_SELECTED_PROFILE', S.member((APP / 'IOSDNSRuntimePolicy.swift').read_text(), '    static func selectedProfile('))
    body = body.replace('// SHIPPING_LINK', S.member((APP / 'RouterVPNModelExternal.swift').read_text(), '    func linkNodeBundle('))
    body = body.replace('// SHIPPING_CHAIN_BUNDLES', S.member((APP / 'IOSMultihopView.swift').read_text(), '    func iosNodeChainBundles('))
    tests = TESTS.replace('// ORIGINAL_COMPILER_SOURCES', S.member(L.TESTS, ' static func sources('))
    editor = (APP / 'IOSNodeChainEditor.swift').read_text()
    view = (APP / 'IOSNodeChainEditorView.swift').read_text()
    # These callbacks are the same operations executed below; the App source
    # directory is included by the real Xcode project, including this view.
    for call in ('draft.choose(id, at: position)', 'draft.move(from: position, to: position - 1)',
                 'draft.move(from: position, to: position + 1)', 'draft.remove(at: position)',
                 'draft.append()', 'draft.chooseFinalMode(mode)', 'draft.chooseMode(mode, at: position)', 'model.saveIOSNodeChain(draft.nodes, owner: owner)',
                 'model.captureIOSNodeChainEditorOwner()'):
        assert call in view, 'shipping editor callback removed: ' + call
    with tempfile.TemporaryDirectory(prefix='.ios-chain-editor-', dir=ROOT) as go_dir, tempfile.TemporaryDirectory(prefix='ios-chain-editor-') as directory:
        go_dir, work = Path(go_dir), Path(directory)
        (go_dir / 'main.go').write_text(GO)
        compiler = work / 'compiler'
        subprocess.run(['go', 'build', '-p', '1', '-o', str(compiler), str(go_dir / 'main.go')], cwd=ROOT, check=True, timeout=180)
        lib = work / 'Libbox.swift'; lib.write_text(LIBBOX)
        code = work / 'Tests.swift'; code.write_text(body + tests)
        shipping = work / 'IOSNodeChainEditor.swift'; shipping.write_text(editor)
        options = ['swiftc', '-j', '1', '-swift-version', '6', '-module-cache-path', str(work / 'modules')]
        library = work / ('libLibbox.dylib' if platform.system() == 'Darwin' else 'libLibbox.so')
        subprocess.run(options + ['-emit-module', '-emit-library', '-module-name', 'Libbox', str(lib), '-emit-module-path', str(work / 'Libbox.swiftmodule'), '-o', str(library)], check=True, timeout=90)
        command = options + ['-I', str(work), '-L', str(work), '-lLibbox', '-Xlinker', '-rpath', '-Xlinker', str(work)]
        command += [str(APP / name) for name in ('Models.swift', 'IOSSpeedLabOwnership.swift', 'IOSMultihopStartLayer.swift', 'IOSNodeChainCapture.swift', 'IOSNodeChainLaunch.swift')]
        binary = work / 'tests'
        command += [str(shipping), str(code), '-o', str(binary)]
        subprocess.run(command, check=True, timeout=120)
        subprocess.run([str(binary), str(compiler)], check=True, timeout=180)
        late = '        try requireIOSNodeChainEditorOwner(owner, nodes: nodes)'
        compile_source = '        let capture = try captureIOSNodeChain(value)\n        defer { try? capture.plan.close() }\n        _ = try IOSRuntimeSelector.selectNodeChain(capture)'
        mutants = (
            ('hysteria-final-scope', editor.replace('mode == "shadowsocks" || nodes.dropLast().allSatisfy(', 'true || nodes.dropLast().allSatisfy(', 1), 'ACCEPTED HY2 final cannot adopt imported middle'),
            ('pinned-final', editor.replace('position < nodes.count - 1,\n              id.isEmpty', 'position < nodes.count,\n              id.isEmpty', 1), 'ACCEPTED changing pinned final'),
            ('original-fingerprints', editor.replace('try iosNodeChainEditorFingerprint(node.id) == expected', '!expected.isEmpty', 1), 'ACCEPTED stale editor middle-token'),
            ('late-source-owner', editor[:editor.rindex(late)] + editor[editor.rindex(late):].replace(late, '        // Lost final editor ownership check', 1), 'ACCEPTED source changed during compile preparation middle-token'),
            ('compile-before-save', editor.replace(compile_source, '        _ = value', 1), 'ACCEPTED invalid draft prefix-mode'),
        )
        for name, changed, failure in mutants:
            if selected_mutations and name not in selected_mutations:
                continue
            assert changed != editor, name + ' mutation missing'
            shipping.write_text(changed)
            subprocess.run(command, check=True, timeout=120)
            rejected = subprocess.run([str(binary), str(compiler)], capture_output=True, text=True, timeout=180)
            assert rejected.returncode != 0 and failure in rejected.stdout + rejected.stderr, name + ': no causal rejection: ' + (rejected.stdout + rejected.stderr)[-1800:]
            print('Rejected ordered editor defect mutation: ' + name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mutation', action='append', choices=['hysteria-final-scope', 'pinned-final', 'original-fingerprints', 'late-source-owner', 'compile-before-save'])
    main(parser.parse_args().mutation)
