#!/usr/bin/env python3
"""Compose actual CONNECT50 capture with schema4 source compiler, presentation and session identity."""
from pathlib import Path
import importlib.util,platform,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1];APP=ROOT/'ios/RouterVPN/App'
spec=importlib.util.spec_from_file_location('connect_capture',ROOT/'deploy/test_ios_node_chain_connect_capture.py');S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
BOUNDARY=r'''
@MainActor final class RouterVPNModel{
 var iosCandidateTesting=false
 var allNodeProfiles:[RouterProfile]{nodes.flatMap{ $0.routerProfiles }}
 var selectedNodeProfile:RouterProfile?{bundle.routerProfiles.first{ $0.id==bundle.selectedRouterID }}
 var nodes:[ClientBundle],bundle:ClientBundle,connected=true,activeSessionIdentity:IOSSessionIdentity?,iosConnectGeneration=UUID(),selectedMode="multihop",selectedLogicalMode="multihop",auto=false
 init(_ nodes:[ClientBundle],identity:IOSSessionIdentity){self.nodes=nodes;bundle=nodes.last!;activeSessionIdentity=identity}
 func iosNodeChainBundles(for bundle:ClientBundle)throws->[ClientBundle]{nodes}
 nonisolated static func iosStrategyDigest(_ data:Data)->String{let h=data.reduce(UInt64(14695981039346656037)){($0 ^ UInt64($1)) &* 1099511628211};return String(repeating:String(format:"%016llx",h),count:4)}
 // ORIGINAL_CAPTURE
}
'''
CASES=r'''
   let realNodes=try bundles.map{try JSONDecoder().decode(ClientBundle.self,from:$0)}
   let identity=try IOSSessionIdentity(connectedAt:Date(timeIntervalSince1970:1),engine:"multihop-libbox",rawProfile:"shadowsocks",bundleData:bundles[2],configuration:["nodeChainCONNECTSource":capture.source])
   let model=RouterVPNModel(realNodes,identity:identity),fifty=try IOSOrderedLatencyCapture(model)
   try check("fifty exact source/config/member capture",fifty.source==capture.plan.sourceSHA256() && fifty.config==capture.plan.configSHA256() && fifty.ids==capture.members.map(\.id))
   try fifty.require(model)
   model.nodes[1].routerProfiles[0].name="edited private saved record"
   try reject("fifty complete source change"){try fifty.require(model)}
   try reject("fifty initial current source"){_ = try IOSOrderedLatencyCapture(model)}
   model.nodes=realNodes;model.iosConnectGeneration=UUID()
   try reject("fifty original app generation"){try fifty.require(model)}
   model.iosConnectGeneration=fifty.selection;model.connected=false
   try reject("fifty disconnected owner"){try fifty.require(model)}
'''
def member(text,anchor):
    start=text.index(anchor);brace=text.index('{',start);depth=1;end=brace+1
    while depth:
        if text[end]=='{':depth+=1
        elif text[end]=='}':depth-=1
        end+=1
    return text[start:end]
def main():
    tests=S.CONNECT_SWIFT.replace('try run();print("Apple ordered native capture: PASS (\\(checks) shipping Swift / shared Go checks; no native connection)")','try connectMiddle();print("iOS CONNECT fifty actual capture: PASS (\\(checks) shared-parser and shipping capture checks)")',1)
    anchor='   let source=try object(Data(capture.source.utf8)),graph=try object(Data(capture.config.utf8))'
    assert S.CONNECT_CASES.count(anchor)==1 and tests.count(S.CONNECT_CASES)==1
    tests=tests.replace(S.CONNECT_CASES,S.CONNECT_CASES.replace(anchor,CASES+anchor))
    launch=(APP/'IOSNodeChainLaunch.swift').read_text();enum=launch.split('@MainActor\nextension RouterVPNModel')[0]
    model=BOUNDARY.replace('// ORIGINAL_CAPTURE',member(launch,'    func captureIOSOrderedRoute('))
    app=(APP/'IOSOrderedLatency.swift').read_text().split('private final class IOSOrderedLatencyReply')[0].replace('import Combine\n','').replace('@preconcurrency import NetworkExtension\n','')
    with tempfile.TemporaryDirectory(prefix='.ios-connect-fifty-capture-',dir=ROOT) as g,tempfile.TemporaryDirectory(prefix='ios-connect-fifty-capture-') as d:
        g,d=Path(g),Path(d);(g/'main.go').write_text(S.C.GO);compiler=d/'compiler';subprocess.run(['go','build','-p','1','-o',str(compiler),str(g/'main.go')],cwd=ROOT,check=True,timeout=180)
        lib=d/'Libbox.swift';lib.write_text(S.C.LIBBOX);library=d/('libLibbox.dylib' if platform.system()=='Darwin' else 'libLibbox.so');options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(d/'modules')]
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(lib),'-emit-module-path',str(d/'Libbox.swiftmodule'),'-o',str(library)],check=True,timeout=90)
        code=d/'Tests.swift';code.write_text(tests);fixture=d/'Capture.swift';binary=d/'tests';command=options+['-I',str(d),'-L',str(d),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(d)]
        command += [str(APP/x) for x in ['Models.swift','IOSMultihopStartLayer.swift','IOSNodeChainCapture.swift','IOSNodeChainProviderCapture.swift','IOSNodeChainSOCKSCapture.swift','IOSNodeChainCONNECTCapture.swift','IOSSessionIdentity.swift','IOSNodeChainPresentation.swift']]
        def run(value):
            fixture.write_text(enum+model+value);subprocess.run(command+[str(fixture),str(code),'-o',str(binary)],check=True,timeout=90)
            return subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
        result=run(app);assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip(),flush=True)
        for name,before,after,count,witness in [
            ('compiled-source','Data(original.source.utf8) == active','true',2,'ACCEPTED fifty initial current source'),
            ('complete-profile','try Self.bytes(model) == snapshot','!snapshot.isEmpty',1,'ACCEPTED fifty complete source change'),
            ('app-generation','model.iosConnectGeneration == selection','true',1,'ACCEPTED fifty original app generation'),
        ]:
            assert app.count(before)==count,name
            result=run(app.replace(before,after));assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,result.stdout+result.stderr)
            print('Rejected CONNECT fifty capture control: '+name,flush=True)
if __name__=='__main__':main()
