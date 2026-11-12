#!/usr/bin/env python3
"""Execute actual Apple execution provider capture and startup handoffs.

Capture uses the real shared Go compiler; provider/native callbacks use explicit
boundaries. Actual Apple framework, relay and device evidence remain separate.
"""
from pathlib import Path
import importlib.util
import os
import platform
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App';TUN=ROOT/'ios/RouterVPN/PacketTunnel'
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
SOURCE=module('execution_source_fixture',ROOT/'deploy/test_ios_node_chain_execution_capture.py')
PROVIDER=module('ordered_provider_fixture',ROOT/'deploy/test_ios_node_chain_provider.py')
CAPTURE_TESTS=SOURCE.SWIFT.split('@main struct Tests {',1)[0]+r'''
@main struct Tests {
 @MainActor static var checks=0
 @MainActor static func check(_ yes:Bool,_ name:String){guard yes else{fatalError(name)};checks+=1}
 @MainActor static func reject(_ name:String,_ action:()throws->Void){do{try action();fatalError("ACCEPTED "+name)}catch{checks+=1}}
 @MainActor static func main()throws{
  defer{LibboxTestClose()}
  for count in [2,3,8]{for requested in ["server","auto"]{for awg in [false,true]{
   let bundles=try fixture(count,"off",requested,awg),capture=try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:requested)
   let final=capture.members.last!
   let provider:[String:Any]=["engine":"multihop-libbox",IOSNodeChainProviderCapture.executionKey:capture.launchInput,
      "bundle":bundles.last!,"mode":final.mode,"rawProfileID":final.mode,"modeCandidates":[final.mode]]
   check(IOSNodeChainProviderCapture.requested(provider,profile:[:]),"execution provider dispatch was not explicit")
   let reopened=try IOSNodeChainProviderCapture.reopenExecution(provider)
   check(reopened.source==capture.source && reopened.config==capture.config && reopened.requested==requested && reopened.members.count==count,"provider source changed after native reopen")
   try reopened.close()
   reject("execution source reused Local provider"){_ = try IOSNodeChainProviderCapture.reopen(provider)}
   for field in ["engine","mode","rawProfileID","modeCandidates","entryBundle","external_entry_bundle","external_entry_mode","tor_entry_bundle","tor_entry_mode","strategy","strategy_catalog","max_source_sha256",IOSNodeChainProviderCapture.key]{
    var changed=provider;changed[field]=field=="modeCandidates" ? ["wg"]:"foreign"
    reject("provider "+field){_ = try IOSNodeChainProviderCapture.reopenExecution(changed)}
   }
   for field in ["selection","duplicate","assets","control"]{
    var changed=provider
    changed["bundle"]=try edit(bundles.last!){root in
     if field=="selection"{root["selectedRouterID"]="foreign"}
     if field=="duplicate"{let ps=root["routerProfiles"] as! [[String:Any]];root["routerProfiles"]=ps+ps}
     if field=="assets"{var assets=root["profiles"] as! [String:[String:String]];var files=assets[final.mode]!;files["changed.conf"]="Zm9yZWlnbg==";assets[final.mode]=files;root["profiles"]=assets}
     if field=="control"{var ps=root["routerProfiles"] as! [[String:Any]];ps[0]["api_token"]="changed-token";root["routerProfiles"]=ps}
    }
    reject("provider "+field){_ = try IOSNodeChainProviderCapture.reopenExecution(changed)}
   }
   try capture.close()
  }}}
  print("PASS Apple execution provider original capture: \(checks) real compiler checks")
 }
}
'''

def source_gate(work):
    with tempfile.TemporaryDirectory(prefix='.ios-execution-provider-',dir=ROOT) as gd:
        gd=Path(gd);(gd/'main.go').write_text(SOURCE.GO);compiler=work/'compiler'
        subprocess.run(['go','build','-p','1','-o',str(compiler),str(gd/'main.go')],cwd=ROOT,check=True,timeout=180)
        (work/'Libbox.swift').write_text(SOURCE.LIBBOX);(work/'CryptoKit.swift').write_text(SOURCE.CRYPTO);(work/'Tests.swift').write_text(CAPTURE_TESTS)
        options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
        suffix='.dylib' if platform.system()=='Darwin' else '.so'
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(work/'Libbox.swift'),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(work/('libLibbox'+suffix))],check=True,timeout=90)
        link=['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
        subprocess.run(options+link+['-emit-module','-emit-library','-module-name','CryptoKit',str(work/'CryptoKit.swift'),'-emit-module-path',str(work/'CryptoKit.swiftmodule'),'-o',str(work/('libCryptoKit'+suffix))],check=True,timeout=90)
        command=options+link+['-lCryptoKit']+[str(APP/name) for name in ['Models.swift','IOSMultihopStartLayer.swift','IOSNodeChainCapture.swift','IOSNodeChainExecutionCapture.swift','IOSNodeChainProviderCapture.swift']]
        source=TUN/'IOSNodeChainExecutionProviderCapture.swift';tests=work/'Tests.swift';binary=work/'capture'
        subprocess.run(command+[str(source),str(tests),'-o',str(binary)],check=True,timeout=90)
        subprocess.run([str(binary),str(compiler)],check=True,timeout=180)
        text=source.read_text()
        for name,before,after,witness in (
          ('dual-source','guard configuration[key] == nil,','guard true,','ACCEPTED provider nodeChainSource'),
          ('selected-assets','selectedFiles == originalFiles else {','!originalFiles.isEmpty else {','ACCEPTED provider assets'),
          ('mode-candidates','configuration["modeCandidates"] as? [String] == [final.mode],','true,','ACCEPTED provider modeCandidates'),
        ):
            assert text.count(before)==1,name
            mutant=work/(name+'.swift');mutant.write_text(text.replace(before,after,1));binary=work/name
            subprocess.run(command+[str(mutant),str(tests),'-o',str(binary)],check=True,timeout=90)
            result=subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
            assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,(result.stdout+result.stderr)[-1500:])
            print('Rejected provider capture control:',name)


def startup_gate(work):
    original=(TUN/'PacketTunnelProvider.swift').read_text()
    shipping='\n'.join(PROVIDER.member(original,s) for s in [
        '    private func startOrderedExecution(',
        '    override func stopTunnel(',
        '    private func finishNativeStop(',
        '    private func beginNodeChainStop(',
    ])
    swift=PROVIDER.SWIFT.replace('IOSNodeChainCapture','IOSNodeChainExecutionCapture')
    swift=swift.replace(' let plan=NativePlan(),strict=true,homeLANAccess=false',' let plan=NativePlan(),strict=true,homeLANAccess=false\n func close()throws{try plan.close()}')
    swift=swift.replace('func start(nodeChain plan:NativePlan,strict:Bool)throws','func start(nodeChainExecution capture:IOSNodeChainExecutionCapture)throws')
    swift=swift.replace('owned=true;self.plan=plan;', 'owned=true;self.plan=capture.plan;',1)
    swift=swift.replace('func completeNodeChainExecution','func completeOrderedExecution').replace('func activatePerformance()','func activateNodeChainExecutionPerformance()').replace('func activateNodeChainMTU()','func activateNodeChainExecutionMTU()')
    swift=swift.replace('try startNodeChain(capture,','try startOrderedExecution(capture,')
    swift=swift.replace(' // SHIPPING_PROVIDER',shipping.replace('IOSNodeChainCapture.issue','IOSNodeChainExecutionCapture.issue'))
    # Reuse original Local handoff cases unchanged except the actual new source
    # and method signatures; this executes the complete production method.
    source=work/'Provider.swift';binary=work/'provider';source.write_text(swift)
    command=['swiftc','-j','1','-swift-version','6','-parse-as-library','-module-cache-path',str(work/'modules'),str(TUN/'RouterVPNNodeChainStop.swift')]
    subprocess.run(command+[str(source),'-o',str(binary)],check=True,timeout=90)
    subprocess.run([str(binary)],check=True,timeout=30)
    for name,before,after,witness in (
      ('post-mtu-path','self.currentPathProofGuard() === chainGuard else {\n                engine.stop(); completionHandler(IOSNodeChainExecutionCapture.issue("The ordered path changed during native activation."))','true else {\n                engine.stop(); completionHandler(IOSNodeChainExecutionCapture.issue("The ordered path changed during native activation."))','failed or stale chain cannot release control credentials'),
      ('after-forwarding','self.currentPathProofGuard() === chainGuard else {\n                engine.stop(); completionHandler(IOSNodeChainExecutionCapture.issue("The ordered path changed before delivery."))','true else {\n                engine.stop(); completionHandler(IOSNodeChainExecutionCapture.issue("The ordered path changed before delivery."))','startup delivers only current full chain'),
    ):
        assert swift.count(before)==1,name
        source.write_text(swift.replace(before,after,1))
        subprocess.run(command+[str(source),'-o',str(binary)],check=True,timeout=90)
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
        assert result.returncode!=0 and witness in result.stdout+result.stderr,(name,(result.stdout+result.stderr)[-1500:])
        print('Rejected execution provider handoff control:',name)


def main():
    with tempfile.TemporaryDirectory(prefix='ios-execution-provider-') as directory:
        work=Path(directory);source_gate(work);startup_gate(work)
if __name__=='__main__':main()
