#!/usr/bin/env python3
"""Execute shipping Apple execution host/factory and latency ownership bodies.

Native handles/MTU/OS are explicit controlled boundaries, not device traffic.
"""
from pathlib import Path
import importlib.util
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
TUN=ROOT/'ios/RouterVPN/PacketTunnel'
spec=importlib.util.spec_from_file_location('original_execution_host',ROOT/'deploy/test_ios_node_chain_execution_host.py')
H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)
NATIVE=r'''
final class LatencyFixture:@unchecked Sendable{
 static let shared=LatencyFixture();var value:LibboxRouterOrderedLatency?,hook:(()->Void)?
}
final class LibboxRouterOrderedLatency{
 var closed=false,closeFailures=0,cancelled=false
 func start(_ request:String,nodeID:String)throws{guard !closed && !cancelled else{throw failure()}}
 func cancel(_ request:String){cancelled=true}
 func drain(_ request:String)throws{}
 func statusJSON()->String{"{}"}
 func savedJSON(_ node:String)->String{""}
 func close()throws{Trace.shared.add("latency-close");if closeFailures>0{closeFailures-=1;throw failure("latency join pending")};closed=true}
}
func LibboxRouterNodeChainExecutionNewLatencyBenchmark(_ plan:LibboxRouterNodeChainExecution,_ server:LibboxCommandServer,_ measurement:LibboxRouterHopMeasurement,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterOrderedLatency?{
 guard plan.owner?.server === server,plan.healthy(),!measurement.closed else{error?.pointee=failure();return nil}
 let value=LibboxRouterOrderedLatency();LatencyFixture.shared.value=value;LatencyFixture.shared.hook?();return value
}
func LibboxRouterValidatePrivateNodeJSON(_ raw:String,_ error:UnsafeMutablePointer<NSError?>?)->Bool{(try? JSONSerialization.jsonObject(with:Data(raw.utf8))) != nil}
final class CommandFactory:@unchecked Sendable{
 static let shared=CommandFactory();var typed=0,ordinary=0,fail=false,created:LibboxCommandServer?
}
func LibboxRouterNodeChainCONNECTExecutionNewCommandServer(_ plan:LibboxRouterNodeChainExecution,_ handler:RouterVPNLibboxPlatform,_ platform:RouterVPNLibboxPlatform,_ error:UnsafeMutablePointer<NSError?>?)->LibboxCommandServer?{
 CommandFactory.shared.typed+=1;let server=LibboxCommandServer();CommandFactory.shared.created=server
 if CommandFactory.shared.fail{error?.pointee=failure("factory failed after acquisition")};return server
}
func LibboxRouterNodeChainSOCKSExecutionNewCommandServer(_ plan:LibboxRouterNodeChainExecution,_ handler:RouterVPNLibboxPlatform,_ platform:RouterVPNLibboxPlatform,_ error:UnsafeMutablePointer<NSError?>?)->LibboxCommandServer?{
 error?.pointee=failure("ordinary CONNECT fixture cannot own a SOCKS execution");return nil
}
func LibboxRouterNodeChainOpenVPNExecutionNewCommandServer(_ plan:LibboxRouterNodeChainExecution,_ handler:RouterVPNLibboxPlatform,_ platform:RouterVPNLibboxPlatform,_ error:UnsafeMutablePointer<NSError?>?)->LibboxCommandServer?{
 error?.pointee=failure("ordinary CONNECT fixture cannot own an OpenVPN execution");return nil
}
func LibboxNewCommandServer(_ handler:RouterVPNLibboxPlatform,_ platform:RouterVPNLibboxPlatform,_ error:UnsafeMutablePointer<NSError?>?)->LibboxCommandServer?{CommandFactory.shared.ordinary+=1;return LibboxCommandServer()}
func error(_ text:String)->NSError{failure(text)}
final class RouterVPNLibboxEngine {
 let ownershipLock=NSLock();var starting=false,permanentlyStopped=false,ownershipGeneration=UUID(),settingsEpoch="original"
 var server:LibboxCommandServer?,nodeCandidatePrefix:NSObject?
 // Unrelated Local slots remain nil; only the actual execution host is built.
 var nodeChainSOCKS:RouterVPNNodeChainExecutionHost?,nodeChainCONNECT:RouterVPNNodeChainExecutionHost?,nodeChainDelivery:RouterVPNNodeChainExecutionHost?,nodeChainExecution:RouterVPNNodeChainExecutionHost?
}
// ACTUAL_IPC
// ACTUAL_FACTORY
'''
TESTS=r'''
@main struct Tests{
 static func check(_ good:Bool,_ message:String){if !good{FileHandle.standardError.write(Data(("FAIL "+message+"\n").utf8));exit(1)}}
 static func reject(_ message:String,_ run:()throws->Void){do{try run();check(false,"ACCEPTED "+message)}catch{}}
 static func request(_ id:Int,operation:String="ordered-latency-open",node:String="proxy",source:String=String(repeating:"a",count:64),lease:String=String(repeating:"c",count:32))->RouterVPNOrderedLatencyRequest{
  RouterVPNOrderedLatencyRequest(operation:operation,request:String(format:"%032x",id),session:"original",owner:"owner",lease:lease,source:source,config:String(repeating:"b",count:64),node:node)
 }
 static func started()throws->(RouterVPNNodeChainExecutionHost,LibboxCommandServer,RouterVPNLibboxPlatform){
  Factory.shared.reset();CommandFactory.shared.typed=0;CommandFactory.shared.ordinary=0;let capture=IOSNodeChainExecutionCapture();capture.isCONNECT=true
  let platform=RouterVPNLibboxPlatform(),host=RouterVPNNodeChainExecutionHost(capture:capture,platform:platform,isCurrent:{true},onFailure:{_ in})
  let server=try actualFactory(capture,host,platform);try host.startNative();host.finishConstruction()
  let result=Result();host.run(adoptMeasurement:{_,_ in true},completion:result.finish)
  check(result.wait() && result.values==[false],"original execution proof required")
  platform.mtu.latencyLease=String(repeating:"c",count:32);return(host,server,platform)
 }
 static func main()throws{
  do{
   let(host,server,_)=try started();let req=request(1)
   check(CommandFactory.shared.typed==1 && CommandFactory.shared.ordinary==0,"execution-owned factory required")
   let info=try host.latencyInfo(req,session:"original")
   let raw=try JSONSerialization.jsonObject(with:info!) as! [String:Any]
   check((raw["nodes"] as! [[String:Any]])[1]["kind"] as? String=="public-path","original imported measurement role")
   reject("foreign source"){_ = try host.latencyOpen(request(2,source:String(repeating:"d",count:64)))}
   reject("foreign lease"){_ = try host.latencyOpen(request(3,lease:String(repeating:"e",count:32)))}
   reject("foreign node"){_ = try host.latencyOpen(request(4,node:"other"))}
   let owner=try host.latencyOpen(req);check(RouterVPNOrderedLatencyRegistry.shared.find(req) === owner,"exact facade registry owner")
   let native=LatencyFixture.shared.value!;native.closeFailures=1
   reject("pending facade join"){try host.close()}
   check(server.boxCloses==0 && Factory.shared.probe?.closed==false,"latency facade must join before native measurement")
   try host.close();check(native.closed && server.released,"original facade and host joined retry")
  }
  do{
   let(host,server,_)=try started();LatencyFixture.shared.hook={host.cancel()}
   reject("late factory cancellation"){_ = try host.latencyOpen(request(5))}
   LatencyFixture.shared.hook=nil
   let native=LatencyFixture.shared.value!;try host.close()
   check(native.closed && server.released,"late original facade retained for close")
  }
  do{
   let capture=IOSNodeChainExecutionCapture();capture.isCONNECT=true;let platform=RouterVPNLibboxPlatform()
   let host=RouterVPNNodeChainExecutionHost(capture:capture,platform:platform,isCurrent:{true},onFailure:{_ in})
   CommandFactory.shared.fail=true
   reject("returned factory error"){_ = try actualFactory(capture,host,platform)}
   check(capture.server === CommandFactory.shared.created,"factory owner bound before error")
   host.finishConstruction();try host.close();check(CommandFactory.shared.created?.released==true,"failed factory original cleanup joined")
   CommandFactory.shared.fail=false
  }
  do{
   let(host,server,_)=try started(),engine=RouterVPNLibboxEngine();engine.server=server;engine.nodeChainExecution=host
   var info:Data?
   OrderedLatencyIPC(engine:engine,request:request(91,operation:"ordered-latency-info"),completion:{info=$0}).run()
   check(info != nil,"typed execution IPC reaches original latency host")
   engine.nodeChainCONNECT=host
   OrderedLatencyIPC(engine:engine,request:request(92,operation:"ordered-latency-info"),completion:{info=$0}).run()
   check(info==nil,"mixed Local execution IPC owner refused");engine.nodeChainCONNECT=nil
   LatencyFixture.shared.hook={engine.ownershipGeneration=UUID()}
   OrderedLatencyIPC(engine:engine,request:request(93),completion:{info=$0}).run()
   check(info==nil,"late latency IPC generation refused");LatencyFixture.shared.hook=nil
   let native=LatencyFixture.shared.value!;try host.close();check(native.closed,"late IPC original facade joined")
  }
  print("PASS Apple CONNECT execution runtime: original factory, typed50 facade, cancellation and joined cleanup")
 }
}
'''

def typed_abi_contract(prepare):
    import ast
    import textwrap
    markers=('    # Distinct typed execution ABI;',
             '    # CONNECTED_TYPED_CANDIDATE_ABI_BEGIN',
             '    # CONNECTED_TYPED_CANDIDATE_ABI_END',
             '    # PREFIX_PREPARATION_ABI_BEGIN')
    assert all(prepare.count(marker)==1 for marker in markers), 'typed ABI boundaries must be unique'
    assert all(sum(line.startswith(marker) for line in prepare.splitlines())==1 for marker in markers), 'typed ABI boundaries must retain their original scope'
    positions=[prepare.index(marker) for marker in markers]
    assert positions==sorted(positions), 'typed ABI boundaries are out of order'
    begin,end=positions[:2]
    block=prepare[begin:end]
    tree=ast.parse(textwrap.dedent(block))
    assert len(tree.body)==2 and all(isinstance(node,ast.For) for node in tree.body), 'both original typed ABI families are required'
    signatures=[]
    for family,loop in zip(('CONNECT','SOCKS'),tree.body):
        original=ast.literal_eval(loop.iter)
        names=(f'LibboxNewRouterNodeChain{family}Execution(', f'LibboxNewRouterNodeChain{family}ExecutionLaunch(', f'LibboxRouterNodeChain{family}ExecutionFromLast(', f'LibboxRouterNodeChain{family}ExecutionNewCommandServer(')
        assert len(original)==4 and all(sum(name in value for value in original)==1 for name in names)
        signatures.extend(original)
    assert len(set(signatures))==8
    content='\n'.join(signatures)
    exec(compile(tree,'actual-apple-abi-check','exec'),{'content':content})
    for signature in signatures:
        try:exec(compile(tree,'actual-apple-abi-check','exec'),{'content':content.replace(signature,'')})
        except AssertionError:pass
        else:raise AssertionError('Missing exact typed ABI signature was accepted')
    return begin,end,block


def build_contract():
    prepare=(ROOT/'ios/RouterVPN/prepare-libbox.sh').read_text()
    begin,end,block=typed_abi_contract(prepare)
    mutations={
        'missing-original-families':prepare[:begin]+prepare[end:],
        'duplicate-original-families':prepare[:end]+block+prepare[end:],
        'commented-original-families':prepare[:begin]+''.join('    # '+line+'\n' for line in block.splitlines())+prepare[end:],
        'conditional-original-families':prepare[:begin]+'    if False:\n'+''.join('    '+line+'\n' for line in block.splitlines())+prepare[end:],
        'sibling-original-families':prepare[:begin]+prepare[end:]+block,
        'duplicate-connected-boundary':prepare+'\n    # CONNECTED_TYPED_CANDIDATE_ABI_BEGIN\n',
        'missing-connected-boundary':prepare.replace('    # CONNECTED_TYPED_CANDIDATE_ABI_BEGIN','    # missing candidate boundary',1),
    }
    for name,mutated in mutations.items():
        try:typed_abi_contract(mutated)
        except AssertionError:pass
        else:raise AssertionError('Invalid original typed ABI scope was accepted: '+name)
    print('PASS Apple original typed ABI scope: 7 source mutation controls')
    caller='python3 "$ROOT/../../deploy/test_node_chain_execution_owner.py" --core "$VENDOR" --go "$(command -v go)" --race --tags with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego'
    def require_caller(value):
        assert value.count(caller)==1 and value.index('prepare-mobile-multihop.py') < value.index(caller), 'missing original native-owner shipping gate'
    require_caller(prepare)
    try:require_caller(prepare.replace(caller,': # omitted native owner'))
    except AssertionError:pass
    else:raise AssertionError('Omitted native owner gate was accepted')
    print('PASS Apple typed ABI8 + missing-signature8 + original native-owner caller/omission')

def main():
    build_contract()
    host=(TUN/'RouterVPNNodeChainExecutionHost.swift').read_text().replace('import Libbox\n','')
    engine=(TUN/'RouterVPNLibboxEngine.swift').read_text();start=engine.index('    private func startOrderedExecution(')
    begin=engine.index('        var createError: NSError?',start);end=engine.index('        ownershipLock.lock()',begin)
    factory='func actualFactory(_ capture:IOSNodeChainExecutionCapture,_ host:RouterVPNNodeChainExecutionHost,_ platform:RouterVPNLibboxPlatform)throws->LibboxCommandServer{\n'+engine[begin:end]+'\n return created\n}\n'
    start=engine.index('    private final class OrderedLatencyIPC:');end=engine.index('    func completeNodeChainSOCKS(',start)
    ipc=engine[start:end].replace('private final class OrderedLatencyIPC:', 'final class OrderedLatencyIPC:',1)
    registry=(TUN/'RouterVPNOrderedLatency.swift').read_text().replace('import Libbox\n','')
    with tempfile.TemporaryDirectory(prefix='ios-connect-execution-runtime-') as folder:
        work=Path(folder);source=work/'Runtime.swift';binary=work/'runtime'
        def run(h,f,dispatch=None):
            source.write_text(H.BOUNDARY+H.RESTORE_BOUNDARY+NATIVE.replace('// ACTUAL_FACTORY',f).replace('// ACTUAL_IPC',ipc if dispatch is None else dispatch)+registry+h+TESTS)
            subprocess.run(['swiftc','-j','1','-swift-version','6','-parse-as-library','-module-cache-path',str(work/'modules'),str(source),'-o',str(binary)],check=True,timeout=90)
            return subprocess.run([str(binary)],capture_output=True,text=True,timeout=35)
        result=run(host,factory);assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip())
        for name,target,before,after,witness in (
          ('typed-factory','factory',': capture.isCONNECT',': false','execution-owned factory required'),
          ('factory-retention','factory','if let created { try host.bindNative(created) }','if let created, createError == nil { try host.bindNative(created) }','factory owner bound before error'),
          ('facade-join','host','try latency?.close() // join the original borrowed facade before its measurement service','_ = latency // omitted original facade join','ACCEPTED pending facade join'),
          ('facade-late-owner','host','if let returned { retain(returned) }','if let returned, !cancelled { retain(returned) }','late original facade retained for close'),
        ):
            value=factory if target=='factory' else host;assert value.count(before)==1,name
            result=run(host if target=='factory' else value.replace(before,after,1),factory if target=='host' else value.replace(before,after,1))
            assert result.returncode==1 and ('FAIL '+witness+'\n') in result.stdout+result.stderr,(name,result.returncode,result.stdout+result.stderr)
            print('Rejected Apple CONNECT runtime control:',name)
        before='if let execution { result = try execution.latencyInfo(request, session: engine.settingsEpoch) }'
        assert ipc.count(before)==1
        result=run(host,factory,ipc.replace(before,'if false {}',1))
        assert result.returncode==1 and 'FAIL typed execution IPC reaches original latency host\n' in result.stdout+result.stderr,result.stdout+result.stderr
        print('Rejected Apple CONNECT runtime control: original-IPC-dispatch')
if __name__=='__main__':main()
