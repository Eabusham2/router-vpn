#!/usr/bin/env python3
"""Run shipping ordered proof/measurement delivery with explicit native handles.

The entire delivery and admission methods run unchanged. Native handles are
controlled doubles; Go's actual service/drain and device traffic have separate gates.
"""
from pathlib import Path
import importlib.util
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('proof_delivery_members', ROOT/'deploy/test_ios_proof_cancel_delivery.py')
MEMBERS = importlib.util.module_from_spec(spec)
spec.loader.exec_module(MEMBERS)

SWIFT = r'''
import Foundation
final class LibboxCommandServer: @unchecked Sendable {}
final class LibboxRouterHopMeasurement: @unchecked Sendable {
 let invalidated=DispatchSemaphore(value:0)
 func networkChanged(){invalidated.signal()}
}
final class LibboxRouterNodeChain: @unchecked Sendable {
 let entered=DispatchSemaphore(value:0), returned=DispatchSemaphore(value:0)
 var gate:DispatchSemaphore?, cancelled=false
 var original:LibboxCommandServer?, retained:LibboxRouterHopMeasurement?
 func run(_ server:LibboxCommandServer)throws{original=server;entered.signal();if let gate{_ = gate.wait(timeout:.now()+5)};returned.signal()}
 func healthy()->Bool{!cancelled}
 func networkChanged(){cancelled=true}
 func progressJSON()->String{"{}"}
}
final class NativeFixture: @unchecked Sendable {
 static let shared=NativeFixture()
 var calls=0,fail=false,hook:(()->Void)?,probe:LibboxRouterHopMeasurement?
 func reset(){calls=0;fail=false;hook=nil;probe=nil}
}
func LibboxRouterNodeChainNewHopMeasurement(_ plan:LibboxRouterNodeChain,_ server:LibboxCommandServer,_ failure:inout NSError?)->LibboxRouterHopMeasurement? {
 let fixture=NativeFixture.shared;fixture.calls+=1
 guard plan.original === server,plan.healthy(),!fixture.fail else{failure=NSError(domain:"native",code:1);return nil}
 let probe=LibboxRouterHopMeasurement();plan.retained=probe;fixture.probe=probe;fixture.hook?();return probe
}
final class MTU {var proofObservationToken:Int?{1}}
final class Platform {let mtu=MTU()}
final class Tunnel {func nativeLibboxFailure(_ owner:RouterVPNLibboxEngine,error:Error){}}
final class RouterVPNLibboxEngine: @unchecked Sendable {
 let ownershipLock=NSLock(),platform=Platform()
 var nodeChain:LibboxRouterNodeChain?=LibboxRouterNodeChain(),server:LibboxCommandServer?=LibboxCommandServer()
 var ownershipGeneration=UUID(),permanentlyStopped=false,starting=false
 private var nodeChainDelivery:NodeChainDelivery?
 var hopMeasurement:LibboxRouterHopMeasurement?,multihopHealth:DispatchSourceTimer?,tunnel:Tunnel?
 func error(_ text:String)->NSError{NSError(domain:"host",code:1,userInfo:[NSLocalizedDescriptionKey:text])}
 func retire(){ownershipLock.lock();permanentlyStopped=true;let delivery=nodeChainDelivery;multihopHealth?.cancel();ownershipLock.unlock();delivery?.cancel()}
 // SHIPPING_ADMISSION
 // SHIPPING_DELIVERY
}
final class Result: @unchecked Sendable {
 let signal=DispatchSemaphore(value:0),lock=NSLock()
 var errors:[Bool]=[]
 func finish(_ error:Error?){lock.lock();errors.append(error != nil);lock.unlock();signal.signal()}
 func wait()->Bool{signal.wait(timeout:.now()+5) == .success}
}
@main struct Main {
 static func check(_ ok:Bool,_ text:String){if !ok{FileHandle.standardError.write(Data((text+"\n").utf8));exit(1)}}
 static func main(){
  let native=NativeFixture.shared
  native.reset()
  do {
   let owner=RouterVPNLibboxEngine(),result=Result()
   owner.completeNodeChainExecution(result.finish);check(result.wait(),"success delivery missing")
   check(result.errors==[false] && native.calls==1 && owner.hopMeasurement === owner.nodeChain?.retained && owner.hopMeasurement != nil,"proved ordered delivery omitted exact measurement adoption")
   owner.retire()
  }
  native.reset()
  do {
   let owner=RouterVPNLibboxEngine(),result=Result(),gate=DispatchSemaphore(value:0)
   owner.nodeChain!.gate=gate;owner.completeNodeChainExecution(result.finish)
   check(owner.nodeChain!.entered.wait(timeout:.now()+5) == .success,"native proof did not start")
   owner.retire();check(result.wait() && result.errors==[true],"cancelled proof delivered success");gate.signal()
   check(owner.nodeChain!.returned.wait(timeout:.now()+5) == .success,"cancelled proof did not unwind")
   check(native.calls==0 && owner.hopMeasurement==nil,"cancelled proof admitted measurement")
  }
  native.reset()
  do {
   let owner=RouterVPNLibboxEngine(),result=Result()
   native.hook={owner.retire()};owner.completeNodeChainExecution(result.finish)
   check(result.wait() && result.errors==[true],"retired measurement delivery reported success")
   guard let probe=native.probe else{check(false,"native factory not reached");return}
   check(probe.invalidated.wait(timeout:.now()+5) == .success,"late measurement was not invalidated")
   check(owner.hopMeasurement==nil && owner.nodeChain?.retained === probe,"late delivery lost original native cleanup owner")
  }
  native.reset();native.fail=true
  do {
   let owner=RouterVPNLibboxEngine(),result=Result();owner.completeNodeChainExecution(result.finish)
   check(result.wait() && result.errors==[true] && owner.hopMeasurement==nil,"failed native factory published connected measurement");owner.retire()
  }
  print("Apple ordered measurement delivery: exact adoption, cancellation, late owner and failed factory PASS; native handles doubled")
 }
}
'''


def main():
    source=(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift').read_text()
    admission=MEMBERS.member(source,'    func completeNodeChainExecution(')
    delivery=MEMBERS.member(source,'    private final class NodeChainDelivery:')
    code=SWIFT.replace(' // SHIPPING_ADMISSION',admission).replace(' // SHIPPING_DELIVERY',delivery)
    with tempfile.TemporaryDirectory(prefix='ios-ordered-measure-delivery-') as temporary:
        folder=Path(temporary);swift=folder/'Main.swift';binary=folder/'test'
        swift.write_text(code)
        subprocess.run(['swiftc','-swift-version','6','-parse-as-library',str(swift),'-o',str(binary)],check=True,timeout=60)
        subprocess.run([str(binary)],check=True,timeout=30)
        seam='if measurementCurrent { owner.hopMeasurement = probe }'
        assert delivery.count(seam)==1
        swift.write_text(code.replace(seam,'if measurementCurrent { }'))
        subprocess.run(['swiftc','-swift-version','6','-parse-as-library',str(swift),'-o',str(binary)],check=True,timeout=60)
        result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
        assert result.returncode!=0 and 'proved ordered delivery omitted exact measurement adoption' in result.stderr,result.stderr
        print('Apple ordered delivery negative control: omitted native measurement adoption rejected')

if __name__=='__main__':main()
