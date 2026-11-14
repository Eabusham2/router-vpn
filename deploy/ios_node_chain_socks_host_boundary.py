"""Explicit typed SOCKS foreign-handle doubles for the full shipping engine.

Source compilation and real native traffic have separate acceptance gates.
"""
NATIVE=r'''
public final class LibboxSOCKSHostFixture: @unchecked Sendable {
 public static let shared=LibboxSOCKSHostFixture()
 private let lock=NSLock()
 private var creation:((LibboxCommandServer)->Void)?,creationError=false
 private var probe:LibboxRouterHopMeasurement?
 public func measurement(_ value:LibboxRouterHopMeasurement){lock.lock();probe=value;lock.unlock()}
 public func measurement()->LibboxRouterHopMeasurement?{lock.lock();defer{lock.unlock()};return probe}
 public func configureCreation(error:Bool=false,_ hook:((LibboxCommandServer)->Void)?=nil){lock.lock();creationError=error;creation=hook;lock.unlock()}
 public func returned(_ server:LibboxCommandServer,_ failure:UnsafeMutablePointer<NSError?>?){lock.lock();let hook=creation,bad=creationError;creation=nil;creationError=false;lock.unlock();hook?(server);if bad{failure?.pointee=NSError(domain:"ExecutionFactoryBoundary",code:1)}}
}
public final class LibboxRouterNodeChainSOCKS {
 private var factoryServer:LibboxCommandServer?
 private let lock=NSLock();private var server:LibboxCommandServer?,retired=false,closed=false,proved=false
 private var runGate:DispatchSemaphore?,closeFailures=0
 private var lastGate:DispatchSemaphore?;public let lastEntered=DispatchSemaphore(value:0)
 public let entered=DispatchSemaphore(value:0),finished=DispatchSemaphore(value:0)
 public init(){}
 public func newCommandServer(_ handler:AnyObject,platform:AnyObject,error:UnsafeMutablePointer<NSError?>?)->LibboxCommandServer?{
  lock.lock();guard factoryServer==nil else{lock.unlock();error?.pointee=NSError(domain:"RepeatedTypedFactory",code:1);return nil}
  let value=LibboxTestState.shared.makeServer();factoryServer=value;lock.unlock()
  LibboxSOCKSHostFixture.shared.returned(value,error);return value
 }
 public func configure(block:Bool=false,failClose:Int=0){lock.lock();runGate=block ? DispatchSemaphore(value:0):nil;closeFailures=failClose;lock.unlock()}
 public func bindNative(_ original:LibboxCommandServer)throws{
  lock.lock();defer{lock.unlock()}
  guard factoryServer===original,server==nil || server===original else{throw NSError(domain:"ExecutionChangedServer",code:1)}
  guard !original.strategyCalls().contains("start") else{throw NSError(domain:"ExecutionLateBind",code:1)}
  server=original;_ = original.strategy("execution-bind",nil)
  if retired{throw NSError(domain:"ExecutionRetired",code:1)}
 }
 public func run(_ original:LibboxCommandServer)throws{
  entered.signal();defer{finished.signal()}
  lock.lock();let exact=server===original,gate=runGate;lock.unlock()
  guard exact,original.strategyCalls().contains("start") else{throw NSError(domain:"ExecutionUnbound",code:1)}
  if let gate{_ = gate.wait(timeout:.now()+5)}
  lock.lock();defer{lock.unlock()};guard !retired else{throw NSError(domain:"ExecutionRetired",code:2)};proved=true
 }
 public func healthy()->Bool{lock.lock();defer{lock.unlock()};return proved && !retired && !closed}
 public func execution()->String{healthy() ? "server":""}
 public func networkChanged(){lock.lock();retired=true;let gate=runGate;lock.unlock();gate?.signal()}
 public func close()throws{networkChanged();lock.lock();defer{lock.unlock()};server?.torCleanup(closeFailures==0);if closeFailures>0{closeFailures-=1;throw NSError(domain:"ExecutionRemotePending",code:1)};closed=true}
 public func nativeClosed()->Bool{lock.lock();defer{lock.unlock()};guard closed,let server else{return false};return !server.strategyCalls().contains("start") || server.instanceJoined()}
 public func retainsServerCleanup(_ original:LibboxCommandServer)->Bool{lock.lock();defer{lock.unlock()};return server===original && !closed}
 public func sourceSHA256()->String{String(repeating:"1",count:64)}
 public func configSHA256()->String{String(repeating:"2",count:64)}
 public func progressJSON()->String{"{\"stage\":\"selected\",\"execution\":\"server\"}"}
 public func holdLast(){lock.lock();lastGate=DispatchSemaphore(value:0);lock.unlock()}
 public func releaseLast(){lock.lock();let gate=lastGate;lock.unlock();gate?.signal()}
 public func lastRecord()throws->String{lock.lock();let gate=lastGate;lock.unlock();lastEntered.signal();if let gate{_ = gate.wait(timeout:.now()+5)};guard healthy()else{throw NSError(domain:"UnprovedLastBoundary",code:1)};return "{\"execution\":\"server\"}"}
 public func mtuProfile()->String{healthy() ? "{\"mtu_policy\":\"auto\"}":""}
 public func measurement(_ original:LibboxCommandServer)->LibboxRouterHopMeasurement?{lock.lock();defer{lock.unlock()};return server===original && proved && !retired && !closed ? LibboxRouterHopMeasurement():nil}
}
public func LibboxRouterNodeChainSOCKSNewHopMeasurement(_ plan:LibboxRouterNodeChainSOCKS,_ original:LibboxCommandServer,_ failure:UnsafeMutablePointer<NSError?>?)->LibboxRouterHopMeasurement?{
 guard let probe=plan.measurement(original) else{failure?.pointee=NSError(domain:"ExecutionMeasurementBoundary",code:1);return nil};LibboxSOCKSHostFixture.shared.measurement(probe);return probe
}
public func LibboxRouterNodeChainSOCKSNewCommandServer(_ plan:LibboxRouterNodeChainSOCKS,_ handler:AnyObject,_ platform:AnyObject,_ error:UnsafeMutablePointer<NSError?>?)->LibboxCommandServer?{
 plan.newCommandServer(handler,platform:platform,error:error)
}
'''
SOURCE=r'''
final class IOSNodeChainSOCKSCapture: @unchecked Sendable {
 struct Member{let id:String}
 let members=[Member(id:"entry"),Member(id:"middle"),Member(id:"final")]
 let plan=LibboxRouterNodeChainSOCKS(),strict=true
 let config="{\"inbounds\":[{\"type\":\"tun\",\"tag\":\"tun-in\"}],\"route\":{\"final\":\"routervpn-chain-application\"}}"
}
'''
MTU_METHODS=r'''
    func activateNodeChainSOCKS(server:LibboxCommandServer,plan:LibboxRouterNodeChainSOCKS,onAbort:@escaping @Sendable(String)->Void)throws{
        guard plan.healthy() else{throw NSError(domain:"TypedMTUFixture",code:1)}
    }
'''
TESTS=r'''
        if CommandLine.arguments.contains("--socks-only") {
            func stop(_ owner:RouterVPNLibboxEngine)throws {
                for _ in 0..<100 {do{try owner.stopCheckedForStrategy();return}catch{Thread.sleep(forTimeInterval:0.005)}}
                try owner.stopCheckedForStrategy()
            }
            do {
                let capture=IOSNodeChainSOCKSCapture(),owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),done=CompletionState()
                try owner.start(nodeChainSOCKS:capture)
                let server=state.currentServer()!
                var refused=false;do{try capture.plan.bindNative(LibboxCommandServer())}catch{refused=true}
                check("typed factory refuses foreign native server",refused && capture.plan.nativeClosed()==false)
                check("typed factory binds before native start",server.strategyCalls().prefix(2)==["execution-bind","start"])
                owner.completeNodeChainSOCKS(done.finish)
                check("typed shared proof gates delivery",done.wait() && done.values()==(1,0) && capture.plan.healthy())
                try owner.activateNodeChainSOCKSMTU()
                let probe=LibboxSOCKSHostFixture.shared.measurement()!
                check("typed measurement is attached to current host",owner.hopMeasurementRequest(operation:"hop-measure-start",request:String(repeating:"c",count:32),session:owner.settingsEpoch) != nil)
                try stop(owner)
                check("typed native close receipt precedes owner release",capture.plan.nativeClosed() && !owner.ownsNodeChain && probe.closeCount()>0)
                check("retired typed owner cannot publish current proof",!capture.plan.healthy() && owner.multihopProgress()==nil)
            }
            for withError in [false,true] {
                let capture=IOSNodeChainSOCKSCapture(),owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),before=state.counts()
                LibboxSOCKSHostFixture.shared.configureCreation(error:withError){_ in owner.stop()}
                var rejected=false;do{try owner.start(nodeChainSOCKS:capture)}catch{rejected=true}
                let server=state.currentServer()!,directory=state.directory()
                check("typed late factory cancellation refuses start",rejected && owner.ownsNodeChain && server.strategyCalls()==["execution-bind"] && state.counts()==before)
                try stop(owner)
                check("typed late factory return survives for cleanup",capture.plan.nativeClosed() && !FileManager.default.fileExists(atPath:directory) && state.counts().1==before.1+1)
            }
            do {
                let capture=IOSNodeChainSOCKSCapture(),owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
                capture.plan.configure(failClose:2)
                try owner.start(nodeChainSOCKS:capture);owner.stop()
                let before=state.counts(),replacement=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
                var refused=false;do{try replacement.start(files:files,strict:false)}catch{refused=true}
                check("typed pending native close blocks replacement",refused && state.counts()==before)
                try stop(owner)
            }
            print("Swift 6 typed SOCKS engine: PASS (\(checks) shipping startup/stop/activity checks; native handles doubled)")
            return
        }
'''
