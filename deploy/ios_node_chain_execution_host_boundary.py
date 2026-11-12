"""Explicit Libbox boundaries for compiled shipping ordered Apple host tests.

No native proof is granted by default: a test must construct this named capture
and run its exact bound server. This is never included in the application.
"""
NATIVE=r'''
public final class LibboxExecutionHostFixture: @unchecked Sendable {
 public static let shared=LibboxExecutionHostFixture()
 private let lock=NSLock()
 private var creation:((LibboxCommandServer)->Void)?,creationError=false
 private var probe:LibboxRouterHopMeasurement?
 public func measurement(_ value:LibboxRouterHopMeasurement){lock.lock();probe=value;lock.unlock()}
 public func measurement()->LibboxRouterHopMeasurement?{lock.lock();defer{lock.unlock()};return probe}
 public func configureCreation(error:Bool=false,_ hook:((LibboxCommandServer)->Void)?=nil){lock.lock();creationError=error;creation=hook;lock.unlock()}
 public func returned(_ server:LibboxCommandServer,_ failure:UnsafeMutablePointer<NSError?>?){lock.lock();let hook=creation,bad=creationError;creation=nil;creationError=false;lock.unlock();hook?(server);if bad{failure?.pointee=NSError(domain:"ExecutionFactoryBoundary",code:1)}}
}
public final class LibboxRouterNodeChainExecution {
 private let lock=NSLock();private var server:LibboxCommandServer?,retired=false,closed=false,proved=false
 private var runGate:DispatchSemaphore?,closeFailures=0
 private var lastGate:DispatchSemaphore?;public let lastEntered=DispatchSemaphore(value:0)
 public let entered=DispatchSemaphore(value:0),finished=DispatchSemaphore(value:0)
 public init(){}
 public func configure(block:Bool=false,failClose:Int=0){lock.lock();runGate=block ? DispatchSemaphore(value:0):nil;closeFailures=failClose;lock.unlock()}
 public func bindNative(_ original:LibboxCommandServer)throws{
  lock.lock();defer{lock.unlock()}
  guard server==nil || server===original else{throw NSError(domain:"ExecutionChangedServer",code:1)}
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
 public func progressJSON()->String{"{\"stage\":\"selected\",\"execution\":\"server\"}"}
 public func holdLast(){lock.lock();lastGate=DispatchSemaphore(value:0);lock.unlock()}
 public func releaseLast(){lock.lock();let gate=lastGate;lock.unlock();gate?.signal()}
 public func lastRecord()throws->String{lock.lock();let gate=lastGate;lock.unlock();lastEntered.signal();if let gate{_ = gate.wait(timeout:.now()+5)};guard healthy()else{throw NSError(domain:"UnprovedLastBoundary",code:1)};return "{\"execution\":\"server\"}"}
 public func mtuProfile()->String{healthy() ? "{\"mtu_policy\":\"auto\"}":""}
 public func measurement(_ original:LibboxCommandServer)->LibboxRouterHopMeasurement?{lock.lock();defer{lock.unlock()};return server===original && proved && !retired && !closed ? LibboxRouterHopMeasurement():nil}
}
public func LibboxRouterNodeChainExecutionNewHopMeasurement(_ plan:LibboxRouterNodeChainExecution,_ original:LibboxCommandServer,_ failure:UnsafeMutablePointer<NSError?>?)->LibboxRouterHopMeasurement?{
 guard let probe=plan.measurement(original) else{failure?.pointee=NSError(domain:"ExecutionMeasurementBoundary",code:1);return nil};LibboxExecutionHostFixture.shared.measurement(probe);return probe
}
'''
SOURCE=r'''
// Source validation has its separate real shared-compiler gate. This boundary
// provides only the immutable fields consumed by this actual native host.
final class IOSNodeChainExecutionCapture: @unchecked Sendable {
 let plan=LibboxRouterNodeChainExecution(),strict=true
 let sourceSHA256=String(repeating:"a",count:64),configSHA256=String(repeating:"b",count:64),ordinaryLaunchInput="original"
 let finalProfile:[String:Any]=["id":"original"]
 final class Restoration {
  let selected="server",original:IOSNodeChainExecutionCapture
  init(_ original:IOSNodeChainExecutionCapture){self.original=original}
  func makeCapture(ordinaryInput:String,selectedProfile:[String:Any])throws->IOSNodeChainExecutionCapture{guard ordinaryInput==original.ordinaryLaunchInput,NSDictionary(dictionary:selectedProfile).isEqual(to:original.finalProfile),original.nativeClosed() else{throw NSError(domain:"OriginalRestoreBoundary",code:1)};return IOSNodeChainExecutionCapture()}
 }
 func captureRestoration()throws->Restoration{guard healthy()else{throw NSError(domain:"UnprovedRestoreBoundary",code:1)};return Restoration(self)}
 func captureLastRecord()throws->String{try requireCurrent();return try plan.lastRecord()}
 let config="{\"inbounds\":[{\"type\":\"tun\",\"tag\":\"tun-in\"}],\"route\":{\"final\":\"routervpn-chain-application\"}}"
 private let lock=NSLock();private var closed=false
 func requireCurrent()throws{lock.lock();defer{lock.unlock()};if closed{throw NSError(domain:"ClosedExecutionCapture",code:1)}}
 func bindNative(_ original:LibboxCommandServer)throws{try plan.bindNative(original);try requireCurrent()}
 func run(_ original:LibboxCommandServer)throws{try requireCurrent();try plan.run(original);try requireCurrent()}
 func healthy()->Bool{(try? requireCurrent()) != nil && plan.healthy() && (try? requireCurrent()) != nil}
 func execution()throws->String{try requireCurrent();let value=plan.execution();guard value=="server" else{throw NSError(domain:"UnprovedExecution",code:1)};return value}
 func networkChanged(){plan.networkChanged()}
 func nativeClosed()->Bool{plan.nativeClosed()}
 func close()throws{try plan.close();lock.lock();closed=true;lock.unlock()}
}
'''
MTU_METHODS=r'''
    func observeNodeChainExecutionMeasurement(_ token:UUID,_ action:()throws->Void)throws->Bool{guard proofObservationToken==token else{return false};try action();return true}
    func drainForNodeChainExecutionCleanup()throws{try drainForTorCleanup()}
    func activateNodeChainExecution(server:LibboxCommandServer,plan:LibboxRouterNodeChainExecution,runAutomatic:Bool=true,onAbort:@escaping @Sendable(String)->Void)throws{
        guard plan.healthy() else{throw NSError(domain:"ExecutionMTUBoundary",code:1)}
        hasOwner=true;self.server=server;failures=MTUActivationFixture.shared.failures()
    }
'''
IPC_TYPES=r'''
final class OrderedIPCReply:@unchecked Sendable {
 private let lock=NSLock();private var received:Data?;let done=DispatchSemaphore(value:0)
 func finish(_ data:Data?){lock.lock();received=data;lock.unlock();done.signal()}
 func result()->Data?{lock.lock();defer{lock.unlock()};return received}
}
'''
TESTS=r'''
        if CommandLine.arguments.contains("--execution-only") {
            func stop(_ owner:RouterVPNLibboxEngine)throws {
                var last:Error?
                for _ in 0..<100{do{try owner.stopCheckedForStrategy();return}catch{last=error;Thread.sleep(forTimeInterval:0.005)}}
                throw last!
            }
            for fault in ["none","remote","box","cancel"] {
                MTUActivationFixture.shared.configure();LibboxExecutionHostFixture.shared.configureCreation()
                let capture=IOSNodeChainExecutionCapture(),provider=PacketTunnelProvider(),owner=RouterVPNLibboxEngine(tunnel:provider),done=CompletionState()
                capture.plan.configure(block:fault=="cancel",failClose:fault=="remote" ? 1:0)
                do{try owner.start(nodeChainExecution:capture)}catch{check("execution startup retains bound original server",false)}
                let server=state.currentServer()!,directory=state.directory(),before=state.counts()
                check("execution startup binds before starting one captured Box",owner.ownsNodeChain && server.strategyCalls()==["execution-bind","start"] && server.capturedConfiguration()==capture.config)
                owner.completeOrderedExecution(done.finish)
                if fault=="cancel" {
                    check("execution native Run entered",capture.plan.entered.wait(timeout:.now()+3) == .success)
                    try stop(owner)
                    check("execution cancellation delivers one failure",done.wait() && done.values()==(1,1))
                } else {
                    check("execution complete proof delivered once",done.wait() && done.values()==(1,0))
                    try owner.activateNodeChainExecutionPerformance();try owner.activateNodeChainExecutionMTU()
                    check("execution retains ordinary owned hop metadata",owner.hopMeasurementRequest(operation:"hop-measure-info",request:String(repeating:"a",count:32),session:"") != nil)
                    check("execution progress uses proved controller",owner.multihopProgress() != nil)
                    if fault=="box"{server.configureStrategy(close:true)}
                    if fault=="remote" || fault=="box" {
                        var rejected=false;do{try owner.stopCheckedForStrategy()}catch{rejected=true}
                        check("execution failed cleanup retains original engine slot",rejected && owner.ownsNodeChain && FileManager.default.fileExists(atPath:directory) && state.counts()==before)
                        if fault=="remote"{check("execution remote failure cannot close native Box",!server.strategyCalls().contains("close"))}
                        if fault=="box"{server.configureStrategy(close:false)}
                    }
                    try stop(owner)
                }
                check("execution successful cleanup removes exact resources",!owner.ownsNodeChain && !FileManager.default.fileExists(atPath:directory) && capture.nativeClosed())
                let events=server.strategyCalls()
                check("execution joined lease precedes original Box close",events.firstIndex(of:"tor-delete")! < events.firstIndex(of:"close")!)
            }
            do {
                MTUActivationFixture.shared.configure()
                let capture=IOSNodeChainExecutionCapture(),owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),done=CompletionState()
                try owner.start(nodeChainExecution:capture);owner.completeOrderedExecution(done.finish)
                check("execution rotation starts with original proof",done.wait() && done.values()==(1,0))
                try owner.activateNodeChainExecutionMTU()
                let old=LibboxExecutionHostFixture.shared.measurement()!
                MTUActivationFixture.shared.currentPlatform()!.mtu.mutateProofEpoch()
                let deadline=Date().addingTimeInterval(3)
                while LibboxExecutionHostFixture.shared.measurement() === old && Date()<deadline{Thread.sleep(forTimeInterval:0.01)}
                let next=LibboxExecutionHostFixture.shared.measurement()!
                check("engine adopts fresh post-MTU original probe",next !== old && old.closeCount()>0)
                let request=String(repeating:"b",count:32)
                check("fresh post-MTU probe is used for real host requests",owner.hopMeasurementRequest(operation:"hop-measure-start",request:request,session:owner.settingsEpoch) != nil && next.statusJSON().contains(request) && !old.statusJSON().contains(request))
                try stop(owner)
                check("rotated engine probe joins exact original teardown",next.closeCount()>0 && capture.nativeClosed())
            }
            do {
                MTUActivationFixture.shared.configure()
                let capture=IOSNodeChainExecutionCapture(),owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),done=CompletionState()
                try owner.start(nodeChainExecution:capture);owner.completeOrderedExecution(done.finish)
                check("ordered IPC original proof",done.wait() && done.values()==(1,0))
                func request(_ operation:String,_ lease:String="")->RouterVPNNodeChainExecutionRegistry.Request {
                    RouterVPNNodeChainExecutionRegistry.Request.parse(try! JSONSerialization.data(withJSONObject:["operation":operation,"request_id":String(repeating:"a",count:32),"session_id":"","owner_id":lease,"token":""]))!
                }
                let saved=OrderedIPCReply();owner.orderedExecutionRequest(request("ordered-execution-last"),completion:saved.finish)
                check("ordered Last IPC returns original observed source",saved.done.wait(timeout:.now()+3) == .success && saved.result().flatMap{try? JSONSerialization.jsonObject(with:$0) as? [String:Any]}?["source_sha256"] as? String==capture.sourceSHA256)
                _ = capture.plan.lastEntered.wait(timeout:.now()+3)
                let held=OrderedIPCReply();capture.plan.holdLast()
                owner.orderedExecutionRequest(request("ordered-execution-last"),completion:held.finish)
                check("ordered Last native observation entered",capture.plan.lastEntered.wait(timeout:.now()+3) == .success)
                var pending=false;do{try owner.stopCheckedForStrategy()}catch{pending=true}
                check("ordered IPC holds original native close",pending && owner.ownsNodeChain)
                capture.plan.releaseLast()
                check("late ordered Last cannot publish after Stop",held.done.wait(timeout:.now()+3) == .success && held.result()==nil)
                try stop(owner)
                check("ordered IPC observation joins original cleanup",capture.nativeClosed() && !owner.ownsNodeChain)
            }
            for withError in [false,true] {
                MTUActivationFixture.shared.configure()
                let capture=IOSNodeChainExecutionCapture(),owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider()),before=state.counts()
                LibboxExecutionHostFixture.shared.configureCreation(error:withError){_ in owner.stop()}
                var rejected=false;do{try owner.start(nodeChainExecution:capture)}catch{rejected=true}
                let server=state.currentServer()!,directory=state.directory()
                check("late factory cancellation refuses startup",rejected && owner.ownsNodeChain && server.strategyCalls()==["execution-bind"] && state.counts()==before)
                try stop(owner)
                check("late created server remains exact cleanup owner",capture.nativeClosed() && !FileManager.default.fileExists(atPath:directory) && state.counts().1==before.1+1)
            }
            do {
                let capture=IOSNodeChainExecutionCapture(),owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
                capture.plan.configure(failClose:2)
                try owner.start(nodeChainExecution:capture);owner.stop()
                let before=state.counts(),replacement=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
                var refused=false;do{try replacement.start(files:files,strict:false)}catch{refused=true}
                check("retained execution blocks replacement native admission",refused && state.counts()==before)
                try stop(owner)
            }
            print("Swift 6 ordered execution engine: PASS (\(checks) shipping startup/stop/activity checks; native handles doubled)")
            return
        }
'''
