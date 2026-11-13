"""Explicit native/source boundaries for the whole shipping Apple engine gate.

The real engine and prefix host are compiled unchanged. Source/compiler and
native ingress/Box proof have independent mandatory gates; these handles cannot
create a candidate score or grant ordinary connection authority.
"""
NATIVE = r'''
public final class LibboxRouterMTUState {
 public let session="prefix-session",path="prefix-physical",interface="utun-fixture"
 public let mtu:Int32=1280
 public init(){}
}
public final class LibboxRouterNodeChainCandidatePreparation {
 private let lock=NSLock()
 private var server:LibboxCommandServer?,retired=false,closed=false,prepared=false
 private var runGate:DispatchSemaphore?,closeFailures=0
 public let entered=DispatchSemaphore(value:0),finished=DispatchSemaphore(value:0)
 public init(){}
 public func configure(block:Bool=false,failClose:Int=0){lock.lock();runGate=block ? DispatchSemaphore(value:0):nil;closeFailures=failClose;lock.unlock()}
 public func bindNative(_ original:LibboxCommandServer)throws{
  lock.lock();defer{lock.unlock()}
  guard server==nil || server===original,!original.strategyCalls().contains("start")else{throw NSError(domain:"PrefixForeignBindBoundary",code:1)}
  server=original
  if retired{throw NSError(domain:"PrefixRetiredBoundary",code:1)}
 }
 public func run(_ original:LibboxCommandServer,catalog:LibboxRouterNodeChainCandidateCatalogProtocol)throws{
  entered.signal();defer{finished.signal()}
  lock.lock();let exact=server===original,gate=runGate;lock.unlock()
  guard exact,original.strategyCalls().contains("start"),!catalog.currentInventorySHA256().isEmpty else{throw NSError(domain:"PrefixUnboundBoundary",code:1)}
  if let gate{_ = gate.wait(timeout:.now()+5)}
  lock.lock();defer{lock.unlock()};guard !retired else{throw NSError(domain:"PrefixRetiredBoundary",code:2)};prepared=true
 }
 public func healthy()->Bool{lock.lock();defer{lock.unlock()};return prepared && !retired && !closed}
 public func progressJSON()->String{"{\"stage\":\"prefix-prepared\",\"prepared\":true,\"application_open\":false,\"dns_open\":false}"}
 public func networkChanged(){lock.lock();retired=true;let gate=runGate;lock.unlock();gate?.signal()}
 public func close()throws{networkChanged();lock.lock();defer{lock.unlock()};if closeFailures>0{closeFailures-=1;throw NSError(domain:"PrefixWorkerPendingBoundary",code:1)};closed=true}
 public func nativeClosed()->Bool{lock.lock();defer{lock.unlock()};guard closed,let original=server else{return false};return !original.strategyCalls().contains("start") || original.instanceJoined()}
 public func metadata()->String{"{\"application_open\":false,\"dns_open\":false}"}
 public func start(_ request:String,candidateID:String)throws{throw NSError(domain:"CandidateWorkerHasSeparateNativeGate",code:1)}
 public func statusJSON()->String{"{}"}
}
'''

SOURCE = r'''
struct IOSNodeCandidatePrefixCapture {
 struct Metadata {struct MTU{let original=1280};let mtu=MTU();let prefix_position=0}
 let native=LibboxRouterNodeChainCandidatePreparation(),strict=true,metadata=Metadata()
 let config="{\"inbounds\":[{\"type\":\"tun\",\"tag\":\"tun-in\"}],\"route\":{\"final\":\"routervpn-candidate-gate\"}}"
 static func issue()->NSError{NSError(domain:"PrefixSourceBoundary",code:1)}
}
final class IOSNodeCandidatePrefixProviderCapture:@unchecked Sendable {
 struct Source{let request=String(repeating:"a",count:32),inventorySHA256=String(repeating:"b",count:64)}
 let capture=IOSNodeCandidatePrefixCapture(),source=Source(),epoch=UUID().uuidString
 private let lock=NSLock();private var valid=true,closed=false
 func requireCurrent()throws{lock.lock();defer{lock.unlock()};guard valid && !closed else{throw IOSNodeCandidatePrefixCapture.issue()}}
 func storeCandidatesClosed()throws{lock.lock();closed=true;lock.unlock()}
 func changeSource(){lock.lock();valid=false;lock.unlock()}
}
extension MTUPlatformDouble {func captureMTU()->LibboxRouterMTUState?{LibboxRouterMTUState()}}
'''

TESTS = r'''
        if CommandLine.arguments.contains("--prefix-only") {
            func stop(_ owner:RouterVPNLibboxEngine)throws {
                var last:Error?
                for _ in 0..<100{do{try owner.stopCheckedForStrategy();return}catch{last=error;Thread.sleep(forTimeInterval:0.005)}}
                throw last!
            }
            for fault in ["none","worker","box","cancel"] {
                MTUActivationFixture.shared.configure();LibboxExecutionHostFixture.shared.configureCreation()
                let input=IOSNodeCandidatePrefixProviderCapture(),provider=PacketTunnelProvider(),owner=RouterVPNLibboxEngine(tunnel:provider),done=CompletionState()
                input.capture.native.configure(block:fault=="cancel",failClose:fault=="worker" ? 1:0)
                try owner.prepareMTUHold("original-prefix-hold")
                try owner.start(candidatePrefix:input)
                let server=state.currentServer()!,directory=state.directory(),before=state.counts()
                check("prefix engine starts exact original gated config",owner.ownsNodeChain && server.strategyCalls()==["start"] && server.capturedConfiguration()==input.capture.config)
                owner.completeCandidatePrefix(done.finish)
                if fault=="cancel" {
                    check("prefix original Run entered",input.capture.native.entered.wait(timeout:.now()+3) == .success)
                    try stop(owner)
                    check("prefix cancellation delivers one failure",done.wait() && done.values()==(1,1))
                } else {
                    check("prefix prepared callback completes exactly once",done.wait() && done.values()==(1,0))
                    check("prefix never activates ordinary MTU owner",!MTUActivationFixture.shared.currentPlatform()!.mtu.hasOwner)
                    check("prefix IPC uses original namespace owner",owner.candidatePrefixRequest(operation:"prefix-candidate-open",request:input.source.request,session:input.epoch,owner:input.source.request,prefix:"0",candidate:"") != nil)
                    check("prefix IPC rejects foreign owner",owner.candidatePrefixRequest(operation:"prefix-candidate-open",request:input.source.request,session:input.epoch,owner:String(repeating:"c",count:32),prefix:"0",candidate:"") == nil)
                    if fault=="box"{server.configureStrategy(close:true)}
                    if fault=="worker" || fault=="box" {
                        var rejected=false;do{try owner.stopCheckedForStrategy()}catch{rejected=true}
                        check("prefix failed close retains original pending owner",rejected && owner.ownsNodeChain && FileManager.default.fileExists(atPath:directory) && state.counts()==before)
                        if fault=="worker"{check("prefix worker join precedes Box close",!server.strategyCalls().contains("close"))}
                        if fault=="box"{
                            let replacement=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider());var refused=false
                            do{try replacement.start(files:files,strict:true)}catch{refused=true}
                            check("prefix pending native close blocks replacement",refused && state.currentServer() === server && FileManager.default.fileExists(atPath:directory))
                            server.configureStrategy(close:false)
                        }
                    }
                    try stop(owner)
                }
                check("prefix original positive native close releases resources",!owner.ownsNodeChain && input.capture.native.nativeClosed() && !FileManager.default.fileExists(atPath:directory))
            }
            for late in [false,true] {
                let input=IOSNodeCandidatePrefixProviderCapture(),owner=RouterVPNLibboxEngine(tunnel:PacketTunnelProvider())
                LibboxExecutionHostFixture.shared.configureCreation(error:!late){_ in if late{owner.stop()}}
                var rejected=false;do{try owner.start(candidatePrefix:input)}catch{rejected=true}
                try stop(owner)
                check("prefix failed or late factory retains its original receipt",rejected && input.capture.native.nativeClosed() && !owner.ownsNodeChain && !FileManager.default.fileExists(atPath:state.directory()))
            }
            print("Swift 6 prefix whole-engine delivery: PASS (\(checks) shipping lifecycle checks; native/source boundaries explicit)");return
        }
'''
