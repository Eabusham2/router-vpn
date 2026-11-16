#!/usr/bin/env python3
"""Execute the Apple SOCKS factory, owned host and complete latency dispatch.

Shipping Swift bodies run with explicit Libbox/MTU/OS boundary doubles.
"""
from pathlib import Path
import importlib.util
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TUN = ROOT / 'ios/RouterVPN/PacketTunnel'
spec = importlib.util.spec_from_file_location('original_typed_execution_host', ROOT / 'deploy/test_ios_connect_execution_runtime.py')
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
NATIVE = C.NATIVE
original = ''' CommandFactory.shared.typed+=1;let server=LibboxCommandServer();CommandFactory.shared.created=server
 if CommandFactory.shared.fail{error?.pointee=failure("factory failed after acquisition")};return server'''
refusal = ' error?.pointee=failure("ordinary CONNECT fixture cannot own a SOCKS execution");return nil'
assert NATIVE.count(original) == 1 and NATIVE.count(refusal) == 1
NATIVE = NATIVE.replace(original, ' CommandFactory.shared.ordinary+=1;return LibboxCommandServer()', 1).replace(refusal, original, 1)
TESTS = C.TESTS.replace('capture.isCONNECT=true', 'capture.isSOCKS=true')
TESTS = TESTS.replace('static func started()throws', 'static func started(_ family:String="socks",count:Int=3)throws', 1)
TESTS = TESTS.replace('let capture=IOSNodeChainExecutionCapture();capture.isSOCKS=true\n', r'''let capture=IOSNodeChainExecutionCapture();capture.isSOCKS=family=="socks"
  if family=="paired"{capture.members=(0..<count).map{IOSNodeChainExecutionCapture.Member(id:"paired-\($0)")}}
  else{capture.members=(0..<count-2).map{IOSNodeChainExecutionCapture.Member(id:"prefix-\($0)")}+[.init(id:"proxy"),.init(id:"final")]}
''', 1)
marker = '  print("PASS Apple CONNECT execution runtime: original factory, typed50 facade, cancellation and joined cleanup")'
assert TESTS.count(marker) == 1
TESTS = TESTS.replace(marker, r'''
  for count in 3...8 {
   let(host,server,_)=try started("socks",count:count)
   let response=try host.latencyInfo(request(200+count,operation:"ordered-latency-info",node:"prefix-0"),session:"original")
   let body=try JSONSerialization.jsonObject(with:response!) as! [String:Any],nodes=body["nodes"] as! [[String:Any]]
   check(CommandFactory.shared.typed==1 && CommandFactory.shared.ordinary==0,"complete SOCKS prefixes retain original typed factory")
   check(nodes.count==count && nodes.enumerated().allSatisfy{$0.element["position"] as? Int==$0.offset && $0.element["kind"] as? String==($0.offset==count-2 ? "public-path":"private-node")},"complete SOCKS measurement retains every original role and position")
   for position in 0..<count-2{check(nodes[position]["node_id"] as? String=="prefix-\(position)","complete SOCKS measurement retains independent prefix identity")}
   check(nodes[count-2]["node_id"] as? String=="proxy" && nodes[count-1]["node_id"] as? String=="final","complete SOCKS measurement keeps original penultimate and final")
   let owner=try host.latencyOpen(request(220+count,node:"prefix-0"))
   check(!owner.isClosed(),"complete SOCKS measurement uses its captured native facade")
   try host.close();check(server.released && owner.isClosed(),"complete SOCKS facade and original native owner join")
  }
  for count in [2,3,8] {
   let(host,server,_)=try started("paired",count:count),req=request(100+count,operation:"ordered-latency-info",node:"paired-0")
   check(CommandFactory.shared.typed==0 && CommandFactory.shared.ordinary==1,"paired execution retains ordinary original factory")
   let response=try host.latencyInfo(req,session:"original"),body=try JSONSerialization.jsonObject(with:response!) as! [String:Any],nodes=body["nodes"] as! [[String:Any]]
   check(nodes.count==count && nodes.allSatisfy{$0["kind"] as? String=="private-node"},"paired execution never labels a private node as an imported public path")
   let owner=try host.latencyOpen(request(120+count,node:"paired-0"));check(!owner.isClosed(),"paired execution uses its original native latency facade")
   try host.close();check(server.released && owner.isClosed(),"paired original latency and host joined")
  }
  do {
   let(host,server,_)=try started("imported"),response=try host.latencyInfo(request(150,operation:"ordered-latency-info"),session:"original")
   let body=try JSONSerialization.jsonObject(with:response!) as! [String:Any],nodes=body["nodes"] as! [[String:Any]]
   check(CommandFactory.shared.typed==0 && CommandFactory.shared.ordinary==1 && nodes[1]["kind"] as? String=="public-path","generic imported SS retains original public-path role")
   let owner=try host.latencyOpen(request(151));try host.close();check(server.released && owner.isClosed(),"generic imported latency joins its actual host")
  }
  print("PASS Apple SOCKS and generic execution runtime: original factory, fifty-sample facade, role labels and joined cleanup")''', 1)


def main():
    C.build_contract()
    host = (TUN / 'RouterVPNNodeChainExecutionHost.swift').read_text().replace('import Libbox\n', '')
    engine = (TUN / 'RouterVPNLibboxEngine.swift').read_text()
    start = engine.index('    private func startOrderedExecution(')
    begin = engine.index('        var createError: NSError?', start)
    end = engine.index('        ownershipLock.lock()', begin)
    factory = 'func actualFactory(_ capture:IOSNodeChainExecutionCapture,_ host:RouterVPNNodeChainExecutionHost,_ platform:RouterVPNLibboxPlatform)throws->LibboxCommandServer{\n' + engine[begin:end] + '\n return created\n}\n'
    start = engine.index('    private final class OrderedLatencyIPC:')
    end = engine.index('    func completeNodeChainSOCKS(', start)
    ipc = engine[start:end].replace('private final class OrderedLatencyIPC:', 'final class OrderedLatencyIPC:', 1)
    registry = (TUN / 'RouterVPNOrderedLatency.swift').read_text().replace('import Libbox\n', '')
    with tempfile.TemporaryDirectory(prefix='ios-socks-execution-runtime-') as folder:
        work = Path(folder)
        source, binary = work / 'Runtime.swift', work / 'runtime'
        def run(h, f, dispatch=None):
            source.write_text(C.H.BOUNDARY + C.H.RESTORE_BOUNDARY + NATIVE.replace('// ACTUAL_FACTORY', f).replace('// ACTUAL_IPC', ipc if dispatch is None else dispatch) + registry + h + TESTS)
            subprocess.run(['swiftc', '-j', '1', '-swift-version', '6', '-parse-as-library', '-module-cache-path', str(work / 'modules'), str(source), '-o', str(binary)], check=True, timeout=90)
            return subprocess.run([str(binary)], capture_output=True, text=True, timeout=35)
        result = run(host, factory)
        assert result.returncode == 0, result.stdout + result.stderr
        print(result.stdout.strip())
        for name, target, before, after, witness in (
            ('typed-factory', 'factory', 'let created = capture.isSOCKS', 'let created = false', 'execution-owned factory required'),
            ('factory-retention', 'factory', 'if let created { try host.bindNative(created) }', 'if let created, createError == nil { try host.bindNative(created) }', 'factory owner bound before error'),
            ('facade-join', 'host', 'try latency?.close() // join the original borrowed facade before its measurement service', '_ = latency // omitted original facade join', 'ACCEPTED pending facade join'),
            ('facade-late-owner', 'host', 'if let returned { retain(returned) }', 'if let returned, !cancelled { retain(returned) }', 'late original facade retained for close'),
            ('original-role', 'host', 'member.profile["node_kind"] as? String == "external"', 'position == capture.members.count - 2', 'paired execution never labels a private node as an imported public path'),
        ):
            value = factory if target == 'factory' else host
            assert value.count(before) == 1, name
            result = run(host if target == 'factory' else value.replace(before, after, 1), factory if target == 'host' else value.replace(before, after, 1))
            assert result.returncode == 1 and ('FAIL ' + witness + '\n') in result.stdout + result.stderr, (name, result.returncode, result.stdout, result.stderr)
            print('Rejected Apple SOCKS runtime control:', name)
        before = 'if let execution { result = try execution.latencyInfo(request, session: engine.settingsEpoch) }'
        assert ipc.count(before) == 1
        result = run(host, factory, ipc.replace(before, 'if false {}', 1))
        assert result.returncode == 1 and 'FAIL typed execution IPC reaches original latency host\n' in result.stdout + result.stderr, result.stdout + result.stderr
        print('Rejected Apple SOCKS runtime control: original-IPC-dispatch')


if __name__ == '__main__':
    main()
