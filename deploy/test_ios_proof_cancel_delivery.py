#!/usr/bin/env python3
"""Exercise the exact Swift proof finish/cancel methods during held native Cancel.

The native cancellation boundary is held after the host claims cancellation.
A concurrent successful Run completion must deliver failure exactly once. This
tests the actual callback transaction without relying on scheduler timing.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / 'ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift'


def member(source, signature):
    begin = source.index(signature)
    end = source.index('{', begin) + 1
    depth = 1
    while depth:
        if source[end] == '{': depth += 1
        if source[end] == '}': depth -= 1
        end += 1
    return source[begin:end]


SWIFT = r'''
import Foundation
final class NativeCancel: @unchecked Sendable {
 let entered=DispatchSemaphore(value:0),release=DispatchSemaphore(value:0)
 func cancel(){entered.signal();precondition(release.wait(timeout:.now()+3) == .success,"native Cancel release missing")}
}
final class Result: @unchecked Sendable {
 private let lock=NSLock();private var values:[Bool]=[]
 func finish(_ error:Error?){lock.lock();values.append(error != nil);lock.unlock()}
 var results:[Bool]{lock.lock();defer{lock.unlock()};return values}
}
final class Delivery: @unchecked Sendable {
 private let lock=NSLock()
 private var callback:((Error?)->Void)?
 private var cancelled=false,proved=false
 let request=NativeCancel()
 init(_ result:Result){callback=result.finish}
 func successfulRun(){finish(nil)}
 var wasProved:Bool{lock.lock();defer{lock.unlock()};return proved}
 // SHIPPING_METHODS
}
@main struct Tests {
 static func main(){
  for _ in 0..<64 {
   let result=Result(),delivery=Delivery(result),joined=DispatchSemaphore(value:0)
   DispatchQueue.global().async{delivery.cancel();joined.signal()}
   precondition(delivery.request.entered.wait(timeout:.now()+3) == .success,"cancellation was not claimed")
   delivery.successfulRun()
   precondition(result.results==[true],"claimed cancellation delivered success")
   precondition(!delivery.wasProved,"cancelled request retained a successful proof")
   delivery.request.release.signal()
   precondition(joined.wait(timeout:.now()+3) == .success,"native cancellation did not join")
   delivery.successfulRun()
   precondition(result.results==[true],"completion callback was delivered more than once")
  }
  // A completed proof may precede cancellation. Later cleanup must not deliver
  // a second callback or retroactively replace that earlier linearized result.
  let result=Result(),delivery=Delivery(result)
  delivery.successfulRun();delivery.request.release.signal();delivery.cancel()
  precondition(result.results==[false],"completed result changed after later cancellation")
  print("shipping proof cancellation callback: 64 held native cancellations + completed-before-cancel PASS")
 }
}
'''


def main():
    swift = shutil.which('swiftc')
    if not swift: raise RuntimeError('swiftc required')
    source = ENGINE.read_text()
    with tempfile.TemporaryDirectory(prefix='ios-proof-cancel-delivery-') as temporary:
        folder = Path(temporary)
        for name in ('TorProofDelivery', 'ExternalProofDelivery'):
            owned = member(source, '    private final class '+name+':')
            methods = '\n'.join(member(owned, signature) for signature in (
                '        private func finish(', '        func cancel()', '        private func retired()'))
            code = folder/(name+'.swift'); binary = folder/name
            code.write_text(SWIFT.replace(' // SHIPPING_METHODS', methods))
            subprocess.run([swift,'-swift-version','6','-parse-as-library',str(code),'-o',str(binary)],check=True,timeout=60)
            subprocess.run([str(binary)],check=True,timeout=10)
            # The former defect still skipped the proved flag but delivered a
            # successful nil callback after cancellation had already won.
            before = 'callback?(delivered)'
            assert methods.count(before) == 1, name
            broken = folder/(name+'-broken.swift'); negative = folder/(name+'-broken')
            broken.write_text(SWIFT.replace(' // SHIPPING_METHODS', methods.replace(before,'callback?(error)')))
            subprocess.run([swift,'-swift-version','6','-parse-as-library',str(broken),'-o',str(negative)],check=True,timeout=60)
            result = subprocess.run([str(negative)],capture_output=True,text=True,timeout=10)
            assert result.returncode != 0 and 'claimed cancellation delivered success' in result.stdout+result.stderr, name+' lost its deterministic negative control'
            print(name+': cancelled-success defect rejected at the actual callback assertion',flush=True)


if __name__ == '__main__': main()
