#!/usr/bin/env python3
"""Execute the typed source/provider composition with the real shared Go parser."""
from pathlib import Path
import importlib.util
import platform
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
APP=ROOT/'ios/RouterVPN/App'
spec=importlib.util.spec_from_file_location('original_ordered_capture',ROOT/'deploy/test_ios_node_chain_capture.py')
C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)

# Retain every original three-node case and run the same real parser/provider
# assertions with additional paired prefixes. The imported family stays SOCKS.
_original_middle = C.SWIFT[C.SWIFT.index(' static func socksMiddle()'):C.SWIFT.index(' static func hostnameMiddle()')]
_middle = _original_middle.replace('  for mode in ', '  for count in [3,4,8] {for mode in ', 1)
_middle = _middle.replace('sources(3,layer,true)', 'sources(count,layer,true)')
_middle = _middle.replace('for layer in ["off","aes-256-gcm","aes-256-gcm+xor-whitening"]', 'for layer in (count==8 ? ["off"]:["off","aes-256-gcm","aes-256-gcm+xor-whitening"])')
_middle = _middle.replace('   var bundles=try sources', r'   print("Compiling SOCKS captured shape: \(count)/\(mode)/\(layer)");var bundles=try sources', 1)
_middle = _middle.replace('[1]', '[count-2]').replace('[2]', '[count-1]').replace('swapAt(0,1)', 'swapAt(0,count-2)')
_middle = _middle.replace('nodes[0]["mode"]=mode;', 'for prefix in 0..<count-2 {nodes[prefix]["mode"]=mode};')
_middle = _middle.replace('  }}\n }\n', '  }}}\n }\n')
_middle = _middle.replace('   let out=(graph["outbounds"]', r'''   let identities=source["identity_sources"] as! [String]
   try check("SOCKS preserves every original paired prefix",capture.members.count==count && capture.members.prefix(count-2).allSatisfy{$0.mode==mode} && capture.members.last?.mode=="shadowsocks")
   try check("SOCKS preserves every original paired identity",identities.count==count && identities.enumerated().allSatisfy{$0.offset==count-2 ? $0.element.isEmpty : !$0.element.isEmpty})
   for position in 0..<count-2 {
    var stale=bundles;stale[position]=try editProfile(stale[position]){$0["node_proof_id"]=String(repeating:"f",count:64)}
    try reject("SOCKS prefix original proof \(position)"){_ = try IOSNodeChainSOCKSCapture.compile(bundles:stale)}
   }
   let out=(graph["outbounds"]''', 1)
assert _middle != _original_middle and 'sources(3,layer,true)' not in _middle
# The original configured packet sizes cannot carry six AES-wrapped AWG
# prefixes with dual-stack minimum1280. Preserve this source refusal explicitly;
# no synthetic physical MTU or changed saved endpoint budget is supplied.
_capacity = _middle[:_middle.index('   let capture=try IOSNodeChainSOCKSCapture.compile')]
_capacity = _capacity.replace('func socksMiddle()', 'func socksCapacity()').replace('for count in [3,4,8]', 'for count in [8]').replace('for mode in ["wg","awg2-fast","awg2-strong"]', 'for mode in ["awg2-fast"]').replace('for layer in (count==8 ? ["off"]:["off","aes-256-gcm","aes-256-gcm+xor-whitening"])', 'for layer in ["aes-256-gcm"]')
_capacity += '   try reject("SOCKS original configured nested packet capacity"){_ = try IOSNodeChainSOCKSCapture.compile(bundles:bundles)}\n  }}}\n }\n'
SOCKS_SWIFT=C.SWIFT.replace(_original_middle,_middle+_capacity,1)

def main():
    tests=SOCKS_SWIFT.replace('try run();print("Apple ordered native capture: PASS (\\(checks) shipping Swift / shared Go checks; no native connection)")','try socksMiddle();try socksCapacity();print("iOS typed SOCKS source: PASS \\(checks) actual shared-parser and provider checks")',1)
    assert tests!=C.SWIFT
    with tempfile.TemporaryDirectory(prefix='.ios-typed-socks-source-',dir=ROOT) as go_dir,tempfile.TemporaryDirectory(prefix='ios-typed-socks-source-') as folder:
        go_dir,work=Path(go_dir),Path(folder)
        (go_dir/'main.go').write_text(C.GO);compiler=work/'compiler'
        subprocess.run(['go','build','-p','1','-o',str(compiler),str(go_dir/'main.go')],cwd=ROOT,check=True,timeout=180)
        lib=work/'Libbox.swift';lib.write_text(C.LIBBOX)
        code=work/'Tests.swift';code.write_text(tests)
        options=['swiftc','-j','1','-swift-version','6','-module-cache-path',str(work/'modules')]
        library=work/('libLibbox.dylib' if platform.system()=='Darwin' else 'libLibbox.so')
        subprocess.run(options+['-emit-module','-emit-library','-module-name','Libbox',str(lib),'-emit-module-path',str(work/'Libbox.swiftmodule'),'-o',str(library)],check=True,timeout=90)
        command=options+['-I',str(work),'-L',str(work),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(work)]
        command += [str(APP/name) for name in ('Models.swift','IOSMultihopStartLayer.swift','IOSNodeChainCapture.swift','IOSImportedOpenVPNSource.swift','IOSNodeChainProviderCapture.swift')]
        original=(APP/'IOSNodeChainSOCKSCapture.swift').read_text();source=work/'TypedCapture.swift';binary=work/'tests'
        def run(value):
            source.write_text(value)
            subprocess.run(command+[str(source),str(code),'-o',str(binary)],check=True,timeout=90)
            return subprocess.run([str(binary),str(compiler)],capture_output=True,text=True,timeout=180)
        result=run(original);assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip())
        for name,before,after,witness in (
            ('final-source','try json(selectedProfile) == json(result.finalProfile)','true','ACCEPTED SOCKS replaced final control'),
            ('provider-assets','selected == original else','true else','ACCEPTED SOCKS replaced provider assets'),
            ('provider-purpose','.allSatisfy({ configuration[$0] == nil })','.allSatisfy({ _ in true })','ACCEPTED SOCKS mixed provider owner'),
        ):
            assert original.count(before)==1,name
            rejected=run(original.replace(before,after,1))
            assert rejected.returncode!=0 and witness in rejected.stdout+rejected.stderr,(name,rejected.stdout+rejected.stderr)
            print('Rejected typed SOCKS capture mutation: '+name)
if __name__=='__main__':main()
