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

def main():
    tests=C.SWIFT.replace('try run();print("Apple ordered native capture: PASS (\\(checks) shipping Swift / shared Go checks; no native connection)")','try socksMiddle();print("iOS typed SOCKS source: PASS \\(checks) actual shared-parser and provider checks")',1)
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
        command += [str(APP/name) for name in ('Models.swift','IOSMultihopStartLayer.swift','IOSNodeChainCapture.swift','IOSNodeChainProviderCapture.swift')]
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
