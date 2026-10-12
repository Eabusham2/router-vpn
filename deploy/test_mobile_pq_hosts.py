#!/usr/bin/env python3
"""Run shipping C/JNI/Swift PQ adapters with an explicit test-only protocol ABI.
The Rust workflow independently exercises real encrypted Rosenpass packets.
"""
from pathlib import Path
from unittest import mock
import importlib.util, json, os, shutil, subprocess, tempfile, unittest
ROOT=Path(__file__).resolve().parents[1]
S=ROOT/'mobile/rosenpass'
spec=importlib.util.spec_from_file_location('build_pq',ROOT/'deploy/build-mobile-pq.py')
B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
FAKE=r'''
#include "routervpn_pq_host.h"
#include <string.h>
static uint64_t next=1;
uint32_t routervpn_rp_abi_version(void){return 1;}
size_t routervpn_rp_secret_size(void){return 32;}
size_t routervpn_rp_public_size(void){return 32;}
size_t routervpn_rp_packet_size(void){return 1024;}
int32_t routervpn_rp_new(const uint8_t*s,size_t sn,const uint8_t*p,size_t pn,const uint8_t*r,size_t rn,uint32_t v,uint64_t*out){
 if(sn!=32||pn!=32||rn!=32||!s||!p||!r||(v!=2&&v!=3)||!memcmp(p,r,32))return -1;*out=next++;return 0;
}
int32_t routervpn_rp_step(uint64_t h,uint32_t k,const uint8_t*in,size_t n,uint8_t*out,size_t cap,size_t*size,uint8_t*key,size_t kc,uint32_t*flags,uint64_t*wait){
 if(!h||k>2||cap<1024||kc!=32)return -1;
 *size=0;*flags=0;*wait=1;
 unsigned int test=n?in[0]:0;
 switch(test){
 case 1:*flags=1;memset(key,7,32);memcpy(out,"test",4);*size=4;break;
 case 2:*flags=2;break;
 case 3:return -2;
 case 4:memset(key,9,32);return -1;
 case 5:*flags=3;break;
 case 6:*wait=1001;break;
 case 7:*size=cap+1;break;
 case 8:*flags=1;return -2;
 case 9:memset(key,9,32);break;
 }
 return 0;
}
int32_t routervpn_rp_close(uint64_t h){return h?0:-1;}
'''
C_TEST=r'''
#include "routervpn_pq_host.h"
#include <assert.h>
#include <string.h>
int main(void){
 uint8_t out[ROUTERVPN_PQ_FRAME_CAPACITY],in=1;size_t n=0;
 assert(routervpn_pq_event(1,1,&in,1,out,sizeof(out),&n)==0 && n==48 && out[8]==1 && out[12]==7 && out[44]=='t');
 for(in=4;in<=8;in++){memset(out,9,sizeof(out));assert(routervpn_pq_event(1,1,&in,1,out,sizeof(out),&n)==-1 && n==0);for(size_t i=0;i<sizeof(out);i++)assert(out[i]==0);}
 in=3;assert(routervpn_pq_event(1,1,&in,1,out,sizeof(out),&n)==0 && n==44 && out[0]==254);
 in=9;assert(routervpn_pq_event(1,1,&in,1,out,sizeof(out),&n)==0);for(size_t i=12;i<44;i++)assert(out[i]==0);
 assert(routervpn_pq_event(1,3,0,0,out,sizeof(out),&n)==-1);
 assert(routervpn_pq_event(0,0,0,0,out,sizeof(out),&n)==-1);
 assert(routervpn_pq_event(1,0,&in,1,out,sizeof(out),&n)==-1);
 assert(routervpn_pq_event(1,1,0,1,out,sizeof(out),&n)==-1);
 assert(routervpn_pq_event(1,0,0,0,out,44,&n)==-1);
 return 0;
}
'''
JAVA_STUBS={
'RouterPQFactory.java':'package io.nekohasekai.libbox; public interface RouterPQFactory {RouterPQProtocol createProtocol(byte[]s,byte[]p,byte[]r,int v)throws Exception;}',
'RouterPQProtocol.java':'package io.nekohasekai.libbox; public interface RouterPQProtocol {RouterPQEvent processEvent(int kind,byte[] packet)throws Exception;void stop()throws Exception;}',
'RouterPQEvent.java':'''package io.nekohasekai.libbox; public class RouterPQEvent {
 public byte[] packet,key; public int wait;public boolean rejected,expired;
 public void setPacket(byte[]p){packet=p.clone();} public void setKey(byte[]k){key=k.clone();}
 public void setWaitMilliseconds(int w){wait=w;}public void setRejected(boolean r){rejected=r;}public void setExpired(boolean e){expired=e;}}
''',
'Libbox.java':'package io.nekohasekai.libbox; public class Libbox {public static int installs;public static void routerInstallPQFactory(RouterPQFactory f){if(++installs!=1)throw new AssertionError();}}'
}
JAVA_TEST=r'''
package com.eabusham.routervpn;
import java.util.*;import java.io.*;import java.nio.*;import io.nekohasekai.libbox.*;
public class TestPQHost {
 static void check(boolean b){if(!b)throw new AssertionError();}
 public static void main(String[]args)throws Exception{
  RouterPQNative.install();RouterPQNative.install();check(Libbox.installs==1);
  byte[] s=new byte[32],p=new byte[32],r=new byte[32];Arrays.fill(s,(byte)1);Arrays.fill(p,(byte)2);Arrays.fill(r,(byte)3);
  RouterPQProtocol a=new RouterPQNative().createProtocol(s,p,r,2);
  RouterPQEvent key=a.processEvent(1,new byte[]{1});check(key.key[0]==7&&key.packet.length==4&&!key.expired);
  check(a.processEvent(1,new byte[]{2}).expired);check(a.processEvent(1,new byte[]{3}).rejected);
  for(int n=4;n<=8;n++){try{a.processEvent(1,new byte[]{(byte)n});throw new AssertionError();}catch(IOException expected){}}
  for(int flags:new int[]{3,4,255}){
   byte[] b=new byte[44];ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).putInt(8,flags);
   try{RouterPQNative.decode(b);throw new AssertionError();}catch(IOException expected){}
   for(byte x:b)check(x==0);
  }
  for(int len:new int[]{0,43,65580}){byte[] b=new byte[len];Arrays.fill(b,(byte)9);try{RouterPQNative.decode(b);throw new AssertionError();}catch(IOException expected){}for(byte x:b)check(x==0);}
  byte[] b=new byte[44];b[12]=7;try{RouterPQNative.decode(b);throw new AssertionError();}catch(IOException expected){}for(byte x:b)check(x==0);
  Thread[] threads=new Thread[20];for(int i=0;i<threads.length;i++){threads[i]=new Thread(()->{try{a.stop();}catch(Exception e){throw new AssertionError(e);}});threads[i].start();}for(Thread t:threads)t.join();
  try{a.processEvent(0,new byte[0]);throw new AssertionError();}catch(IOException expected){}
  RouterPQProtocol next=new RouterPQNative().createProtocol(s,p,r,3);check(next.processEvent(1,new byte[]{1}).key[0]==7);next.stop();
  System.out.println("Java/JNI host, decoding, cancellation and owner isolation passed");
 }
}
'''
SWIFT_LIBBOX=r'''
import Foundation
public protocol LibboxRouterPQFactoryProtocol {func createProtocol(_ secretKey:Data?,publicKey:Data?,peerKey:Data?,version:Int32)throws->any LibboxRouterPQProtocolProtocol}
public protocol LibboxRouterPQProtocolProtocol {func processEvent(_ kind:Int32,packet:Data?)throws->LibboxRouterPQEvent;func stop()throws}
public class LibboxRouterPQEvent {public init(){};public var waitMilliseconds:Int32=0;public var rejected=false;public var expired=false;public var key:Data?;public var packet:Data?}
public func LibboxRouterInstallPQFactory(_ factory:any LibboxRouterPQFactoryProtocol,_ error:UnsafeMutablePointer<NSError?>?) {}
'''
SWIFT_TEST=r'''
import Foundation
import Libbox
@main struct Test {
 static func main()throws{
  try RouterVPNPQFactory.install();try RouterVPNPQFactory.install()
  let s=Data(repeating:1,count:32),p=Data(repeating:2,count:32),r=Data(repeating:3,count:32)
  let a=try RouterVPNPQFactory().createProtocol(s,publicKey:p,peerKey:r,version:2)
  let event=try a.processEvent(1,packet:Data([1]));precondition(event.key==Data(repeating:7,count:32)&&event.packet==Data("test".utf8))
  let expired=try a.processEvent(1,packet:Data([2]));precondition(expired.expired)
  let rejected=try a.processEvent(1,packet:Data([3]));precondition(rejected.rejected)
  for n in 4...8 {do{_ = try a.processEvent(1,packet:Data([UInt8(n)]));fatalError("invalid native event accepted")}catch{}}
  for flags:UInt8 in [3,4,255] {var b=[UInt8](repeating:0,count:44);b[8]=flags;do{_ = try RouterVPNPQProtocol.decode(b,size:44);fatalError()}catch{}}
  try a.stop();try a.stop();do{_ = try a.processEvent(0,packet:nil);fatalError("stale owner accepted")}catch{}
  let next=try RouterVPNPQFactory().createProtocol(s,publicKey:p,peerKey:r,version:3)
  let key=try next.processEvent(1,packet:Data([1]));precondition(key.key==Data(repeating:7,count:32));try next.stop()
  print("Swift/C host, decoding, cancellation and owner isolation passed")
 }
}
'''
class PythonBootstrap(unittest.TestCase):
    def test_current_supported_python_is_not_restarted(self):
        with mock.patch.object(B.sys, 'version_info', (3, 11)), mock.patch.object(B.os, 'execv') as execute:
            B.ensure_python()
            execute.assert_not_called()

    def test_xcode_system_python_uses_checked_homebrew_interpreter(self):
        # Build a real Homebrew-style symlink. This must exercise canonical
        # execution on Linux too, not depend on the runner's installed version.
        with tempfile.TemporaryDirectory(prefix='pq interpreter ') as tmp:
            root = Path(tmp)
            modern = root/'Cellar/python/bin/python3'
            modern.parent.mkdir(parents=True)
            modern.write_text('test-only interpreter; execution is mocked')
            alias = root/'bin/python3'
            alias.parent.mkdir()
            alias.symlink_to(modern)
            current = root/'system/python3'
            current.parent.mkdir()
            current.write_text('test-only old interpreter')
            canonical = str(modern.resolve())
            which = lambda name: {'python3': str(current), '/opt/homebrew/bin/python3': str(alias)}.get(name)
            with mock.patch.object(B.sys, 'version_info', (3, 9)), mock.patch.object(B.sys, 'executable', str(current)), \
                 mock.patch.object(B.sys, 'argv', ['build-mobile-pq.py', '--platform', 'ios', '--output', '/tmp/output with spaces']), \
                 mock.patch.dict(B.os.environ, {'ROUTER_VPN_PYTHON': ''}), mock.patch.object(B.shutil, 'which', side_effect=which), \
                 mock.patch.object(B.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as probe, \
                 mock.patch.object(B.os, 'execv', side_effect=SystemExit(0)) as execute:
                with self.assertRaises(SystemExit):
                    B.ensure_python()
                probe.assert_called_once()
                self.assertEqual(probe.call_args.args[0][0], canonical)
                self.assertIn('import sys, tomllib', probe.call_args.args[0][-1])
                self.assertEqual(probe.call_args.kwargs['timeout'], 5)
                execute.assert_called_once_with(canonical, [canonical, '-I', str(Path(B.__file__).resolve()), '--platform', 'ios', '--output', '/tmp/output with spaces'])

    def test_alias_of_current_interpreter_is_not_reprobed(self):
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp)/'python3'
            executable.write_text('test-only current interpreter')
            alias = Path(tmp)/'python-alias'
            alias.symlink_to(executable)
            with mock.patch.object(B.sys, 'version_info', (3, 9)), mock.patch.object(B.sys, 'executable', str(executable)), \
                 mock.patch.dict(B.os.environ, {'ROUTER_VPN_PYTHON': ''}), \
                 mock.patch.object(B.shutil, 'which', return_value=str(alias)), \
                 mock.patch.object(B.subprocess, 'run') as probe, mock.patch.object(B.os, 'execv') as execute:
                with self.assertRaisesRegex(RuntimeError, 'Python 3.11'):
                    B.ensure_python()
                probe.assert_not_called()
                execute.assert_not_called()

    def test_invalid_explicit_interpreter_does_not_silently_fallback(self):
        with mock.patch.object(B.sys, 'version_info', (3, 9)), \
             mock.patch.dict(B.os.environ, {'ROUTER_VPN_PYTHON': '/chosen/python'}), \
             mock.patch.object(B.shutil, 'which', return_value='/chosen/python') as which, \
             mock.patch.object(B.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1)), \
             mock.patch.object(B.os, 'execv') as execute:
            with self.assertRaisesRegex(RuntimeError, 'Python 3.11'):
                B.ensure_python()
            which.assert_called_once_with('/chosen/python')
            execute.assert_not_called()

    def test_interpreter_probe_is_bounded_and_no_candidate_is_not_success(self):
        for failure in (OSError('missing'), subprocess.TimeoutExpired('python3', 5)):
            with self.subTest(failure=failure), mock.patch.object(B.sys, 'version_info', (3, 9)), \
                 mock.patch.dict(B.os.environ, {'ROUTER_VPN_PYTHON': '/chosen/python'}), \
                 mock.patch.object(B.shutil, 'which', return_value='/chosen/python'), \
                 mock.patch.object(B.subprocess, 'run', side_effect=failure), mock.patch.object(B.os, 'execv') as execute:
                with self.assertRaisesRegex(RuntimeError, 'Python 3.11'):
                    B.ensure_python()
                execute.assert_not_called()

class OutputPublication(unittest.TestCase):
    @staticmethod
    def fake_native(stage, cache):
        for abi, _, _ in B.ANDROID:
            p = stage/'jni'/abi/'libroutervpn_rosenpass_jni.so'
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b'test-only-native-payload')

    def build(self, output):
        with mock.patch.object(B, 'ensure_tools'), mock.patch.object(B, 'android_build', side_effect=self.fake_native):
            B.build('android', output)

    def test_gradle_precreated_empty_output_and_cached_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'native'
            (output/'jni').mkdir(parents=True)
            self.build(output)
            self.assertTrue(B.verify(output, 'android', B.source_digest()))
            with mock.patch.object(B, 'ensure_tools') as tools, mock.patch.object(B, 'android_build') as compiler:
                B.build('android', output)
                tools.assert_not_called()
                compiler.assert_not_called()

    def test_unknown_files_and_final_symlinks_survive_preflight(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'native';output.mkdir()
            keep = output/'keep.txt';keep.write_text('unrelated')
            for path in (output, Path(tmp)/'linked'):
                if path != output:
                    path.symlink_to(output, target_is_directory=True)
                with mock.patch.object(B, 'ensure_tools') as tools:
                    with self.assertRaisesRegex(RuntimeError, 'unowned'):
                        B.build('android', path)
                    tools.assert_not_called()
                self.assertEqual(keep.read_text(), 'unrelated')
            self.assertTrue((Path(tmp)/'linked').is_symlink())

    def test_owned_artifact_rebuild_and_failed_publish_restore_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'native';self.build(output)
            original = {str(p.relative_to(output)): p.read_bytes() for p in output.rglob('*') if p.is_file()}
            stage = Path(tmp)/'replacement';stage.mkdir();self.fake_native(stage, Path(tmp))
            (stage/'source.json').write_bytes((output/'source.json').read_bytes())
            replace = os.replace
            calls = []
            def fail_publication(source, target):
                calls.append((source, target))
                if source == stage:
                    raise OSError('simulated publication failure')
                return replace(source, target)
            with mock.patch.object(B.os, 'replace', side_effect=fail_publication):
                with self.assertRaisesRegex(OSError, 'simulated'):
                    B.publish_output(stage, output, 'android')
            self.assertEqual(len(calls), 3)
            self.assertEqual(original, {str(p.relative_to(output)): p.read_bytes() for p in output.rglob('*') if p.is_file()})
            B.publish_output(stage, output, 'android')
            self.assertTrue(B.verify(output, 'android', B.source_digest()))

    def test_extra_file_invalid_marker_and_manifest_escape_are_not_owned(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'native';self.build(output)
            marker = output/'source.json';original = marker.read_text()
            extra = output/'keep.txt';extra.write_text('unrelated')
            with self.assertRaisesRegex(RuntimeError, 'unowned'):
                B.output_state(output, 'android')
            self.assertEqual(extra.read_text(), 'unrelated');extra.unlink()
            for content in ('{}', '{invalid', json.dumps({'schema':1, 'platform':'android', 'files':{'../outside':'0'*64}})):
                marker.write_text(content)
                with self.assertRaisesRegex(RuntimeError, 'unowned'):
                    B.output_state(output, 'android')
            marker.write_text(original)
            self.assertEqual(B.output_state(output, 'android'), 'owned')
            linked = output/'linked';linked.symlink_to(marker)
            with self.assertRaisesRegex(RuntimeError, 'unowned'):
                B.output_state(output, 'android')

    def test_invalid_staging_does_not_remove_previous_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)/'native';self.build(output)
            marker = output/'source.json';old = json.loads(marker.read_text());old['source_sha256'] = '0'*64
            marker.write_text(json.dumps(old));saved = marker.read_bytes()
            with mock.patch.object(B, 'ensure_tools'), mock.patch.object(B, 'android_build'):
                with self.assertRaisesRegex(RuntimeError, 'verification failed'):
                    B.build('android', output)
            self.assertEqual(marker.read_bytes(), saved)

class Hosts(unittest.TestCase):
    def setup_sources(self,work):
        (work/'fake.c').write_text(FAKE)
        return [str(S/'routervpn_pq_host.c'),str(work/'fake.c'),'-I'+str(S)]
    def test_c_abi_frame_under_sanitizers(self):
        with tempfile.TemporaryDirectory() as tmp:
            w=Path(tmp);sources=self.setup_sources(w);(w/'test.c').write_text(C_TEST)
            subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',*sources,str(w/'test.c'),'-o',str(w/'test')],check=True)
            subprocess.run([str(w/'test')],check=True)
    def test_java_and_actual_jni(self):
        with tempfile.TemporaryDirectory() as tmp:
            w=Path(tmp);sources=self.setup_sources(w)
            java_home=Path(os.environ.get('JAVA_HOME') or Path(shutil.which('javac')).resolve().parents[1])
            include=java_home/'include';system='darwin' if os.uname().sysname=='Darwin' else 'linux'
            lib=w/('libroutervpn_rosenpass_jni.dylib' if system=='darwin' else 'libroutervpn_rosenpass_jni.so')
            subprocess.run(['clang','-std=c11','-Wall','-Wextra','-Werror','-fPIC','-shared',*sources,str(S/'routervpn_pq_jni.c'),'-I'+str(include),'-I'+str(include/system),'-o',str(lib)],check=True)
            files=[]
            for name,body in JAVA_STUBS.items():
                p=w/'io/nekohasekai/libbox'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(body);files.append(str(p))
            app=w/'com/eabusham/routervpn';app.mkdir(parents=True)
            (app/'RouterPQNative.java').write_bytes((ROOT/'android/app/src/main/java/com/eabusham/routervpn/RouterPQNative.java').read_bytes());(app/'TestPQHost.java').write_text(JAVA_TEST)
            subprocess.run(['javac','-d',str(w),*files,*map(str,app.glob('*.java'))],check=True)
            subprocess.run(['java','-Djava.library.path='+str(w),'-cp',str(w),'com.eabusham.routervpn.TestPQHost'],check=True)
    def test_actual_swift_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            w=Path(tmp);sources=self.setup_sources(w)
            module=w/'RouterVPNPQ';module.mkdir()
            for name in ('routervpn_pq_host.h','routervpn_rosenpass.h'):(module/name).write_bytes((S/name).read_bytes())
            (module/'module.modulemap').write_text('module RouterVPNPQ { header "routervpn_pq_host.h" export * }')
            for src,name in [(S/'routervpn_pq_host.c','host'),(w/'fake.c','fake')]:subprocess.run(['clang','-std=c11','-c',str(src),'-I'+str(S),'-o',str(w/(name+'.o'))],check=True)
            (w/'Libbox.swift').write_text(SWIFT_LIBBOX);(w/'Test.swift').write_text(SWIFT_TEST)
            ext='dylib' if os.uname().sysname=='Darwin' else 'so'
            subprocess.run(['swiftc','-swift-version','6','-emit-module','-emit-library','-module-name','Libbox',str(w/'Libbox.swift'),'-o',str(w/('libLibbox.'+ext)),'-emit-module-path',str(w/'Libbox.swiftmodule')],check=True)
            subprocess.run(['swiftc','-swift-version','6','-I',str(w),'-L',str(w),'-lLibbox','-Xlinker','-rpath','-Xlinker',str(w),str(ROOT/'ios/RouterVPN/PacketTunnel/RouterVPNPQFactory.swift'),str(w/'Test.swift'),str(w/'host.o'),str(w/'fake.o'),'-o',str(w/'test')],check=True)
            subprocess.run([str(w/'test')],check=True)
    def test_locked_build_and_cache_integrity(self):
        self.assertEqual(len(B.validate_lock()),64)
        self.assertEqual(len(B.ANDROID),4);self.assertEqual(len(B.APPLE),3)
        self.assertIn('--locked',Path(B.__file__).read_text())
        with tempfile.TemporaryDirectory() as tmp:
            w=Path(tmp);meta={'schema':1,'source_sha256':B.source_digest(),'platform':'android','rust':B.RUST,'cargo_lock_sha256':B.validate_lock(),'files':{}}
            for abi,_,_ in B.ANDROID:
                p=w/'jni'/abi/'libroutervpn_rosenpass_jni.so';p.parent.mkdir(parents=True);p.write_bytes(b'test-only-elf')
                meta['files'][str(p.relative_to(w))]=B.hashlib.sha256(p.read_bytes()).hexdigest()
            (w/'source.json').write_text(json.dumps(meta));self.assertTrue(B.verify(w,'android',B.source_digest()))
            p.write_bytes(b'corrupted');self.assertFalse(B.verify(w,'android',B.source_digest()))
            self.assertFalse(B.verify(w,'ios',B.source_digest()))
if __name__=='__main__':unittest.main()
