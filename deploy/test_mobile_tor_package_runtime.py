#!/usr/bin/env python3
"""Exercise the actual packaged Tor DSO, crypto isolation and shipping Go owner."""
from pathlib import Path
import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'mobile/torpack'
spec = importlib.util.spec_from_file_location('routervpn_tor_package', ROOT / 'deploy/build-mobile-tor-package.py')
PACKAGE = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PACKAGE)

DAEMON = r'''
#define _POSIX_C_SOURCE 200809L
#include "routervpn_tor_host.h"
#include <assert.h>
#include <stdio.h>
#include <time.h>
int main(int argc, char **argv) {
 assert(argc==2);
 char torrc[4096]; assert(snprintf(torrc,sizeof(torrc),"%s/empty",argv[1])>0);
 FILE *file=fopen(torrc,"w"); assert(file && fclose(file)==0);
 const char *args[]={"tor","--quiet","-f",torrc,"--defaults-torrc",torrc,"--DataDirectory",argv[1],
  "--ClientOnly","1","--DisableNetwork","1","--__DisableSignalHandlers","1","--SocksPort","0", "--RunAsDaemon","1"};
 uint64_t handle=0; assert(routervpn_tor_start(args,sizeof(args)/sizeof(args[0]),&handle)==0 && handle);
 int32_t code=0; int status=0;
 for(int i=0;i<500 && status==0;i++) { struct timespec delay={0,10000000L}; nanosleep(&delay,0); status=routervpn_tor_status(handle,&code); }
 assert(routervpn_tor_close(handle,5000)==0);
 assert(status==1 && code!=0);
 puts("PASS packaged Tor rejects daemon mode before native execution");
 return 0;
}
'''

POISON = r'''
#include <unistd.h>
int OPENSSL_init_crypto(unsigned long flags, const void *config) { (void)flags; (void)config; _exit(86); }
int OPENSSL_init_ssl(unsigned long flags, const void *config) { (void)flags; (void)config; _exit(86); }
unsigned long OpenSSL_version_num(void) { _exit(86); }
void *event_base_new(void) { _exit(86); }
const char *zlibVersion(void) { _exit(86); }
'''

REAL_GO = r'''
package torpackfixture
import (
 "context"
 "errors"
 "path/filepath"
 "testing"
 "time"
 "github.com/sagernet/sing-box/routervpn/nativetor"
 "router-vpn/internal/common"
 "router-vpn/internal/mobiletor"
)
func TestPackagedResidentTorThroughShippingOwner(t *testing.T) {
 if nativetor.ABI()!=1 || nativetor.Version()!=nativetor.RequiredVersion { t.Fatal("wrong linked source/ABI") }
 directory:=filepath.Join(t.TempDir(),"tor")
 if err:=mobiletor.PrepareState(directory);err!=nil { t.Fatal(err) }
 args,err:=mobiletor.ResidentArguments(directory);if err!=nil { t.Fatal(err) }
 instance,err:=nativetor.Start(args)
 if instance!=nil { t.Cleanup(func(){ ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel();if err:=instance.Close(ctx);err!=nil { t.Error(err) } }) }
 if err!=nil { t.Fatal(err) }
 connection,err:=instance.Control();if err!=nil { t.Fatal(err) }
 control,err:=mobiletor.NewControl(connection);if err!=nil { t.Fatal(err) }
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second);defer cancel()
 if err:=control.Quiesce(ctx);err!=nil { t.Fatal(err) }
 if other,err:=instance.Control();other!=nil || err==nil { t.Fatal("duplicate controller acquired") }
 if err:=control.Quiesce(ctx);err!=nil { t.Fatal("duplicate request destroyed resident control",err) }
 configs:=[]common.ExternalTorBridgeConfig{
  {Bridges:[]string{"obfs4 198.51.100.9:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=Y2VydA iat-mode=0"}},
  {Bridges:[]string{"meek_lite 192.0.2.2:2 url=https://bridge.example/ front=front.example"}},
 }
 for cycle:=0;cycle<32;cycle++ {
  plan,err:=mobiletor.NewPlan(configs[cycle%len(configs)]);if err!=nil { t.Fatal(err) }
  if err:=control.Configure(ctx,plan,map[string]string{plan.Transports()[0]:"127.0.0.1:18443"});err!=nil { t.Fatal(err) }
  state,err:=control.Bootstrap(ctx);if err!=nil { t.Fatal(err) }
  if state.CircuitEstablished || state.SOCKSAddress!="" { t.Fatal("offline fixture fabricated circuit/listener proof") }
  if err:=control.Quiesce(ctx);err!=nil { t.Fatal(err) }
 }
 if exited,_,err:=instance.Status();exited || err!=nil { t.Fatal("resident invocation was not retained",err) }
 if err:=control.Close();err!=nil { t.Fatal(err) }
 if err:=instance.Close(ctx);err!=nil { t.Fatal(err) }
 if exited,_,err:=instance.Status();!exited || !errors.Is(err,nativetor.ErrReleased) { t.Fatal("released handle status fabricated native exit code") }
 if next,err:=nativetor.Start(args);next!=nil || err==nil { t.Fatal("retired C runtime restarted") }
}
'''


def command(arguments, directory, env, expected=0, timeout=90):
    result = subprocess.run([str(value) for value in arguments], cwd=directory, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
    if result.returncode != expected:
        raise RuntimeError('Packaged native Tor runtime command failed:\n' + result.stdout[-9000:])
    return result.stdout


def main(native_package, go):
    native_package = native_package.resolve()
    PACKAGE.verify(native_package, 'host-test')
    if not go or not shutil.which('cc'):
        raise RuntimeError('Go and a C compiler are required for packaged native Tor runtime proof')
    with tempfile.TemporaryDirectory(prefix='routervpn-tor-package-runtime-') as temporary:
        root = Path(temporary)
        env = PACKAGE.base_env(root)
        for key in ('GOOS', 'GOARCH', 'GOARM', 'GOAMD64', 'GOFLAGS'):
            env.pop(key, None)
        compiler = shutil.which('cc')
        command([sys.executable, ROOT / 'deploy/test_mobile_tor_thread_signals.py', '--cc', compiler], root, env)
        print('PASS native Tor thread-local SIGPIPE protection under ASan/UBSan', flush=True)
        link = ['-L' + str(native_package / 'lib'), '-Wl,-rpath,' + str(native_package / 'lib'), '-lroutervpn_tor']
        common = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-pthread', '-I' + str(ROOT / 'mobile/tor')]
        fixture = root / 'native-host'
        command([*common, ROOT / 'mobile/tor/native_host_test.c', *link, '-o', fixture], root, env)
        for scenario in ('resident', 'failed-start', 'premature-stop', 'fd-reuse'):
            with tempfile.TemporaryDirectory(prefix=scenario + '-', dir=root) as directory:
                command([fixture, directory, scenario], root, env)
            print('PASS packaged pinned Tor C lifetime:', scenario, flush=True)
        (root / 'daemon.c').write_text(DAEMON)
        command([*common, root / 'daemon.c', *link, '-o', root / 'daemon'], root, env)
        with tempfile.TemporaryDirectory(prefix='daemon-', dir=root) as directory:
            command([root / 'daemon', directory], root, env)
        print('PASS packaged Tor rejects daemon mode', flush=True)
        (root / 'poison.c').write_text(POISON)
        poison = root / 'libothercrypto.so'
        command([compiler, '-std=c11', '-shared', '-fPIC', '-Wall', '-Wextra', '-Werror', root / 'poison.c', '-o', poison], root, env)
        poisoned = dict(env, LD_PRELOAD=str(poison))
        # Prove the deliberately incompatible symbols actually interpose under
        # the native linker before trusting the protected Tor positive case.
        (root / 'unprotected.c').write_text('extern unsigned long OpenSSL_version_num(void);\nint main(void){ return OpenSSL_version_num()==0; }\n')
        command([compiler, root / 'unprotected.c', '-L' + str(root), '-lothercrypto', '-Wl,-rpath,' + str(root), '-o', root / 'unprotected'], root, env)
        command([root / 'unprotected'], root, poisoned, expected=86)
        with tempfile.TemporaryDirectory(prefix='isolated-', dir=root) as directory:
            command([fixture, directory, 'resident'], root, poisoned)
        print('PASS actual dynamic crypto/event/zlib isolation with active incompatible-symbol negative', flush=True)
        native = root / 'native'; native.mkdir()
        (native / 'go.mod').write_text('module github.com/sagernet/sing-box/routervpn/nativetor\n\ngo 1.26.3\n')
        for name in ('native.go', 'backend.go', 'unavailable.go'):
            shutil.copyfile(SOURCE / (name + '.tmpl'), native / name)
        shutil.copyfile(ROOT / 'mobile/tor/routervpn_tor_host.h', native / 'routervpn_tor_host.h')
        fixture_go = root / 'go'; fixture_go.mkdir()
        (fixture_go / 'go.mod').write_text('module router-vpn/mobile/torpackfixture\n\ngo 1.26.3\n\n'
            'require (\n router-vpn v0.0.0\n github.com/sagernet/sing-box/routervpn/nativetor v0.0.0\n)\n'
            'replace router-vpn => ' + json.dumps(str(ROOT)) + '\n'
            'replace github.com/sagernet/sing-box/routervpn/nativetor => ' + json.dumps(str(native)) + '\n')
        (fixture_go / 'native_test.go').write_text(REAL_GO)
        env.update(CGO_ENABLED='1', CC=compiler, GOTOOLCHAIN='local',
                   CGO_LDFLAGS=' '.join(link), GOCACHE=env.get('GOCACHE', str(root / 'go-cache')))
        command([go, 'test', '-race', '-mod=mod', '-count=1', '-tags=routervpn_tor_native_test', '-timeout=40s', './...'], fixture_go, env, timeout=120)
        print('PASS packaged Tor + unchanged Cgo owner + real shared controller: 32 network-disabled session resets, -race', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--go', default=shutil.which('go'))
    args = parser.parse_args()
    main(args.package, args.go)
