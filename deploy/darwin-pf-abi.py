#!/usr/bin/env python3
"""Verify the exact unmodified Apple private PF userland header dependency.

The manifest is a review artifact, not mutable hash authority. The pinned source
identity and byte digests below must agree with it and the actual source files.
"""
from pathlib import Path
import hashlib
import json
import stat

COMMIT = '43a90889846e00bfb5cf1d255cdc0a701a1e05a4'
DIRECTORY = 'desktop_socket_darwin_pfabi'
PINNED = {
    'net/pfvar.h': ('bsd/net/pfvar.h',
                    'aeaaa90c761577247bfa0328bd4765512f787f5af9a56b9bb530030c90a692c9',
                    '691a4e711f5c8ec77184d575e4ffebb9ce41d772'),
    'libkern/tree.h': ('libkern/libkern/tree.h',
                       'ae6e463397b9fe9a0de1d509a5fda87d388da56010442302d18efe77efbdd4b1',
                       'f728efcf33a5cc46a7ecae09c77be4b626c11378'),
    'APPLE_LICENSE': ('APPLE_LICENSE',
                       'e5881019d8766c1e88a5fe1dbca4ba40c78011d41fcb18f6e9f50df60182685b',
                       'fe81a60cae982c042a69f97623b427666c455093'),
}
MANIFEST = {
    'schema_version': 1,
    'repository': 'apple-oss-distributions/xnu',
    'tag': 'xnu-11417.140.69',
    'commit': COMMIT,
    'status': 'Unmodified primary-source private userland ABI headers; this is not a public SDK API. Native kernel acceptance is required.',
    'files': {name: {'source': source,
                     'url': 'https://github.com/apple-oss-distributions/xnu/blob/'+COMMIT+'/'+source,
                     'sha256': digest, 'git_blob': blob}
              for name, (source, digest, blob) in PINNED.items()},
}


def regular(root, name):
    current = root
    if current.is_symlink() or not current.is_dir():
        raise ValueError('Private PF dependency root is not a regular directory')
    parts = Path(name).parts
    for index, part in enumerate(parts):
        current = current/part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or (index < len(parts)-1 and not stat.S_ISDIR(info.st_mode)):
            raise ValueError('Private PF dependency contains a linked or non-directory ancestor')
    if not stat.S_ISREG(info.st_mode) or info.st_size > 1024*1024:
        raise ValueError('Private PF dependency is not a bounded regular file')
    return current.read_bytes()


def checked_files(mobiletor):
    """Return exact relative copy inputs; reject unknown, changed or linked files."""
    mobiletor = Path(mobiletor)
    root = mobiletor/DIRECTORY
    expected = {*PINNED, 'UPSTREAM.json', 'README.md'}
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Private PF source dependency is absent or linked')
    files = set()
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('Private PF dependency contains a linked input')
        if path.is_file():
            files.add(path.relative_to(root).as_posix())
        elif not path.is_dir() or path.relative_to(root).as_posix() not in {'net', 'libkern'}:
            raise ValueError('Private PF dependency contains an undeclared input')
    if files != expected:
        raise ValueError('Private PF dependency source/license closure differs')
    result = {}
    for name in sorted(expected):
        raw = regular(root, name)
        if name in PINNED:
            _, digest, blob = PINNED[name]
            actual_blob = hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
            if hashlib.sha256(raw).hexdigest() != digest or actual_blob != blob:
                raise ValueError('Pinned Apple PF dependency bytes differ: '+name)
        elif name == 'UPSTREAM.json':
            if raw != (json.dumps(MANIFEST, indent=2)+'\n').encode():
                raise ValueError('Pinned Apple PF dependency manifest differs')
        result[DIRECTORY+'/'+name] = raw
    result['desktop_socket_darwin_pfabi.h'] = regular(mobiletor, 'desktop_socket_darwin_pfabi.h')
    return result


# This fixture exists only as a temporary Go overlay; shipping code has no scope override.
NATIVE_SMOKE_SOURCE = r'''
//go:build darwin && cgo && routervpn_darwin_guardian

package mobiletor

import (
 "bytes"
 "context"
 "crypto/rand"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net"
 "net/netip"
 "os"
 "os/exec"
 "os/signal"
 "path/filepath"
 "regexp"
 "strconv"
 "syscall"
 "testing"
 "time"
)

const pfSmokeRoot = @ROOT@
const pfSmokeAddress = @ADDRESS@
const pfSmokeNamespace = @NAMESPACE@
const pfSmokeSource = @SOURCE@

func TestMain(_ *testing.M) {
 desktopDarwinPFNamespace = pfSmokeNamespace
 desktopDarwinPFTestScope = "on lo0 to " + pfSmokeAddress
 desktopDarwinPFTestAddresses = []netip.Addr{netip.MustParseAddr(pfSmokeAddress)}
 desktopDarwinIdentities = pfSmokeRoot + "/identities"
 if len(os.Args) == 3 && os.Args[1] == "routervpn-owned-socket-helper" {
  if err := RunDesktopDarwinSocketHelper(os.Args[2]); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
  os.Exit(0)
 }
 if len(os.Args) != 2 || os.Args[1] != "--native-smoke" { os.Exit(2) }
 parent, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
 ctx, cancel := context.WithTimeout(parent, 90*time.Second)
 err := pfSmokeRun(ctx)
 cancel(); stop()
 if err != nil { fmt.Fprintln(os.Stderr, "Native macOS PF component failed:", err); os.Exit(1) }
 os.Exit(0)
}

func pfSmokeCommand(ctx context.Context, path string, arguments ...string) ([]byte, error) {
 if err := desktopDarwinProtectedPath(path, false); err != nil { return nil, err }
 command := exec.CommandContext(ctx, path, arguments...)
 output := desktopDarwinCommandBuffer{limit: 8192}
 command.Stdout, command.Stderr = &output, &output
 command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
 command.WaitDelay = time.Second
 err := command.Run()
 return output.Bytes(), errors.Join(err, ctx.Err())
}

func pfSmokeProbe(packet net.PacketConn, target net.Addr, allowed bool) error {
 token := make([]byte, 32)
 if _, err := rand.Read(token); err != nil { return err }
 if err := packet.SetDeadline(time.Now().Add(600*time.Millisecond)); err != nil { return err }
 n, err := packet.WriteTo(token, target)
 if err == nil && n != len(token) { return io.ErrShortWrite }
 var source net.Addr
 response := make([]byte, 64)
 if err == nil { n, source, err = packet.ReadFrom(response) }
 if err == nil {
  if !allowed { return errors.New("ungranted/revoked socket delivered real traffic") }
  if source.String() != target.String() || !bytes.Equal(response[:n], token) { return errors.New("live target returned another nonce or tuple") }
  return nil
 }
 if allowed { return err }
 var network net.Error
 if errors.As(err, &network) && network.Timeout() || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) { return nil }
 return fmt.Errorf("refusal was not an observed network denial: %w", err)
}

func pfSmokeRun(ctx context.Context) (failure error) {
 if os.Getuid() != 0 || os.Geteuid() != 0 { return errors.New("native PF component requires root") }
 executable, err := desktopDarwinExecutable()
 if err != nil || executable != pfSmokeRoot+"/native-pf-check" { return errors.Join(err, errors.New("fixture lost its protected executable")) }
 address := netip.MustParseAddr(pfSmokeAddress)
 iface, err := net.InterfaceByName("lo0")
 if err != nil { return err }
 addresses, err := net.InterfaceAddrs()
 if err != nil { return err }
 for _, value := range addresses {
  prefix, err := netip.ParsePrefix(value.String())
  if err != nil { return err }
  if prefix.Addr().WithZone("") == address { return errors.New("fixture address already has an owner") }
 }
 before := make(map[string]string)
 for _, kind := range []string{"rules", "nat"} {
  raw, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-s", kind)
  if err != nil { return err }; before[kind] = string(raw)
 }
 info, err := desktopDarwinCommand(ctx, "/sbin/pfctl", nil, "-s", "info")
 if err != nil { return err }
 enabled := regexp.MustCompile(`(?m)^Status:\s+Enabled\b`).Match(info)
 capture := DesktopSocketCapture{SessionID: @SESSION@, SourceSHA256: pfSmokeSource, NetworkID: @NETWORK@}
 var policy *DesktopDarwinSocketPolicy
 var created DesktopSocketCreated
 var packet, control net.PacketConn
 var target *net.UDPConn
 var worker chan struct{}
 var grant DesktopSocketGrant
 var baseline DesktopDarwinPFBaselineProof
 var token uint64
 aliasAttempted, baselineAttempted, grantAttempted := false, false, false
 stage := "preflight"
 defer func() {
  cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second); defer cancel()
  var retired error
  if grantAttempted && policy != nil { retired = errors.Join(retired, policy.Revoke(cleanup, grant)) }
  if packet != nil { retired = errors.Join(retired, packet.Close()) }
  if created.File != nil { retired = errors.Join(retired, created.File.Close()) }
  if policy != nil {
   if created.Creation.SocketID != "" { retired = errors.Join(retired, policy.ReleaseSocket(cleanup, created.Creation)) }
   retired = errors.Join(retired, policy.Close(cleanup))
  }
  if retired == nil && baselineAttempted {
   raw, encodeErr := EncodeDesktopDarwinPFBaselineRequest(DesktopDarwinPFBaselineRequest{Schema:1, Action:"clear", Expected:[]DesktopDarwinPFBaselineProof{baseline,{}}})
   if encodeErr != nil { retired = encodeErr } else { _, retired = RunDesktopDarwinPFBaseline(cleanup, raw, true) }
  }
  if policy != nil && retired == nil {
   retired = errors.Join(desktopDarwinNoUIDProcesses(policy.uid), desktopDarwinLocalIdentityAbsent(cleanup, policy.account, policy.uid))
   if _, err := os.Lstat(filepath.Join(desktopDarwinIdentities, policy.account)); !errors.Is(err, os.ErrNotExist) { retired = errors.Join(retired, errors.New("owned UID recovery record was not retired")) }
  }
  if token != 0 {
   present, err := desktopDarwinPFReferenceExists(cleanup, token)
   if err == nil && !present { err = errors.New("owned PF enable reference disappeared before release") }
   if err == nil { _, err = pfSmokeCommand(cleanup, "/sbin/pfctl", "-X", strconv.FormatUint(token,10)) }
   if err == nil { present, err = desktopDarwinPFReferenceExists(cleanup, token); if present { err = errors.New("owned PF enable reference remains") } }
   retired = errors.Join(retired, err)
  }
  if control != nil && target != nil { retired = errors.Join(retired, pfSmokeProbe(control, target.LocalAddr(), true)) }
  if control != nil { retired = errors.Join(retired, control.Close()) }
  if target != nil { retired = errors.Join(retired, target.Close()); select { case <-worker: case <-cleanup.Done(): retired = errors.Join(retired, cleanup.Err()) } }
  if aliasAttempted {
   current, err := net.InterfaceByIndex(iface.Index)
   if err == nil && current.Name != iface.Name { err = errors.New("owned loopback interface changed identity") }
   if err == nil {
    var captured []net.Addr
    captured, err = current.Addrs()
    present := false
    for _, value := range captured { prefix, parseErr := netip.ParsePrefix(value.String()); if parseErr != nil { err = errors.Join(err, parseErr) } else if prefix.Addr().WithZone("") == address { present = true } }
    if err == nil && present { _, err = pfSmokeCommand(cleanup, "/sbin/ifconfig", "lo0", "-alias", pfSmokeAddress) }
    if err == nil {
     captured, err = current.Addrs()
     for _, value := range captured { prefix, parseErr := netip.ParsePrefix(value.String()); if parseErr != nil { err = errors.Join(err, parseErr) } else if prefix.Addr().WithZone("") == address { err = errors.New("owned loopback alias was not retired") } }
    }
   }
   retired = errors.Join(retired, err)
  }
  for kind, expected := range before {
   raw, err := desktopDarwinCommand(cleanup, "/sbin/pfctl", nil, "-s", kind)
   if err == nil && string(raw) != expected { err = errors.New("global PF "+kind+" changed") }
   retired = errors.Join(retired, err)
  }
  info, err := desktopDarwinCommand(cleanup, "/sbin/pfctl", nil, "-s", "info")
  if err == nil && regexp.MustCompile(`(?m)^Status:\s+Enabled\b`).Match(info) != enabled { err = errors.New("PF enablement changed after releasing only the owned reference") }
  retired = errors.Join(retired, err)
  if baselineAttempted {
   present, err := desktopDarwinPFNamespacePresent(cleanup,pfSmokeNamespace)
   if err == nil && present { err = errors.New("owned PF namespace was not retired") }
   retired = errors.Join(retired,err)
  }
  if retired == nil {
   entries, err := os.ReadDir(desktopDarwinIdentities)
   if err == nil {
    if len(entries)!=1 || entries[0].Name()!="allocator.lock" { retired=errors.New("fixture identity directory retained an unknown or quarantined owner") } else {
     lock:=filepath.Join(desktopDarwinIdentities,"allocator.lock")
     retired=desktopDarwinProtectedPath(lock,true)
     if retired==nil { retired=os.Remove(lock) };if retired==nil { retired=os.Remove(desktopDarwinIdentities) }
    }
   } else if !errors.Is(err,os.ErrNotExist) { retired=err }
  }
  failure = errors.Join(failure, retired)
  if failure != nil { failure = fmt.Errorf("%s: %w", stage, failure); return }
  receipt := map[string]any{"scope":"native owned-UID UDP/IPv4 PF component; no UI or full-device VPN claim", "source_sha256":pfSmokeSource, "denied_before_grant":true, "nonce_payload_after_grant":true, "denied_after_revoke":true, "independent_control_alive":true, "native_close_and_uid_joined":true, "owned_pf_reference_released":true, "global_rules_unchanged":true, "global_states_flushed":false}
  encoded, _ := json.Marshal(receipt)
  fmt.Println("Native macOS PF component: "+string(encoded))
 }()
 present, err := desktopDarwinPFNamespacePresent(ctx, pfSmokeNamespace)
 if err != nil || present { return errors.Join(err, errors.New("fixture PF namespace already has an owner")) }
 aliasAttempted = true
 if _, err := pfSmokeCommand(ctx, "/sbin/ifconfig", "lo0", "alias", pfSmokeAddress, "netmask", "255.255.255.255"); err != nil { return err }
 target, err = net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(address,0)))
 if err != nil { return err }
 worker = make(chan struct{})
 go func() { defer close(worker); buffer := make([]byte,256); for { n, peer, err := target.ReadFromUDP(buffer); if err != nil { return }; if _, err := target.WriteToUDP(buffer[:n],peer); err != nil { return } } }()
 control, err = net.ListenPacket("udp4", netip.AddrPortFrom(address,0).String())
 if err != nil { return err }
 if err := pfSmokeProbe(control, target.LocalAddr(), true); err != nil { return err }
 stage = "PF enable and exact baseline"
 raw, enableErr := pfSmokeCommand(ctx, "/sbin/pfctl", "-E")
 match := regexp.MustCompile(`(?m)Token\s*:\s*([0-9]+)`).FindAllSubmatch(raw,-1)
 if len(match)==1 { token, err = strconv.ParseUint(string(match[0][1]),10,64) }
 if enableErr != nil || err != nil || token == 0 { return errors.Join(enableErr,err,errors.New("PF did not return its single owned enable reference")) }
 if present, err := desktopDarwinPFReferenceExists(ctx,token); err != nil || !present { return errors.Join(err,errors.New("owned PF reference was not independently present")) }
 request, err := EncodeDesktopDarwinPFBaselineRequest(DesktopDarwinPFBaselineRequest{Schema:1,Action:"replace",IsolatedOnly:true,SessionID:capture.SessionID,SourceSHA256:capture.SourceSHA256,Expected:[]DesktopDarwinPFBaselineProof{{}}})
 if err != nil { return err }
 raw, err = RunDesktopDarwinPFBaseline(ctx,request,false)
 if err != nil { return err }
 var plan DesktopDarwinPFBaselineResult
 if json.Unmarshal(raw,&plan)!=nil || !plan.Target.Present { return errors.New("native baseline plan did not retain its target") }
 baseline, baselineAttempted = plan.Target, true
 if _, err := RunDesktopDarwinPFBaseline(ctx,request,true); err != nil { return err }
 remote := target.LocalAddr().(*net.UDPAddr).AddrPort()
 options := DesktopDarwinSocketOptions{HostProtectionOff:true,Interfaces:[]DesktopDarwinSocketInterface{{Name:"lo0",Index:uint32(iface.Index),Address:address}},PrivateDestinations:[]DesktopDarwinSocketDestination{{Network:"udp",Address:remote}}}
 stage = "native UID guardian"
 policy, err = NewDesktopDarwinSocketPolicy(ctx,capture,options)
 if err != nil { return err }
 binding, err := policy.Select(ctx,capture,"udp",remote)
 if err != nil { return err }
 creation := DesktopSocketCreation{Capture:capture,Binding:binding,SocketID:@SOCKET@,Network:"udp"}
 stage = "native create and bind"
 created, err = policy.CreateSocket(ctx,creation)
 if err != nil { return err }
 if created.Creation != creation || created.File == nil || created.prebound == nil { return errors.New("native creation lost its original kernel owner") }
 packet, err = desktopSocketImportPacket(ctx,"udp",created.File,address,func(network, _ string, raw syscall.RawConn) error { return policy.Bind(ctx,capture,binding,network,raw) },created.prebound)
 if err != nil { return err }
 stage = "ungranted traffic denial"
 if err := pfSmokeProbe(packet,target.LocalAddr(),false); err != nil { return err }
 if err := pfSmokeProbe(control,target.LocalAddr(),true); err != nil { return err }
 local := packet.LocalAddr().(*net.UDPAddr).AddrPort()
 grant = DesktopSocketGrant{Capture:capture,Binding:binding,SocketID:creation.SocketID,Network:"udp",Local:local,Remote:remote,Sequence:1}
 stage = "native grant and live payload"
 grantAttempted = true
 receipt, err := policy.Grant(ctx,grant)
 if err != nil { return err }
 if receipt.Grant != grant || !policy.Current(capture,binding.Owner) { return errors.New("grant receipt changed its native owner") }
 if err := pfSmokeProbe(packet,target.LocalAddr(),true); err != nil { return err }
 stage = "native revoke and live-target denial"
 if err := policy.Revoke(ctx,grant); err != nil { return err }; grantAttempted = false
 if err := pfSmokeProbe(packet,target.LocalAddr(),false); err != nil { return err }
 if err := pfSmokeProbe(control,target.LocalAddr(),true); err != nil { return err }
 if !policy.Current(capture,binding.Owner) { return errors.New("denial came from a lost guardian") }
 stage = "exact native retirement"
 return nil
}
'''


def native_smoke(receipt_path):
    """Opt-in native owned-UID PF component proof, never a full VPN claim."""
    import os, platform, secrets, signal, subprocess, sys, tempfile
    if sys.platform != 'darwin' or os.environ.get('ROUTERVPN_DARWIN_NATIVE_HOST_ACCEPTANCE') != '1':
        raise RuntimeError('Native PF smoke requires the explicitly authorized disposable macOS host')
    root = Path(__file__).resolve().parents[1]
    source = root/'internal/mobiletor'
    checked_files(source)
    env = os.environ.copy()
    env.update(CGO_ENABLED='1', GOTOOLCHAIN='local', GOOS='darwin',
               GOARCH={'x86_64':'amd64','arm64':'arm64'}[platform.machine()])
    if subprocess.check_output(['go','env','GOVERSION'], env=env, text=True).strip() != 'go1.26.3':
        raise RuntimeError('Native PF fixture requires the pinned Go toolchain')
    subprocess.run(['git','diff','--exit-code','HEAD','--','internal/mobiletor','go.mod','go.sum','deploy/darwin-pf-abi.py'],cwd=root,check=True)
    source_sha = subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
    files = [*source.rglob('*.go'),*source.rglob('*.h'),root/'go.mod',root/'go.sum',Path(__file__).resolve()]
    hashes = {p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}
    source_digest = hashlib.sha256(json.dumps(hashes,sort_keys=True).encode()).hexdigest()
    suffix = secrets.token_hex(4)
    runtime = Path('/opt/routervpn-pf-smoke-'+suffix)
    values = {'ROOT':str(runtime),'ADDRESS':'127.249.'+str(int(suffix[:2],16))+'.'+str(1+int(suffix[2:4],16)%253),
              'NAMESPACE':'com.apple/000.t-'+suffix,'SOURCE':source_digest,
              'SESSION':secrets.token_hex(16),'NETWORK':secrets.token_hex(16),'SOCKET':secrets.token_hex(16)}
    fixture = NATIVE_SMOKE_SOURCE
    for name,value in values.items():
        fixture = fixture.replace('@'+name+'@',json.dumps(value))
    evidence = {'source_sha':source_sha,'source_sha256':source_digest,'source_files':hashes,
                'go_version':'go1.26.3','host_arch':env['GOARCH'],'scope':'native owned-UID UDP/IPv4 PF component',
                'status':'failed','fixture_source_sha256':hashlib.sha256(fixture.encode()).hexdigest()}
    receipt_path = Path(receipt_path).absolute()
    receipt_path.parent.mkdir(parents=True,exist_ok=True)
    installed = False
    try:
        with tempfile.TemporaryDirectory(prefix='routervpn-pf-smoke-') as directory:
            work = Path(directory)
            helper = work/'native-pf-smoke_test.go'; helper.write_text(fixture)
            overlay_path = source/'routervpn_pf_native_smoke_test.go'
            if overlay_path.exists() or overlay_path.is_symlink():
                raise RuntimeError('Native PF fixture overlay would replace a retained source file')
            overlay = work/'overlay.json'
            overlay.write_text(json.dumps({'Replace':{str(overlay_path):str(helper)}}))
            binary = work/'native-pf-check'
            subprocess.run(['go','test','-c','-mod=readonly','-trimpath','-buildvcs=false','-tags=routervpn_darwin_guardian',
                            '-overlay',str(overlay),'-o',str(binary),'./internal/mobiletor'],cwd=root,env=env,check=True,timeout=900)
            subprocess.run(['/usr/bin/codesign','--force','--sign','-',str(binary)],check=True,timeout=15)
            binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
            subprocess.run(['sudo','-n','/bin/mkdir','-m','755',str(runtime)],check=True,timeout=10)
            installed = True
            original = runtime.lstat()
            subprocess.run(['sudo','-n','/usr/bin/install','-m','755',str(binary),str(runtime/binary.name)],check=True,timeout=10)
            if hashlib.sha256((runtime/binary.name).read_bytes()).hexdigest() != binary_sha:
                raise RuntimeError('Protected native PF executable differs from its captured build')
            evidence['binary_sha256'] = binary_sha
            log_path = work/'native.log'
            with log_path.open('wb') as log:
                process = subprocess.Popen(['sudo','-n',str(runtime/binary.name),'--native-smoke'],
                                           stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
                try:
                    code = process.wait(timeout=125)
                except subprocess.TimeoutExpired:
                    # Signal only this newly created process group; the helper's
                    # cancellation path performs its bounded original-owner drain.
                    for name,wait in (('TERM',25),('KILL',5)):
                        if process.poll() is not None: break
                        if os.getpgid(process.pid) != process.pid:
                            raise RuntimeError('Native PF timeout lost its original process group')
                        subprocess.run(['sudo','-n','/bin/kill','-'+name,'--','-'+str(process.pid)],check=True,timeout=5)
                        try: process.wait(timeout=wait)
                        except subprocess.TimeoutExpired: pass
                    raise RuntimeError('Native PF component exceeded its original bounded lifetime')
                finally:
                    output = log_path.read_bytes()[-65536:].decode('utf-8',errors='replace')
                    print(output,end='',flush=True)
                    evidence['exit_code'] = process.returncode
                    evidence['native_log_tail'] = output
            results = [line.removeprefix('Native macOS PF component: ') for line in output.splitlines()
                       if line.startswith('Native macOS PF component: ')]
            if code != 0 or len(results) != 1:
                raise RuntimeError('Native PF lifecycle did not produce its joined positive/negative proof')
            proof = json.loads(results[0])
            if proof.get('source_sha256') != source_digest or any(proof.get(name) is not True for name in
                    ('denied_before_grant','nonce_payload_after_grant','denied_after_revoke','independent_control_alive',
                     'native_close_and_uid_joined','owned_pf_reference_released','global_rules_unchanged')):
                raise RuntimeError('Native PF component omitted an original lifecycle proof')
            current = runtime.lstat()
            if (current.st_dev,current.st_ino,current.st_uid,current.st_mode) != (original.st_dev,original.st_ino,original.st_uid,original.st_mode):
                raise RuntimeError('Protected native PF fixture directory changed identity')
            # No recursive removal: an unknown or quarantined owner remains for
            # diagnosis and makes this job fail, rather than being erased.
            subprocess.run(['sudo','-n','/bin/rm',str(runtime/binary.name)],check=True,timeout=5)
            subprocess.run(['sudo','-n','/bin/rmdir',str(runtime)],check=True,timeout=5)
            installed = False
            evidence.update(status='passed',proof=proof)
    finally:
        evidence['protected_fixture_retained'] = str(runtime) if installed else None
        receipt_path.write_text(json.dumps(evidence,sort_keys=True,indent=2)+'\n')


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-smoke',action='store_true')
    parser.add_argument('--receipt',type=Path)
    args = parser.parse_args()
    if not args.native_smoke or args.receipt is None:
        parser.error('Use --native-smoke --receipt PATH only on an explicitly authorized native macOS build host')
    native_smoke(args.receipt)
