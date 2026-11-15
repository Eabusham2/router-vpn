#!/usr/bin/env python3
"""Execute the shipping bindExternal body with real captured policy/selection.

Only inherited-bootstrap authentication and the native child constructor are
fixture boundaries. Kernel/bootstrap acceptance remains the mandatory installed
Linux external host gate; this test does not claim kernel acceptance.
"""
from pathlib import Path
import argparse
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / 'mobile/desktop/external_control_linux.go.tmpl'

HEADER = r'''package main
import (
 "context"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "strings"
 "sync/atomic"
 "testing"
 mobilemultihop "router-vpn/internal/mobilemultihop"
 "router-vpn/internal/linuxprocess"
 "router-vpn/internal/linuxprotection"
)
var routerVPNExternalFailure = errors.New("original external failure")
type routerVPNLinuxNodeControl struct {
 policy any
 external *mobilemultihop.DesktopExternalPolicy
 control *linuxprotection.NodeControl
 retiring atomic.Bool
 authErr error
 authCalls int
 commandHash string
 bootstrap *linuxprocess.Bootstrap
 selection linuxprotection.NodeSelection
 selectionHash string
}
func (o *routerVPNLinuxNodeControl) original(ctx context.Context) error {
 o.authCalls++
 return errors.Join(ctx.Err(),o.authErr)
}
var construct func(context.Context,*linuxprocess.Bootstrap,linuxprotection.NodeSelection)(*linuxprotection.NodeControl,error)
func fixtureNewNodeChildControl(ctx context.Context,b *linuxprocess.Bootstrap,s linuxprotection.NodeSelection)(*linuxprotection.NodeControl,error) { return construct(ctx,b,s) }
'''
TEST = r'''
func TestActualLinuxExternalBinding(t *testing.T) {
 var fixtures map[string]struct{ Source,Capture,Target string; Allowed bool }
 body,err:=os.ReadFile(filepath.Join(os.Getenv("ROUTERVPN_LINUX_EXTERNAL_ADMISSION_FIXTURES"),"captures.json"))
 if err!=nil || json.Unmarshal(body,&fixtures)!=nil || len(fixtures)<20 {t.Fatal("missing actual policy captures",err)}
 for name,f:=range fixtures { t.Run(name,func(t *testing.T){
  original,err:=mobilemultihop.NewExternalPolicy(f.Source,f.Capture); if err!=nil {t.Fatal(err)}
  policy,err:=mobilemultihop.NewDesktopExternalPolicy(original,strings.Repeat("a",32),f.Target); if err!=nil {t.Fatal(err)}
  meta:=policy.Metadata()
  selection:=linuxprotection.NodeSelection{SessionID:meta.SessionID,SourceSHA256:meta.SourceSHA256,ConfigSHA256:meta.ConfigSHA256,Policy:meta.KillSwitchPolicy,HomeLAN:meta.HomeLANAccess}
  command,_:=selection.CaptureSHA256(); transfer,_:=selection.ControlSHA256()
  for _,fault:=range []string{"","foreign-source","foreign-config","foreign-transfer","foreign-command","foreign-original","auth-refused","cancelled","retiring","bound-policy","bound-external","bound-control","native-refused"} {
   t.Run(fault,func(t *testing.T){
    ctx,cancel:=context.WithCancel(context.Background());defer cancel()
    bootstrap:=&linuxprocess.Bootstrap{}
    owner:=&routerVPNLinuxNodeControl{commandHash:command,bootstrap:bootstrap}
    source,config,selected:=meta.SourceSHA256,meta.ConfigSHA256,transfer
    captured:=original
    switch fault {
    case "foreign-source":source=strings.Repeat("b",64)
    case "foreign-config":config=strings.Repeat("b",64)
    case "foreign-transfer":selected=strings.Repeat("b",64)
    case "foreign-command":owner.commandHash=strings.Repeat("b",64)
    case "foreign-original":captured,_=mobilemultihop.NewExternalPolicy(f.Source,f.Capture)
    case "auth-refused":owner.authErr=errors.New("original bootstrap refused")
    case "cancelled":cancel()
    case "retiring":owner.retiring.Store(true)
    case "bound-policy":owner.policy=struct{}{}
    case "bound-external":owner.external=policy
    case "bound-control":owner.control=&linuxprotection.NodeControl{}
    }
    previousExternal,previousControl:=owner.external,owner.control
    calls:=0; native:=&linuxprotection.NodeControl{}; refused:=errors.New("original native constructor refused")
    construct=func(c context.Context,b *linuxprocess.Bootstrap,s linuxprotection.NodeSelection)(*linuxprotection.NodeControl,error){
     calls++
     if c!=ctx || b!=bootstrap || s!=selection {t.Fatal("child substituted captured bootstrap/caller/selection")}
     if fault=="native-refused" {return nil,refused};return native,nil
    }
    err=owner.bindExternal(ctx,captured,policy,source,config,selected)
    if f.Allowed && fault=="" {
     if err!=nil || calls!=1 || owner.authCalls!=1 || owner.control!=native || owner.external!=policy || owner.selection!=selection || owner.selectionHash!=transfer {t.Fatal("supported retained graph failed actual child binding",err,calls)}
     if owner.bindExternal(ctx,captured,policy,source,config,selected)==nil || calls!=1 {t.Fatal("replayed binding replaced original owner")}
    } else {
     wantCalls:=0;if f.Allowed && fault=="native-refused" {wantCalls=1;if !errors.Is(err,refused){t.Fatal("native refusal replaced",err)}}
     if err==nil || calls!=wantCalls || owner.control!=previousControl || owner.external!=previousExternal || owner.selectionHash!="" {t.Fatal("rejected binding mutated ownership",err,calls,wantCalls)}
    }
   })
  }
 }) }
}
'''


def execute(go='go', template=TEMPLATE):
    source = Path(template).read_text()
    start = source.index('func (owner *routerVPNLinuxNodeControl) bindExternal(')
    end = source.index('\n}\n', start) + 3
    body = source[start:end]
    call = 'linuxprotection.NewNodeChildControl('
    if body.count(call) != 1:
        raise ValueError('shipping binding lost its sole native constructor')
    body = body.replace(call, 'fixtureNewNodeChildControl(')
    with tempfile.TemporaryDirectory(prefix='linux-external-binding-', dir=ROOT) as directory:
        directory = Path(directory)
        env = dict(os.environ, ROUTERVPN_LINUX_EXTERNAL_ADMISSION_FIXTURES=str(directory))
        subprocess.run([go, 'test', '-p=1', './internal/mobilemultihop', '-run', '^TestDesktopExternalLinuxControlledAdmission$', '-count=1', '-timeout=90s'], cwd=ROOT, env=env, check=True)
        (directory / 'binding_test.go').write_text(HEADER + body + TEST)
        subprocess.run([go, 'test', '-p=1', '-race', './' + directory.name, '-run', '^TestActualLinuxExternalBinding$', '-count=1', '-timeout=90s'], cwd=ROOT, env=env, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    parser.add_argument('--template', type=Path, default=TEMPLATE, help=argparse.SUPPRESS)
    args = parser.parse_args()
    execute(args.go, args.template)
