#!/usr/bin/env python3
"""Portable race execution of the actual Darwin admission/retirement helpers.

Only imports/build tags are projected. The complete shared execution compiler,
private workspace methods, process identity, startup and native cleanup state
machines remain shipping source. Native launch entry points are refusing doubles;
this is not installed process, PF, utun or macOS Server/Compare acceptance.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = 'router-vpn/darwinexecutionfixture'
CASES = {
    'TestRouterVPNNodeChainExecutionDarwinOriginalControl': ('server','auto','policy-pointer','preparation-pointer','execution-source','replacement-root','late-source','late-cancel','missing-authority','capture','handshake','retiring'),
    'TestRouterVPNNodeChainExecutionDarwinSelectionBinding': ('Session','Source','Config','CallerUID','WorkspaceDevice','WorkspaceInode','EngineSHA256','ControllerSHA256','CatalogSHA256','InputsSHA256','Family'),
    'TestRouterVPNNodeChainExecutionDarwinSeparateRequestedExecution': ('same-physical-source',),
    'TestRouterVPNNodeChainExecutionDarwinStoppedReceipt': ('joined','proof-retry','source-retry','box-failure','foreign-file','foreign-workspace','cancelled'),
    'TestRouterVPNNodeChainExecutionDarwinCommandFlags': ('server','auto','physical-transfer-sha256','physical-mtu','journal-parent-handle','journal-parent-image','journal-pipe','journal-capture-sha256','linux-parent-channel','linux-parent-directory','linux-parent-capture','empty-family','unknown-family','missing-execution','cancelled'),
    'TestRouterVPNDesktopNodeChainExecutionDispatchCapturesOriginal': ('linux/server','linux/auto','windows/server','windows/auto'),
    'TestRouterVPNDesktopNodeChainExecutionDispatchRejectsSubstitution': ('directory','session','config','physical','execution','transfer','mtu-small','mtu-large','mixed-parent','local-source','darwin-parent','cancelled'),
    'TestRouterVPNDesktopNodeChainExecutionDispatchRequiresOriginalParent': ('absent','mixed','invalid-source','cancelled','nil-caller'),
}
CONTROLS = (
    ('selection', 'control.go', 'owner.capture.Selection() != owner.selection', 'false', 'TestRouterVPNNodeChainExecutionDarwinSelectionBinding/InputsSHA256', 'changed original execution selection reached replay'),
    ('physical-pointer', 'control.go', 'owner.policy != policy', 'false', 'TestRouterVPNNodeChainExecutionDarwinOriginalControl/policy-pointer', 'foreign or retired execution owner prepared native authority'),
    ('preparation-pointer', 'control.go', 'err != nil || policy != owner.policy', 'err != nil', 'TestRouterVPNNodeChainExecutionDarwinOriginalControl/preparation-pointer', 'foreign or retired execution owner prepared native authority'),
    ('execution-source', 'command.go', 'prep.SourceSHA256() != executionSource || ', '', 'TestRouterVPNNodeChainExecutionDarwinSeparateRequestedExecution/same-physical-source', 'Server source authorized a Compare launch sharing the physical graph'),
    ('source-join', 'native.go', 'if err := owner.source.CloseSource(ctx); err != nil {\n\t\t\t\treturn err\n\t\t\t}', 'if err := owner.source.CloseSource(ctx); err != nil { _ = err }', 'TestRouterVPNNodeChainExecutionDarwinStoppedReceipt/source-retry', 'unjoined execution source or foreign writer acknowledged Stop'),
    ('foreign-flag', 'dispatch.go', 'if command.Flags().Changed(name) {', 'if command.Flags().Changed(name) && false {', 'TestRouterVPNNodeChainExecutionDarwinCommandFlags/physical-mtu', 'explicit foreign or cancelled Darwin execution reached native dispatch'),
)

def load(filename):
    spec=importlib.util.spec_from_file_location('darwin_execution_'+filename.replace('.','_'),ROOT/'deploy'/filename)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def require_pass(output, validator, cases=CASES):
    # Go permits t.Run("linux/server", ...) without emitting a synthetic
    # "linux" parent. Require the nearest actual declared parent, along with
    # the exact complete inventory; never invent omitted parent events.
    wanted=set(validator.expected(cases))
    events=validator.events(output)
    states={};ended=False
    if not events or events[0].get('Action')!='start':raise ValueError('Missing original package start')
    for index,event in enumerate(events):
        action,name=event.get('Action'),event.get('Test')
        if ended:raise ValueError('Events after package result')
        if not name:
            if action=='start' and index==0:continue
            if action=='output':continue
            if action=='pass' and index==len(events)-1 and set(states)==wanted and all(value=='pass' for value in states.values()):
                ended=True;continue
            raise ValueError('Incomplete or failed package result')
        if name not in wanted:raise ValueError('Unexpected original test identity')
        if action=='run':
            parents=[parent for parent in wanted if name.startswith(parent+'/')]
            if name in states or parents and states.get(max(parents,key=len))!='run':raise ValueError('Duplicate or unowned test start')
            states[name]='run'
        elif action=='output':
            if states.get(name)!='run':raise ValueError('Output escaped original running test')
        elif action=='pass':
            if states.get(name)!='run' or any(state=='run' and child.startswith(name+'/') for child,state in states.items()):raise ValueError('Unjoined original test result')
            states[name]='pass'
        else:raise ValueError('Skipped, failed or changed original test')
    if not ended:raise ValueError('Missing package result')
    return len(states)


def project(text):
    return text.removeprefix('//go:build darwin\n\n').replace('github.com/sagernet/sing-box/experimental/libbox/routervpn/', 'router-vpn/internal/').replace('github.com/sagernet/sing-box/routervpn/', 'router-vpn/internal/').replace('"router-vpn/internal/mobiletor"', 'mobiletor "'+PACKAGE+'/authority"')


def section(text, first, last):
    if text.count(first)!=1 or text.count(last)!=1: raise ValueError('Shipping extraction boundary changed: '+first)
    return text[text.index(first):text.index(last)]


def prepare(directory):
    directory.mkdir(parents=True,exist_ok=True)
    (directory/'go.mod').write_text('module '+PACKAGE+'\n\ngo 1.26.3\n\nrequire (\n router-vpn v0.0.0\n github.com/spf13/cobra v1.10.2\n github.com/spf13/pflag v1.0.10\n)\nreplace router-vpn => '+str(ROOT)+'\n')
    records={}
    def source(relative):
        path=ROOT/relative
        if path.is_symlink(): raise ValueError('Linked shipping source: '+relative)
        records[relative]=digest(path);return path.read_text()
    def template(name):return source('mobile/desktop/'+name+'.go.tmpl')
    def write(name,raw): (directory/name).write_text(project(raw))
    for output,name in (('control.go','node_chain_execution_control_darwin'),('retirement.go','node_chain_execution_retirement_darwin'),('command.go','node_chain_execution_command'),('dispatch.go','node_chain_execution_dispatch'),('startup.go','node_startup_lifecycle'),('control_test.go','node_chain_execution_control_darwin_test'),('darwin_dispatch_test.go','node_chain_execution_darwin_dispatch_test'),('dispatch_test.go','node_chain_execution_dispatch_test')):
        write(output,template(name))
    original=template('node_chain_control_darwin')
    interfaces=section(original,'type routerVPNDarwinNodeChainCapture interface','type routerVPNDarwinNodeChainControl struct')
    write('capture.go','package main\nimport("context";"os";"github.com/sagernet/sing-box/routervpn/macosprocess")\n'+interfaces)
    native=template('node_chain_retirement_darwin').split('// finish is the sole native stopped-receipt producer.',1)[0].replace('\t"github.com/sagernet/sing-box/routervpn/macosprocess"\n','')
    write('native.go',native)
    external=template('external')
    files=section(external,'type routerVPNExternalFiles struct','type routerVPNExternalOwner interface')
    write('files.go','package main\nimport("bytes";"encoding/json";"errors";"io";"os";"path/filepath";"runtime";"router-vpn/internal/applexray")\n'+files)
    raw=template('node_chain_command_test')
    helpers=section(raw,'func desktopNodeChainCommandPolicy(', 'func TestRouterVPNDesktopNodeChainCommandExactSourceReplay')
    write('policy_test.go','package main\nimport("bytes";"crypto/ecdh";"crypto/sha256";"encoding/base64";"encoding/hex";"encoding/json";"fmt";"testing";"router-vpn/internal/mobilemultihop")\n'+helpers)
    raw=template('node_command_imported_test')
    helper=section(raw,'func desktopImportedCommandFiles(', 'func TestRouterVPNDesktopNodePhysicalCommandImportedSourceBoundary')
    raw=template('node_chain_control_darwin_test')
    helper+=section(raw,'type routerVPNDarwinChainCaptureRead struct','func routerVPNDarwinChainControlFixture(')
    helper+=section(raw,'func routerVPNDarwinChainControlContext(', 'func TestRouterVPNNodeChainDarwinOriginalControl')
    raw=template('node_chain_retirement_darwin_test')
    helper+=section(raw,'type routerVPNDarwinChainTestClose struct','func TestRouterVPNNodeChainDarwinNativeRetirementOrder')
    write('helpers_test.go','package main\nimport("context";"errors";"os";"path/filepath";"testing";"time";"router-vpn/internal/macosprocess")\n'+helper)
    authority=directory/'authority';authority.mkdir(exist_ok=True)
    (authority/'authority.go').write_text(source('internal/mobiletor/desktop_socket_darwin_authority.go').removeprefix('//go:build darwin\n\n'))
    options=section(template('node_command_control'),'type routerVPNNodeLinuxParentOptions struct','func routerVPNRunNodeMTUWithParents')
    options+=section(template('node_command_journal'),'type routerVPNNodeJournalOptions struct','type routerVPNNodeJournal interface')
    admission=template('node_command_admission')
    limits=[line for line in admission.splitlines() if line.startswith('const routerVPNNodeAdmissionLimit =')]
    if len(limits)!=1: raise ValueError('Execution admission bound changed shape')
    write('refusing_native.go','''package main
import("context";"errors";"regexp";"time";"github.com/spf13/cobra")
var mainCommand=&cobra.Command{}
var routerVPNExternalSession=regexp.MustCompile(`^[0-9a-f]{32}$`)
var routerVPNExternalSource=regexp.MustCompile(`^[0-9a-f]{64}$`)
var routerVPNExternalFailure=errors.New("projected native boundary refused")
const desktopExternalSession="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
'''+limits[0]+'\n'+options+'''
// These entry points refuse; no portable test obtains native process authority.
type fixtureJournal struct{}
func(*fixtureJournal)close()error{return routerVPNExternalFailure}
func routerVPNNewNodeJournal(context.Context,string,routerVPNNodeJournalOptions)(*fixtureJournal,error){return nil,routerVPNExternalFailure}
func routerVPNRunNodeMTUExecutionFamiliesCaptured(context.Context,string,string,string,string,string,string,string,string,int,*fixtureJournal)error{return routerVPNExternalFailure}
func routerVPNRunLinuxNodeChainExecutionControlled(context.Context,routerVPNNodeChainExecutionCommand)error{return routerVPNExternalFailure}
func routerVPNRunDarwinNodeChainExecutionControlled(context.Context,string,string,string,string,string)error{return routerVPNExternalFailure}
''')
    for package in ('mobilemultihop','macosprocess','desktopnetwork','applexray'):
        for path in sorted((ROOT/'internal'/package).glob('*.go')):
            records[path.relative_to(ROOT).as_posix()]=digest(path)
    records['deploy/test_desktop_darwin_execution_control.py']=digest(Path(__file__))
    (directory/'shipping-source.json').write_text(json.dumps(records,indent=2,sort_keys=True)+'\n')
    return records


def check(directory):
    source=directory/'fixture';records=prepare(source)
    race=load('darwin_race_toolchain.py')
    validator=load('test_desktop_darwin_retirement.py');validator.PACKAGE=PACKAGE
    receipt={'status':'running','scope':__doc__,'shipping_source':records,'phases':[]}
    receipt_path=directory/'receipt.json'
    def save():receipt_path.write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n')
    save()
    try:
        for label,filename,before,after,witness,message in (('baseline','','','','',''),*CONTROLS):
            path=source/filename if filename else None
            original=path.read_bytes() if path else None
            if path:
                raw=original.decode()
                if raw.count(before)!=1: raise ValueError('Original causal boundary changed: '+label)
                path.write_text(raw.replace(before,after,1))
            try:
                command=['go','test','-race','-p=1','-mod=mod','-json','-count=1','-timeout=90s']
                if witness: command+=['-run='+ '/'.join('^'+part+'$' for part in witness.split('/'))]
                command,env=race.command(command,source,dict(os.environ))
                env.update(GOMAXPROCS='1',GOMEMLIMIT='768MiB',GOGC='100')
                result=subprocess.run(command,cwd=source,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=300)
                log=directory/(label+'.jsonl');log.write_text(result.stdout)
                phase={'label':label,'command':command,'exit_code':result.returncode,'process_joined':True,'log':str(log),'log_sha256':digest(log)}
                receipt['phases'].append(phase);save()
                if not witness:
                    if result.returncode: raise ValueError(result.stdout)
                    phase['verdicts']=require_pass(result.stdout,validator)
                else:
                    validator.require_rejection(result.returncode,result.stdout,witness,message)
                    phase['required_failure']=witness
                save();print('Darwin execution projected control:',label,'passed',flush=True)
            finally:
                if path:path.write_bytes(original)
        if any(digest(ROOT/name)!=value for name,value in records.items()):raise ValueError('Shipping source changed during portable control')
        receipt['shipping_source_guard']=True;receipt['status']='passed';save()
    except BaseException as error:
        receipt['status']='failed';receipt['error']=str(error);save();raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--receipt-dir',type=Path);args=parser.parse_args()
    if args.receipt_dir:
        args.receipt_dir.mkdir(parents=True,exist_ok=True);check(args.receipt_dir.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix='darwin-execution-control-') as temporary:check(Path(temporary))
