#!/usr/bin/env python3
"""Exercise the typed SOCKS bridge against the original separate encrypted peers."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[1]
sys.dont_write_bytecode=True
SUITE="socks-run"
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value
BASE_PATH=ROOT/"deploy/test_focused_socks_bridge.py"
BASE=module("socks_run_trusted_bridge",BASE_PATH)
# Only the fixed source-selection suite label differs. The trusted process,
# snapshot, native source and strict event parsers are reused unchanged.
BASE.SUITE=SUITE
CASE_ROOT="TestRouterNodeChainSOCKSEncryptedRun"
CASES=("wg","awg2-fast","awg2-strong","middle-password","final-token","selected-dns","middle-public","hold-prefix")
PEER_ROOT="TestRouterVPNDesktopNodeChainSOCKSRunReference"
PEER_TEMPLATE="mobile/desktop/node_chain_socks_process_test.go.tmpl"
PEER_PROJECTION="protocol/routervpnamnezia/routervpn_desktop_node_chain_socks_process_test.go"
RUN_TEMPLATE="mobile/chain/socks_run_test.go.tmpl"
RUN_PROJECTION="experimental/libbox/routervpn_node_chain_socks_run_test.go"
ORIGINAL_ROOT="TestRouterVPNDesktopNodeChainImportedMiddleTraffic"
ORIGINAL=(
    ORIGINAL_ROOT,*(ORIGINAL_ROOT+"/"+mode+"/"+method+suffix
      for mode in ("wg","awg2-fast","awg2-strong")
      for method in ("2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305")
      for suffix in ("","/public-middle-private-final","/final-selected-dns","/middle-refuses-selected-dns",
                     "/wrong-middle-key","/omit-middle","/wrong-final-key","/stop-drains-middle-socket")))
CONTROLS=(
 dict(name="original-selected-dns",case="wg",path="routervpn_node_chain_socks.go",
      before="\tquery, cancel := context.WithTimeout(ctx, 5*time.Second)\n",
      after='\treturn e.observation.Dial(ctx, tag, "1.1.1.1:443") // causal bypass of selected resolver\n\tquery, cancel := context.WithTimeout(ctx, 5*time.Second)\n',
      witness="real measurement bypassed original selected DNS/byte sink"),
 dict(name="original-complete-prefix-proof",case="wg",path="experimental/libbox/routervpn/mobilemultihop/node_chain_runtime.go",
      before="func (c *NodeChain) provePrefixes(ctx context.Context, publish bool) error {\n",
      after="func (c *NodeChain) provePrefixes(ctx context.Context, publish bool) error {\n\treturn c.currentContext(ctx, true) // causal omission of complete original prefix proof\n",
      witness="complete original prefix/DNS/public proof missing"),
 dict(name="original-native-down",case="wg",path="experimental/libbox/routervpn_node_chain_socks_lifecycle.go",
      before="if err := native.capture.ClosedContext(ctx); err != nil {",
      after="if err := ctx.Err(); err != nil {",
      witness="shared join fabricated native DOWN"),
 dict(name="original-cancel-join",case="hold-prefix",path="experimental/libbox/routervpn_node_chain_socks_lifecycle.go",
      before="func (m *RouterNodeChainSOCKS) networkChangedContext(ctx context.Context) error {\n\tif m == nil || ctx == nil {\n\t\treturn errRouterNodeChainSOCKS()\n\t}\n\tm.retireProof()\n",
      after="func (m *RouterNodeChainSOCKS) networkChangedContext(ctx context.Context) error {\n\tif m == nil || ctx == nil {\n\t\treturn errRouterNodeChainSOCKS()\n\t}\n\t// causal omission of immediate original proof cancellation\n",
      witness="cancelled original proof did not join before observation deadline"),
)
def case_names(case):
    if case not in CASES:raise ValueError("Uncaptured encrypted case")
    return (CASE_ROOT,CASE_ROOT+"/"+case)
def sources(source,mobile,mobile_xray,owner,owner_xray):
    captured={"mobile":BASE.checked_sources(source,mobile,mobile_xray),
              "owner":BASE.checked_owner_sources(source,owner,owner_xray)}
    mobile_prep=BASE.module("socks_run_candidate_mobile",source/"deploy/prepare-mobile-node-chain.py")
    desktop=BASE.module("socks_run_candidate_desktop",source/"deploy/prepare-desktop-external.py")
    for original,projected,root,table in (
        (RUN_TEMPLATE,RUN_PROJECTION,mobile,mobile_prep.TEMPLATES),
        (PEER_TEMPLATE,PEER_PROJECTION,owner,desktop.PEER_TEMPLATES)):
        a,b=source/original,root/projected
        if table.get(Path(original).name)!=projected or a.is_symlink() or b.is_symlink() or a.read_bytes()!=b.read_bytes():
            raise ValueError("Original positive native projection changed: "+original)
    original=(source/"mobile/desktop/node_chain_imported_test.go.tmpl").read_bytes()
    native=owner/"protocol/routervpnamnezia/routervpn_desktop_node_chain_imported_test.go"
    if native.is_symlink() or native.read_bytes()!=original:
        raise ValueError("Original complete imported peer helper changed")
    return captured
def native_events(raw,status,case,control=None):
    names=case_names(case)
    actual=dict(control,cases=names) if control else None
    return BASE.require_events(raw,status,BASE.LIBBOX,names,actual)

def validate(source,source_sha,output,go="go"):
    source=Path(source).resolve(strict=True);output=Path(output).absolute()
    if output.is_symlink() or output.exists() or source==output or source in output.parents:
        raise ValueError("Encrypted output must be fresh and outside candidate")
    metadata,selection_raw=BASE.selection(source,source_sha,output)
    before=BASE.CORE.snapshot(source)
    output.mkdir(mode=0o700)
    (output/"source-before.json").write_text(json.dumps(before,sort_keys=True)+"\n")
    compiler=shutil.which(go)
    if compiler is None:raise ValueError("Pinned compiler missing")
    env=dict(os.environ,CGO_ENABLED="1",GOTOOLCHAIN="local",GOWORK="off",GOFLAGS="",PYTHONDONTWRITEBYTECODE="1",
             GOMAXPROCS="2",GOGC="100",GOMEMLIMIT="2GiB")
    env["PATH"]=str(Path(compiler).parent)+os.pathsep+env.get("PATH","")
    version=subprocess.check_output([compiler,"version"],text=True,env=env,timeout=30).strip()
    if version!="go version go1.26.3 linux/amd64":raise ValueError("Original pinned Linux compiler required")
    receipt=dict(schema=1,suite=SUITE,status="running",selection=metadata,phases=[],
        scope="actual typed Run/Healthy/ordered measurement over original encrypted WG/AWG-SOCKS-SS peers",
        boundaries=["loopback mapping of one captured physical UDP tuple","TUN reader and OS interface monitor","isolated TLS root"],
        installed_native_accepted=False,public_native_admission=False,native_mtu_continuation_accepted=False,
        original_external_final_fifty_scope_unchanged=True,go_version=version,compiler=compiler,
        resource_limits=dict(parallel_packages=1,GOMAXPROCS=2,GOGC=100,GOMEMLIMIT="2GiB"),
        trusted_bridge_sha256=hashlib.sha256(BASE_PATH.read_bytes()).hexdigest(),
        trusted_executor_sha256=hashlib.sha256(BASE.CORE_PATH.read_bytes()).hexdigest())
    def save():(output/"progress.json").write_text(json.dumps(receipt,indent=2)+"\n")
    def run(name,command,cwd,bound,captured=None):
        command=list(map(str,command));log=output/(name+".log");started=time.monotonic()
        try:status,timed_out,joined=BASE.CORE.execute(command,cwd,captured or env,log,bound)
        except BaseException as error:
            receipt["phases"].append(dict(name=name,command=command,bound=bound,error=type(error).__name__));save();raise
        raw=log.read_bytes()
        receipt["phases"].append(dict(name=name,command=command,bound=bound,status=status,timed_out=timed_out,
            process_group_joined=joined,seconds=time.monotonic()-started,output_sha256=hashlib.sha256(raw).hexdigest()))
        save()
        if timed_out or not joined:raise RuntimeError("Original encrypted child failed bounded join")
        return status,raw
    save()
    try:
        with tempfile.TemporaryDirectory(prefix="routervpn-socks-run-",dir=output.parent) as temporary:
            work=Path(temporary);mobile,mobile_xray=work/"mobile",work/"mobile-xray";owner,owner_xray=work/"owner",work/"owner-xray"
            status,raw=run("original-owner-preflight",[sys.executable,source/"deploy/test_desktop_tor_preparation.py","--daemon-capture-only"],source,60)
            BASE.OWNER.require_daemon_preflight(raw.decode(),status)
            for name,core,xray,flag in (("prepare-owner",owner,owner_xray,"--prepare-owner"),("prepare-mobile",mobile,mobile_xray,"--prepare-mobile")):
                status,_=run(name,[sys.executable,BASE_PATH,flag,"--source",source,"--source-sha",source_sha,
                    "--core",core,"--xray",xray,"--go",compiler],source,600)
                if status:raise ValueError("Original shipping "+name+" failed")
            native_before=sources(source,mobile,mobile_xray,owner,owner_xray)
            (output/"native-before.json").write_text(json.dumps(native_before,sort_keys=True)+"\n")
            gate=BASE.OWNER.load_gate(source)
            if tuple(gate.NODE_CHAIN_IMPORTED_VERDICTS)!=ORIGINAL:
                raise ValueError("Original complete imported peer inventory changed")
            compiler,captured,arch=gate.NODE.selected_compiler(compiler,owner,env)
            if arch!="amd64":raise ValueError("Encrypted original peer architecture changed")
            env.update(captured);env["CGO_ENABLED"]="1"
            peer,client=work/"peer.test",work/"client.test"
            flags=["-race","-p=1","-mod=readonly","-tags="+BASE.TAGS,"-ldflags=-checklinkname=0"]
            owner_flags=["-race","-p=1","-mod=readonly","-tags="+",".join(gate.NODE.TAGS),"-ldflags=-checklinkname=0"]
            for name,image,core,target,arguments in (
                ("peer-build",peer,owner,"./protocol/routervpnamnezia",owner_flags),
                ("client-build",client,mobile,"./experimental/libbox",flags)):
                status,_=run(name,[compiler,"test","-c",*arguments,"-o",image,target],core,600)
                if status:raise ValueError("Actual encrypted "+name+" failed")
            peer_identity,client_identity=BASE.COMMON.image_identity(peer),BASE.COMMON.image_identity(client)
            status,raw=run("original-imported-middle",[peer,"-test.run=^"+ORIGINAL_ROOT+"$","-test.count=1","-test.timeout=90s","-test.v"],owner,100)
            if status:raise ValueError("Original complete imported peer baseline failed")
            gate.NODE.require_native_verdicts(raw.decode(),ORIGINAL,"unchanged original imported peer")
            records=[]
            for case in CASES:
                selected=dict(env,ROUTERVPN_SOCKS_RUN_PEER=str(peer),ROUTERVPN_SOCKS_RUN_CASE=case,GODEBUG="x509usefallbackroots=1")
                status,raw=run("run-"+case,[compiler,"tool","test2json","-t","-p",BASE.LIBBOX,client,
                    "-test.run=^"+CASE_ROOT+"$","-test.count=1","-test.timeout=90s","-test.v"],mobile,100,selected)
                records.append(dict(case=case,**native_events(raw,status,case)))
                if BASE.COMMON.image_identity(peer)!=peer_identity:raise ValueError("Original peer executable changed")
            controls=[]
            for control in CONTROLS:
                original=mobile/control["path"];changed=BASE.mutate(control,original.read_text())
                replacement,overlay=work/(control["name"]+".go"),work/(control["name"]+".json")
                replacement.write_text(changed);overlay.write_text(json.dumps({"Replace":{str(original):str(replacement)}}))
                selected=dict(env,ROUTERVPN_SOCKS_RUN_PEER=str(peer),ROUTERVPN_SOCKS_RUN_CASE=control["case"],GODEBUG="x509usefallbackroots=1")
                status,raw=run(control["name"],[compiler,"test",*flags,"-json","-overlay="+str(overlay),
                    "-run=^"+CASE_ROOT+"$","-count=1","-timeout=90s","./experimental/libbox"],mobile,600,selected)
                controls.append(dict(name=control["name"],original_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
                    mutation_sha256=hashlib.sha256(changed.encode()).hexdigest(),
                    **native_events(raw,status,control["case"],control)))
            if sources(source,mobile,mobile_xray,owner,owner_xray)!=native_before or BASE.CORE.snapshot(source)!=before:
                raise ValueError("Original encrypted native/candidate source changed")
            if BASE.COMMON.git(source,"status","--porcelain","--untracked-files=all"):
                raise ValueError("Candidate changed during native execution")
            if BASE.selection(source,source_sha,output)[0]!=metadata or (output.parent/"selection.json").read_bytes()!=selection_raw:
                raise ValueError("Original selected candidate changed")
            if BASE.COMMON.image_identity(peer)!=peer_identity or BASE.COMMON.image_identity(client)!=client_identity:
                raise ValueError("Original compiled encrypted image changed")
            receipt.update(status="passed",cases=list(CASES),case_records=records,original_cases=list(ORIGINAL),controls=controls,
                peer_image=list(peer_identity),client_image=list(client_identity),successful_run_accepted=True,ordered_measurement_accepted=True)
            (output/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
    except BaseException as error:
        receipt.update(status="failed",error=str(error));raise
    finally:save()
    return receipt

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite",required=True,choices=(SUITE,));parser.add_argument("--source",required=True,type=Path)
    parser.add_argument("--source-sha",required=True);parser.add_argument("--output",required=True,type=Path);parser.add_argument("--go",default="go")
    args=parser.parse_args();validate(args.source,args.source_sha,args.output,args.go)
if __name__=="__main__":main()
