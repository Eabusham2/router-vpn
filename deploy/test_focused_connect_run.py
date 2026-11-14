#!/usr/bin/env python3
"""Exercise the typed CONNECT bridge against the original separate encrypted peers."""
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
SUITE="connect-run"
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);sys.modules[name]=value;spec.loader.exec_module(value);return value
BASE_PATH=ROOT/"deploy/test_focused_socks_bridge.py"
BASE=module("connect_run_trusted_bridge",BASE_PATH)
# Only the fixed source-selection suite label differs. The trusted process,
# snapshot, native source and strict event parsers are reused unchanged.
BASE.SUITE=SUITE
FIFTY=module("connect_run_ordered_fifty",ROOT/"deploy/connect_ordered_fifty_native.py")
ORDINARY=module("connect_run_ordinary_fifty",ROOT/"deploy/ordinary_ordered_fifty_native.py")
REMAINING=module("connect_run_remaining_fifty",ROOT/"deploy/ordinary_remaining_fifty_native.py")
LIFETIME=module("connect_run_reference_lifetime",ROOT/"deploy/connect_reference_lifetime.py")
CASE_ROOT="TestRouterNodeChainCONNECTEncryptedRun"
CASES=("http-wg","http-awg2-fast","http-awg2-strong","https-wg","https-awg2-fast","https-awg2-strong","middle-password","final-key","final-token","selected-dns","middle-public","hold-prefix","tls-trust","tls-name")
PEER_ROOT="TestRouterVPNDesktopNodeChainCONNECTRunReference"
PEER_TEMPLATE="mobile/chain/connect_reference_test.go.tmpl"
PEER_PROJECTION="protocol/routervpnamnezia/routervpn_connect_reference_test.go"
RUN_TEMPLATE="mobile/chain/connect_run_test.go.tmpl"
RUN_PROJECTION="experimental/libbox/routervpn_node_chain_connect_run_test.go"
REFERENCE_PACKAGE="github.com/sagernet/sing-box/protocol/routervpnamnezia"
REFERENCE_ROOT="TestRouterVPNCONNECTReferenceTLSReciprocalClose"
REFERENCE_CASES=(REFERENCE_ROOT,*(REFERENCE_ROOT+"/"+leaf for leaf in ("reciprocal","held","cancelled")))
REFERENCE_CONTROL=dict(name="reference-reciprocal-tls-close", path=PEER_PROJECTION,
    before="func (r *nodeCONNECTRunMiddleRouter) routeTLS(ctx context.Context, connection net.Conn, secured *tls.Conn, metadata adapter.InboundContext) error {\n",
    after="func (r *nodeCONNECTRunMiddleRouter) routeTLS(ctx context.Context, connection net.Conn, secured *tls.Conn, metadata adapter.InboundContext) error {\n\treturn r.server.plainConnection(ctx, connection, M.Metadata{Source: metadata.Source, Destination: metadata.Destination}) // causal original premature TLS reader interruption\n",
    cases=(REFERENCE_ROOT,REFERENCE_ROOT+"/reciprocal"),
    witness="reference closed original TLS before reciprocal close_notify")
REFERENCE_TCP_ROOT="TestRouterVPNCONNECTReferenceTCPReciprocalClose"
REFERENCE_TCP_CASES=(REFERENCE_TCP_ROOT,*(REFERENCE_TCP_ROOT+"/"+leaf for leaf in ("reciprocal","refused","held","cancelled","packet-reciprocal","packet-refused","packet-held","packet-cancelled")))
REFERENCE_TCP_CONTROL=dict(name="reference-reciprocal-tcp-close",path=PEER_PROJECTION,
    before="func (r *nodeCONNECTRunMiddleRouter) routeTCP(ctx context.Context, connection, raw net.Conn, metadata adapter.InboundContext) error {\n",
    after="func (r *nodeCONNECTRunMiddleRouter) routeTCP(ctx context.Context, connection, raw net.Conn, metadata adapter.InboundContext) error {\n\treturn r.server.plainConnection(ctx, connection, M.Metadata{Source: metadata.Source, Destination: metadata.Destination}) // causal original premature TCP reader interruption\n",
    cases=(REFERENCE_TCP_ROOT,REFERENCE_TCP_ROOT+"/reciprocal"),
    witness="reference closed original TCP before reciprocal EOF")
REFERENCE_PACKET_CONTROL=dict(name="reference-packet-reciprocal-close",path=PEER_PROJECTION,
    before="func (h *nodeCONNECTRunPacketHandler) NewConnectionEx(ctx context.Context, c net.Conn, source, destination M.Socksaddr, done N.CloseHandlerFunc) {\n",
    after="func (h *nodeCONNECTRunPacketHandler) NewConnectionEx(ctx context.Context, c net.Conn, source, destination M.Socksaddr, done N.CloseHandlerFunc) {\n\th.desktopNodeWGHandler.NewConnectionEx(ctx, c, source, destination, done); return // causal original first-packet premature TCP close\n",
    cases=(REFERENCE_TCP_ROOT,REFERENCE_TCP_ROOT+"/packet-reciprocal"),
    witness="reference closed original TCP before reciprocal EOF")
REFERENCE_VERDICT=module("connect_run_reference_strict_bridge",BASE_PATH)
REFERENCE_VERDICT.BOX=REFERENCE_PACKAGE
REFERENCE_VERDICT.BOX_CORE.PACKAGE=REFERENCE_PACKAGE
ORIGINAL_ROOT="TestRouterVPNDesktopNodeChainImportedMiddleTraffic"
ORIGINAL=(
    ORIGINAL_ROOT,*(ORIGINAL_ROOT+"/"+mode+"/"+method+suffix
      for mode in ("wg","awg2-fast","awg2-strong")
      for method in ("2022-blake3-aes-128-gcm","2022-blake3-aes-256-gcm","2022-blake3-chacha20-poly1305")
      for suffix in ("","/public-middle-private-final","/final-selected-dns","/middle-refuses-selected-dns",
                     "/wrong-middle-key","/omit-middle","/wrong-final-key","/stop-drains-middle-socket")))
CONTROLS=(
 dict(name="original-selected-dns",case="http-wg",path="routervpn_node_chain_connect.go",
      before="\tquery, cancel := context.WithTimeout(ctx, 5*time.Second)\n",
      after='\treturn e.observation.Dial(ctx, tag, "1.1.1.1:443") // causal bypass of selected resolver\n\tquery, cancel := context.WithTimeout(ctx, 5*time.Second)\n',
      witness="real measurement bypassed original selected DNS/byte sink"),
 dict(name="original-complete-prefix-proof",case="http-wg",path="experimental/libbox/routervpn/mobilemultihop/node_chain_runtime.go",
      before="func (c *NodeChain) provePrefixes(ctx context.Context, publish bool) error {\n",
      after="func (c *NodeChain) provePrefixes(ctx context.Context, publish bool) error {\n\treturn c.currentContext(ctx, true) // causal omission of complete original prefix proof\n",
      witness="complete original prefix/DNS/public proof missing"),
 dict(name="original-native-down",case="http-wg",path="experimental/libbox/routervpn_node_chain_connect_lifecycle.go",
      before="if err := native.capture.ClosedContext(ctx); err != nil {",
      after="if err := ctx.Err(); err != nil {",
      witness="shared join fabricated native DOWN"),
 dict(name="original-cancel-join",case="hold-prefix",path="experimental/libbox/routervpn_node_chain_connect_lifecycle.go",
      before="func (m *RouterNodeChainCONNECT) networkChangedContext(ctx context.Context) error {\n\tif m == nil || ctx == nil {\n\t\treturn errRouterNodeChainCONNECT()\n\t}\n\tm.retireProof()\n",
      after="func (m *RouterNodeChainCONNECT) networkChangedContext(ctx context.Context) error {\n\tif m == nil || ctx == nil {\n\t\treturn errRouterNodeChainCONNECT()\n\t}\n\t// causal omission of immediate original proof cancellation\n",
      witness="cancelled original proof did not join before observation deadline"),
)
def case_names(case):
    if case not in CASES:raise ValueError("Uncaptured encrypted case")
    return (CASE_ROOT,CASE_ROOT+"/"+case)
def sources(source,mobile,mobile_xray,owner,owner_xray):
    captured={"mobile":BASE.checked_sources(source,mobile,mobile_xray),
              "owner":BASE.checked_owner_sources(source,owner,owner_xray)}
    connect=BASE.module("connect_run_candidate_projection",source/"deploy/prepare-mobile-connect.py")
    for root,mobile_mode in ((mobile,True),(owner,False)):
        paths={relative for name,relative in connect.TEMPLATES.items()
               if (not mobile_mode or name not in connect.DESKTOP_ONLY) and
                  (mobile_mode or not relative.startswith("experimental/libbox/"))}
        manifest=json.loads((root/connect.OWNER).read_bytes())
        if set(manifest["files"])!=paths:
            raise ValueError("CONNECT native projection inventory changed")
        for name,relative in connect.TEMPLATES.items():
            if relative not in paths:continue
            a,b=source/"mobile/chain"/name,root/relative
            if a.is_symlink() or b.is_symlink() or a.read_bytes()!=b.read_bytes() or hashlib.sha256(b.read_bytes()).hexdigest()!=manifest["files"][relative]:
                raise ValueError("CONNECT original native projection changed: "+relative)
        if connect.box_source((root/"box.go").read_text())!=(root/"box.go").read_text():
            raise ValueError("CONNECT original constructor-return ownership changed")
        if "routervpnnodeconnect" in (root/"include/registry.go").read_text():
            raise ValueError("CONNECT acquired ordinary native registration")
    for relative in ("protocol/http/outbound.go",):
        original=subprocess.check_output(["git","show",BASE.PIN+":"+relative],cwd=mobile,timeout=20)
        if (mobile/relative).read_bytes()!=original or (owner/relative).read_bytes()!=original:
            raise ValueError("Original pinned HTTP implementation changed")
    original=(source/"mobile/desktop/node_chain_imported_test.go.tmpl").read_bytes()
    native=owner/"protocol/routervpnamnezia/routervpn_desktop_node_chain_imported_test.go"
    if native.is_symlink() or native.read_bytes()!=original:
        raise ValueError("Original complete imported peer helper changed")
    shared=BASE.module("connect_run_shared_latency_projection",source/"deploy/prepare-mobile-node-chain.py")
    FIFTY.checked_projection(source,mobile,connect.TEMPLATES,shared.TEMPLATES)
    desktop=BASE.module("ordinary_fifty_peer_projection",source/"deploy/prepare-desktop-external.py")
    ORDINARY.checked_projection(source,mobile,owner,shared.TEMPLATES,desktop.PEER_TEMPLATES)
    REMAINING.checked_projection(source,mobile,owner,shared.TEMPLATES,desktop.PEER_TEMPLATES)
    return captured
def native_events(raw,status,case,control=None):
    names=case_names(case)
    actual=dict(control,cases=names) if control else None
    return BASE.require_events(raw,status,BASE.LIBBOX,names,actual)

def reference_events(raw,status,control=False):
    selected=REFERENCE_CONTROL if control else None
    names=selected["cases"] if selected else REFERENCE_CASES
    return REFERENCE_VERDICT.require_events(raw,status,REFERENCE_PACKAGE,names,selected)

def reference_tcp_events(raw,status,control=False):
    selected=REFERENCE_TCP_CONTROL if control else None
    names=selected["cases"] if selected else REFERENCE_TCP_CASES
    return REFERENCE_VERDICT.require_events(raw,status,REFERENCE_PACKAGE,names,selected)

def reference_packet_events(raw,status):
    return REFERENCE_VERDICT.require_events(raw,status,REFERENCE_PACKAGE,REFERENCE_PACKET_CONTROL["cases"],REFERENCE_PACKET_CONTROL)

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
        scope="actual typed Run/Healthy/ordered measurement over original encrypted WG/AWG-HTTP/HTTPS-SS2022 UoT-v2 peers",
        boundaries=["loopback mapping of one captured physical UDP tuple","TUN reader and OS interface monitor","isolated TLS root"],
        installed_native_accepted=False,public_native_admission=False,native_mtu_continuation_accepted=False,
        native_mtu_constructor_accepted=False,typed_connect_fifty_sample_benchmark_accepted=False,
        original_external_final_fifty_scope_unchanged=True,go_version=version,compiler=compiler,
        resource_limits=dict(parallel_packages=1,GOMAXPROCS=2,GOGC=100,GOMEMLIMIT="2GiB"),
        trusted_bridge_sha256=hashlib.sha256(BASE_PATH.read_bytes()).hexdigest(),
        trusted_executor_sha256=hashlib.sha256(BASE.CORE_PATH.read_bytes()).hexdigest())
    def save():(output/"progress.json").write_text(json.dumps(receipt,indent=2)+"\n")
    def run(name,command,cwd,bound,captured=None):
        command=list(map(str,command));log=output/(name+".log");started=time.monotonic()
        try:
            status,timed_out,joined=BASE.CORE.execute(command,cwd,captured or env,log,bound)
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
        with tempfile.TemporaryDirectory(prefix="routervpn-connect-run-",dir=output.parent) as temporary:
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
            status,raw=run("reference-tls-close",[compiler,"tool","test2json","-t","-p",REFERENCE_PACKAGE,peer,
                "-test.run=^"+REFERENCE_ROOT+"$","-test.count=1","-test.timeout=15s","-test.v"],owner,30)
            reference_positive=reference_events(raw,status)
            original=owner/REFERENCE_CONTROL["path"]
            replacement,overlay=work/"reference-tls-close.go",work/"reference-tls-close.json"
            replacement.write_text(BASE.mutate(REFERENCE_CONTROL,original.read_text()))
            overlay.write_text(json.dumps({"Replace":{str(original):str(replacement)}}))
            status,raw=run(REFERENCE_CONTROL["name"],[compiler,"test",*owner_flags,"-json","-overlay="+str(overlay),
                "-run=^"+REFERENCE_ROOT+"$/^reciprocal$","-count=1","-timeout=15s","./protocol/routervpnamnezia"],owner,600)
            reference_negative=reference_events(raw,status,True)
            status,raw=run("reference-tcp-close",[compiler,"tool","test2json","-t","-p",REFERENCE_PACKAGE,peer,
                "-test.run=^"+REFERENCE_TCP_ROOT+"$","-test.count=1","-test.timeout=15s","-test.v"],owner,30)
            reference_tcp_positive=reference_tcp_events(raw,status)
            original=owner/REFERENCE_TCP_CONTROL["path"]
            replacement,overlay=work/"reference-tcp-close.go",work/"reference-tcp-close.json"
            replacement.write_text(BASE.mutate(REFERENCE_TCP_CONTROL,original.read_text()))
            overlay.write_text(json.dumps({"Replace":{str(original):str(replacement)}}))
            status,raw=run(REFERENCE_TCP_CONTROL["name"],[compiler,"test",*owner_flags,"-json","-overlay="+str(overlay),
                "-run=^"+REFERENCE_TCP_ROOT+"$/^reciprocal$","-count=1","-timeout=15s","./protocol/routervpnamnezia"],owner,600)
            reference_tcp_negative=reference_tcp_events(raw,status,True)
            original=owner/REFERENCE_PACKET_CONTROL["path"]
            replacement,overlay=work/"reference-packet-close.go",work/"reference-packet-close.json"
            replacement.write_text(BASE.mutate(REFERENCE_PACKET_CONTROL,original.read_text()))
            overlay.write_text(json.dumps({"Replace":{str(original):str(replacement)}}))
            status,raw=run(REFERENCE_PACKET_CONTROL["name"],[compiler,"test",*owner_flags,"-json","-overlay="+str(overlay),
                "-run=^"+REFERENCE_TCP_ROOT+"$/^packet-reciprocal$","-count=1","-timeout=15s","./protocol/routervpnamnezia"],owner,600)
            reference_packet_negative=reference_packet_events(raw,status)
            lifetime=LIFETIME.validate(BASE,gate,run,compiler,owner,peer,work,owner_flags)
            records=[]
            for case in CASES:
                selected=dict(env,ROUTERVPN_CONNECT_RUN_PEER=str(peer),ROUTERVPN_CONNECT_RUN_CASE=case,GODEBUG="x509usefallbackroots=1")
                status,raw=run("run-"+case,[compiler,"tool","test2json","-t","-p",BASE.LIBBOX,client,
                    "-test.run=^"+CASE_ROOT+"$","-test.count=1","-test.timeout=180s","-test.v"],mobile,190,selected)
                records.append(dict(case=case,**native_events(raw,status,case)))
                if BASE.COMMON.image_identity(peer)!=peer_identity:raise ValueError("Original peer executable changed")
            controls=[]
            for control in CONTROLS:
                original=mobile/control["path"];changed=BASE.mutate(control,original.read_text())
                replacement,overlay=work/(control["name"]+".go"),work/(control["name"]+".json")
                replacement.write_text(changed);overlay.write_text(json.dumps({"Replace":{str(original):str(replacement)}}))
                selected=dict(env,ROUTERVPN_CONNECT_RUN_PEER=str(peer),ROUTERVPN_CONNECT_RUN_CASE=control["case"],GODEBUG="x509usefallbackroots=1")
                status,raw=run(control["name"],[compiler,"test",*flags,"-json","-overlay="+str(overlay),
                    "-run=^"+CASE_ROOT+"$","-count=1","-timeout=180s","./experimental/libbox"],mobile,600,selected)
                controls.append(dict(name=control["name"],original_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
                    mutation_sha256=hashlib.sha256(changed.encode()).hexdigest(),
                    **native_events(raw,status,control["case"],control)))
            fifty=FIFTY.validate_compiled(BASE,run,compiler,mobile,peer,client,work,flags,env)
            ordinary=ORDINARY.validate_compiled(BASE,run,compiler,mobile,peer,client,work,flags,env)
            remaining=REMAINING.validate_compiled(BASE,run,compiler,mobile,peer,client,work,flags,env)
            if sources(source,mobile,mobile_xray,owner,owner_xray)!=native_before or BASE.CORE.snapshot(source)!=before:
                raise ValueError("Original encrypted native/candidate source changed")
            if BASE.COMMON.git(source,"status","--porcelain","--untracked-files=all"):
                raise ValueError("Candidate changed during native execution")
            if BASE.selection(source,source_sha,output)[0]!=metadata or (output.parent/"selection.json").read_bytes()!=selection_raw:
                raise ValueError("Original selected candidate changed")
            if BASE.COMMON.image_identity(peer)!=peer_identity or BASE.COMMON.image_identity(client)!=client_identity:
                raise ValueError("Original compiled encrypted image changed")
            receipt.update(status="passed",cases=list(CASES),case_records=records,original_cases=list(ORIGINAL),controls=controls,
                peer_image=list(peer_identity),client_image=list(client_identity),reference_tls_close=reference_positive,reference_tls_close_control=reference_negative,
                reference_tcp_close=reference_tcp_positive,reference_tcp_close_control=reference_tcp_negative,
                reference_packet_close_control=reference_packet_negative,
                successful_run_accepted=True,ordered_measurement_accepted=True,native_mtu_constructor_accepted=False,**fifty,**lifetime,**ordinary,**remaining)
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
