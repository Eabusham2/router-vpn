#!/usr/bin/env python3
"""Validate typed SOCKS native objects without granting host or device admission."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
SUITE = "socks-bridge"
BOX = "github.com/sagernet/sing-box"
LIBBOX = BOX + "/experimental/libbox"
PIN = "1ac1a339cb1223e9c70eae14c44411c75033c02d"
TAGS = "with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego"
HEX40 = re.compile(r"[0-9a-f]{40}")
CORE_PATH = ROOT / "deploy/test_focused_multihop_clocks.py"

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value

# Each trusted parser instance is configured for one fixed compiled package.
# Its parser/executor/snapshot implementation is unchanged; candidate output
# and source are never rewritten to substitute another package or verdict.
CORE = module("socks_bridge_libbox_clock", CORE_PATH)
CORE.PACKAGE = LIBBOX
BOX_CORE = module("socks_bridge_box_clock", CORE_PATH)
BOX_CORE.PACKAGE = BOX
COMMON_PATH = ROOT / "deploy/validate-linux-hy2-source.py"
COMMON = module("socks_bridge_native_common", COMMON_PATH)
OWNER_PATH = ROOT / "deploy/validate-node-chain-socks-owner.py"
OWNER = module("socks_bridge_original_owner", OWNER_PATH)

B = "TestRouterNodeChainSOCKSBridge"
N = "TestRouterNodeChainSOCKSNative"
BRIDGE_ROOTS = (
    B+"KeepsSourceAndExplicitBinding", B+"BindingFailureKeepsHostHandle",
    B+"RefusesForeignAndOrdinaryServer", B+"EmptyOwnerDoesNotProveDOWN",
    B+"CloseAndNetworkKeepCallerDeadline", B+"CloseJoinsOriginalStartup",
    B+"CloseRetainsActiveMeasurement", B+"MeasurementRequiresOriginalProof",
    B+"MeasurementKeepsCallerContext", B+"RetainsLateCommandFactory",
    B+"ActualNativeIdentity", B+"ActualNativeCloseReceipt", B+"ActualNativeReadKeepsDeadline",
    B+"RetainsOnlyBoundedOriginalCleanup",
)
BRIDGE = (
    *BRIDGE_ROOTS,
    *(BRIDGE_ROOTS[0]+"/"+x for x in ("wg","awg2-fast","awg2-strong")),
    *(BRIDGE_ROOTS[4]+"/"+x for x in ("close","network")),
    *(BRIDGE_ROOTS[9]+"/"+x for x in ("close","network")),
    *(BRIDGE_ROOTS[10]+"/"+x for x in ("source-object","native-record","captured-state","native-instance","lifetime","retired")),
    *(BRIDGE_ROOTS[11]+"/"+x for x in ("joined","held","failed")),
    *(BRIDGE_ROOTS[13]+"/"+x for x in ("original","foreign-server","foreign-state","expired","unbounded")),
)
NATIVE_ROOTS = (
    N+"CaptureKeepsOriginalSource", N+"WholeGraphPrecedesAcquisition",
    N+"SecondBoxCannotReacquire", N+"ReadbackAndCallerStayCurrent",
    N+"PublicMeasurementUsesCapturedDNS", N+"PrivateContextCannotBeBorrowed",
)
NATIVE = (
    *NATIVE_ROOTS,
    *(NATIVE_ROOTS[0]+"/"+x for x in ("wg","awg2-fast","awg2-strong")),
    *(NATIVE_ROOTS[1]+"/"+x for x in ("middle-password","middle-detour","dns","mtu","extra-inbound","route-final")),
)
VERDICTS = (*BRIDGE,*NATIVE)
ORIGINAL_LIBBOX_ROOTS = (
    "TestRouterNodeChainBridgeRejectsMissingAndRetiredOwners",
    "TestRouterNodeChainBridgeRetainsCommandServerReadDeadline",
    "TestRouterNodeChainBridgeNativeOwnerRejectsCancelledAndReplacedGeneration",
    "TestRouterNodeChainBridgeNativeOwnerKeepsOriginalReadDeadline",
    "TestRouterNodeChainBridgeMTUClaimCannotReleaseReplacement",
    "TestRouterNodeChainBridgeMeasurementRequiresOriginalProvedOwner",
    "TestRouterNodeChainBridgeMeasurementRetainsOriginalActivityDeadline",
    "TestRouterNodeChainBridgeMeasurementBlocksMTUMutationUntilRelease",
    "TestRouterNodeChainBridgeMeasurementCloseKeepsCallerDeadline",
)
ORIGINAL_LIBBOX = (*ORIGINAL_LIBBOX_ROOTS,
    *(ORIGINAL_LIBBOX_ROOTS[2]+"/"+x for x in ("lifetime","generation","instance","retired")))
ORIGINAL_BOX_ROOTS = (
    "TestRouterVPNNodeChainNativeCaptureAndSubstitution",
    "TestRouterVPNNodeChainNativeHeldReadAndLateDial",
    "TestRouterVPNNodeChainNativeAWGCaptureAndOwnership",
)
ORIGINAL_BOX = (
    *ORIGINAL_BOX_ROOTS,
    *(ORIGINAL_BOX_ROOTS[0]+"/"+x for x in ("middle-key","dns","route","mtu")),
    *(ORIGINAL_BOX_ROOTS[1]+"/"+x for x in ("manager-held","cancel","network","replacement","closing")),
    *(ORIGINAL_BOX_ROOTS[2]+"/"+mode+suffix
      for mode in ("awg2-fast-wg","wg-awg2-strong","awg2-strong-awg2-fast-wg")
      for suffix in ("","/awg-parameters","/awg-key","/wg-downgrade","/skip-prefix")),
)
PROJECTIONS = {
    "socks_owner.go.tmpl":"protocol/routervpnnodesocks/socks_owner.go",
    "socks_scope.go.tmpl":"protocol/routervpnnodesocks/socks_scope.go",
    "socks_box.go.tmpl":"routervpn_node_chain_socks.go",
    "socks_server.go.tmpl":"experimental/libbox/routervpn_node_chain_socks_server.go",
    "socks_bridge.go.tmpl":"experimental/libbox/routervpn_node_chain_socks.go",
    "socks_lifecycle.go.tmpl":"experimental/libbox/routervpn_node_chain_socks_lifecycle.go",
    "socks_measurement.go.tmpl":"experimental/libbox/routervpn_node_chain_socks_measurement.go",
    "socks_bridge_test.go.tmpl":"experimental/libbox/routervpn_node_chain_socks_test.go",
    "socks_lifecycle_test.go.tmpl":"experimental/libbox/routervpn_node_chain_socks_lifecycle_test.go",
    "socks_measurement_test.go.tmpl":"experimental/libbox/routervpn_node_chain_socks_measurement_test.go",
    "socks_native_test.go.tmpl":"experimental/libbox/routervpn_node_chain_socks_native_test.go",
    "box.go.tmpl":"routervpn_node_chain.go",
}
CONTROLS = (
    dict(name="whole-original-graph",path=PROJECTIONS["socks_box.go.tmpl"],
         before="if routerVPNNodeChainOptionsDigest(ctx, options) != original.digest {",
         after="if false { // causal omission of complete original graph",
         root=NATIVE_ROOTS[1],cases=tuple(x for x in NATIVE if x==NATIVE_ROOTS[1] or x.startswith(NATIVE_ROOTS[1]+"/")),
         witness="altered complete graph did not fail at original preconstruction guard"),
    dict(name="one-original-construction",path=PROJECTIONS["socks_box.go.tmpl"],
         before="if original.attempted || ctx.Err() != nil {",
         after="if ctx.Err() != nil {",
         root=NATIVE_ROOTS[2],cases=(NATIVE_ROOTS[2],),
         witness="same typed construction reacquired native components"),
    dict(name="initial-native-readback",path=PROJECTIONS["socks_box.go.tmpl"],
         before=" || mtu != meta.MTU.Original || mtu < 1280 || mtu > meta.MTU.Ceiling",
         after="",root=NATIVE_ROOTS[3],cases=(NATIVE_ROOTS[3],),
         witness="fresh engine accepted MTU without continuation receipt"),
    dict(name="original-private-source",path=PROJECTIONS["socks_scope.go.tmpl"],
         before="original != c.source || ",after="",
         root=NATIVE_ROOTS[5],cases=(NATIVE_ROOTS[5],),
         witness="foreign context/source pair acquired original native construction"),
    dict(name="original-native-close",path=PROJECTIONS["socks_lifecycle.go.tmpl"],
         before="\tif err := native.capture.ClosedContext(ctx); err != nil {\n\t\treturn err\n\t}",
         after="\t// Causal omission of actual original native close receipt.",
         root=BRIDGE_ROOTS[11],cases=tuple(x for x in BRIDGE if x==BRIDGE_ROOTS[11] or x.startswith(BRIDGE_ROOTS[11]+"/")),
         witness="shared close substituted for original native Box join"),
    dict(name="original-startup-join",path=PROJECTIONS["socks_lifecycle.go.tmpl"],
         before="\t\tselect {\n\t\tcase <-state.done:\n\t\tcase <-ctx.Done():\n\t\t\treturn ctx.Err()\n\t\t}",
         after="\t\t// Causal omission of original startup join.",
         root=BRIDGE_ROOTS[5],cases=(BRIDGE_ROOTS[5],),
         witness="pending original startup lost its join or cancellation"),
)

def selection(source, source_sha, output):
    if not HEX40.fullmatch(source_sha):
        raise ValueError("Exact typed native candidate SHA is required")
    path=output.parent/"selection.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("Original trusted selection is absent")
    raw=path.read_bytes()
    record=json.loads(raw)
    if record.get("schema")!=1 or record.get("suite")!=SUITE or record.get("source_sha")!=source_sha or record.get("validation_scope")!="read-only-source-candidate":
        raise ValueError("Typed bridge selection changed original suite or candidate")
    for field in ("validator_sha","validator_tree","base_sha","base_tree","source_sha","source_tree"):
        if not isinstance(record.get(field),str) or not HEX40.fullmatch(record[field]):
            raise ValueError("Typed bridge selection lost exact Git identity")
    if COMMON.git(source,"rev-parse","HEAD")!=source_sha or COMMON.git(source,"rev-parse","HEAD^{tree}")!=record["source_tree"] or COMMON.git(source,"status","--porcelain","--untracked-files=all"):
        raise ValueError("Typed bridge candidate differs from original clean checkout")
    if COMMON.git(ROOT,"rev-parse","HEAD")!=record["validator_sha"] or COMMON.git(ROOT,"rev-parse","HEAD^{tree}")!=record["validator_tree"]:
        raise ValueError("Typed bridge validator differs from trusted selection")
    return record,raw

def native_snapshot(root):
    result={}
    for path in sorted(root.rglob("*")):
        relative=path.relative_to(root)
        if ".git" in relative.parts:
            continue
        if path.is_symlink():
            raise ValueError("Native source closure contains a link: "+str(relative))
        if path.is_file():
            result[relative.as_posix()]=hashlib.sha256(path.read_bytes()).hexdigest()
    if not result:
        raise ValueError("Native source closure is empty")
    return result

def checked_sources(source,core,xray):
    prep=module("socks_bridge_candidate_projection",source/"deploy/prepare-mobile-node-chain.py")
    for name,relative in PROJECTIONS.items():
        original,native=source/"mobile/chain"/name,core/relative
        if prep.TEMPLATES.get(name)!=relative or original.is_symlink() or native.is_symlink() or not original.is_file() or not native.is_file() or original.read_bytes()!=native.read_bytes():
            raise ValueError("Original typed native projection changed: "+relative)
    for relative,derive in (
        ("box.go",lambda text:prep.box_source(text)),
        ("experimental/libbox/command_server.go",lambda text:prep.command_source(core,text)),
    ):
        path=core/relative
        if path.is_symlink() or derive(path.read_text())!=path.read_bytes():
            raise ValueError("Original native construction hook changed: "+relative)
    packet=module("socks_bridge_candidate_packet",source/"deploy/prepare-sing-packet-concurrency.py")
    packet.verify(core)
    if "routervpnnodesocks" in (core/"include/registry.go").read_text():
        raise ValueError("Typed SOCKS owner acquired global registration")
    for relative in ("dns/transport/conn_pool.go","dns/transport/multiplexer.go","dns/transport/udp.go","protocol/socks/outbound.go"):
        original=subprocess.check_output(["git","show",PIN+":"+relative],cwd=core,timeout=20)
        if (core/relative).is_symlink() or (core/relative).read_bytes()!=original:
            raise ValueError("Original pinned caller changed: "+relative)
    return {"core":native_snapshot(core),"xray":native_snapshot(xray)}

def checked_owner_sources(source,core,xray):
    gate=OWNER.load_gate(source)
    owner=OWNER.checked_sources(gate,source,core)
    return {"owner":owner,"core":native_snapshot(core),"xray":native_snapshot(xray)}

def prepare_owner(source,source_sha,core,xray):
    if COMMON.git(source,"rev-parse","HEAD")!=source_sha:
        raise ValueError("Preparation source moved after selection")
    if core.exists() or xray.exists():
        raise ValueError("Desktop preparation requires its own fresh pinned trees")
    OWNER.prepare(OWNER.load_gate(source),core,xray,dict(os.environ))

def prepare_mobile(source,source_sha,core,xray,go):
    # Runs only as a bounded, joined child after exact candidate selection.
    # Reuse each shipping preparer in the same order as the mobile build.
    if COMMON.git(source,"rev-parse","HEAD")!=source_sha:
        raise ValueError("Preparation source moved after selection")
    build=module("socks_bridge_candidate_build",source/"deploy/build-native-runtime.py")
    if build.PIN!=PIN or build.TOOLCHAIN!="go1.26.3":
        raise ValueError("Original pinned native toolchain changed")
    # Desktop and mobile generated Tor namespaces are deliberately different.
    # Start from separate clean pinned checkouts, exactly as the shipping mobile
    # build does. Never remove a generated file or weaken its namespace guard.
    if core.exists() or xray.exists():
        raise ValueError("Mobile preparation requires its own fresh pinned trees")
    build.checkout(core,"https://github.com/SagerNet/sing-box.git",PIN)
    build.checkout(xray,"https://github.com/XTLS/Xray-core.git",build.POLICY.XRAY.XRAY_PIN)
    if COMMON.git(core,"rev-parse","HEAD")!=PIN or COMMON.git(xray,"rev-parse","HEAD")!=build.POLICY.XRAY.XRAY_PIN:
        raise ValueError("Original mobile source pins changed")
    commands=(
        [sys.executable,source/"deploy/prepare-mobile-openvpn.py",core],
        [sys.executable,source/"deploy/prepare-mobile-multihop.py",core],
        [sys.executable,source/"deploy/test_retained_strategy_preparation.py",core],
        [sys.executable,source/"deploy/prepare-mobile-tor.py",core,"--go",go],
        [sys.executable,source/"deploy/prepare-apple-xray.py",core,xray],
        ["git","-C",core,"tag","-f","v1.14.1",PIN],
        [go,"mod","edit","-go=1.26.3"],
        [go,"mod","edit","-require=github.com/xtls/xray-core@"+build.POLICY.XRAY_VERSION],
        [go,"mod","edit","-replace=github.com/xtls/xray-core="+str(xray)],
        [go,"mod","tidy"],[go,"mod","verify"],
    )
    for command in commands:
        subprocess.run(list(map(str,command)),cwd=core,check=True)

def require_events(raw,status,package,expected,control=None):
    parser=CORE if package==LIBBOX else BOX_CORE if package==BOX else None
    if parser is None:
        raise ValueError("Foreign native package")
    # Native output must be entirely framed; the reused shared parser then
    # enforces each exact run/terminal, no skip/race/panic/build failure.
    begun=False;ended=False;started=set();finished=set();outputs={};build_bytes=0
    expected=set(expected)
    for line in raw.splitlines():
        event=json.loads(line)
        if not isinstance(event,dict):
            raise ValueError("Unframed native verdict")
        action,name=event.get("Action"),event.get("Test")
        if action=="build-output":
            build_bytes+=len(event.get("Output","").encode())
            if begun or ended or event.get("ImportPath")!=package+".test" or build_bytes>65536:
                raise ValueError("Foreign, late or excessive native build output")
            continue
        if event.get("Package")!=package or ended:
            raise ValueError("Foreign or late native event")
        if name:
            if not begun or name not in expected:
                raise ValueError("Unstarted or foreign native test")
            if action=="run":
                if name in started or name in finished:
                    raise ValueError("Repeated native start")
                parts=name.split("/")
                if any("/".join(parts[:n]) not in started or "/".join(parts[:n]) in finished for n in range(1,len(parts))):
                    raise ValueError("Original native ancestor is not active")
                started.add(name)
            elif action=="output":
                if name not in started or name in finished or not isinstance(event.get("Output"),str):
                    raise ValueError("Native witness is outside its original active test")
                outputs[name]=outputs.get(name,"")+event["Output"]
            elif action in ("pass","fail","skip"):
                if name not in started or name in finished or any(x.startswith(name+"/") and x not in finished for x in expected):
                    raise ValueError("Early or repeated native terminal")
                finished.add(name)
            else:
                raise ValueError("Unexpected native test action")
        elif action=="start":
            if begun:
                raise ValueError("Repeated native package start")
            begun=True
        elif action=="output":
            if not begun or not isinstance(event.get("Output"),str):
                raise ValueError("Native package output lost its start")
            if control and control["witness"] in event["Output"]:
                raise ValueError("Native witness escaped its original test")
        elif action in ("pass","fail","skip"):
            if not begun or finished!=expected:
                raise ValueError("Native package ended before its complete inventory")
            ended=True
        else:
            raise ValueError("Unexpected native package action")
    if not begun or not ended:
        raise ValueError("Native package did not join its exact inventory")
    leaves=tuple(name for name in expected if not any(child.startswith(name+"/") for child in expected))
    case=parser.Case("native","",frozenset(expected),90,600,
        mutation=control["name"] if control else "",
        witness=control["witness"] if control else "",
        witness_tests=frozenset(leaves) if control else frozenset())
    if control and any(outputs.get(name,"").count(control["witness"])!=(1 if name in leaves else 0) for name in expected):
        raise ValueError("Native control lost its exact unique leaf witness")
    record=parser.verdict(raw,case,status)
    if not record["accepted"]:
        raise ValueError("Original native verdict refused: "+record["reason"])
    return record

def mutate(control,original):
    if original.count(control["before"])!=1:
        raise ValueError("Original native causal seam changed: "+control["name"])
    changed=original.replace(control["before"],control["after"],1)
    if changed==original:
        raise ValueError("Native control made no source change")
    return changed

def validate(source,source_sha,output,go="go"):
    source,output=Path(source).resolve(strict=True),Path(output).absolute()
    if output.is_symlink() or output.exists() or output==source or source in output.parents:
        raise ValueError("Native output must be fresh and outside candidate")
    metadata,raw_selection=selection(source,source_sha,output)
    before=CORE.snapshot(source)
    output.mkdir(mode=0o700)
    (output/"source-before.json").write_text(json.dumps(before,sort_keys=True)+"\n")
    compiler=shutil.which(go)
    if compiler is None:
        raise ValueError("Pinned Go compiler is missing")
    env=dict(os.environ,CGO_ENABLED="1",GOTOOLCHAIN="local",GOWORK="off",GOFLAGS="",PYTHONDONTWRITEBYTECODE="1",
             GOMAXPROCS="2",GOGC="100",GOMEMLIMIT="2GiB")
    env["PATH"]=str(Path(compiler).parent)+os.pathsep+env.get("PATH","")
    version=subprocess.check_output([compiler,"version"],text=True,env=env,timeout=30).strip()
    if version!="go version go1.26.3 linux/amd64":
        raise ValueError("Typed native gate requires pinned Go1.26.3 linux/amd64")
    receipt=dict(schema=1,suite=SUITE,selection=metadata,status="running",phases=[],
        scope="encrypted-original-owner-and-typed-native-object-composition",
        typed_object_boundaries=["TUN","OS monitor","packet-prefix I/O","selected DNS responses"],
        prepared_source_roles={"mobile":"original shipping mobile preparers on pristine pinned core",
                               "desktop_owner":"unchanged original owner preparer on independent pinned core"},
        installed_native_accepted=False,successful_run_accepted=False,public_native_admission=False,
        compiler=compiler,go_version=version,
        resource_limits=dict(parallel_packages=1,GOMAXPROCS=2,GOGC=100,GOMEMLIMIT="2GiB"),
        trusted_executor_sha256=hashlib.sha256(CORE_PATH.read_bytes()).hexdigest(),
        trusted_preparation_helpers_sha256=hashlib.sha256(COMMON_PATH.read_bytes()).hexdigest(),
        trusted_owner_validator_sha256=hashlib.sha256(OWNER_PATH.read_bytes()).hexdigest())
    def save():
        (output/"progress.json").write_text(json.dumps(receipt,indent=2)+"\n")
    def run(name,command,cwd,bound):
        command=list(map(str,command));log=output/(name+".log");start=time.monotonic()
        try:
            status,timed_out,joined=CORE.execute(command,cwd,env,log,bound)
        except BaseException as error:
            receipt["phases"].append(dict(name=name,command=command,timeout=bound,error=type(error).__name__))
            save();raise
        raw=log.read_bytes()
        receipt["phases"].append(dict(name=name,command=command,timeout=bound,
            seconds=time.monotonic()-start,status=status,timed_out=timed_out,process_group_joined=joined,
            output_sha256=hashlib.sha256(raw).hexdigest()))
        save()
        if timed_out or not joined:
            raise RuntimeError("Original native child timed out or did not join")
        return status,raw
    save()
    try:
        with tempfile.TemporaryDirectory(prefix="routervpn-socks-bridge-",dir=output.parent) as temp:
            work=Path(temp);core,xray=work/"mobile-core",work/"mobile-xray"
            owner_core,owner_xray=work/"owner-core",work/"owner-xray"
            status,raw=run("original-owner-preflight",
                [sys.executable,source/"deploy/test_desktop_tor_preparation.py","--daemon-capture-only"],source,60)
            OWNER.require_daemon_preflight(raw.decode(),status)
            status,_=run("prepare-owner",
                [sys.executable,Path(__file__).resolve(),"--prepare-owner","--source",source,
                 "--source-sha",source_sha,"--core",owner_core,"--xray",owner_xray],source,600)
            if status:
                raise ValueError("Original shipping desktop owner preparation failed")
            status,_=run("prepare-mobile",
                [sys.executable,Path(__file__).resolve(),"--prepare-mobile","--source",source,
                 "--source-sha",source_sha,"--core",core,"--xray",xray,"--go",compiler],source,600)
            if status:
                raise ValueError("Original shipping mobile preparation failed")
            native_before={"mobile":checked_sources(source,core,xray),
                           "desktop_owner":checked_owner_sources(source,owner_core,owner_xray)}
            (output/"native-before.json").write_text(json.dumps(native_before,sort_keys=True)+"\n")
            receipt["native_source_sha256"]=hashlib.sha256(json.dumps(native_before,sort_keys=True,separators=(",",":")).encode()).hexdigest()
            flags=["-race","-p=1","-mod=readonly","-tags="+TAGS,"-ldflags=-checklinkname=0"]
            images={}
            owner_gate=OWNER.load_gate(source)
            compiler,captured,architecture=owner_gate.NODE.selected_compiler(compiler,owner_core,env)
            if architecture!="amd64":
                raise ValueError("Original native owner compiler selected another architecture")
            env.update(captured)
            env["CGO_ENABLED"]="1"
            receipt["compiler"]=str(compiler)
            owner_flags=["-race","-p=1","-mod=readonly","-tags="+",".join(owner_gate.NODE.TAGS),"-ldflags=-checklinkname=0"]
            for package,target,name in ((OWNER.PACKAGE,"./protocol/routervpnamnezia","owner"),
                                        (LIBBOX,"./experimental/libbox","libbox"),(BOX,".","box")):
                image=work/(name+".test")
                compile_flags=owner_flags if package==OWNER.PACKAGE else flags
                build_core=owner_core if package==OWNER.PACKAGE else core
                status,_=run(name+"-build",[compiler,"test","-c",*compile_flags,"-o",image,target],build_core,600)
                if status:
                    raise ValueError("Actual native "+name+" image failed to compile")
                images[package]=(image,COMMON.image_identity(image))
            owner_image,_=images[OWNER.PACKAGE]
            # Reuse the exact trusted encrypted-owner/peer inventories and
            # original parser. No reduced replica or native verdict is inferred.
            for name,roots,expected in (
                ("original-encrypted-owner",OWNER.ROOTS,OWNER.VERDICTS),
                ("original-encrypted-peer",(OWNER.ORIGINAL_ROOT,),OWNER.ORIGINAL),
            ):
                status,raw=run(name,[owner_image,"-test.run=^("+"|".join(roots)+")$",
                    "-test.count=1","-test.timeout=90s","-test.v"],owner_core,100)
                if status:
                    raise ValueError("Original encrypted owner/peer baseline failed")
                owner_gate.NODE.require_native_verdicts(raw.decode(),expected,name)
            owner_controls=[]
            owner_original=(owner_core/OWNER.OWNER_PROJECTION).read_text()
            for control in OWNER.CONTROLS:
                changed=mutate(control,owner_original)
                replacement,overlay=work/("owner-"+control["name"]+".go"),work/("owner-"+control["name"]+".json")
                replacement.write_text(changed)
                overlay.write_text(json.dumps({"Replace":{str(owner_core/OWNER.OWNER_PROJECTION):str(replacement)}}))
                status,raw=run("owner-"+control["name"],[compiler,"test",*owner_flags,"-json",
                    "-overlay="+str(overlay),"-run=^"+control["root"]+"$","-count=1","-timeout=90s",
                    "./protocol/routervpnamnezia"],owner_core,600)
                OWNER.require_control(raw.decode(),status,control)
                owner_controls.append(dict(name=control["name"],cases=list(control["cases"]),
                    failed_cases=sorted(OWNER.required_failures(control)[1]),witness=control["witness"],
                    mutated_sha256=hashlib.sha256(changed.encode()).hexdigest()))
            baseline=(
                ("typed-native",LIBBOX,(*BRIDGE_ROOTS,*NATIVE_ROOTS),VERDICTS),
                ("original-libbox",LIBBOX,ORIGINAL_LIBBOX_ROOTS,ORIGINAL_LIBBOX),
                ("original-box",BOX,ORIGINAL_BOX_ROOTS,ORIGINAL_BOX),
            )
            records=[]
            for name,package,roots,expected in baseline:
                image,_=images[package]
                status,raw=run(name,[compiler,"tool","test2json","-t","-p",package,image,
                    "-test.run=^("+"|".join(roots)+")$","-test.count=1","-test.timeout=90s","-test.v"],core,100)
                records.append(dict(name=name,**require_events(raw,status,package,expected)))
            controls=[]
            for control in CONTROLS:
                original=core/control["path"];changed=mutate(control,original.read_text())
                replacement,overlay=work/(control["name"]+".go"),work/(control["name"]+".json")
                replacement.write_text(changed)
                overlay.write_text(json.dumps({"Replace":{str(original):str(replacement)}}))
                status,raw=run(control["name"],[compiler,"test",*flags,"-json","-overlay="+str(overlay),
                    "-run=^"+control["root"]+"$","-count=1","-timeout=90s","./experimental/libbox"],core,600)
                result=require_events(raw,status,LIBBOX,control["cases"],control)
                controls.append(dict(name=control["name"],original_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
                    mutated_sha256=hashlib.sha256(changed.encode()).hexdigest(),**result))
            native_after={"mobile":checked_sources(source,core,xray),
                          "desktop_owner":checked_owner_sources(source,owner_core,owner_xray)}
            if native_after!=native_before or CORE.snapshot(source)!=before or COMMON.git(source,"status","--porcelain","--untracked-files=all"):
                raise ValueError("Original native or candidate source changed during execution")
            if (output.parent/"selection.json").read_bytes()!=raw_selection or selection(source,source_sha,output)[0]!=metadata:
                raise ValueError("Original native source selection changed during execution")
            for image,identity in images.values():
                if COMMON.image_identity(image)!=identity:
                    raise ValueError("Original compiled native image changed")
            receipt.update(status="passed",cases=list(VERDICTS),original_owner_cases=list(OWNER.VERDICTS),
                original_peer_cases=list(OWNER.ORIGINAL),owner_controls=owner_controls,original_libbox_cases=list(ORIGINAL_LIBBOX),
                original_box_cases=list(ORIGINAL_BOX),baselines=records,controls=controls,
                images={package:list(identity) for package,(_,identity) in images.items()})
            (output/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
    except BaseException as error:
        receipt.update(status="failed",error=str(error));raise
    finally:
        save()
    return receipt

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite",choices=(SUITE,))
    parser.add_argument("--source",required=True,type=Path)
    parser.add_argument("--source-sha",required=True)
    parser.add_argument("--output",type=Path)
    parser.add_argument("--go",default="go")
    parser.add_argument("--prepare-mobile",action="store_true",help=argparse.SUPPRESS)
    parser.add_argument("--prepare-owner",action="store_true",help=argparse.SUPPRESS)
    parser.add_argument("--core",type=Path,help=argparse.SUPPRESS)
    parser.add_argument("--xray",type=Path,help=argparse.SUPPRESS)
    args=parser.parse_args()
    if args.prepare_mobile or args.prepare_owner:
        if args.prepare_mobile==args.prepare_owner or args.core is None or args.xray is None or args.suite or args.output:
            parser.error("exact internal mobile preparation arguments required")
        if args.prepare_mobile:
            prepare_mobile(args.source,args.source_sha,args.core,args.xray,args.go)
        else:
            prepare_owner(args.source,args.source_sha,args.core,args.xray)
    else:
        if args.suite!=SUITE or args.output is None or args.core or args.xray:
            parser.error("suite and output are required")
        validate(args.source,args.source_sha,args.output,args.go)

if __name__=="__main__":
    main()
