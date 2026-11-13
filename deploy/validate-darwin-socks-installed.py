#!/usr/bin/env python3
"""Require the exact complete Darwin bundle and original37 plus typed8 installed cases."""
from pathlib import Path
from contextlib import contextmanager
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SUITE = "darwin-socks-installed"
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
TEST = "TestMacOSRetainedNodeChainSOCKSNativeHost"
AUTHORITY = "TestDesktopDarwinInstalledSOCKSNodeChainFixtureKeepsOriginalSources"
AUTHORITY_CASES = (AUTHORITY, *(AUTHORITY+"/"+mode for mode in ("wg","awg2-fast","awg2-strong")))
TYPED = ("node-chain-socks-wg-connect","node-chain-socks-awg-fast-connect","node-chain-socks-awg-strong-connect",
         "node-chain-socks-wg-wrong-middle-key","node-chain-socks-wg-wrong-middle-public",
         "node-chain-socks-wg-final-dns-failure","node-chain-socks-wg-final-node-failure",
         "node-chain-socks-wg-middle-source")
FLAG = "ROUTERVPN_DARWIN_SOCKS_NODE_CHAIN_HOST_ACCEPTANCE"
SOURCE_CONTROL = "installed source changed original SOCKS credential or invented paired assets"
BUILD_SECONDS, TOOLCHAIN_SECONDS = 3600, 2400

def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec);sys.modules[name]=result
    spec.loader.exec_module(result)
    return result

CORE=module("installed_socks_process",ROOT/"deploy/test_focused_multihop_clocks.py")
IDENTITY=module("installed_socks_identity",ROOT/"deploy/focused_source_identity.py")
SDK=module("installed_socks_build_owner",ROOT/"deploy/validate-android-sdk-source.py")
BASE=module("installed_socks_original",ROOT/"deploy/test_macos_node_chain_host.py")
ORIGINAL=tuple(BASE.CASES)

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def sha(path):
    return digest(Path(path).read_bytes())

def selection(source,source_sha,output):
    path=output.parent/"selection.json"
    if not HEX40.fullmatch(source_sha) or path.is_symlink() or not path.is_file():
        raise ValueError("Original installed source selection is missing")
    raw=path.read_bytes();value=json.loads(raw)
    if type(value.get("schema")) is not int or value["schema"]!=1 or value.get("suite")!=SUITE or value.get("source_sha")!=source_sha or value.get("validation_scope")!="read-only-source-candidate":
        raise ValueError("Installed selection changed its exact source or purpose")
    for key in ("validator_sha","validator_tree","base_sha","base_tree","source_sha","source_tree"):
        if not isinstance(value.get(key),str) or not HEX40.fullmatch(value[key]):
            raise ValueError("Installed selection lost original Git identity")
    IDENTITY.original_checkout(ROOT,value["validator_sha"])
    IDENTITY.original_checkout(source,source_sha)
    for work,commit,tree in ((ROOT,value["validator_sha"],value["validator_tree"]),(source,source_sha,value["source_tree"])):
        if CORE.git(work,"rev-parse","HEAD").decode().strip()!=commit or CORE.git(work,"rev-parse","HEAD^{tree}").decode().strip()!=tree:
            raise ValueError("Installed selection changed original commit/tree")
    return value,raw

def native_target():
    arch={"x86_64":"amd64","arm64":"arm64"}.get(platform.machine())
    if platform.system()!="Darwin" or arch is None:
        raise ValueError("Installed native gate requires its matching Darwin host")
    return "darwin/"+arch

def native_environment(original,target):
    for key,wanted in (("GOOS","darwin"),("GOARCH",target.split("/")[1])):
        if original.get(key,wanted)!=wanted:
            raise ValueError("Installed dispatch labels a foreign native target")
    env=dict(original,CGO_ENABLED="1",GOTOOLCHAIN="local",GOWORK="off",GOFLAGS="-p=2 -mod=readonly",
             GOMAXPROCS="2",GOGC="100",GOMEMLIMIT="2GiB",PYTHONDONTWRITEBYTECODE="1",
             GOOS="darwin",GOARCH=target.split("/")[1],
             ROUTERVPN_DARWIN_NATIVE_HOST_ACCEPTANCE="1",ROUTERVPN_DARWIN_NODE_CHAIN_HOST_ACCEPTANCE="1",
             ROUTERVPN_DARWIN_SOCKS_NODE_CHAIN_HOST_ACCEPTANCE="1")
    if env.get("HOMEVPN_MTU_BENCH_FAKE"):
        raise ValueError("Installed native gate refuses fake MTU")
    # Setup reports its exact local environment in JSON. It may not append state
    # to a later workflow step while this original driver is still running.
    env.pop("GITHUB_ENV",None);env.pop("GITHUB_PATH",None)
    return env

def apply_toolchain(raw,target,env):
    value=json.loads(raw)
    if value.get("target")!=target or value.get("rust_target")!=BASE.BUILD.PQ.TARGETS[target]:
        raise ValueError("Original native toolchain changed target")
    values,paths=value.get("environment"),value.get("prepend_path")
    if not isinstance(values,dict) or not isinstance(paths,list) or not paths:
        raise ValueError("Original native toolchain environment is incomplete")
    suffix=value["rust_target"].replace("-","_")
    required={"RUSTUP_TOOLCHAIN","LIBCLANG_PATH","CC","CXX","AR","CC_"+suffix,"CXX_"+suffix,
              "AR_"+suffix,"CARGO_TARGET_"+suffix.upper()+"_LINKER"}
    if values.get("RUSTUP_TOOLCHAIN")!=BASE.BUILD.PQ.RUST:
        raise ValueError("Installed toolchain changed the original Rust source pin")
    if set(values)!=required or any(not isinstance(v,str) or not v or "\n" in v or "\r" in v for v in [*values.values(),*paths]):
        raise ValueError("Original native toolchain exported foreign authority")
    if any(not Path(v).is_absolute() for v in paths):
        raise ValueError("Original native toolchain PATH is not captured")
    env.update(values);env["PATH"]=os.pathsep.join([*paths,env.get("PATH","")])
    return value

def require_gate(gate):
    if tuple(gate.BASE.CASES)!=ORIGINAL or len(ORIGINAL)!=37 or tuple(gate.CASES)!=TYPED or gate.TEST!=TEST or tuple(gate.AUTHORITY_CASES)!=AUTHORITY_CASES:
        raise ValueError("Installed native gate changed original37 or typed8 inventory")

@contextmanager
def capture_cases(gate,output,outputs,observations):
    original=gate.CONTROLLER.reported_run
    original_reuse=gate.BUILD.reuse
    def reused(bundle,*args,**kwargs):
        result=original_reuse(bundle,*args,**kwargs)
        if Path(bundle).name=="sealed-bundle":
            value=sha(Path(bundle)/"NATIVE-RUNTIME.json")
            if "signed_bundle" in observations and observations["signed_bundle"]!=value:
                raise ValueError("Original sealed bundle changed during validation")
            observations["signed_bundle"]=value
        return result
    def observed(command,**kwargs):
        index=len(outputs)
        if index>=45 or kwargs.get("timeout")!=270:
            raise ValueError("Installed native invocation count or original bound changed")
        case=(*ORIGINAL,*TYPED)[index]
        root=TEST if case in TYPED else BASE.TEST
        strings=[str(x) for x in command]
        if strings.count("-test.run=^"+root+"$/^"+case+"$")!=1 or strings.count("-test.timeout=240s")!=1 or strings.count("-test.count=1")!=1:
            raise ValueError("Installed native invocation changed exact selected case")
        try:
            text=original(command,**kwargs)
        except BaseException as failure:
            raw=getattr(failure,"output",b"")
            if isinstance(raw,str):raw=raw.encode()
            (output/("native-%02d-%s-failure.log"%(index,case))).write_bytes(raw or (type(failure).__name__+": "+str(failure)).encode())
            raise
        (output/("native-%02d-%s.log"%(index,case))).write_text(text)
        outputs.append(text)
        return text
    gate.CONTROLLER.reported_run=observed
    gate.BUILD.reuse=reused
    try:
        yield
    finally:
        gate.CONTROLLER.reported_run=original
        gate.BUILD.reuse=original_reuse

def require_receipt(value,target,metadata,policy,bundle_hash,signed_hash,outputs,gate):
    exact={"schema":1,"gate":"installed-darwin-ordered-socks-host","scope":"installed-controller-typed-socks-and-original-preservation",
           "target":target,"public_darwin_admission":"closed","native":True}
    for key,wanted in exact.items():
        if type(value.get(key)) is not type(wanted) or value[key]!=wanted:
            raise ValueError("Installed native receipt changed scope")
    if value.get("repository")!={"repository":"Eabusham2/router-vpn","commit":metadata["source_sha"],"tree":metadata["source_tree"]}:
        raise ValueError("Installed native receipt borrowed a different source")
    if value.get("source_sha256")!=policy or value.get("bundle_sha256")!=bundle_hash or value.get("sealed_bundle_sha256")!=signed_hash:
        raise ValueError("Installed native receipt borrowed a different complete bundle")
    if value.get("cases")!=list(TYPED) or value.get("original_cases")!=list(ORIGINAL) or value.get("completed")!=list((*ORIGINAL,*TYPED)) or len(outputs)!=45:
        raise ValueError("Installed native receipt omitted an original native case")
    for key in ("authority_cases","hysteria_authority_cases","typed_authority_cases"):
        wanted={"authority_cases":BASE.AUTHORITY_CASES,"hysteria_authority_cases":BASE.HYSTERIA_AUTHORITY_CASES,"typed_authority_cases":AUTHORITY_CASES}[key]
        if value.get(key)!=list(wanted) or len(wanted)!=4:
            raise ValueError("Installed native receipt omitted original source authority")
    for key in ("authority_output_sha256","hysteria_authority_output_sha256","typed_authority_output_sha256","output_sha256"):
        if not isinstance(value.get(key),str) or not HEX64.fullmatch(value[key]):
            raise ValueError("Installed native receipt lost its original output")
    for key,cases,witness in (("hysteria_source_control",BASE.HYSTERIA_AUTHORITY_CASES,BASE.HYSTERIA_CONTROL_WITNESS),
                              ("typed_source_control",AUTHORITY_CASES,SOURCE_CONTROL)):
        item=value.get(key)
        if not isinstance(item,dict) or item.get("cases")!=list(cases) or item.get("witness")!=witness or any(not isinstance(item.get(k),str) or not HEX64.fullmatch(item[k]) for k in ("image_sha256","output_sha256")):
            raise ValueError("Installed native receipt omitted exact compiled negative control")
    images=value.get("images")
    if not isinstance(images,dict) or set(images)!={"controller","peer"} or any(not isinstance(v,str) or not HEX64.fullmatch(v) for v in images.values()):
        raise ValueError("Installed native receipt lost original controller/peer images")
    sources=value.get("sources")
    if not isinstance(sources,dict) or not isinstance(sources.get("application"),dict) or not sources["application"]:
        raise ValueError("Installed native receipt lost original full source inventory")
    for name,claimed in sources["application"].items():
        path=Path(name)
        if path.is_absolute() or ".." in path.parts or not isinstance(claimed,str) or not HEX64.fullmatch(claimed) or sha(gate.ROOT/path)!=claimed:
            raise ValueError("Installed application source inventory changed")
    for name in gate.SOURCES:
        if sources["application"].get(name)!=sha(gate.ROOT/name):
            raise ValueError("Installed source receipt differs from original typed fixture")
    for index,(case,text) in enumerate(zip((*ORIGINAL,*TYPED),outputs)):
        (gate.check_verdict if case in TYPED else BASE.check_verdict)(text,case)

def validate(source,source_sha,output,go="go"):
    target=native_target()
    source,output=Path(source).resolve(strict=True),Path(output).absolute()
    if output.exists() or output.is_symlink() or output==source or source in output.parents:
        raise ValueError("Installed evidence must be fresh outside the pristine candidate")
    selected,selection_raw=selection(source,source_sha,output)
    before=CORE.snapshot(source);version=SDK.full_history_version(source)
    output.mkdir(mode=0o700);(output/"source-before.json").write_text(json.dumps(before,sort_keys=True)+"\n")
    env=native_environment(os.environ,target)
    compiler=shutil.which(go)
    if compiler is None:raise ValueError("Pinned original Go compiler is missing")
    env["PATH"]=os.pathsep.join([str(Path(compiler).parent),env.get("PATH","")])
    receipt=dict(schema=1,suite=SUITE,selection=selected,target=target,accepted=False,phases=[],
                 public_darwin_admission="closed",source_files=len(before),swift_editor_accepted=False,
                 generated_fifty_and_mtu_rollback_accepted=False,
                 entrypoint="tagged root-owned admission bridge; shipping decode/capture/preflight/stage/proof/measurement/disconnect",
                 required_later_activation="public Darwin handler and UI remain closed until all native gates pass")
    workspace=None;work=source;joined=True;complete=False
    def save():
        (output/"manifest.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    def run(name,command,bound,cwd=None):
        nonlocal joined
        log=output/(name+".log");start=time.monotonic();joined=False
        code,timed_out,joined=CORE.execute([str(x) for x in command],work if cwd is None else cwd,env,log,bound)
        receipt["phases"].append(dict(name=name,command=[str(x) for x in command],outer_seconds=bound,seconds=time.monotonic()-start,
                                      exit=code,timed_out=timed_out,joined=joined,log_sha256=sha(log)))
        save()
        if code!=0 or timed_out or not joined:raise ValueError("Original installed phase failed or did not join: "+name)
        return log.read_bytes()
    save()
    try:
        workspace=SDK.OwnedBuildCheckout(source,output,source_sha,before,version)
        receipt["build_checkout"]=workspace.prepare(run);work=workspace.path;save()
        if run("pinned-go",[compiler,"version"],15).decode().strip()!="go version go1.26.3 "+target:
            raise ValueError("Installed build requires pinned matching Go")
        setup=run("original-native-toolchain",[sys.executable,work/"deploy/setup-desktop-native-toolchain.py",target,workspace.root/"toolchain"],TOOLCHAIN_SECONDS)
        receipt["toolchain"]=apply_toolchain(setup,target,env);save()
        run("original-dns-source-contract",[sys.executable,work/"deploy/test_dnsproxy_build.py"],120)
        run("original-dns-native",[sys.executable,work/"deploy/build-dnsproxy.py","test","--go",compiler],1800)
        run("original-native-concurrency-contract",[sys.executable,work/"deploy/test_linux_native_concurrency.py"],120)
        bundle=workspace.root/"complete-bundle"
        run("original-complete-native-runtime",[sys.executable,work/"deploy/build-native-runtime.py",target,bundle],BUILD_SECONDS)
        for name,script,args in (
                ("original-tor-delivery","test_desktop_tor_package.py",["--package",bundle,"--target",target,"--within-native"]),
                ("original-complete-bundle","test_desktop_native_bundle.py",[bundle,target]),
                ("original-delivery","test_native_runtime_delivery.py",["--bundle",bundle,"--target",target])):
            run(name,[sys.executable,work/"deploy"/script,*args],300)
        gate=module("installed_socks_candidate_gate",work/"deploy/test_macos_socks_node_chain_host.py")
        require_gate(gate)
        policy=gate.BUILD.digest();gate.BUILD.reuse(bundle,target,env=env)
        bundle_hash=sha(bundle/"NATIVE-RUNTIME.json")
        (output/"complete-bundle-receipt.json").write_bytes((bundle/"NATIVE-RUNTIME.json").read_bytes())
        outputs=[];observations={}
        # Failure retains both the gate's captured workspace and the independent
        # build clone. No outer timeout or process exit can manufacture DOWN.
        joined=False
        with capture_cases(gate,output,outputs,observations):
            value=gate.execute(bundle,go=str(compiler),environment=env,required_commit=source_sha,receipt_file=output/"native-receipt.json")
        joined=True
        if json.loads((output/"native-receipt.json").read_bytes())!=value:
            raise ValueError("Installed native durable receipt differs from original result")
        signed_hash=observations.get("signed_bundle")
        if not isinstance(signed_hash,str) or not HEX64.fullmatch(signed_hash):
            raise ValueError("Installed receipt lost its signed original bundle")
        require_receipt(value,target,selected,policy,bundle_hash,signed_hash,outputs,gate)
        if gate.BUILD.digest()!=policy or sha(bundle/"NATIVE-RUNTIME.json")!=bundle_hash:
            raise ValueError("Installed execution changed its complete bundle policy")
        gate.BUILD.reuse(bundle,target,env=env)
        receipt["build_checkout_after"]=workspace.verify()
        if CORE.snapshot(source)!=before or selection(source,source_sha,output)!=(selected,selection_raw):
            raise ValueError("Installed execution changed its pristine selection")
        (output/"source-after.json").write_text(json.dumps(before,sort_keys=True)+"\n")
        receipt.update(native_receipt_sha256=sha(output/"native-receipt.json"),bundle_receipt_sha256=sha(output/"complete-bundle-receipt.json"),
                       cases=list(TYPED),original_cases=list(ORIGINAL),native_scope=value["scope"])
        complete=True
    except BaseException as failure:
        receipt["failure_type"]=type(failure).__name__
        raise
    finally:
        if workspace is not None:
            try:
                receipt["workspace_cleanup"]=workspace.cleanup(joined and complete)
                if not receipt["workspace_cleanup"]["removed"]:complete=False
            except BaseException as failure:
                complete=False
                receipt["cleanup_error"]=type(failure).__name__
                receipt["retained_workspace"]=str(workspace.root)
        receipt["accepted"]=complete
        receipt["logs"]={p.name:sha(p) for p in sorted(output.glob("*.log"))}
        save()
    if not complete:raise ValueError("Installed native workspace did not retire")
    return receipt

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",required=True,type=Path)
    parser.add_argument("--source-sha",required=True)
    parser.add_argument("--output",required=True,type=Path)
    parser.add_argument("--go",default="go")
    args=parser.parse_args()
    print(json.dumps(validate(args.source,args.source_sha,args.output,args.go),sort_keys=True))
