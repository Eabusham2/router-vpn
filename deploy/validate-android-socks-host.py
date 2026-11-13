#!/usr/bin/env python3
"""Run exact shipping Android SOCKS source and host ownership, never SDK/device acceptance."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
SUITE = "android-socks-host"
CORE_PATH = ROOT/"deploy/test_focused_multihop_clocks.py"
spec = importlib.util.spec_from_file_location("android_socks_original_executor", CORE_PATH)
CORE = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = CORE
spec.loader.exec_module(CORE)
PHASES = json.loads(r'''[{"name":"source","args":["android/test_android_connection_profiles.py","--case-family","ordered-chain"],"controls":["hysteria-final","hysteria-final","hysteria-final","hostname","hostname","imported","imported","native-identity","native-identity","identity-compiler","paired-identity","paired-identity","editor-mixed","editor-mixed-ui","editor-mixed-ui","product-handoff","product-handoff","product-handoff","product-handoff","source","generation","atomic","restore","editor-generation","ordered-permission","editor-native","editor-atomic","editor-budget","editor-ui"],"prefix":"Android ordered source causal control rejected: ","terminals":["Android ordered sources: ([1-9][0-9]*) checks; actual Go compilation, exact all-member saved capture and rollback passed","Android hostname ordered sources: ([1-9][0-9]*) shipping Java/shared Go checks passed; no native execution","Android ordered SOCKS source: ([1-9][0-9]*) checks; actual shared compiler and saved profile ownership passed","Android paired HY2 final sources: ([1-9][0-9]*) shipping Java/shared Go checks passed; native crypto separate"]},{"name":"typed-host","args":["android/test_android_node_chain_socks_runtime.py"],"controls":["0/success","1/success","2/pending","3/receipt","4/retired-factory","5/success"],"prefix":"Android typed SOCKS host causal control rejected: ","terminals":["Android typed SOCKS host: ([1-9][0-9]*) executable ownership checks passed; OS/native boundaries doubled\\.","Android typed SOCKS host: all (7) case families and 6 compiled controls passed"],"families":["success","pending","receipt","binding","factory","retired-factory","stale-proof"],"family_prefix":"Android typed SOCKS host case passed: "},{"name":"original-local","args":["android/test_android_node_chain_runtime.py"],"controls":["AndroidHomeStateStore/hysteria-final","LayeredVpnService/measurement","LayeredVpnService/measurement","AndroidNodeChainSession/source","AndroidNodeChainSession/source","AndroidNodeChainSession/proof","LayeredVpnService/cleanup","LayeredVpnService/destroyed","AndroidNodeChainRuntime/idle","LayeredVpnService/watchdog","LayeredVpnService/late-destroyed","AndroidNodeChainRuntime/preclaim","LayeredVpnService/preclaim","LayeredVpnService/destroyed","AndroidNodeChainRuntime/same-runtime","LayeredVpnService/publication","LayeredVpnService/publication","AndroidNodeChainRuntime/success","AndroidNodeChainRuntime/success","AndroidNodeChainRuntime/success","AndroidNodeChainRuntime/captured-drain","AndroidNodeChainRuntime/captured-drain","AndroidNodeChainSession/selection","AndroidNodeChainRuntime/captured-drain","LayeredVpnService/captured-drain"],"prefix":"Android ordered host causal control rejected: ","terminals":["Android ordered native host ownership: ([1-9][0-9]*) executable checks passed; OS/native handles doubled\\."]},{"name":"original-execution","args":["android/test_android_node_chain_execution_runtime.py"],"controls":["AndroidNodeChainSession/success","AndroidNodeChainRuntime/success","LayeredVpnService/cleanup","LayeredVpnService/cleanup","LayeredVpnService/cleanup","LayeredVpnService/cleanup","LayeredVpnService/mtu-cleanup","AndroidNodeChainExecutionCapture/success","AndroidNodeChainMTUPlatform/mtu-pause","LayeredVpnService/mtu-pause-close","LayeredVpnService/mtu-pause-close","AndroidNodeChainSession/native-receipt","AndroidNodeChainSession/bind-failure","LayeredVpnService/bind-pending","AndroidNodeChainSession/constructor","AndroidNodeChainSession/before-bind"],"prefix":"Android execution host causal control rejected: ","terminals":["Android ordered execution host: ([1-9][0-9]*) actual shipping Java checks PASS; native/OS boundaries doubled"]},{"name":"original-restore","args":["android/test_android_node_chain_execution_restore.py"],"controls":["foreign","effective","effective"],"prefix":"Android typed restore causal control rejected: ","terminals":["Android execution typed restore: ([1-9][0-9]*) shipping Java checks PASS; native capsules/OS doubled"]},{"name":"original-mtu","args":["android/test_android_node_chain_mtu.py"],"controls":["restored","constructor","constructor","policy","policy","observation","temporary","temporary","prefix","prefix","prefix","prefix"],"prefix":"Android ordered MTU causal control rejected: ","terminals":["Android ordered MTU adapter: ([1-9][0-9]*) executable checks passed; OS/native handles doubled\\."]}]''')
OUTER_SECONDS = 1200
HEX40 = re.compile(r"[0-9a-f]{40}")

def verdict(raw, code, timed_out, joined, phase):
    if code != 0 or timed_out or not joined:
        raise ValueError("Android child failed, timed out or did not join")
    text = raw.decode("utf-8", "strict")
    if re.search(r"(?m)^(Traceback \(|Exception in thread|panic:|fatal error:|WARNING: DATA RACE|FAIL\b)", text):
        raise ValueError("Android output contains an unrelated runtime failure")
    lines = text.splitlines()
    controls = [line[len(phase["prefix"]):] for line in lines if line.startswith(phase["prefix"])]
    if controls != phase["controls"]:
        raise ValueError("Android compiled control inventory changed")
    counts=[]
    for pattern in phase["terminals"]:
        found=re.findall("^"+pattern+"$",text,re.M)
        if len(found)!=1:
            raise ValueError("Android positive terminal omitted or repeated")
        counts.append(int(found[0]))
    if phase.get("families"):
        observed=[line[len(phase["family_prefix"]):] for line in lines if line.startswith(phase["family_prefix"])]
        if observed!=phase["families"]:
            raise ValueError("Android typed lifecycle case inventory changed")
    return dict(name=phase["name"],exit=code,timed_out=timed_out,process_group_joined=joined,
                positive_counts=counts,controls=controls,accepted=True)

def selection(source, sha, output):
    if not HEX40.fullmatch(sha):
        raise ValueError("Exact Android source SHA required")
    p=output.parent/"selection.json"
    if p.is_symlink() or not p.is_file():
        raise ValueError("Original trusted Android selection is absent")
    raw=p.read_bytes();record=json.loads(raw)
    if record.get("schema")!=1 or record.get("suite")!=SUITE or record.get("source_sha")!=sha or record.get("validation_scope")!="read-only-source-candidate":
        raise ValueError("Android suite or selected source changed")
    for key in ("validator_sha","validator_tree","base_sha","base_tree","source_sha","source_tree"):
        if not isinstance(record.get(key),str) or not HEX40.fullmatch(record[key]):
            raise ValueError("Android selection lost exact Git identity")
    for root,commit,tree in ((source,sha,record["source_tree"]),(ROOT,record["validator_sha"],record["validator_tree"])):
        if CORE.git(root,"rev-parse","HEAD").decode().strip()!=commit or CORE.git(root,"rev-parse","HEAD^{tree}").decode().strip()!=tree or CORE.git(root,"status","--porcelain","--untracked-files=all"):
            raise ValueError("Original Android checkout changed")
    return record,raw

def validate(source, sha, output):
    source=Path(source).resolve(strict=True);output=Path(output).absolute()
    if output.exists() or output.is_symlink() or output==source or source in output.parents:
        raise ValueError("Android evidence must be fresh and outside candidate")
    original,selected=selection(source,sha,output)
    before=CORE.snapshot(source)
    output.mkdir(mode=0o700)
    (output/"source-before.json").write_text(json.dumps(before,sort_keys=True)+"\n")
    if platform.system()!="Linux" or platform.machine()!="x86_64":
        raise ValueError("Android source gate requires its original Linux amd64 host")
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1",GOTOOLCHAIN="local",GOWORK="off",GOFLAGS="-p=2 -mod=readonly")
    go=subprocess.check_output(["go","version"],text=True,env=env,timeout=15).strip()
    java=subprocess.check_output(["javac","-version"],text=True,stderr=subprocess.STDOUT,env=env,timeout=15).strip()
    if go!="go version go1.26.3 linux/amd64" or not java.startswith("javac 17."):
        raise ValueError("Android gate lost pinned Go1.26.3 or JDK17")
    receipt=dict(schema=1,suite=SUITE,selection=original,status="running",go_version=go,javac_version=java,
                 source_file_count=len(before),source_closure_sha256=hashlib.sha256(json.dumps(before,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
                 scope="actual-shared-source-and-shipping-Java-host-ownership",sdk_accepted=False,native_tunnel_accepted=False,
                 explicit_boundaries=["Android OS","libbox native handles in host fixtures"],phases=[],
                 trusted_executor_sha256=hashlib.sha256(CORE_PATH.read_bytes()).hexdigest())
    def save():
        (output/"progress.json").write_text(json.dumps(receipt,indent=2)+"\n")
    save()
    try:
        for phase in PHASES:
            command=[sys.executable,str(source/phase["args"][0]),*phase["args"][1:]]
            log=output/(phase["name"]+".log");started=time.monotonic()
            try:
                code,timed_out,joined=CORE.execute(command,source,env,log,OUTER_SECONDS)
            except BaseException as error:
                receipt["phases"].append(dict(name=phase["name"],error=type(error).__name__,timeout=OUTER_SECONDS));save();raise
            raw=log.read_bytes()
            record=dict(name=phase["name"],command=command,timeout=OUTER_SECONDS,seconds=time.monotonic()-started,
                        exit=code,timed_out=timed_out,process_group_joined=joined,log_sha256=hashlib.sha256(raw).hexdigest())
            receipt["phases"].append(record);save()
            record.update(verdict(raw,code,timed_out,joined,phase));save()
        if CORE.snapshot(source)!=before or CORE.git(source,"status","--porcelain","--untracked-files=all"):
            raise ValueError("Android source changed while executing original fixtures")
        if (output.parent/"selection.json").read_bytes()!=selected or selection(source,sha,output)[0]!=original:
            raise ValueError("Android original source selection changed")
        receipt["status"]="passed"
        (output/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
    except BaseException as error:
        receipt.update(status="failed",error=str(error));raise
    finally:
        save()
    return receipt

def self_test():
    def valid(phase):
        lines=[]
        for pattern in phase["terminals"]:
            line=pattern.replace("([1-9][0-9]*)","100").replace("(7)","7").replace(r"\.",".")
            lines.append(line)
        if phase.get("families"):
            lines.extend(phase["family_prefix"]+name for name in phase["families"])
        lines.extend(phase["prefix"]+name for name in phase["controls"])
        return ("\n".join(lines)+"\n").encode()
    class Gate(unittest.TestCase):
        def test_exact_fixed_phase_and_control_inventory(self):
            self.assertEqual([p["name"] for p in PHASES],["source","typed-host","original-local","original-execution","original-restore","original-mtu"])
            self.assertEqual([len(p["controls"]) for p in PHASES],[29,6,25,16,3,12])
            self.assertEqual(OUTER_SECONDS,1200)
            for phase in PHASES:
                result=verdict(valid(phase),0,False,True,phase);self.assertTrue(result["accepted"])
        def test_failure_timeout_and_unjoined_are_never_accepted(self):
            for phase in PHASES:
                for status,timed_out,joined in ((1,False,True),(-9,False,True),(0,True,True),(0,False,False)):
                    with self.subTest(phase=phase["name"],status=status,timed_out=timed_out,joined=joined):
                        with self.assertRaises(ValueError):verdict(valid(phase),status,timed_out,joined,phase)
        def test_every_missing_compiled_control_is_refused(self):
            for phase in PHASES:
                lines=valid(phase).decode().splitlines()
                indexes=[i for i,line in enumerate(lines) if line.startswith(phase["prefix"])]
                for index in indexes:
                    with self.subTest(phase=phase["name"],index=index):
                        with self.assertRaises(ValueError):verdict(("\n".join(lines[:index]+lines[index+1:])+"\n").encode(),0,False,True,phase)
        def test_extra_or_reordered_control_is_refused(self):
            for phase in PHASES:
                raw=valid(phase)
                with self.assertRaises(ValueError):verdict(raw+(phase["prefix"]+"foreign\n").encode(),0,False,True,phase)
                lines=raw.decode().splitlines();indexes=[i for i,line in enumerate(lines) if line.startswith(phase["prefix"])]
                first=indexes[0];last=next(i for i in reversed(indexes) if lines[i]!=lines[first])
                lines[first],lines[last]=lines[last],lines[first]
                with self.assertRaises(ValueError):verdict(("\n".join(lines)+"\n").encode(),0,False,True,phase)
        def test_each_missing_or_repeated_positive_terminal_is_refused(self):
            for phase in PHASES:
                raw=valid(phase);lines=raw.decode().splitlines()
                for index in range(len(phase["terminals"])):
                    with self.assertRaises(ValueError):verdict(("\n".join(lines[:index]+lines[index+1:])+"\n").encode(),0,False,True,phase)
                    with self.assertRaises(ValueError):verdict(raw+(lines[index]+"\n").encode(),0,False,True,phase)
        def test_typed_lifecycle_families_are_complete_and_unique(self):
            phase=PHASES[1];raw=valid(phase)
            for name in phase["families"]:
                line=(phase["family_prefix"]+name+"\n").encode()
                with self.assertRaises(ValueError):verdict(raw.replace(line,b""),0,False,True,phase)
                with self.assertRaises(ValueError):verdict(raw+line,0,False,True,phase)
        def test_unrelated_runtime_failure_is_refused(self):
            phase=PHASES[1]
            for line in ("Traceback (most recent call last):","Exception in thread main","panic: foreign","fatal error: deadlock","WARNING: DATA RACE","FAIL native"):
                with self.assertRaises(ValueError):verdict(valid(phase)+(line+"\n").encode(),0,False,True,phase)
        def test_original_executor_runs_and_joins_actual_child(self):
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory);log=path/"child.log"
                result=CORE.execute([sys.executable,"-c","print('original Android validator child')"],path,dict(os.environ),log,3)
                self.assertEqual(result,(0,False,True));self.assertEqual(log.read_text().strip(),"original Android validator child")
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(Gate)
    if not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful():
        raise SystemExit(1)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test",action="store_true")
    parser.add_argument("--suite",choices=(SUITE,),default=SUITE)
    parser.add_argument("--source",type=Path);parser.add_argument("--source-sha");parser.add_argument("--output",type=Path)
    args=parser.parse_args()
    if args.self_test:self_test();return
    if not all((args.source,args.source_sha,args.output)):parser.error("Exact source, SHA and output required")
    print(json.dumps(validate(args.source,args.source_sha,args.output),sort_keys=True))

if __name__=="__main__":
    main()
