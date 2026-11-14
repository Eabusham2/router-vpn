#!/usr/bin/env python3
"""Run exact Swift/shared-Go SOCKS source and retained-host controls; not SDK/device acceptance."""
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
SUITE = "ios-socks-host"
CORE_PATH = ROOT/"deploy/test_focused_multihop_clocks.py"
spec = importlib.util.spec_from_file_location("ios_socks_original_executor", CORE_PATH)
CORE = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = CORE
spec.loader.exec_module(CORE)
PHASES = json.loads(r'''[{"name":"typed-source","args":["deploy/test_ios_node_chain_socks_capture.py"],"prefix":"Rejected typed SOCKS capture mutation: ","controls":["final-source","provider-assets","provider-purpose"],"samples":["iOS typed SOCKS source: PASS 150 actual shared-parser and provider checks"],"terminals":["iOS typed SOCKS source: PASS ([1-9][0-9]*) actual shared-parser and provider checks"]},{"name":"typed-host","args":["deploy/test_ios_node_chain_socks_host.py"],"prefix":"Rejected typed SOCKS host causal control: ","controls":["shared-before-box","native-receipt","construction-join","observation-join","proof-join","mtu-probe-rotation","late-measurement","retain-before-bind","failed-bind-retry"],"samples":["PASS Apple typed SOCKS host: 21 ownership scenarios; native/OS boundaries doubled"],"terminals":["PASS Apple typed SOCKS host: (21) ownership scenarios; native/OS boundaries doubled"]},{"name":"launch","args":["deploy/test_ios_node_chain_launch.py"],"prefix":"Rejected ordered app launch defect mutation: ","controls":["temporary-purpose-admission","initial-manager-source","middle-source-revalidation","preference-readback","hysteria-final-raw-mode"],"samples":["Apple ordered app launch: PASS (100 shipping Swift/shared Go checks; NetworkExtension doubled)"],"terminals":["Apple ordered app launch: PASS \\(([1-9][0-9]*) shipping Swift/shared Go checks; NetworkExtension doubled\\)"]},{"name":"editor","args":["deploy/test_ios_node_chain_editor.py"],"prefix":"Rejected ordered editor defect mutation: ","controls":["hysteria-final-scope","pinned-final","original-fingerprints","late-source-owner","compile-before-save","visible-socks-eligibility","visible-socks-mode","visible-middle-position","visible-source-admission","visible-unique-source"],"samples":["Apple ordered editor: PASS (274 shipping Swift/shared Go checks; persistence boundary)"],"terminals":["Apple ordered editor: PASS \\((274) shipping Swift/shared Go checks; persistence boundary\\)"]},{"name":"identity","args":["deploy/test_ios_node_chain_identity.py"],"prefix":"Rejected ordered identity defect mutation: ","controls":["required-native-inventory","post-await-identity","original-WG-proof"],"samples":["Apple ordered identity capture: PASS (100 shipping Swift/shared Go checks; NetworkExtension doubled)"],"terminals":["Apple ordered identity capture: PASS \\(([1-9][0-9]*) shipping Swift/shared Go checks; NetworkExtension doubled\\)"]},{"name":"startup","args":["deploy/test_ios_node_chain_startup.py"],"prefix":"Rejected ordered startup defect mutation: ","controls":["changed ordered startup refuses middle-token","ordered startup never selects a raw member","changed typed startup refuses credential"],"samples":["Apple ordered startup: PASS (100 shipping Swift/shared Go checks; native launch boundary)"],"terminals":["Apple ordered startup: PASS \\(([1-9][0-9]*) shipping Swift/shared Go checks; native launch boundary\\)"]},{"name":"profiles","args":["deploy/test_ios_node_chain_socks_profiles.py"],"prefix":"Apple ordered profile source control rejected: ","controls":["candidate-final-source-guard","old-two-record-limit","lost-ordered-selection"],"samples":["Apple ordered profile persistence: PASS (100 shipping Swift checks)"],"terminals":["Apple ordered profile persistence: PASS \\(([1-9][0-9]*) shipping Swift checks\\)"],"trailers":["Apple typed SOCKS profile composition: original persistence and controls completed"]},{"name":"external-profiles","args":["deploy/test_ios_external_connection_profiles.py"],"prefix":"Apple paired-final profile original entry guard causal rejected","controls":[""],"samples":["Apple external whole connection profiles: PASS (100 shipping store/model checks; storage and app boundaries substituted)"],"terminals":["Apple external whole connection profiles: PASS \\(([1-9][0-9]*) shipping store/model checks; storage and app boundaries substituted\\)"]},{"name":"tor-profiles","args":["deploy/test_ios_tor_connection_profiles.py"],"prefix":"Rejected Tor connection-profile defect mutation: ","controls":["snapshot-native-validation","restore-native-validation","protocol-identity","import-rollback","active-restore"],"samples":["Apple whole Tor connection profiles: PASS (100 shipping callbacks/store/import/native validation checks)"],"terminals":["Apple whole Tor connection profiles: PASS \\(([1-9][0-9]*) shipping callbacks/store/import/native validation checks\\)"]},{"name":"legacy-startup","args":["deploy/test_ios_startup_policy.py"],"prefix":"Rejected iOS startup defect mutation: ","controls":["router-only","stale-source","ignore-off","foreign-vpn","ignore-admission","hidden-reset","repeat-launch","ignore-generation","late-vpn","router-readmission","last-choice-lost","startup-mtu-owner"],"samples":["iOS cold-launch startup and external Settings: 100 executable checks PASS"],"terminals":["iOS cold-launch startup and external Settings: ([1-9][0-9]*) executable checks PASS"],"trailers":["iOS startup boundary gate PASS; physical VPN permission and networking remain native/device acceptance"]}]''')
# Preserve every original phase and causal control. CONNECT receives separate
# source, ownership, provider and complete-profile executions at the same SHA.
import copy
CONNECT_PHASES = []
for original, name, script in (
    ("typed-source", "connect-source", "test_ios_node_chain_connect_capture.py"),
    ("typed-host", "connect-host", "test_ios_node_chain_connect_host.py"),
    ("editor", "connect-editor", "test_ios_node_chain_connect_editor.py"),
    ("startup", "connect-startup", "test_ios_node_chain_connect_startup.py"),
    ("profiles", "connect-profiles", "test_ios_node_chain_connect_profiles.py"),
):
    phase=copy.deepcopy(next(value for value in PHASES if value["name"]==original))
    phase["name"]=name;phase["args"]=["deploy/"+script]
    for key in ("prefix",):phase[key]=phase[key].replace("SOCKS","CONNECT")
    for key in ("controls","samples","terminals","trailers"):
        if key in phase:phase[key]=[value.replace("SOCKS","CONNECT").replace("visible-socks-","visible-connect-") for value in phase[key]]
    CONNECT_PHASES.append(phase)
CONNECT_PHASES += [
    {"name":"connect-provider","args":["deploy/test_ios_node_chain_connect_provider.py"],
     "prefix":"Rejected CONNECT provider control: ","controls":["route-policy","proof-result","transferred-owner"],
     "samples":["Apple typed CONNECT provider: PASS (15 actual callback scenarios; engine and NetworkExtension doubled)"],
     "terminals":[r"Apple typed CONNECT provider: PASS \((15) actual callback scenarios; engine and NetworkExtension doubled\)"]},
    {"name":"connect-engine","args":["deploy/test_ios_libbox_delivery.py","--connect-only"],
     "prefix":"Rejected CONNECT engine control: ","controls":[],
     "samples":["Swift 6 typed CONNECT engine: PASS (11 shipping startup/stop/activity checks; native handles doubled)"],
     "terminals":[r"Swift 6 typed CONNECT engine: PASS \((11) shipping startup/stop/activity checks; native handles doubled\)"]},
]
PHASES += CONNECT_PHASES
PHASES += [{'name': 'ordered-fifty-components', 'args': ['deploy/test_ios_ordered_latency.py'], 'prefix': 'Rejected ordered fifty causal control: ', 'controls': ['exact-fifty', 'closed-label', 'source-rollback', 'factory-retain', 'failed-close', 'request-tombstone', 'failed-close-history', 'post-close-current'], 'samples': ['iOS ordered fifty history + transaction + retained IPC: PASS (50 executable checks; native/file boundaries doubled)'], 'terminals': ['iOS ordered fifty history \\+ transaction \\+ retained IPC: PASS \\(([1-9][0-9]*) executable checks; native/file boundaries doubled\\)']}, {'name': 'ordered-fifty-callbacks', 'args': ['deploy/test_ios_ordered_latency_callbacks.py'], 'prefix': 'Rejected ordered fifty callback control: ', 'controls': ['complete-source', 'close-before-history'], 'samples': ['iOS ordered fifty actual app callbacks: PASS (59 executable checks; native/OS/private-file boundaries doubled)'], 'terminals': ['iOS ordered fifty actual app callbacks: PASS \\(([1-9][0-9]*) executable checks; native/OS/private-file boundaries doubled\\)']}, {'name': 'ordered-fifty-host', 'args': ['deploy/test_ios_ordered_latency_host.py'], 'prefix': 'Rejected ordered fifty typed-host control: ', 'controls': ['quiesce-before-factory', 'exact-lease', 'borrowed-service', 'retain-before-observation', 'facade-before-throughput'], 'samples': ['iOS ordered fifty typed host: PASS (21 ownership checks; native/MTU boundaries doubled)'], 'terminals': ['iOS ordered fifty typed host: PASS \\(([1-9][0-9]*) ownership checks; native/MTU boundaries doubled\\)']}]
PHASES += [{'name': 'connect-fifty-capture', 'args': ['deploy/test_ios_ordered_latency_connect_capture.py'], 'prefix': 'Rejected CONNECT fifty capture control: ', 'controls': ['compiled-source', 'complete-profile', 'app-generation'], 'samples': ['iOS CONNECT fifty actual capture: PASS (150 shared-parser and shipping capture checks)'], 'terminals': ['iOS CONNECT fifty actual capture: PASS \\(([1-9][0-9]*) shared-parser and shipping capture checks\\)']}, {'name': 'connect-fifty-callbacks', 'args': ['deploy/test_ios_ordered_latency_connect_callbacks.py'], 'prefix': 'Rejected ordered fifty callback control: ', 'controls': ['complete-source', 'close-before-history', 'typed-capture', 'complete-source', 'close-before-history', 'typed-capture'], 'samples': ['iOS http-connect fifty actual app callbacks: PASS (60 executable checks; native/OS/private-file boundaries doubled)', 'iOS https-connect fifty actual app callbacks: PASS (60 executable checks; native/OS/private-file boundaries doubled)'], 'terminals': ['iOS http-connect fifty actual app callbacks: PASS \\(([1-9][0-9]*) executable checks; native/OS/private-file boundaries doubled\\)', 'iOS https-connect fifty actual app callbacks: PASS \\(([1-9][0-9]*) executable checks; native/OS/private-file boundaries doubled\\)'], 'trailers': ['Completed actual CONNECT fifty callback mode: http-connect', 'Completed actual CONNECT fifty callback mode: https-connect']}, {'name': 'connect-fifty-host', 'args': ['deploy/test_ios_ordered_latency_connect_host.py'], 'prefix': 'Rejected ordered CONNECT fifty typed-host control: ', 'controls': ['quiesce-before-factory', 'exact-lease', 'borrowed-service', 'retain-before-observation', 'facade-before-throughput'], 'samples': ['iOS ordered CONNECT fifty typed host: PASS (21 ownership checks; native/MTU boundaries doubled)'], 'terminals': ['iOS ordered CONNECT fifty typed host: PASS \\(([1-9][0-9]*) ownership checks; native/MTU boundaries doubled\\)']}, {'name': 'ordered-fifty-dispatch', 'args': ['deploy/test_ios_ordered_latency_dispatch.py'], 'prefix': 'Rejected ordered fifty dispatch control: ', 'controls': ['typed-connect-dispatch', 'exclusive-owner', 'original-session', 'post-response-owner'], 'samples': ['iOS ordered fifty typed dispatch: PASS (26 actual engine IPC checks; native/OS boundaries doubled)'], 'terminals': ['iOS ordered fifty typed dispatch: PASS \\(([1-9][0-9]*) actual engine IPC checks; native/OS boundaries doubled\\)']}]
PHASES += [{'name': 'ordinary-fifty-host', 'args': ['deploy/test_ios_ordered_latency_ordinary_host.py'], 'prefix': 'Rejected ordinary host causal control: ', 'controls': ['original-probe', 'MTU', 'retained-close'], 'samples': ['iOS ordinary50 delivery: PASS (61 checks; original class executed, native/OS boundaries doubled)'], 'terminals': ['iOS ordinary50 delivery: PASS \\(([1-9][0-9]*) checks; original class executed, native/OS boundaries doubled\\)']}, {'name': 'ordinary-fifty-callbacks', 'args': ['deploy/test_ios_ordered_latency_ordinary_callbacks.py'], 'prefix': 'Rejected ordinary callback control: ', 'controls': ['local-owner', 'actual-kind'], 'samples': ['iOS ordinary50 app callbacks: PASS (133 checks;35 positions2–8; native/OS boundaries doubled)'], 'terminals': ['iOS ordinary50 app callbacks: PASS \\(([1-9][0-9]*) checks;35 positions2–8; native/OS boundaries doubled\\)']}]
OUTER_SECONDS = 1200
HEX40 = re.compile(r"[0-9a-f]{40}")

def verdict(raw, code, timed_out, joined, phase):
    if code != 0 or timed_out or not joined:
        raise ValueError("Apple typed SOCKS child failed, timed out or did not join")
    text = raw.decode("utf-8", "strict")
    if re.search(r"(?m)^(Traceback \(|Exception in thread|panic:|fatal error:|WARNING: DATA RACE|FAIL\b)", text):
        raise ValueError("Apple typed SOCKS output contains an unrelated runtime failure")
    lines = text.splitlines()
    controls = [line[len(phase["prefix"]):] for line in lines if line.startswith(phase["prefix"])]
    if controls != phase["controls"]:
        raise ValueError("Apple typed SOCKS compiled control inventory changed")
    counts=[]
    for pattern in phase["terminals"]:
        found=re.findall("^"+pattern+"$",text,re.M)
        if len(found)!=1:
            raise ValueError("Apple typed SOCKS positive terminal omitted or repeated")
        counts.append(int(found[0]))
    for trailer in phase.get("trailers",[]):
        if lines.count(trailer)!=1:
            raise ValueError("Apple typed SOCKS phase trailer omitted or repeated")
    if phase.get("families"):
        observed=[line[len(phase["family_prefix"]):] for line in lines if line.startswith(phase["family_prefix"])]
        if observed!=phase["families"]:
            raise ValueError("Apple typed SOCKS typed lifecycle case inventory changed")
    return dict(name=phase["name"],exit=code,timed_out=timed_out,process_group_joined=joined,
                positive_counts=counts,controls=controls,accepted=True)

def selection(source, sha, output):
    if not HEX40.fullmatch(sha):
        raise ValueError("Exact Apple typed SOCKS source SHA required")
    p=output.parent/"selection.json"
    if p.is_symlink() or not p.is_file():
        raise ValueError("Original trusted Apple typed SOCKS selection is absent")
    raw=p.read_bytes();record=json.loads(raw)
    if record.get("schema")!=1 or record.get("suite")!=SUITE or record.get("source_sha")!=sha or record.get("validation_scope")!="read-only-source-candidate":
        raise ValueError("Apple typed SOCKS suite or selected source changed")
    for key in ("validator_sha","validator_tree","base_sha","base_tree","source_sha","source_tree"):
        if not isinstance(record.get(key),str) or not HEX40.fullmatch(record[key]):
            raise ValueError("Apple typed SOCKS selection lost exact Git identity")
    for root,commit,tree in ((source,sha,record["source_tree"]),(ROOT,record["validator_sha"],record["validator_tree"])):
        if CORE.git(root,"rev-parse","HEAD").decode().strip()!=commit or CORE.git(root,"rev-parse","HEAD^{tree}").decode().strip()!=tree or CORE.git(root,"status","--porcelain","--untracked-files=all"):
            raise ValueError("Original Apple typed SOCKS checkout changed")
    return record,raw

def validate(source, sha, output):
    source=Path(source).resolve(strict=True);output=Path(output).absolute()
    if output.exists() or output.is_symlink() or output==source or source in output.parents:
        raise ValueError("Apple typed SOCKS evidence must be fresh and outside candidate")
    original,selected=selection(source,sha,output)
    before=CORE.snapshot(source)
    output.mkdir(mode=0o700)
    (output/"source-before.json").write_text(json.dumps(before,sort_keys=True)+"\n")
    if platform.system()!="Darwin" or platform.machine() not in ("x86_64","arm64"):
        raise ValueError("Apple typed SOCKS source gate requires a native macOS host")
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1",GOTOOLCHAIN="local",GOWORK="off",GOFLAGS="-p=2 -mod=readonly")
    go=subprocess.check_output(["go","version"],text=True,env=env,timeout=15).strip()
    swift=subprocess.check_output(["swiftc","--version"],text=True,stderr=subprocess.STDOUT,env=env,timeout=15).strip()
    architecture={"x86_64":"amd64","arm64":"arm64"}[platform.machine()]
    if go!="go version go1.26.3 darwin/"+architecture or not re.search(r"Apple Swift version 6\.",swift):
        raise ValueError("Apple gate lost pinned Go1.26.3 or Swift6")
    receipt=dict(schema=1,suite=SUITE,selection=original,status="running",go_version=go,swift_version=swift,
                 source_file_count=len(before),source_closure_sha256=hashlib.sha256(json.dumps(before,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
                 scope="actual-shared-Go-source-and-shipping-Swift-capture-callers-and-retained-host",sdk_accepted=False,native_tunnel_accepted=False,
                 explicit_boundaries=["NetworkExtension and app scheduling in caller fixtures","libbox native handles and OS in retained-host fixture"],
                 sdk_binding_accepted=False,native_mtu_accepted=False,packet_tunnel_build_accepted=False,visible_socks_editor_enabled=True,phases=[],
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
            raise ValueError("Apple typed SOCKS source changed while executing original fixtures")
        if (output.parent/"selection.json").read_bytes()!=selected or selection(source,sha,output)[0]!=original:
            raise ValueError("Apple typed SOCKS original source selection changed")
        receipt["status"]="passed"
        (output/"receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
    except BaseException as error:
        receipt.update(status="failed",error=str(error));raise
    finally:
        save()
    return receipt

def self_test():
    def valid(phase):
        lines=list(phase["samples"])
        lines.extend(phase["prefix"]+name for name in phase["controls"])
        lines.extend(phase.get("trailers",[]))
        return ("\n".join(lines)+"\n").encode()
    class Gate(unittest.TestCase):
        def test_exact_ten_phases_and_all_original_controls(self):
            self.assertEqual([p["name"] for p in PHASES[:10]],["typed-source","typed-host","launch","editor","identity","startup","profiles","external-profiles","tor-profiles","legacy-startup"])
            self.assertEqual([len(p["controls"]) for p in PHASES[:10]],[3,9,5,10,3,3,3,1,5,12])
            self.assertEqual(sum(len(p["controls"]) for p in PHASES[:10]),54)
            self.assertEqual([p["name"] for p in PHASES[10:17]],["connect-source","connect-host","connect-editor","connect-startup","connect-profiles","connect-provider","connect-engine"])
            self.assertEqual([len(p["controls"]) for p in PHASES[10:17]],[3,9,10,3,3,3,0])
            self.assertEqual(sum(len(p["controls"]) for p in PHASES),123)
            self.assertEqual([p["name"] for p in PHASES[17:20]],["ordered-fifty-components","ordered-fifty-callbacks","ordered-fifty-host"])
            self.assertEqual([len(p["controls"]) for p in PHASES[17:20]],[8,2,5])
            self.assertEqual([p["name"] for p in PHASES[20:24]],["connect-fifty-capture","connect-fifty-callbacks","connect-fifty-host","ordered-fifty-dispatch"])
            self.assertEqual([len(p["controls"]) for p in PHASES[20:24]],[3,6,5,4])
            self.assertEqual([p["name"] for p in PHASES[24:]],["ordinary-fifty-host","ordinary-fifty-callbacks"])
            self.assertEqual([len(p["controls"]) for p in PHASES[24:]],[3,2])
            self.assertEqual(OUTER_SECONDS,1200)
            for phase in PHASES:self.assertTrue(verdict(valid(phase),0,False,True,phase)["accepted"])
        def test_exact_visible_editor_count_and_all_ten_controls(self):
            phase=next(p for p in PHASES if p["name"]=="editor")
            raw=valid(phase)
            self.assertEqual(len(phase["controls"]),10)
            for count in (142,273,275):
                with self.subTest(count=count):
                    with self.assertRaises(ValueError):
                        verdict(raw.replace(b"(274 shipping",("("+str(count)+" shipping").encode()),0,False,True,phase)
            identity=next(p for p in PHASES if p["name"]=="identity")
            self.assertEqual(identity["controls"],["required-native-inventory","post-await-identity","original-WG-proof"])
        def test_failed_timeout_or_unjoined_child_is_refused(self):
            for phase in PHASES:
                for code,timeout,joined in ((1,False,True),(-9,False,True),(0,True,True),(0,False,False)):
                    with self.subTest(phase=phase["name"],code=code,timeout=timeout,joined=joined):
                        with self.assertRaises(ValueError):verdict(valid(phase),code,timeout,joined,phase)
        def test_every_missing_duplicate_and_foreign_control_is_refused(self):
            for phase in PHASES:
                raw=valid(phase)
                for name in phase["controls"]:
                    line=(phase["prefix"]+name+"\n").encode()
                    with self.subTest(phase=phase["name"],control=name):
                        with self.assertRaises(ValueError):verdict(raw.replace(line,b"",1),0,False,True,phase)
                        with self.assertRaises(ValueError):verdict(raw+line,0,False,True,phase)
                with self.assertRaises(ValueError):verdict(raw+(phase["prefix"]+"foreign\n").encode(),0,False,True,phase)
        def test_reordered_controls_are_refused(self):
            for phase in PHASES:
                if len(phase["controls"])<2:continue
                raw=valid(phase);a=(phase["prefix"]+phase["controls"][0]+"\n").encode();b=(phase["prefix"]+phase["controls"][-1]+"\n").encode()
                wrong=raw.replace(a,b"__FIRST__").replace(b,a).replace(b"__FIRST__",b)
                with self.assertRaises(ValueError):verdict(wrong,0,False,True,phase)
        def test_each_missing_or_repeated_terminal_and_trailer_is_refused(self):
            for phase in PHASES:
                raw=valid(phase)
                for name in phase["samples"]+phase.get("trailers",[]):
                    line=(name+"\n").encode()
                    with self.subTest(phase=phase["name"],terminal=name):
                        with self.assertRaises(ValueError):verdict(raw.replace(line,b"",1),0,False,True,phase)
                        with self.assertRaises(ValueError):verdict(raw+line,0,False,True,phase)
        def test_exact_host_inventory_and_utf8_required(self):
            phase=PHASES[1];raw=valid(phase)
            for wrong in (raw.replace(b"21 ownership",b"20 ownership"),raw+b"\xff"):
                with self.assertRaises((ValueError,UnicodeError)):verdict(wrong,0,False,True,phase)
        def test_unrelated_runtime_failure_refused(self):
            for line in ("Traceback (most recent call last):","Exception in thread main","panic: foreign","fatal error: deadlock","WARNING: DATA RACE","FAIL native"):
                with self.assertRaises(ValueError):verdict(valid(PHASES[1])+(line+"\n").encode(),0,False,True,PHASES[1])
        def test_original_executor_joins_actual_owned_child(self):
            with tempfile.TemporaryDirectory() as directory:
                path=Path(directory);log=path/"child.log"
                result=CORE.execute([sys.executable,"-c","print('original Apple validator child')"],path,dict(os.environ),log,3)
                self.assertEqual(result,(0,False,True));self.assertEqual(log.read_text().strip(),"original Apple validator child")
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Gate))
    if not result.wasSuccessful():raise SystemExit(1)

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
