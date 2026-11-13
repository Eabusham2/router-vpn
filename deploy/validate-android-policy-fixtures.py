#!/usr/bin/env python3
"""Compile and execute four original Android policy fixtures; never SDK/device/native acceptance."""
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
SUITE = "android-policy-fixtures"
CORE_PATH = ROOT/"deploy/test_focused_multihop_clocks.py"
spec = importlib.util.spec_from_file_location("android_policy_original_executor", CORE_PATH)
CORE = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = CORE
spec.loader.exec_module(CORE)
PHASES = json.loads('[{"name":"tor-form","args":["android/test_android_tor_form.py"],"controls":["Android Tor form imported member ABI control rejected: malformed original source","Android Tor form: all 22 original-source negative controls rejected"],"terminals":[{"pattern":"Android Tor form: PASS \\\\(([1-9][0-9]*) real compiler roundtrips, all 19 mode choices, ([1-9][0-9]*) checks; full shipping Activity, Android widgets/permission doubled\\\\)","example":"Android Tor form: PASS (10 real compiler roundtrips, all 19 mode choices, 100 checks; full shipping Activity, Android widgets/permission doubled)"},{"pattern":"Android ordinary external settings: ([1-9][0-9]*) real Java/Go graph roundtrips plus Home, rejection and permission ownership checks passed","example":"Android ordinary external settings: 10 real Java/Go graph roundtrips plus Home, rejection and permission ownership checks passed"},{"pattern":"Android Local Tor padding form/compiler: PASS \\\\(([1-9][0-9]*) real captured graphs, ([1-9][0-9]*) checks; actual production admission\\\\)","example":"Android Local Tor padding form/compiler: PASS (10 real captured graphs, 100 checks; actual production admission)"}]},{"name":"external-policy","args":["android/test_android_external_policy.py"],"controls":[],"terminals":[{"pattern":"Android external policy: ([1-9][0-9]*) executable checks passed","example":"Android external policy: 100 executable checks passed"}]},{"name":"external-entries","args":["android/test_android_external_entries.py"],"controls":[],"terminals":[{"pattern":"Android ordinary external entries: PASS (456) local and (912) Server/Compare and (144) independent exit-layer and (171) unlayered / (342) per-remote layered OpenVPN shipping Java/Go graphs, ([1-9][0-9]*) checks; all19 native entry modes and saved Start Layers","example":"Android ordinary external entries: PASS 456 local and 912 Server/Compare and 144 independent exit-layer and 171 unlayered / 342 per-remote layered OpenVPN shipping Java/Go graphs, 100 checks; all19 native entry modes and saved Start Layers"}]},{"name":"imported-shadowsocks","args":["android/test_android_imported_router.py","--phase","shadowsocks"],"controls":["Android imported member ABI causal rejected: malformed original source","Android imported source causal rejected: accepted changed final session label","Android imported source causal rejected: failed staging cleanup lost its retained session capability","Android imported source causal rejected: accepted forged graph","Android imported source causal rejected: accepted changed imported capture","Android imported source causal rejected: source check deadlocked behind store mutation owner"],"terminals":[{"pattern":"Android imported-entry original sources: ([1-9][0-9]*) checks; shadowsocks, ([1-9][0-9]*) original independent layer graphs","example":"Android imported-entry original sources: 100 checks; shadowsocks, 9 original independent layer graphs"}]}]')
CANDIDATE_PATHS = tuple(phase["args"][0] for phase in PHASES)
OUTER_SECONDS = 1200
HEX40 = re.compile(r"[0-9a-f]{40}")

def verdict(raw, code, timed_out, joined, phase):
    if code != 0 or timed_out or not joined:
        raise ValueError("Android fixture failed, timed out or did not join")
    text = raw.decode("utf-8", "strict")
    if re.search(r"(?m)^(Traceback \(|Exception in thread|panic:|fatal error:|WARNING: DATA RACE|FAIL\b)", text):
        raise ValueError("Android output contains an unrelated runtime failure")
    lines = text.splitlines()
    controls = [line for line in lines if re.match(r"^Android .*(?:causal|control)", line)]
    if controls != phase["controls"]:
        raise ValueError("Android original compiled control inventory changed")
    counts = []
    for terminal in phase["terminals"]:
        found = re.findall("^" + terminal["pattern"] + "$", text, re.M)
        if len(found) != 1:
            raise ValueError("Android original positive terminal omitted or repeated")
        values = found[0] if isinstance(found[0], tuple) else (found[0],)
        counts.append([int(value) for value in values])
    return dict(name=phase["name"], exit=code, timed_out=timed_out,
                process_group_joined=joined, positive_counts=counts,
                controls=controls, accepted=True)

def require_pristine(source, expected):
    after = CORE.snapshot(source)
    if (after != expected or
            CORE.git(source, "status", "--porcelain", "--untracked-files=all") or
            CORE.git(source, "ls-files", "--others", "--ignored", "--exclude-standard", "-z")):
        raise ValueError("Android original source closure changed")
    return after

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
    changes = record.get("changes")
    if not isinstance(changes,list) or len(changes)!=4 or {row.get("path") for row in changes if isinstance(row,dict)}!=set(CANDIDATE_PATHS):
        raise ValueError("Android policy fixture candidate changed its fixed four-file allowlist")
    return record,raw

def validate(source, sha, output):
    source=Path(source).resolve(strict=True);output=Path(output).absolute()
    if output.exists() or output.is_symlink() or output==source or source in output.parents:
        raise ValueError("Android evidence must be fresh and outside candidate")
    original,selected=selection(source,sha,output)
    before=CORE.snapshot(source)
    require_pristine(source,before)
    output.mkdir(mode=0o700)
    (output/"source-before.json").write_text(json.dumps(before,sort_keys=True)+"\n")
    if platform.system()!="Linux" or platform.machine()!="x86_64":
        raise ValueError("Android source gate requires its original Linux amd64 host")
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1",GOTOOLCHAIN="local",GOWORK="off",GOFLAGS="-p=2 -mod=readonly",GOMAXPROCS="2",GOGC="100",GOMEMLIMIT="2GiB")
    go=subprocess.check_output(["go","version"],text=True,env=env,timeout=15).strip()
    java=subprocess.check_output(["javac","-version"],text=True,stderr=subprocess.STDOUT,env=env,timeout=15).strip()
    if go!="go version go1.26.3 linux/amd64" or not java.startswith("javac 17."):
        raise ValueError("Android gate lost pinned Go1.26.3 or JDK17")
    jar=Path(env.get("ANDROID_JSON_JAR","/usr/share/java/com.android.json.jar")).resolve(strict=True)
    if not jar.is_file():raise ValueError("Original Android JSON jar is required")
    env["ANDROID_JSON_JAR"]=str(jar)
    receipt=dict(schema=1,suite=SUITE,selection=original,status="running",go_version=go,javac_version=java,
                 source_file_count=len(before),source_closure_sha256=hashlib.sha256(json.dumps(before,sort_keys=True,separators=(",",":")).encode()).hexdigest(),
                 scope="actual-shared-Go-and-shipping-Java-policy-fixtures",sdk_accepted=False,native_tunnel_accepted=False,
                 android_json_sha256=hashlib.sha256(jar.read_bytes()).hexdigest(),
                 resources={key:env[key] for key in ("GOFLAGS","GOMAXPROCS","GOGC","GOMEMLIMIT")},
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
            require_pristine(source,before)
        after=require_pristine(source,before)
        (output/"source-after.json").write_text(json.dumps(after,sort_keys=True)+"\n")
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
    runner_path=ROOT/"deploy/test_android_policy_fixtures_runner.py"
    spec=importlib.util.spec_from_file_location("android_policy_fixture_refusals",runner_path)
    runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
    runner.run_tests()


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
