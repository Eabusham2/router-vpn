#!/usr/bin/env python3
from pathlib import Path
import importlib.util, json, os, subprocess, sys, tempfile

ROOT=Path(__file__).resolve().parents[1]
TOOL=ROOT/"deploy/live-release-evidence.py"
SHA="a"*40

def run(*args,ok=True):
    r=subprocess.run(["python3",str(TOOL),*args],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    if ok and r.returncode: raise AssertionError(r.stdout+r.stderr)
    if not ok and not r.returncode: raise AssertionError("unexpected PASS: "+" ".join(args))
    return r

def main():
    with tempfile.TemporaryDirectory(prefix="router-vpn-live-evidence-") as td:
        root=Path(td); manifest=root/"evidence.json"; blob=root/"proof.txt"; blob.write_text("captured live evidence\n")
        run("init",str(manifest),"--sha",SHA)
        data=json.loads(manifest.read_text())
        assert data["release_sha"]==SHA and len(data["gates"])==13
        run("record",str(manifest),"--gate","physical-windows","--status","pass",ok=False)
        run("record",str(manifest),"--gate","physical-windows","--status","pass","--evidence",str(blob),"--note","real-device matrix")
        data=json.loads(manifest.read_text()); row=data["gates"]["physical-windows"]["evidence"][0]
        assert len(row["sha256"])==64 and row["size"]==blob.stat().st_size
        before=manifest.read_bytes()
        run("validate",str(manifest),"--sha","b"*40,ok=False); assert manifest.read_bytes()==before
        run("validate",str(manifest),"--sha",SHA)
        run("validate",str(manifest),"--sha",SHA,"--require-final",ok=False)
        forged=json.loads(manifest.read_text()); forged["gates"]["physical-android"]={"status":"pass","note":"forged","evidence":[]}; manifest.write_text(json.dumps(forged))
        run("validate",str(manifest),"--sha",SHA,ok=False)
        run("init",str(manifest),"--sha",SHA,ok=False)

        # Reset and prove the release scorer cannot be tricked by mere file
        # existence, a wrong SHA, or a manifest whose raw evidence disappeared.
        run("init",str(manifest),"--sha",SHA,"--force")
        live_spec=importlib.util.spec_from_file_location("routervpn_live_release_test",TOOL)
        if live_spec is None or live_spec.loader is None: raise AssertionError("cannot load live evidence tool")
        live=importlib.util.module_from_spec(live_spec); live_spec.loader.exec_module(live)
        for gate in live.GATES:
            run("record",str(manifest),"--gate",gate,"--status","pass","--evidence",str(blob),"--note","fixture live proof")
        run("validate",str(manifest),"--sha",SHA,"--require-final")

        weighted_path=ROOT/"deploy/weighted-release-audit.py"
        weighted_spec=importlib.util.spec_from_file_location("routervpn_weighted_live_test",weighted_path)
        if weighted_spec is None or weighted_spec.loader is None: raise AssertionError("cannot load weighted scorer")
        weighted=importlib.util.module_from_spec(weighted_spec)
        sys.modules[weighted_spec.name]=weighted
        old_manifest=os.environ.get("ROUTER_VPN_LIVE_EVIDENCE_MANIFEST")
        old_sha=os.environ.get("ROUTER_VPN_RELEASE_SHA")
        try:
            os.environ["ROUTER_VPN_LIVE_EVIDENCE_MANIFEST"]=str(manifest)
            os.environ["ROUTER_VPN_RELEASE_SHA"]=SHA
            weighted_spec.loader.exec_module(weighted)
            manual=[gate for gate in weighted.GATES if gate.kind!="source"]
            assert len(manual)==6 and all(gate.check() for gate in manual)
            os.environ["ROUTER_VPN_RELEASE_SHA"]="b"*40
            assert not any(gate.check() for gate in manual)
            os.environ["ROUTER_VPN_RELEASE_SHA"]=SHA
            blob.write_text("tampered after recording\n")
            assert not any(gate.check() for gate in manual)
            run("validate",str(manifest),"--sha",SHA,"--require-final",ok=False)
        finally:
            if old_manifest is None: os.environ.pop("ROUTER_VPN_LIVE_EVIDENCE_MANIFEST",None)
            else: os.environ["ROUTER_VPN_LIVE_EVIDENCE_MANIFEST"]=old_manifest
            if old_sha is None: os.environ.pop("ROUTER_VPN_RELEASE_SHA",None)
            else: os.environ["ROUTER_VPN_RELEASE_SHA"]=old_sha
    print("Exact-SHA physical/live release evidence runner + weighted scorer integration: PASS")

if __name__=="__main__": main()
