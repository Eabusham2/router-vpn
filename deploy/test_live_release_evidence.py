#!/usr/bin/env python3
from pathlib import Path
import json, subprocess, tempfile

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
    print("Exact-SHA physical/live release evidence runner: PASS")

if __name__=="__main__": main()
