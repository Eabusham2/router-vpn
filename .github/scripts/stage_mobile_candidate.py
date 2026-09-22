#!/usr/bin/env python3
"""Create immutable candidate objects from exact-identity text edits, never refs.
Only this trusted main helper has a write token; candidate code is data here.
Actual candidate tests run separately with read-only credentials.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import urllib.error
import urllib.request

REPO = "Eabusham2/router-vpn"
LIMIT = 2 * 1024 * 1024
ROOTS = {"mobile", "ios", "android", "deploy", "internal", "docs", ".github"}

def git(*args, env=None, data=None):
    return subprocess.check_output(["git", *args], env=env, input=data)

def sha(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("A full lowercase Git SHA is required")
    return value

def blob_hash(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

def apply_edits(original, edits):
    lines=original.decode("utf-8").splitlines(keepends=True)
    if not isinstance(edits, list) or not 1 <= len(edits) <= 256:
        raise ValueError("Invalid edit count")
    previous=-1
    for edit in edits:
        if not isinstance(edit, list) or len(edit)!=3:
            raise ValueError("Invalid text edit")
        start,end,text=edit
        if type(start) is not int or type(end) is not int or not isinstance(text,str):
            raise ValueError("Invalid text edit types")
        if not 0 <= start <= end <= len(lines) or start <= previous:
            raise ValueError("Edits must be ordered, nonoverlapping source-line ranges")
        previous=max(start,end-1)
    for start,end,text in reversed(edits):
        lines[start:end]=text.splitlines(keepends=True)
    data="".join(lines).encode()
    if len(data)>LIMIT:
        raise ValueError("Candidate file is too large")
    return data

def post(kind, body, token):
    if kind not in {"blobs", "trees", "commits"}:
        raise ValueError("This helper cannot change refs or publish anything")
    req=urllib.request.Request(f"https://api.github.com/repos/{REPO}/git/{kind}",
        data=json.dumps(body).encode(), method="POST",
        headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
                 "Content-Type":"application/json","X-GitHub-Api-Version":"2022-11-28"})
    try:
        with urllib.request.urlopen(req,timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"Git object upload failed: HTTP {error.code}") from None

def main():
    if os.environ.get("GITHUB_REPOSITORY")!=REPO or os.environ.get("GITHUB_REF")!="refs/heads/main":
        raise ValueError("Candidate staging requires trusted main in the exact repository")
    raw=Path("configs/mobile-native-candidate.json").read_bytes()
    if len(raw)>LIMIT:
        raise ValueError("Candidate specification is too large")
    spec=json.loads(raw)
    expected=sha(spec["tree_sha"])
    if spec.get("schema_version")==1:
        source=sha(spec["source_sha"])
        subprocess.run(["git","fetch","--depth=1","origin",source],check=True)
        if git("rev-parse",source+"^{tree}").decode().strip()!=expected:
            raise ValueError("Candidate source tree mismatch")
    elif spec.get("schema_version")==2:
        base=sha(spec["base_sha"])
        files=spec["files"]
        if not isinstance(files,list) or not 1 <= len(files) <= 96:
            raise ValueError("Invalid changed-file count")
        subprocess.run(["git","fetch","--depth=1","origin",base],check=True)
        base_tree=git("rev-parse",base+"^{tree}").decode().strip()
        entries=[]; prepared=[]; seen=set()
        with tempfile.TemporaryDirectory(prefix="routervpn-candidate-") as work:
            env=dict(os.environ,GIT_INDEX_FILE=str(Path(work)/"index"))
            git("read-tree",base,env=env)
            for item in files:
                path=item["path"]; pure=PurePosixPath(path)
                if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] not in ROOTS or path in seen or "\0" in path or str(pure)!=path:
                    raise ValueError("Unsafe, duplicate or out-of-scope candidate path")
                seen.add(path)
                mode=item["mode"]; wanted=sha(item["result_blob"])
                if mode not in {"100644","100755"}:
                    raise ValueError("Only regular text files are allowed")
                row=git("ls-tree",base,"--",path).decode().strip()
                if row:
                    oldmode,kind,oldblob=row.split("\t",1)[0].split()
                    if kind!="blob" or oldmode!=mode or sha(item["base_blob"])!=oldblob:
                        raise ValueError("Existing source identity or executable mode changed")
                    original=git("cat-file","blob",oldblob)
                else:
                    if item["base_blob"] is not None:
                        raise ValueError("Expected existing source is missing")
                    original=b""
                if len(original)>LIMIT:
                    raise ValueError("Source file is too large")
                data=apply_edits(original,item["edits"])
                if blob_hash(data)!=wanted:
                    raise ValueError("Edited source differs from reviewed result: "+path)
                local=git("hash-object","-w","--stdin",data=data).decode().strip()
                if local!=wanted:
                    raise ValueError("Local Git blob verification failed")
                git("update-index","--add","--cacheinfo",mode+","+wanted+","+path,env=env)
                entries.append({"path":path,"mode":mode,"type":"blob","sha":wanted})
                prepared.append((wanted,data))
            if git("write-tree",env=env).decode().strip()!=expected:
                raise ValueError("Candidate tree differs from reviewed tree")
        token=os.environ["GITHUB_TOKEN"]
        for wanted,data in prepared:
            result=post("blobs",{"content":base64.b64encode(data).decode(),"encoding":"base64"},token)
            if result.get("sha")!=wanted:
                raise ValueError("Uploaded blob verification failed")
        tree=post("trees",{"base_tree":base_tree,"tree":entries},token)
        if tree.get("sha")!=expected:
            raise ValueError("Uploaded tree verification failed")
        commit=post("commits",{"message":"Stage exact reviewed mobile-native candidate; no ref change", "tree":expected,"parents":[base]},token)
        source=sha(commit["sha"])
    else:
        raise ValueError("Unsupported candidate schema")
    with open(os.environ["GITHUB_OUTPUT"],"a") as out:
        out.write("source_sha="+source+"\ntree_sha="+expected+"\n")
    with open(os.environ["GITHUB_STEP_SUMMARY"],"a") as out:
        out.write("Immutable candidate `"+source+"`, tree `"+expected+"`. No branch, tag, release or deployment changed.\n")
    print("Immutable candidate",source,"tree",expected)

if __name__=="__main__":
    main()
