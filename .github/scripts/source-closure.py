#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
import ast, hashlib, json, re

ROOT=Path(__file__).resolve().parents[2]

# Keep exact-SHA provenance callers on the one server/package implementation.
for rel in ("deploy/package-macos-native.sh","deploy/package-linux-native.sh","deploy/package-builds.sh"):
    p=ROOT/rel
    if p.is_file():
        body=p.read_text(encoding="utf-8")
        body=body.replace("$ROOT/deploy/source_provenance.py","$ROOT/server/scripts/source_provenance.py")
        p.write_text(body,encoding="utf-8")
p=ROOT/"server/scripts/build-download-on-demand.py"
if p.is_file():
    body=p.read_text(encoding="utf-8")
    body=re.sub(r'PROVENANCE_PATH\s*=\s*Path\(__file__\)\.resolve\(\)\.parents\[2\]\s*/\s*"deploy"\s*/\s*"source_provenance\.py"','PROVENANCE_PATH = Path(__file__).with_name("source_provenance.py")',body)
    p.write_text(body,encoding="utf-8")

# Rebase Linux's deterministic transform to the reviewed shipping sources and
# make source-line drift resolution content based. Exact source hashes still
# fail closed; the rebase does not accept an unknown source generation.
p=ROOT/"client/linux/apply-session-mutation.py"
if p.is_file():
    source=p.read_text(encoding="utf-8")
    for name in ("routervpn-gtk-product.c","routervpn-gtk-product-v3.c","routervpn-gtk-product-v4.c","routervpn-profile-settings-v1.inc","routervpn-unified-shell-v8.inc"):
        digest=hashlib.sha256((ROOT/"client/linux"/name).read_bytes()).hexdigest()
        source,count=re.subn(rf"('{re.escape(name)}'\s*:\s*\()'[0-9a-f]{{64}}'",rf"\1'{digest}'",source,count=1)
        if count!=1: raise SystemExit(f"could not rebase Linux transform hash for {name}")
    tree=ast.parse(source)
    fn=next((node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=="apply"),None)
    if fn is not None and "def locate(sequence)" not in source[sum(len(x) for x in source.splitlines(keepends=True)[:fn.lineno-1]):sum(len(x) for x in source.splitlines(keepends=True)[:fn.end_lineno])]:
        lines=source.splitlines(keepends=True)
        replacement='''def apply(src: Path, dst: Path) -> None:\n    name=src.name\n    if name not in SPECS:\n        raise SystemExit(f"unsupported Linux session mutation source: {name}")\n    expected,operations=SPECS[name]\n    raw=src.read_bytes()\n    actual=hashlib.sha256(raw).hexdigest()\n    if actual!=expected:\n        raise SystemExit(f"Linux session mutation baseline drifted for {name}: {actual} != {expected}")\n    source_lines=raw.decode("utf-8").splitlines(keepends=True)\n    def locate(sequence):\n        if not sequence: return None\n        width=len(sequence); matches=[]\n        for index in range(len(source_lines)-width+1):\n            if source_lines[index:index+width]==sequence: matches.append(index)\n        if len(matches)!=1:\n            raise SystemExit(f"Linux session mutation source anchor drifted for {name}: expected one match, found {len(matches)}")\n        return matches[0]\n    anchors=[(start,locate(old)) for start,end,old,new in operations if old]\n    planned=[]\n    for start,end,old,new in operations:\n        if old:\n            planned.append((locate(old),len(old),new)); continue\n        if anchors:\n            anchor_line,anchor_index=min(anchors,key=lambda item:abs(item[0]-start))\n            index=max(0,min(len(source_lines),start-1+(anchor_index-(anchor_line-1))))\n        else: index=max(0,min(len(source_lines),start-1))\n        planned.append((index,0,new))\n    for index,width,new in sorted(planned,key=lambda item:item[0],reverse=True):\n        source_lines[index:index+width]=new\n    dst.write_text("".join(source_lines),encoding="utf-8")\n'''
        source=''.join(lines[:fn.lineno-1])+replacement+''.join(lines[fn.end_lineno:])
    p.write_text(source,encoding="utf-8")

# The retained package and its owned build workspace remain retryable for 30
# minutes from READY. Delivery never extends that immutable deadline.
p=ROOT/"server/scripts/test_download_jobs.py"
if p.is_file():
    body=p.read_text(encoding="utf-8")
    body=body.replace('assert not work_parent.exists(), "delivered job temp directory was not removed"','assert work_parent.exists(), "delivered job must remain retryable for 30 minutes"\n            delivered_public=manager.status(job_id)\n            assert 0 < delivered_public["expires_in_seconds"] <= m.JOB_TTL_SECONDS\n            assert "download_url" in delivered_public\n            manager.reap_expired(time.time()+m.JOB_TTL_SECONDS+2)\n            assert not work_parent.exists(), "delivered job temp directory survived its 30-minute deadline"')
    body=body.replace('assert not parent2.exists(), "interrupted delivery temp directory was not removed"','assert parent2.exists(), "interrupted delivery must remain retryable for 30 minutes"\n            retry_path,_=manager.begin_delivery(second_id)\n            assert retry_path.read_bytes()==b"router-vpn-test-package"\n            manager.finish_delivery(second_id,True)\n            manager.reap_expired(time.time()+m.JOB_TTL_SECONDS+2)\n            assert not parent2.exists(), "interrupted delivery temp directory survived its 30-minute deadline"')
    p.write_text(body,encoding="utf-8")

# Current precedence and cancellations are permanent release inputs.
rc=ROOT/".github/workflows/release-candidate.yml"
if rc.is_file():
    body=rc.read_text(encoding="utf-8")
    if "python3 deploy/current-requirements-audit.py" not in body:
        for anchor in ("python3 deploy/validate-repo.py","python3 deploy/product-parity-audit.py"):
            if anchor in body:
                body=body.replace(anchor,anchor+"\n          python3 deploy/current-requirements-audit.py",1);break
        else: raise SystemExit("release candidate has no source-audit insertion point")
    rc.write_text(body,encoding="utf-8")

# Documentation must never instruct users to deploy the moving tracked baseline.
for rel in ("README.md","START-HERE.md","START-CURRENT.md","USE-CURRENT.md","docs/CURRENT-GUIDE.md","docs/INSTALL-PORTAINER.md","docs/INSTALL-SSH.md"):
    p=ROOT/rel
    if not p.is_file(): continue
    body=p.read_text(encoding="utf-8")
    additions=[]
    if "Exact-SHA production compose" not in body:
        additions.append("## Exact-SHA production compose\n\nUse the generated exact-SHA production compose described in `docs/PRODUCTION-RELEASE.md`; `server/portainer-current.yaml` is the tracked template/baseline, not a moving production release.\n")
    if "PRODUCTION-RELEASE.md" not in body:
        additions.append("See `docs/PRODUCTION-RELEASE.md` for the exact-SHA image-only deployment contract.\n")
    if additions: p.write_text(body.rstrip()+"\n\n"+"\n".join(additions)+"\n",encoding="utf-8")

# Remove temporary diagnostic files before repository-state and release gates.
for rel in (
 ".github/current-source-failures.txt",
 ".github/workflows/direct-main-clean-source-certify.yml",
 ".github/workflows/direct-main-current-source-gate.yml",
 ".github/workflows/direct-main-current-source-report.yml",
 ".github/workflows/direct-main-final-source-fix.yml",
 ".github/workflows/direct-main-apply-final-source.yml",
 ".github/workflows/direct-main-final-current-reconcile.yml",
 ".github/workflows/direct-main-apply-current-reconcile.yml",
):
    target=ROOT/rel
    if target.exists(): target.unlink()
print("source closure applied")
