#!/usr/bin/env python3
from __future__ import annotations
from pathlib import Path
import hashlib, re

ROOT=Path(__file__).resolve().parents[2]

production_test=r'''#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"deploy/materialize-production-compose.py"
VERIFY=ROOT/"server/scripts/verify-production-compose.py"
SOURCE=ROOT/"server/portainer-current.yaml"
TARGET="a"*40


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    if spec is None or spec.loader is None: raise RuntimeError(path)
    module=importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module

PROD=load("routervpn_exact_compose",SCRIPT)


def test_materialization():
    original=SOURCE.read_bytes()
    rendered=PROD.materialize(PROD.read_regular_text(SOURCE),TARGET)
    assert rendered.startswith(f"# GENERATED exact-SHA Router VPN production compose: {TARGET}\n")
    assert f"ROUTER_VPN_GITHUB_SHA: {TARGET}" in rendered
    assert "ghcr.io/sagernet/sing-box:v1.13.12" in rendered
    assert "ghcr.io/xtls/xray-core:26.7.11" in rendered
    assert "/var/run/docker.sock" not in rendered
    assert "\n    build:\n" not in rendered
    assert SOURCE.read_bytes()==original
    with tempfile.TemporaryDirectory(prefix="router-vpn-production-compose-") as td:
        out=Path(td)/f"RouterVPN-Portainer-{TARGET}.yaml"
        PROD.atomic_write(out,rendered)
        verified=subprocess.run([sys.executable,str(VERIFY),str(out)],cwd=ROOT,text=True,capture_output=True,check=True)
        assert verified.stdout.strip()==TARGET
        if os.name!="nt": assert out.stat().st_mode&0o777==0o644


def test_invalid_sha_and_template_fail_closed():
    template=PROD.read_regular_text(SOURCE)
    for value in ("", "short", "G"*40):
        try: PROD.materialize(template,value)
        except SystemExit: pass
        else: raise AssertionError(f"invalid release SHA accepted: {value!r}")
    for mutation in (
        template+"\nservices:\n  bad:\n    build:\n      context: .\n",
        template.replace("ROUTER_VPN_UPDATE_LISTEN: 127.0.0.1:8793","ROUTER_VPN_UPDATE_LISTEN: 0.0.0.0:8793"),
        template.replace("ROUTER_VPN_GITHUB_SHA:","BROKEN_GITHUB_SHA:",1),
    ):
        try: PROD.materialize(mutation,TARGET)
        except SystemExit: pass
        else: raise AssertionError("unsafe production template was accepted")


def test_atomic_write_preserves_old_target_on_precommit_failure():
    with tempfile.TemporaryDirectory(prefix="router-vpn-compose-atomic-") as td:
        root=Path(td); out=root/"compose.yaml"; out.write_text("old\n"); os.chmod(out,0o644)
        with mock.patch.object(PROD.os,"replace",side_effect=OSError("injected")):
            try: PROD.atomic_write(out,"new\n")
            except OSError: pass
            else: raise AssertionError("injected adoption failure was ignored")
        assert out.read_text()=="old\n"
        assert not list(root.glob(".compose.yaml.compose-*"))


def test_atomic_write_rejects_postrename_replacement():
    if os.name=="nt": return
    with tempfile.TemporaryDirectory(prefix="router-vpn-compose-race-") as td:
        root=Path(td); out=root/"compose.yaml"; out.write_text("old\n"); os.chmod(out,0o644)
        foreign=root/"foreign"; foreign.write_text("foreign\n"); os.chmod(foreign,0o644)
        real=PROD.os.replace; swapped=False
        def replace_then_swap(src,dst):
            nonlocal swapped
            result=real(src,dst)
            if Path(dst)==out and not swapped:
                swapped=True; real(foreign,out)
            return result
        with mock.patch.object(PROD.os,"replace",side_effect=replace_then_swap):
            try: PROD.atomic_write(out,"new\n")
            except RuntimeError as exc: assert "identity changed" in str(exc)
            else: raise AssertionError("foreign post-rename replacement accepted")
        assert out.read_text()=="foreign\n"


def test_workflow_and_docs_use_generated_compose():
    workflow=(ROOT/".github/workflows/production-release-compose.yml").read_text()
    for marker in ("materialize-production-compose.py --sha", "verify-production-compose.py", "RouterVPN-production-compose-${{ github.sha }}"):
        assert marker in workflow,marker
    assert "--template" not in workflow and "--env" not in workflow
    for rel in ("README.md","START-HERE.md","START-CURRENT.md","USE-CURRENT.md","docs/CURRENT-GUIDE.md","docs/INSTALL-PORTAINER.md","docs/INSTALL-SSH.md"):
        body=(ROOT/rel).read_text(encoding="utf-8")
        assert "Exact-SHA production compose" in body,rel
        assert "PRODUCTION-RELEASE.md" in body,rel


def main():
    test_materialization(); test_invalid_sha_and_template_fail_closed(); test_atomic_write_preserves_old_target_on_precommit_failure(); test_atomic_write_rejects_postrename_replacement(); test_workflow_and_docs_use_generated_compose()
    print("production release compose materializer tests passed")
    return 0

if __name__=="__main__": raise SystemExit(main())
'''
(ROOT/"deploy/test-production-release-compose.py").write_text(production_test,encoding="utf-8")

# Rebase every deterministic Linux transform source hash after reviewed source
# changes. Keep the patch operations themselves unchanged.
transform=ROOT/"client/linux/apply-session-mutation.py"
body=transform.read_text(encoding="utf-8")
for name in ("routervpn-gtk-product.c","routervpn-gtk-product-v3.c","routervpn-gtk-product-v4.c","routervpn-profile-settings-v1.inc","routervpn-unified-shell-v8.inc"):
    digest=hashlib.sha256((ROOT/"client/linux"/name).read_bytes()).hexdigest()
    body,count=re.subn(rf"('{re.escape(name)}'\s*:\s*\()'[0-9a-f]{{64}}'",rf"\1'{digest}'",body,count=1)
    if count!=1: raise SystemExit(f"cannot rebase Linux transform hash: {name}")
transform.write_text(body,encoding="utf-8")

# Make the reconciled requirement contract a permanent exact-head release gate.
rc=ROOT/".github/workflows/release-candidate.yml"
workflow=rc.read_text(encoding="utf-8")
if "python3 deploy/current-requirements-audit.py" not in workflow:
    anchors=("python3 deploy/validate-repo.py","python3 deploy/product-parity-audit.py")
    for anchor in anchors:
        if anchor in workflow:
            workflow=workflow.replace(anchor,anchor+"\n          python3 deploy/current-requirements-audit.py",1)
            break
    else: raise SystemExit("cannot wire current requirements into release candidate")
rc.write_text(workflow,encoding="utf-8")

# Current source matrix must own the production and delivery contract.
orch=ROOT/"deploy/release-orchestration-audit.py"
text=orch.read_text(encoding="utf-8")
marker="current-requirements-audit.py"
if marker not in text:
    insertion='''\n# Current requirement precedence/cancellations are an authoritative release input.\n_current_release=(ROOT/".github/workflows/release-candidate.yml").read_text(encoding="utf-8")\nif "python3 deploy/current-requirements-audit.py" not in _current_release:\n    errors.append("release candidate omits current-requirements-audit.py")\n'''
    pos=text.rfind("if errors:")
    if pos<0: raise SystemExit("cannot wire current requirements into release orchestration audit")
    text=text[:pos]+insertion+"\n"+text[pos:]
    orch.write_text(text,encoding="utf-8")

# Remove diagnostic/reconciliation automation and reports; they are not product
# source and routine work remains direct-main only.
for rel in (
 ".github/workflows/direct-main-current-source-gate.yml",
 ".github/workflows/direct-main-current-source-report.yml",
 ".github/workflows/direct-main-final-current-reconcile.yml",
 ".github/workflows/direct-main-apply-current-reconcile.yml",
 ".github/current-source-gate-failures.txt",
 ".github/scripts/final-current-reconcile.py",
):
    p=ROOT/rel
    if p.exists(): p.unlink()

print("final source integration drift fixed")
