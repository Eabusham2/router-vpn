#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/materialize-exact-sha-release.py"
SPEC = importlib.util.spec_from_file_location("router_vpn_release_materializer_tested", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {SCRIPT}")
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)

SHA = "2" * 40

with tempfile.TemporaryDirectory() as raw:
    work = Path(raw)
    source = work / "candidate"
    source.mkdir()
    expected = sorted(set(module._policy.EXACT_SHA_RELEASE_ASSETS.values()))
    for index, name in enumerate(expected):
        path = source / f"producer-{index}" / name
        path.parent.mkdir(parents=True)
        path.write_bytes((name + "\n").encode("utf-8"))

    output = work / "release"
    metadata = module.materialize(source, output, SHA, "Eabusham2/router-vpn")
    assert metadata["source_sha"] == SHA
    assert metadata["tag"] == "router-vpn-sha-" + SHA
    for name in expected:
        assert (output / name).read_bytes() == (name + "\n").encode("utf-8")
    saved = json.loads((output / "RouterVPN-RELEASE.json").read_text(encoding="utf-8"))
    assert saved["source_sha"] == SHA and saved["repository"] == "Eabusham2/router-vpn"
    manifest = (output / "SHA256SUMS").read_text(encoding="utf-8")
    for name in expected + ["RouterVPN-RELEASE.json"]:
        assert f"  {name}\n" in manifest

with tempfile.TemporaryDirectory() as raw:
    work = Path(raw)
    source = work / "candidate"
    source.mkdir()
    expected = sorted(set(module._policy.EXACT_SHA_RELEASE_ASSETS.values()))
    for index, name in enumerate(expected):
        path = source / f"producer-{index}" / name
        path.parent.mkdir(parents=True)
        path.write_bytes(b"x")
    duplicate = source / "duplicate" / expected[0]
    duplicate.parent.mkdir()
    duplicate.write_bytes(b"y")
    try:
        module.materialize(source, work / "release", SHA, "Eabusham2/router-vpn")
    except RuntimeError as exc:
        assert "exactly one" in str(exc)
    else:
        raise AssertionError("duplicate release asset was accepted")

print("Exact-SHA GitHub Release materialization: PASS")


with tempfile.TemporaryDirectory() as raw:
    work = Path(raw)
    staged = work / "staged"
    destination = work / "published"
    staged.write_bytes(b"verified staged release")
    staged_info = staged.lstat()
    destination.write_bytes(b"foreign concurrent release")
    try:
        module._adopt_no_clobber(staged, destination, staged_info)
    except RuntimeError as exc:
        assert "already exists" in str(exc)
    else:
        raise AssertionError("concurrent release destination was overwritten")
    assert destination.read_bytes() == b"foreign concurrent release"
    assert staged.read_bytes() == b"verified staged release"

with tempfile.TemporaryDirectory() as raw:
    work = Path(raw)
    destination = work / "metadata.json"
    destination.write_text("foreign", encoding="utf-8")
    try:
        module._atomic_text(destination, "verified\n")
    except RuntimeError as exc:
        assert "already exists" in str(exc)
    else:
        raise AssertionError("existing metadata destination was overwritten")
    assert destination.read_text(encoding="utf-8") == "foreign"
