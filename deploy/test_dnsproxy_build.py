#!/usr/bin/env python3
"""Exercise the real pinned helper at subprocess and module-cache boundaries."""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("dnsproxy_build", ROOT / "deploy/build-dnsproxy.py")
assert spec and spec.loader
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
checks = 0


def require(value, message):
    global checks
    assert value, message
    checks += 1


def reject(callback, message):
    global checks
    try:
        callback()
    except (RuntimeError, ValueError, FileNotFoundError):
        checks += 1
        return
    raise AssertionError(message)


def main():
    raw = helper.notices()
    notice = json.loads(raw)
    require(len(notice["modules"]) == 6, "actual runtime module closure changed")
    require(all(module["licenses"] for module in notice["modules"]), "missing module license texts")
    require(len(notice["toolchain_licenses"]) == 2, "Go notices missing")
    all_modules = {module["path"] for module in notice["modules"]}
    require(helper.compiled_dependency_names(notice, "netbsd/arm64") == all_modules - {"golang.org/x/sys"}, "generic NetBSD ARM64 module set changed")
    require(helper.compiled_dependency_names(notice, "windows/arm64") == all_modules, "native Windows dependency verification was weakened")
    require(helper.race_supported("windows", "amd64") and not helper.race_supported("windows", "arm64"), "Windows native race contract changed")
    require(helper.race_supported("linux", "arm64") and helper.race_supported("darwin", "arm64"), "available native race gate lost")
    with tempfile.TemporaryDirectory(prefix="routervpn-dns-build-") as directory:
        work = Path(directory)
        source = work / "module"
        source.mkdir()
        for name in helper.INPUTS:
            shutil.copyfile(helper.MODULE / name, source / name)
        for name in helper.INPUTS:
            path = source / name
            original = path.read_bytes()
            path.write_bytes(original + b"\n")
            reject(lambda: helper.notices(source), "changed pinned source was accepted: " + name)
            path.write_bytes(original)
            path.unlink()
            reject(lambda: helper.notices(source), "missing pinned source was accepted: " + name)
            path.write_bytes(original)
        output = work / "package/DNS-PROXY-NOTICES.json"
        helper.stage_notices(output, source)
        require(output.read_bytes() == raw, "staged notice bytes changed")
        require(not list(output.parent.glob(".dns-notices-*")), "notice stage left temporary files")
        if os.name != "nt":
            output.unlink()
            output.symlink_to(source / "go.mod")
            reject(lambda: helper.stage_notices(output, source), "notice stage followed a link")

        # Verify the actual h1 content algorithm, then retain the same expected
        # hash while changing, adding and removing cache files.
        cache = work / "cache"
        cache.mkdir()
        (cache / "LICENSE").write_bytes(b"test notice\n")
        prefix = "example.invalid/test@v1.0.0"
        line = hashlib.sha256(b"test notice\n").hexdigest() + "  " + prefix + "/LICENSE\n"
        expected = "h1:" + base64.b64encode(hashlib.sha256(line.encode()).digest()).decode()
        helper.verify_module(cache, prefix, expected)
        checks_before = checks
        (cache / "LICENSE").write_bytes(b"changed notice\n")
        reject(lambda: helper.verify_module(cache, prefix, expected), "changed module cache was accepted")
        (cache / "LICENSE").write_bytes(b"test notice\n")
        (cache / "extra.go").write_bytes(b"foreign compiled source\n")
        reject(lambda: helper.verify_module(cache, prefix, expected), "extra compiled source was accepted")
        (cache / "extra.go").unlink()
        (cache / "LICENSE").unlink()
        reject(lambda: helper.verify_module(cache, prefix, expected), "missing cache source was accepted")
        require(checks == checks_before + 3, "module checksum negative controls did not run")

        poison = {"GOTOOLCHAIN": "auto", "GOWORK": "/foreign/go.work", "GOFLAGS": "-mod=mod -overlay=foreign.json",
                  "GOOS": "wrong", "GOARCH": "wrong", "GOARM": "5", "GOSUMDB": "off", "GONOSUMDB": "*"}
        with mock.patch.dict(os.environ, poison):
            env = helper.environment("linux/arm")
            require(env["GOTOOLCHAIN"] == "local" and env["GOWORK"] == "off" and env["GOFLAGS"] == "", "ambient build policy escaped")
            require((env["GOOS"], env["GOARCH"], env["GOARM"], env["CGO_ENABLED"]) == ("linux", "arm", "7", "0"), "cross target changed")
            require(env["GOSUMDB"] == "sum.golang.org" and env["GONOSUMDB"] == "", "checksum policy bypassed")
            native = helper.environment(None, race=True)
            require("GOOS" not in native and "GOARCH" not in native and native["CGO_ENABLED"] == "1", "host race test became a cross build")
        reject(lambda: helper.environment("windows/386"), "unknown target accepted")

        calls = []
        def execute(command, **kwargs):
            calls.append((command, kwargs))
            return subprocess.CompletedProcess(command, 0, "fixture output\n", "")
        with mock.patch.object(helper.subprocess, "run", side_effect=execute):
            require(helper.run("/installed/go", ["test", "-race", "./..."], env, source) == "fixture output\n", "subprocess output lost")
        command, kwargs = calls[0]
        require(command == ["/installed/go", "test", "-race", "./..."] and kwargs["cwd"] == source, "helper escaped nested module")
        require(kwargs["env"] is env and kwargs["timeout"] == 1200, "bounded captured environment lost")
        with mock.patch.object(helper, "run", return_value="go1.24.13\n"):
            reject(lambda: helper.prepare("go", env, source), "old Go silently built H3")

        # Unknown dependency is tested before license reads; put it first.
        def foreign_first(go, arguments, captured, module):
            if arguments == ["env", "GOVERSION"]:
                return helper.TOOLCHAIN
            return "example.invalid/foreign|v1.0.0|h1:foreign|/unused\n"
        with mock.patch.object(helper, "run", side_effect=foreign_first):
            reject(lambda: helper.prepare("go", env, source), "unnoticed production dependency accepted")

    # All actual compile call sites must use the helper, including the init
    # image and the narrowly allowed requested-client-package fallback.
    for relative in ("deploy/build-client.sh", "deploy/package-linux-native.sh", "deploy/package-macos-native.sh", "server/init/Dockerfile"):
        text = (ROOT / relative).read_text()
        require("build-dnsproxy.py" in text and "./cmd/dnsproxy" not in text, "legacy root-module build remains: " + relative)
    fallback = (ROOT / "server/scripts/build-download-on-demand.py").read_text()
    require('if package == "./cmd/dnsproxy":' in fallback and '"--go", go]' in fallback, "client fallback bypasses pinned helper")
    print(f"DNS proxy build boundaries: {checks} checks passed")


if __name__ == "__main__":
    main()
