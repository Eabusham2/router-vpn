#!/usr/bin/env python3
"""Validate shipping SOCKS5 ordered editor callbacks on native desktop hosts."""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SUITE = "desktop-socks-editor"
SOURCE_PATHS = (
    "client/RouterVPN-Windows-ProfileSettings.ps1",
    "client/RouterVPN-Windows-UnifiedShell.ps1",
    "client/test-windows-ordered-editor.ps1",
    "client/linux/routervpn-ordered-nodes-v1.inc",
    "client/linux/test-ordered-nodes-v1.c",
    "client/linux/test-ordered-nodes-v1.py",
    "deploy/test_desktop_connection_profile_modes.py",
    "deploy/test_desktop_connection_profile_modes_runner.py",
)
WINDOWS_CONTROLS = frozenset(("socks-mode", "final-mode", "raw-mode", "add-mode",
    "change-mode", "row-label", "source-token", "summary-reset"))
LINUX_CONTROLS = ("socks-mode", "final-mode", "source-token", "generation", "prefix-mode",
    "capability", "final-pin", "expected-inventory", "disk-receipt", "load-current-graph",
    "response-inventory")
TARGETS = {
    "linux/amd64": ("Linux", ("x86_64", "AMD64")),
    "windows/amd64": ("Windows", ("AMD64", "x86_64")),
    "windows/arm64": ("Windows", ("ARM64", "aarch64")),
}


# One shipping profile case, its nineteen original mutations, and one native
# ordered-editor process each keep the fixture's existing ninety-second bound.
WINDOWS_PROFILE_MUTATIONS = (
    "shipping", "capture-two-modes", "load-fallback", "connect-fallback",
    "entry-capture-fallback", "entry-load-fallback", "entry-connect-fallback",
    "startup-deadline", "ordered-drop-middle", "ordered-final-owner",
    "ordered-capability", "ordered-source", "ordered-locked-source",
    "setup-expectation", "setup-current-receipt", "setup-response-source",
    "setup-response-order", "setup-load-inventory", "setup-refresh-retirement",
    "setup-uncertain-owner",
)
WINDOWS_CHILD_SECONDS = 90


def windows_suite_budget(raw):
    """Account for the original bounded processes without changing any child."""
    tree = ast.parse(raw)
    functions = {}
    for name in ("run", "windows"):
        found = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name]
        if len(found) != 1:
            raise ValueError("original Windows fixture function inventory changed")
        functions[name] = found[0]
    children = [node for node in ast.walk(functions["run"]) if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute) and node.func.attr == "run"
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess"]
    if len(children) != 1:
        raise ValueError("original Windows subprocess inventory changed")
    deadlines = [item.value for item in children[0].keywords if item.arg == "timeout"]
    if (len(deadlines) != 1 or not isinstance(deadlines[0], ast.Constant)
            or type(deadlines[0].value) is not int or deadlines[0].value != WINDOWS_CHILD_SECONDS):
        raise ValueError("original Windows child deadline changed")
    loops = [node for node in functions["windows"].body if isinstance(node, ast.For)
             and isinstance(node.target, ast.Name) and node.target.id == "mutation"]
    if len(loops) != 1 or not isinstance(loops[0].iter, ast.Tuple):
        raise ValueError("original Windows profile inventory changed")
    try:
        mutations = ast.literal_eval(loops[0].iter)
    except (ValueError, TypeError):
        raise ValueError("original Windows profile inventory is not literal") from None
    if mutations != WINDOWS_PROFILE_MUTATIONS:
        raise ValueError("original Windows profile inventory changed")
    def calls(node):
        return [item for item in ast.walk(node) if isinstance(item, ast.Call)
                and isinstance(item.func, ast.Name) and item.func.id == "run"]
    if len(calls(loops[0])) != 1 or len(calls(functions["windows"])) != 2:
        raise ValueError("original Windows owned command inventory changed")
    return (len(mutations) + 1) * WINDOWS_CHILD_SECONDS


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError("trusted desktop editor executor missing")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


CORE = load("desktop_editor_trusted_executor", ROOT / "deploy/test_focused_multihop_clocks.py")


def require_host(target, system, machine):
    wanted = TARGETS.get(target)
    if wanted is None or system != wanted[0] or machine not in wanted[1]:
        raise ValueError("desktop editor requires its exact native target")
    return system


def verdict(raw, target, code, timed_out, joined):
    text = raw.decode("utf-8", "strict").replace("\r\n", "\n").replace("\r", "\n")
    failures = bool(re.search(r"(?m)^(?:Traceback|FAILED|FAIL:|ERROR|GTK ordered:|ORDERED-EDITOR:)", text))
    result = {"accepted": False, "exit": code, "timed_out": timed_out,
              "process_group_joined": joined}
    if target == "linux/amd64":
        positives = re.findall(r"(?m)^Shipping GTK ordered editor \+ Add/Load/Update/Connect: ([1-9][0-9]*) checks PASS; real callbacks/persistence, doubled controller boundary\.$", text)
        controls = re.findall(r"(?m)^GTK ordered causal control ([^\r\n]+): rejected$", text)
        result.update(positive_counts=positives, controls=controls)
        complete = len(positives) == 1 and tuple(controls) == LINUX_CONTROLS
        failures = failures or "CRITICAL" in text or "WARNING" in text
    elif target in ("windows/amd64", "windows/arm64"):
        profiles = re.findall(r"(?m)^Actual WPF profile Add/Load/Update and main Connect callbacks: ([1-9][0-9]*) checks PASS$", text)
        editors = re.findall(r"(?m)^Actual ordered node editor callbacks: ([1-9][0-9]*) checks PASS; WPF=True$", text)
        summaries = re.findall(r"(?m)^WPF pair and ordered capture, setup ownership/response, load/Connect, capability and startup deadline negatives: ([0-9]+) rejected$", text)
        controls = re.findall(r"(?m)^Actual ordered editor causal control ([^\r\n]+): rejected$", text)
        result.update(profile_counts=profiles, editor_counts=editors, controls=controls,
                      original_control_counts=summaries)
        complete = (len(profiles) == 1 and len(editors) == 1 and summaries == ["19"] and
                    len(controls) == len(WINDOWS_CONTROLS) and frozenset(controls) == WINDOWS_CONTROLS)
    else:
        raise ValueError("unknown desktop editor target")
    result["accepted"] = bool(code == 0 and not timed_out and joined and complete and not failures)
    return result


def require_selection(source, sha, output):
    path = output.parent / "selection.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("desktop editor lost its original selection")
    raw = path.read_bytes()
    selected = json.loads(raw)
    if (selected.get("schema") != 1 or selected.get("suite") != SUITE or
            selected.get("source_sha") != sha or selected.get("repository") != "Eabusham2/router-vpn" or
            selected.get("workflow_ref") != "refs/heads/main" or
            selected.get("validation_scope") != "read-only-source-candidate" or
            selected.get("base_sha") != selected.get("validator_sha") or
            selected.get("base_tree") != selected.get("validator_tree")):
        raise ValueError("desktop editor selection changed its source or authority")
    for key in ("source_sha", "source_tree", "base_sha", "base_tree", "validator_sha", "validator_tree"):
        if not isinstance(selected.get(key), str) or not re.fullmatch("[0-9a-f]{40}", selected[key]):
            raise ValueError("desktop editor selection lost full Git identity")
    for root, commit, tree in ((source, sha, selected["source_tree"]),
                              (ROOT, selected["validator_sha"], selected["validator_tree"])):
        if (CORE.git(root, "rev-parse", "HEAD").decode().strip() != commit or
                CORE.git(root, "rev-parse", "HEAD^{tree}").decode().strip() != tree or
                CORE.git(root, "status", "--porcelain", "--untracked-files=all")):
            raise ValueError("desktop editor original checkout changed")
    return selected, raw


def validate(args):
    source, output = Path(args.source).resolve(), Path(args.output).resolve()
    system = require_host(args.target, platform.system(), platform.machine())
    if not re.fullmatch("[0-9a-f]{40}", args.source_sha):
        raise ValueError("source SHA must be exact lowercase 40-hex")
    if output == source or source in output.parents or (output.exists() and any(output.iterdir())):
        raise ValueError("editor output must be fresh and outside source")
    selected, selection_raw = require_selection(source, args.source_sha, output)
    before, trusted_before = CORE.snapshot(source), CORE.snapshot(ROOT)
    if any(path not in before or before[path]["mode"] != "100644" for path in SOURCE_PATHS):
        raise ValueError("desktop editor source inventory changed")
    output.mkdir(parents=True, exist_ok=True)
    (output / "source-before.json").write_text(json.dumps(before, sort_keys=True) + "\n")
    manifest = {"schema": 1, "suite": SUITE, "source_sha": args.source_sha,
        "target": args.target, "selection": selected,
        "selection_sha256": hashlib.sha256(selection_raw).hexdigest(),
        "validator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "trusted_executor_sha256": hashlib.sha256((ROOT / "deploy/test_focused_multihop_clocks.py").read_bytes()).hexdigest(),
        "commands": [], "status": "running", "native_tunnel_accepted": False,
        "scope": "Actual GTK and WPF ordered-editor widgets plus shipping callbacks. Original full-profile widget/HTTP fixtures and ordered causal widgets retain their explicit doubles; no physical visual or tunnel acceptance."}

    def save():
        (output / "manifest.json").write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")

    owner = load("desktop_editor_windows_owner", ROOT / "deploy/windows_build_owner.py") if system == "Windows" else None
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")

    def execute(name, command, bound):
        command = [str(value) for value in command]
        path = output / (name + ".log")
        started, code, timed_out, joined = time.monotonic(), None, False, False
        try:
            if owner is None:
                code, timed_out, joined = CORE.execute(command, source, env, path, bound)
            else:
                # The existing owner admits a suspended bootstrap, retains the
                # native Job and joins original descendants before returning.
                try:
                    result = owner.run(command, cwd=source, env=env, timeout=bound)
                    if result.args != command:
                        raise ValueError("native editor command identity changed")
                    code, joined = result.returncode, True
                    path.write_bytes(result.stdout + result.stderr)
                except subprocess.CalledProcessError as error:
                    if error.cmd != command:
                        raise
                    code, joined = error.returncode, True
                    path.write_bytes((error.stdout or b"") + (error.stderr or b""))
                except subprocess.TimeoutExpired as error:
                    if error.cmd == command:
                        code, timed_out, joined = 124, True, True
                    path.write_bytes((error.stdout or b"") + (error.stderr or b""))
                    raise
        except BaseException as error:
            if not path.exists():
                path.write_text(type(error).__name__ + ": " + str(error) + "\n")
            raise
        finally:
            row = {"name": name, "command": command, "bound": bound, "exit": code,
                   "timed_out": timed_out, "process_group_joined": joined,
                   "seconds": time.monotonic() - started, "log": path.name,
                   "log_sha256": hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None}
            manifest["commands"].append(row)
            save()
        return path.read_bytes(), code, timed_out, joined, row

    save()
    try:
        if system == "Windows":
            suite_bound = windows_suite_budget((source / "deploy/test_desktop_connection_profile_modes.py").read_text(encoding="utf-8"))
            manifest["per_child_seconds"] = WINDOWS_CHILD_SECONDS
            manifest["profile_suite_seconds"] = suite_bound
            for name, wanted in (("powershell.exe", "Desktop"), ("pwsh", "Core")):
                shell = shutil.which(name)
                if shell is None:
                    raise ValueError("required native PowerShell is missing: " + name)
                probe = "[pscustomobject]@{version=$PSVersionTable.PSVersion.ToString();edition=$PSVersionTable.PSEdition;bits=([IntPtr]::Size*8)}|ConvertTo-Json -Compress"
                raw, code, timed_out, joined, _ = execute(name + "-version",
                    [shell, "-NoProfile", "-NonInteractive", "-Command", probe], 30)
                version = json.loads(raw.decode("utf-8").strip())
                if (code != 0 or timed_out or not joined or version.get("edition") != wanted or
                        version.get("bits") != 64 or
                        (wanted == "Desktop" and not str(version.get("version", "")).startswith("5.1.")) or
                        (wanted == "Core" and not re.match(r"^7\.", str(version.get("version", ""))))):
                    raise ValueError("native PowerShell identity did not match its required shell")
                manifest.setdefault("shells", []).append({"path": shell, **version})
                command = [sys.executable, source / "deploy/test_desktop_connection_profile_modes.py",
                           "--platform", "windows", "--shell", shell]
                raw, code, timed_out, joined, row = execute(name + "-profiles", command, suite_bound)
                row["verdict"] = verdict(raw, args.target, code, timed_out, joined)
                save()
                if not row["verdict"]["accepted"]:
                    raise ValueError("original WPF profile and ordered-editor verdicts incomplete")
        else:
            bus = shutil.which("dbus-run-session")
            if bus is None:
                raise ValueError("native GTK accessibility session owner is missing")
            command = [bus, "--", sys.executable, source / "client/linux/test-ordered-nodes-v1.py"]
            raw, code, timed_out, joined, row = execute("gtk-profiles", command, 900)
            row["verdict"] = verdict(raw, args.target, code, timed_out, joined)
            save()
            if not row["verdict"]["accepted"]:
                raise ValueError("actual GTK editor did not produce every original verdict")
        if (CORE.snapshot(source) != before or CORE.snapshot(ROOT) != trusted_before or
                require_selection(source, args.source_sha, output)[1] != selection_raw):
            raise ValueError("desktop editor source or original selection changed during execution")
        manifest["status"] = "passed"
        print(json.dumps({"target": args.target, "status": "passed",
            "native_widgets": True, "native_tunnel_accepted": False}), flush=True)
    except BaseException as error:
        manifest["status"], manifest["error"] = "failed", str(error)
        raise
    finally:
        save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--target", choices=tuple(TARGETS), required=True)
    parser.add_argument("--output", required=True)
    validate(parser.parse_args())


if __name__ == "__main__":
    main()
