#!/usr/bin/env python3
"""Execute the complete Go source gate without one growing controller alarm.

The controller binary is compiled once. Its own list supplies every Test,
Example and ordinary Fuzz seed root; each whole root runs once with the original
15-minute Go alarm. No child selector or source inventory can omit a new case.
Other requested packages retain ordinary, unfiltered go test execution. Explicit
test-owned skips remain skips and are printed, not presented as native proof.
Each phase is a new process, so package initialization and any TestMain run once
per root rather than once for the entire package; descendants stay together.
"""
from collections import Counter
from pathlib import Path
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "router-vpn/cmd/client"
TIMEOUT = "15m"
# Only a process-reaping allowance: the Go alarm itself is still 900 seconds.
PROCESS_TIMEOUT = 930
SCOPES = {
    "all": ("./...",),
    "client-common": ("./cmd/client", "./internal/common"),
    "client": ("./cmd/client",),
}
NAME = re.compile(r"(?:Test|Example|Fuzz|Benchmark)\w*\Z")
PACKAGE_NAME = re.compile(r"router-vpn(?:/[A-Za-z0-9_.~-]+)*\Z")


def packages(output, scope):
    values = tuple(output.splitlines())
    if (not values or len(set(values)) != len(values) or PACKAGE not in values
            or any(not PACKAGE_NAME.fullmatch(value) for value in values)):
        raise ValueError("Invalid or incomplete original Go package inventory")
    if scope != "all":
        expected = {"router-vpn/" + value[2:] for value in SCOPES[scope]}
        if set(values) != expected:
            raise ValueError("Requested package scope changed")
    return values


def inventory(output):
    names = tuple(output.splitlines())
    if (not names or len(set(names)) != len(names)
            or any(not NAME.fullmatch(name) for name in names)):
        raise ValueError("Invalid or duplicate compiled Go test inventory")
    # Ordinary go test does not execute benchmarks without -bench. Fuzz seed
    # corpora and examples DO run normally and must not be lost here.
    roots = tuple(name for name in names if not name.startswith("Benchmark"))
    if not roots:
        raise ValueError("Compiled controller inventory has no executable roots")
    return roots


def validate_partition(roots, phases):
    if not roots or len(set(roots)) != len(roots) or tuple(phases) != tuple(roots):
        raise ValueError("Controller phases omitted, duplicated or reordered a compiled root")
    if any(not NAME.fullmatch(root) or root.startswith("Benchmark") for root in roots):
        raise ValueError("Controller phase is not one complete compiled root")


def test2json_tool(directory):
    # Resolve through the same module/toolchain selection used to compile the
    # test image, once. Re-entering the go driver for every root adds minutes.
    # Go 1.26 may build this standard tool into its executable cache instead
    # of installing it in GOTOOLDIR. -n reports that actual selected image.
    value = subprocess.check_output(["go", "tool", "-n", "test2json"], cwd=directory,
                                    text=True, timeout=120).strip()
    tool = Path(value)
    if not tool.is_absolute() or tool.name != "test2json" or not tool.is_file() or not os.access(tool, os.X_OK):
        raise ValueError("Original Go toolchain test2json executable is unavailable")
    return tool


def command(binary, root, tool):
    if not NAME.fullmatch(root) or root.startswith("Benchmark"):
        raise ValueError("A controller phase must select one whole test root")
    return [str(tool), "-p", PACKAGE, "-t", str(binary),
            "-test.v=test2json", "-test.count=1", "-test.timeout=" + TIMEOUT,
            "-test.run=^" + re.escape(root) + "$"]


def verdict(output, returncode, root, stderr=""):
    """Validate actual test2json receipts, including explicitly reported skips."""
    if returncode != 0:
        raise ValueError("Controller phase exited nonzero: " + str(returncode))
    runs, terminal, suspended = set(), {}, set()
    started = finished = False
    text = [stderr]
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except (TypeError, ValueError) as exc:
            raise ValueError("Malformed test2json event") from exc
        if not isinstance(event, dict) or event.get("Package") != PACKAGE:
            raise ValueError("Missing or substituted controller package")
        action, name = event.get("Action"), event.get("Test", "")
        if not isinstance(name, str) or action not in {
                "start", "run", "pause", "cont", "pass", "fail", "skip", "output"}:
            raise ValueError("Unexpected test2json event")
        if finished:
            raise ValueError("Event arrived after the package verdict")
        if not started:
            if action != "start" or name:
                raise ValueError("Missing package start")
            started = True
            continue
        if action == "start":
            raise ValueError("Duplicate package start")
        if action == "fail":
            raise ValueError("Failed controller evidence: " + (name or root))
        if name and name != root and not name.startswith(root + "/"):
            raise ValueError("A different controller root executed: " + name)
        if action == "output":
            value = event.get("Output")
            if not isinstance(value, str):
                raise ValueError("Malformed test output")
            text.append(value)
        elif action == "run":
            if not name or name in runs or (name != root and root not in runs):
                raise ValueError("Missing parent or duplicate test execution")
            if any(name.startswith(parent + "/") for parent in terminal):
                raise ValueError("Child began after an original ancestor completed")
            runs.add(name)
        elif action in ("pass", "skip"):
            if name:
                if name not in runs or name in terminal or name in suspended:
                    raise ValueError("Terminal test receipt lacks one active run")
                if any(child.startswith(name + "/") and child not in terminal for child in runs):
                    raise ValueError("Parent completed before an entered child joined")
                terminal[name] = action
            else:
                if action != "pass" or root not in runs or runs != set(terminal):
                    raise ValueError("Package completed without every original test receipt")
                finished = True
        elif action in ("pause", "cont"):
            if name not in runs or name in terminal:
                raise ValueError("Invalid suspended test receipt")
            if action == "pause":
                if name in suspended:
                    raise ValueError("Duplicate pause receipt")
                suspended.add(name)
            else:
                if name not in suspended:
                    raise ValueError("Continue without original pause")
                suspended.remove(name)
    joined = "".join(text)
    if "WARNING: DATA RACE" in joined or "race detected during execution of test" in joined:
        raise ValueError("Race detector reported unsafe execution")
    if not finished or root not in terminal or runs != set(terminal) or suspended:
        raise ValueError("Missing complete original controller run/terminal/package receipts")
    return terminal


def run_phase(binary, root, directory, tool):
    print("Controller root: " + root + " (Go alarm " + TIMEOUT + ")", flush=True)
    process = subprocess.Popen(command(binary, root, tool), cwd=directory, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        output, errors = process.communicate(timeout=PROCESS_TIMEOUT)
    except BaseException:
        # Join only this newly-created group, never an unrelated native owner.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise
    try:
        terminal = verdict(output, process.returncode, root, errors)
    except ValueError:
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if errors:
            print(errors, file=sys.stderr, flush=True)
        raise
    for line in report_lines(output, terminal):
        print(line, flush=True)
    return terminal


def report_lines(output, terminal):
    # Keep original names, verdicts, timings AND test-owned skip reasons. A
    # skipped native fixture is never rewritten as passing native acceptance.
    skipped = {name for name, result in terminal.items() if result == "skip"}
    for line in output.splitlines():
        event = json.loads(line)
        if event.get("Test") and (event.get("Action") in ("pass", "skip") or
                                  (event.get("Action") == "output" and event["Test"] in skipped)):
            yield line


def complete(roots, results):
    if tuple(root for root, _ in results) != tuple(roots):
        raise ValueError("Final controller inventory is incomplete, duplicated or reordered")
    observed = Counter()
    counts = Counter()
    for root, terminal in results:
        if root not in terminal:
            raise ValueError("Final root has no original terminal receipt")
        if any(name != root and not name.startswith(root + "/") for name in terminal):
            raise ValueError("Final phase adopted another root's receipt")
        if any(value not in ("pass", "skip") for value in terminal.values()):
            raise ValueError("Final phase contains a failed or unknown verdict")
        observed.update(terminal.keys())
        counts.update(terminal.values())
    if any(count != 1 for count in observed.values()):
        raise ValueError("A controller test executed in more than one phase")
    return counts


def other_command(selected):
    remaining = [package for package in selected if package != PACKAGE]
    return ["go", "test", "-timeout=" + TIMEOUT, *remaining] if remaining else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", choices=tuple(SCOPES), required=True)
    args = parser.parse_args()
    # Every shipping invocation checks the runner and all seven required
    # workflow edges before it can execute a filtered binary command.
    subprocess.run([sys.executable, str(ROOT / "deploy/test_go_source_groups_runner.py")],
                   cwd=ROOT, check=True, timeout=60)
    listed = subprocess.check_output(["go", "list", *SCOPES[args.scope]],
                                     cwd=ROOT, text=True, timeout=120)
    selected = packages(listed, args.scope)
    print("Original Go package inventory: " + json.dumps(selected), flush=True)
    with tempfile.TemporaryDirectory(prefix="routervpn-complete-controller-") as directory:
        binary = Path(directory) / "client.test"
        subprocess.run(["go", "test", "-c", "-o", str(binary), "./cmd/client"],
                       cwd=ROOT, check=True, timeout=600)
        listed = subprocess.check_output([str(binary), "-test.list=."], cwd=ROOT / "cmd/client",
                                         text=True, timeout=30)
        roots = inventory(listed)
        phases = tuple(roots)
        validate_partition(roots, phases)
        tool = test2json_tool(ROOT)
        print("Complete compiled controller roots: " + json.dumps(roots), flush=True)
        results = [(root, run_phase(binary, root, ROOT / "cmd/client", tool)) for root in phases]
        counts = complete(roots, results)
        print("Controller inventory complete: " + str(len(roots)) + " whole roots, " +
              str(counts["pass"]) + " PASS and " + str(counts["skip"]) +
              " explicit SKIP receipts; each root retained the 15m Go alarm", flush=True)
    command = other_command(selected)
    if command is not None:
        # No root/child selector, -short, skip, compile-only mode or ignored
        # status is applied to the rest of the original package inventory.
        subprocess.run(command, cwd=ROOT, check=True)
    print("Complete original Go package gate passed: " + args.scope, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
