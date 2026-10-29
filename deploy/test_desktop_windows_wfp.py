#!/usr/bin/env python3
"""Exercise the shipping owned Windows WFP baseline on the actual host kernel.

Every test filter is scoped to the actual test executable. This gate changes no
Firewall profile, route, existing account, or foreign policy. It is a distinct
gate from isolated socket identity; both are required before native admission.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "routervpn_windows_identity_gate", ROOT / "deploy/test_desktop_windows_identity.py")
IDENTITY = importlib.util.module_from_spec(spec)
spec.loader.exec_module(IDENTITY)

REQUIRED = (
    "TestDesktopSocketWindowsWFPLayout",
    "TestDesktopSocketWindowsWFPActualBaseline",
    "TestDesktopSocketWindowsWFPRejectsActiveOwner",
    "TestDesktopSocketWindowsWFPAlwaysReplacement",
    "TestDesktopSocketWindowsWFPRejectsAdditionalPermit",
    "TestDesktopSocketWindowsWFPRejectsNoncanonicalRecords",
    "TestDesktopSocketWindowsWFPExplicitRecovery",
    "TestDesktopSocketWindowsWFPAssignedWeights",
    "TestDesktopSocketWindowsWFPRejectsRecordedWeight",
    "TestDesktopSocketWindowsWFPInterfaceReadback",
    "TestDesktopSocketWindowsWFPStatusAndNormalRelease",
    "TestDesktopSocketWindowsWFPStatusRejectsExtraRetainedRule",
    "TestDesktopSocketWindowsWFPProbeOrdinaryAbsence",
    "TestDesktopSocketWindowsWFPProbeOrdinaryProtectedObjects",
    "TestDesktopSocketWindowsWFPProbeCancelledGate",
    "TestDesktopSocketWindowsWFPProbeWorkerLifetime",
)


def mutants(target):
    baseline = (target / "desktop_socket_windows_baseline.go").read_text(encoding="utf-8")
    wfp = (target / "desktop_socket_windows_wfp.go").read_text(encoding="utf-8")
    policy = (target / "desktop_socket_windows_policy.go").read_text(encoding="utf-8")
    status = (target / "desktop_socket_windows_status.go").read_text(encoding="utf-8")
    probe = (target / "desktop_socket_windows_probe.go").read_text(encoding="utf-8")
    worker = (target / "desktop_socket_windows_probe_worker_test.go").read_text(encoding="utf-8")
    fixture = (target / "desktop_socket_windows_probe_process_test.go").read_text(encoding="utf-8")
    return (
        ("extra-filter", "desktop_socket_windows_wfp.go", REQUIRED[4],
         "full WFP readback accepted an extra broader permit",
         IDENTITY.replace_once(wfp,
                               'failure = errors.New("WFP captured sublayer acquired an extra or repeated filter")\n\t\t\t\tbreak',
                               'continue')),
        ("always-retention", "desktop_socket_windows_baseline.go", REQUIRED[3],
         "Always lost its persistent baseline",
         IDENTITY.replace_once(baseline,
                               'if p.installed && p.options.KillSwitchPolicy != "always" {',
                               'if p.installed {')),
        ("canonical-record", "desktop_socket_windows_baseline.go", REQUIRED[5],
         "untrusted WFP record acquired baseline replacement authority",
         IDENTITY.replace_once(baseline,
                               "err != nil || !bytes.Equal(canonical, data) || record.Schema != 2",
                               "err != nil || len(canonical) == 0 || record.Schema != 2")),
        ("active-weight", "desktop_socket_windows_wfp.go", REQUIRED[7],
         "captured WFP weight drift was accepted",
         IDENTITY.replace_once(wfp,
                               "if snapshot.Weight != weight {",
                               "if false && snapshot.Weight != weight {")),
        ("recorded-weight", "desktop_socket_windows_baseline.go", REQUIRED[8],
         "prior-session record accepted a substituted kernel weight",
         IDENTITY.replace_once(baseline,
                               "old.sublayer != key || snapshot.Weight != old.baselineWeight",
                               "old.sublayer != key")),
        ("interface-byte-order", "desktop_socket_windows_policy.go", REQUIRED[9],
         "actual interface application failed",
         IDENTITY.replace_once(policy,
                               "err != nil || uint32(actual) != item.Index",
                               "err != nil || uint32(actual) != uint32(value)")),
        ("normal-release-always", "desktop_socket_windows_baseline.go", REQUIRED[10],
         "normal release removed Always protection",
         IDENTITY.replace_once(baseline, "if removeAlways {", "if true {")),
        ("retained-status-extra-rule", "desktop_socket_windows_status.go", REQUIRED[11],
         "native status accepted an extra retained permit",
         IDENTITY.replace_once(status,
                               "if err := engine.AssertComplete(baseline.sublayer, baseline.baseline); err != nil {",
                               "if err := error(nil); err != nil {")),
        ("probe-access-denied", "desktop_socket_windows_probe.go", REQUIRED[13],
         "ordinary protected session-lock access denial was reported as missing native protection",
         IDENTITY.replace_once(probe,
                               'if err := desktopWFPError("probe managed protection absence", status); err != nil {\n\t\t\treturn false, err\n\t\t}',
                               'if err := desktopWFPError("probe managed protection absence", status); err != nil {\n\t\t\treturn true, nil\n\t\t}')),
        ("probe-omits-baseline", "desktop_socket_windows_probe.go", REQUIRED[13],
         "ordinary protected baseline access denial was reported as missing native protection",
         IDENTITY.replace_once(probe,
                               '[]string{"session-lock", "baseline", "session-lock"}',
                               '[]string{"session-lock", "session-lock"}')),
        ("probe-omits-lock", "desktop_socket_windows_probe.go", REQUIRED[13],
         "ordinary protected session-lock access denial was reported as missing native protection",
         IDENTITY.replace_once(probe,
                               '[]string{"session-lock", "baseline", "session-lock"}',
                               '[]string{"baseline", "baseline"}')),
        ("probe-worker-owner-death", "desktop_socket_windows_probe_worker_test.go", REQUIRED[15],
         "probe worker death left its ordinary child alive",
         IDENTITY.replace_once(worker,
                               'desktopWindowsProbeJobLimits{Flags: 0x2008, ActiveProcesses: count}',
                               'desktopWindowsProbeJobLimits{Flags: 0x0008, ActiveProcesses: count}')),
        ("probe-file-mask-on-station", "desktop_socket_windows_probe_process_test.go", REQUIRED[12],
         "private probe station lacks captured caller authority",
         IDENTITY.replace_once(fixture,
                               'D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;',
                               'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;')),
    )


def execute(source=ROOT, go="go", *, env=None):
    if platform.system() != "Windows":
        raise ValueError("WFP kernel proof requires actual Windows execution")
    if not IDENTITY.ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("WFP kernel proof requires an elevated native test host")
    source, target, package, before = IDENTITY.checked_sources(source)
    for name in ("desktop_socket_windows_wfp.go", "desktop_socket_windows_wfp_security.go",
                 "desktop_socket_windows_baseline.go", "desktop_socket_windows_policy.go",
                 "desktop_socket_windows_status.go",
                 "desktop_socket_windows_probe.go", "desktop_socket_windows_probe_test.go",
                 "desktop_socket_windows_probe_process_test.go",
                 "desktop_socket_windows_probe_worker_test.go",
                 "desktop_socket_windows_tunnel.go", "desktop_socket_windows_wfp_test.go"):
        if name not in before:
            raise ValueError("WFP gate lost its shipping source closure: " + name)
    compiler, captured, architecture = IDENTITY.selected_compiler(
        go, source, dict(os.environ if env is None else env))
    candidates = mutants(target)
    race = ["-race"] if architecture == "amd64" else []
    captured["CGO_ENABLED"] = "1" if race else "0"
    build = [compiler, "test", "-c", "-mod=readonly", "-tags=routervpn_windows_wfp", *race]
    with tempfile.TemporaryDirectory(prefix="routervpn-windows-wfp-") as directory:
        workspace = Path(directory)
        binary = workspace / "wfp.test.exe"
        status, output = IDENTITY.run([*build, "-o", binary, package], cwd=source, env=captured)
        if status:
            raise ValueError("WFP baseline compilation failed:\n" + output[-32768:])
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        status, output = IDENTITY.run([binary, "-test.run=^TestDesktopSocketWindowsWFP", "-test.count=1",
                                       "-test.timeout=120s", "-test.v"], cwd=source, env=captured, timeout=135)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if status or "--- SKIP:" in output or any("--- PASS: " + name + " (" not in output for name in REQUIRED):
            raise ValueError("WFP baseline did not execute every actual kernel proof")
        for kind in ("session-lock", "baseline"):
            if "--- PASS: " + REQUIRED[13] + "/" + kind + " (" not in output:
                raise ValueError("WFP probe omitted an actual non-admin protected-object query: " + kind)
        for mode in ("worker-death", "outer-owner-close"):
            if "--- PASS: " + REQUIRED[15] + "/" + mode + " (" not in output:
                raise ValueError("WFP probe omitted actual nested Job cleanup: " + mode)
        if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("WFP baseline binary changed during execution")
        for label, filename, test, witness, replacement in candidates:
            changed = workspace / (label + ".go")
            changed.write_text(replacement, encoding="utf-8")
            overlay = workspace / (label + ".json")
            overlay.write_text(json.dumps({"Replace": {str(target / filename): str(changed)}}), encoding="utf-8")
            candidate = workspace / (label + ".test.exe")
            status, output = IDENTITY.run([*build, "-overlay=" + str(overlay), "-o", candidate, package],
                                          cwd=source, env=captured)
            if status:
                raise ValueError("WFP negative control did not compile: " + label + "\n" + output[-8192:])
            status, output = IDENTITY.run([candidate, "-test.run=^" + test + "$", "-test.count=1",
                                           "-test.timeout=40s", "-test.v"], cwd=source, env=captured, timeout=50)
            if (status == 0 or "--- FAIL: " + test + " (" not in output or witness not in output or
                    "--- SKIP:" in output or "panic: test timed out" in output or "DATA RACE" in output):
                raise ValueError("WFP negative control missed its exact broken behavior: " + label + "\n" + output[-16384:])
            kind = "fixture" if filename.endswith("_test.go") else "production"
            print("Rejected " + kind + " WFP mutant:", label, flush=True)
        if IDENTITY.checked_sources(source)[3] != before:
            raise ValueError("WFP source changed during its actual native gate")
    print("Owned Windows WFP baseline passed sixteen actual kernel/lifecycle cases, distinct non-admin process absence/ACCESS_DENIED proofs, eleven production negative controls and two broken Job-owner/station-access fixture controls; socket traffic and native admission remain separately gated.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", nargs="?", type=Path, default=ROOT)
    parser.add_argument("--go", default="go")
    arguments = parser.parse_args()
    execute(arguments.source, arguments.go)
