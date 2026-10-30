"""Exercise the owned Windows updater's actual private cache and provenance.

The Session runner supplies its native compiler and full shipping fixture.
These tests use disposable files only and never query a release service. The
updater process and final launcher adoption remain separate composition gates.
"""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "TestWindowsUpdaterCapturedPackageProvenance",
    "TestWindowsUpdaterRejectsForeignCacheNames",
    "TestWindowsUpdaterCacheRetainsPrivateIdentity",
    "TestWindowsUpdaterCacheRejectsForeignObjects",
    "TestWindowsUpdaterPinnedProvenance",
    "TestWindowsUpdaterCacheCancellation",
)
NEGATIVE_CASES = ("cache-link", "file-link", "file-hardlink", "foreign-name",
                  "foreign-directory", "foreign-cache-acl", "foreign-file-acl")


def mutations(native):
    cache = "internal/windowsapp/updater_cache_windows.go"
    policy = "internal/windowsapp/updater_policy.go"
    cache_source = (ROOT / cache).read_text(encoding="utf-8")
    policy_source = (ROOT / policy).read_text(encoding="utf-8")
    return (
        (cache, "directory-pin-without-list-access", REQUIRED[2] + "/updates",
         "retained updater cache allowed directory or ancestor replacement",
         native.replace_once(cache_source,
                             "access |= 1 // FILE_LIST_DIRECTORY:",
                             "access |= 0 // FILE_LIST_DIRECTORY:")),
        (cache, "foreign-private-access", REQUIRED[3] + "/foreign-cache-acl",
         "unsafe existing updater cache was admitted",
         native.replace_once(cache_source,
                             "return validatePortablePrivateGrants(owner, cache.desktop, grants)",
                             "return nil // deliberately bypass the captured private ACL")),
        (cache, "existing-hardlink", REQUIRED[3] + "/file-hardlink",
         "unsafe existing updater cache was admitted",
         native.replace_once(cache_source,
                             "!directory && info.NumberOfLinks != 1",
                             "false && !directory && info.NumberOfLinks != 1")),
        (policy, "foreign-package-family", REQUIRED[0],
         "updater adopted another package layout's provenance",
         native.replace_once(policy_source,
                             "if provenance.ArtifactFamily != family+architecture {",
                             "if false && provenance.ArtifactFamily != family+architecture {")),
    )


def execute_prepared(native, compiler, captured, build, fixture, workspace):
    digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
    expression = "^(" + "|".join(REQUIRED) + ")$"
    status, output = native.run(
        [fixture, "-test.run=" + expression, "-test.count=1", "-test.timeout=90s", "-test.v"],
        cwd=ROOT / "internal/windowsapp", env=captured, timeout=105)
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    expected = (*REQUIRED, *(REQUIRED[3] + "/" + case for case in NEGATIVE_CASES))
    if (status or "--- SKIP:" in output or "DATA RACE" in output or
            any("--- PASS: " + name + " (" not in output for name in expected)):
        raise ValueError("Updater preparation omitted or failed an actual private-file boundary")
    if hashlib.sha256(fixture.read_bytes()).hexdigest() != digest:
        raise ValueError("Updater preparation fixture changed during native execution")
    for filename, name, test, witness, replacement in mutations(native):
        changed = workspace / ("updater-" + name + ".go")
        changed.write_text(replacement, encoding="utf-8")
        overlay = workspace / ("updater-" + name + ".json")
        overlay.write_text(json.dumps({"Replace": {str(ROOT / filename): str(changed)}}), encoding="utf-8")
        candidate = workspace / ("updater-" + name + ".test.exe")
        status, output = native.run(
            [*build, "-overlay=" + str(overlay), "-o", candidate, "./internal/windowsapp"],
            cwd=ROOT, env=captured, timeout=240)
        if status:
            raise ValueError("Updater preparation defect did not compile: " + name + "\n" + output[-8192:])
        status, output = native.run(
            [candidate, "-test.run=^" + test + "$", "-test.count=1", "-test.timeout=45s", "-test.v"],
            cwd=ROOT / "internal/windowsapp", env=captured, timeout=55)
        if (not status or witness not in output or "--- FAIL: " + test + " (" not in output or
                "--- SKIP:" in output or "panic: test timed out" in output or "DATA RACE" in output):
            raise ValueError("Updater preparation defect missed its intended boundary: " + name + "\n" + output[-16384:])
        print("Actual updater preparation defect rejected: " + name, flush=True)
    return {"updater_preparation_groups": len(REQUIRED), "updater_unsafe_state_cases": len(NEGATIVE_CASES),
            "updater_preparation_defects": len(mutations(native))}
