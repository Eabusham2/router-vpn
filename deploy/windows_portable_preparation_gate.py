"""Native Portable preparation checks shared by the actual Windows Session gate.

The caller supplies the already selected native compiler, captured environment
and compiled Session fixture. Tests create only disposable local package/data
objects. A source parser or cross-compile cannot satisfy this execution gate.
"""
from pathlib import Path
import hashlib
import json

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    "TestWindowsPortableConfigurationPreservesAndRelocates",
    "TestWindowsPortableConfigurationFreshDefaultsAndInvalidPreservation",
    "TestWindowsPortablePrivateAccessPolicy",
    "TestWindowsPortableInitializationAndRelocation",
    "TestWindowsPortableRejectsUnsafeAndInvalidState",
    "TestWindowsPortableCancellationAndPublicationOwnership",
    "TestWindowsPortableRequiresCapturedCore",
    "TestWindowsPortableInspectionPreservesLivePins",
    "TestWindowsPortableTemporaryRetainsPrivateIdentity",
)
NEGATIVE_CASES = ("private-hardlink", "data-link", "generated-link",
                  "source-hardlink", "invalid-config", "invalid-routers", "existing-lock")


def mutations(native):
    configuration = "internal/windowsapp/portable_config.go"
    files = "internal/windowsapp/portable_security_windows.go"
    publication = "internal/windowsapp/portable_prepare_windows.go"
    temporary = "internal/windowsapp/temporary_windows.go"
    config_source = (ROOT / configuration).read_text(encoding="utf-8")
    file_source = (ROOT / files).read_text(encoding="utf-8")
    publish_source = (ROOT / publication).read_text(encoding="utf-8")
    temporary_source = (ROOT / temporary).read_text(encoding="utf-8")
    return (
        (configuration, "reset-existing-settings", REQUIRED[0],
         "Portable relocation replaced saved field",
         native.replace_once(config_source, "if body == nil {", "if true {")),
        (configuration, "foreign-private-access", REQUIRED[2],
         "Portable private policy accepted an unrelated read/write/inherited grant",
         native.replace_once(config_source,
                             "if !portableTrustedPrincipal(grant.principal, desktop) {",
                             "if false && !portableTrustedPrincipal(grant.principal, desktop) {")),
        (files, "private-hardlink", REQUIRED[4] + "/private-hardlink",
         "unsafe/invalid existing Portable state was admitted",
         native.replace_once(file_source, "!directory && info.NumberOfLinks != 1",
                             "false && !directory && info.NumberOfLinks != 1")),
        (publication, "stale-private-publication", REQUIRED[5],
         "stale Portable publication replaced a newer private value",
         native.replace_once(publish_source,
                             "if (before == nil) != (current == nil) || before != nil &&",
                             "if false && (before == nil) != (current == nil) || false && before != nil &&")),
        (temporary, "metadata-only-temporary-owner", REQUIRED[8] + "/private",
         "live Portable temporary capture allowed its directory to move",
         native.replace_once(temporary_source, "0x00020000|0x80|syscall.FILE_LIST_DIRECTORY",
                             "0x00020000|0x80")),
    )


def execute_prepared(native, compiler, captured, build, fixture, workspace):
    digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
    expression = "^(" + "|".join(REQUIRED) + ")$"
    status, output = native.run(
        [fixture, "-test.run=" + expression, "-test.count=1", "-test.timeout=90s", "-test.v"],
        cwd=ROOT / "internal/windowsapp", env=captured, timeout=105)
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    expected = (*REQUIRED, *(REQUIRED[4] + "/" + case for case in NEGATIVE_CASES))
    if (status or "--- SKIP:" in output or "DATA RACE" in output or
            any("--- PASS: " + name + " (" not in output for name in expected)):
        raise ValueError("Portable preparation omitted or failed an actual private-file/relocation boundary")
    if hashlib.sha256(fixture.read_bytes()).hexdigest() != digest:
        raise ValueError("Portable preparation fixture changed during native execution")
    for filename, name, test, witness, replacement in mutations(native):
        changed = workspace / ("portable-" + name + ".go")
        changed.write_text(replacement, encoding="utf-8")
        overlay = workspace / ("portable-" + name + ".json")
        overlay.write_text(json.dumps({"Replace": {str(ROOT / filename): str(changed)}}), encoding="utf-8")
        candidate = workspace / ("portable-" + name + ".test.exe")
        status, output = native.run(
            [*build, "-overlay=" + str(overlay), "-o", candidate, "./internal/windowsapp"],
            cwd=ROOT, env=captured, timeout=240)
        if status:
            raise ValueError("Portable preparation defect did not compile: " + name + "\n" + output[-8192:])
        status, output = native.run(
            [candidate, "-test.run=^" + test + "$", "-test.count=1", "-test.timeout=45s", "-test.v"],
            cwd=ROOT / "internal/windowsapp", env=captured, timeout=55)
        if (not status or witness not in output or "--- FAIL: " + test + " (" not in output or
                "--- SKIP:" in output or "panic: test timed out" in output or "DATA RACE" in output):
            raise ValueError("Portable preparation defect missed its intended boundary: " + name + "\n" + output[-16384:])
        print("Actual Portable preparation defect rejected: " + name, flush=True)
    return {"native_preparation_groups": len(REQUIRED), "unsafe_state_cases": len(NEGATIVE_CASES),
            "preparation_defects": len(mutations(native))}
