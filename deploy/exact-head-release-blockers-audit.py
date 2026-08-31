#!/usr/bin/env python3
"""Regression gate for exact-head failures previously exposed only by native CI.

These checks inspect the real shipping source. They preserve Android's frozen
multihop identity contract, Android-compatible JSON iteration, and an executable
profile-schema shipping audit on every release generation.
"""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


main = read("android/app/src/main/java/com/eabusham/routervpn/MainActivity.java")
assert "multihop.connect(entry.file, exit.file" not in main, (
    "Android multihop regressed to passing profile files instead of frozen Node identities"
)
assert "multihop.connect(entry, exit" in main, (
    "Android multihop shipping source no longer proves frozen entry/exit Node identity"
)

profiles = read(
    "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java"
)
assert "JSONObject.getNames(" not in profiles, (
    "Android profile validation uses a non-portable JSONObject.getNames API"
)
assert ".keys()" in profiles, (
    "Android profile policy validation no longer iterates every persisted policy key"
)

profile_audit = ROOT / "deploy/profile-schema-shipping-audit.py"
proc = subprocess.run(
    [sys.executable, str(profile_audit)],
    cwd=ROOT,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    timeout=120,
)
assert proc.returncode == 0, (
    "profile schema shipping audit is not executable on this exact source generation:\n"
    + proc.stdout[-8000:]
)

print("exact-head native/release blocker regression audit: PASS")
