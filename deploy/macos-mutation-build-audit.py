#!/usr/bin/env python3
"""Keep macOS cross-file session-mutation proof aligned with the compiled module."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
build = (ROOT / "client/macos/build-native-app.sh").read_text(encoding="utf-8")
transform = (ROOT / "client/macos/macos-session-mutation-transform.py").read_text(encoding="utf-8")

errors: list[str] = []

# The product transform owns the shared mutationBusy(from:) definition. The
# unified transform must prove that it calls that shared guard, not pretend the
# definition is duplicated into the unified source.
if "'self.mutationBusy(from: statusObject)'" not in build:
    errors.append("macOS build no longer proves the unified mutation-guard call")
if "'func mutationBusy(from status:'" not in build:
    errors.append("macOS build no longer proves the product mutation-guard definition")
if "for marker in 'mutationBusy(from status:'" in build:
    errors.append("macOS build again requires the shared guard definition from the unified source")
if "macos-session-mutation-transform.py" not in build:
    errors.append("macOS build no longer applies the session mutation transformer")
for marker in ("product", "unified", "PAIRS", "session-mutation"):
    if marker not in transform:
        errors.append(f"macOS session mutation transformer lost marker {marker!r}")

if errors:
    print("macOS mutation build audit: FAIL", file=sys.stderr)
    for error in errors:
        print(f" - {error}", file=sys.stderr)
    raise SystemExit(1)

print("macOS mutation build audit: PASS")
