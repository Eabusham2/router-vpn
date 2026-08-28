#!/usr/bin/env python3
"""Reject pipefail-sensitive release evidence pipelines.

Release workflows often run bash with -o pipefail. A producer piped into an
early-exiting consumer such as grep -q/head can receive SIGPIPE and invert the
meaning of otherwise valid artifact evidence. Capture producer output first,
then inspect the complete snapshot.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

FILES = {
    "client": ".github/workflows/client-apps-ci.yml",
    "preflight": ".github/workflows/arm64-portainer-preflight.yml",
    "macos": ".github/workflows/macos-native-app.yml",
    "ios_libbox": ".github/workflows/ios-libbox-engine.yml",
}

body = {key: (ROOT / rel).read_text(encoding="utf-8") for key, rel in FILES.items()}

for label, source in body.items():
    for pattern, description in (
        (r"unzip\s+-Z1[^\n]*\|\s*grep\s+-(?:[^\n]*q)", "ZIP listing streamed into early grep"),
        (r"tar\s+-tzf[^\n]*\|\s*grep\s+-(?:[^\n]*q)", "TAR listing streamed into early grep"),
        (r"find\s+[^\n]*\|\s*grep\s+-q", "find existence proof streamed into grep -q"),
        (r"codesign\s+-d[^\n]*\|\s*grep\s+-E?q", "codesign evidence streamed into early grep"),
        (r"grep\s+[^\n]*\|\s*head\s+-n", "grep diagnostics streamed into head"),
    ):
        assert not re.search(pattern, source), f"{FILES[label]}: {description}"

client = body["client"]
assert 'unzip -Z1 "$archive" >"$list"' in client
assert 'tar -tzf "$archive" >"$list"' in client
assert "grep -q '/logical-modes.json$' \"$list\"" in client

preflight = body["preflight"]
assert 'test -z "$(find /opt/router-vpn/downloads -maxdepth 1 -type f -name "*.zip" -print -quit)"' in preflight

macos = body["macos"]
assert 'codesign -dv --verbose=2 "$app" >"$signature" 2>&1' in macos
assert "grep -Eq 'Signature=adhoc|Authority=Developer ID Application' \"$signature\"" in macos

ios = body["ios_libbox"]
assert 'SIGNATURES="$RUNNER_TEMP/routervpn-libbox-signatures.txt"' in ios
assert 'head -n 240 "$SIGNATURES"' in ios

print("release workflow evidence pipeline audit: OK")
