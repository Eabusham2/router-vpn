#!/usr/bin/env python3
from pathlib import Path
here=Path(__file__).resolve()
p=here.with_name('prepare-libbox.sh').read_text()
workflow=(here.parents[2]/'.github/workflows/ios-libbox-engine.yml').read_text()
required=[
 'VERSION=1.13.12',
 'COMMIT=1086ab2563320e0da0c23b3a491d8dfa0939dff4',
 'GO_TOOLCHAIN=go1.26.3',
 'GOMOBILE_VERSION=0.1.12',
 'go run ./cmd/internal/build_libbox -target apple -platform ios,iossimulator',
 'Libbox.xcframework',
 'libbox-LICENSE.txt',
 "('ios','')",
 "('ios','simulator')",
 "if grep -Fq 'with_openvpn'",
]
for marker in required:
    assert marker in p, marker
assert 'latest' not in p.lower()
assert "grep -nE 'PlatformInterface|CommandServer|StartOrReloadService|OpenTun|openTun|LibboxVersion|SetupOptions' \"$HEADER\" | head" not in workflow
assert 'SIGNATURES="$RUNNER_TEMP/routervpn-libbox-signatures.txt"' in workflow
assert 'head -n 240 "$SIGNATURES"' in workflow
print('Pinned Apple Libbox build contract OK')
