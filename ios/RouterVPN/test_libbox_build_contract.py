#!/usr/bin/env python3
from pathlib import Path
p=Path(__file__).with_name('prepare-libbox.sh').read_text()
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
print('Pinned Apple Libbox build contract OK')
