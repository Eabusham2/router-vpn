#!/usr/bin/env python3
from pathlib import Path
here=Path(__file__).resolve()
p=here.with_name('prepare-libbox.sh').read_text()
workflow=(here.parents[2]/'.github/workflows/ios-libbox-engine.yml').read_text()
required=[
 'VERSION=1.14.1',
 'COMMIT=1ac1a339cb1223e9c70eae14c44411c75033c02d',
 'GO_TOOLCHAIN=go1.26.3',
 'GOMOBILE_VERSION=0.1.12',
 'go run ./cmd/internal/build_libbox -target apple -platform ios,iossimulator',
 'Libbox.xcframework',
 'libbox-LICENSE.txt',
 "('ios','')",
 "('ios','simulator')",
 "grep -Fq 'with_openvpn'",
 'LibboxRouterOpenVPNEndpoint', 'BRIDGE_SHA', 'BRIDGE_STAMP',
]
for marker in required:
    assert marker in p, marker
assert 'latest' not in p.lower()
assert "grep -nE 'PlatformInterface|CommandServer|StartOrReloadService|OpenTun|openTun|LibboxVersion|SetupOptions' \"$HEADER\" | head" not in workflow
assert 'SIGNATURES="$RUNNER_TEMP/routervpn-libbox-signatures.txt"' in workflow
assert 'head -n 240 "$SIGNATURES"' in workflow
print('Pinned Apple Libbox build contract OK')
