#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parent
project=(root/'project.yml').read_text()
probe=(root/'PacketTunnel/LibboxCompileProbe.swift').read_text()
for marker in [
    '- framework: .deps/Libbox.xcframework',
    'embed: false',
    '"$SRCROOT/prepare-libbox.sh"',
    '1.14.1+1ac1a339cb1223e9c70eae14c44411c75033c02d+go1.26.3+0.1.12+ios,iossimulator',
]:
    assert marker in project, marker
for marker in ['import Libbox','LibboxVersion()','expectedVersion = "1.14.1"']:
    assert marker in probe, marker
print('Router VPN PacketTunnel Libbox link contract OK')
