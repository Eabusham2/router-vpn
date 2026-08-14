#!/usr/bin/env python3
from pathlib import Path
root=Path(__file__).resolve().parent
project=(root/'project.yml').read_text()
probe=(root/'PacketTunnel/LibboxCompileProbe.swift').read_text()
for marker in [
    '- framework: .deps/Libbox.xcframework',
    'embed: false',
    '"$SRCROOT/prepare-libbox.sh"',
    '1.13.12+1086ab2563320e0da0c23b3a491d8dfa0939dff4+go1.26.3+0.1.12+ios,iossimulator',
]:
    assert marker in project, marker
for marker in ['import Libbox','LibboxVersion()','expectedVersion = "1.13.12"']:
    assert marker in probe, marker
print('Router VPN PacketTunnel Libbox link contract OK')
