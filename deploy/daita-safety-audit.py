#!/usr/bin/env python3
"""Bounded DAITA-like cover traffic safety contract."""
from pathlib import Path
import re
ROOT=Path(__file__).resolve().parents[1]
def text(r): return (ROOT/r).read_text(encoding='utf-8')
client=text('cmd/client/main.go'); server=text('cmd/router-agent/main.go'); schema=text('internal/common/profile_schema.go'); router=text('router/asus-merlin-router-vpn-forwards.sh'); control=text('cmd/router-agent/admin_server_control_test.go'); reserved=text('cmd/router-agent/reserved_dynamic.go')
for m in ('DAITALikeMinRateKbps = 32','DAITALikeMaxRateKbps = 192'):
 assert m in schema, f'DAITA schema bound missing {m}'
for m in ('time.NewTicker(50 * time.Millisecond)','if n > 1200','n = 1200','bytesPerTick := rate * 1000 / 8 / 20'):
 assert m in client, f'DAITA client bound missing {m}'
for m in ('replyN := n','if replyN > 1200','replyN = 1200','pc.WriteTo(reply, addr)'):
 assert m in server, f'DAITA sink non-amplification missing {m}'
assert '45999' in reserved, 'DAITA private service is not reserved'
assert 'udp dport 45999 drop' in control, 'server-control WAN safety does not test DAITA drop'
assert '45999' in router and 'for PORT in' in router, 'ASUS verify does not protect private DAITA port'
# No Router-VPN WAN allowlist rule may target the private padding service.
for line in router.splitlines():
 if 'ensure_nat "$WAN"' in line: assert '45999' not in line, 'DAITA private service became WAN DNAT'
print('DAITA-like bounded/non-amplifying/private-service safety audit: PASS')
