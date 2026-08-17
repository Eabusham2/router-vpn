#!/usr/bin/env python3
from pathlib import Path

root = Path(__file__).resolve().parents[2]
app = Path(__file__).with_name("App")

runtime = app.joinpath("IOSDNSRuntimePolicy.swift").read_text()
for marker in [
    'modeIDs = ["home", "fastest", "custom", "dot", "doh", "doh3", "rescue"]',
    'type = "tls"', 'type = "https"', 'type = "h3"',
    'WireGuardKit can only enforce plain IP DNS',
    'routervpn-selected-dns', '"action": "hijack-dns"',
    'guard final != "direct"', 'fastestDNSHost', 'dnsResults',
    'Array(profiles.keys)', 'isSelfContainedLibbox',
    'routervpn-bootstrap-dns', 'server["domain_resolver"] = "routervpn-bootstrap-dns"',
    '"detour": detour', 'bootstrapHost(profile)', 'isLiteralIP(policy.host)',
]:
    assert marker in runtime, marker
assert runtime.index('"tag": "routervpn-bootstrap-dns"') < runtime.index('server["domain_resolver"] = "routervpn-bootstrap-dns"')

view = app.joinpath("IOSDNSPolicyView.swift").read_text()
for marker in [
    'Home AdGuard', 'Fastest measured', 'Custom UDP/TCP', 'DNS over TLS',
    'DNS over HTTPS', 'DNS over HTTP/3', 'Rescue',
    'Cloudflare Primary', 'Cloudflare Secondary', 'Google Primary', 'Google Secondary',
    'Quad9 Primary', 'Quad9 Secondary',
    'Retest over active VPN path', 'real DNS A queries', 'IOSDNSRTTProbe.query',
    'latencyMs', 'fastestDNSHost', 'fastestDNSLatencyMs',
]:
    assert marker in view, marker

selector = app.joinpath("IOSRuntimeSelection.swift").read_text()
assert 'IOSDNSRuntimePolicy.validate(selection: selection, in: bundle)' in selector

model = app.joinpath("RouterVPNModel.swift").read_text()
for marker in ['let prepared = try IOSDNSRuntimePolicy.patch(decoded)', 'current = try IOSDNSRuntimePolicy.patch(current)', 'guard saveRouter() else']:
    assert marker in model, marker

content = app.joinpath("ContentView.swift").read_text()
assert 'var body: some View { IOSDNSPolicyView() }' in content
assert 'current DNS/runtime policy' in content

# Keep Apple behavior aligned with the canonical server-generated sing-box DNS
# shape already validated against the pinned sing-box 1.13.12 runtime.
gen = (root / "server/scripts/generate-transports.sh").read_text()
for marker in ['"type":"udp"', '"detour":"proxy"', '"protocol":"dns","action":"hijack-dns"']:
    assert marker in gen, marker

print("iOS DNS policy/runtime/RTT/hostname-bootstrap contract OK")
