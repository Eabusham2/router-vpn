#!/usr/bin/env python3
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
errors=[]

def body(rel):
    p=ROOT/rel
    if not p.is_file():
        errors.append(f'missing {rel}')
        return ''
    return p.read_text(encoding='utf-8',errors='replace')

def need(rel,*markers):
    b=body(rel)
    for m in markers:
        if m not in b: errors.append(f'{rel}: missing {m!r}')

def forbid(rel,*markers):
    b=body(rel)
    for m in markers:
        if m in b: errors.append(f'{rel}: forbidden {m!r}')

# Protected DMZ: authenticated admin-only, tunnel-subnet target, reserved ports and
# explicit rules win; broad peer API must never enable it.
need('cmd/router-agent/admin_forwarding_extension.go','protected_dmz','reserved_ports','otherwise-unused unreserved WAN ports','Protected DMZ target must be inside a Router VPN tunnel subnet')
need('cmd/router-agent/main.go','Protected DMZ is an authenticated Setup Center admin action','Explicit forwarding is more specific than broad Protected DMZ')
need('cmd/router-agent/admin_forwarding_extension_test.go','Protected DMZ ranges unexpectedly include blocked/explicit port','Protected DMZ must emit tagged nft rules')

# LAN Off is a real forward-path policy rather than a UI-only toggle.
need('cmd/router-agent/admin_mutations.go','LANAccess','lan_access_write')
need('server/scripts/setup-center-server.py','Home LAN access','Tunnel-to-home-LAN forwarding is blocked by policy.')
need('server/scripts/setup_center_guide.py','LAN Off blocks ordinary home-LAN reachability')

# Apple LAN linking permission is carried into the generated native target.
need('ios/RouterVPN/project.yml','INFOPLIST_KEY_NSLocalNetworkUsageDescription','INFOPLIST_KEY_NSAppTransportSecurity_NSAllowsLocalNetworking: YES')

# MAX is fail-closed; ALL tries only validated MAX TLS/QUIC branches and fails
# rather than claiming a degraded cleartext connection.
need('modes/run-max.sh','MAX profile is not validated with PQ base','MAX component exited; stopping')
need('modes/run-all.sh','ALL trying $candidate','ALL connected with $candidate','ALL could not establish any validated MAX TLS or MAX QUIC branch.')
need('deploy/historical-regression-audit.py','MAX must fail closed','ALL must continue through valid MAX branches')

# Direct public IP must work without introducing a mandatory DDNS dependency.
need('server/scripts/setup_center_guide.py','Direct public IP works.','DDNS is optional.','endpoint can stay blank')
need('server/scripts/generate-setup-assets.py','ENDPOINT can stay blank for automatic public IPv4 detection','Leave ENDPOINT blank for automatic detection')
need('server/portainer-current.yaml','ENDPOINT: ${ENDPOINT:-}')

# Endpoint synchronization is narrowly owned: only the home Router-VPN profile
# and raw WireGuard-family endpoints, never unrelated/external linked nodes.
need('server/finalize/sync-endpoint.py','owns only direct Router VPN WireGuard-family endpoint fields','Other linked Router VPN nodes and all external nodes','owned home Router VPN profile only')
need('server/finalize/test_sync_endpoint.py','external','endpoint')

# Upgrades preserve private state/credentials and rollback failed exact-SHA
# server updates rather than replacing user state with generic defaults.
need('client/install-windows.ps1','Private linked-node state is install-once data','Existing linked Router VPN nodes were preserved')
need('server/scripts/test_preserve_generated_state.py','Preserved generated state tests: OK')
need('server/scripts/setup_center_release_status.py','existing stack environment values are preserved')
need('server/scripts/setup_center_update.py','automatically restore the prior stack')

# Dependencies must be pinned; floating latest/main download sources are not an
# acceptable production/native artifact mechanism.
need('deploy/native-download-policy-audit.py','VERSION=v26.7.11','AWG_GO_COMMIT=0527dfa47639714dd8f5c9ffbd9d40d19083f0ba','SSR_COMMIT=227127c4bc5a6555e0556693d084c96860e75b5e')
for rel in ('server/scripts/download-broker.py','client/install-xray.sh'):
    forbid(rel,'/releases/latest','refs/heads/main')

# Public app packages are generic/secret-free, ship LICENSE, and node linking is
# separate from installation. Mobile/desktop packaging must preserve this line.
need('deploy/check-generic-package-secrets.py','generic package contains private bundle','generic package contains linked router profiles','package does not ship LICENSE')
need('deploy/package-builds.sh','contains no linked home/server node; link nodes separately','MIT-licensed open-source software')
need('server/scripts/build-download-on-demand.py','GENERIC and secret-free','linking a home/server node are separate operations','LICENSE')
need('README.md','Install the generic Router VPN app for the device once, then link/import','Private node data is not baked into public generic installers')

if errors:
    print('BINDING EDGE REQUIREMENTS: FAIL',file=sys.stderr)
    for e in errors: print(' - '+e,file=sys.stderr)
    raise SystemExit(1)
print('BINDING EDGE REQUIREMENTS: PASS')
