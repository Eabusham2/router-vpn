#!/usr/bin/env python3
from pathlib import Path
import json

ROOT=Path(__file__).resolve().parents[1]
errors=[]

def text(rel):
    p=ROOT/rel
    if not p.is_file(): errors.append(f'missing {rel}'); return ''
    return p.read_text(encoding='utf-8',errors='replace')

def need(rel,*markers):
    body=text(rel)
    for m in markers:
        if m not in body: errors.append(f'{rel}: missing {m!r}')

def forbid(rel,*markers):
    body=text(rel).lower()
    for m in markers:
        if m.lower() in body: errors.append(f'{rel}: forbidden {m!r}')

# A20-1/2: daily native product stays map/globe-first and distinct from Setup Center admin.
need('server/scripts/setup-center-server.py','Server administration','Connected clients','Persistent port forwarding')
need('server/scripts/setup_center_ux_patch.py','Download for this device','getHighEntropyValues','CPU architecture is not safely exposed','will not guess the wrong architecture')
need('client/RouterVPN-Windows-UnifiedShell.ps1','Fastest','Connect','Multihop','Settings','Mode','DNS')
need('client/macos/RouterVPNMacUnifiedShell.swift','Fastest','Connect','Multihop','Settings','Mode','DNS')
need('client/linux/routervpn-unified-shell-v8.inc','Fastest','Connect','Multihop','Settings','Mode','DNS')
need('android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java','Fastest','Connect','Kill','Forward','Multihop','Settings')
need('ios/RouterVPN/App/IOSUnifiedProductView.swift','map-first','Fastest','Connect','Multihop','Settings','Mode','DNS')

# A20-3/4: SMART/AUTO/CUSTOM + default IPv6 On / Auto MTU / SMART AUTO + bounded filters.
need('modes/test_smart_auto_rollback.py','last-good rollback behavior','restore','AUTO')
need('internal/common/profile_schema.go','p.StartupMode = "smart-auto"','p.IPv6Mode = "on"','p.MTUPolicy = "auto"')
need('internal/common/types.go','RouterProfileSchemaVersion = 4','RouterProfileStoreVersion  = 4')
need('cmd/client/profile_settings.go','AutoRequireEncrypted','AutoRequireObfuscation')
need('modes/test_mtu_policy.py','auto','manual','retest')
need('server/scripts/generate-setup-assets.py','Home AdGuard','Fastest measured','DoT','DoH','DoH3','Rescue')

# A20-5: real external node model includes all supported families; mobile OpenVPN remains fail closed.
need('internal/common/profile_schema.go','case "wireguard"','case "openvpn"','case "shadowsocks"','case "socks5"','case "http-connect"','case "https-connect"','case "hysteria2"')
need('android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitStore.java','http-connect','https-connect','hysteria2','openvpn')
need('ios/RouterVPN/PacketTunnel/RouterVPNExternalExit.swift','OpenVPN external exits are unavailable on iOS')

# A20-6/7: role-colored real-coordinate map and real throughput are separate from RTT/MTU.
need('ios/RouterVPN/App/IOSUnifiedProductView.swift','real coordinates','animated packet','path','Location')
need('android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java','real temporary proven hop-1 tunnel','routed hop Mbps')
need('android/app/src/main/java/com/eabusham/routervpn/RouterVpnNodeMapView.java','LOCATE ME','Only real coordinates','no first-launch prompt')
need('cmd/router-agent/benchmark.go','/api/benchmark/download','/api/benchmark/upload','benchmarkDefaultBytes int64 = 8 << 20','benchmarkMaxBytes     int64 = 16 << 20','no-store, no-transform','authenticated tunnel-peer private throughput sink')
need('cmd/client/telemetry.go','/api/connection/speed-test','/api/multihop/live-latency','does not fake an entry-to-exit hop measurement from arithmetic')
need('cmd/client/telemetry_hops.go','/api/profile/speed-test','/api/multihop/speed-test','not derived from RTT or another hop','active multihop graph identity is unavailable')

# A20-8: Android via-entry candidate measurement owns a temporary proven path and tears it down.
need('android/test_android_via_entry_latency_contract.py','AndroidVpnMutationGuard.isBusy(context)','Temporary entry did not fully disconnect; candidate results discarded.','before candidate RTT measurement','after candidate RTT measurement','unavailable')

# A20-9: forwarding master is narrow/private and does not export Setup Center admin credentials.
need('cmd/router-agent/client_forwarding_master.go','/api/forwarding/master','Setup Center admin token never','authenticated tunnel peers','loopback-only')
need('android/app/src/main/java/com/eabusham/routervpn/AndroidForwardingMaster.java','/api/forwarding/master','VPN session/path changed')
need('ios/RouterVPN/App/IOSUnifiedProductView.swift','keep this unavailable rather than showing a fake switch')

# A20-10/11: schema-v4 whole-connection profiles + transactional/frozen runtime identity.
example=json.loads(text('configs/client/routers.json.example') or '{}')
if example.get('schema_version') != 4: errors.append('routers.json.example is not schema v4')
need('cmd/client/profile_id_safety_test.go','profile')
need('android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java','SCHEMA_VERSION','add','update','delete')
need('ios/RouterVPN/App/IOSConnectionProfilesView.swift','Add','Load','Update','Delete')
need('android/app/src/main/java/com/eabusham/routervpn/AndroidRuntimeRegistry.java','NativeWireGuardController','NativeAmneziaWGController','AndroidModeOrchestrator','AndroidMultihopRuntime')
need('android/test_android_session_identity_contract.py','session','path','node')

# A20-12/13: native shipping truth and exact identity proof.
for rel in ('client/Prepare-Windows-Mode-Catalog.ps1','client/RouterVPN-Windows-Product.ps1'):
    if (ROOT/rel).exists(): errors.append(f'retired Windows payload revived: {rel}')
need('deploy/check-generic-package-secrets.py','generic package contains private bundle','generic package contains linked router profiles')
need('cmd/client/session_state.go','path_proof','exit_ip')
need('internal/common/profile_schema.go','external node cannot contain Router VPN proof/admin credentials')

# A20-14: private home-network invariants and AdGuard blank-list semantics.
need('docs/CURRENT-GUIDE.md','192.168.50.133','10.77.0.0/24','10.78.0.0/24','fd77:77::/64','fd78:78::/64','blank Allowed Clients list already means unrestricted')
need('README.md','8786-8793','45999','14444')

# A20-16/17: exact-SHA artifact safety, image-only production, and do-not-regress boundaries.
need('server/scripts/download-broker.py','ROUTER_VPN_GITHUB_SHA')
need('deploy/native-download-policy-audit.py','same-SHA')
need('server/scripts/publish-downloads.sh','github_exact_sha_required')
compose=text('server/portainer-current.yaml')
if '\nbuild:' in compose or '\n    build:' in compose: errors.append('production compose revived build: path')
for rel in ('README.md','docs/CURRENT-GUIDE.md','docs/INSTALL-PORTAINER.md'):
    need(rel,'image-only')
need('router/asus-merlin-router-vpn-forwards.sh','--comment "$TAG"','45999','verify')
forbid('client/RouterVPN-Windows-App.ps1','wsl.exe','portableapps')

if errors:
    print('LATEST A20 PRODUCT/SHIPPING CONTRACT: FAIL')
    for e in errors: print(' - '+e)
    raise SystemExit(1)
print('LATEST A20 PRODUCT/SHIPPING CONTRACT: PASS')
