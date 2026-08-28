#!/usr/bin/env python3
from pathlib import Path
import json

ROOT=Path(__file__).resolve().parents[1]
errors=[]
def text(p):
    q=ROOT/p
    if not q.is_file(): errors.append(f'missing {p}'); return ''
    return q.read_text(errors='replace')
def need(p,*markers):
    s=text(p)
    for m in markers:
        if m not in s: errors.append(f'{p}: missing {m!r}')
def forbid(p,*markers):
    s=text(p)
    for m in markers:
        if m in s: errors.append(f'{p}: forbidden {m!r}')
def exists(*paths):
    for p in paths:
        if not (ROOT/p).exists(): errors.append(f'missing {p}')

rc=text('.github/workflows/release-candidate.yml')
def rc_has(*cmds):
    for c in cmds:
        if c not in rc: errors.append(f'release candidate missing {c!r}')

# 312-319: distinct app + Setup Center onboarding, truthful lanes, persistent rerun,
# direct packages, and safe ASUS onboarding.
need('client/macos/RouterVPNMacApp.swift','Install once; add routers as data','Setup Center Full Guide')
need('client/linux/build-native-app.sh','router-vpn-bundle.json','AUTO','AmneziaWG','kill-switch','Run Tutorial')
need('server/scripts/setup_center_verified_onboarding.py','Simple / native','full VPN or proxy-only')
need('server/scripts/generate-setup-assets.py','WIZKEY','localStorage.setItem(WIZKEY','router-vpn-ios.ipa','router-vpn-android.apk')
need('server/scripts/setup_center_verified_onboarding.py','Run onboarding again','routerVpnRunOnboardingAgain')
need('server/scripts/test_setup_center_router_onboarding.py','routerUser','Safe manual ASUS-GUI fallback','Never use DMZ/Exposed Host')
rc_has('python3 server/scripts/test_setup_center_router_onboarding.py')

# 320-329: native launch surfaces, broad build family, Windows Portable behavior,
# short artifact retention, archive safety, ID safety, cancellation cleanup.
need('deploy/build-client.sh','freebsd/amd64','openbsd/arm64','netbsd/arm64','dragonfly/amd64','illumos/amd64')
need('cmd/portable-launcher/main.go','HOMEVPN_PORTABLE=1','nativeCmd.Wait()','stopPortableController(cmd)','filepath.Join(dataDir, "state.json")','filepath.Join(dataDir, "routers.json")')
forbid('cmd/portable-launcher/main.go','wsl.exe','bash.exe','msedge.exe','chrome.exe','--app=')
exists('cmd/portable-launcher/portable_contract_test.go','cmd/portable-launcher/portable_state_test.go')
need('.github/workflows/release-candidate.yml','retention-days: 1','Relocated Portable self-test failed','controller remained alive')
rc_has('python3 server/scripts/test_download_safety.py')
need('modes/test_profile_id_safety.py','%252e%252e')
need('cmd/client/main.go','len(id) > 64')
need('server/scripts/test_download_jobs.py','cancel')

# 330-339: forwarding semantics/auth, Protected DMZ, LAN-off, pairing privacy,
# sorting/multihop latency, disconnect policy, and truthful macOS distribution.
need('server/scripts/setup_center_guide.py','TCP/UDP/both','ranges','IPv4/IPv6 targets','Proxy-only modes cannot pretend to provide DNAT')
need('cmd/router-agent/admin_forwarding_extension.go','protected_dmz','reserved_ports','Protected DMZ covers only otherwise-unused unreserved WAN ports')
exists('cmd/router-agent/client_forwarding_master_test.go','cmd/router-agent/admin_mutations_test.go')
need('server/scripts/download-broker.py','lan_only','one_time','apple_local_network_permission_required','private_node_material_not_discoverable_without_pairing')
exists('cmd/client/profile_sort_test.go','cmd/client/multihop_test.go','cmd/client/kill_switch_transition_test.go')
need('server/scripts/setup_center_guide.py','Privacy & Security → Open Anyway','Never globally disable Gatekeeper')
need('ios/README.md','unsigned','re-sign')

# 340-347: fail-closed MAX/ALL, bounded private DAITA, endpoint ownership,
# direct-IP endpoint detection, upgrade preservation, pins, historical regressions.
need('modes/run-max.sh','MAX outer chain failed to start')
need('modes/run-all.sh','max-tls-awg max-tls-wg max-quic-awg max-quic-wg','ALL could not establish any validated MAX TLS or MAX QUIC branch')
rc_has('python3 modes/test_smart_auto_rollback.py','python3 deploy/daita-safety-audit.py','python3 server/finalize/test_sync_endpoint.py')
need('server/finalize/current-entrypoint.sh','https://icanhazip.com','https://api.ipify.org')
forbid('server/finalize/current-entrypoint.sh','ddns','DDNS')
rc_has('python3 deploy/release-orchestration-audit.py','python3 deploy/historical-regression-audit.py')
need('deploy/release-orchestration-audit.py','server/scripts/test_preserve_generated_state.py')
need('deploy/native-download-policy-audit.py','VERSION=v26.7.11','AWG_GO_COMMIT','SSR_COMMIT')

# 348-356: LICENSE in packages; composed management UI; branding/full guide;
# secret-free generic app separation; authenticated mutations; mode table; explicit regressions.
need('deploy/package-builds.sh','cp "$ROOT/LICENSE" "$dir/LICENSE"')
rc_has('python3 server/scripts/test_setup_center_requirement_349.py')
need('server/scripts/generate-setup-assets.py','<link rel="icon"','router-vpn-client-bundle.zip')
need('server/scripts/setup_center_guide.py','Full Guide','rerun from step 1')
need('server/scripts/publish-downloads.sh','node_linking','separate-bundle-or-pairing')
need('deploy/private-bundle-boundary-audit.py','setup_token','admin_token')
need('server/scripts/setup-center-product-server.py','_require_auth()','/api/admin/server-control','/api/admin/forwarding-extension')
need('server/scripts/generate-setup-assets.py','ping_min_ms','traffic_min_pct','speed_loss_min_pct','why')
rc_has('python3 deploy/historical-regression-audit.py')
need('deploy/historical-regression-audit.py','MAX','ALL')

# Physical/off-LAN claims remain explicit live acceptance gates. Source/CI may prove
# plumbing and truthful limitations, but must not convert these into fake DONE states.
live_only=[314,331,338,339]
if errors:
    print('RECOVERED ADDENDUM 312-356 AUDIT: FAIL')
    for e in errors: print(' - '+e)
    raise SystemExit(1)
print('RECOVERED ADDENDUM 312-356 AUDIT: PASS')
print('Live acceptance still required for off-LAN/platform distribution aspects:',','.join(map(str,live_only)))
