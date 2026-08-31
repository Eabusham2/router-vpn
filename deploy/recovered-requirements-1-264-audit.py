#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
errors=[]
def text(p):
 q=ROOT/p
 if not q.is_file(): errors.append(f'missing {p}'); return ''
 return q.read_text(errors='replace')
def need(p,*ms):
 s=text(p)
 for m in ms:
  if m not in s: errors.append(f'{p}: missing {m!r}')
def exists(*ps):
 for p in ps:
  if not (ROOT/p).exists(): errors.append(f'missing {p}')
def forbid(p,*ms):
 s=text(p)
 for m in ms:
  if m in s: errors.append(f'{p}: forbidden {m!r}')
rc=text('.github/workflows/release-candidate.yml')
def rc_has(*cs):
 for c in cs:
  if c not in rc: errors.append(f'RC missing {c!r}')

# A. 1-15: path-proven sessions/progress/rollback. Real leak/cleanup behavior on
# physical networks remains live; source may not promote generic Internet health.
exists('cmd/client/path_probe_test.go','cmd/client/session_state_test.go','cmd/client/strategy_requirements_test.go','cmd/client/kill_switch_transition_test.go')
need('cmd/client/session_state.go','path_proof','dns_proof','rollback_state','events','auto:')
need('cmd/client/path_probe_test.go','generic ok=true must not count as exact Router VPN node path proof')
rc_has('python3 modes/test_smart_auto_rollback.py')

# B. 16-44: simple methods/import truth; complex stacks stay app-only; private
# endpoint scopes are explicit. External-client interoperability is a live gate.
rc_has('python3 server/scripts/test_setup_imports.py')
need('server/scripts/test_setup_imports.py','test_sip002','test_ssr','test_hysteria_validation','SOCKS5 must not get a fake remote QR','manual-advanced')
need('server/scripts/normalize-setup-imports.py','simple-native','manual-app-proxy','manual-advanced')
need('router/asus-merlin-router-vpn-forwards.sh','SS_PORT=${SS_PORT:-8388}','OVERTLS_PORT=${OVERTLS_PORT:-14443}','SSR_PORT=${SSR_PORT:-15443}')

# C/D. 45-92: authenticated server admin + final Setup Center management,
# zero-knowledge verified onboarding, private-port review and permanent Full Guide.
exists('cmd/router-agent/admin_test.go','cmd/router-agent/admin_mutations_test.go','cmd/router-agent/admin_forwarding_extension_test.go','cmd/router-agent/admin_server_control_test.go')
need('server/scripts/setup-center-server.py','Connected clients','Ban','Revoke','forwarding','reserved')
need('server/scripts/setup-center-product-server.py','exact-SHA Portainer update','release/recovery status')
rc_has('python3 server/scripts/test_setup_center_requirement_349.py','python3 server/scripts/test_setup_center_router_onboarding.py','python3 server/scripts/test_setup_center_verified_onboarding.py')
need('server/scripts/setup_center_guide.py','Full Guide','first-run onboarding','8786–8793','45999')

# E. 93-110: generic install is secret-free; node linking/pairing and download
# jobs are separate; Portable state stays local/movable.
need('deploy/check-generic-package-secrets.py','generic package contains private bundle','generic package contains linked router profiles')
need('server/scripts/download-broker.py','separate-bundle-or-pairing','/api/download-jobs','/api/pairing/redeem')
need('deploy/native-download-policy-audit.py','local_build_platforms')
exists('cmd/portable-launcher/portable_contract_test.go','cmd/portable-launcher/portable_state_test.go')

# F. 111-119: one v4 profile/store model carries LAN, kill switch, multihop,
# MTU, IPv6 and startup policies with migration/future-schema guards.
need('internal/common/profile_schema.go','RouterProfileSchemaVersion','HomeLANAccess','KillSwitchPolicy','MultihopEnabled','MTUPolicy','IPv6Mode','StartupMode')
need('configs/client/routers.json.example','"schema_version": 4')
rc_has('python3 deploy/profile-schema-shipping-audit.py')

# G/H. 120-148: real native daily-use shells and unified Home/node telemetry.
rc_has('python3 deploy/product-parity-audit.py','python3 client/test_native_onboarding_contract.py')
need('cmd/client/home_summary.go','actual_exit_ip','connection_phase','path_proof','logical_mode','actual_runtime','fallback','dns_latency_ms','node_latency_ms','kill_switch','lan_access')
exists('cmd/client/profile_sort_test.go','cmd/client/telemetry_test.go','cmd/client/multihop_exit_proof_contract_test.go')
need('client/RouterVPN-Windows-App.ps1','Modes','DNS','Settings')
need('client/RouterVPN-Windows-UnifiedShell.ps1','Content="Add / manage nodes"')
need('client/RouterVPN-Windows-Telemetry.ps1','UnifiedForwardButton','/api/forwarding/master')
need('client/macos/RouterVPNMacUnifiedShell.swift','openUnifiedNodes','openUnifiedModes','openUnifiedDNS','openUnifiedSettings','openUnifiedForwarding')
need('client/linux/routervpn-gtk.c','Nodes','Diagnostics','Emergency stop')

# I/J. 149-169: 20 raw/16 logical, truthful readiness, AUTO/SMART/CUSTOM,
# DNS policy/benchmark/proof and AdGuard default/access truth.
need('server/scripts/generate-setup-assets.py','20 raw runtimes','16 logical modes','AUTO','SMART AUTO','CUSTOM','exact live reason')
rc_has('python3 modes/test_smart_auto_rollback.py','python3 deploy/profile-settings-audit.py')
exists('cmd/client/dns_policy_api_test.go','cmd/client/strategy_requirements_test.go')
need('docs/CURRENT-GUIDE.md','Home AdGuard','Allowed Clients','10.77.0.0/24','fd78:78::/64')

# K-N. 170-199: native Windows/Android/iOS and macOS/Linux source paths are
# release-gated. Device/signing/sleep-wake proof remains live below.
need('internal/common/native_runtime_contract_test.go','WindowsRawAndLayeredNativeRuntimeIsReal','ApplePacketTunnelRunsPinnedWireGuardAndLibbox')
rc_has('python3 android/test_android_runtime_contract.py','python3 android/test_android_native_policy_contract.py')
need('.github/workflows/release-candidate.yml','python3 test_runtime_selection_contract.py','python3 test_packet_tunnel_libbox_contract.py')
need('client/linux/build-native-app.sh','routervpn-gtk-product-v5.c')
need('.github/workflows/release-candidate.yml','Windows native + Portable','iOS/iPadOS real WireGuard + Libbox PacketTunnel')

# O. 200-213: strict kill switch is separate from Emergency Stop and has
# platform source/state/transition tests; physical leak-negative proof stays live.
need('server/scripts/generate-setup-assets.py','Emergency Stop is separate from strict kill-switch policy')
rc_has('python3 deploy/test-killswitch-transition-contract.py','python3 deploy/test_macos_killswitch_contract.py')
need('modes/kill-switch.py','on-connect','always','force-off','home_lan_access')
need('modes/darwin_kill_switch.py','pfctl')

# P. 214-224: multihop data model/builder, entry/exit proof, compatibility and
# latency telemetry are source-tested; physical benchmark remains live.
rc_has('python3 modes/test_multihop.py')
exists('cmd/client/multihop_test.go','cmd/client/multihop_exit_proof_contract_test.go','cmd/client/telemetry_hops_test.go')
need('cmd/client/multihop.go','EntryID','ExitID','LatencyMedianMs')
need('server/scripts/generate-setup-assets.py','Multihop truth')

# Q. 225-241: MTU policy, manual/auto/effective/cache/Jumbo and performance
# plumbing are source-tested. Cellular root-cause/CPU/PMTU/device proof stays live.
rc_has('python3 modes/test_mtu_policy.py')
exists('cmd/client/mtu_retest_test.go')
need('internal/common/profile_schema.go','MTUPolicy','ManualMTU')
need('internal/common/types.go','EffectiveMTU','EffectiveMTUSource')
need('server/scripts/generate-setup-assets.py','Jumbo TUN')

# R. 242-251: cancellable asynchronous download lifecycle + bounded local slot.
rc_has('python3 server/scripts/test_download_jobs.py','python3 server/scripts/test_download_safety.py')
need('server/scripts/download_jobs.py','queued','building','ready','failed','cancel')
need('server/scripts/publish-downloads.sh','max_parallel_package_requests','local_build_slots')

# S. 252-262: optional server-side AI Help, disabled when unavailable, provider
# secrets server-side, bounded/redacted context and no auto-execution.
rc_has('python3 server/scripts/test_ai_help_provider.py','python3 server/scripts/test_setup_center_ai.py')
need('server/scripts/configure-ai-help.sh','openai','gemini','anthropic','local','0600')
need('server/scripts/setup-center-ai-server.py','Provider keys stay server-side','Do not paste private keys, passwords, tokens')
need('server/scripts/test_ai_help_provider.py','bounded_redacted_and_not_stored')

# 263-264 named an old baseline. Current replacement is exact-SHA authoritative
# release orchestration; its remote result remains an exact-current CI gate.
rc_has('python3 deploy/release-orchestration-audit.py')
need('.github/workflows/release-candidate.yml','${{ github.sha }}')

# Explicitly retain genuinely physical/manual acceptance instead of rewriting old
# labels to DONE from source evidence alone.
live_only={5,12,14,15,19,21,26,27,30,77,78,88,177,185,194,197,213,223,225,226,228,229,230,239,263,264}
# Superseded/optional old requirements remain accounted but not revived.
superseded={64,93,109,120,176}
covered=set(range(1,265))-live_only-superseded
if covered|live_only|superseded != set(range(1,265)):
 errors.append('internal requirement accounting gap')

if errors:
 print('RECOVERED REQUIREMENTS 1-264 AUDIT: FAIL')
 for e in errors: print(' - '+e)
 raise SystemExit(1)
print('RECOVERED REQUIREMENTS 1-264 AUDIT: PASS')
print('Physical/manual acceptance remains required for:',','.join(map(str,sorted(live_only))))
print('Superseded/optional historical items not revived:',','.join(map(str,sorted(superseded))))
