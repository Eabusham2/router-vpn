#!/usr/bin/env python3
"""Stable full Router VPN product/security/native capability audit."""
from __future__ import annotations
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1];errors:list[str]=[]
def read(rel:str)->str:
 p=ROOT/rel
 if not p.is_file():errors.append(f"missing required file: {rel}");return""
 return p.read_text(encoding="utf-8",errors="replace")
def need(rel:str,*parts:str)->None:
 text=read(rel)
 for part in parts:
  if part not in text:errors.append(f"{rel}: missing contract marker {part!r}")
def no(rel:str,*parts:str)->None:
 text=read(rel)
 for part in parts:
  if part in text:errors.append(f"{rel}: stale/forbidden marker {part!r}")
need("cmd/client/main.go","selected-router path proof","PathProbeURL","func (a *app) testHealth","path proof endpoint did not return the Router VPN proof response");need("cmd/client/trust_init.go","defaultPrivatePathProbeURL","trustedPathProbeURL","legacyPublicHealthURL");legacy_public_health="connectivitycheck.gstatic.com/generate_204"
for rel in("cmd/client/main.go","cmd/portable-launcher/main.go","modes/orchestrate.py","modes/run-all.sh"):
 if legacy_public_health in read(rel):errors.append(f"public Internet health proof remains in runtime: {rel}")
need("modes/orchestrate.py","DEFAULT_PATH_PROBE_URL","path_probe_url","selected router path proof URL must be private/local");need("modes/run-all.sh","http://10.77.0.1:8787/health","ipaddress.ip_address","b'\"ok\"'");need("cmd/client/session_state.go","connectionSession","typedSessionError","PathProof","RollbackState","DNSProof","sessionStatus","sessionEvents");need("cmd/client/extras.go",'"/api/session"','"/api/session/events"');need("cmd/client/session_state_test.go","path_proof_failed","DNS must not be fabricated as proven")
need("internal/common/types.go","RouterProfileSchemaVersion","RouterProfileStoreVersion","KillSwitchPolicy","MTUPolicy","DiagnosticsEnabled","PathProbeURL");need("internal/common/profile_schema.go","NormalizeRouterProfile","NormalizeRouterProfileStore","HomeLANAccess","newer than supported schema");need("internal/common/onboarding.go","OnboardingSchemaVersion","LastReopenedAt",'"connection-validation"')
need("deploy/check-generic-package-secrets.py","generic package contains private bundle","generic package contains linked router profiles","package does not ship LICENSE");need("server/scripts/build-download-on-demand.py","safe_extract_zip","safe_extract_tar","assert_generic_tree","generic package contains linked router profiles","explicit private node-link bundle");publisher=read("server/scripts/publish-downloads.sh")
for bad in('copy_static "$BUNDLE/router-vpn-bundle.json"','copy_static "$BUNDLE/CREDENTIALS.txt"','copy_public "$BUNDLE/router-vpn-bundle.json"','copy_public "$BUNDLE/CREDENTIALS.txt"'):
 if bad in publisher:errors.append(f"private node material is statically published: {bad}")
need("server/scripts/publish-downloads.sh",'"$OUT"/router-vpn-bundle.json','"$OUT"/CREDENTIALS.txt',"server_cache");need("server/scripts/build-download-on-demand.py","MAX_UNPACKED","archive symlink is not allowed","unsafe archive path");need("server/scripts/download-broker.py","MAX_COMPRESSION_RATIO","GitHub artifact contains a symlink","cleanup_stale_temp");need("server/scripts/download_jobs.py","JOB_TTL_SECONDS","delivery-interrupted","cancel_requested","_cleanup_dir");need("server/scripts/test_download_jobs.py","interrupted delivery temp directory was not removed")
need("server/scripts/import_payloads.py","sip002_uri","parse_sip002","ssr_uri","parse_ssr","validate_hysteria2_uri");need("server/scripts/normalize-setup-imports.py",'"sip002"','"ssr-uri"','"qrSupported"');need("server/scripts/test_setup_imports.py","SIP002","SSR","Hysteria");need("server/scripts/ensure-setup-auth.py","setup-center.token","0o600","Never print the token");need("server/scripts/pairing.py","one_time","lan_source","MAX_FAILURES_PER_MINUTE","invalid or expired pairing code");need("server/scripts/download-broker.py","hmac.compare_digest","HttpOnly; SameSite=Strict","/api/pairing/redeem","apple_local_network_permission_required");need("server/scripts/test_broker_security.py","status == 401","status == 403","X-Router-VPN-Pairing")
need("cmd/router-agent/main.go","ConstantTimeCompare","source is not a tunnel peer","validateForward","allowedRanges","formatDNAT");need("cmd/router-agent/main_test.go","missing bearer token was authorized","Protected DMZ","IPv6")
for wf in(ROOT/".github"/"workflows").glob("*.yml"):
 text=wf.read_text(encoding="utf-8",errors="ignore")
 if"--method DELETE"in text and"git/refs/heads"in text:errors.append(f"workflow blindly deletes branches: {wf.relative_to(ROOT)}")
need(".github/workflows/keep-main-only.yml","Unexpected non-main branch","exit 1");need("cmd/portable-launcher/main.go","Portable clean-exit requires","browserCmd.Wait","stopPortableController",'localURL+"api/emergency-stop"');no("cmd/portable-launcher/main.go","url.dll,FileProtocolHandler",legacy_public_health)
need("cmd/client/logical_ui.js","Connection validation","/api/session","Selected-node path proof","DNS proof","policy intent","live enforcement stays unavailable until its runtime adapter passes end-to-end tests","The Modes page shows the 16 logical modes");no("cmd/client/logical_ui.js","PortableApps 3.9")
need("android/app/build.gradle","com.wireguard.android:tunnel:1.0.20260102");need("android/gradle.properties","android.useAndroidX=true");need("android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java","GoBackend","State.UP","Config.parse",'optJSONObject("wg")');need("android/app/src/main/java/com/eabusham/routervpn/MainActivity.java","VpnService.prepare(this)","does not fake a live all-mode VPN connection","automatic reconnect are still unavailable")
need("client/native-wireguard-windows.ps1","WireGuard\\wireguard.exe","/installtunnelservice","/uninstalltunnelservice","Is-Administrator","Unsafe WireGuard profile path","will not fake native readiness through WSL");need("client/native-windows-mode.ps1","sing-box.exe","xray.exe","hysteria2","shadowsocks","reality-vision","reality-pq-vision","split","max","Patch-SingBox","Get-SelectedProfile","fastest_dns_host","hijack-dns","HOMEVPN_JUMBO","9000","Write-Utf8NoBom","Native Windows TUN modes require an elevated Router VPN process");need("client/Setup-Windows-Runtime.ps1","1.13.12","26.7.11","SHA-256 mismatch","e93fc531134eb1beb4efa3c74990a24e48456098a31c03b60d5ddf17f223cf98","af801b62c4d41d248d3db8016d4c6e2a7ccfb7ed443e3738aeb6f9e062321512");need("client/Prepare-Windows-Mode-Catalog-v2.ps1","$mode.id -eq 'wg'","native-wireguard-windows.ps1","native-windows-mode.ps1","no native Windows adapter yet","Write-Utf8NoBom");need("cmd/client/windows_runtime.go","Prepare-Windows-Mode-Catalog-v2.ps1","sing-box/Xray TUN adapter");need("cmd/portable-launcher/main.go",'modeID=="wg"',"native-wireguard-windows.ps1","native-windows-mode.ps1","nativeLayeredWindowsModes","no native Windows adapter yet")
for rel in("client/native-windows-mode.ps1","client/Setup-Windows-Runtime.ps1","client/Prepare-Windows-Mode-Catalog-v2.ps1","cmd/client/windows_runtime.go","cmd/portable-launcher/main.go","deploy/package-builds.sh"):
 text=read(rel).lower()
 if"wsl.exe"in text or"requires wsl2"in text:errors.append(f"current Windows runtime still depends on WSL: {rel}")
need("ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift","Link AmneziaWGKit/Xray engine before signing this target.","completionHandler(error)");no("ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift","completionHandler(nil)");need("ios/RouterVPN/project.yml","NSLocalNetworkUsageDescription","com.apple.networkextension.packet-tunnel")
for line in read("server/portainer-current.yaml").splitlines():
 s=line.strip()
 if s.startswith("image:"):
  ref=s.split(":",1)[1].strip()
  if ref.endswith(":latest")or ref.endswith(":main"):errors.append(f"floating production image tag: {ref}")
for rel in("cmd/client/windows_runtime.go","cmd/portable-launcher/main.go","deploy/package-builds.sh","client/Setup-Windows-Runtime.ps1"):
 text=read(rel)
 if"Prepare-Windows-Mode-Catalog.ps1"in text and"Prepare-Windows-Mode-Catalog-v2.ps1"not in text:errors.append(f"{rel}: selects retired Windows catalog v1")
if errors:
 print("ROUTER VPN FULL AUDIT: FAIL",file=sys.stderr)
 for err in errors:print(" - "+err,file=sys.stderr)
 raise SystemExit(1)
print("ROUTER VPN FULL AUDIT: PASS")
