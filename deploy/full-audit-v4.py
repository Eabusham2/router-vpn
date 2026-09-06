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

# Connection truth: success is exact selected-node/private-path proof, not generic Internet reachability or ok=true.
need("cmd/client/main.go","selected-router path proof","PathProbeURL","func (a *app) testHealth","validateSelectedNodeProof(p, body)","NodeProofID","newStagedBundle(","nodeProofIDFromWGConfig(wgData)","p.NodeProofID = derivedNodeID")
need("cmd/client/node_proof.go","router-vpn-private-agent-v1","router-vpn-node-proof-v1\\n","generated","wg.conf","p.NodeProofID","proof.NodeID != expected","proof.Proof != desktopNodeProofKind","selected router has no saved WireGuard identity profile")
need("cmd/client/node_proof_test.go","ok-only","wrong-node","wrong-kind","not-ok","persisted proof mismatch accepted")
need("cmd/client/trust_init.go","defaultPrivatePathProbeURL","trustedPathProbeURL","legacyPublicHealthURL")
legacy_public_health="connectivitycheck.gstatic.com/generate_204"
for rel in("cmd/client/main.go","cmd/portable-launcher/main.go","modes/orchestrate.py","modes/run-all.sh"):
 if legacy_public_health in read(rel):errors.append(f"public Internet health proof remains in runtime: {rel}")
need("modes/orchestrate.py","DEFAULT_PATH_PROBE_URL","path_probe_url","selected router path proof URL must be private/local")
need("modes/run-all.sh","http://10.77.0.1:8787/health","ipaddress.ip_address","b'\"ok\"'")
need("cmd/client/session_state.go","connectionSession","typedSessionError","PathProof","RollbackState","DNSProof","sessionStatus","sessionEvents")
need("cmd/client/extras.go",'"/api/session"','"/api/session/events"',"activeAsyncMeasurementProfile","target := strings.TrimSpace(st.RouterID)","refusing to substitute the mutable selected node","validateAsyncMeasurementProfile")
need("cmd/client/session_state_test.go","path_proof_failed","DNS must not be fabricated as proven")

# Versioned profile/onboarding state.
need("internal/common/types.go","RouterProfileSchemaVersion","RouterProfileStoreVersion","NodeProofID","KillSwitchPolicy","MTUPolicy","DiagnosticsEnabled","PathProbeURL","MultihopEnabled","MultihopEntryID","MultihopExitID")
need("internal/common/profile_schema.go","NormalizeRouterProfile","NormalizeRouterProfileStore","ValidNodeProofID","invalid node proof id","HomeLANAccess","newer than supported schema","multihop requires both an entry node and an exit node","multihop entry and exit nodes must be different")
need("internal/common/profile_schema_test.go","TestMultihopRequiresCompleteDistinctNodes","requires both","different")
need("internal/common/onboarding.go","OnboardingSchemaVersion","LastReopenedAt",'"connection-validation"')

# Generic package/private node separation and archive safety.
need("deploy/check-generic-package-secrets.py","generic package contains private bundle","generic package contains linked router profiles","package does not ship LICENSE")
need("server/scripts/build-download-on-demand.py","safe_extract_zip","safe_extract_tar","assert_generic_tree","generic package contains linked router profiles","explicit private node-link bundle")
publisher=read("server/scripts/publish-downloads.sh")
for bad in('copy_static "$BUNDLE/router-vpn-bundle.json"','copy_static "$BUNDLE/CREDENTIALS.txt"','copy_public "$BUNDLE/router-vpn-bundle.json"','copy_public "$BUNDLE/CREDENTIALS.txt"'):
 if bad in publisher:errors.append(f"private node material is statically published: {bad}")
need("server/scripts/publish-downloads.sh",'"$OUT"/router-vpn-bundle.json','"$OUT"/CREDENTIALS.txt',"server_cache")
need("server/scripts/build-download-on-demand.py","MAX_UNPACKED","archive symlink is not allowed","unsafe archive path")
need("server/scripts/download-broker.py","MAX_COMPRESSION_RATIO","GitHub artifact contains a symlink","cleanup_stale_temp")
need("server/scripts/download_jobs.py","JOB_TTL_SECONDS","delivery-interrupted","cancel_requested","_cleanup_dir")
need("server/scripts/test_download_jobs.py","interrupted delivery temp directory was not removed")

# Setup Center real import contracts/auth/pairing.
need("server/scripts/import_payloads.py","sip002_uri","parse_sip002","ssr_uri","parse_ssr","validate_hysteria2_uri")
need("server/scripts/normalize-setup-imports.py",'"sip002"','"ssr-uri"','"qrSupported"')
need("server/scripts/test_setup_imports.py","SIP002","SSR","Hysteria")
need("server/scripts/ensure-setup-auth.py","setup-center.token","0o600","Never print the token")
need("server/scripts/pairing.py","one_time","lan_source","MAX_FAILURES_PER_MINUTE","invalid or expired pairing code")
need("server/scripts/download-broker.py","hmac.compare_digest","HttpOnly; SameSite=Strict","/api/pairing/redeem","apple_local_network_permission_required")
need("server/scripts/test_broker_security.py","status == 401","status == 403","X-Router-VPN-Pairing")

# Router agent trust/forwarding boundaries and stable public node identity proof.
need("cmd/router-agent/main.go","ConstantTimeCompare","source is not a tunnel peer","validateForward","allowedRanges","formatDNAT","NodeID","validNodeID","router-vpn-private-agent-v1")
need("cmd/router-agent/main_test.go","missing bearer token was authorized","Protected DMZ","IPv6")
need("cmd/router-agent/node_proof_test.go","TestValidNodeIDRequiresLowercaseSHA256Hex","TestPrivateHealthReturnsExactNodeIdentity","router-vpn-private-agent-v1")
need("server/scripts/ensure-node-proof.py","router-vpn-node-proof-v1\\n","config[\"node_id\"] = node_id","WireGuard server public key")
need("server/scripts/create-bundle-json.py","nodeProofId","node_proof_id","ensure-node-proof.py")

# Main-only discipline.
for wf in(ROOT/".github"/"workflows").glob("*.yml"):
 text=wf.read_text(encoding="utf-8",errors="ignore")
 if"--method DELETE"in text and"git/refs/heads"in text:errors.append(f"workflow blindly deletes branches: {wf.relative_to(ROOT)}")
need(".github/workflows/keep-main-only.yml","cleanup-known-stale-branches.sh")
need("deploy/cleanup-known-stale-branches.sh","Unexpected non-main branch","exit 1","Refusing to delete changed stale-branch candidate")

# Current controller/native app UI: 16 logical modes, typed validation, real Windows WPF shell, real Linux multihop UI.
need("cmd/portable-launcher/main.go","RouterVPN-Windows-App.ps1","openNativeApp(nativeApp)","nativeCmd.Wait()","-SelfTest","stopPortableController",'localURL+"api/emergency-stop"')
no("cmd/portable-launcher/main.go","url.dll,FileProtocolHandler",legacy_public_health,"openAppWindow","browserCmd","msedge.exe","chrome.exe","--app=","BrowserProfile")
need("client/RouterVPN-Windows-App.ps1","PresentationFramework","http://127.0.0.1:8788","ShowDialog()","$SelfTest","/api/status","/api/profiles","/api/logical-modes","/api/auto","/api/connect-logical","/api/disconnect","/api/profile/select","/api/profile/latency","/api/public-ip","/api/dns/retest","/api/emergency-stop")
need("deploy/package-builds.sh","RouterVPN-Windows-App.ps1","Native Router VPN Windows app is missing","api/emergency-stop","native Windows Router VPN WPF app")
no("deploy/package-builds.sh","--app=$url","msedge.exe","chrome.exe")
need("cmd/client/logical_ui.js","Connection validation","/api/session","Selected-node path proof","DNS proof","Cross-platform policy intent","The Modes page shows the 16 logical modes","/api/multihop/status","/api/multihop/connect","platform_supported","Entry and exit nodes must be different","exit public endpoint is not opened as a direct firewall exception")
no("cmd/client/logical_ui.js","PortableApps 3.9")
need("cmd/client/ui_contract_test.go","/api/multihop/status","/api/multihop/connect","platform_supported")

# Real first Linux multihop dataplane.
need("modes/multihop.py","detour",'"entry-hop"',"AllowedIPs = {allowed}","strict_route","multihop-proof","direct_exit_exception","first multihop runtime supports only shadowsocks or hysteria2 exit transports")
need("modes/run-multihop.sh","HOMEVPN_POLICY_PROFILE_ID","kill-switch.py","dns-policy.py","ENTRY_SOCKS_HOST","sing-box run")
need("modes/test_multihop.py","Multihop builder tests: OK","direct_exit_exception","0.0.0.0/0","entry-hop")
need("cmd/client/multihop.go","/api/multihop/status","/api/multihop/connect","runtime.GOOS != \"linux\"","multihopCommand","HOMEVPN_ROOT=","multihopNodeSummaries","multihopProofProxy","a.state.RouterID = sel.Exit.ID")
no("cmd/client/multihop.go",'"HOMEVPN_ROOT=."','"profiles": profiles')
need("cmd/client/multihop_test.go","HOMEVPN_ROOT=/tmp/router-vpn-data","TestMultihopNodeSummariesNeverExposeSecrets","same-node multihop was accepted")
need(".github/workflows/multihop-contract.yml","go test ./cmd/client ./internal/common","node --check cmd/client/logical_ui.js")

# Linux strict/persistent kill switch, including multihop-aware physical-entry policy.
need("modes/kill-switch.py","policy drop",'action == "reassert"',"current profile policy is no longer always","use force-off recovery locally","HOMEVPN_POLICY_PROFILE_ID","policy_profile_id","physical entry")
need("modes/test_kill_switch.py","router-vpn-killswitch-reassert-","router-vpn-killswitch-multihop-","cannot safely read routers.json")
need("client/install-linux.sh","nftables","Before=network-pre.target","RequiredBy=network-pre.target","kill-switch.py reassert","router-vpn-killswitch-recovery","force-off")

# Android: real raw WG/AWG, embedded libbox AUTO/SMART/CUSTOM, and narrow WG->SS/Hysteria2 multihop.
need("android/app/build.gradle","com.wireguard.android:tunnel:1.0.20260102")
need("android/app/build.gradle","libs/libbox.aar")
no("android/app/build.gradle","libs/libxray.aar","prepareXrayLibXray")
need("android/build-sing-box-libbox.sh","LIBXRAY_COMMIT=294fb37343205b9b0cb7b7b1b423d3d4b60d9998","XRAY_CORE_VERSION=v1.260327.1-0.20260711155151-50231eaff98c","GO_TOOLCHAIN=go1.26.3","exactly one gomobile go.Seq runtime class","github.com/xtls/libxray=$XRAY_VENDOR")
need("android/routervpn_xray_bridge.go","RouterXrayDialerController","RouterXrayRegisterDialerController","RouterXrayRegisterListenerController","RouterXraySetDNS","RouterXrayResetDNS","RouterXrayInvoke","net.DefaultResolver","controller.ProtectFd(int64(fd))")
need("android/gradle.properties","android.useAndroidX=true")
need("android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java","GoBackend","State.UP","Config.parse",'optJSONObject("wg")',"AndroidKillSwitchPolicy.strictRequested(privateBundle)","AndroidNativeProfilePolicy.patchWireGuardLikeConfig","AndroidPathProbe.prove(privateBundle, 8000)","recoverAfterNetworkChange","network-transition recovery failed closed")
need("android/app/src/main/java/com/eabusham/routervpn/NativeAmneziaWGController.java","org.amnezia.awg.backend.GoBackend","State.UP","Config.parse",'optJSONObject("awg2-fast")',"AndroidKillSwitchPolicy.strictRequested(privateBundle)","AndroidNativeProfilePolicy.patchWireGuardLikeConfig","AndroidPathProbe.prove(privateBundle, 8000)","recoverAfterNetworkChange","network-transition recovery failed closed")
need("android/app/src/main/java/com/eabusham/routervpn/NativeSingBoxController.java","isDirectFullDeviceConfig","MAX_PROFILE_FILE","MAX_PROFILE_TOTAL","cleanupOldSessions")
need("android/app/src/main/java/com/eabusham/routervpn/NativeXrayController.java","isCompositeProfile","cannot be represented truthfully by native Xray alone","AndroidNativeProfilePolicy.selectedPlainUdpDns(root)","AndroidNativeProfilePolicy.selectedMtu(root, 1380)")
need("android/app/src/main/java/com/eabusham/routervpn/XrayVpnService.java","routerXrayRegisterDialerController","routerXrayRegisterListenerController","routerXraySetDNS","routerXrayResetDNS","routerXrayBridgeRevision",'env.put("xray.tun.fd"',"AndroidPathProbe.prove(activeBundle","restartAfterNetworkChange","isLockdownEnabled()")
need("android/app/src/main/java/com/eabusham/routervpn/AndroidNativeProfilePolicy.java","patchWireGuardLikeConfig","selectedPlainUdpDns","requires an encrypted/transport-aware resolver","cannot be enforced by Android's address-only native VPN DNS API")
need("android/app/src/main/java/com/eabusham/routervpn/AndroidUnderlyingNetworkMonitor.java","NET_CAPABILITY_NOT_VPN","initialized && (current == null || !current.equals(network))")
need("android/app/src/main/java/com/eabusham/routervpn/AndroidModeOrchestrator.java","AndroidPathProbe.prove(bundle","No candidate passed selected-node path proof","SMART AUTO could not restore its last-known-good mode","void all(File bundle,Callback cb)","protectionRank","ALL failed closed because no Android-native branch passed Start Layer requirements and selected-node path proof","Composite desktop MAX chains remain separate and are never faked on Android")
need("android/app/src/main/java/com/eabusham/routervpn/AndroidNodeStore.java","MAX_NODES = 24","stableNodeIdentity","router-nodes-v1","return stable.substring(0, 32)")
need("android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopController.java",'"shadowsocks".equals(exitMode)','"hysteria2".equals(exitMode)','proxy.put("detour", "entry-wg")','put("type", "wireguard")',"AndroidNodeStore.stableNodeIdentity(entry)")
need("android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopRuntime.java","AndroidPathProbe.prove(prepared.exitBundle",'"FAILED".equals(state)','"REVOKED".equals(state)',"Exit-node private path proof failed; multihop was disconnected.")
need("android/app/src/main/java/com/eabusham/routervpn/AndroidPathProbe.java","AndroidNodeStore.stableNodeIdentity(bundle)","expectedNode.equals(body.optString(\"node_id\"","PROOF_KIND.equals(body.optString(\"proof\"")
need("android/app/src/main/java/com/eabusham/routervpn/MainActivity.java","VpnService.prepare(this)","Connect embedded layered mode","AUTO — first proven working mode","SMART AUTO — simplify and restore safely","Multihop — choose entry → exit","Strict embedded libbox/Xray sessions require","AWG-entry multihop")
need("android/test_android_runtime_contract.py","Android runtime truth contract: PASS")
need("android/test_android_multihop_contract.py","android multihop source contract: OK")

# Windows: official WG plus native pinned sing-box/Xray TUN and strict Windows Firewall policy.
need("client/native-wireguard-windows.ps1","WireGuard\\wireguard.exe","/installtunnelservice","/uninstalltunnelservice","Is-Administrator","Unsafe WireGuard profile path","will not fake native readiness through WSL","windows-kill-switch.ps1","Invoke-KillSwitch 'prepare'","Invoke-KillSwitch 'release'")
need("client/native-windows-mode.ps1","sing-box.exe","xray.exe","hysteria2","shadowsocks","reality-vision","reality-pq-vision","split","max","Patch-SingBox","Get-SelectedProfile","fastest_dns_host","hijack-dns","HOMEVPN_JUMBO","9000","Write-Utf8NoBom","Native Windows TUN modes require an elevated Router VPN process","windows-kill-switch.ps1","Invoke-KillSwitch 'prepare'","Invoke-KillSwitch 'release'","Get-TunAlias")
need("client/windows-kill-switch.ps1","Get-NetFirewallProfile -PolicyStore ActiveStore","Set-NetFirewallProfile","DefaultOutboundAction Block","New-NetFirewallRule","Remove-NetFirewallRule","original_profiles","ProgramData","Router VPN Kill Switch","InterfaceAlias","on-connect","always","force-off","literal IPv4/IPv6")
need("client/test-windows-kill-switch.ps1","plan/rollback/private-state contract","hostname endpoint was accepted","default_outbound")
kill=read("client/windows-kill-switch.ps1")
if "Action='Block'" in kill or "Action = 'Block'" in kill:errors.append("Windows kill switch uses an explicit block-all rule; narrow allow rules may be overridden")
need("client/Setup-Windows-Runtime.ps1","1.13.12","26.7.11","SHA-256 mismatch","e93fc531134eb1beb4efa3c74990a24e48456098a31c03b60d5ddf17f223cf98","af801b62c4d41d248d3db8016d4c6e2a7ccfb7ed443e3738aeb6f9e062321512")
need("client/Prepare-Windows-Mode-Catalog-v2.ps1","$mode.id -eq 'wg'","native-wireguard-windows.ps1","native-windows-mode.ps1","no native Windows adapter yet","Write-Utf8NoBom")
need("cmd/client/windows_runtime.go","Prepare-Windows-Mode-Catalog-v2.ps1","sing-box/Xray TUN adapter")
need("cmd/portable-launcher/main.go",'modeID == "wg"',"native-wireguard-windows.ps1","native-windows-mode.ps1","nativeLayeredWindowsModes","no native Windows adapter yet")
for retired in ("client/Prepare-Windows-Mode-Catalog.ps1","client/RouterVPN-Windows-Product.ps1"):
 if (ROOT/retired).exists():errors.append(f"retired Windows payload still ships in source tree: {retired}")
for rel in("client/native-windows-mode.ps1","client/Setup-Windows-Runtime.ps1","client/Prepare-Windows-Mode-Catalog-v2.ps1","cmd/client/windows_runtime.go","cmd/portable-launcher/main.go","deploy/package-builds.sh"):
 text=read(rel).lower()
 if"wsl.exe"in text or"requires wsl2"in text:errors.append(f"current Windows runtime still depends on WSL: {rel}")

# Apple: pinned WireGuardKit plus validated Libbox PacketTunnel; unsupported engines remain fail closed.
need("ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift","import WireGuardKit","WireGuardAdapter(with: self)","RouterVPNWireGuardConfig.parse","strict Apple kill switch requested",'case "libbox":','case "external-libbox":',"RouterVPNLibboxEngine","proveExternalExit","deriveNodeProof",'body["node_id"] as? String == expectedNodeID','body["proof"] as? String == Self.proofKind',"completionHandler(nil)")
need("ios/RouterVPN/App/IOSRuntimeSelection.swift",'case libbox = "libbox"',"sing-box.json","Xray-only, AmneziaWG-only, ALL/MAX and multihop combinations remain unavailable instead of faking Connected.")
need("ios/RouterVPN/App/RouterVPNModelExternal.swift","external-libbox","External OpenVPN — unavailable on iOS until a pinned native Apple OpenVPN dataplane exists","exact public-exit proof")
no("ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift","Link AmneziaWGKit/Xray engine before signing this target.")
need("ios/RouterVPN/PacketTunnel/WireGuardQuickConfig.swift","PrivateKey(base64Key:","IPAddressRange(from:","DNSServer(from:","scripts/hooks are never executed","profile exceeds the 1 MiB safety limit")
need("ios/RouterVPN/App/Models.swift","nodeProofID","node_proof_id","nodeProofId","Router bundle node proof ids disagree")
need("ios/RouterVPN/project.yml","NSLocalNetworkUsageDescription","com.apple.networkextension.packet-tunnel","WireGuardKit","2fec12a6e1f6e3460b6ee483aa00ad29cddadab1","Build pinned wireguard-go bridge","libwg-go.a")

# Production images remain exact/non-floating.
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