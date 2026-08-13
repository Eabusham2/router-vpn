package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

func TestAndroidNativeWireGuardAmneziaWGLayeredAndNarrowMultihopAreReal(t *testing.T) {
	gradle := repoFile(t, "android/app/build.gradle")
	for _, required := range []string{"com.wireguard.android:tunnel:1.0.20260102", "amneziawg-tunnel.aar", "prepareAmneziaWgTunnel", "coreLibraryDesugaring"} {
		if !strings.Contains(gradle, required) {
			t.Fatalf("Android native dependency/build boundary missing %q", required)
		}
	}
	props := repoFile(t, "android/gradle.properties")
	if !strings.Contains(props, "android.useAndroidX=true") {
		t.Fatal("Android native tunnel dependencies require android.useAndroidX=true")
	}
	wg := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java")
	for _, required := range []string{"new GoBackend", "backend.setState(this, State.UP, config)", "backend.setState(this, State.DOWN, null)", "Config.parse", `profiles.optJSONObject("wg")`, `wg.optString("wg.conf"`, "AndroidKillSwitchPolicy.strictRequested(privateBundle)", "AndroidNativeProfilePolicy.patchWireGuardLikeConfig", "AndroidPathProbe.prove(privateBundle, 8000)", "recoverAfterNetworkChange", "network-transition recovery failed closed"} {
		if !strings.Contains(wg, required) {
			t.Fatalf("Android WireGuard runtime missing %q", required)
		}
	}
	awg := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/NativeAmneziaWGController.java")
	for _, required := range []string{"org.amnezia.awg.backend.GoBackend", "backend.setState(this, State.UP, config)", "backend.setState(this, State.DOWN, null)", "Config.parse", `profiles.optJSONObject("awg2-fast")`, `profiles.optJSONObject("awg2-strong")`, `awg.optString("awg.conf"`, "AndroidKillSwitchPolicy.strictRequested(privateBundle)", "AndroidNativeProfilePolicy.patchWireGuardLikeConfig", "AndroidPathProbe.prove(privateBundle, 8000)", "recoverAfterNetworkChange", "network-transition recovery failed closed"} {
		if !strings.Contains(awg, required) {
			t.Fatalf("Android AmneziaWG runtime missing %q", required)
		}
	}
	builder := repoFile(t, "android/build-awg-tunnel.sh")
	for _, required := range []string{"2.0.0", "4116c836241f737badb99dcd4e990600d46e4c65", "submodule update --init --recursive", "libawg-go.so", "soname=libawg-go.so", "loadSharedLibrary(context, \"awg-go\")", "libwg*.so name that can collide"} {
		if !strings.Contains(builder, required) {
			t.Fatalf("Android pinned/namespaced AWG source build missing %q", required)
		}
	}
	sing := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/NativeSingBoxController.java")
	for _, required := range []string{"isDirectFullDeviceConfig", "MAX_PROFILE_FILE", "MAX_PROFILE_TOTAL", "cleanupOldSessions", "LayeredVpnService"} {
		if !strings.Contains(sing, required) {
			t.Fatalf("Android embedded libbox runtime missing %q", required)
		}
	}
	xray := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/NativeXrayController.java")
	for _, required := range []string{"isCompositeProfile", "cannot be represented truthfully by native Xray alone", "AndroidNativeProfilePolicy.selectedPlainUdpDns(root)", "AndroidNativeProfilePolicy.selectedMtu(root, 1380)"} {
		if !strings.Contains(xray, required) {
			t.Fatalf("Android native Xray controller missing %q", required)
		}
	}
	xrayService := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/XrayVpnService.java")
	for _, required := range []string{"routerXrayRegisterDialerController", "routerXrayRegisterListenerController", "routerXraySetDNS", "routerXrayResetDNS", "routerXrayBridgeRevision", `env.put("xray.tun.fd"`, "AndroidPathProbe.prove(activeBundle", "restartAfterNetworkChange", "isLockdownEnabled()"} {
		if !strings.Contains(xrayService, required) {
			t.Fatalf("Android native Xray VpnService missing %q", required)
		}
	}
	nativePolicy := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidNativeProfilePolicy.java")
	for _, required := range []string{"patchWireGuardLikeConfig", "selectedPlainUdpDns", "requires an encrypted/transport-aware resolver", "cannot be enforced by Android's address-only native VPN DNS API"} {
		if !strings.Contains(nativePolicy, required) {
			t.Fatalf("Android native DNS/MTU policy missing %q", required)
		}
	}
	combinedBuild := repoFile(t, "android/build-sing-box-libbox.sh")
	for _, required := range []string{"LIBXRAY_COMMIT=294fb37343205b9b0cb7b7b1b423d3d4b60d9998", "XRAY_CORE_VERSION=v1.260327.1-0.20260711155151-50231eaff98c", "GO_TOOLCHAIN=go1.26.3", "exactly one gomobile go.Seq runtime class", "github.com/xtls/libxray=$XRAY_VENDOR"} {
		if !strings.Contains(combinedBuild, required) {
			t.Fatalf("Android combined Go runtime build missing %q", required)
		}
	}
	bridge := repoFile(t, "android/routervpn_xray_bridge.go")
	for _, required := range []string{"RouterXrayDialerController", "RouterXrayRegisterDialerController", "RouterXrayRegisterListenerController", "RouterXraySetDNS", "RouterXrayResetDNS", "RouterXrayInvoke", "net.DefaultResolver", "controller.ProtectFd(int64(fd))"} {
		if !strings.Contains(bridge, required) {
			t.Fatalf("Android combined Xray bridge missing %q", required)
		}
	}
	combinedGradle := repoFile(t, "android/app/build.gradle")
	if !strings.Contains(combinedGradle, "libs/libbox.aar") || strings.Contains(combinedGradle, "libs/libxray.aar") || strings.Contains(combinedGradle, "prepareXrayLibXray") {
		t.Fatal("Android Gradle must package one combined libbox Go runtime and no standalone libXray AAR")
	}
	orchestrator := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidModeOrchestrator.java")
	for _, required := range []string{"AndroidPathProbe.prove(bundle", "No candidate passed selected-node path proof", "SMART AUTO could not restore its last-known-good mode", "void all(File bundle,Callback cb)", "protectionRank", "ALL failed closed because no Android-native branch passed selected-node path proof"} {
		if !strings.Contains(orchestrator, required) {
			t.Fatalf("Android AUTO/SMART truth boundary missing %q", required)
		}
	}
	multihop := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidMultihopController.java")
	for _, required := range []string{`"shadowsocks".equals(exitMode)`, `"hysteria2".equals(exitMode)`, `proxy.put("detour", "entry-wg")`, `put("type", "wireguard")`, "AndroidNodeStore.stableNodeIdentity(entry)", "AndroidNodeStore.stableNodeIdentity(exit)"} {
		if !strings.Contains(multihop, required) {
			t.Fatalf("Android narrow multihop runtime missing %q", required)
		}
	}
	activity := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/MainActivity.java")
	for _, required := range []string{"PREPARE_NATIVE_WG", "PREPARE_NATIVE_AWG", "PREPARE_MULTIHOP", "VpnService.prepare(this)", "Connect native WireGuard", "Connect native AmneziaWG 2", "Connect embedded layered mode", "AUTO — first proven working mode", "SMART AUTO — simplify and restore safely", "Multihop — choose entry → exit", "Strict embedded libbox/Xray sessions require", "AWG-entry multihop", "Network changes reset/revalidate libbox and native Xray"} {
		if !strings.Contains(activity, required) {
			t.Fatalf("Android capability boundary missing %q", required)
		}
	}
}

func TestWindowsRawAndLayeredNativeRuntimeIsRealAndUnsupportedModesStayGated(t *testing.T) {
	wg := repoFile(t, "client/native-wireguard-windows.ps1")
	for _, required := range []string{"WireGuard\\wireguard.exe", "/installtunnelservice", "/uninstalltunnelservice", "WireGuardTunnel`$", "Is-Administrator", "HOMEVPN_PROFILE_ID", "Unsafe WireGuard profile path", "will not fake native readiness through WSL", "windows-kill-switch.ps1", "Invoke-KillSwitch 'prepare'", "Invoke-KillSwitch 'release'"} {
		if !strings.Contains(wg, required) {
			t.Fatalf("Windows native WireGuard helper missing %q", required)
		}
	}
	if strings.Contains(wg, "wsl.exe") {
		t.Fatal("native Windows WireGuard helper must not implement its tunnel through WSL")
	}
	layered := repoFile(t, "client/native-windows-mode.ps1")
	for _, required := range []string{"sing-box.exe", "xray.exe", "hysteria2", "shadowsocks", "naive-h2", "naive-h3", "reality-vision", "reality-pq-vision", "split", "max", "Patch-SingBox", "Get-SelectedProfile", "fastest_dns_host", "hijack-dns", "HOMEVPN_JUMBO", "9000", "Write-Utf8NoBom", "Native Windows TUN modes require an elevated Router VPN process", "windows-kill-switch.ps1", "Invoke-KillSwitch 'prepare'", "Invoke-KillSwitch 'release'", "Get-TunAlias"} {
		if !strings.Contains(layered, required) {
			t.Fatalf("Windows native layered helper missing %q", required)
		}
	}
	kill := repoFile(t, "client/windows-kill-switch.ps1")
	for _, required := range []string{"Get-NetFirewallProfile -PolicyStore ActiveStore", "Set-NetFirewallProfile", "DefaultOutboundAction Block", "New-NetFirewallRule", "Remove-NetFirewallRule", "original_profiles", "ProgramData", "Router VPN Kill Switch", "InterfaceAlias", "on-connect", "always", "force-off", "literal IPv4/IPv6"} {
		if !strings.Contains(kill, required) {
			t.Fatalf("Windows strict kill-switch helper missing %q", required)
		}
	}
	if strings.Contains(kill, "Action='Block'") || strings.Contains(kill, "Action = 'Block'") {
		t.Fatal("Windows kill switch must use profile default outbound Block rather than a block-all rule that can override narrow allow rules")
	}
	setup := repoFile(t, "client/Setup-Windows-Runtime.ps1")
	for _, required := range []string{"1.13.12", "26.7.11", "SHA-256 mismatch", "e93fc531134eb1beb4efa3c74990a24e48456098a31c03b60d5ddf17f223cf98", "af801b62c4d41d248d3db8016d4c6e2a7ccfb7ed443e3738aeb6f9e062321512", "CompanionPatterns", "*.dll", "*.dat"} {
		if !strings.Contains(setup, required) {
			t.Fatalf("Windows pinned runtime setup missing %q", required)
		}
	}
	catalog := repoFile(t, "client/Prepare-Windows-Mode-Catalog-v2.ps1")
	for _, required := range []string{"$mode.id -eq 'wg'", "native-wireguard-windows.ps1", "native-windows-mode.ps1", "no native Windows adapter yet", "Write-Utf8NoBom"} {
		if !strings.Contains(catalog, required) {
			t.Fatalf("Windows catalog boundary missing %q", required)
		}
	}
	startup := repoFile(t, "cmd/client/windows_runtime.go")
	if !strings.Contains(startup, "Prepare-Windows-Mode-Catalog-v2.ps1") || !strings.Contains(startup, "sing-box/Xray TUN adapter") {
		t.Fatal("installed Windows package does not prepare native runtime catalog")
	}
	portable := repoFile(t, "cmd/portable-launcher/main.go")
	for _, required := range []string{"nativeLayeredWindowsModes", "native-wireguard-windows.ps1", "native-windows-mode.ps1", "no native Windows adapter yet"} {
		if !strings.Contains(portable, required) {
			t.Fatalf("Portable Windows native catalog missing %q", required)
		}
	}
	for _, body := range []string{strings.ToLower(layered), strings.ToLower(setup), strings.ToLower(catalog), strings.ToLower(startup), strings.ToLower(portable)} {
		if strings.Contains(body, "wsl.exe") || strings.Contains(body, "requires wsl2") {
			t.Fatal("current Windows path must not depend on WSL")
		}
	}
}

func TestApplePacketTunnelRunsPinnedNativeWireGuardAndKeepsUnsupportedModesFailClosed(t *testing.T) {
	provider := repoFile(t, "ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift")
	for _, required := range []string{"import WireGuardKit", "WireGuardAdapter(with: self)", "RouterVPNWireGuardConfig.parse", "strict Apple kill switch requested", "AmneziaWG, layered, ALL/MAX and multihop remain unavailable", "deriveNodeProof", "nodeProofDomain", `body["node_id"] as? String == expectedNodeID`, `body["proof"] as? String == Self.proofKind`, "completionHandler(nil)"} {
		if !strings.Contains(provider, required) {
			t.Fatalf("Apple native WireGuard runtime missing %q", required)
		}
	}
	if strings.Contains(provider, "Link AmneziaWGKit/Xray engine before signing this target.") {
		t.Fatal("Apple PacketTunnel still contains the retired unavailable-engine stub")
	}
	parser := repoFile(t, "ios/RouterVPN/PacketTunnel/WireGuardQuickConfig.swift")
	for _, required := range []string{"PrivateKey(base64Key:", "IPAddressRange(from:", "DNSServer(from:", "PersistentKeepalive", "scripts/hooks are never executed", "profile exceeds the 1 MiB safety limit"} {
		if !strings.Contains(parser, required) {
			t.Fatalf("Apple bounded WireGuard parser missing %q", required)
		}
	}
	models := repoFile(t, "ios/RouterVPN/App/Models.swift")
	for _, required := range []string{"nodeProofID", "node_proof_id", "nodeProofId", "Router bundle node proof ids disagree"} {
		if !strings.Contains(models, required) {
			t.Fatalf("Apple app bundle model does not preserve node identity: %q", required)
		}
	}
	project := repoFile(t, "ios/RouterVPN/project.yml")
	for _, required := range []string{"NSLocalNetworkUsageDescription", "com.apple.networkextension.packet-tunnel", "WireGuardKit", "2fec12a6e1f6e3460b6ee483aa00ad29cddadab1", "Build pinned wireguard-go bridge", "libwg-go.a"} {
		if !strings.Contains(project, required) {
			t.Fatalf("Apple pinned native tunnel build boundary missing %q", required)
		}
	}
}

func TestRetiredWindowsCatalogV1AndCompatibilityRuntimeAreNotReferenced(t *testing.T) {
	for _, rel := range []string{"cmd/client/windows_runtime.go", "cmd/portable-launcher/main.go", "deploy/package-builds.sh", "client/Setup-Windows-Runtime.ps1"} {
		body := repoFile(t, rel)
		if strings.Contains(body, "Prepare-Windows-Mode-Catalog.ps1") && !strings.Contains(body, "Prepare-Windows-Mode-Catalog-v2.ps1") {
			t.Fatalf("%s references retired Windows catalog v1", rel)
		}
		lower := strings.ToLower(body)
		if strings.Contains(lower, "wsl.exe") || strings.Contains(lower, "requires wsl2") {
			t.Fatalf("%s still depends on WSL", rel)
		}
	}
}
