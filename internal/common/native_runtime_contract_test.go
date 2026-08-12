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
	if err != nil { t.Fatalf("read %s: %v", rel, err) }
	return string(b)
}

func TestAndroidNativeWireGuardIsRealAndOtherModesStayGated(t *testing.T) {
	gradle := repoFile(t, "android/app/build.gradle")
	for _, required := range []string{
		"com.wireguard.android:tunnel:1.0.20260102",
		"coreLibraryDesugaring",
	} {
		if !strings.Contains(gradle, required) { t.Fatalf("Android native dependency missing %q", required) }
	}
	props := repoFile(t, "android/gradle.properties")
	if !strings.Contains(props, "android.useAndroidX=true") { t.Fatal("WireGuard AndroidX dependency requires android.useAndroidX=true") }
	controller := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/NativeWireGuardController.java")
	for _, required := range []string{
		"new GoBackend", "backend.setState(this, State.UP, config)",
		"backend.setState(this, State.DOWN, null)", "Config.parse",
		`profiles.optJSONObject("wg")`, `wg.optString("wg.conf"`,
	} {
		if !strings.Contains(controller, required) { t.Fatalf("Android WireGuard runtime missing %q", required) }
	}
	activity := repoFile(t, "android/app/src/main/java/com/eabusham/routervpn/MainActivity.java")
	for _, required := range []string{
		"VpnService.prepare(this)", "Tunnel.State.UP",
		"does not fake a live all-mode VPN connection",
		"AmneziaWG", "automatic reconnect are still unavailable",
	} {
		if !strings.Contains(activity, required) { t.Fatalf("Android capability boundary missing %q", required) }
	}
}

func TestWindowsRawWireGuardUsesOfficialNativeTunnelService(t *testing.T) {
	helper := repoFile(t, "client/native-wireguard-windows.ps1")
	for _, required := range []string{
		"WireGuard\\wireguard.exe", "/installtunnelservice", "/uninstalltunnelservice",
		"WireGuardTunnel`$", "Is-Administrator", "HOMEVPN_PROFILE_ID",
		"Unsafe WireGuard profile path", "will not fake native readiness through WSL",
	} {
		if !strings.Contains(helper, required) { t.Fatalf("Windows native WireGuard helper missing %q", required) }
	}
	if strings.Contains(helper, "wsl.exe") { t.Fatal("native Windows WireGuard helper must not implement its tunnel through WSL") }
	catalog := repoFile(t, "client/Prepare-Windows-Mode-Catalog-v2.ps1")
	for _, required := range []string{
		"$mode.id -eq 'wg'", "native-wireguard-windows.ps1", "powershell.exe",
		"This layered Router VPN mode requires WSL2/default Linux until its native Windows adapter is implemented",
	} {
		if !strings.Contains(catalog, required) { t.Fatalf("Windows catalog boundary missing %q", required) }
	}
	startup := repoFile(t, "cmd/client/windows_runtime.go")
	if !strings.Contains(startup, "Prepare-Windows-Mode-Catalog-v2.ps1") { t.Fatal("installed Windows package does not prepare the native raw-WG catalog") }
	portable := repoFile(t, "cmd/portable-launcher/main.go")
	if !strings.Contains(portable, `modeID == "wg"`) || !strings.Contains(portable, "native-wireguard-windows.ps1") {
		t.Fatal("Portable Windows raw WG is not mapped to native WireGuard")
	}
}

func TestApplePacketTunnelRemainsFailClosedUntilRealEngineBridgeExists(t *testing.T) {
	provider := repoFile(t, "ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift")
	for _, required := range []string{
		"Link AmneziaWGKit/Xray engine before signing this target.",
		"completionHandler(error)",
	} {
		if !strings.Contains(provider, required) { t.Fatalf("Apple fail-closed boundary missing %q", required) }
	}
	if strings.Contains(provider, "completionHandler(nil)") {
		t.Fatal("Apple Packet Tunnel claims success even though the real engine bridge is still unavailable")
	}
	project := repoFile(t, "ios/RouterVPN/project.yml")
	for _, required := range []string{"NSLocalNetworkUsageDescription", "com.apple.networkextension.packet-tunnel"} {
		if !strings.Contains(project, required) { t.Fatalf("Apple local-network/tunnel declaration missing %q", required) }
	}
}

func TestRetiredWindowsCatalogV1IsNotReferenced(t *testing.T) {
	for _, rel := range []string{
		"cmd/client/windows_runtime.go", "cmd/portable-launcher/main.go",
		"deploy/package-builds.sh", "client/Setup-Windows-Runtime.ps1",
	} {
		body := repoFile(t, rel)
		if strings.Contains(body, "Prepare-Windows-Mode-Catalog.ps1") && !strings.Contains(body, "Prepare-Windows-Mode-Catalog-v2.ps1") {
			t.Fatalf("%s references retired Windows catalog v1", rel)
		}
	}
}
