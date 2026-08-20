package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func requireRepoMarkers(t *testing.T, relative string, markers ...string) {
	t.Helper()
	path := filepath.Join(append([]string{"..", ".."}, strings.Split(relative, "/")...)...)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	text := string(data)
	for _, marker := range markers {
		if !strings.Contains(text, marker) {
			t.Errorf("%s missing unified telemetry marker %q", relative, marker)
		}
	}
}

func TestUnifiedTelemetryAndPerformanceContract(t *testing.T) {
	requireRepoMarkers(t, "cmd/router-agent/benchmark.go",
		"/api/benchmark/download", "/api/benchmark/upload", "s.authorized(r)",
		"benchmarkDefaultBytes", "benchmarkMaxBytes", "no-store, no-transform", "content-encoding")
	requireRepoMarkers(t, "cmd/client/telemetry.go",
		"/api/profile/fastest", "/api/connection/live-latency", "/api/multihop/live-latency",
		"/api/connection/speed-test", "/api/benchmark/download", "/api/benchmark/upload", "DownloadMbps", "UploadMbps")
	requireRepoMarkers(t, "cmd/client/multihop.go",
		"activeMultihopGraph", "setActiveMultihopGraph", "clearActiveMultihopGraph", "getActiveMultihopGraph",
		"configured_entry_id", "configured_exit_id", "actual_entry_id", "actual_exit_id")
	requireRepoMarkers(t, "cmd/client/telemetry_hops.go",
		"/api/profile/speed-test", "/api/multihop/speed-test", "measureRoutedProfileSpeed",
		"validateActiveMultihopSpeedGraph", "does not match active multihop entry", "does not match active multihop exit",
		"refusing to guess hop ownership", "entry_error", "exit_error", "not derived from RTT", "active routing graph")
	requireRepoMarkers(t, "cmd/client/telemetry_hops_test.go",
		"TestValidateActiveMultihopSpeedGraphRequiresExactLivePair", "TestValidateActiveMultihopSpeedGraphFailsClosedWithoutIdentity",
		"TestActiveMultihopGraphTrackerStoresExactSelection")
	requireRepoMarkers(t, "cmd/client/mtu_retest.go", "registerHopTelemetryRoutes(h, a)")

	requireRepoMarkers(t, "client/RouterVPN-Windows-Telemetry.ps1",
		"UnifiedFastestNode", "UnifiedLiveLatency", "UnifiedMultihopLatency", "UnifiedForwardButton",
		"Real path speed", "/api/connection/speed-test", "Routed hop speeds", "/api/multihop/speed-test", "50-sample selected node", "Throughput + Auto MTU")
	requireRepoMarkers(t, "client/RouterVPN-Windows-App.ps1",
		"RouterVPN-Windows-Telemetry.ps1", "Add-RouterVPNTelemetryWindowsShell", "/api/connection/speed-test",
		"/api/multihop/speed-test", "Routed hop speeds")
	requireRepoMarkers(t, "client/macos/RouterVPNMacTelemetry.swift",
		"unified-fastest-node", "unified-live-latency", "unified-multihop-latency", "Forward",
		"Real path speed", "/api/connection/speed-test", "Routed hop speeds", "/api/multihop/speed-test", "50-sample selected node", "Throughput + Auto MTU")
	requireRepoMarkers(t, "client/macos/build-native-app.sh", "TELEMETRY_SRC", `"$TELEMETRY_SRC"`, "installUnifiedTelemetryUI")
	requireRepoMarkers(t, "client/linux/routervpn-telemetry-v9.inc",
		"⚡ Fastest", "/api/profile/fastest", "/api/connection/live-latency", "/api/multihop/live-latency",
		"Real path speed", "/api/connection/speed-test", "Routed hop speeds", "/api/multihop/speed-test", "Throughput + Auto MTU", "Forward")
	requireRepoMarkers(t, "client/linux/build-native-app.sh", "routervpn-telemetry-v9.inc", "linux_install_telemetry_v9(&app);")

	requireRepoMarkers(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidTelemetry.java",
		"class SpeedResult", "speedTest", "speedTest(AndroidNodeStore.Node", "/api/benchmark/download", "/api/benchmark/upload",
		"Authorization", "Accept-Encoding", "downloadMbps", "uploadMbps")
	requireRepoMarkers(t, "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",
		"⚡ Fastest", "liveLatency", "Performance", "Forward", "Profiles", "showProfileManager",
		"Real current VPN path speed", "Routed multihop speeds", "runRoutedHopSpeeds", "telemetry.speedTest(entry", "telemetry.speedTest(exit",
		"currentPathMs", "refreshMultihopSummary", "RouterVpnNodeMapView.Marker")
	requireRepoMarkers(t, "android/app/src/main/java/com/eabusham/routervpn/RouterVpnNodeMapView.java",
		"latencyMs", "System.currentTimeMillis", "postInvalidateDelayed", "ROLE_ENTRY", "ROLE_EXIT", "canvas.drawLine")

	requireRepoMarkers(t, "ios/RouterVPN/App/IOSUnifiedTelemetry.swift",
		"IOSSpeedResult", "speedTest", "/api/benchmark/download", "/api/benchmark/upload",
		"Authorization", "downloadMbps", "uploadMbps", "IOSProbeOnce")
	requireRepoMarkers(t, "ios/RouterVPN/App/IOSUnifiedProductView.swift",
		"bolt.fill", "livePathMs", "Performance", "Master port forwarding", "IOSUnifiedMap",
		"Run real current VPN path speed", "telemetry.speedTest", "packet", "multihop", "New CUSTOM preset")
	requireRepoMarkers(t, "ios/RouterVPN/App/NodeManagerSheet.swift",
		"Pair from home LAN", "Import node bundle", "Select lowest-latency node", "model.removeNode", "Edit", "updateNodeMetadata")

	requireRepoMarkers(t, ".github/workflows/release-candidate-status.yml",
		"workflow_run", "Router VPN release candidate", "statuses: write", "Router VPN release candidate", "head_sha")
	requireRepoMarkers(t, ".github/workflows/server-release-status.yml",
		"Router VPN ARM64 images", "Router VPN ARM64 Portainer preflight", "head_sha")
}

func TestUnifiedDefaultsAndSettingsContract(t *testing.T) {
	requireRepoMarkers(t, "internal/common/profile_schema.go",
		"p.StartupMode", `p.StartupMode = "smart-auto"`, "p.IPv6Mode", `p.IPv6Mode = "on"`, "p.MTUPolicy", `p.MTUPolicy = "auto"`)
	requireRepoMarkers(t, "internal/common/types.go",
		`json:"auto_require_encrypted,omitempty"`, `json:"auto_require_obfuscation,omitempty"`, `json:"daita_enabled,omitempty"`, `json:"jumbo_tun,omitempty"`)
	requireRepoMarkers(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidProfileSettingsDialog.java",
		"Require encrypted", "Require obfuscation", "Auto measured", "Jumbo", "DAITA")
	requireRepoMarkers(t, "ios/RouterVPN/App/IOSUnifiedProductView.swift",
		"SMART AUTO", "Require encrypted", "Require obfuscation", "IPv6 On", "Auto MTU")
}
