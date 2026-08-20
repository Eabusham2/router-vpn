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

	requireRepoMarkers(t, "client/RouterVPN-Windows-Telemetry.ps1",
		"UnifiedFastestNode", "UnifiedLiveLatency", "UnifiedMultihopLatency", "UnifiedForwardButton",
		"Real path speed", "/api/connection/speed-test", "50-sample selected node", "Throughput + Auto MTU")
	requireRepoMarkers(t, "client/macos/RouterVPNMacTelemetry.swift",
		"unified-fastest-node", "unified-live-latency", "unified-multihop-latency", "Forward",
		"Real path speed", "/api/connection/speed-test", "50-sample selected node", "Throughput + Auto MTU")
	requireRepoMarkers(t, "client/linux/routervpn-telemetry-v9.inc",
		"⚡ Fastest", "/api/profile/fastest", "/api/connection/live-latency", "/api/multihop/live-latency",
		"Real path speed", "/api/connection/speed-test", "Throughput + Auto MTU", "Forward")

	requireRepoMarkers(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidTelemetry.java",
		"class SpeedResult", "speedTest", "/api/benchmark/download", "/api/benchmark/upload",
		"Authorization", "Accept-Encoding", "downloadMbps", "uploadMbps")
	requireRepoMarkers(t, "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",
		"⚡ Fastest", "liveLatency", "Performance", "Forward", "Profiles", "showProfileManager",
		"currentPathMs", "refreshMultihopSummary", "RouterVpnNodeMapView.Marker")
	requireRepoMarkers(t, "android/app/src/main/java/com/eabusham/routervpn/RouterVpnNodeMapView.java",
		"latencyMs", "packetPhase", "ROLE_ENTRY", "ROLE_EXIT", "canvas.drawLine", "invalidate")

	requireRepoMarkers(t, "ios/RouterVPN/App/IOSUnifiedTelemetry.swift",
		"IOSSpeedResult", "speedTest", "/api/benchmark/download", "/api/benchmark/upload",
		"Authorization", "downloadMbps", "uploadMbps", "IOSProbeOnce")
	requireRepoMarkers(t, "ios/RouterVPN/App/IOSUnifiedProductView.swift",
		"bolt.fill", "livePathMs", "Performance", "Master port forwarding", "IOSUnifiedMap",
		"packet", "multihop", "New CUSTOM preset")
}

func TestUnifiedDefaultsAndSettingsContract(t *testing.T) {
	requireRepoMarkers(t, "internal/common/profile_schema.go",
		"smart-auto", "ipv6", "auto", "auto_require_encrypted", "auto_require_obfuscation")
	requireRepoMarkers(t, "android/app/src/main/java/com/eabusham/routervpn/AndroidProfileSettingsDialog.java",
		"Require encrypted", "Require obfuscation", "Auto measured", "Jumbo", "DAITA")
	requireRepoMarkers(t, "ios/RouterVPN/App/IOSUnifiedProductView.swift",
		"SMART AUTO", "Require encrypted", "Require obfuscation", "IPv6 On", "Auto MTU")
}
