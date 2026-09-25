package common

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMultihopExecutionShippingOwners(t *testing.T) {
	files := map[string][]string{
		"cmd/client/multihop.go":                                                                   {"runMultihopExecution", "comparisonProgress(a)"},
		"cmd/client/multihop_native_routes.go":                                                     {"runMultihopExecution", "comparisonProgress(a)"},
		"cmd/client/multihop_execution.go":                                                         {"routechoice.Compare", "releaseDesktopRelay", "ProbeLast", "ProbeExternal"},
		"client/RouterVPN-Windows-UnifiedShell.ps1":                                                {"UnifiedExecution", "RefreshUnifiedMultihopComparison", "StopUnifiedComparisonProgress"},
		"client/macos/RouterVPNMacProduct.swift":                                                   {"multihopExecutionChoice", "multihopComparisonSummary", "stopMultihopProgress"},
		"client/linux/apply-multihop-execution.py":                                                 {"linux_multihop_execution_changed_v1", "execution"},
		"android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java":                  {"newRouterMultihop", "multihopProgressJSON", "executionController"},
		"android/app/src/main/java/com/eabusham/routervpn/AndroidUnifiedConnectionController.java": {"pendingExecution", "execution"},
		"ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift":                                   {"LibboxNewRouterMultihop", "plan.run(owned)", "try plan.close()", "ownershipLock", "ownershipGeneration"},
		"ios/RouterVPN/App/IOSMultihopProgress.swift":                                              {"multihopProgressInFlight", "multihopProgressDeadline", "multihopProgressGeneration", "16384"},
		"ios/RouterVPN/App/IOSMultihopView.swift":                                                  {"multihopExecution", "server", "auto"},
		"ios/RouterVPN/App/IOSConnectionProfilesView.swift":                                        {"multihopExecution", "forKey: .multihopExecution", "profile.multihopExecution = prefs.multihopExecution"},
		"deploy/prepare-mobile-multihop.py":                                                        {"routechoice", "multihoprelay", "mobilemultihop"},
		"mobile/routervpn_multihop_bridge.go.tmpl":                                                 {"SelectOutbound(tag)", "DialContext(ctx", "StartedService.Instance()"},
		"server/scripts/provision-multihop-relays.py":                                              {"registry_lock", "check-multihop-registry", "native_wireguard"},
	}
	for file, markers := range files {
		body, err := os.ReadFile(filepath.Join("../..", file))
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range markers {
			if !strings.Contains(string(body), marker) {
				t.Errorf("%s: missing shipping owner %q", file, marker)
			}
		}
	}
}

func TestNativeMultihopConfigChecksKeepWireGuardEnabled(t *testing.T) {
	for _, file := range []string{"android/build-sing-box-libbox.sh", "ios/RouterVPN/prepare-libbox.sh"} {
		body, err := os.ReadFile(filepath.Join("../..", file))
		if err != nil {
			t.Fatal(err)
		}
		checked := 0
		for _, line := range strings.Split(string(body), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[1] != "test" {
				continue
			}
			nativePackage := false
			wireguard := false
			for i, field := range fields {
				if field == "./experimental/libbox" {
					nativePackage = true
				}
				if field == "-tags" && i+1 < len(fields) {
					for _, tag := range strings.Split(fields[i+1], ",") {
						if tag == "with_wireguard" {
							wireguard = true
						}
					}
				}
			}
			if nativePackage {
				checked++
				if !wireguard {
					t.Errorf("%s: actual native multihop test omitted WireGuard: %s", file, line)
				}
			}
		}
		if checked == 0 {
			t.Errorf("%s: actual native configuration test is missing", file)
		}
	}
}
