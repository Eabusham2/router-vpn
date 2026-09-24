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
