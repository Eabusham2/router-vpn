//go:build windows && routervpn_windows_candidate_prefix_native

package routervpnamnezia

import (
	"encoding/json"
	"os"
	"testing"
)

// The process first publishes its actual selected physical address. The parent
// owns and reads back the two private aliases before sending the original
// authenticated provider request. No synthetic peer or lease is returned here.
func TestRouterVPNDesktopWindowsCONNECTExecutionReferenceProcess(t *testing.T) {
	if os.Getenv("ROUTERVPN_WINDOWS_PREFIX_REFERENCE") != "1" || os.Getenv("ROUTERVPN_CONNECT_EXECUTION_REFERENCE") != "1" {
		t.Fatal("Windows execution reference lost its exact original invocation")
	}
	address, err := desktopWindowsPrefixReferenceAddress()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 1, "physical_address": address.String()}); err != nil {
		t.Fatal(err)
	}
	TestRouterVPNDesktopCONNECTExecutionReferenceProcess(t)
}
