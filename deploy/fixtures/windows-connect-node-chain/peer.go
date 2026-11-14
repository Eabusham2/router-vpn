//go:build windows && routervpn_windows_candidate_prefix_native

package routervpnamnezia

import (
	"encoding/json"
	"os"
	"testing"
)

// Only the physical selector is platform-specific. The original authenticated
// HTTP/HTTPS CONNECT provider, encrypted packet prefix and final SS UoT-v2
// counterparty are the same shared installed reference on every desktop.
func TestRouterVPNDesktopWindowsCONNECTReferenceProcess(t *testing.T) {
	if os.Getenv("ROUTERVPN_WINDOWS_PREFIX_REFERENCE") != "1" || os.Getenv("ROUTERVPN_CONNECT_INSTALLED_REFERENCE") != "1" {
		t.Fatal("Windows CONNECT reference lost its exact native invocation")
	}
	address, err := desktopWindowsPrefixReferenceAddress()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 1, "physical_address": address.String()}); err != nil {
		t.Fatal(err)
	}
	TestRouterVPNDesktopNodeChainCONNECTInstalledReferenceProcess(t)
}
