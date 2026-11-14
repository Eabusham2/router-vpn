//go:build windows && routervpn_windows_candidate_prefix_native

package routervpnamnezia

import (
	"encoding/json"
	"os"
	"testing"
)

func TestRouterVPNDesktopWindowsSOCKSReferenceProcess(t *testing.T) {
	if os.Getenv("ROUTERVPN_WINDOWS_PREFIX_REFERENCE") != "1" || os.Getenv("ROUTERVPN_SOCKS_INSTALLED_REFERENCE") != "1" {
		t.Fatal("Windows full-path reference lost its exact native invocation")
	}
	address, err := desktopWindowsPrefixReferenceAddress()
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 1, "physical_address": address.String()}); err != nil {
		t.Fatal(err)
	}
	TestRouterVPNDesktopNodeChainSOCKSInstalledReferenceProcess(t)
}
