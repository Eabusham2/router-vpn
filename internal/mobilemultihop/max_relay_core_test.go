//go:build go1.24

package mobilemultihop

import (
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/multihoprelay"
)

// Each shipping image parses the actual compiler/pairer/relay output with its
// exact bundled core. These are valid structural keys, not runtime crypto proof.
func TestExportPinnedCoreMAXRelayConfigurations(t *testing.T) {
	root := os.Getenv("ROUTER_VPN_RELAY_FIXTURES_DIR")
	if root == "" {
		t.Skip("native fixture export is requested by the router-agent image build")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	pq, err := mlkem.NewDecapsulationKey768(make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			assets, metadata := maxFixture(t, mode)
			if strings.HasPrefix(mode, "max-tls-") {
				maxChange(t, assets, "outer-xray.json", func(source map[string]any) {
					source["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)["encryption"] = "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(pq.EncapsulationKey().Bytes())
				})
			}
			exit, _ := pairedMAXSource(t, mode, layer, assets, metadata)
			lease := multihoprelay.Lease{Request: maxRelayRequest(exit), Host: "10.99.0.1", Port: 26240, Username: "public-fixture-user", Password: "public-fixture-password"}
			graph, err := multihoprelay.Build(exit, netip.MustParseAddr("10.99.0.2"), lease)
			if err != nil {
				t.Fatal(mode, layer, err)
			}
			var parsed map[string]any
			if json.Unmarshal(graph, &parsed) != nil || parsed["endpoints"] == nil {
				t.Fatal("native MAX fixture omitted its mandatory packet base")
			}
			label := layer
			if label == "" {
				label = "off"
			}
			if err = os.WriteFile(filepath.Join(root, mode+"-"+label+".json"), graph, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
