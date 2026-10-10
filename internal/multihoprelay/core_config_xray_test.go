//go:build go1.24

package multihoprelay

import (
	"crypto/mlkem"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestExportPinnedCoreXrayRelayConfigurations(t *testing.T) {
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
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
		exit := nativeXrayExit(t, mode)
		if mode != "reality-vision" {
			var source map[string]any
			if err = json.Unmarshal([]byte(exit.Transport["config_json"].(string)), &source); err != nil {
				t.Fatal(err)
			}
			source["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)["encryption"] = "mlkem768x25519plus.native.0rtt." + base64.RawURLEncoding.EncodeToString(pq.EncapsulationKey().Bytes())
			raw, err := json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			exit.Transport["config_json"] = string(raw)
		}
		body, err := Build(exit, netip.MustParseAddr("10.77.0.2"), Lease{Host: "10.77.0.1", Port: 26240, Username: "public-fixture-user", Password: "public-fixture-password"})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(root, mode+".json"), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
