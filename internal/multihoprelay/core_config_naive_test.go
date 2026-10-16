package multihoprelay

import (
	"encoding/base64"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The produced files must pass the exact packaged Cronet/Naive registry. This
// parser check does not start the captured endpoints or replace a traffic test.
func TestExportPinnedCoreNaiveRelayConfigurations(t *testing.T) {
	root := os.Getenv("ROUTER_VPN_RELAY_FIXTURES_DIR")
	if root == "" {
		t.Skip("fixture export requested by native image build")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"naive-h2", "naive-h3"} {
		for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			exit := Exit{ID: "exit", Mode: mode, NodeID: strings.Repeat("b", 64), DNS: "192.168.50.133", Transport: naiveFixture(mode)}
			lease := Lease{Host: "10.77.0.1", Port: 26240, Username: "public-fixture-user", Password: "public-fixture-password"}
			if layer != "off" {
				exit.StartLayer = &StartLayer{Mode: layer, API: "http://10.88.0.1:8787", Transport: map[string]any{
					"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.4", "server_port": float64(8388),
					"method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))}}
				lease.ExitStartLayer = layer
			}
			body, err := Build(exit, netip.MustParseAddr("10.77.0.2"), lease)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(root, mode+"-"+layer+".json"), body, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}
