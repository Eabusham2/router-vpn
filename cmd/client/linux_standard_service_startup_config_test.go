//go:build linux

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"router-vpn/internal/standardengine"
)

func TestLinuxStandardServiceStartupStockGraphs(t *testing.T) {
	for _, protocol := range []string{"wireguard", "socks5", "http-connect", "https-connect", "shadowsocks", "hysteria2"} {
		for _, policy := range []string{"default", "fixed", "ipv6-off"} {
			t.Run(protocol+"/"+policy, func(t *testing.T) {
				profile, exit := standardPreparedPolicyFixture(t, protocol)
				profile.IPv6Mode = "on"
				if policy == "fixed" {
					profile.MTUPolicy = "manual"
					profile.ManualMTU = 1370
					profile.HomeLANAccess = true
				}
				if policy == "ipv6-off" {
					profile.IPv6Mode = "off"
				}
				directory, _, err := prepareDirectStandardExit(desktopAWGPrivateTestRoot(t), profile, exit)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := os.ReadFile(filepath.Join(directory, "sing-box.json"))
				if err != nil {
					t.Fatal(err)
				}
				before := standardengine.SHA256(raw)
				shape, err := standardengine.Config(raw, "standard-"+protocol)
				if err != nil || shape.Name != "router-vpn" || shape.MTU < 1280 {
					t.Fatal("captured stock graph rejected", shape, err, string(raw))
				}
				if standardengine.SHA256(raw) != before {
					t.Fatal("standard command rewrote captured options")
				}
				var graph map[string]any
				if json.Unmarshal(raw, &graph) != nil {
					t.Fatal("prepared JSON invalid")
				}
				graph["services"] = []any{map[string]any{"type": "resolved"}}
				changed, _ := json.Marshal(graph)
				if _, err := standardengine.Config(changed, "standard-"+protocol); err == nil {
					t.Fatal("unrelated runtime service accepted")
				}
				if output := os.Getenv("ROUTERVPN_STANDARD_CONFIG_FIXTURES"); output != "" {
					if err := os.MkdirAll(output, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(output, protocol+"-"+policy+".json"), raw, 0600); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
