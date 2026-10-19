package nativecomposite

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func TestPairedCompositeStartLayerPreservesBothLanesAndRejectsForeignPolicy(t *testing.T) {
	for _, mode := range []string{"ss-v2ray", "split", "max"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, host := range []string{"10.88.0.1", "[fd88::1]"} {
				t.Run(mode+"/"+layer+"/"+host, func(t *testing.T) {
					node := strings.Repeat("e", 64)
					plan := planFor(t, mode, node, "")
					outer := map[string]any{"type": "shadowsocks", "tag": "proxy", "server": "192.0.2.1", "server_port": 8388, "method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("l", 32)))}
					original, key := encoded(plan), encoded(outer)
					result, err := WithStartLayer(plan, mode, node, layer, "http://"+host+":8787", outer)
					if err != nil || ValidatePlan(result, mode, node, layer) != nil {
						t.Fatal("paired complete graph could not own both lanes", err)
					}
					if encoded(plan) != original || encoded(outer) != key {
						t.Fatal("operator-private input changed")
					}
					udp, tcp := result["udp"].(map[string]any), result["tcp"].(map[string]any)
					if udp["server"] != strings.Trim(host, "[]") || udp["detour"] != StartTag || tcp["detour"] != StartTag || !reflect.DeepEqual(udp["tls"], plan["udp"].(map[string]any)["tls"]) || udp["password"] != plan["udp"].(map[string]any)["password"] {
						t.Fatal("captured private service or independent UDP authentication changed")
					}
					for name, change := range map[string]func(map[string]any){
						"foreign-node": func(p map[string]any) { p["server"] = "192.0.2.99" },
						"weak-key":     func(p map[string]any) { p["password"] = "private-must-not-echo" },
						"weak-cipher":  func(p map[string]any) { p["method"] = "none" },
						"preowned":     func(p map[string]any) { p["detour"] = "bypass" },
					} {
						t.Run(name, func(t *testing.T) {
							copy := parsed(t, key)
							change(copy)
							if _, err := WithStartLayer(plan, mode, node, layer, "http://"+host+":8787", copy); err == nil || strings.Contains(err.Error(), "private-must-not-echo") {
								t.Fatal("unowned paired Start Layer accepted or echoed")
							}
						})
					}
					for _, api := range []string{"http://127.0.0.1:8787", "http://8.8.8.8:8787", "http://user@10.88.0.1:8787", "http://10.88.0.1:8787/path", "http://10.88.0.1:8787?bypass=1"} {
						if _, err := WithStartLayer(plan, mode, node, layer, api, outer); err == nil {
							t.Fatal("foreign API accepted", api)
						}
					}
					if _, err := WithStartLayer(result, mode, node, layer, "http://"+host+":8787", outer); err == nil {
						t.Fatal("same complete graph encrypted twice")
					}
				})
			}
		}
	}
}
