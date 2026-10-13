package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestMAXAdditionalStartLayerPreservesCompleteInnerChain(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, api := range []string{"http://10.77.0.1:8787", "https://[fd77:77::1]:8787", "http://10.77.0.1"} {
				t.Run(mode+"/"+layer+"/"+api, func(t *testing.T) {
					files, rawPolicy := maxFixture(t, mode)
					var policy maxPolicy
					json.Unmarshal([]byte(rawPolicy), &policy)
					policy.RouterAPI = api
					b, _ := json.Marshal(policy)
					plain, err := CompileMAXProfile(mode, pqEncoded(files), string(b))
					if err != nil {
						t.Fatal(err)
					}
					policy.StartLayer = layer
					b, _ = json.Marshal(policy)
					source := pqEncoded(files)
					wrapped, err := CompileMAXProfile(mode, source, string(b))
					if err != nil {
						t.Fatal(err)
					}
					if source != pqEncoded(files) {
						t.Fatal("saved profiles mutated")
					}
					var before, after map[string]any
					json.Unmarshal([]byte(plain), &before)
					json.Unmarshal([]byte(wrapped), &after)
					for _, field := range []string{"endpoints", "inbounds", "dns", "route", "log"} {
						if !reflect.DeepEqual(before[field], after[field]) {
							t.Fatal("inner policy or PQ key changed", field)
						}
					}
					outs := after["outbounds"].([]any)
					old := before["outbounds"].([]any)
					if len(outs) != 3 || !reflect.DeepEqual(outs[0], old[0]) {
						t.Fatal("required SS2022 layer lost")
					}
					transport := outs[1].(map[string]any)
					aes := outs[2].(map[string]any)
					if transport["detour"] != MAXStartLayerTag || transport["tag"] != MAXOuterTag || aes["tag"] != MAXStartLayerTag || aes["detour"] != nil || aes["server"] != "192.0.2.44" {
						t.Fatal("outer ownership changed")
					}
					expectedType, port := "shadowsocks", float64(8388)
					if layer == "aes-256-gcm+xor-whitening" {
						expectedType, port = "routervpn-aes-xor", 8389
					}
					if aes["type"] != expectedType || aes["server_port"] != port || aes["method"] != NativeStartLayerMethod || aes["password"] != outs[0].(map[string]any)["password"] {
						t.Fatal("AES source credential/cipher changed")
					}
					service := "10.77.0.1"
					if strings.Contains(api, "fd77") {
						service = "fd77:77::1"
					}
					preserved := old[1].(map[string]any)
					preserved["detour"] = MAXStartLayerTag
					if strings.Contains(mode, "tls") {
						var config map[string]any
						json.Unmarshal([]byte(preserved["config_json"].(string)), &config)
						config["outbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["address"] = service
						changed, _ := json.Marshal(config)
						preserved["config_json"] = string(changed)
					} else {
						preserved["server"] = service
					}
					if !reflect.DeepEqual(preserved, transport) {
						t.Fatal("outer authenticated protocol silently changed")
					}
				})
			}
		}
	}
}

func TestMAXStartLayerCannotSilentlyDropMalformedSavedPolicy(t *testing.T) {
	files, metadata := maxFixture(t, "max-quic-wg")
	for _, value := range []any{"xor", "unknown", true, float64(1), nil, []any{}, map[string]any{}} {
		var p map[string]any
		json.Unmarshal([]byte(metadata), &p)
		p["start_layer"] = value
		b, _ := json.Marshal(p)
		if _, err := CompileMAXProfile("max-quic-wg", pqEncoded(files), string(b)); err == nil {
			t.Fatalf("invalid start layer accepted: %#v", value)
		}
	}
}
