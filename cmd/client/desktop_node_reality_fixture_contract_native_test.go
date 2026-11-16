//go:build (linux || darwin) && routervpn_controller_privileged

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"

	"router-vpn/internal/applexray"
	"router-vpn/internal/common"
)

func pairedREALITYContractAssets(t *testing.T, mode string) map[string][]byte {
	t.Helper()
	assets := nativeMultihopProxyExitAssets(t, common.RouterProfile{Endpoint: "192.0.2.17"}, mode)
	graph, err := applexray.Object(assets["sing-box.json"])
	if err != nil {
		t.Fatal(err)
	}
	graph["inbounds"].([]any)[0].(map[string]any)["tag"] = "tun-in"
	graph["route"].(map[string]any)["rules"] = []any{}
	assets["sing-box.json"], err = json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	return assets
}

func pairedREALITYContractEncode(t *testing.T, assets map[string][]byte) string {
	t.Helper()
	files := map[string]string{}
	for name, body := range assets {
		files[name] = base64.StdEncoding.EncodeToString(body)
	}
	raw, err := json.Marshal(files)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// Source contracts exercise the complete shared parser and original bytes.
// Only the separate installed phase proves encrypted traffic and native policy.
func TestDesktopUnixREALITYPrivateFixtureRefusesSubstitution(t *testing.T) {
	endpoint := netip.MustParseAddrPort("192.0.2.17:24443")
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
		for _, fault := range []string{"original", "endpoint", "port", "mode", "missing-xray", "extra-source", "foreign-final", "wrapper-listener", "xray-listener", "user", "reality-key", "duplicate-field", "extra-outbound", "physical-wrapper"} {
			t.Run(mode+"/"+fault, func(t *testing.T) {
				assets := pairedREALITYContractAssets(t, mode)
				graph, _ := applexray.Object(assets["xray.json"])
				wrapper, _ := applexray.Object(assets["sing-box.json"])
				out := graph["outbounds"].([]any)[0].(map[string]any)
				next := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
				user := next["users"].([]any)[0].(map[string]any)
				selected := mode
				switch fault {
				case "endpoint":
					next["address"] = "192.0.2.18"
				case "port":
					next["port"] = 24444
				case "mode":
					selected = "naive-h2"
				case "foreign-final":
					wrapper["route"].(map[string]any)["final"] = "direct"
				case "wrapper-listener":
					wrapper["outbounds"].([]any)[0].(map[string]any)["server_port"] = 1091
				case "xray-listener":
					graph["inbounds"].([]any)[0].(map[string]any)["port"] = 1091
				case "user":
					user["id"] = ""
				case "reality-key":
					out["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)["password"] = ""
				case "extra-outbound":
					graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"protocol": "freedom"})
				case "physical-wrapper":
					wrapper["outbounds"].([]any)[0].(map[string]any)["server"] = "192.0.2.17"
				}
				assets["xray.json"], _ = json.Marshal(graph)
				assets["sing-box.json"], _ = json.Marshal(wrapper)
				if fault == "missing-xray" {
					delete(assets, "xray.json")
				}
				if fault == "extra-source" {
					assets["foreign.json"] = assets["xray.json"]
				}
				if fault == "duplicate-field" {
					assets["xray.json"] = bytes.Replace(assets["xray.json"], []byte(`"outbounds":`), []byte(`"outbounds":[],"outbounds":`), 1)
				}
				accepted, err := pairedREALITYAssets(pairedREALITYContractEncode(t, assets), endpoint, selected, "connect")
				if (err == nil) != (fault == "original") {
					t.Fatal("REALITY original source substitution verdict changed", fault, err)
				}
				if fault == "original" && !reflect.DeepEqual(accepted, assets) {
					t.Fatal("positive REALITY installation replaced original private asset bytes")
				}
			})
		}
	}
}

func TestDesktopUnixREALITYPrivateFixtureMutatesOnlyNamedCredential(t *testing.T) {
	endpoint := netip.MustParseAddrPort("192.0.2.17:24443")
	for _, mode := range []string{"reality-vision", "reality-pq-vision", "reality-xhttp"} {
		actions := []string{"wrong-key", "wrong-user", "wrong-server-name", "wrong-short-id"}
		if mode != "reality-vision" {
			actions = append(actions, "wrong-pq-key")
		}
		if mode == "reality-xhttp" {
			actions = append(actions, "wrong-path")
		}
		for _, action := range actions {
			t.Run(mode+"/"+action, func(t *testing.T) {
				assets := pairedREALITYContractAssets(t, mode)
				changed, err := pairedREALITYAssets(pairedREALITYContractEncode(t, assets), endpoint, mode, action)
				if err != nil || len(changed) != 2 || !bytes.Equal(changed["sing-box.json"], assets["sing-box.json"]) || bytes.Equal(changed["xray.json"], assets["xray.json"]) {
					t.Fatal("REALITY credential control did not retain its original complete source", action, err)
				}
				original, _ := applexray.Object(assets["xray.json"])
				next, err := applexray.Object(changed["xray.json"])
				if err != nil {
					t.Fatal(err)
				}
				a := original["outbounds"].([]any)[0].(map[string]any)
				b := next["outbounds"].([]any)[0].(map[string]any)
				au := a["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
				bu := b["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
				as := a["streamSettings"].(map[string]any)
				bs := b["streamSettings"].(map[string]any)
				ar := as["realitySettings"].(map[string]any)
				br := bs["realitySettings"].(map[string]any)
				switch action {
				case "wrong-key":
					br["password"] = ar["password"]
				case "wrong-user":
					bu["id"] = au["id"]
				case "wrong-server-name":
					br["serverName"] = ar["serverName"]
				case "wrong-short-id":
					br["shortId"] = ar["shortId"]
				case "wrong-pq-key":
					bu["encryption"] = au["encryption"]
				case "wrong-path":
					bs["xhttpSettings"].(map[string]any)["path"] = as["xhttpSettings"].(map[string]any)["path"]
				}
				if !reflect.DeepEqual(original, next) {
					t.Fatal("REALITY credential control changed unrelated protocol, trust or identity fields", action)
				}
			})
		}
	}
}

func TestDesktopUnixREALITYPeerReceiptRefusesForeignLower(t *testing.T) {
	for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		for _, fault := range []string{"original", "raw-udp", "protocol-udp-lower", "foreign-address", "foreign-base", "borrowed-source", "foreign-layer", "outer-source", "websocket", "mux", "tls-http", "negative-counter", "missing-source"} {
			t.Run(layer+"/"+fault, func(t *testing.T) {
				physical := netip.MustParseAddr("192.0.2.17")
				original := &pairedREALITYPeer{Address: netip.AddrPortFrom(physical, 24443), Base: netip.AddrPortFrom(physical, 24443), Files: "original-private-source"}
				capturedLayer := layer
				if layer == "off" {
					capturedLayer = ""
				} else {
					original.AES = netip.AddrPortFrom(physical, 24444)
					original.Address = original.AES
					if layer == common.StartLayerAES256GCMXOR {
						original.Address = netip.AddrPortFrom(physical, 8389)
					}
				}
				v := map[string]any{"schema": 1, "address": original.Address.String(), "base_address": original.Base.String(), "protocol_files": original.Files}
				if original.AES.IsValid() {
					v["aes_address"] = original.AES.String()
				}
				switch fault {
				case "raw-udp":
					v["raw_udp"] = 1
				case "protocol-udp-lower":
					v["protocol_raw_udp"] = 1
				case "foreign-address":
					v["address"] = "192.0.2.18:24443"
				case "foreign-base":
					v["base_address"] = "192.0.2.17:24445"
				case "borrowed-source":
					v["protocol_files"] = "replacement-private-source"
				case "foreign-layer":
					capturedLayer = "xor"
				case "outer-source":
					v["aes_address"] = "192.0.2.17:24445"
				case "websocket":
					v["protocol_websocket"] = 1
				case "mux":
					v["protocol_mux"] = 1
				case "tls-http":
					v["protocol_tls_http"] = 1
				case "negative-counter":
					v["raw_tcp"] = -1
				case "missing-source":
					delete(v, "protocol_files")
				}
				raw, _ := json.Marshal(v)
				_, err := pairedREALITYRead(raw, physical, capturedLayer, original)
				if (err == nil) != (fault == "original") {
					t.Fatal("REALITY peer receipt substitution verdict changed", layer, fault, err)
				}
			})
		}
	}
}
