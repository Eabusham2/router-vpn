package mobilemultihop

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/multihoprelay"
)

func externalTestAddLayer(profile map[string]any, mode, host, privateHost, key string) {
	profile["start_layer"] = mode
	profile["external"].(map[string]any)["start_layer"] = map[string]any{
		"mode": mode, "api": "http://" + privateHost + ":8787",
		"transport": map[string]any{"type": "shadowsocks", "tag": "private-start-layer", "server": host,
			"server_port": 8388, "method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat(key, 32)))},
	}
}

func externalDirectLayerFixture(t *testing.T, protocol, layer string) (string, string) {
	t.Helper()
	source, capture := externalExecutionProtocolFixture(t, protocol, "local", layer)
	graph, selected := externalTestRead(t, source), externalTestRead(t, capture)
	delete(externalTestFind(t, graph, ExternalFinalTag), "detour")
	graph["endpoints"] = []any{}
	delete(selected, "entry")
	delete(selected, "entry_tag")
	profile := selected["profile"].(map[string]any)
	profile["multihop_enabled"] = false
	delete(profile["external"].(map[string]any), "response_probe")
	return externalTestJSON(t, graph), externalTestJSON(t, selected)
}

func TestExternalStartLayerLocalImportsNeedNoInventedServerProbe(t *testing.T) {
	for _, protocol := range externalExecutionProtocols {
		for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			t.Run(protocol+"/"+layer, func(t *testing.T) {
				source, capture := externalDirectLayerFixture(t, protocol, layer)
				if err := ValidateExternalTransport(source, capture); err != nil {
					t.Fatal("idle import could not validate its exact layer", err)
				}
				policy, err := NewExternalPolicy(source, capture)
				if err != nil {
					t.Fatal("Local layer demanded a fabricated remote comparison endpoint", err)
				}
				graph := externalTestRead(t, policy.Config())
				local := externalTestFind(t, graph, ExternalFinalTag)
				outer := externalTestFind(t, graph, multihoprelay.ExitStartLayerTag)
				if local["detour"] != multihoprelay.ExitStartLayerTag || outer["detour"] != nil || local["server"] != "10.93.0.1" || outer["server"] != "203.0.113.20" {
					t.Fatal("Local layer changed the selected physical path")
				}
				if policy.capture.Execution != nil || strings.Contains(policy.Metadata(), outer["password"].(string)) {
					t.Fatal("Local wrapper manufactured a server lease or exposed credentials")
				}
			})
		}
	}
}

func TestExternalStartLayerRejectsUnprovisionedChangedOrImplicitEncryption(t *testing.T) {
	mutations := map[string]func(map[string]any){
		"missing object": func(p map[string]any) { delete(p["external"].(map[string]any), "start_layer") },
		"null object":    func(p map[string]any) { p["external"].(map[string]any)["start_layer"] = nil },
		"implicit mode":  func(p map[string]any) { delete(p, "start_layer") },
		"explicit off":   func(p map[string]any) { p["start_layer"] = "off" },
		"mode differs":   func(p map[string]any) { p["start_layer"] = "aes-256-gcm+xor-whitening" },
		"invalid mode":   func(p map[string]any) { p["start_layer"] = "xor" },
		"unknown outer owner": func(p map[string]any) {
			p["external"].(map[string]any)["start_layer"].(map[string]any)["unknown"] = true
		},
		"public inner": func(p map[string]any) {
			p["external"].(map[string]any)["start_layer"].(map[string]any)["api"] = "http://203.0.113.99:8787"
		},
		"other server": func(p map[string]any) {
			p["external"].(map[string]any)["start_layer"].(map[string]any)["transport"].(map[string]any)["server"] = "203.0.113.99"
		},
		"different cipher": func(p map[string]any) {
			p["external"].(map[string]any)["start_layer"].(map[string]any)["transport"].(map[string]any)["method"] = "chacha20-ietf-poly1305"
		},
		"malformed key": func(p map[string]any) {
			p["external"].(map[string]any)["start_layer"].(map[string]any)["transport"].(map[string]any)["password"] = "not-base64"
		},
		"host path": func(p map[string]any) {
			p["external"].(map[string]any)["start_layer"].(map[string]any)["transport"].(map[string]any)["password_path"] = "/unowned/password"
		},
		"detour bypass": func(p map[string]any) {
			p["external"].(map[string]any)["start_layer"].(map[string]any)["transport"].(map[string]any)["detour"] = "direct"
		},
	}
	for _, protocol := range externalExecutionProtocols {
		for name, change := range mutations {
			t.Run(protocol+"/"+name, func(t *testing.T) {
				source, capture := externalDirectLayerFixture(t, protocol, "aes-256-gcm")
				selected := externalTestRead(t, capture)
				change(selected["profile"].(map[string]any))
				capture = externalTestJSON(t, selected)
				if _, err := NewExternalPolicy(source, capture); err == nil {
					t.Fatal("connection silently ignored or replaced selected exit encryption")
				}
				if err := ValidateExternalTransport(source, capture); err == nil {
					t.Fatal("idle import accepted an invalid private exit layer")
				}
			})
		}
	}
}

func TestExternalStartLayersKeepSeparateOrdinaryEntryAndExitOwners(t *testing.T) {
	for _, protocol := range externalExecutionProtocols {
		for _, entryProtocol := range externalExecutionProtocols {
			for _, entryMode := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				for _, exitMode := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
					t.Run(strings.Join([]string{entryProtocol, protocol, entryMode, exitMode}, "/"), func(t *testing.T) {
						graph, selected := externalTestFixture(t, protocol, entryProtocol)
						profile, entryProfile := selected["profile"].(map[string]any), selected["entry"].(map[string]any)
						externalTestAddLayer(profile, exitMode, "203.0.113.20", "10.93.0.1", "e")
						externalTestAddLayer(entryProfile, entryMode, "198.51.100.20", "10.94.0.1", "i")
						profile["dns_mode"], profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "custom", "tcp", "9.9.9.9", 5353
						profile["mtu_policy"], profile["manual_mtu"], profile["ipv6_mode"], profile["home_lan_access"] = "fixed", 1360, "off", false
						expectedEntry := predecessorCopy(externalTestFind(t, graph, "external-entry"))
						expectedExit := predecessorCopy(externalTestFind(t, graph, ExternalFinalTag))
						source, capture := externalTestJSON(t, graph), externalTestJSON(t, selected)
						policy, err := NewExternalPolicy(source, capture)
						if protocol == "hysteria2" && !externalUDP(entryProtocol) {
							if err == nil {
								t.Fatal("Start Layer invented UDP support in a TCP-only predecessor")
							}
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						compiled, meta := externalTestRead(t, policy.Config()), externalTestRead(t, policy.Metadata())
						entry, exit := externalTestFind(t, compiled, "external-entry"), externalTestFind(t, compiled, ExternalFinalTag)
						entryOuter, exitOuter := externalTestFind(t, compiled, ExternalEntryStartLayerTag), externalTestFind(t, compiled, multihoprelay.ExitStartLayerTag)
						expectedEntry["server"], expectedEntry["detour"] = "10.94.0.1", ExternalEntryStartLayerTag
						expectedExit["server"], expectedExit["detour"] = "10.93.0.1", multihoprelay.ExitStartLayerTag
						if !reflect.DeepEqual(entry, expectedEntry) || !reflect.DeepEqual(exit, expectedExit) {
							t.Fatal("a layer changed its captured inner protocol, TLS or credential owner")
						}
						if entryOuter["detour"] != nil || entryOuter["server"] != "198.51.100.20" || exitOuter["detour"] != "external-entry" || exitOuter["server"] != "203.0.113.20" || entryOuter["password"] == exitOuter["password"] {
							t.Fatal("entry and exit physical paths or private layer credentials were merged")
						}
						if meta["entry_start_layer"] != entryMode || meta["start_layer"] != exitMode || meta["entry_proof"] != "required" || meta["configured_mtu"] != float64(1360) || meta["auto_mtu"] != "not-requested" {
							t.Fatal("layer metadata lost independent proof or virtual-interface MTU ownership")
						}
						dns := compiled["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)
						if dns["detour"] != ExternalFinalTag || dns["server"] != "9.9.9.9" || dns["server_port"] != float64(5353) || len(compiled["route"].(map[string]any)["rules"].([]any)) != 4 {
							t.Fatal("independent layers changed selected DNS or LAN/IPv6 guards")
						}
						if source != externalTestJSON(t, graph) || capture != externalTestJSON(t, selected) {
							t.Fatal("compilation mutated a saved private profile")
						}
					})
				}
			}
		}
	}
}

func TestExternalEntryStartLayerCannotBeIgnoredOrBorrowTheExit(t *testing.T) {
	for _, protocol := range externalExecutionProtocols {
		for _, mutation := range []string{"missing", "off", "different node", "unknown member", "duplicate owner"} {
			t.Run(protocol+"/"+mutation, func(t *testing.T) {
				graph, selected := externalTestFixture(t, "shadowsocks", protocol)
				entry := selected["entry"].(map[string]any)
				externalTestAddLayer(entry, "aes-256-gcm", "198.51.100.20", "10.94.0.1", "i")
				layer := entry["external"].(map[string]any)["start_layer"].(map[string]any)
				switch mutation {
				case "missing":
					delete(entry["external"].(map[string]any), "start_layer")
				case "off":
					entry["start_layer"] = "off"
				case "different node":
					layer["transport"].(map[string]any)["server"] = "203.0.113.20"
				case "unknown member":
					layer["fallback"] = true
				case "duplicate owner":
					graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": "direct", "tag": ExternalEntryStartLayerTag})
				}
				if _, err := NewExternalPolicy(externalTestJSON(t, graph), externalTestJSON(t, selected)); err == nil {
					t.Fatal("ordinary external entry silently bypassed its exact selected wrapper")
				}
			})
		}
	}
}
