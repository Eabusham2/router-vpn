package nativeopenvpn

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func remoteLayers(mode string) StartLayers {
	layers := StartLayers{}
	for i, host := range []string{"192.0.2.60", "192.0.2.61"} {
		layers[host] = StartLayer{Mode: mode, API: "http://10.93.0.1:8787", Transport: map[string]any{
			"type": "shadowsocks", "tag": "provisioned-start", "server": host, "server_port": float64(8388 + i*2),
			"method": "2022-blake3-aes-256-gcm", "password": base64.StdEncoding.EncodeToString([]byte(strings.Repeat(string(rune('a'+i)), 32))),
		}}
	}
	return layers
}

func TestOpenVPNStartLayersPreserveOriginalRemotesAndExplicitKeys(t *testing.T) {
	profile, endpoint, probes := remoteProfile(t)
	profileJSON, _ := json.Marshal(profile)
	probeJSON, _ := json.Marshal(probes)
	before, _ := json.Marshal(endpoint)
	for _, mode := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		t.Run(mode, func(t *testing.T) {
			layers := remoteLayers(mode)
			raw, _ := json.Marshal(layers)
			if err := ValidateStartLayers(string(profileJSON), string(probeJSON), string(raw), mode); err != nil {
				t.Fatal(err)
			}
			var decoded StartLayers
			if json.Unmarshal(raw, &decoded) != nil || !reflect.DeepEqual(decoded, layers) {
				t.Fatal("captured private layer map changed")
			}
			if decoded["192.0.2.60"].Transport["password"] == decoded["192.0.2.61"].Transport["password"] {
				t.Fatal("fixture lost distinct provider keys")
			}
			egress, err := StartLayerEgress(string(profileJSON), string(probeJSON), string(raw), mode)
			expected := []LayerEgress{{"192.0.2.60", 8388, "udp"}, {"192.0.2.61", 8390, "tcp"}}
			if mode == "aes-256-gcm+xor-whitening" {
				expected[0].Port, expected[1].Port = 8389, 8389
			}
			if err != nil || !reflect.DeepEqual(egress, expected) {
				t.Fatal("physical layer egress differs from compiled outer transport", egress, err)
			}
			after, _ := json.Marshal(endpoint)
			if string(before) != string(after) {
				t.Fatal("original remote ordering, ports or protocols changed")
			}
			if _, err := SameRemoteHost(endpoint); err == nil {
				t.Fatal("singular-layer distinct-host guard was removed")
			}
		})
	}
}

func TestOpenVPNStartLayersRejectAmbiguousHostLayerAndRawPolicy(t *testing.T) {
	profile, endpoint, probes := remoteProfile(t)
	profileJSON, _ := json.Marshal(profile)
	probeJSON, _ := json.Marshal(probes)
	layers := remoteLayers("aes-256-gcm")
	raw, _ := json.Marshal(layers)
	for name, mutate := range map[string]func(StartLayers){
		"missing host":    func(m StartLayers) { delete(m, "192.0.2.61") },
		"foreign host":    func(m StartLayers) { m["192.0.2.62"] = m["192.0.2.61"] },
		"wrong provider":  func(m StartLayers) { m["192.0.2.61"].Transport["server"] = "192.0.2.60" },
		"private outer":   func(m StartLayers) { m["192.0.2.61"].Transport["server"] = "10.93.0.1" },
		"wrong cipher":    func(m StartLayers) { m["192.0.2.61"].Transport["method"] = "aes-256-gcm" },
		"invalid key":     func(m StartLayers) { m["192.0.2.61"].Transport["password"] = "invalid-key" },
		"key too large":   func(m StartLayers) { m["192.0.2.61"].Transport["password"] = strings.Repeat("a", 4097) },
		"raw detour":      func(m StartLayers) { m["192.0.2.61"].Transport["detour"] = "direct" },
		"invalid port":    func(m StartLayers) { m["192.0.2.61"].Transport["server_port"] = float64(0) },
		"fractional port": func(m StartLayers) { m["192.0.2.61"].Transport["server_port"] = 8388.5 },
		"oversized tag":   func(m StartLayers) { m["192.0.2.61"].Transport["tag"] = strings.Repeat("a", 129) },
		"mixed modes":     func(m StartLayers) { l := m["192.0.2.61"]; l.Mode = "aes-256-gcm+xor-whitening"; m["192.0.2.61"] = l },
		"public service":  func(m StartLayers) { l := m["192.0.2.61"]; l.API = "http://192.0.2.61:8787"; m["192.0.2.61"] = l },
		"API query":       func(m StartLayers) { l := m["192.0.2.61"]; l.API += "?"; m["192.0.2.61"] = l },
		"API username": func(m StartLayers) {
			l := m["192.0.2.61"]
			l.API = "http://private@10.93.0.1:8787"
			m["192.0.2.61"] = l
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed StartLayers
			if json.Unmarshal(raw, &changed) != nil {
				t.Fatal("fixture")
			}
			mutate(changed)
			if changed.Validate(endpoint, probes, "aes-256-gcm") == nil {
				t.Fatal("invalid captured layer accepted")
			}
			encoded, _ := json.Marshal(changed)
			if egress, err := StartLayerEgress(string(profileJSON), string(probeJSON), string(encoded), "aes-256-gcm"); err == nil || egress != nil {
				t.Fatal("invalid layer gained physical policy authority")
			}
		})
	}
	for _, mode := range []string{"", "off", "aes-256-gcm+xor-whitening", "other"} {
		if ValidateStartLayers(string(profileJSON), string(probeJSON), string(raw), mode) == nil {
			t.Fatal("map did not match selected mode")
		}
	}
	for _, invalid := range []string{
		`null`, `{}`, `[]`, string(raw) + ` {}`,
		strings.Replace(string(raw), `"192.0.2.61":`, `"192.0.2.60":`, 1),
		strings.Replace(string(raw), `"mode":`, `"mode":null,"mode":`, 1),
		strings.Replace(string(raw), `"mode":`, `"unknown":"private","mode":`, 1),
		strings.Replace(string(raw), `"server_port":8388`, `"server_port":null`, 1),
		strings.Replace(string(raw), `"password":`, `"password":null,"password":`, 1),
		strings.Repeat(" ", MaxStartLayersBytes) + string(raw),
	} {
		if ValidateStartLayers(string(profileJSON), string(probeJSON), invalid, "aes-256-gcm") == nil {
			t.Fatal("malformed raw map accepted")
		}
	}
}

func TestOpenVPNStartLayerEgressDeduplicatesExactOuterTuple(t *testing.T) {
	profile, _, probes := remoteProfile(t)
	profile.Config += "remote 192.0.2.60 1195 udp\nremote 192.0.2.60 1196 tcp\n"
	profileJSON, _ := json.Marshal(profile)
	probeJSON, _ := json.Marshal(probes)
	layerJSON, _ := json.Marshal(remoteLayers("aes-256-gcm"))
	egress, err := StartLayerEgress(string(profileJSON), string(probeJSON), string(layerJSON), "aes-256-gcm")
	if err != nil {
		t.Fatal(err)
	}
	expected := []LayerEgress{{"192.0.2.60", 8388, "tcp"}, {"192.0.2.60", 8388, "udp"}, {"192.0.2.61", 8390, "tcp"}}
	if !reflect.DeepEqual(egress, expected) {
		t.Fatal("outer tuple dedupe widened network or used inner port", egress)
	}
}
