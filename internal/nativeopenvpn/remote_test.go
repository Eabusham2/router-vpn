package nativeopenvpn

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func remoteProfile(t *testing.T) (Profile, map[string]any, ResponseProbes) {
	t.Helper()
	profile := openVPNProfile("", "")
	profile.Username, profile.Password = "local-provider", "private-provider-password"
	profile.Config += "remote 192.0.2.61 443 tcp4\nremote-random\n"
	endpoint, err := CompileProfile(profile, "exit", "")
	if err != nil {
		t.Fatal(err)
	}
	probes := ResponseProbes{
		"192.0.2.60": {URL: "https://192.0.2.60/response", ServerName: "provider.example"},
		"192.0.2.61": {URL: "https://192.0.2.61:9443/response", ServerName: "provider.example"},
	}
	return profile, endpoint, probes
}

func TestOpenVPNRemoteProofMapRetainsExactHostPortAndProtocol(t *testing.T) {
	profile, endpoint, probes := remoteProfile(t)
	remotes, err := Remotes(endpoint)
	if err != nil || len(remotes) != 2 || remotes[0] != (Remote{"192.0.2.60", 1194, "udp"}) || remotes[1] != (Remote{"192.0.2.61", 443, "tcp"}) {
		t.Fatal("captured transport list changed", err)
	}
	if err := probes.Validate(endpoint); err != nil {
		t.Fatal(err)
	}
	profileJSON, _ := json.Marshal(profile)
	probeJSON, _ := json.Marshal(probes)
	if err := ValidateResponseProbesJSON(string(profileJSON), string(probeJSON)); err != nil {
		t.Fatal(err)
	}
	server := profile
	server.Username, server.Password = "server-provider", "other-private-password"
	descriptor, err := DescribePeer(server, openVPNAuthKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidatePairing(profile, Pairing{PrivateKey: openVPNAuthKey(t), Server: descriptor}); err != nil {
		t.Fatal("independent multi-host owners rejected", err)
	}
	if _, err := SameRemoteHost(endpoint); err == nil {
		t.Fatal("single-endpoint proof accepted distinct hosts")
	}
	receipt := RemoteReceipt{Remote: remotes[1], Generation: 7, ConnectedAt: time.Now().UnixMilli()}
	if !receipt.Matches(endpoint) {
		t.Fatal("actual second remote receipt rejected")
	}
	for name, mutate := range map[string]func(*RemoteReceipt){
		"wrong host":        func(r *RemoteReceipt) { r.Host = "192.0.2.62" },
		"wrong port":        func(r *RemoteReceipt) { r.Port = 1194 },
		"wrong network":     func(r *RemoteReceipt) { r.Network = "udp" },
		"no generation":     func(r *RemoteReceipt) { r.Generation = 0 },
		"unsafe generation": func(r *RemoteReceipt) { r.Generation = 1 << 53 },
		"not connected":     func(r *RemoteReceipt) { r.ConnectedAt = 0 },
		"hostname":          func(r *RemoteReceipt) { r.Host = "provider.example" },
		"loopback":          func(r *RemoteReceipt) { r.Host = "127.0.0.1" },
	} {
		t.Run(name, func(t *testing.T) {
			other := receipt
			mutate(&other)
			if other.Matches(endpoint) {
				t.Fatal("unowned native remote accepted")
			}
		})
	}
	encoded, _ := json.Marshal(receipt)
	var decoded RemoteReceipt
	if json.Unmarshal(encoded, &decoded) != nil || decoded != receipt {
		t.Fatal("native receipt roundtrip changed")
	}
	for _, raw := range []string{`null`, `[]`, strings.Replace(string(encoded), `"generation":7`, `"generation":7,"generation":8`, 1), strings.Replace(string(encoded), `"generation":7`, `"generation":null`, 1), strings.TrimSuffix(string(encoded), "}") + `,"challenge":"private"}`, string(encoded) + ` {}`} {
		if json.Unmarshal([]byte(raw), &decoded) == nil {
			t.Fatal("ambiguous or private receipt accepted")
		}
	}
}

func TestOpenVPNResponseMapRejectsMissingForeignAmbiguousAndUnverifiedEndpoints(t *testing.T) {
	profile, endpoint, probes := remoteProfile(t)
	profileJSON, _ := json.Marshal(profile)
	raw, _ := json.Marshal(probes)
	for name, mutate := range map[string]func(ResponseProbes){
		"missing remote":    func(p ResponseProbes) { delete(p, "192.0.2.61") },
		"foreign remote":    func(p ResponseProbes) { p["192.0.2.62"] = ResponseEndpoint{URL: "https://192.0.2.62/response"} },
		"HTTP downgrade":    func(p ResponseProbes) { p["192.0.2.61"] = ResponseEndpoint{URL: "http://192.0.2.61/response"} },
		"other-node timing": func(p ResponseProbes) { p["192.0.2.61"] = ResponseEndpoint{URL: "https://192.0.2.60/response"} },
		"public echo":       func(p ResponseProbes) { p["192.0.2.61"] = ResponseEndpoint{URL: "https://1.1.1.1/response"} },
		"query": func(p ResponseProbes) {
			p["192.0.2.61"] = ResponseEndpoint{URL: "https://192.0.2.61/response?secret=x"}
		},
		"private TLS name": func(p ResponseProbes) {
			p["192.0.2.61"] = ResponseEndpoint{URL: "https://192.0.2.61/response", ServerName: "localhost"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var copy ResponseProbes
			if json.Unmarshal(raw, &copy) != nil {
				t.Fatal("fixture")
			}
			mutate(copy)
			if copy.Validate(endpoint) == nil {
				t.Fatal("invalid proof map accepted")
			}
		})
	}
	for _, invalid := range []string{
		`null`, `{}`, `[]`, string(raw) + `{}`,
		strings.Replace(string(raw), `"192.0.2.61":`, `"192.0.2.60":`, 1),
		strings.Replace(string(raw), `"url":`, `"unknown":"secret","url":`, 1),
		strings.Replace(string(raw), `"url":`, `"url":null,"url":`, 1),
		strings.Replace(string(raw), `"server_name":"provider.example"`, `"server_name":null`, 1),
	} {
		if ValidateResponseProbesJSON(string(profileJSON), invalid) == nil {
			t.Fatal("malformed raw response map accepted")
		}
	}
}
