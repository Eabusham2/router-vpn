//go:build linux && routervpn_controller_privileged

package main

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// Only these exact Off scenarios select the existing independent Hysteria2
// QUIC/TLS/Salamander peer. Each retains the complete installed host assertions.
var linuxHostTUNHysteria2Cases = []string{
	"hy2-public-connect", "hy2-home-lan", "hy2-wrong-key", "hy2-wrong-trust", "hy2-wrong-salamander",
	"hy2-resolver-failure", "hy2-wrong-node", "hy2-active-network-change", "hy2-cancelled-proof",
	"hy2-restore-sealed", "hy2-always", "hy2-cover-connect", "hy2-cover-restore", "hy2-mtu-rollback", "hy2-mtu-commit",
}

func linuxHostTUNHysteria2Case(scenario string) bool {
	for _, value := range linuxHostTUNHysteria2Cases {
		if value == scenario {
			return true
		}
	}
	return linuxHostTUNHysteria2LayerCase(scenario)
}

func linuxHostTUNHysteria2Assets(t *testing.T, peer *linuxHostTUNPeer, scenario string) map[string][]byte {
	t.Helper()
	if peer.mode != "hysteria2" || peer.layer != linuxHostTUNHysteria2Layer(scenario) || !linuxHostTUNHysteria2Case(scenario) || peer.protocolFiles == "" {
		t.Fatal("installed Hysteria2 lost its captured peer/layer configuration")
	}
	var encoded map[string]string
	if json.Unmarshal([]byte(peer.protocolFiles), &encoded) != nil || len(encoded) != 2 || encoded["sing-box.json"] == "" || encoded["cert.pem"] == "" {
		t.Fatal("installed Hysteria2 lost its complete independent configuration and CA")
	}
	assets := make(map[string][]byte, len(encoded))
	for name, value := range encoded {
		raw, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || len(raw) == 0 || len(raw) > 32<<10 || base64.StdEncoding.EncodeToString(raw) != value {
			t.Fatal("installed Hysteria2 changed its exact private source bytes", err)
		}
		assets[name] = raw
	}
	var graph struct {
		Outbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			Server     string `json:"server"`
			ServerPort int    `json:"server_port"`
			Password   string `json:"password"`
			Obfs       struct {
				Type     string `json:"type"`
				Password string `json:"password"`
			} `json:"obfs"`
			TLS struct {
				Enabled         bool   `json:"enabled"`
				Insecure        bool   `json:"insecure"`
				ServerName      string `json:"server_name"`
				CertificatePath string `json:"certificate_path"`
			} `json:"tls"`
		} `json:"outbounds"`
	}
	if json.Unmarshal(assets["sing-box.json"], &graph) != nil || len(graph.Outbounds) != 1 {
		t.Fatal("installed Hysteria2 has another independent transport graph")
	}
	out := graph.Outbounds[0]
	endpoint := peer.address
	if peer.layer != "" {
		endpoint = peer.baseAddress
	}
	if out.Type != "hysteria2" || out.Tag != "proxy" || out.Server != endpoint.Addr().String() || out.ServerPort != int(endpoint.Port()) ||
		out.Password == "" || out.Obfs.Type != "salamander" || out.Obfs.Password == "" || out.Obfs.Password == out.Password ||
		!out.TLS.Enabled || out.TLS.Insecure || out.TLS.ServerName != "captured-node.test" || out.TLS.CertificatePath != "cert.pem" {
		t.Fatal("installed Hysteria2 changed the captured UDP endpoint, authentication, Salamander or selected trust")
	}
	// Positive cases copy both original byte strings without reserialization.
	// Negative cases change only their named authentication/trust field.
	action := linuxHostTUNAction(scenario)
	if action == "wrong-key" || action == "wrong-trust" || action == "wrong-salamander" {
		var changed map[string]any
		if err := json.Unmarshal(assets["sing-box.json"], &changed); err != nil {
			t.Fatal(err)
		}
		outer := changed["outbounds"].([]any)[0].(map[string]any)
		switch action {
		case "wrong-key":
			outer["password"] = out.Password + "-wrong"
		case "wrong-trust":
			outer["tls"].(map[string]any)["server_name"] = "wrong-node.test"
		case "wrong-salamander":
			outer["obfs"].(map[string]any)["password"] = out.Obfs.Password + "-wrong"
		}
		raw, err := json.Marshal(changed)
		if err != nil {
			t.Fatal(err)
		}
		assets["sing-box.json"] = raw
	}
	return assets
}
