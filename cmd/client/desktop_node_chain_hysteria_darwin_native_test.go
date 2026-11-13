//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

type macOSNodeChainHysteriaObservation struct {
	CA           string `json:"ca"`
	ServerName   string `json:"server_name"`
	RawUDP       int64  `json:"raw_udp"`
	TCP          int64  `json:"tcp"`
	UDP          int64  `json:"udp"`
	AuthFailures uint32 `json:"auth_failures"`
}

func macOSNodeChainHysteriaCipherCases() []macOSNodeChainCipherCase {
	return []macOSNodeChainCipherCase{
		{"wg-wg", "node-chain-hy2-wg-wg-", []string{"wg", "wg"}},
		{"awg-fast-awg-strong", "node-chain-hy2-awg-fast-awg-strong-", []string{"awg2-fast", "awg2-strong"}},
		{"awg-strong-awg-fast", "node-chain-hy2-awg-strong-awg-fast-", []string{"awg2-strong", "awg2-fast"}},
	}
}

func macOSNodeChainHysteriaHostCases() []string {
	return []string{
		"node-chain-hy2-wg-wg-connect",
		"node-chain-hy2-awg-fast-awg-strong-connect",
		"node-chain-hy2-awg-strong-awg-fast-connect",
		"node-chain-hy2-wg-wg-final-password",
		"node-chain-hy2-wg-wg-final-trust",
		"node-chain-hy2-wg-wg-final-mask",
		"node-chain-hy2-wg-wg-final-dns-failure",
		"node-chain-hy2-wg-wg-middle-source",
		"node-chain-hy2-wg-wg-prefix-lost",
	}
}

func macOSNodeChainHysteriaScenario(scenario string) ([]string, string, bool) {
	for _, item := range macOSNodeChainHysteriaCipherCases() {
		if action, ok := strings.CutPrefix(scenario, item.prefix); ok {
			return append([]string(nil), item.modes...), action, true
		}
	}
	return nil, "", false
}

func macOSNodeChainHysteriaCredentials(t *testing.T, peer *macOSNodeChainPeer) {
	t.Helper()
	if peer.middlePassword != "" {
		t.Fatal("paired Hysteria2 final cannot acquire an imported middle")
	}
	secret := func() string {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(raw)
	}
	peer.hysteriaPassword, peer.hysteriaMask = secret(), secret()
}

func macOSNodeChainHysteriaReadback(t *testing.T, peer *macOSNodeChainPeer, reply macOSNodeChainPeerReply) {
	t.Helper()
	if peer.hysteriaPassword == "" {
		if reply.Hysteria != nil {
			t.Fatal("SS reference acquired foreign Hysteria2 authority")
		}
		return
	}
	h := reply.Hysteria
	if h == nil || h.ServerName != "captured-final.example" || len(h.CA) == 0 || len(h.CA) > 16384 {
		t.Fatal("Hysteria2 peer lost its original bounded TLS identity")
	}
	block, rest := pem.Decode([]byte(h.CA))
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatal("Hysteria2 peer CA is not its original certificate")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatal(err)
	}
	if original := peer.reply.Hysteria; original != nil && (original.CA != h.CA || original.ServerName != h.ServerName) {
		t.Fatal("Hysteria2 peer replaced its original TLS identity")
	}
}

func macOSNodeChainHysteriaAssets(t *testing.T, peer *macOSNodeChainPeer, fault string) map[string][]byte {
	t.Helper()
	if peer.reply.Hysteria == nil || peer.hysteriaPassword == "" || peer.hysteriaMask == "" || peer.middlePassword != "" {
		t.Fatal("installed Hysteria2 source lost its original paired identity")
	}
	password, mask, ca := peer.hysteriaPassword, peer.hysteriaMask, peer.reply.Hysteria.CA
	switch fault {
	case "final-password":
		password += "-wrong"
	case "final-mask":
		mask += "-wrong"
	case "final-trust":
		ca, _ = nativeMultihopTrafficCertificate(t)
	}
	graph, err := json.Marshal(map[string]any{
		"inbounds": []any{map[string]any{"type": "tun", "tag": "tun-in", "auto_route": true, "strict_route": true}},
		"outbounds": []any{map[string]any{"type": "hysteria2", "tag": "proxy", "server": "10.77.0.1", "server_port": 443,
			"password": password, "obfs": map[string]any{"type": "salamander", "password": mask},
			"tls": map[string]any{"enabled": true, "server_name": peer.reply.Hysteria.ServerName, "certificate_path": "cert.pem"}}},
		"route": map[string]any{"final": "proxy"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{"sing-box.json": graph, "cert.pem": []byte(ca)}
}

func macOSNodeChainHysteriaCounters(t *testing.T, peer *macOSNodeChainPeer, reply macOSNodeChainPeerReply, action string) {
	t.Helper()
	if peer.hysteriaPassword == "" {
		return
	}
	h := reply.Hysteria
	if h == nil || h.RawUDP == 0 || reply.Final.FinalRawTCP != 0 || reply.Final.FinalRawUDP != 0 || reply.Final.FinalTCP != 0 || reply.Final.FinalUDP != 0 {
		t.Fatal("installed final did not use only original encrypted Hysteria2", reply)
	}
	if action == "final-password" || action == "final-trust" || action == "final-mask" {
		if h.TCP != 0 || h.UDP != 0 || reply.Final.RouterQueries != 0 || reply.Final.DNSQueries != 0 || reply.Final.FinalPublicQueries != 0 {
			t.Fatal("invalid final dependency reached authenticated inner service", action, reply)
		}
		if action == "final-password" && h.AuthFailures == 0 {
			t.Fatal("wrong Hysteria2 password did not reach native authentication", reply)
		}
	} else if action == "final-dns-failure" && h.UDP == 0 {
		t.Fatal("selected DNS refusal never traversed original Hysteria2 UDP", reply)
	} else if action != "final-dns-failure" && (h.TCP == 0 || h.UDP == 0) {
		t.Fatal("installed Hysteria2 final omitted actual TCP and selected DNS UDP", reply)
	}
}

func TestDesktopDarwinInstalledHysteriaNodeChainFixtureKeepsOriginalSources(t *testing.T) {
	for _, scenario := range macOSNodeChainHysteriaCipherCases() {
		t.Run(scenario.name, func(t *testing.T) {
			peer := macOSNodeChainPeerKeys(t, len(scenario.modes)+1)
			macOSNodeChainSetModes(t, peer, scenario.modes)
			macOSNodeChainHysteriaCredentials(t, peer)
			peer.reply.Address = "192.168.210.2:51820"
			ca, _ := nativeMultihopTrafficCertificate(t)
			peer.reply.Hysteria = &macOSNodeChainHysteriaObservation{CA: ca, ServerName: "exit-certificate.example"}
			profiles, assets := macOSNodeChainInstalledSources(t, peer, "")
			root := t.TempDir()
			for id, modes := range assets {
				for mode, files := range modes {
					directory := filepath.Join(root, "generated", id, mode)
					if err := os.MkdirAll(directory, 0700); err != nil {
						t.Fatal(err)
					}
					for name, body := range files {
						if err := os.WriteFile(filepath.Join(directory, name), body, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			final := profiles.Profiles[len(profiles.Profiles)-1]
			capture, err := captureDesktopNodeChain(context.Background(), root, final, profiles.Profiles, final.MultihopNodes, "local", nil)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := mobilemultihop.NewDesktopNodeChainPolicy(capture.chain, strings.Repeat("b", 32), "darwin", 0)
			if err != nil {
				t.Fatal(err)
			}
			physical, err := policy.NodeChain().PhysicalEgress()
			if err != nil || len(physical) != 1 || physical[0].Host != "192.168.210.2" || len(policy.NodeChain().ProofInventory()) != 3 {
				t.Fatal("installed Hysteria2 path lost original complete paired authority", err)
			}
			launch, err := capture.chain.LaunchInput()
			if err != nil {
				t.Fatal(err)
			}
			var source mobilemultihop.NodeChainSource
			if json.Unmarshal([]byte(launch), &source) != nil || source.Schema != 1 || source.Execution != "local" || len(source.Nodes) != 3 {
				t.Fatal("installed Hysteria2 changed source kind or scope")
			}
			var original struct {
				Mode    string `json:"mode"`
				Files   string `json:"files"`
				Profile string `json:"profile_json"`
			}
			if json.Unmarshal([]byte(source.Nodes[2]), &original) != nil || original.Mode != "hysteria2" {
				t.Fatal("installed final substituted SS mode")
			}
			var files map[string]string
			if json.Unmarshal([]byte(original.Files), &files) != nil || len(files) != 2 {
				t.Fatal("installed final lost complete source assets")
			}
			for name, body := range assets[final.ID]["hysteria2"] {
				if files[name] != base64.StdEncoding.EncodeToString(body) {
					t.Fatal("installed final replaced original asset", name)
				}
			}
			var originalProfile common.RouterProfile
			if json.Unmarshal([]byte(original.Profile), &originalProfile) != nil || originalProfile.ID != final.ID || originalProfile.NodeProofID != final.NodeProofID || originalProfile.APIToken != final.APIToken || originalProfile.StartLayer != "off" {
				t.Fatal("installed final lost original paired proof or Off layer")
			}
			var compiled struct {
				Outbounds []map[string]any `json:"outbounds"`
			}
			if json.Unmarshal([]byte(capture.chain.Config()), &compiled) != nil {
				t.Fatal("compiled Hysteria2 graph unavailable")
			}
			found := 0
			for _, row := range compiled.Outbounds {
				if row["type"] == "hysteria2" {
					found++
					tls, ok := row["tls"].(map[string]any)
					obfs, ok2 := row["obfs"].(map[string]any)
					if !ok || !ok2 || row["server"] != "10.77.0.1" || row["server_port"] != float64(443) || row["password"] != peer.hysteriaPassword || tls["server_name"] != peer.reply.Hysteria.ServerName || tls["insecure"] == true || obfs["type"] != "salamander" || obfs["password"] != peer.hysteriaMask || row["detour"] == nil {
						t.Fatal("compiled installed final substituted TLS, password, Salamander or packet prefix")
					}
				}
			}
			if found != 1 {
				t.Fatal("compiled installed graph did not retain exactly one Hysteria2 final")
			}
			changed := append([]common.RouterProfile(nil), profiles.Profiles...)
			changed[len(changed)-1].StartLayer = "tls"
			if _, err := captureDesktopNodeChain(context.Background(), root, changed[len(changed)-1], changed, final.MultihopNodes, "local", nil); err == nil {
				t.Fatal("installed Hysteria2 final admitted a Start Layer")
			}
			if _, err := captureDesktopNodeChain(context.Background(), root, final, profiles.Profiles, final.MultihopNodes, "server", nil); err == nil {
				t.Fatal("installed Hysteria2 final escaped Local scope")
			}
		})
	}
}

func TestDesktopDarwinHysteriaReferencePhysicalCapture(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("ROUTERVPN_DARWIN_NODE_CHAIN_REFERENCE") != "1" ||
		os.Getenv("ROUTERVPN_DARWIN_NODE_CHAIN_CAPTURE") != "1" || os.Getenv("ROUTERVPN_DARWIN_NODE_CHAIN_ADDRESS") != "" {
		t.Fatal("Darwin reference capture requires its original elevated discovery invocation")
	}
	// Reuse the installed fixture's actual default-route/interface readback.
	// This emits no socket, TUN, PF or application forwarding authority.
	address := macOSExternalNativeAddress(t)
	t.Logf("ROUTERVPN_DARWIN_NODE_CHAIN_CAPTURED_IPV4=%s", address.String())
}
