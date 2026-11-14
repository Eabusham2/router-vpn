//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/nativecomposite"
)

var linuxNodeChainCONNECTHostCases = []string{
	"node-chain-connect-http-wg-connect", "node-chain-connect-http-awg-fast-connect", "node-chain-connect-http-awg-strong-connect",
	"node-chain-connect-https-wg-connect", "node-chain-connect-https-awg-fast-connect", "node-chain-connect-https-awg-strong-connect",
	"node-chain-connect-http-wg-wrong-middle-key", "node-chain-connect-http-wg-wrong-middle-user", "node-chain-connect-http-wg-wrong-middle-public",
	"node-chain-connect-http-wg-final-dns-failure", "node-chain-connect-http-wg-final-node-failure", "node-chain-connect-http-wg-middle-source", "node-chain-connect-http-wg-prefix-lost",
	"node-chain-connect-https-wg-wrong-middle-key", "node-chain-connect-https-wg-wrong-middle-user", "node-chain-connect-https-wg-wrong-middle-public",
	"node-chain-connect-https-wg-final-dns-failure", "node-chain-connect-https-wg-final-node-failure", "node-chain-connect-https-wg-middle-source", "node-chain-connect-https-wg-prefix-lost",
	"node-chain-connect-https-wg-wrong-middle-sni", "node-chain-connect-https-wg-wrong-middle-trust",
}

func linuxNodeChainCONNECTCipherCases() []linuxNodeChainCipherCase {
	var cases []linuxNodeChainCipherCase
	for _, protocol := range []string{"http", "https"} {
		for _, entry := range []struct{ mode, label string }{{"wg", "wg"}, {"awg2-fast", "awg-fast"}, {"awg2-strong", "awg-strong"}} {
			name := protocol + "/" + entry.mode
			cases = append(cases, linuxNodeChainCipherCase{name, "node-chain-connect-" + protocol + "-" + entry.label + "-", []string{entry.mode, protocol + "-connect"}})
		}
	}
	return cases
}

func linuxNodeChainCONNECTProfile(t *testing.T, peer *linuxNodeChainPeer, fault string) common.RouterProfile {
	t.Helper()
	proxy := &common.ExternalHTTPConnectConfig{Host: "10.79.0.1", Port: 1080, Username: "captured-native-user", Password: peer.middlePassword}
	if fault == "wrong-middle-key" {
		proxy.Password += "-wrong"
	}
	if fault == "wrong-middle-user" {
		proxy.Username += "-wrong"
	}
	ext := &common.ExternalNodeConfig{Protocol: peer.middleCONNECT, ExpectedPublicIP: "203.0.113.88"}
	switch peer.middleCONNECT {
	case "http-connect":
		ext.HTTPConnect = proxy
	case "https-connect":
		proxy.TLSServerName = peer.reply.CONNECTServerName
		if fault == "wrong-middle-sni" {
			proxy.TLSServerName = "wrong-original-connect.routervpn.test"
		}
		ext.HTTPSConnect = proxy
	default:
		t.Fatal("installed CONNECT profile lost its exact original protocol")
	}
	profile := common.RouterProfile{ID: "installed-original-connect-middle", Name: "Original imported CONNECT middle", NodeKind: "external", Endpoint: "10.79.0.1", External: ext,
		DNSMode: "rescue", IPv6Mode: "off", StartLayer: "off", MTUPolicy: "auto", KillSwitch: true, KillSwitchPolicy: "on-connect"}
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		t.Fatal(err)
	}
	return profile
}

func linuxNodeChainCONNECTNegative(action string) bool {
	return action == "wrong-middle-user" || action == "wrong-middle-sni" || action == "wrong-middle-trust"
}

func linuxNodeChainCONNECTFinalAssets(t *testing.T, peer *linuxNodeChainPeer, final common.RouterProfile, files map[string][]byte) {
	t.Helper()
	raw := files["sing-box.json"]
	var graph map[string]any
	if json.Unmarshal(raw, &graph) != nil {
		t.Fatal("installed CONNECT final lost original SS source")
	}
	outbounds, ok := graph["outbounds"].([]any)
	if !ok || len(outbounds) != 1 {
		t.Fatal("installed CONNECT final lost original single SS carrier")
	}
	out, ok := outbounds[0].(map[string]any)
	if !ok || len(out) != 6 || out["type"] != "shadowsocks" || out["password"] != peer.password || out["server"] != "10.77.0.1" || out["server_port"] != float64(8388) {
		t.Fatal("installed CONNECT final replaced paired SS credentials")
	}
	// Keep the original SS bytes unchanged. The captured service declaration
	// authorizes the compiler, rather than the fixture, to derive UoT-v2.
	configHash, keyHash := sha256.Sum256(raw), sha256.Sum256([]byte(peer.password))
	declaration, err := json.Marshal(map[string]any{"schema": 1, "node_id": final.NodeProofID,
		"configured_image": nativecomposite.SSServiceImage, "uot_version": 2, "endpoint": out["server"], "port": out["server_port"], "method": out["method"],
		"source_sha256": hex.EncodeToString(configHash[:]), "key_sha256": hex.EncodeToString(keyHash[:])})
	if err != nil {
		t.Fatal(err)
	}
	files[nativecomposite.SSServiceAsset] = declaration
}

func linuxNodeChainCONNECTReadback(t *testing.T, peer *linuxNodeChainPeer, reply linuxNodeChainPeerReply) {
	t.Helper()
	if peer.middleCONNECT == "" {
		if reply.CONNECTProtocol != "" || reply.CONNECTCA != "" || reply.CONNECTServerName != "" || reply.OpenCONNECTStreams != nil || reply.FinalUOTVersion != 0 {
			t.Fatal("ordinary installed peer acquired CONNECT authority")
		}
		return
	}
	if reply.CONNECTProtocol != peer.middleCONNECT || reply.OpenCONNECTStreams == nil || *reply.OpenCONNECTStreams < 0 || reply.FinalUOTVersion != 2 ||
		reply.CONNECTAuthRefusals < 0 || reply.CONNECTTargetRefusals < 0 || reply.CONNECTTLSRefusals < 0 {
		t.Fatal("installed CONNECT peer lost its exact protocol, stream or final UoT identity")
	}
	if peer.middleCONNECT == "https-connect" {
		if reply.CONNECTServerName != "speed.cloudflare.com" || reply.CONNECTCA == reply.PublicCA || !x509.NewCertPool().AppendCertsFromPEM([]byte(reply.CONNECTCA)) {
			t.Fatal("installed HTTPS peer lost its separate captured TLS trust")
		}
	} else if reply.CONNECTCA != "" || reply.CONNECTServerName != "" || reply.CONNECTTLSRefusals != 0 {
		t.Fatal("installed plain HTTP peer acquired HTTPS authority")
	}
	if peer.reply.CONNECTProtocol != "" && (peer.reply.CONNECTProtocol != reply.CONNECTProtocol || peer.reply.CONNECTCA != reply.CONNECTCA || peer.reply.CONNECTServerName != reply.CONNECTServerName) {
		t.Fatal("installed CONNECT peer replaced its captured protocol or TLS identity")
	}
	if reply.Middle == nil || reply.Middle.RawUDP != 0 || reply.Middle.UDP != 0 || reply.Final.FinalRawUDP != 0 {
		t.Fatal("installed CONNECT middle or final acquired an uncaptured UDP socket")
	}
}

func linuxNodeChainCONNECTPositiveCounters(t *testing.T, reply linuxNodeChainPeerReply) {
	t.Helper()
	middle := reply.Middle
	if middle == nil || middle.RawTCP == 0 || middle.TCP == 0 || middle.RawUDP != 0 || middle.UDP != 0 || middle.PublicQueries == 0 ||
		middle.DownloadBytes < 8<<20 || middle.UploadBytes < 8<<20 || reply.Final.FinalRawTCP == 0 || reply.Final.FinalRawUDP != 0 || reply.Final.FinalUDP == 0 ||
		reply.Final.DNSQueries == 0 || reply.FinalUOTVersion != 2 || reply.CONNECTAuthRefusals != 0 || reply.CONNECTTargetRefusals != 0 || reply.CONNECTTLSRefusals != 0 {
		t.Fatal("installed CONNECT path omitted authenticated TCP, selected final UoT DNS or complete transfer", middle, reply.Final)
	}
}

func linuxNodeChainCONNECTNegativeCounters(t *testing.T, reply linuxNodeChainPeerReply, action string) {
	t.Helper()
	middle := reply.Middle
	if middle == nil || middle.RawUDP != 0 || middle.UDP != 0 || reply.Final.FinalRawUDP != 0 {
		t.Fatal("CONNECT refusal acquired a direct UDP path")
	}
	switch action {
	case "wrong-middle-key", "wrong-middle-user":
		if middle.RawTCP == 0 || reply.CONNECTAuthRefusals == 0 || middle.TCP != 0 || middle.PublicQueries != 0 || reply.Final.RouterQueries != 0 {
			t.Fatal("wrong CONNECT credential did not fail at the original authenticated proxy", reply)
		}
	case "wrong-middle-sni", "wrong-middle-trust":
		if middle.RawTCP == 0 || reply.CONNECTTLSRefusals == 0 || middle.TCP != 0 || middle.PublicQueries != 0 || reply.Final.RouterQueries != 0 {
			t.Fatal("wrong CONNECT TLS identity did not fail at the original certificate", reply)
		}
	case "wrong-middle-public":
		if middle.TCP == 0 || middle.PublicQueries == 0 || reply.Final.RouterQueries != 0 {
			t.Fatal("wrong CONNECT public identity failed before its original routed proof", reply)
		}
	}
}

func linuxNodeChainCONNECTClose(t *testing.T, peer *linuxNodeChainPeer) {
	t.Helper()
	if err := peer.output.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(peer.input, "quit\n"); err != nil {
		t.Fatal(err)
	}
	tail, err := io.ReadAll(io.LimitReader(peer.reader, 16385))
	if err != nil || len(tail) > 16384 || strings.Count(string(tail), "CONNECT_INSTALLED_PEER_JOINED\n") != 1 || !strings.Contains(string(tail), "PASS\n") || strings.Contains(string(tail), "FAIL") {
		t.Fatal("installed CONNECT peer did not report its actual bounded joined cleanup", err, string(tail))
	}
	select {
	case <-peer.done:
		if peer.waitErr != nil {
			t.Fatal("installed CONNECT peer did not exit cleanly", peer.waitErr, peer.diagnostic.String())
		}
	case <-time.After(time.Second):
		t.Fatal("installed CONNECT peer returned EOF before its original process joined")
	}
}

func TestDesktopLinuxInstalledCONNECTNodeChainFixtureKeepsOriginalSources(t *testing.T) {
	for _, scenario := range linuxNodeChainCONNECTCipherCases() {
		t.Run(scenario.name, func(t *testing.T) {
			peer := linuxNodeChainPeerForModes(t, scenario.modes)
			peer.reply.Address = net.JoinHostPort("192.168.210.2", "51820")
			peer.reply.CONNECTServerName = "original-connect.routervpn.test"
			profiles, assets := linuxNodeChainInstalledSources(t, peer, "")
			middle := profiles.Profiles[1]
			proxy := middle.External.HTTPConnect
			if scenario.modes[1] == "https-connect" {
				proxy = middle.External.HTTPSConnect
			}
			if len(profiles.Profiles) != 3 || len(peer.requests) != 1 || middle.NodeKind != "external" || middle.NodeProofID != "" || middle.APIToken != "" || middle.RouterAPI != "" || assets[middle.ID] != nil ||
				middle.External.Protocol != scenario.modes[1] || proxy == nil || proxy.Password != peer.middlePassword || proxy.Username != "captured-native-user" ||
				(scenario.modes[1] == "https-connect" && proxy.TLSServerName != peer.reply.CONNECTServerName) || (scenario.modes[1] == "http-connect" && proxy.TLSServerName != "") {
				t.Fatal("installed source changed original CONNECT protocol, credential or TLS authority, or invented paired assets")
			}
			root := t.TempDir()
			for id, modes := range assets {
				for mode, files := range modes {
					directory := filepath.Join(root, "generated", id, mode)
					if err := os.MkdirAll(directory, 0700); err != nil {
						t.Fatal(err)
					}
					for name, raw := range files {
						if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			control := profiles.Profiles[2]
			selection, err := resolveDesktopNodeChainSelection(control, profiles.Profiles, control.MultihopNodes, "local")
			if err != nil {
				t.Fatal(err)
			}
			selection, err = captureNativeNodeChainSelection(context.Background(), root, selection, []string{"shadowsocks"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), "linux")
			if err != nil {
				t.Fatal(err)
			}
			if launch.chain.policy != nil || launch.chain.socksPolicy != nil || selection.Native.chain.chain != nil || selection.Native.chain.socks != nil || launch.chain.connectPolicy == nil {
				t.Fatal("installed CONNECT source acquired generic or SOCKS authority")
			}
			_, meta, physical, err := launch.chain.readPolicy()
			if err != nil || len(meta.Prefixes) != 3 || meta.Prefixes[0].Mode != scenario.modes[0] || meta.Prefixes[1].Mode != scenario.modes[1] || meta.Prefixes[1].NodeID != "" || meta.Prefixes[1].Kind != "public-path" ||
				meta.Prefixes[1].ProfileID != middle.ID || meta.Prefixes[2].NodeID != control.NodeProofID || len(physical.PhysicalRoots) != 1 || physical.PhysicalRoots[0].Destinations[0].Host != "192.168.210.2" {
				t.Fatal("installed CONNECT source lost original proof or physical identity", err)
			}
			var source mobilemultihop.NodeChainSource
			if json.Unmarshal([]byte(selection.Native.chain.connect.original.input), &source) != nil || source.Schema != 4 || source.IdentitySources[1] != "" {
				t.Fatal("installed CONNECT source acquired paired middle identity")
			}
			var envelope struct {
				Config  string `json:"config"`
				Capture string `json:"capture"`
			}
			var captured struct {
				Profile common.RouterProfile `json:"profile"`
			}
			if json.Unmarshal([]byte(source.Nodes[1]), &envelope) != nil || json.Unmarshal([]byte(envelope.Capture), &captured) != nil || !reflect.DeepEqual(captured.Profile, middle) {
				t.Fatal("installed CONNECT source changed its original complete imported policy")
			}
			for _, named := range linuxNodeChainCONNECTHostCases {
				if !strings.HasPrefix(named, scenario.prefix) {
					continue
				}
				modes, action, err := linuxNodeChainScenario(named)
				if err != nil || fmt.Sprint(modes) != fmt.Sprint(scenario.modes) || named != scenario.prefix+action {
					t.Fatal("installed CONNECT case changed its exact native inventory", err)
				}
			}
		})
	}
}
