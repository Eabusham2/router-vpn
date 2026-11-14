//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/nativecomposite"
)

const macOSNodeChainCONNECTFiftyReceipt = "actual installed Darwin CONNECT fifty: all three original members returned fifty samples and retained exact durable receipts"
const macOSNodeChainCONNECTStreamsReceipt = "actual installed Darwin CONNECT streams: original authenticated TCP owners joined before controller release"

var macOSNodeChainCONNECTHostCases = []string{
	"node-chain-http-connect-wg-connect",
	"node-chain-http-connect-awg-fast-connect",
	"node-chain-http-connect-awg-strong-connect",
	"node-chain-http-connect-wg-wrong-middle-key",
	"node-chain-http-connect-wg-wrong-middle-user",
	"node-chain-http-connect-wg-wrong-middle-public",
	"node-chain-http-connect-wg-final-dns-failure",
	"node-chain-http-connect-wg-final-node-failure",
	"node-chain-http-connect-wg-middle-source",
	"node-chain-http-connect-wg-prefix-lost",
	"node-chain-https-connect-wg-connect",
	"node-chain-https-connect-awg-fast-connect",
	"node-chain-https-connect-awg-strong-connect",
	"node-chain-https-connect-wg-wrong-middle-key",
	"node-chain-https-connect-wg-wrong-middle-user",
	"node-chain-https-connect-wg-wrong-middle-public",
	"node-chain-https-connect-wg-final-dns-failure",
	"node-chain-https-connect-wg-final-node-failure",
	"node-chain-https-connect-wg-middle-source",
	"node-chain-https-connect-wg-prefix-lost",
	"node-chain-https-connect-wg-tls-name",
	"node-chain-https-connect-wg-tls-trust",
}

func macOSNodeChainCONNECTCipherCases() []macOSNodeChainCipherCase {
	return []macOSNodeChainCipherCase{
		{"http-wg", "node-chain-http-connect-wg-", []string{"wg", "http-connect"}},
		{"http-awg-fast", "node-chain-http-connect-awg-fast-", []string{"awg2-fast", "http-connect"}},
		{"http-awg-strong", "node-chain-http-connect-awg-strong-", []string{"awg2-strong", "http-connect"}},
		{"https-wg", "node-chain-https-connect-wg-", []string{"wg", "https-connect"}},
		{"https-awg-fast", "node-chain-https-connect-awg-fast-", []string{"awg2-fast", "https-connect"}},
		{"https-awg-strong", "node-chain-https-connect-awg-strong-", []string{"awg2-strong", "https-connect"}},
	}
}
func macOSNodeChainCONNECTProfile(t *testing.T, peer *macOSNodeChainPeer, fault string) common.RouterProfile {
	t.Helper()
	password := peer.middlePassword
	if fault == "wrong-middle-key" {
		password += "-wrong"
	}
	proxy := &common.ExternalHTTPConnectConfig{Host: "10.79.0.1", Port: 1080, Username: "captured-native-user", Password: password}
	if fault == "wrong-middle-user" {
		proxy.Username += "-wrong"
	}
	external := &common.ExternalNodeConfig{Protocol: peer.middleCONNECT, ExpectedPublicIP: "203.0.113.88"}
	if peer.middleCONNECT == "http-connect" {
		external.HTTPConnect = proxy
	} else if peer.middleCONNECT == "https-connect" {
		proxy.TLSServerName = peer.reply.CONNECTServerName
		if fault == "tls-name" {
			proxy.TLSServerName = "wrong-original-connect.routervpn.test"
		}
		external.HTTPSConnect = proxy
	} else {
		t.Fatal("installed CONNECT source lost original protocol")
	}
	profile := common.RouterProfile{ID: "installed-original-connect-middle", Name: "Original imported CONNECT middle", NodeKind: "external", Endpoint: "10.79.0.1",
		External: external, DNSMode: "rescue", IPv6Mode: "off", StartLayer: "off", MTUPolicy: "auto", KillSwitch: true, KillSwitchPolicy: "on-connect"}
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		t.Fatal(err)
	}
	return profile
}

func macOSNodeChainCONNECTFinalAssets(t *testing.T, peer *macOSNodeChainPeer, final common.RouterProfile, files map[string][]byte) {
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
	// The final source stays byte-identical. Only its separately captured
	// SS service declaration authorizes the compiler to derive UoT-v2.
	configHash, keyHash := sha256.Sum256(raw), sha256.Sum256([]byte(peer.password))
	declaration, err := json.Marshal(map[string]any{"schema": 1, "node_id": final.NodeProofID,
		"configured_image": nativecomposite.SSServiceImage, "uot_version": 2, "endpoint": out["server"], "port": out["server_port"], "method": out["method"],
		"source_sha256": hex.EncodeToString(configHash[:]), "key_sha256": hex.EncodeToString(keyHash[:])})
	if err != nil {
		t.Fatal(err)
	}
	files[nativecomposite.SSServiceAsset] = declaration
}

func macOSNodeChainCONNECTReadback(t *testing.T, peer *macOSNodeChainPeer, reply macOSNodeChainPeerReply) {
	t.Helper()
	if peer.middleCONNECT == "" {
		if reply.CONNECTProtocol != "" || reply.CONNECTCA != "" || reply.CONNECTServerName != "" || reply.OpenCONNECTStreams != nil || reply.FinalUoTVersion != nil || reply.CONNECTAuthRefusals != 0 || reply.CONNECTTargetRefusals != 0 || reply.CONNECTTLSRefusals != 0 {
			t.Fatal("ordinary installed peer acquired CONNECT authority")
		}
		return
	}
	if reply.CONNECTProtocol != peer.middleCONNECT || reply.OpenCONNECTStreams == nil || *reply.OpenCONNECTStreams < 0 || reply.FinalUoTVersion == nil || *reply.FinalUoTVersion != 2 || reply.Associations != nil || reply.Middle == nil || reply.Middle.RawUDP != 0 || reply.Middle.UDP != 0 || reply.Final.FinalRawUDP != 0 || reply.CONNECTAuthRefusals < 0 || reply.CONNECTTargetRefusals < 0 || reply.CONNECTTLSRefusals < 0 {
		t.Fatal("installed CONNECT peer lost exact TCP-only ownership receipt")
	}
	if peer.middleCONNECT == "https-connect" {
		if reply.CONNECTCA == "" || reply.CONNECTCA == reply.PublicCA || reply.CONNECTServerName != "speed.cloudflare.com" {
			t.Fatal("installed HTTPS peer lost separate proxy trust or exact server name")
		}
	} else if reply.CONNECTCA != "" || reply.CONNECTServerName != "" || reply.CONNECTTLSRefusals != 0 {
		t.Fatal("installed HTTP peer acquired HTTPS authority")
	}
	if peer.reply.Address != "" && (reply.CONNECTProtocol != peer.reply.CONNECTProtocol || reply.CONNECTCA != peer.reply.CONNECTCA || reply.CONNECTServerName != peer.reply.CONNECTServerName) {
		t.Fatal("installed CONNECT peer substituted original proxy identity")
	}
}

func macOSNodeChainCONNECTPositiveCounters(t *testing.T, reply macOSNodeChainPeerReply, transfer bool) {
	t.Helper()
	middle := reply.Middle
	if middle == nil || middle.RawTCP == 0 || middle.TCP == 0 || middle.RawUDP != 0 || middle.UDP != 0 || middle.PublicQueries == 0 || reply.Final.FinalRawTCP == 0 || reply.Final.FinalRawUDP != 0 || reply.CONNECTAuthRefusals != 0 || reply.CONNECTTLSRefusals != 0 || reply.CONNECTTargetRefusals != 0 {
		t.Fatal("installed CONNECT path omitted actual authenticated TCP carriage", reply)
	}
	if transfer && (middle.DownloadBytes < 8<<20 || middle.UploadBytes < 8<<20) {
		t.Fatal("installed CONNECT middle omitted actual benchmark transfer", middle)
	}
}

func macOSNodeChainCONNECTNegativeCounters(t *testing.T, reply macOSNodeChainPeerReply, action string) {
	t.Helper()
	middle := reply.Middle
	if middle == nil || middle.RawTCP == 0 || middle.RawUDP != 0 || middle.UDP != 0 || reply.Final.FinalRawUDP != 0 {
		t.Fatal("installed CONNECT refusal lost actual TCP boundary", reply)
	}
	switch action {
	case "wrong-middle-key", "wrong-middle-user":
		if reply.CONNECTAuthRefusals == 0 || middle.TCP != 0 || middle.PublicQueries != 0 || reply.Final.RouterQueries != 0 || reply.CONNECTTLSRefusals != 0 {
			t.Fatal("wrong CONNECT credentials did not fail at original Basic boundary", reply)
		}
	case "tls-name", "tls-trust":
		if reply.CONNECTTLSRefusals == 0 || reply.CONNECTAuthRefusals != 0 || middle.TCP != 0 || middle.PublicQueries != 0 || reply.Final.RouterQueries != 0 {
			t.Fatal("wrong HTTPS trust did not fail at original TLS boundary", reply)
		}
	case "wrong-middle-public":
		if middle.TCP == 0 || middle.PublicQueries == 0 || reply.Final.RouterQueries != 0 {
			t.Fatal("wrong CONNECT identity failed before original public proof", reply)
		}
	case "final-dns-failure", "final-node-failure":
		if middle.TCP == 0 || middle.PublicQueries == 0 || reply.Final.FinalRawTCP == 0 || reply.CONNECTTLSRefusals != 0 || reply.CONNECTAuthRefusals != 0 {
			t.Fatal("CONNECT final refusal never traversed original authenticated predecessor", reply)
		}
	}
}

func TestMacOSRetainedNodeChainCONNECTNativeHost(t *testing.T) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getenv(macOSControllerFixtureMarker) != "1" || os.Getenv("HOMEVPN_MTU_BENCH_FAKE") != "" {
		t.Fatal("typed native host requires its explicit real disposable controller")
	}
	for _, scenario := range macOSNodeChainCONNECTHostCases {
		t.Run(scenario, func(t *testing.T) { macOSNodeChainNativeCase(t, scenario) })
	}
}

func TestDesktopDarwinInstalledCONNECTNodeChainFixtureKeepsOriginalSources(t *testing.T) {
	for _, scenario := range macOSNodeChainCONNECTCipherCases() {
		t.Run(scenario.name, func(t *testing.T) {
			peer := macOSNodeChainPeerForModes(t, scenario.modes)
			peer.reply.Address = net.JoinHostPort("192.168.210.2", "51820")
			if scenario.modes[1] == "https-connect" {
				peer.reply.CONNECTServerName = "speed.cloudflare.com"
			}
			profiles, assets := macOSNodeChainInstalledSources(t, peer, "")
			middle := profiles.Profiles[1]
			if len(profiles.Profiles) != 3 || len(peer.requests) != 1 || middle.NodeKind != "external" || middle.NodeProofID != "" || middle.APIToken != "" || middle.RouterAPI != "" || assets[middle.ID] != nil || middle.External == nil || middle.External.Protocol != scenario.modes[1] {
				t.Fatal("installed source changed original CONNECT credential or invented paired assets")
			}
			proxy := middle.External.HTTPConnect
			if scenario.modes[1] == "https-connect" {
				proxy = middle.External.HTTPSConnect
			}
			if proxy == nil || proxy.Password != peer.middlePassword || proxy.Username != "captured-native-user" || proxy.Host != "10.79.0.1" || proxy.Port != 1080 || (scenario.modes[1] == "https-connect" && proxy.TLSServerName != "speed.cloudflare.com") || (scenario.modes[1] == "http-connect" && proxy.TLSServerName != "") {
				t.Fatal("installed source changed original CONNECT credential or invented paired assets")
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
			selection, err = captureNativeNodeChainSelection(context.Background(), root, selection, []string{"shadowconnect"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), "darwin")
			if err != nil {
				t.Fatal(err)
			}
			if launch.chain.policy != nil || launch.chain.socksPolicy != nil || selection.Native.chain.socks != nil || selection.Native.chain.chain != nil || launch.chain.connectPolicy == nil {
				t.Fatal("installed typed source acquired generic chain authority")
			}
			_, meta, physical, err := launch.chain.readPolicy()
			if err != nil || len(meta.Prefixes) != 3 || meta.Prefixes[0].Mode != scenario.modes[0] || meta.Prefixes[1].Mode != scenario.modes[1] || meta.Prefixes[1].NodeID != "" || meta.Prefixes[1].Kind != "public-path" || meta.Prefixes[1].ProfileID != middle.ID || meta.Prefixes[2].NodeID != control.NodeProofID || len(physical.PhysicalRoots) != 1 || physical.PhysicalRoots[0].Destinations[0].Host != "192.168.210.2" {
				t.Fatal("installed typed source lost original proof or physical identity", err)
			}
			var source mobilemultihop.NodeChainSource
			if json.Unmarshal([]byte(selection.Native.chain.connect.original.input), &source) != nil || source.Schema != 4 || source.IdentitySources[1] != "" {
				t.Fatal("typed original source acquired paired middle identity")
			}
			var envelope struct {
				Config  string `json:"config"`
				Capture string `json:"capture"`
			}
			var captured struct {
				Profile common.RouterProfile `json:"profile"`
			}
			if json.Unmarshal([]byte(source.Nodes[1]), &envelope) != nil || json.Unmarshal([]byte(envelope.Capture), &captured) != nil || !reflect.DeepEqual(captured.Profile, middle) {
				t.Fatal("installed typed source changed original complete imported policy")
			}
			for _, action := range []string{"connect", "wrong-middle-key", "wrong-middle-user", "wrong-middle-public", "final-dns-failure", "final-node-failure", "middle-source", "prefix-lost", "tls-name", "tls-trust"} {
				if (scenario.modes[0] != "wg" && action != "connect") || (scenario.modes[1] != "https-connect" && (action == "tls-name" || action == "tls-trust")) {
					continue
				}
				modes, actual, err := macOSNodeChainScenario(scenario.prefix + action)
				if err != nil || fmt.Sprint(modes) != fmt.Sprint(scenario.modes) || actual != action {
					t.Fatal("typed native case changed exact original inventory", err)
				}
			}
		})
	}
}
