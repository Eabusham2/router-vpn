//go:build darwin && routervpn_controller_privileged

package main

import (
	"context"
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
)

const macOSNodeChainSOCKSFiftyReceipt = "actual installed Darwin SOCKS fifty: all three original members returned fifty samples and retained exact durable receipts"
const macOSNodeChainSOCKSLongFiftyReceipt = "actual installed Darwin SOCKS long path fifty: captured penultimate public and final private members retained exact durable receipts"

var macOSNodeChainSOCKSHostCases = []string{
	"node-chain-socks-wg-connect", "node-chain-socks-awg-fast-connect", "node-chain-socks-awg-strong-connect",
	"node-chain-socks-wg-wrong-middle-key", "node-chain-socks-wg-wrong-middle-public",
	"node-chain-socks-wg-final-dns-failure", "node-chain-socks-wg-final-node-failure", "node-chain-socks-wg-middle-source",
	"node-chain-socks-wg-four-connect", "node-chain-socks-wg-eight-connect",
}

func macOSNodeChainSOCKSCipherCases() []macOSNodeChainCipherCase {
	return []macOSNodeChainCipherCase{
		{"wg", "node-chain-socks-wg-", []string{"wg", "socks5"}},
		{"awg2-fast", "node-chain-socks-awg-fast-", []string{"awg2-fast", "socks5"}},
		{"awg2-strong", "node-chain-socks-awg-strong-", []string{"awg2-strong", "socks5"}},
		{"wg-four", "node-chain-socks-wg-four-", []string{"wg", "wg", "socks5"}},
		{"wg-eight", "node-chain-socks-wg-eight-", []string{"wg", "wg", "wg", "wg", "wg", "wg", "socks5"}},
	}
}
func (peer *macOSNodeChainPeer) observedMiddleMethod() string {
	if peer.middleCONNECT != "" {
		return peer.middleCONNECT
	}
	if peer.middleSOCKS {
		return "socks5"
	}
	return peer.middleMethod
}
func (peer *macOSNodeChainPeer) observedMiddleProtocol() string {
	if peer.middleCONNECT != "" {
		return peer.middleCONNECT
	}
	if peer.middleSOCKS {
		return "socks5"
	}
	return "shadowsocks"
}
func macOSNodeChainSOCKSProfile(t *testing.T, peer *macOSNodeChainPeer, fault string) common.RouterProfile {
	t.Helper()
	password := peer.middlePassword
	if fault == "wrong-middle-key" {
		password += "-wrong"
	}
	profile := common.RouterProfile{ID: "installed-original-socks-middle", Name: "Original imported SOCKS middle", NodeKind: "external", Endpoint: "10.79.0.1",
		External: &common.ExternalNodeConfig{Protocol: "socks5", ExpectedPublicIP: "203.0.113.88", SOCKS5: &common.ExternalSOCKS5Config{Host: "10.79.0.1", Port: 1080, Username: "captured-native-user", Password: password}},
		DNSMode:  "rescue", IPv6Mode: "off", StartLayer: "off", MTUPolicy: "auto", KillSwitch: true, KillSwitchPolicy: "on-connect"}
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		t.Fatal(err)
	}
	return profile
}

func TestMacOSRetainedNodeChainSOCKSNativeHost(t *testing.T) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getenv(macOSControllerFixtureMarker) != "1" || os.Getenv("HOMEVPN_MTU_BENCH_FAKE") != "" {
		t.Fatal("typed native host requires its explicit real disposable controller")
	}
	for _, scenario := range macOSNodeChainSOCKSHostCases {
		t.Run(scenario, func(t *testing.T) { macOSNodeChainNativeCase(t, scenario) })
	}
}

func TestDesktopDarwinInstalledSOCKSNodeChainFixtureKeepsOriginalSources(t *testing.T) {
	for _, scenario := range macOSNodeChainSOCKSCipherCases() {
		t.Run(scenario.name, func(t *testing.T) {
			peer := macOSNodeChainPeerForModes(t, scenario.modes)
			peer.reply.Address = net.JoinHostPort("192.168.210.2", "51820")
			profiles, assets := macOSNodeChainInstalledSources(t, peer, "")
			middlePosition, count := len(scenario.modes)-1, len(scenario.modes)+1
			middle := profiles.Profiles[middlePosition]
			if len(profiles.Profiles) != count || len(peer.requests) != middlePosition || middle.NodeKind != "external" || middle.NodeProofID != "" || middle.APIToken != "" || middle.RouterAPI != "" || assets[middle.ID] != nil || middle.External == nil || middle.External.Protocol != "socks5" || middle.External.SOCKS5 == nil || middle.External.SOCKS5.Password != peer.middlePassword || middle.External.SOCKS5.Username != "captured-native-user" {
				t.Fatal("installed source changed original SOCKS credential or invented paired assets")
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
			control := profiles.Profiles[count-1]
			selection, err := resolveDesktopNodeChainSelection(control, profiles.Profiles, control.MultihopNodes, "local")
			if err != nil {
				t.Fatal(err)
			}
			selection, err = captureNativeNodeChainSelection(context.Background(), root, selection, []string{"shadowsocks"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), "darwin")
			if err != nil {
				t.Fatal(err)
			}
			if launch.chain.policy != nil || selection.Native.chain.chain != nil || launch.chain.socksPolicy == nil {
				t.Fatal("installed typed source acquired generic chain authority")
			}
			_, meta, physical, err := launch.chain.readPolicy()
			if err != nil || len(meta.Prefixes) != count || meta.Prefixes[0].Mode != scenario.modes[0] || meta.Prefixes[middlePosition].NodeID != "" || meta.Prefixes[middlePosition].Kind != "public-path" || meta.Prefixes[middlePosition].ProfileID != middle.ID || meta.Prefixes[count-1].NodeID != control.NodeProofID || meta.ProfileID != control.ID || meta.NodeID != control.NodeProofID || meta.FinalTag != meta.Prefixes[count-1].Tag || len(physical.PhysicalRoots) != 1 || physical.PhysicalRoots[0].Destinations[0].Host != "192.168.210.2" {
				t.Fatal("installed typed source lost original proof or physical identity", err)
			}
			var source mobilemultihop.NodeChainSource
			if json.Unmarshal([]byte(selection.Native.chain.socks.original.input), &source) != nil || source.Schema != 3 || len(source.Nodes) != count || len(source.IdentitySources) != count || source.IdentitySources[middlePosition] != "" {
				t.Fatal("typed original source acquired paired middle identity")
			}
			for position := 0; position < middlePosition; position++ {
				original := profiles.Profiles[position]
				if source.IdentitySources[position] == "" || meta.Prefixes[position].ProfileID != original.ID || meta.Prefixes[position].NodeID != original.NodeProofID || meta.Prefixes[position].Mode != scenario.modes[position] {
					t.Fatal("SOCKS replaced an original paired prefix", position)
				}
			}
			var envelope struct {
				Config  string `json:"config"`
				Capture string `json:"capture"`
			}
			var captured struct {
				Profile common.RouterProfile `json:"profile"`
			}
			if json.Unmarshal([]byte(source.Nodes[middlePosition]), &envelope) != nil || json.Unmarshal([]byte(envelope.Capture), &captured) != nil || !reflect.DeepEqual(captured.Profile, middle) {
				t.Fatal("installed typed source changed original complete imported policy")
			}
			for _, action := range []string{"connect", "wrong-middle-key", "wrong-middle-public", "final-dns-failure", "final-node-failure", "middle-source"} {
				if scenario.name != "wg" && action != "connect" {
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
