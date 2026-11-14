//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

var linuxNodeChainSOCKSHostCases = []string{
	"node-chain-socks-wg-connect", "node-chain-socks-awg-fast-connect", "node-chain-socks-awg-strong-connect",
	"node-chain-socks-wg-wrong-middle-key", "node-chain-socks-wg-wrong-middle-public",
	"node-chain-socks-wg-final-dns-failure", "node-chain-socks-wg-final-node-failure", "node-chain-socks-wg-middle-source",
}

func linuxNodeChainSOCKSCipherCases() []linuxNodeChainCipherCase {
	return []linuxNodeChainCipherCase{
		{"wg", "node-chain-socks-wg-", []string{"wg", "socks5"}},
		{"awg2-fast", "node-chain-socks-awg-fast-", []string{"awg2-fast", "socks5"}},
		{"awg2-strong", "node-chain-socks-awg-strong-", []string{"awg2-strong", "socks5"}},
	}
}
func (peer *linuxNodeChainPeer) observedMiddleMethod() string {
	if peer.middleSOCKS {
		return "socks5"
	}
	return peer.middleMethod
}
func (peer *linuxNodeChainPeer) observedMiddleProtocol() string {
	if peer.middleSOCKS {
		return "socks5"
	}
	return "shadowsocks"
}
func linuxNodeChainSOCKSProfile(t *testing.T, peer *linuxNodeChainPeer, fault string) common.RouterProfile {
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

func TestDesktopLinuxInstalledSOCKSNodeChainFixtureKeepsOriginalSources(t *testing.T) {
	for _, scenario := range linuxNodeChainSOCKSCipherCases() {
		t.Run(scenario.name, func(t *testing.T) {
			peer := linuxNodeChainPeerForModes(t, scenario.modes)
			peer.reply.Address = net.JoinHostPort("192.168.210.2", "51820")
			profiles, assets := linuxNodeChainInstalledSources(t, peer, "")
			middle := profiles.Profiles[1]
			if len(profiles.Profiles) != 3 || len(peer.requests) != 1 || middle.NodeKind != "external" || middle.NodeProofID != "" || middle.APIToken != "" || middle.RouterAPI != "" || assets[middle.ID] != nil || middle.External == nil || middle.External.Protocol != "socks5" || middle.External.SOCKS5 == nil || middle.External.SOCKS5.Password != peer.middlePassword || middle.External.SOCKS5.Username != "captured-native-user" {
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
			if launch.chain.policy != nil || selection.Native.chain.chain != nil || launch.chain.socksPolicy == nil {
				t.Fatal("installed typed source acquired generic chain authority")
			}
			_, meta, physical, err := launch.chain.readPolicy()
			if err != nil || len(meta.Prefixes) != 3 || meta.Prefixes[0].Mode != scenario.modes[0] || meta.Prefixes[1].NodeID != "" || meta.Prefixes[1].Kind != "public-path" || meta.Prefixes[1].ProfileID != middle.ID || meta.Prefixes[2].NodeID != control.NodeProofID || len(physical.PhysicalRoots) != 1 || physical.PhysicalRoots[0].Destinations[0].Host != "192.168.210.2" {
				t.Fatal("installed typed source lost original proof or physical identity", err)
			}
			var source mobilemultihop.NodeChainSource
			if json.Unmarshal([]byte(selection.Native.chain.socks.original.input), &source) != nil || source.Schema != 3 || source.IdentitySources[1] != "" {
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
			for _, action := range []string{"connect", "wrong-middle-key", "wrong-middle-public", "final-dns-failure", "final-node-failure", "middle-source"} {
				if scenario.name != "wg" && action != "connect" {
					continue
				}
				modes, actual, err := linuxNodeChainScenario(scenario.prefix + action)
				if err != nil || fmt.Sprint(modes) != fmt.Sprint(scenario.modes) || actual != action {
					t.Fatal("typed native case changed exact original inventory", err)
				}
			}
		})
	}
}

// Installed-only admission bridge. All source, operation, staging, proof,
// publication and retirement remain the shipping retained-host path.
func linuxNodeChainNativeConnect(a *app, w http.ResponseWriter, r *http.Request, driver nativeMultihopConnectRuntime) {
	if nativeNodeChainSOCKSPlatformSupported() {
		a.nativeMultihopConnectOwned(w, r, driver)
		return
	}
	operation, finish, err := a.beginConnectionOperationContext(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	defer finish()
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	q, err := decodeMultihopConnectRequest(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil || !q.ordered() {
		http.Error(w, "original ordered request required", http.StatusBadRequest)
		return
	}
	if execution, err := routeExecution(q); err != nil || execution != "local" {
		http.Error(w, "original local execution required", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	selection, err := a.resolveNativeMultihopRequestLocked(q)
	a.mu.Unlock()
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	a.nativeMultihopConnectLocalOwned(w, r, operation, selection, driver)
}
