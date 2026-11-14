//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

type linuxNodeChainImportedCounters struct {
	Method        string `json:"method"`
	RawTCP        int64  `json:"raw_tcp"`
	RawUDP        int64  `json:"raw_udp"`
	TCP           int64  `json:"tcp"`
	UDP           int64  `json:"udp"`
	PublicQueries uint64 `json:"public_queries"`
	DownloadBytes uint64 `json:"download_bytes"`
	UploadBytes   uint64 `json:"upload_bytes"`
}

func linuxNodeChainImportedCipherCases() []linuxNodeChainCipherCase {
	return []linuxNodeChainCipherCase{
		{"custom-wg", "node-chain-custom-wg-", []string{"wg", "shadowsocks"}},
		{"custom-awg-fast", "node-chain-custom-awg-fast-", []string{"awg2-fast", "shadowsocks"}},
		{"custom-awg-strong", "node-chain-custom-awg-strong-", []string{"awg2-strong", "shadowsocks"}},
	}
}

func linuxNodeChainPeerForModes(t *testing.T, modes []string) *linuxNodeChainPeer {
	t.Helper()
	peer := linuxNodeChainPeerKeys(t, len(modes)+1)
	if len(modes) == 2 && (modes[1] == "shadowsocks" || modes[1] == "socks5" || modes[1] == "http-connect" || modes[1] == "https-connect") {
		// Keep the original paired first and final keys. The custom middle receives
		// only its own independent SS2022 PSK, never a synthetic WG/API identity.
		peer.middlePassword = peer.requests[1].PreSharedKey
		peer.middleMethod = mobilemultihop.NativeStartLayerMethod
		peer.middleSOCKS = modes[1] == "socks5"
		if modes[1] == "http-connect" || modes[1] == "https-connect" {
			peer.middleCONNECT = modes[1]
		}
		peer.requests = peer.requests[:1]
		peer.clients = peer.clients[:1]
		linuxNodeChainSetModes(t, peer, modes[:1])
	} else {
		linuxNodeChainSetModes(t, peer, modes)
	}
	return peer
}

func linuxNodeChainImportedProfile(t *testing.T, peer *linuxNodeChainPeer, fault string) common.RouterProfile {
	t.Helper()
	password := peer.middlePassword
	if fault == "wrong-middle-key" {
		password = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("w", 32)))
	}
	profile := common.RouterProfile{ID: "installed-original-custom-middle", Name: "Original imported SS2022 middle", NodeKind: "external", Endpoint: "10.79.0.1",
		External: &common.ExternalNodeConfig{Protocol: "shadowsocks", ExpectedPublicIP: "203.0.113.88", Shadowsocks: &common.ExternalShadowsocksConfig{Server: "10.79.0.1", Port: 8388, Method: peer.middleMethod, Password: password}},
		DNSMode:  "rescue", IPv6Mode: "off", StartLayer: "off", MTUPolicy: "auto", KillSwitch: true, KillSwitchPolicy: "on-connect"}
	if err := common.NormalizeRouterProfile(&profile); err != nil {
		t.Fatal(err)
	}
	return profile
}

func linuxNodeChainImportedPositiveCounters(t *testing.T, reply linuxNodeChainPeerReply) {
	t.Helper()
	middle := reply.Middle
	if middle == nil || middle.RawTCP == 0 || middle.RawUDP == 0 || middle.TCP == 0 || middle.UDP == 0 || middle.PublicQueries == 0 || middle.DownloadBytes < 8<<20 || middle.UploadBytes < 8<<20 {
		t.Fatal("installed custom middle omitted encrypted traffic, independent public proof or complete benchmark transfer", middle)
	}
}

func linuxNodeChainImportedNegativeCounters(t *testing.T, reply linuxNodeChainPeerReply, action string) {
	t.Helper()
	middle := reply.Middle
	if middle == nil {
		t.Fatal("custom refusal lost independent source counters")
	}
	switch action {
	case "wrong-middle-key":
		if middle.RawTCP+middle.RawUDP == 0 || middle.TCP != 0 || middle.UDP != 0 || middle.PublicQueries != 0 || reply.Final.RouterQueries != 0 {
			t.Fatal("wrong custom PSK did not fail at its original cipher boundary", middle)
		}
	case "wrong-middle-public":
		if middle.TCP == 0 || middle.PublicQueries == 0 || reply.Final.RouterQueries != 0 {
			t.Fatal("wrong custom public identity failed before its original routed proof", middle)
		}
	}
}

func TestDesktopLinuxInstalledImportedNodeChainFixtureKeepsOriginalSources(t *testing.T) {
	for _, scenario := range linuxNodeChainImportedCipherCases() {
		t.Run(scenario.name, func(t *testing.T) {
			peer := linuxNodeChainPeerForModes(t, scenario.modes)
			peer.reply.Address = net.JoinHostPort("192.168.210.2", "51820")
			profiles, assets := linuxNodeChainInstalledSources(t, peer, "")
			if len(profiles.Profiles) != 3 || len(peer.requests) != 1 || profiles.Profiles[1].NodeKind != "external" || profiles.Profiles[1].NodeProofID != "" || profiles.Profiles[1].APIToken != "" || profiles.Profiles[1].RouterAPI != "" || assets[profiles.Profiles[1].ID] != nil {
				t.Fatal("installed custom source invented paired credentials or assets")
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
			capture, err := captureDesktopNodeChain(context.Background(), root, control, profiles.Profiles, control.MultihopNodes, "local", nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range []string{"linux", "windows", "darwin"} {
				policy, err := mobilemultihop.NewDesktopNodeChainPolicy(capture.chain, strings.Repeat("a", 32), target, 0)
				if err != nil {
					t.Fatal(target, err)
				}
				proofs := policy.NodeChain().ProofInventory()
				physical, err := policy.NodeChain().PhysicalEgress()
				if err != nil || len(proofs) != 3 || proofs[0].Mode != scenario.modes[0] || proofs[1].NodeID != "" || proofs[1].ProfileID != profiles.Profiles[1].ID || proofs[2].NodeID != control.NodeProofID || len(physical) != 1 || physical[0].Host != "192.168.210.2" {
					t.Fatal("installed custom fixture lost exact source/physical ownership", target, err)
				}
			}
			for _, action := range []string{"connect", "wrong-middle-key", "wrong-middle-public", "middle-source", "prefix-lost"} {
				if scenario.modes[0] != "wg" && action != "connect" {
					continue
				}
				modes, actual, err := linuxNodeChainScenario(scenario.prefix + action)
				if err != nil || fmt.Sprint(modes) != fmt.Sprint(scenario.modes) || actual != action {
					t.Fatal("installed custom scenario lost exact captured mode/action", err)
				}
			}
		})
	}
}
