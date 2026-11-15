package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func installDesktopOrderedOpenVPN(t *testing.T, a *app, nodes []common.MultihopNodeSelection, network string) {
	t.Helper()
	p := desktopImportedOpenVPNProfileFixture(t, network)
	p.ID, p.Name, p.StartLayer = nodes[1].ID, "Original ordered OpenVPN middle", "off"
	p.MTUPolicy, p.ManualMTU = "manual", 1500
	a.profiles.Profiles[1] = p
	nodes[1].Mode = "openvpn"
	a.profiles.Profiles[2].MultihopNodes = append([]common.MultihopNodeSelection(nil), nodes...)
}

func TestDesktopOrderedOpenVPNOriginalCaptureAndPhysicalOwner(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
			t.Run(mode+"/"+network, func(t *testing.T) {
				a, nodes := desktopNodeChainCaptureFixture(t, 3)
				installOrderedAWGAssets(t, a, nodes, []string{mode, "wg", "shadowsocks"}, "off")
				installDesktopOrderedOpenVPN(t, a, nodes, network)
				for i := range a.profiles.Profiles {
					a.profiles.Profiles[i].KillSwitch = false
					a.profiles.Profiles[i].KillSwitchPolicy = "off"
				}
				a.profiles.Profiles[1].KillSwitchPolicy = "always"
				before := cloneRouterProfileStore(a.profiles)
				capture := captureNodeChainTest(t, a, nodes)
				var wire mobilemultihop.NodeChainSource
				if json.Unmarshal([]byte(capture.input), &wire) != nil || wire.Schema != 5 || len(wire.IdentitySources) != 3 || wire.IdentitySources[1] != "" || wire.IdentitySources[0] == "" || wire.IdentitySources[2] == "" {
					t.Fatal("OpenVPN capture lost exclusive schema or paired identity inventory")
				}
				wire.Schema = 2
				raw, _ := json.Marshal(wire)
				if _, err := mobilemultihop.NewNodeChain(string(raw)); err == nil {
					t.Fatal("OpenVPN middle entered legacy SS schema")
				}
				proofs := capture.chain.ProofInventory()
				if len(proofs) != 3 || proofs[0].NodeID == proofs[2].NodeID || proofs[1].NodeID != "" || proofs[1].Mode != "openvpn" || proofs[2].Mode != "shadowsocks" {
					t.Fatal("middle invented paired authority or replaced original final", proofs)
				}
				for _, target := range []string{"linux", "windows", "darwin"} {
					policy, err := mobilemultihop.NewDesktopNodeChainPolicy(capture.chain, strings.Repeat("a", 32), target, 0)
					if err != nil {
						t.Fatal(target, err)
					}
					config, meta, physical, err := policy.ReadValidated()
					if err != nil || len(physical.PhysicalRoots) != 1 || meta.Prefixes[1].Mode != "openvpn" || meta.KillSwitchPolicy != "always" {
						t.Fatal("desktop projection lost exact first ingress", target, err, physical)
					}
					var graph map[string]any
					if json.Unmarshal([]byte(config), &graph) != nil {
						t.Fatal("invalid projected graph")
					}
					middle := desktopImportedGraphNode(t, graph, proofs[1].Tag)
					if middle["type"] != "openvpn-client" || middle["detour"] != proofs[0].Tag || middle["server"] != a.profiles.Profiles[1].Endpoint || middle["network"] != network || middle["system"] != false {
						t.Fatal("OpenVPN bypassed original packet prefix", middle)
					}
					if physical.PhysicalRoots[0].Tag == proofs[1].Tag {
						t.Fatal("middle acquired physical ingress")
					}
					launch, err := policy.ReadValidatedLaunch()
					if err != nil {
						t.Fatal(err)
					}
					replay, err := mobilemultihop.ParseDesktopNodeChainLaunchInput(launch.Input)
					if err != nil || replay.Config() != config {
						t.Fatal("native command cannot replay exact schema-five desktop policy", err)
					}
				}
				if !reflect.DeepEqual(before, a.profiles) {
					t.Fatal("capture rewrote saved sources")
				}
				a.profiles.Profiles[1].External.OpenVPN.Password = "replacement"
				if capture.validate(context.Background(), a.profiles.Profiles[2], a.profiles.Profiles) == nil {
					t.Fatal("changed middle credential retained source authority")
				}
			})
		}
	}
}

func TestDesktopOrderedOpenVPNRejectsUnsupportedSourceAndPlacement(t *testing.T) {
	for _, fault := range []string{"first", "final", "four-members", "hostname", "second-remote", "endpoint", "proof-id", "api-token", "router-api", "layer", "external-layer", "wrong-mode", "wrong-final", "same-final-identity", "server", "auto"} {
		t.Run(fault, func(t *testing.T) {
			a, nodes := desktopNodeChainCaptureFixture(t, 3)
			installDesktopOrderedOpenVPN(t, a, nodes, "udp")
			p := &a.profiles.Profiles[1]
			execution := "local"
			switch fault {
			case "first":
				nodes[0], nodes[1] = nodes[1], nodes[0]
			case "final":
				nodes[1], nodes[2] = nodes[2], nodes[1]
			case "four-members":
				nodes = append(nodes, common.MultihopNodeSelection{ID: "extra", Mode: "shadowsocks"})
			case "hostname":
				p.Endpoint = "middle.example"
				p.External.OpenVPN.Config = strings.ReplaceAll(p.External.OpenVPN.Config, "203.0.113.24", p.Endpoint)
			case "second-remote":
				p.External.OpenVPN.Config += "remote 203.0.113.25 1194\n"
			case "endpoint":
				p.Endpoint = "203.0.113.25"
			case "proof-id":
				p.NodeProofID = a.profiles.Profiles[0].NodeProofID
			case "api-token":
				p.APIToken = "private"
			case "router-api":
				p.RouterAPI = "http://10.1.0.1:8787"
			case "layer":
				p.StartLayer = "aes-256-gcm"
			case "external-layer":
				p.External.StartLayer = &common.ExternalStartLayer{Mode: "aes-256-gcm"}
			case "wrong-mode":
				nodes[1].Mode = "shadowsocks"
			case "wrong-final":
				nodes[2].Mode = "hysteria2"
			case "same-final-identity":
				a.profiles.Profiles[2].NodeProofID = a.profiles.Profiles[0].NodeProofID
			case "server", "auto":
				execution = fault
			}
			selected, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[2], a.profiles.Profiles, nodes, execution)
			if err == nil {
				_, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selected, []string{"shadowsocks"}, nil)
			}
			if err == nil {
				t.Fatal("unsupported original OpenVPN shape admitted")
			}
		})
	}
}

func TestDesktopOrderedOpenVPNPublicRequestAndSourceRevisions(t *testing.T) {
	a, nodes := desktopNodeChainCaptureFixture(t, 3)
	installDesktopOrderedOpenVPN(t, a, nodes, "tcp")
	original := a.profiles.Profiles[1]
	view := publicProfileFor(original)
	if view.External == nil || view.External.OrderedMiddle != nativeNodeChainOpenVPNPlatformSupported() {
		t.Fatal("public capability differs from retained platform admission")
	}
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), original.External.OpenVPN.Password) || strings.Contains(string(raw), original.External.OpenVPN.Username) {
		t.Fatal("public capability exposed credentials")
	}
	request := orderedPublicRequest(t, a, nodes)
	a.mu.Lock()
	selection, err := a.resolveNativeMultihopRequestLocked(request)
	a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
	if err != nil || selection.Native.validate(selection) != nil {
		t.Fatal("public request failed original native capture", err)
	}
	a.profiles.Profiles[1].External.OpenVPN.Password = "replacement"
	if nativeMultihopLiveProfilesCurrentContext(context.Background(), a, selection) {
		t.Fatal("current owner adopted replaced OpenVPN source")
	}
	a.mu.Lock()
	_, err = a.resolveNativeMultihopRequestLocked(request)
	a.mu.Unlock()
	if err == nil {
		t.Fatal("stale public editor admitted replacement source")
	}
}

func TestDesktopOrderedOpenVPNSavedAndStartupSources(t *testing.T) {
	a, nodes := startupOrderedTestApp(t, 3)
	installDesktopOrderedOpenVPN(t, a, nodes, "udp")
	original := common.CloneRouterProfile(a.profiles.Profiles[1])
	id := saveOrderedConnectionFixture(t, a, nodes)
	raw, err := os.ReadFile(connectionProfileStorePath(a))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), original.External.OpenVPN.Password) || strings.Contains(string(raw), original.External.OpenVPN.Config) {
		t.Fatal("saved references copied OpenVPN credentials")
	}
	capture := startupNodeChainCaptureForTest(t, a)
	receipt := startupOrderedReceipt(t, capture)
	if receipt.NodeChain.Schema != 5 || receipt.NodeChain.Nodes[1].NodeKind != "external" || receipt.NodeChain.Nodes[1].NodeProofID != "" {
		t.Fatal("startup lost original source kind")
	}
	raw, _ = json.Marshal(receipt)
	var decoded startupSelection
	if err := json.Unmarshal(raw, &decoded); err != nil || !reflect.DeepEqual(decoded, receipt) {
		t.Fatal("schema-five startup replay failed", err)
	}
	decoded.NodeChain.Schema = 2
	if validateStartupNodeChainSelection(decoded) == nil {
		t.Fatal("startup OpenVPN borrowed legacy SS authority")
	}
	a.profiles.Profiles[1].External.OpenVPN.Password = "replacement"
	if capture.current(a) == nil {
		t.Fatal("scheduled startup adopted replaced source")
	}
	response := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
	if response.Code == http.StatusOK {
		t.Fatal("saved route adopted replaced source")
	}
}
