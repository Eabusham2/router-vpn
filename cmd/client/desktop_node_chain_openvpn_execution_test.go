package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/nativeopenvpn"
)

// This owns two actual compiler inputs and independent provider identities.
// Native provider connection, device and lease execution are separate tests.
func desktopOpenVPNExecutionProfiles(t *testing.T, count int, mode, network, layer string) (*app, []common.MultihopNodeSelection, common.RouterProfile, mobilemultihop.NodeChainOpenVPNServerPairing) {
	t.Helper()
	a, nodes := desktopOpenVPNPrefixCaptureFixture(t, count-2, mode, network, layer)
	local := &a.profiles.Profiles[count-2]
	server := cloneRouterProfile(*local)
	server.External.OpenVPN.Username = "independent Server provider"
	server.External.OpenVPN.Password = "independent Server secret"
	localKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("l", 32)))
	serverKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 32)))
	left, err := nativeopenvpn.DescribePeer(*local.External.OpenVPN, localKey)
	if err != nil {
		t.Fatal(err)
	}
	right, err := nativeopenvpn.DescribePeer(*server.External.OpenVPN, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = nativeopenvpn.ValidatePublicPair(left, right); err != nil {
		t.Fatal(err)
	}
	local.External.OpenVPNPairing = &common.ExternalOpenVPNPairing{PrivateKey: localKey, Server: right}
	return a, nodes, server, mobilemultihop.NodeChainOpenVPNServerPairing{PrivateKey: serverKey, Local: left, Server: right}
}
func desktopOpenVPNExecutionLaunchFixture(t *testing.T, count int, target, choice string) (*app, multihopSelection, *desktopNodeLaunch, *desktopNodeChainExecutionLaunch, *mobilemultihop.NodeChainServerPolicy) {
	t.Helper()
	return desktopOpenVPNExecutionLaunchFixtureWithProtection(t, count, target, choice, "")
}
func desktopOpenVPNExecutionLaunchFixtureWithProtection(t *testing.T, count int, target, choice, protection string) (*app, multihopSelection, *desktopNodeLaunch, *desktopNodeChainExecutionLaunch, *mobilemultihop.NodeChainServerPolicy) {
	t.Helper()
	a, nodes, server, pair := desktopOpenVPNExecutionProfiles(t, count, "wg", "tcp", "off")
	if protection != "" {
		a.profiles.Profiles[count-2].KillSwitchPolicy = protection
	}
	selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[count-1], a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal(err)
	}
	captured, err := captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := newDesktopNodeChainLaunch(captured, strings.Repeat("b", 32), target)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := newDesktopNodeChainExecutionSource(launch.chain, choice)
	if err != nil {
		t.Fatal("original OpenVPN execution preparation", err)
	}
	var local mobilemultihop.NodeChainSource
	if json.Unmarshal([]byte(execution.preparation.LocalSource()), &local) != nil {
		t.Fatal("original source")
	}
	proofs := launch.chain.policy.OriginalChain().ProofInventory()
	remote := mobilemultihop.NodeChainServerSource{Schema: 5, EntryID: proofs[0].ProfileID, EntryNodeID: proofs[0].NodeID, EntryMode: proofs[0].Mode, OpenVPNPairing: &pair}
	for i := 1; i < count; i++ {
		raw, identity, err := desktopExecutionServerNode(local.Nodes[i], local.IdentitySources[i], i, false)
		if i == count-2 {
			raw, _, err = desktopNodeChainOpenVPNInput(context.Background(), server)
			identity = ""
		}
		if err != nil {
			t.Fatal(err)
		}
		remote.Nodes = append(remote.Nodes, raw)
		remote.IdentitySources = append(remote.IdentitySources, identity)
	}
	raw, _ := json.Marshal(remote)
	remotePolicy, err := mobilemultihop.NewNodeChainOpenVPNServerPolicy(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return a, captured, launch, execution, remotePolicy
}
func TestDesktopOpenVPNExecutionOriginalPreparation(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, count := range []int{3, 4, 8} {
			for _, choice := range []string{"server", "auto"} {
				t.Run(fmt.Sprintf("%s/%d/%s", target, count, choice), func(t *testing.T) {
					_, selection, launch, e, server := desktopOpenVPNExecutionLaunchFixture(t, count, target, choice)
					if e.openvpnPhysical == nil || e.physical != nil || e.socksPhysical != nil || e.connectPhysical != nil || !e.preparation.RequiresDesktopOpenVPNExecutionObserver() {
						t.Fatal("typed original preparation missing")
					}
					source, err := e.preparation.OriginalOpenVPNSource()
					if err != nil || source != selection.Native.chain.chain {
						t.Fatal("original source replaced", err)
					}
					retained, err := e.openvpnPhysical.OriginalDesktopOpenVPNPolicy()
					if err != nil || retained != launch.chain.policy {
						t.Fatal("original physical owner replaced", err)
					}
					if err = e.attach(launch); err != nil {
						t.Fatal(err)
					}
					if err = e.bound(launch); err != nil {
						t.Fatal(err)
					}
					if server.Descriptor().Schema != 5 || len(server.Descriptor().Members) != count-1 {
						t.Fatal("independent Server suffix lost original shape")
					}
					for _, parser := range []func(string) (*mobilemultihop.NodeChainExecutionPreparation, error){mobilemultihop.ParseDesktopNodeChainExecutionPreparation, mobilemultihop.ParseDesktopNodeChainSOCKSExecutionPreparation, mobilemultihop.ParseDesktopNodeChainCONNECTExecutionPreparation} {
						if _, err := parser(e.preparation.Source()); err == nil {
							t.Fatal("foreign parser admitted OpenVPN")
						}
					}
				})
			}
		}
	}
}

func TestDesktopOpenVPNExecutionSourceRefusals(t *testing.T) {
	for _, fault := range []string{"missing-pair", "invalid-local-credential", "foreign-server-peer", "shared-provider-identity", "paired-middle", "middle-layer", "duplicate-proof", "duplicate-id", "wrong-final", "wrong-prefix", "CONNECT-family"} {
		t.Run(fault, func(t *testing.T) {
			a, nodes, _, _ := desktopOpenVPNExecutionProfiles(t, 4, "wg", "tcp", "off")
			selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[3], a.profiles.Profiles, nodes, "server")
			if err != nil || !desktopOpenVPNExecutionMembers(selection.Nodes, "server") {
				t.Fatal("original independent OpenVPN execution refused", err)
			}
			changed := cloneDesktopNodeChainMembers(selection.Nodes)
			p := &changed[2].Profile
			switch fault {
			case "missing-pair":
				p.External.OpenVPNPairing = nil
			case "invalid-local-credential":
				p.External.OpenVPN.Username = ""
			case "foreign-server-peer":
				p.External.OpenVPNPairing.Server.Transport["foreign"] = true
			case "shared-provider-identity":
				peer, e := nativeopenvpn.DescribePeer(*p.External.OpenVPN, p.External.OpenVPNPairing.PrivateKey)
				if e != nil {
					t.Fatal(e)
				}
				p.External.OpenVPNPairing.Server = peer
			case "paired-middle":
				p.NodeKind = "router-vpn"
			case "middle-layer":
				p.StartLayer = "aes-256-gcm"
			case "duplicate-proof":
				changed[3].Profile.NodeProofID = changed[0].Profile.NodeProofID
			case "duplicate-id":
				changed[3].Profile.ID = changed[0].Profile.ID
			case "wrong-final":
				changed[3].Mode = "hysteria2"
			case "wrong-prefix":
				changed[1].Mode = "socks5"
			case "CONNECT-family":
				changed[2].Mode, p.External.Protocol = "http-connect", "http-connect"
			}
			if desktopOpenVPNExecutionMembers(changed, "server") {
				t.Fatal("OpenVPN execution accepted replaced original pairing or member", fault)
			}
		})
	}
}
func TestDesktopOpenVPNExecutionPublicHintKeepsPairPrivate(t *testing.T) {
	for _, paired := range []bool{true, false} {
		t.Run(fmt.Sprint(paired), func(t *testing.T) {
			a, _, _, _ := desktopOpenVPNExecutionProfiles(t, 3, "wg", "tcp", "off")
			// Select the real retained dispatcher; this empty marker is an
			// explicit source fixture, not an installed native receipt.
			directory := filepath.Join(clientRoot(a), "runtime", "native")
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "NATIVE-RUNTIME.json"), []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOMEVPN_PORTABLE", "0")
			profile := cloneRouterProfile(a.profiles.Profiles[1])
			secretKey := profile.External.OpenVPNPairing.PrivateKey
			if !paired {
				profile.External.OpenVPNPairing = nil
			}
			before := cloneRouterProfile(profile)
			view := publicProfileFor(profile)
			want := paired && nativeDesktopImportedTrioExecutionPlatformSupported() && nativeNodeChainOpenVPNPlatformSupported()
			if view.External == nil || view.External.OrderedOpenVPNExecutionMiddle != want || view.External.OrderedSOCKSExecutionMiddle || view.External.OrderedCONNECTExecutionMiddle || !reflect.DeepEqual(before, profile) {
				t.Fatal("OpenVPN public hint lost independent pairing or borrowed family")
			}
			raw, err := json.Marshal(view)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{secretKey, profile.External.OpenVPN.Username, profile.External.OpenVPN.Password} {
				if secret != "" && strings.Contains(string(raw), secret) {
					t.Fatal("OpenVPN public hint exposed private provider source")
				}
			}
		})
	}
}
