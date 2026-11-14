package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
	"router-vpn/internal/macosprocess"
	"router-vpn/internal/mobilemultihop"
)

func desktopSOCKSParentFixture(t *testing.T, mode string) (*app, multihopSelection, *desktopNodeLaunch) {
	t.Helper()
	a, nodes := desktopSOCKSCaptureFixture(t, mode, "password", "off")
	selected, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[2], a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal(err)
	}
	selected, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selected, []string{"shadowsocks"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := newDesktopNodeChainLaunch(selected, strings.Repeat("a", 32), "darwin")
	if err != nil {
		t.Fatal(err)
	}
	return a, selected, launch
}

func TestDesktopSOCKSParentRetainsExactTypedAuthority(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			a, selected, launch := desktopSOCKSParentFixture(t, mode)
			original := selected.Native.chain.socks
			if original.original.chain != nil || original.original.host != nil || original.original.socks != nil || selected.Native.chain.chain != nil || launch.chain.policy != nil || launch.chain.socksPolicy == nil {
				t.Fatal("typed parent acquired generic authority")
			}
			if err := validateDesktopNodeChainLaunch(context.Background(), launch); err != nil {
				t.Fatal(err)
			}
			if err := selected.Native.chain.currentContext(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			parsed, err := mobilemultihop.ParseDesktopNodeChainSOCKSLaunchInput(launch.chain.input)
			if err != nil || parsed.Config() != string(launch.config) {
				t.Fatal("typed launch lost original private input", err)
			}
			if _, err := mobilemultihop.ParseDesktopNodeChainLaunchInput(launch.chain.input); err == nil {
				t.Fatal("typed launch became ordinary source")
			}
			_, meta, physical, err := launch.chain.readPolicy()
			if err != nil || meta.OriginalSourceSHA256 != selected.Native.source || len(meta.Prefixes) != 3 || meta.Prefixes[1].Kind != "public-path" || meta.Prefixes[1].NodeID != "" || len(physical.PhysicalRoots) != 1 {
				t.Fatal("typed projection changed source or proof inventory", err)
			}
			if launch.chain.sourceName() != "node-chain-socks-source.json" || launch.chain.readyName() != "node-chain-socks-ready.json" || launch.chain.macOSFamily() != macosprocess.NodeChainSOCKSFamily {
				t.Fatal("typed native dispatch changed family")
			}
			budget, err := desktopNodeReadyBudget(launch)
			if err != nil || budget != 65*time.Second {
				t.Fatal("typed readiness changed original complete budget", budget, err)
			}
			for _, target := range []string{"linux", "windows"} {
				native, err := newDesktopNodeChainLaunch(selected, strings.Repeat("b", 32), target)
				if err != nil || native.chain.socksPolicy == nil || native.chain.policy != nil || !native.chain.originalPolicyCurrent() || nativeNodeChainSOCKSPlatformSupported() {
					t.Fatal("typed internal adapter changed source or opened public admission before native acceptance", target, err)
				}
			}
		})
	}
}

func TestDesktopSOCKSParentRejectsSubstitution(t *testing.T) {
	for _, fault := range []string{"missing-source", "foreign-source", "ordinary-policy", "changed-member", "changed-source", "changed-scope", "changed-input", "changed-config"} {
		t.Run(fault, func(t *testing.T) {
			a, selection, launch := desktopSOCKSParentFixture(t, "awg2-strong")
			switch fault {
			case "missing-source":
				selection.Native.chain.socks.source = nil
			case "foreign-source":
				other := captureDesktopSOCKSTest(t, a, nodeChainSelectedReferences(selection.Nodes))
				foreign, err := mobilemultihop.NewDesktopNodeChainSOCKSPolicy(other.source, launch.mtuSession, "darwin", 0)
				if err != nil {
					t.Fatal(err)
				}
				launch.chain.socksPolicy = foreign
			case "ordinary-policy":
				_, ordinary := desktopNodeChainLaunchFixture(t, 3, "darwin")
				launch.chain.policy = ordinary.chain.policy
			case "changed-member":
				launch.chain.selection.Nodes[1].Profile.External.SOCKS5.Password += "-foreign"
			case "changed-source":
				selection.Native.source = strings.Repeat("f", 64)
			case "changed-scope":
				launch.mtuSession = strings.Repeat("b", 32)
			case "changed-input":
				launch.chain.input += " "
			case "changed-config":
				launch.config = append(launch.config, ' ')
			}
			if validateDesktopNodeChainLaunch(context.Background(), launch) == nil {
				t.Fatal("substituted typed parent accepted", fault)
			}
		})
	}
}

func TestDesktopSOCKSParentReadyUsesTypedParser(t *testing.T) {
	_, _, launch := desktopSOCKSParentFixture(t, "wg")
	_, meta, capture, err := launch.chain.readPolicy()
	if err != nil {
		t.Fatal(err)
	}
	r := mobilemultihop.DesktopNodeChainSOCKSReadyRecord{Schema: 1, Kind: "routervpn-node-chain-socks-ready-v1", SourceSHA256: meta.SourceSHA256, TransferSHA256: strings.Repeat("b", 64), DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256,
		Identity: mobilemultihop.NodeChainIdentity{EngineID: "original-engine", SessionID: meta.SessionID, NetworkID: "original-network", SourceSHA256: meta.OriginalSourceSHA256, ConfigSHA256: meta.ConfigSHA256}, Generation: 1, Reader: 1, InterfaceName: "utun91", InterfaceIndex: 91, MTU: capture.ConfiguredMTU, ObservedAt: time.Now().UnixMilli()}
	raw, err := mobilemultihop.CanonicalDesktopNodeChainSOCKSReadyRecord(r, launch.chain.socksPolicy, r.TransferSHA256)
	if err != nil {
		t.Fatal(err)
	}
	got, err := launch.chain.parseReady(raw, r.TransferSHA256)
	if err != nil || got != mobilemultihop.DesktopNodeChainReadyRecord(r) {
		t.Fatal("typed proof changed", err)
	}
	for _, fault := range []string{"ordinary-kind", "foreign-transfer", "foreign-source", "foreign-dns"} {
		t.Run(fault, func(t *testing.T) {
			changed := r
			switch fault {
			case "ordinary-kind":
				changed.Kind = "routervpn-node-chain-ready-v1"
			case "foreign-transfer":
				changed.TransferSHA256 = strings.Repeat("e", 64)
			case "foreign-source":
				changed.SourceSHA256 = strings.Repeat("e", 64)
			case "foreign-dns":
				changed.DNSConfigSHA256 = strings.Repeat("e", 64)
			}
			raw, _ := json.Marshal(changed)
			if _, err := launch.chain.parseReady(raw, r.TransferSHA256); err == nil {
				t.Fatal("typed readiness accepted borrowed evidence")
			}
		})
	}
}

func TestConnectionProfileOrderedSOCKSCompleteTransactions(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			a, nodes := desktopSOCKSCaptureFixture(t, mode, "password", "off")
			// Saved profiles retain an explicit Local choice; empty legacy values
			// are independently canonicalized by the existing profile format.
			a.profiles.Profiles[1].MultihopExecution = "local"
			original := cloneRouterProfileStore(a.profiles)
			id := saveOrderedConnectionFixture(t, a, nodes)
			saved, err := loadConnectionProfileStore(a)
			if err != nil {
				t.Fatal(err)
			}
			middle := saved.Profiles[0].NodeChain[1]
			if middle.NodeKind != "external" || middle.External == nil || middle.External.Protocol != "socks5" || middle.Preferences != nil || middle.NodeProofID != "" || len(middle.Sources) != 1 || middle.Sources[0].Mode != "external-socks5" {
				t.Fatal("saved typed profile lost exact original identity")
			}
			raw, err := os.ReadFile(connectionProfileStorePath(a))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), original.Profiles[1].External.SOCKS5.Password) || strings.Contains(string(raw), original.Profiles[1].External.SOCKS5.Username) {
				t.Fatal("saved profile copied SOCKS credentials")
			}
			a.profiles.Profiles[1].DNSPort = 53
			a.profiles.Profiles[1].ManualMTU = 1400
			a.profiles.Profiles[1].IPv6Mode = "on"
			a.profiles.Profiles[1].HomeLANAccess = true
			response := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
			if response.Code != http.StatusOK {
				t.Fatal(response.Code, response.Body.String())
			}
			if !reflect.DeepEqual(a.profiles.Profiles[1], original.Profiles[1]) || a.cmd != nil || a.state.Connected {
				var fields []string
				actual, expected := reflect.ValueOf(a.profiles.Profiles[1]), reflect.ValueOf(original.Profiles[1])
				for i := 0; i < actual.NumField(); i++ {
					if !reflect.DeepEqual(actual.Field(i).Interface(), expected.Field(i).Interface()) {
						fields = append(fields, actual.Type().Field(i).Name)
					}
				}
				t.Fatal("Load changed complete policy fields or connected", fields, a.cmd != nil, a.state.Connected)
			}
			a.profiles.Profiles[1].ManualMTU = 1360
			response = postSetup(t, a, "/api/connection-profile/setup/update", map[string]any{"id": id, "name": "Updated typed path", "mode": "shadowsocks", "multihop_enabled": true, "multihop_execution": "local", "multihop_nodes": nodes})
			if response.Code != http.StatusOK {
				t.Fatal(response.Code, response.Body.String())
			}
			a.profiles.Profiles[1].ManualMTU = 1400
			response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
			if response.Code != http.StatusOK || a.profiles.Profiles[1].ManualMTU != 1360 {
				t.Fatal("Update did not retain current complete typed policy", response.Code, response.Body.String())
			}
			a.profiles.Profiles[1].External.SOCKS5.Password += "-replaced"
			before := cloneRouterProfileStore(a.profiles)
			response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
			if response.Code == http.StatusOK || !reflect.DeepEqual(a.profiles, before) {
				t.Fatal("Load accepted replaced credential or partially published")
			}
			response = postSetup(t, a, "/api/connection-profile/setup/delete", map[string]any{"id": id})
			if response.Code != http.StatusOK || !reflect.DeepEqual(a.profiles, before) {
				t.Fatal("Delete changed private source", response.Code, response.Body.String())
			}
		})
	}
}

func TestDesktopSOCKSParentMeasurementRequiresPublicMiddle(t *testing.T) {
	_, selection, _ := desktopSOCKSParentFixture(t, "wg")
	status := hopmeasure.Status{Complete: true, Drained: true, Stage: "complete"}
	for i, member := range selection.Nodes {
		role, kind := "intermediate", "private-node"
		if i == 0 {
			role = "entry"
		}
		if i == 2 {
			role = "exit"
		}
		if i == 1 {
			kind = "public-path"
		}
		status.Results = append(status.Results, hopmeasure.Result{ID: member.Profile.ID, Role: role, Kind: kind, Ready: true, Idle: &hopmeasure.Latency{Samples: 6, Min: 1, Median: 2, Average: 2, P90: 3, Max: 3}, Download: &hopmeasure.Transfer{Bytes: 65536, Seconds: 0.5, Mbps: 1.048576}, Upload: &hopmeasure.Transfer{Bytes: 65536, Seconds: 1, Mbps: 0.524288}})
	}
	rows, err := desktopNodeChainMeasurementRows(status, selection.Nodes, 65536)
	if err != nil || len(rows) != 3 || !strings.Contains(rows[1].Speed.Proof, "public benchmark") {
		t.Fatal("typed measurement lost public middle", err)
	}
	status.Results[1].Kind = "private-node"
	if _, err := desktopNodeChainMeasurementRows(status, selection.Nodes, 65536); err == nil {
		t.Fatal("typed middle borrowed private-node authority")
	}
}

func TestDesktopSOCKSParentLastRetainsPrivateDigest(t *testing.T) {
	_, selection, _ := desktopSOCKSParentFixture(t, "wg")
	capture := &startupNodeChainCapture{root: selection.Native.root, selection: selection}
	for _, member := range selection.Nodes {
		sources, err := captureSavedNodeChainSources(capture.root, member.Profile, member.Mode)
		if err != nil {
			t.Fatal(err)
		}
		for _, source := range sources {
			capture.assets = append(capture.assets, viaEntryAsset{member.Profile.ID, source.Mode, source.SHA256})
		}
	}
	last := startupSelection{RouterID: selection.Control.ID, RuntimeMode: selection.ExitMode, LogicalMode: "multihop", Base: selection.Base, ProfileToken: startupExternalProfileToken(selection.Control), UpdatedAt: time.Now().UTC(), NodeChain: capture.receipt(), PathKind: startupNodeChainPathKind}
	raw, err := json.Marshal(last)
	if err != nil {
		t.Fatal(err)
	}
	var decoded startupSelection
	if err := json.Unmarshal(raw, &decoded); err != nil || !reflect.DeepEqual(decoded, last) || decoded.NodeChain.Schema != 3 {
		t.Fatal("Last lost exact typed inventory", err)
	}
	decoded.NodeChain.Schema = 2
	if validateStartupNodeChainSelection(decoded) == nil {
		t.Fatal("typed Last borrowed original imported SS schema")
	}
	// The complete source retains the same original references, without private values.
	if decoded.NodeChain.Nodes[1].Sources[0].Mode != "external-socks5" || len(decoded.NodeChain.Nodes) != 3 || common.ValidateMultihopNodes(nodeChainSelectedReferences(selection.Nodes)) != nil {
		t.Fatal("Last lost source kind")
	}
}
