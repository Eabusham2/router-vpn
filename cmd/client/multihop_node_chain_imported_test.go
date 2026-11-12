package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/hopmeasure"
)

func installDesktopOrderedImported(t *testing.T, a *app, nodes []common.MultihopNodeSelection) {
	t.Helper()
	q := createRequestFor("shadowsocks")
	q.Method, q.Secret = "2022-blake3-aes-256-gcm", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("m", 32)))
	p, err := externalProfileFromCreateRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	p.ID, p.Name, p.StartLayer = nodes[1].ID, "Original custom middle", "off"
	p.MTUPolicy, p.ManualMTU, p.DNSMode, p.DNSProtocol, p.DNSHost, p.DNSPort = "manual", 1380, "custom", "udp", "9.9.9.9", 5353
	if err := common.NormalizeRouterProfile(&p); err != nil {
		t.Fatal(err)
	}
	a.profiles.Profiles[1] = p
	nodes[1].Mode = "shadowsocks"
	a.profiles.Profiles[2].MultihopNodes = append([]common.MultihopNodeSelection(nil), nodes...)
}

func TestDesktopOrderedImportedOriginalSourceCapture(t *testing.T) {
	a, nodes := desktopNodeChainCaptureFixture(t, 3)
	installDesktopOrderedImported(t, a, nodes)
	original := common.CloneRouterProfile(a.profiles.Profiles[1])
	capture := captureNodeChainTest(t, a, nodes)
	var wire struct {
		Schema          int      `json:"schema"`
		IdentitySources []string `json:"identity_sources"`
	}
	if json.Unmarshal([]byte(capture.input), &wire) != nil || wire.Schema != 2 || len(wire.IdentitySources) != 3 || wire.IdentitySources[1] != "" {
		t.Fatal("imported middle acquired paired identity assets")
	}
	proofs := capture.chain.ProofInventory()
	if len(proofs) != 3 || proofs[1].ProfileID != original.ID || proofs[1].NodeID != "" || proofs[1].Mode != "shadowsocks" {
		t.Fatal("original external member lost its independent proof", proofs)
	}
	if !reflect.DeepEqual(original, a.profiles.Profiles[1]) || capture.members[1].Profile.External == nil || capture.members[1].Profile.NodeKind != "external" {
		t.Fatal("capture rewrote original custom source")
	}
	for _, target := range []string{"linux", "windows", "darwin"} {
		projected, err := capture.project(context.Background(), target, 0)
		if err != nil || !reflect.DeepEqual(projected.ProofInventory(), proofs) {
			t.Fatal("native projection changed imported provenance", target, err)
		}
	}
	a.profiles.Profiles[1].External.Shadowsocks.Password = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	if capture.validate(context.Background(), a.profiles.Profiles[2], a.profiles.Profiles) == nil {
		t.Fatal("replaced imported credential retained original native authority")
	}
}

func TestDesktopOrderedImportedRejectsUnsupportedPlacementAndIdentity(t *testing.T) {
	for _, change := range []string{"first", "final", "paired-token", "hostname", "wrong-mode", "start-layer", "legacy-cipher", "missing-source"} {
		t.Run(change, func(t *testing.T) {
			a, nodes := desktopNodeChainCaptureFixture(t, 3)
			installDesktopOrderedImported(t, a, nodes)
			p := &a.profiles.Profiles[1]
			switch change {
			case "first":
				nodes[0], nodes[1] = nodes[1], nodes[0]
			case "final":
				nodes[1], nodes[2] = nodes[2], nodes[1]
			case "paired-token":
				p.NodeProofID = a.profiles.Profiles[0].NodeProofID
			case "hostname":
				p.Endpoint = "middle.example"
				p.External.Shadowsocks.Server = p.Endpoint
			case "wrong-mode":
				nodes[1].Mode = "wg"
			case "start-layer":
				p.StartLayer = "aes-256-gcm"
			case "legacy-cipher":
				p.External.Shadowsocks.Method = "aes-256-gcm"
			case "missing-source":
				p.External = nil
			}
			if _, err := resolveDesktopNodeChainMembers(a.profiles.Profiles[2], a.profiles.Profiles, nodes, "local"); err == nil {
				t.Fatal("unsupported custom path admitted")
			}
		})
	}
}

func TestConnectionProfileOrderedImportedRestoresOriginalPolicyAndRejectsCredentials(t *testing.T) {
	a, nodes := desktopNodeChainCaptureFixture(t, 3)
	installDesktopOrderedImported(t, a, nodes)
	original := common.CloneRouterProfile(a.profiles.Profiles[1])
	id := saveOrderedConnectionFixture(t, a, nodes)
	store, err := loadConnectionProfileStore(a)
	if err != nil {
		t.Fatal(err)
	}
	middle := store.Profiles[0].NodeChain[1]
	if middle.NodeKind != "external" || middle.NodeProofID != "" || middle.Preferences != nil || middle.External == nil || len(middle.Sources) != 1 || middle.Sources[0].Mode != "external-shadowsocks" {
		t.Fatal("saved custom capture invented paired identity", middle)
	}
	raw, err := os.ReadFile(connectionProfileStorePath(a))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), original.External.Shadowsocks.Password) || strings.Contains(string(raw), "private-api-") {
		t.Fatal("saved references copied source credentials")
	}
	a.profiles.Profiles[1].DNSPort = 53
	a.profiles.Profiles[1].ManualMTU = 1400
	response := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
	if response.Code != http.StatusOK {
		t.Fatal(response.Code, response.Body.String())
	}
	restored := a.profiles.Profiles[1]
	if restored.DNSPort != original.DNSPort || restored.ManualMTU != original.ManualMTU || !reflect.DeepEqual(restored.External, original.External) || restored.NodeKind != "external" {
		t.Fatal("saved imported source/policy lost")
	}
	a.profiles.Profiles[1].External.Shadowsocks.Password = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
	if response.Code == http.StatusOK {
		t.Fatal("saved profile adopted replaced imported credentials")
	}
}

func TestStartupOrderedImportedRetainsSourceKindAndDigest(t *testing.T) {
	a, nodes := startupOrderedTestApp(t, 3)
	installDesktopOrderedImported(t, a, nodes)
	capture := startupNodeChainCaptureForTest(t, a)
	receipt := startupOrderedReceipt(t, capture)
	if receipt.NodeChain.Schema != 2 || receipt.NodeChain.Nodes[1].NodeKind != "external" || receipt.NodeChain.Nodes[1].NodeProofID != "" {
		t.Fatal("startup receipt lost source kind")
	}
	raw, _ := json.Marshal(receipt)
	var decoded startupSelection
	if err := json.Unmarshal(raw, &decoded); err != nil || !reflect.DeepEqual(decoded, receipt) {
		t.Fatal("typed startup receipt failed round trip", err)
	}
	decoded.NodeChain.Nodes[1].NodeKind = ""
	if validateStartupNodeChainSelection(decoded) == nil {
		t.Fatal("startup receipt adopted external source as paired")
	}
	a.profiles.Profiles[1].External.Shadowsocks.Password = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))
	if capture.current(a) == nil {
		t.Fatal("delayed startup adopted replaced custom source")
	}
}

func TestDesktopOrderedImportedMeasurementPreservesPublicKind(t *testing.T) {
	a, nodes := desktopNodeChainCaptureFixture(t, 3)
	installDesktopOrderedImported(t, a, nodes)
	members, err := resolveDesktopNodeChainMembers(a.profiles.Profiles[2], a.profiles.Profiles, nodes, "local")
	if err != nil {
		t.Fatal(err)
	}
	status := hopmeasure.Status{Complete: true, Drained: true, Stage: "complete"}
	for i, m := range members {
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
		status.Results = append(status.Results, hopmeasure.Result{ID: m.Profile.ID, Role: role, Kind: kind, Ready: true, Idle: &hopmeasure.Latency{Samples: 6, Min: 1, Median: 2, Average: 2, P90: 3, Max: 3}, Download: &hopmeasure.Transfer{Bytes: 65536, Seconds: 0.5, Mbps: 1.048576}, Upload: &hopmeasure.Transfer{Bytes: 65536, Seconds: 1, Mbps: 0.524288}})
	}
	rows, err := desktopNodeChainMeasurementRows(status, members, 65536)
	if err != nil || len(rows) != 3 || !strings.Contains(rows[1].Speed.Proof, "public benchmark") || strings.Contains(rows[1].Speed.Proof, "authenticated bytes") {
		t.Fatal("custom speed result misrepresented public observation", err)
	}
	status.Results[1].Kind = "private-node"
	if _, err := desktopNodeChainMeasurementRows(status, members, 65536); err == nil {
		t.Fatal("custom middle accepted fabricated private API measurement")
	}
}

func TestDesktopOrderedImportedPublicCapabilityContainsNoCredentials(t *testing.T) {
	a, nodes := desktopNodeChainCaptureFixture(t, 3)
	installDesktopOrderedImported(t, a, nodes)
	original := a.profiles.Profiles[1]
	view := publicProfileFor(original)
	if view.External == nil || !view.External.OrderedMiddle || view.NodeKind != "external" {
		t.Fatal("valid custom source hidden or mislabeled")
	}
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), original.External.Shadowsocks.Password) || strings.Contains(string(raw), "node_proof_id") {
		t.Fatal("public custom capability leaked private source or paired identity")
	}
	original.External.Shadowsocks.Method = "aes-256-gcm"
	if publicProfileFor(original).External.OrderedMiddle {
		t.Fatal("unsupported cipher advertised as ordered candidate")
	}
}

func TestDesktopOrderedImportedPublicRequestRetainsEveryCurrentSource(t *testing.T) {
	a, nodes := desktopNodeChainCaptureFixture(t, 3)
	installDesktopOrderedImported(t, a, nodes)
	request := orderedPublicRequest(t, a, nodes)
	before := cloneRouterProfileStore(a.profiles)
	a.mu.Lock()
	selection, err := a.resolveNativeMultihopRequestLocked(request)
	a.mu.Unlock()
	if err != nil || len(selection.Nodes) != 3 || selection.Nodes[1].Profile.NodeKind != "external" || !reflect.DeepEqual(before, a.profiles) {
		t.Fatal("public admission substituted original imported source", err)
	}
	selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
	if err != nil || selection.Native.validate(selection) != nil || !nativeMultihopLiveProfilesCurrentContext(context.Background(), a, selection) {
		t.Fatal("public custom request did not reach original native compiler", err)
	}
	a.profiles.Profiles[1].External.Shadowsocks.Password = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
	if nativeMultihopLiveProfilesCurrentContext(context.Background(), a, selection) {
		t.Fatal("native owner adopted replacement external source")
	}
	a.mu.Lock()
	_, err = a.resolveNativeMultihopRequestLocked(request)
	a.mu.Unlock()
	if err == nil {
		t.Fatal("stale public editor token admitted changed imported source")
	}
}

func TestDesktopOrderedImportedPreservesExactAWGPhysicalEntry(t *testing.T) {
	for _, mode := range []string{"awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			a, nodes := desktopNodeChainCaptureFixture(t, 3)
			installOrderedAWGAssets(t, a, nodes, []string{mode, "wg", "shadowsocks"}, "off")
			installDesktopOrderedImported(t, a, nodes)
			capture := captureNodeChainTest(t, a, nodes)
			proofs := capture.chain.ProofInventory()
			if proofs[0].Mode != mode || proofs[1].NodeID != "" || proofs[1].ProfileID != nodes[1].ID {
				t.Fatal("custom graph substituted first physical cipher or middle identity")
			}
			egress, err := capture.chain.PhysicalEgress()
			if err != nil || len(egress) != 1 || egress[0].Host != a.profiles.Profiles[0].Endpoint {
				t.Fatal("custom graph added a physical bypass", egress, err)
			}
		})
	}
}
