package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
)

// Real private assets reach the shipping source readers and shared compiler.
// These tests own no TUN or native encrypted peer; those gates remain separate.
func installDesktopOrderedHysteriaFinal(t *testing.T, a *app, nodes []common.MultihopNodeSelection) string {
	t.Helper()
	last := &a.profiles.Profiles[len(nodes)-1]
	last.StartLayer = "off"
	nodes[len(nodes)-1].Mode = "hysteria2"
	last.MultihopNodes = append([]common.MultihopNodeSelection(nil), nodes...)
	certificate, _ := nativeMultihopTrafficCertificate(t)
	graph := map[string]any{
		"inbounds": []any{map[string]any{"type": "tun", "auto_route": true, "strict_route": true}},
		"route":    map[string]any{"final": "proxy"},
		"outbounds": []any{map[string]any{"type": "hysteria2", "tag": "proxy", "server": last.Endpoint,
			"server_port": 8443, "password": "original-ordered-hysteria-password",
			"obfs": map[string]any{"type": "salamander", "password": "original-ordered-salamander"},
			"tls":  map[string]any{"enabled": true, "server_name": "exit-certificate.example", "certificate_path": "cert.pem"}}},
	}
	raw, err := json.Marshal(graph)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(clientRoot(a), "generated", last.ID, "hysteria2")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string][]byte{"sing-box.json": raw, "cert.pem": []byte(certificate)} {
		if err := os.WriteFile(filepath.Join(dir, name), value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return certificate
}

func desktopOrderedHysteriaFixture(t *testing.T, count int, first string) (*app, []common.MultihopNodeSelection, string) {
	t.Helper()
	a, nodes := desktopNodeChainCaptureFixture(t, count)
	modes := make([]string, count)
	for i := range modes {
		modes[i] = []string{"wg", "awg2-fast", "awg2-strong"}[i%3]
	}
	modes[0], modes[count-1] = first, "shadowsocks"
	installOrderedAWGAssets(t, a, nodes, modes, "off")
	// Installed desktop graph projection requires the original protected owner.
	// A source-only node fixture does not implicitly grant that authority.
	for i := range a.profiles.Profiles {
		a.profiles.Profiles[i].KillSwitch, a.profiles.Profiles[i].KillSwitchPolicy = true, "on-connect"
	}
	return a, nodes, installDesktopOrderedHysteriaFinal(t, a, nodes)
}

func captureDesktopOrderedHysteria(t *testing.T, a *app, nodes []common.MultihopNodeSelection) multihopSelection {
	t.Helper()
	control, _ := a.profileByIDLocked(a.profiles.SelectedID)
	selection, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
	if err == nil {
		selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"hysteria2"}, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	return selection
}

func TestDesktopOrderedHysteriaPreservesCompleteCapturedSources(t *testing.T) {
	for _, first := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, count := range []int{2, 3, 8} {
			t.Run(fmt.Sprintf("%s/%d", first, count), func(t *testing.T) {
				a, nodes, certificate := desktopOrderedHysteriaFixture(t, count, first)
				before := cloneRouterProfileStore(a.profiles)
				selection := captureDesktopOrderedHysteria(t, a, nodes)
				chain := selection.Native.chain.chain
				var graph map[string]any
				if json.Unmarshal([]byte(chain.Config()), &graph) != nil {
					t.Fatal("compiled ordered graph missing")
				}
				var final map[string]any
				for _, raw := range graph["outbounds"].([]any) {
					row := raw.(map[string]any)
					if row["tag"] == chain.FinalTag() {
						final = row
					}
				}
				if final == nil || final["type"] != "hysteria2" || final["password"] != "original-ordered-hysteria-password" ||
					final["server"] != selection.Exit.Endpoint || final["detour"] != chain.ProofInventory()[count-2].Tag {
					t.Fatal("desktop capture changed Hysteria2 final or bypassed a selected prefix")
				}
				tls := final["tls"].(map[string]any)
				if tls["enabled"] != true || tls["insecure"] == true || tls["server_name"] != "exit-certificate.example" ||
					tls["certificate_path"] != nil || tls["certificate"].([]any)[0] != certificate ||
					final["obfs"].(map[string]any)["password"] != "original-ordered-salamander" {
					t.Fatal("desktop capture changed original TLS trust or Salamander credential")
				}
				for _, target := range []string{"windows", "linux", "darwin"} {
					launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), target)
					if err != nil || validateDesktopNodeChainLaunch(context.Background(), launch) != nil ||
						launch.mode != "hysteria2" || launch.chain.policy.Metadata().Mode != "hysteria2" || launch.chain.ready != nil {
						t.Fatal("host projection lost exact original final or invented readiness", target, err)
					}
				}
				if chain.Progress().Ready || !reflect.DeepEqual(before, a.profiles) || a.cmd != nil {
					t.Fatal("source capture mutated profiles or invented a connected runtime")
				}
				changed := selection
				changed.ExitMode = "shadowsocks"
				if selection.Native.validateNodeChainSelection(changed) == nil {
					t.Fatal("another final mode borrowed the original native capture")
				}
			})
		}
	}
}

func TestDesktopOrderedHysteriaKeepsAdmissionAndSourceBoundaries(t *testing.T) {
	for _, fault := range []string{"aes-layer", "xor-layer", "imported-middle", "server", "compare", "hostname", "wrong-capture-mode", "changed-trust", "changed-credential"} {
		t.Run(fault, func(t *testing.T) {
			a, nodes, _ := desktopOrderedHysteriaFixture(t, 3, "awg2-fast")
			last := &a.profiles.Profiles[2]
			if fault == "changed-trust" || fault == "changed-credential" {
				selection := captureDesktopOrderedHysteria(t, a, nodes)
				name := "cert.pem"
				if fault == "changed-credential" {
					name = "sing-box.json"
				}
				path := filepath.Join(clientRoot(a), "generated", last.ID, "hysteria2", name)
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if name == "sing-box.json" {
					raw = []byte(strings.Replace(string(raw), "original-ordered-hysteria-password", "replacement-private-password", 1))
				} else {
					cert, _ := nativeMultihopTrafficCertificate(t)
					raw = []byte(cert)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
				if selection.Native.chain.currentContext(context.Background(), a) == nil {
					t.Fatal("changed Hysteria2 private source retained old capture")
				}
				return
			}
			execution := "local"
			switch fault {
			case "aes-layer":
				last.StartLayer = "aes-256-gcm"
			case "xor-layer":
				last.StartLayer = "aes-256-gcm+xor-whitening"
			case "imported-middle":
				installDesktopOrderedImported(t, a, nodes)
			case "server":
				execution = "server"
			case "compare":
				execution = "auto"
			case "hostname":
				last.Endpoint = "final.example.test"
			}
			control, _ := a.profileByIDLocked(a.profiles.SelectedID)
			if fault == "wrong-capture-mode" {
				selection, err := resolveDesktopNodeChainSelection(control, a.profiles.Profiles, nodes, "local")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil); err == nil {
					t.Fatal("Hysteria2 capture accepted a different requested final")
				}
				return
			}
			lookups := 0
			_, err := captureDesktopNodeChain(context.Background(), clientRoot(a), control, a.profiles.Profiles, nodes, execution,
				func(context.Context, string) ([]netip.Addr, error) { lookups++; return nil, nil })
			if err == nil || lookups != 0 {
				t.Fatal("unsupported ordered final acquired source or ambient lookup authority", fault, err)
			}
		})
	}
}

func TestDesktopOrderedHysteriaSavedProfileRestoresExactPolicyAndSourceReferences(t *testing.T) {
	a, nodes, _ := desktopOrderedHysteriaFixture(t, 3, "awg2-strong")
	last := &a.profiles.Profiles[2]
	last.MTUPolicy, last.ManualMTU, last.IPv6Mode, last.HomeLANAccess = "manual", 1280, "off", false
	response := postSetup(t, a, "/api/connection-profile/setup/save", map[string]any{
		"name": "Ordered Hysteria2", "mode": "hysteria2", "multihop_enabled": true, "multihop_execution": "local", "multihop_nodes": nodes,
	})
	if response.Code != http.StatusOK {
		t.Fatalf("saved Hysteria2 profile rejected: %d %s", response.Code, response.Body.String())
	}
	store, err := loadConnectionProfileStore(a)
	if err != nil || len(store.Profiles) != 1 {
		t.Fatal("saved profile missing", err)
	}
	record := store.Profiles[0]
	var modes []string
	for _, source := range record.NodeChain[2].Sources {
		modes = append(modes, source.Mode)
	}
	if record.Mode != "hysteria2" || record.NodeChain[2].Mode != "hysteria2" || !reflect.DeepEqual(modes, []string{"wg", "hysteria2"}) {
		t.Fatal("saved Hysteria2 source inventory substituted SS or omitted peer identity")
	}
	raw, _ := os.ReadFile(connectionProfileStorePath(a))
	for _, secret := range []string{"original-ordered-hysteria-password", "original-ordered-salamander", "BEGIN CERTIFICATE", "private-api-"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("saved connection copied private source instead of references")
		}
	}
	a.profiles.Profiles[2].MTUPolicy, a.profiles.Profiles[2].ManualMTU, a.profiles.Profiles[2].IPv6Mode, a.profiles.Profiles[2].HomeLANAccess = "auto", 0, "on", true
	response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": record.ID})
	if response.Code != http.StatusOK {
		t.Fatalf("saved Hysteria2 profile restore failed: %d %s", response.Code, response.Body.String())
	}
	last = &a.profiles.Profiles[2]
	if last.MTUPolicy != "manual" || last.ManualMTU != 1280 || last.IPv6Mode != "off" || last.HomeLANAccess ||
		!reflect.DeepEqual(last.MultihopNodes, nodes) || last.APIToken != "private-api-2" || a.state.Connected || a.cmd != nil {
		t.Fatal("saved Hysteria2 restore changed complete policy, credentials or connection state")
	}
	_ = captureDesktopOrderedHysteria(t, a, nodes)
	before := cloneRouterProfileStore(a.profiles)
	path := filepath.Join(clientRoot(a), "generated", last.ID, "hysteria2", "cert.pem")
	cert, _ := nativeMultihopTrafficCertificate(t)
	if err := os.WriteFile(path, []byte(cert), 0600); err != nil {
		t.Fatal(err)
	}
	response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": record.ID})
	if response.Code == http.StatusOK || !reflect.DeepEqual(before, a.profiles) {
		t.Fatal("changed Hysteria2 trust was restored under an old saved source or partially mutated profiles")
	}
}

func TestDesktopOrderedHysteriaStartupRetainsFinalAndRejectsBorrowedLast(t *testing.T) {
	a, nodes := startupOrderedTestApp(t, 3)
	installDesktopOrderedHysteriaFinal(t, a, nodes)
	capture := startupNodeChainCaptureForTest(t, a)
	last := startupOrderedReceipt(t, capture)
	if last.RuntimeMode != "hysteria2" || last.NodeChain.Nodes[2].Mode != "hysteria2" || len(last.NodeChain.Nodes[2].Sources) != 2 {
		t.Fatal("startup receipt replaced final mode or captured another source family")
	}
	var round startupSelection
	raw, _ := json.Marshal(last)
	if json.Unmarshal(raw, &round) != nil || !reflect.DeepEqual(last, round) {
		t.Fatal("strict startup receipt lost exact Hysteria2 source")
	}
	for _, fault := range []string{"mode", "imported-schema", "layer-inventory"} {
		var changed startupSelection
		if json.Unmarshal(raw, &changed) != nil {
			t.Fatal("original receipt missing")
		}
		switch fault {
		case "mode":
			changed.RuntimeMode = "shadowsocks"
		case "imported-schema":
			changed.NodeChain.Schema = 2
		case "layer-inventory":
			changed.NodeChain.Nodes[2].Sources = append(changed.NodeChain.Nodes[2].Sources,
				connectionProfileNodeSource{Mode: "shadowsocks", SHA256: strings.Repeat("a", 64)})
		}
		if validateStartupNodeChainSelection(changed) == nil {
			t.Fatal("Hysteria2 Last accepted an unproved family or final layer", fault)
		}
	}
	h := startupOrderedDriver(t, context.Background(), a)
	driver, err := a.nodeChainStartupDriver(context.Background(), capture, h.driver)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := driver.capture(a, capture.nodeChain.selection, []string{"shadowsocks"}); err == nil || h.captures != 0 {
		t.Fatal("scheduled Hysteria2 path accepted another transport before original capture")
	}
	selection, err := driver.capture(a, capture.nodeChain.selection, []string{"hysteria2"})
	if err != nil || selection.Native == nil || h.captures != 1 || selection.ExitMode != "hysteria2" {
		t.Fatal("startup adapter lost exact Hysteria2 source", err)
	}
	if _, err := driver.capture(a, capture.nodeChain.selection, []string{"hysteria2"}); err == nil || h.captures != 1 {
		t.Fatal("scheduled Hysteria2 owner accepted a replacement native capture")
	}
}

func TestDesktopOrderedHysteriaPrefixPreparationKeepsFinalAsUncontactedProvenance(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		t.Skip("public selected-prefix admission remains closed on this platform")
	}
	a, request := orderedPreparationFixture(t, "awg2-fast")
	nodes := append([]common.MultihopNodeSelection(nil), a.profiles.Profiles[2].MultihopNodes...)
	installDesktopOrderedHysteriaFinal(t, a, nodes)
	request.Scope = orderedCandidateSavedPrefixScope
	observe := func(ctx context.Context) (string, error) { return "original-physical-network", ctx.Err() }
	view, err := captureOrderedCandidatePreparedViewScope(context.Background(), a, 0, request.Scope, observe)
	if err != nil {
		t.Fatal(err)
	}
	preparation := beginOrderedPreparationFixture(t, a, request)
	if !view.matchesPreparation(preparation, time.Now()) || preparation.selection.ExitMode != "hysteria2" || preparation.prefixPreparation == nil {
		t.Fatal("saved Hysteria2 prefix view lost original complete provenance")
	}
	config := preparation.prefixPreparation.Config()
	for _, forbidden := range []string{`"type":"hysteria2"`, "original-ordered-hysteria-password", a.profiles.Profiles[2].Endpoint} {
		if strings.Contains(config, forbidden) {
			t.Fatal("prefix-only graph constructed its saved Hysteria2 final")
		}
	}
	var metadata map[string]any
	if json.Unmarshal([]byte(preparation.prefixPreparation.Metadata()), &metadata) != nil || metadata["ready"] != false ||
		metadata["application_open"] != false || metadata["dns_open"] != false || a.cmd != nil || a.state.Connected {
		t.Fatal("source-only prefix preparation acquired connected authority")
	}
}
