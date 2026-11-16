//go:build linux || windows || (darwin && (amd64 || arm64))

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func orderedTypedPrefixFixture(t *testing.T, count int, protocol string) (*app, orderedCandidatePreparationRequest) {
	t.Helper()
	mode := map[int]string{3: "wg", 4: "awg2-fast", 8: "awg2-strong"}[count]
	var a *app
	var nodes []common.MultihopNodeSelection
	if protocol == "socks5" {
		a, nodes = desktopSOCKSPrefixCaptureFixture(t, count-2, mode, "password", "off")
	} else {
		a, nodes = desktopCONNECTPrefixCaptureFixture(t, count-2, mode, "password", "off")
		if protocol == "http-connect" {
			middle, err := externalProfileFromCreateRequest(createRequestFor(protocol))
			if err != nil {
				t.Fatal(err)
			}
			middle.ID, middle.Name, middle.StartLayer = nodes[count-2].ID, "Original HTTP CONNECT middle", "off"
			middle.MTUPolicy, middle.ManualMTU = "manual", 1380
			middle.DNSMode, middle.DNSProtocol, middle.DNSHost, middle.DNSPort = "custom", "tcp", "9.9.9.9", 5353
			middle.KillSwitchPolicy, middle.IPv6Mode, middle.HomeLANAccess = "always", "off", false
			if err := common.NormalizeRouterProfile(&middle); err != nil {
				t.Fatal(err)
			}
			a.profiles.Profiles[count-2] = middle
			nodes[count-2].Mode = protocol
			a.profiles.Profiles[count-1].MultihopNodes = append([]common.MultihopNodeSelection(nil), nodes...)
		}
	}
	a.state.Connected, a.state.Mode, a.state.Phase = false, "off", "off"
	id := desktopCandidateAddCustomSource(t, a, "2022-blake3-aes-256-gcm")
	return a, orderedCandidatePreparationRequest{RequestID: strings.Repeat("a", 32), Position: count - 3, CandidateIDs: []string{id}, Samples: 50, Scope: orderedCandidateSavedPrefixScope}
}

func testOrderedCandidateTypedPrefix(t *testing.T, protocol string) {
	for _, count := range []int{3, 4, 8} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			a, q := orderedTypedPrefixFixture(t, count, protocol)
			before, state := cloneRouterProfileStore(a.profiles), a.state
			observe := func(ctx context.Context) (string, error) { return "original-physical-network", ctx.Err() }
			view, err := captureOrderedCandidatePreparedViewScope(context.Background(), a, q.Position, q.Scope, observe)
			if err != nil {
				t.Fatal("typed saved-prefix chooser refused its original complete route", err)
			}
			p, err := beginOrderedCandidatePreparationWithNetwork(context.Background(), a, q, observe)
			if err != nil {
				t.Fatal("typed saved-prefix purpose was blocked by absent suffix execution", err)
			}
			t.Cleanup(func() { _ = p.finish() })
			if !view.matchesPreparation(p, time.Now()) || p.inventory.plan != nil || p.prefixPreparation != p.inventory.prefixPreparation || p.prefixPreparation == nil ||
				len(view.prefixes) != count-2 || len(p.selection.Nodes) != count || p.selection.Nodes[count-2].Mode != protocol || p.prefixPreparation.OriginalSourceSHA256() != p.selection.Native.source {
				t.Fatal("typed prefix lost its whole route, selected position or exact independent owner")
			}
			var envelope struct {
				Kind           string `json:"kind"`
				OriginalSource string `json:"original_source"`
			}
			if json.Unmarshal([]byte(p.prefixPreparation.Source()), &envelope) != nil {
				t.Fatal("typed prefix source is unreadable")
			}
			family, schema := "connect", 4
			if protocol == "socks5" {
				family, schema = "socks", 3
			}
			var original mobilemultihop.NodeChainSource
			if envelope.Kind != "routervpn-node-chain-"+family+"-candidate-preparation" || envelope.OriginalSource != p.selection.Native.chain.input ||
				json.Unmarshal([]byte(envelope.OriginalSource), &original) != nil || original.Schema != schema || len(original.Nodes) != count || len(original.IdentitySources) != count || original.IdentitySources[count-2] != "" {
				t.Fatal("typed prefix detached or reconstructed a different original source family")
			}
			if _, err := mobilemultihop.ParseNodeChainCandidatePreparation(p.prefixPreparation.Source()); err == nil {
				t.Fatal("typed prefix acquired generic preparation authority")
			}
			if _, err := captureDesktopNodeChainCandidateSources(context.Background(), a, p.inventory.launch, q.Position, q.CandidateIDs); err == nil || p.inventory.current(context.Background()) == nil {
				t.Fatal("typed prefix widened the independent connected/full-path gate")
			}
			launch, err := newDesktopNodeCandidatePrefixLaunchForPurpose(context.Background(), p.selection, strings.Repeat("b", 32), "windows", p)
			if err != nil {
				t.Fatal("typed prefix failed its original desktop policy projection", err)
			}
			meta := launch.candidatePrefix.policy.Metadata()
			if meta.ApplicationOpen || meta.DNSOpen || len(meta.Prefixes) != count-2 || meta.PrefixPosition != q.Position || meta.OriginalSourceSHA256 != p.selection.Native.source || meta.PolicyProfileID != before.SelectedID ||
				meta.KillSwitchPolicy != "always" || meta.IPv6Mode != "off" || meta.HomeLANAccess || launch.chain != nil || launch.command != nil {
				t.Fatal("typed prefix lost the absent proxy/final policies or opened ordinary traffic", meta)
			}
			if err := p.finish(); err != nil {
				t.Fatal(err)
			}
			if !p.down || !p.owner.drained || a.candidatePreparation != nil || a.connectionContext != nil || a.cmd != nil || a.state != state || !reflect.DeepEqual(a.profiles, before) {
				t.Fatal("unused typed prefix changed the complete saved path or connection")
			}
		})
	}
}

func TestOrderedCandidateTypedPrefixSOCKS(t *testing.T) { testOrderedCandidateTypedPrefix(t, "socks5") }
func TestOrderedCandidateTypedPrefixHTTP(t *testing.T) {
	testOrderedCandidateTypedPrefix(t, "http-connect")
}
func TestOrderedCandidateTypedPrefixHTTPS(t *testing.T) {
	testOrderedCandidateTypedPrefix(t, "https-connect")
}

func testOrderedCandidateTypedPrefixRefusals(t *testing.T, protocol string) {
	for _, fault := range []string{"complete-scope", "imported-position", "final-position", "credential", "prefix-token", "final-token", "final-asset", "equal-preparation", "network", "generic-plan", "mixed-policy", "foreign-projection"} {
		t.Run(fault, func(t *testing.T) {
			a, q := orderedTypedPrefixFixture(t, 4, protocol)
			switch fault {
			case "complete-scope":
				q.Scope = orderedCandidateSavedCompleteScope
			case "imported-position":
				q.Position = 2
			case "final-position":
				q.Position = 3
			}
			observe := func(ctx context.Context) (string, error) { return "original-physical-network", ctx.Err() }
			p, err := beginOrderedCandidatePreparationWithNetwork(context.Background(), a, q, observe)
			if fault == "complete-scope" || fault == "imported-position" || fault == "final-position" {
				if err == nil {
					_ = p.finish()
					t.Fatal("typed prefix adopted connected authority or imported/final position")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = p.finish() })
			switch fault {
			case "credential":
				middle := a.profiles.Profiles[2].External
				if protocol == "socks5" {
					middle.SOCKS5.Password += "-replacement"
				} else if protocol == "http-connect" {
					middle.HTTPConnect.Password += "-replacement"
				} else {
					middle.HTTPSConnect.Password += "-replacement"
				}
			case "prefix-token":
				a.profiles.Profiles[0].APIToken += "-replacement"
			case "final-token":
				a.profiles.Profiles[3].APIToken += "-replacement"
			case "final-asset":
				path := filepath.Join(clientRoot(a), "generated", a.profiles.SelectedID, "shadowsocks", "sing-box.json")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "equal-preparation":
				other, err := mobilemultihop.ParseNodeChainCandidatePreparationCapture(p.prefixPreparation.Source())
				if err != nil {
					t.Fatal(err)
				}
				p.prefixPreparation = other
			case "network":
				p.observeNetwork = func(ctx context.Context) (string, error) { return "replacement-network", ctx.Err() }
			case "generic-plan":
				p.inventory.plan = &mobilemultihop.NodeChainCandidatePlan{}
			case "mixed-policy":
				p.inventory.launch.chain.policy = &mobilemultihop.DesktopNodeChainPolicy{}
			case "foreign-projection":
				p.inventory.launch.chain.input += " "
			}
			if p.sourceCurrent(context.Background()) == nil || !p.invalidated.Load() || a.state.Connected {
				t.Fatal("typed prefix adopted a substituted original source, purpose or projection", fault)
			}
		})
	}
}

func TestOrderedCandidateTypedPrefixSOCKSRefusals(t *testing.T) {
	testOrderedCandidateTypedPrefixRefusals(t, "socks5")
}
func TestOrderedCandidateTypedPrefixHTTPRefusals(t *testing.T) {
	testOrderedCandidateTypedPrefixRefusals(t, "http-connect")
}
func TestOrderedCandidateTypedPrefixHTTPSRefusals(t *testing.T) {
	testOrderedCandidateTypedPrefixRefusals(t, "https-connect")
}
