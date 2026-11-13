package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
)

func installDesktopOrderedHostname(t *testing.T, a *app, nodes []common.MultihopNodeSelection) {
	t.Helper()
	installDesktopOrderedImported(t, a, nodes)
	p := &a.profiles.Profiles[1]
	p.Endpoint = "middle.example.test"
	p.External.Shadowsocks.Server = p.Endpoint
	p.DNSMode, p.DNSProtocol, p.DNSHost, p.DNSPort = "custom", "tcp", "10.81.0.53", 5353
	p.DNSServerName, p.DNSPath = "", ""
	p.HomeLANAccess, p.IPv6Mode, p.KillSwitchPolicy = false, "off", "always"
	if err := common.NormalizeRouterProfile(p); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopOrderedHostnameCaptureUsesSavedResolverWithoutPhysicalBootstrap(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			a, nodes := desktopNodeChainCaptureFixture(t, 3)
			if mode != "wg" {
				installOrderedAWGAssets(t, a, nodes, []string{mode, "wg", "shadowsocks"}, "off")
			}
			installDesktopOrderedHostname(t, a, nodes)
			if mode == "wg" {
				// Existing imports preserve DNS-name case. Keep all three saved
				// endpoint copies identical instead of rewriting that source.
				a.profiles.Profiles[1].Endpoint = "Middle.Example.Test"
				a.profiles.Profiles[1].External.Shadowsocks.Server = "Middle.Example.Test"
			}
			original := cloneRouterProfileStore(a.profiles)
			control := a.profiles.Profiles[2]
			lookups := 0
			capture, err := captureDesktopNodeChain(context.Background(), clientRoot(a), control, a.profiles.Profiles, nodes, "local",
				func(context.Context, string) ([]netip.Addr, error) {
					lookups++
					return nil, errors.New("ordinary-network lookup forbidden in this captured graph")
				})
			if err != nil || lookups != 0 || !reflect.DeepEqual(original, a.profiles) {
				t.Fatal("hostname capture looked up or rewrote an original member", err, lookups)
			}
			var source mobilemultihop.NodeChainSource
			var imported struct {
				Config  string `json:"config"`
				Capture string `json:"capture"`
			}
			if json.Unmarshal([]byte(capture.input), &source) != nil || source.Schema != 2 || len(source.Nodes) != 3 ||
				len(source.IdentitySources) != 3 || source.IdentitySources[1] != "" ||
				json.Unmarshal([]byte(source.Nodes[1]), &imported) != nil {
				t.Fatal("hostname middle lost its exact independent source")
			}
			var envelope map[string]any
			var selected struct {
				Profile json.RawMessage `json:"profile"`
			}
			// Compare every serialized source field directly. Decoding the wire
			// into RouterProfile would apply ordinary import normalization; the
			// ordered source parser retains the original captured JSON map.
			expected, err := json.Marshal(original.Profiles[1])
			var wanted, actual map[string]any
			if json.Unmarshal([]byte(imported.Config), &envelope) != nil || envelope["dns"] != nil ||
				json.Unmarshal([]byte(imported.Capture), &selected) != nil || err != nil ||
				json.Unmarshal(expected, &wanted) != nil || json.Unmarshal(selected.Profile, &actual) != nil || !reflect.DeepEqual(actual, wanted) {
				t.Fatal("transport source invented application DNS or changed saved policy")
			}
			if _, err := mobilemultihop.NewExternalPolicy(imported.Config, imported.Capture); err == nil {
				t.Fatal("hostname middle acquired a standalone physical connection")
			}
			proofs := capture.chain.ProofInventory()
			if len(proofs) != 3 || proofs[0].Mode != mode || proofs[1].ProfileID != nodes[1].ID || proofs[1].NodeID != "" {
				t.Fatal("hostname capture substituted an original transport or node identity")
			}
			for _, target := range []string{"linux", "windows", "darwin"} {
				projected, err := capture.project(context.Background(), target, 0)
				if err != nil || !reflect.DeepEqual(projected.ProofInventory(), proofs) {
					t.Fatal("desktop projection changed the captured hostname path", target, err)
				}
				var graph map[string]any
				if json.Unmarshal([]byte(projected.Config()), &graph) != nil {
					t.Fatal("missing projected native graph", target)
				}
				var middle map[string]any
				for _, raw := range graph["outbounds"].([]any) {
					out := raw.(map[string]any)
					if out["tag"] == proofs[1].Tag {
						middle = out
					}
				}
				if middle == nil || middle["server"] != original.Profiles[1].Endpoint || middle["detour"] != proofs[0].Tag ||
					middle["password"] != original.Profiles[1].External.Shadowsocks.Password {
					t.Fatal("native graph replaced hostname, credential or preceding prefix", target)
				}
				query, ok := middle["domain_resolver"].(map[string]any)
				if !ok || query["strategy"] != "ipv4_only" {
					t.Fatal("native hostname lookup lost captured IPv6 policy", target)
				}
				transportDNS, finalDNS := 0, 0
				for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
					dns := raw.(map[string]any)
					if dns["tag"] == query["server"] {
						transportDNS++
						if dns["type"] != "tcp" || dns["server"] != "10.81.0.53" || dns["server_port"] != float64(5353) || dns["detour"] != proofs[0].Tag {
							t.Fatal("middle DNS escaped its saved resolver or preceding prefix", target)
						}
					}
					if dns["tag"] == projected.DNSCapture().ResolverTag {
						finalDNS++
						if dns["server"] != control.AdGuardIPv4 || dns["detour"] != projected.FinalTag() || dns["type"] != "udp" {
							t.Fatal("middle DNS replaced the final Home AdGuard policy", target)
						}
					}
				}
				if transportDNS != 1 || finalDNS != 1 {
					t.Fatal("native graph lost separate transport and application DNS", target)
				}
				physical, err := projected.PhysicalEgress()
				if err != nil || len(physical) != 1 || physical[0].Host != original.Profiles[0].Endpoint {
					t.Fatal("hostname or DNS acquired a physical bypass", target, err)
				}
			}
		})
	}
}

func TestDesktopOrderedHostnameAdmissionRequiresOriginalExplicitPolicy(t *testing.T) {
	for _, fault := range []string{"home", "rescue", "fastest", "udp", "dot", "resolver-hostname", "resolver-loopback", "missing-port", "bad-port", "resolver-tls", "resolver-path", "wrong-endpoint", "host-case-mismatch", "paired-api", "layer", "first", "final"} {
		t.Run(fault, func(t *testing.T) {
			a, nodes := desktopNodeChainCaptureFixture(t, 3)
			installDesktopOrderedHostname(t, a, nodes)
			p := &a.profiles.Profiles[1]
			switch fault {
			case "home", "rescue", "fastest", "dot":
				p.DNSMode = fault
			case "udp":
				p.DNSProtocol = "udp"
			case "resolver-hostname":
				p.DNSHost = "resolver.example.test"
			case "resolver-loopback":
				p.DNSHost = "127.0.0.1"
			case "missing-port":
				p.DNSPort = 0
			case "bad-port":
				p.DNSPort = 65536
			case "resolver-tls":
				p.DNSServerName = "resolver.example.test"
			case "resolver-path":
				p.DNSPath = "/dns-query"
			case "wrong-endpoint":
				p.Endpoint = "other.example.test"
			case "host-case-mismatch":
				p.Endpoint = "Middle.example.test"
			case "paired-api":
				p.APIToken = "borrowed-private-token"
			case "layer":
				p.StartLayer = "aes-256-gcm"
			case "first":
				nodes[0], nodes[1] = nodes[1], nodes[0]
			case "final":
				nodes[1], nodes[2] = nodes[2], nodes[1]
			}
			if _, err := resolveDesktopNodeChainMembers(a.profiles.Profiles[2], a.profiles.Profiles, nodes, "local"); err == nil {
				t.Fatal("unsupported hostname path was admitted")
			}
			if fault != "first" && fault != "final" && desktopNodeChainImported(*p, "shadowsocks") {
				t.Fatal("invalid hostname policy advertised ordered membership")
			}
		})
	}
}

func TestDesktopOrderedHostnamePublicCaptureRejectsChangedResolver(t *testing.T) {
	a, nodes := desktopNodeChainCaptureFixture(t, 3)
	installDesktopOrderedHostname(t, a, nodes)
	view := publicProfileFor(a.profiles.Profiles[1])
	if view.External == nil || !view.External.OrderedMiddle {
		t.Fatal("valid saved hostname middle unavailable to native editor")
	}
	raw, _ := json.Marshal(view)
	if strings.Contains(string(raw), a.profiles.Profiles[1].External.Shadowsocks.Password) {
		t.Fatal("hostname capability exposed its private credential")
	}
	request := orderedPublicRequest(t, a, nodes)
	a.mu.Lock()
	selection, err := a.resolveNativeMultihopRequestLocked(request)
	a.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
	if err != nil || selection.Native.validate(selection) != nil || !nativeMultihopLiveProfilesCurrentContext(context.Background(), a, selection) {
		t.Fatal("native hostname editor did not retain original private source", err)
	}
	a.profiles.Profiles[1].DNSPort = 5354
	if nativeMultihopLiveProfilesCurrentContext(context.Background(), a, selection) {
		t.Fatal("captured hostname path adopted a replaced transport resolver")
	}
	a.mu.Lock()
	_, err = a.resolveNativeMultihopRequestLocked(request)
	a.mu.Unlock()
	if err == nil {
		t.Fatal("stale public editor admitted a changed hostname resolver")
	}
}

func TestDesktopOrderedHostnameSavedProfileRestoresExactPolicy(t *testing.T) {
	a, nodes := desktopNodeChainCaptureFixture(t, 3)
	installDesktopOrderedHostname(t, a, nodes)
	original := common.CloneRouterProfile(a.profiles.Profiles[1])
	id := saveOrderedConnectionFixture(t, a, nodes)
	a.profiles.Profiles[1].DNSPort = 5354
	a.profiles.Profiles[1].HomeLANAccess = true
	a.profiles.Profiles[1].ManualMTU = 1400
	response := postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
	if response.Code != http.StatusOK {
		t.Fatal(response.Code, response.Body.String())
	}
	restored := a.profiles.Profiles[1]
	if restored.Endpoint != original.Endpoint || restored.DNSHost != original.DNSHost || restored.DNSProtocol != "tcp" ||
		restored.DNSPort != original.DNSPort || restored.HomeLANAccess || restored.ManualMTU != original.ManualMTU ||
		!reflect.DeepEqual(restored.External, original.External) {
		t.Fatal("saved hostname source lost original credentials or resolver/protection policy")
	}
	a.profiles.Profiles[1].External.Shadowsocks.Password = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("z", 32)))
	response = postSetup(t, a, "/api/connection-profile/setup/load", map[string]any{"id": id})
	if response.Code == http.StatusOK {
		t.Fatal("saved hostname profile adopted a replacement credential")
	}
}
