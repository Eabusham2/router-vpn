package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/common"
	"router-vpn/internal/mobilemultihop"
	"router-vpn/internal/nativecomposite"
)

func desktopCONNECTCaptureFixture(t *testing.T, mode, authentication, layer string) (*app, []common.MultihopNodeSelection) {
	t.Helper()
	a, nodes := desktopNodeChainCaptureFixture(t, 3)
	installOrderedAWGAssets(t, a, nodes, []string{mode, "wg", "shadowsocks"}, layer)
	q := createRequestFor("https-connect")
	if authentication == "none" {
		q.Username, q.Password = "", ""
	}
	middle, err := externalProfileFromCreateRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	middle.ID, middle.Name, middle.StartLayer = nodes[1].ID, "Original literal CONNECT middle", "off"
	middle.MTUPolicy, middle.ManualMTU = "manual", 1380
	middle.DNSMode, middle.DNSProtocol, middle.DNSHost, middle.DNSPort = "custom", "tcp", "9.9.9.9", 5353
	middle.KillSwitchPolicy, middle.IPv6Mode, middle.HomeLANAccess = "always", "off", false
	if err := common.NormalizeRouterProfile(&middle); err != nil {
		t.Fatal(err)
	}
	a.profiles.Profiles[1] = middle
	nodes[1].Mode = "https-connect"
	a.profiles.Profiles[2].MultihopNodes = append([]common.MultihopNodeSelection(nil), nodes...)
	// Declare the original paired service capability without adding inline UoT
	// to the six-field source. The typed compiler owns that later derivation.
	final := a.profiles.Profiles[2]
	directory := filepath.Join(clientRoot(a), "generated", final.ID, "shadowsocks")
	raw, err := os.ReadFile(filepath.Join(directory, "sing-box.json"))
	if err != nil {
		t.Fatal(err)
	}
	var graph map[string]any
	if json.Unmarshal(raw, &graph) != nil {
		t.Fatal("original paired SS fixture is not JSON")
	}
	out := graph["outbounds"].([]any)[0].(map[string]any)
	configHash, keyHash := sha256.Sum256(raw), sha256.Sum256([]byte(out["password"].(string)))
	declaration, err := json.Marshal(map[string]any{"schema": 1, "node_id": final.NodeProofID,
		"configured_image": nativecomposite.SSServiceImage, "uot_version": 2,
		"endpoint": out["server"], "port": out["server_port"], "method": out["method"],
		"source_sha256": hex.EncodeToString(configHash[:]), "key_sha256": hex.EncodeToString(keyHash[:])})
	if err != nil || nativecomposite.ValidateSSServiceCompanion(raw, declaration, final.NodeProofID) != nil {
		t.Fatal("original CONNECT fixture lost paired UoT-v2 service authority", err)
	}
	if err := os.WriteFile(filepath.Join(directory, nativecomposite.SSServiceAsset), declaration, 0600); err != nil {
		t.Fatal(err)
	}
	// This original imported source owns no paired asset directory.
	if err := os.RemoveAll(filepath.Join(clientRoot(a), "generated", middle.ID)); err != nil {
		t.Fatal(err)
	}
	return a, nodes
}

func captureDesktopCONNECTTest(t *testing.T, a *app, nodes []common.MultihopNodeSelection) *desktopNodeChainCONNECTCapture {
	t.Helper()
	capture, err := captureDesktopNodeChainCONNECT(context.Background(), clientRoot(a), a.profiles.Profiles[2], a.profiles.Profiles, nodes, "local", nil)
	if err != nil {
		t.Fatal("original desktop CONNECT capture", err)
	}
	return capture
}

func TestDesktopNodeChainCONNECTCapturePlainHTTPKeepsTypedPath(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			a, nodes := desktopCONNECTCaptureFixture(t, mode, "password", "off")
			middle := &a.profiles.Profiles[1]
			proxy := *middle.External.HTTPSConnect
			proxy.TLSServerName = ""
			middle.External.Protocol, middle.External.HTTPSConnect, middle.External.HTTPConnect = "http-connect", nil, &proxy
			nodes[1].Mode = "http-connect"
			a.profiles.Profiles[2].MultihopNodes = append([]common.MultihopNodeSelection(nil), nodes...)
			capture := captureDesktopCONNECTTest(t, a, nodes)
			config, metadata, err := capture.source.ReadValidated()
			if err != nil || metadata.Proofs[1].Mode != "http-connect" || metadata.TransportCapability != "uot-v2" {
				t.Fatal("plain CONNECT capture changed its final transport", err)
			}
			var graph map[string]any
			if json.Unmarshal([]byte(config), &graph) != nil {
				t.Fatal("missing captured graph")
			}
			var found bool
			for _, raw := range graph["outbounds"].([]any) {
				out := raw.(map[string]any)
				if out["tag"] == metadata.Proofs[1].Tag {
					found = true
					if out["type"] != "http" || out["tls"] != nil || out["udp_over_tcp"] != nil || out["username"] != proxy.Username || out["password"] != proxy.Password {
						t.Fatal("plain CONNECT became HTTPS or lost its original credentials")
					}
				}
			}
			if !found {
				t.Fatal("missing original CONNECT middle")
			}
			selection, err := resolveDesktopNodeChainSelection(a.profiles.Profiles[2], a.profiles.Profiles, nodes, "local")
			if err != nil {
				t.Fatal(err)
			}
			selection, err = captureNativeNodeChainSelection(context.Background(), clientRoot(a), selection, []string{"shadowsocks"}, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range []string{"windows", "linux", "darwin"} {
				launch, err := newDesktopNodeChainLaunch(selection, strings.Repeat("a", 32), target)
				if err != nil || launch.chain.connectPolicy == nil || !launch.chain.originalPolicyCurrent() {
					t.Fatal("plain CONNECT lost typed desktop adoption", target, err)
				}
			}
		})
	}
}

func TestDesktopNodeChainCONNECTCaptureOriginalSources(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, authentication := range []string{"password", "none"} {
			t.Run(mode+"/"+authentication, func(t *testing.T) {
				a, nodes := desktopCONNECTCaptureFixture(t, mode, authentication, "off")
				before := cloneRouterProfileStore(a.profiles)
				beforeView := publicProfileFor(before.Profiles[1])
				lookups := 0
				capture, err := captureDesktopNodeChainCONNECT(context.Background(), clientRoot(a), a.profiles.Profiles[2], a.profiles.Profiles, nodes, "local",
					func(context.Context, string) ([]netip.Addr, error) {
						lookups++
						return nil, errors.New("ambient DNS is forbidden for the original literal graph")
					})
				if err != nil || lookups != 0 || !reflect.DeepEqual(before, a.profiles) {
					t.Fatal("typed capture looked up or changed an original saved source", err, lookups)
				}
				if err := capture.currentContext(context.Background(), a); err != nil {
					t.Fatal(err)
				}
				var source mobilemultihop.NodeChainSource
				if json.Unmarshal([]byte(capture.original.input), &source) != nil || source.Schema != 4 ||
					source.Execution != "local" || len(source.Nodes) != 3 || len(source.IdentitySources) != 3 ||
					source.IdentitySources[0] == "" || source.IdentitySources[1] != "" || source.IdentitySources[2] == "" {
					t.Fatal("typed source lost original paired identity or lent it to CONNECT")
				}
				var middle struct {
					Config  string `json:"config"`
					Capture string `json:"capture"`
				}
				var captured struct {
					Profile json.RawMessage `json:"profile"`
				}
				if json.Unmarshal([]byte(source.Nodes[1]), &middle) != nil ||
					json.Unmarshal([]byte(middle.Capture), &captured) != nil {
					t.Fatal("original private CONNECT member missing")
				}
				expected, err := json.Marshal(before.Profiles[1])
				var wanted, actual map[string]any
				if err != nil || json.Unmarshal(expected, &wanted) != nil ||
					json.Unmarshal(captured.Profile, &actual) != nil || !reflect.DeepEqual(wanted, actual) {
					t.Fatal("typed source changed saved CONNECT credential or device policy")
				}
				config, meta, err := capture.source.ReadValidated()
				if err != nil || config != capture.config || meta.NativeAdmission != "closed" ||
					len(meta.Proofs) != 3 || meta.Proofs[0].Mode != mode || meta.Proofs[1].Mode != "https-connect" ||
					meta.Proofs[1].NodeID != "" || meta.Proofs[1].Kind != "public-path" ||
					meta.Proofs[2].Mode != "shadowsocks" {
					t.Fatal("typed source invented runtime authority or lost original proof kind", err)
				}
				var graph map[string]any
				if json.Unmarshal([]byte(config), &graph) != nil {
					t.Fatal("missing native source graph")
				}
				var connect, final map[string]any
				for _, raw := range graph["outbounds"].([]any) {
					out := raw.(map[string]any)
					if out["tag"] == meta.Proofs[1].Tag {
						connect = out
					}
					if out["tag"] == meta.Proofs[2].Tag {
						final = out
					}
				}
				original := before.Profiles[1].External.HTTPSConnect
				if connect == nil || connect["type"] != "http" ||
					connect["server"] != original.Host || connect["server_port"] != float64(original.Port) ||
					connect["detour"] != meta.Proofs[0].Tag || final == nil || final["detour"] != meta.Proofs[1].Tag {
					t.Fatal("typed graph changed the original CONNECT transport or ordered detours")
				}
				tls, tlsOK := connect["tls"].(map[string]any)
				uot, uotOK := final["udp_over_tcp"].(map[string]any)
				if !tlsOK || tls["enabled"] != true || tls["server_name"] != original.TLSServerName || !uotOK || uot["enabled"] != true || uot["version"] != float64(2) || meta.TransportCapability != "uot-v2" {
					t.Fatal("HTTPS capture lost original verified TLS or final UoT-v2 authority")
				}
				if authentication == "password" {
					if connect["username"] != original.Username || connect["password"] != original.Password {
						t.Fatal("typed graph substituted original CONNECT credentials")
					}
				} else if connect["username"] != nil || connect["password"] != nil {
					t.Fatal("typed graph invented CONNECT authentication")
				}
				selected := 0
				for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
					dns := raw.(map[string]any)
					if dns["tag"] == meta.DNS.ResolverTag {
						selected++
						if dns["server"] != before.Profiles[2].AdGuardIPv4 || dns["detour"] != meta.Proofs[2].Tag {
							t.Fatal("CONNECT middle replaced the selected final Home DNS")
						}
					}
				}
				if selected != 1 || len(meta.Physical) != 1 || meta.Physical[0].Host != before.Profiles[0].Endpoint {
					t.Fatal("CONNECT middle gained physical relay or resolver authority")
				}
				for _, asset := range capture.original.assets {
					if asset.id == nodes[1].ID {
						t.Fatal("CONNECT middle borrowed a paired asset")
					}
				}
				if _, err := mobilemultihop.NewNodeChain(capture.original.input); err == nil {
					t.Fatal("typed source escaped through generic chain admission")
				}
				if _, err := captureDesktopNodeChain(context.Background(), clientRoot(a), a.profiles.Profiles[2], a.profiles.Profiles, nodes, "local", nil); err == nil {
					t.Fatal("typed source escaped through generic desktop capture")
				}
				if view := publicProfileFor(before.Profiles[1]); !reflect.DeepEqual(view, beforeView) {
					t.Fatal("source-only capture changed public native admission or the original profile capability")
				}
				for i := range a.profiles.Profiles {
					a.profiles.Profiles[i].EffectiveMTU = 1300 + i
				}
				if err := capture.currentContext(context.Background(), a); err != nil {
					t.Fatal("actual measurement readback replaced original source policy", err)
				}
			})
		}
	}
}

func TestDesktopNodeChainCONNECTCaptureKeepsIndependentPairedLayers(t *testing.T) {
	for _, layer := range []string{"aes-256-gcm", "aes-256-gcm+xor-whitening"} {
		t.Run(layer, func(t *testing.T) {
			a, nodes := desktopCONNECTCaptureFixture(t, "awg2-strong", "password", layer)
			capture := captureDesktopCONNECTTest(t, a, nodes)
			_, meta, err := capture.source.ReadValidated()
			if err != nil || meta.Proofs[0].StartLayer != layer || meta.Proofs[1].StartLayer != "off" || meta.Proofs[2].StartLayer != layer {
				t.Fatal("typed capture rewrote an independent original paired layer", err)
			}
		})
	}
}

func TestDesktopNodeChainCONNECTCaptureRejectsUnsupportedSource(t *testing.T) {
	for _, fault := range []string{
		"server", "auto", "first", "final", "extra", "prefix-mode", "final-mode",
		"hostname", "wrong-host", "zone", "mapped", "unspecified", "multicast",
		"paired-token", "paired-api", "paired-proof", "middle-layer", "wrong-mode",
		"partial-auth", "oversized-auth", "bad-port", "missing-source", "duplicate-catalog",
		"foreign-control", "changed-control", "final-hostname", "missing-final-service", "inline-final-carrier",
	} {
		t.Run(fault, func(t *testing.T) {
			a, nodes := desktopCONNECTCaptureFixture(t, "wg", "password", "off")
			execution := "local"
			control := common.CloneRouterProfile(a.profiles.Profiles[2])
			p := &a.profiles.Profiles[1]
			switch fault {
			case "missing-final-service":
				if err := os.Remove(filepath.Join(clientRoot(a), "generated", control.ID, "shadowsocks", nativecomposite.SSServiceAsset)); err != nil {
					t.Fatal(err)
				}
			case "inline-final-carrier":
				path := filepath.Join(clientRoot(a), "generated", control.ID, "shadowsocks", "sing-box.json")
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var graph map[string]any
				if json.Unmarshal(raw, &graph) != nil {
					t.Fatal("original final fixture missing")
				}
				graph["outbounds"].([]any)[0].(map[string]any)["udp_over_tcp"] = map[string]any{"enabled": true, "version": 2}
				changed, err := json.Marshal(graph)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, changed, 0600); err != nil {
					t.Fatal(err)
				}
			case "server", "auto":
				execution = fault
			case "first":
				nodes[0], nodes[1] = nodes[1], nodes[0]
			case "final":
				nodes[1], nodes[2] = nodes[2], nodes[1]
			case "extra":
				nodes = append(nodes, common.MultihopNodeSelection{ID: "extra", Mode: "shadowsocks"})
			case "prefix-mode":
				nodes[0].Mode = "hysteria2"
			case "final-mode":
				nodes[2].Mode = "hysteria2"
			case "hostname":
				p.Endpoint, p.External.HTTPSConnect.Host = "middle.example.test", "middle.example.test"
			case "wrong-host":
				p.Endpoint = "203.0.113.41"
			case "zone":
				p.Endpoint, p.External.HTTPSConnect.Host = "fe80::1%en0", "fe80::1%en0"
			case "mapped":
				p.Endpoint, p.External.HTTPSConnect.Host = "::ffff:203.0.113.40", "::ffff:203.0.113.40"
			case "unspecified":
				p.Endpoint, p.External.HTTPSConnect.Host = "0.0.0.0", "0.0.0.0"
			case "multicast":
				p.Endpoint, p.External.HTTPSConnect.Host = "224.0.0.1", "224.0.0.1"
			case "paired-token":
				p.APIToken = "borrowed-paired-token"
			case "paired-api":
				p.RouterAPI = "https://192.0.2.1"
			case "paired-proof":
				p.NodeProofID = a.profiles.Profiles[0].NodeProofID
			case "middle-layer":
				p.StartLayer = "aes-256-gcm"
			case "wrong-mode":
				nodes[1].Mode = "shadowsocks"
			case "partial-auth":
				p.External.HTTPSConnect.Password = ""
			case "oversized-auth":
				p.External.HTTPSConnect.Password = strings.Repeat("x", 4097)
			case "bad-port":
				p.External.HTTPSConnect.Port = 65536
			case "missing-source":
				p.External = nil
			case "duplicate-catalog":
				a.profiles.Profiles = append(a.profiles.Profiles, *p)
			case "foreign-control":
				control = a.profiles.Profiles[0]
			case "changed-control":
				control.APIToken += "-replaced"
			case "final-hostname":
				a.profiles.Profiles[2].Endpoint = "final.example.test"
				control = common.CloneRouterProfile(a.profiles.Profiles[2])
			}
			calls := 0
			if _, err := captureDesktopNodeChainCONNECT(context.Background(), clientRoot(a), control, a.profiles.Profiles, nodes, execution,
				func(context.Context, string) ([]netip.Addr, error) {
					calls++
					return nil, errors.New("forbidden lookup")
				}); err == nil || calls != 0 {
				t.Fatal("unsupported CONNECT graph reached source capture or physical lookup", err, calls)
			}
		})
	}
}

func TestDesktopNodeChainCONNECTCaptureRetiresChangedOriginal(t *testing.T) {
	for _, fault := range []string{"credential", "resolver", "mtu", "policy", "paired-token", "entry-asset", "final-asset", "order", "removed", "duplicate", "selection", "closing", "source", "config", "cancelled"} {
		t.Run(fault, func(t *testing.T) {
			a, nodes := desktopCONNECTCaptureFixture(t, "wg", "password", "off")
			capture := captureDesktopCONNECTTest(t, a, nodes)
			originalPassword := capture.original.members[1].Profile.External.HTTPSConnect.Password
			ctx := context.Background()
			switch fault {
			case "credential":
				a.profiles.Profiles[1].External.HTTPSConnect.Password += "-replaced"
			case "resolver":
				a.profiles.Profiles[1].DNSPort++
			case "mtu":
				a.profiles.Profiles[1].ManualMTU++
			case "policy":
				a.profiles.Profiles[1].HomeLANAccess = true
			case "paired-token":
				a.profiles.Profiles[2].APIToken += "-replaced"
			case "entry-asset", "final-asset":
				index, mode, name := 0, "wg", "wg.conf"
				if fault == "final-asset" {
					index, mode, name = 2, "shadowsocks", "sing-box.json"
				}
				path := filepath.Join(clientRoot(a), "generated", nodes[index].ID, mode, name)
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(raw, '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			case "order":
				a.profiles.Profiles[2].MultihopNodes[0], a.profiles.Profiles[2].MultihopNodes[1] = a.profiles.Profiles[2].MultihopNodes[1], a.profiles.Profiles[2].MultihopNodes[0]
			case "removed":
				a.profiles.Profiles = append(a.profiles.Profiles[:1], a.profiles.Profiles[2:]...)
			case "duplicate":
				a.profiles.Profiles = append(a.profiles.Profiles, a.profiles.Profiles[1])
			case "selection":
				a.profiles.SelectedID = nodes[0].ID
			case "closing":
				a.closing = true
			case "source":
				capture.original.input += "\n"
			case "config":
				capture.config += "\n"
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if err := capture.currentContext(ctx, a); err == nil {
				t.Fatal("changed original CONNECT source retained desktop authority")
			}
			if capture.original.members[1].Profile.External.HTTPSConnect.Password != originalPassword {
				t.Fatal("live catalog mutation replaced original credential capture")
			}
		})
	}
}

func TestDesktopNodeChainCONNECTCaptureCatalogWaitUsesOriginalDeadline(t *testing.T) {
	a, nodes := desktopCONNECTCaptureFixture(t, "wg", "password", "off")
	capture := captureDesktopCONNECTTest(t, a, nodes)
	a.mu.Lock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- capture.currentContext(ctx, a) }()
	select {
	case err := <-done:
		a.mu.Unlock()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("held catalog did not preserve original cancellation", err)
		}
	case <-time.After(time.Second):
		a.mu.Unlock()
		<-done
		t.Fatal("held catalog stranded original CONNECT capture caller")
	}
}
