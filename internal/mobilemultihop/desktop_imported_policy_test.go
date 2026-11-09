package mobilemultihop

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func desktopImportedOriginal(t *testing.T, source []string, kill string) *Controller {
	t.Helper()
	source = append([]string(nil), source...)
	final := externalTestRead(t, source[4])
	final["kill_switch_policy"] = kill
	source[4] = externalTestJSON(t, final)
	return importedPacketXrayCompile(t, source)
}

func desktopImportedPlan(t *testing.T, original *Controller, session string, mtu int) *DesktopImportedPolicy {
	t.Helper()
	policy, err := NewDesktopImportedPolicyWithMTU(original, session, "windows", mtu)
	if err != nil {
		t.Fatal("complete captured imported graph lost its protected native policy", err)
	}
	return policy
}

// Reconstruct every original graph object by removing only the documented
// native lower owners, exact proof lanes and captured TUN adaptation. The full
// equality catches changes to credentials, Start Layers, DNS or routing that a
// projection of a few interesting fields would miss.
func assertDesktopImportedExactDerivation(t *testing.T, policy *DesktopImportedPolicy) {
	t.Helper()
	config, meta, capture, err := policy.ReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	before := externalTestRead(t, policy.OriginalController().Config())
	after := externalTestRead(t, config)
	for i, root := range capture.PhysicalRoots {
		old := desktopNodeObject(t, before, root.Family, root.Tag)
		actual := desktopNodeObject(t, after, root.Family, root.Tag)
		if actual["detour"] != DesktopNodePhysicalTag || meta.Roots[i].OriginalSHA256 != desktopExternalObjectDigest(old) ||
			meta.Roots[i].DerivedSHA256 != desktopExternalObjectDigest(actual) {
			t.Fatal("imported native root lost exact original/derived bytes")
		}
		delete(actual, "detour")
		if root.DynamicSOCKSUDP {
			if actual["type"] != DesktopImportedSOCKSType || actual["session_id"] != meta.SessionID || actual["source_sha256"] != meta.SourceSHA256 {
				t.Fatal("dynamic imported SOCKS root lost its distinct retained association owner")
			}
			actual["type"] = "socks"
			delete(actual, "session_id")
			delete(actual, "source_sha256")
		}
		if !reflect.DeepEqual(old, actual) {
			t.Fatal("imported adaptation changed original root credentials or transport")
		}
	}
	oldTUN := desktopNodeObject(t, before, "inbounds", capture.TUNTag)
	tun := desktopNodeObject(t, after, "inbounds", capture.TUNTag)
	if tun["interface_name"] != "router-vpn" || meta.OriginalTUNSHA256 != desktopExternalObjectDigest(oldTUN) || meta.DerivedTUNSHA256 != desktopExternalObjectDigest(tun) {
		t.Fatal("imported TUN identity is not bound to original and actual options")
	}
	if old, exists := oldTUN["interface_name"]; exists {
		tun["interface_name"] = old
	} else {
		delete(tun, "interface_name")
	}
	if meta.RestoredMTU != 0 {
		if tun["mtu"] != float64(meta.RestoredMTU) {
			t.Fatal("imported restoration lost its captured TUN value")
		}
		tun["mtu"] = oldTUN["mtu"]
	}
	ins := after["inbounds"].([]any)
	if len(ins) != 3 {
		t.Fatal("imported path must own one TUN and two distinct loopback proof lanes")
	}
	for i, lane := range []struct {
		tag      string
		port     int
		outbound string
	}{
		{DesktopImportedEntryProofTag, DesktopImportedEntryProofPort, "entry-wg"},
		{DesktopImportedExitProofTag, DesktopImportedExitProofPort, "proxy"},
	} {
		listener := ins[i+1].(map[string]any)
		rule := after["route"].(map[string]any)["rules"].([]any)[i].(map[string]any)
		if len(listener) != 4 || listener["type"] != "mixed" || listener["tag"] != lane.tag || listener["listen"] != "127.0.0.1" || listener["listen_port"] != float64(lane.port) ||
			len(rule) != 2 || !reflect.DeepEqual(rule["inbound"], []any{lane.tag}) || rule["outbound"] != lane.outbound {
			t.Fatal("entry and final proofs were merged, widened or routed through the wrong hop")
		}
	}
	after["inbounds"] = []any{tun, before["inbounds"].([]any)[1]}
	route := after["route"].(map[string]any)
	route["rules"] = route["rules"].([]any)[2:]
	for _, pair := range []struct{ family, tag, kind string }{
		{"outbounds", DesktopNodePhysicalTag, DesktopNodePhysicalType}, {"services", DesktopNodeNetworkTag, DesktopNodeNetworkType},
	} {
		rows := after[pair.family].([]any)
		owner := rows[len(rows)-1].(map[string]any)
		if len(owner) != 4 || owner["tag"] != pair.tag || owner["type"] != pair.kind || owner["session_id"] != meta.SessionID || owner["source_sha256"] != meta.SourceSHA256 {
			t.Fatal("imported graph acquired another native owner")
		}
		if _, exists := before[pair.family]; exists {
			after[pair.family] = rows[:len(rows)-1]
		} else {
			delete(after, pair.family)
		}
	}
	for _, bootstrap := range capture.BootstrapDNS {
		if !bootstrap.Physical {
			continue
		}
		for _, raw := range after["dns"].(map[string]any)["servers"].([]any) {
			server := raw.(map[string]any)
			if server["tag"] == bootstrap.Tag {
				if server["detour"] != DesktopNodePhysicalTag {
					t.Fatal("physical bootstrap bypassed the captured socket owner")
				}
				delete(server, "detour")
				if desktopExternalObjectDigest(server) != bootstrap.ConfigSHA256 {
					t.Fatal("native bootstrap changed selected protocol, port or options")
				}
			}
		}
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatal("imported adaptation changed the original graph beyond its exact native boundary")
	}
}

func TestDesktopImportedPolicyPreservesProtocolsIndependentLayersAndBothProofLanes(t *testing.T) {
	for _, kind := range []string{"socks5", "shadowsocks", "hysteria2", "http-connect", "https-connect", "wireguard", "amneziawg", "openvpn-tcp", "openvpn-udp"} {
		for _, first := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			for _, last := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				t.Run(kind+"/"+first+"/"+last, func(t *testing.T) {
					original := desktopImportedOriginal(t, importedLaunchSource(t, kind, first, last), "always")
					before, oldMeta := original.Config(), original.Metadata()
					policy := desktopImportedPlan(t, original, desktopNodeTestSession, 0)
					_, meta, capture, err := policy.ReadValidated()
					if err != nil || meta.EntryID == meta.ExitID || meta.ProfileID != meta.ExitID || meta.ExitNodeID == "" || meta.EntryMode != capture.EntryMode ||
						meta.ExitMode != "reality-vision" || meta.EntryStartLayer != capture.EntryStartLayer || meta.ExitStartLayer != capture.ExitStartLayer ||
						meta.OriginalSourceSHA256 != original.SourceSHA256() || meta.OriginalConfigSHA256 != externalDigest([]byte(before)) ||
						meta.OriginalMetadataSHA256 != externalDigest([]byte(oldMeta)) || meta.KillSwitchPolicy != "always" ||
						capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != "proxy" ||
						meta.SourceSHA256 == meta.OriginalSourceSHA256 || meta.ConfigSHA256 == meta.OriginalConfigSHA256 {
						t.Fatal("imported native policy lost independent identities, final policy or original source")
					}
					if meta.SOCKSUDPAssociationRequired {
						t.Fatal("TCP-carried REALITY final invented a physical SOCKS UDP relay")
					}
					assertDesktopImportedExactDerivation(t, policy)
					if original.Config() != before || original.Metadata() != oldMeta {
						t.Fatal("native adaptation edited its original imported owner")
					}
					_, shared, physical, err := ReadDesktopPhysicalPolicy(policy)
					if err != nil || shared.Kind != "imported" || shared.ProfileID != meta.ExitID || shared.NodeID != meta.ExitNodeID || shared.Mode != meta.ExitMode ||
						physical.TUNTag != capture.TUNTag || !reflect.DeepEqual(physical.PhysicalRoots, capture.PhysicalRoots) {
						t.Fatal("native projection disguised the imported policy as a Router profile")
					}
				})
			}
		}
	}
}

func TestDesktopImportedPolicyKeepsFinalModesDNSDevicePolicyAndRestoredMTU(t *testing.T) {
	for _, mode := range []string{"shadowsocks", "hysteria2", "wg", "awg2-fast", "awg2-strong"} {
		t.Run("socks5/"+mode, func(t *testing.T) {
			original := desktopImportedOriginal(t, importedSOCKSFixture(t, mode), "always")
			policy := desktopImportedPlan(t, original, desktopNodeTestSession, 0)
			_, meta, capture, err := policy.ReadValidated()
			if err != nil || !meta.SOCKSUDPAssociationRequired || len(capture.PhysicalRoots) != 1 ||
				!capture.PhysicalRoots[0].DynamicSOCKSUDP || len(capture.PhysicalRoots[0].Destinations) != 1 ||
				capture.PhysicalRoots[0].Destinations[0].Network != "tcp" {
				t.Fatal("imported datagram path dropped its negotiated SOCKS relay or invented a UDP tuple")
			}
			assertDesktopImportedExactDerivation(t, policy)
		})
		t.Run(mode, func(t *testing.T) {
			original := desktopImportedOriginal(t, importedOpenVPNFixture(t, "udp", mode, "aes-256-gcm", "aes-256-gcm+xor-whitening"), "on-connect")
			policy := desktopImportedPlan(t, original, desktopNodeTestSession, 1392)
			if policy.Metadata().ExitMode != mode || policy.Metadata().RestoredMTU != 1392 {
				t.Fatal("imported final mode or captured TUN restoration changed")
			}
			assertDesktopImportedExactDerivation(t, policy)
		})
	}
	source := importedLaunchSource(t, "shadowsocks", "aes-256-gcm", "aes-256-gcm+xor-whitening")
	entry, final := externalTestRead(t, source[1]), externalTestRead(t, source[4])
	ep := entry["profile"].(map[string]any)
	ep["ipv6_mode"], ep["home_lan_access"], ep["home_lan_cidrs"], ep["kill_switch_policy"] = "off", false, []string{"10.20.0.0/16"}, "off"
	final["dns_mode"], final["dns_protocol"], final["dns_host"], final["dns_port"] = "custom", "tls", "198.51.100.44", 8853
	final["dns_server_name"] = "selected.example"
	source[1], source[4] = externalTestJSON(t, entry), externalTestJSON(t, final)
	original := desktopImportedOriginal(t, source, "always")
	policy := desktopImportedPlan(t, original, desktopNodeTestSession, 0)
	_, meta, capture, err := policy.ReadValidated()
	if err != nil || meta.KillSwitchPolicy != "always" || meta.IPv6Mode != "off" || meta.HomeLANAccess || capture.SelectedDNS.Type != "tls" ||
		capture.SelectedDNS.Host != "198.51.100.44" || capture.SelectedDNS.Port != 8853 || capture.SelectedDNS.ServerName != "selected.example" || capture.SelectedDNS.Detour != "proxy" {
		t.Fatal("imported entry overrode final DNS/protection or lost combined IPv6/LAN policy")
	}
	assertDesktopImportedExactDerivation(t, policy)
}

func TestDesktopImportedPolicyRejectsChangedSourceGraphPolicyAndGeneration(t *testing.T) {
	for name, mutate := range map[string]func(*DesktopImportedPolicy){
		"entry-mode":      func(p *DesktopImportedPolicy) { p.metadata.EntryMode = "socks5" },
		"final-identity":  func(p *DesktopImportedPolicy) { p.metadata.ExitID = "another-final" },
		"final-proof":     func(p *DesktopImportedPolicy) { p.metadata.ExitNodeID = strings.Repeat("f", 64) },
		"source":          func(p *DesktopImportedPolicy) { p.metadata.SourceSHA256 = strings.Repeat("f", 64) },
		"session":         func(p *DesktopImportedPolicy) { p.metadata.SessionID = strings.Repeat("f", 32) },
		"native-root":     func(p *DesktopImportedPolicy) { p.metadata.Roots[0].Tag = "proxy" },
		"mtu-input":       func(p *DesktopImportedPolicy) { p.inputs.restoredMTU = 1450 },
		"selected-policy": func(p *DesktopImportedPolicy) { p.original.imported.profile += " " },
		"original-graph":  func(p *DesktopImportedPolicy) { p.original.config += " " },
		"original-entry":  func(p *DesktopImportedPolicy) { p.original.imported.inputs.EntryCapture += " " },
		"original-final":  func(p *DesktopImportedPolicy) { p.original.imported.inputs.ExitFiles += " " },
		"network-change":  func(p *DesktopImportedPolicy) { p.original.NetworkChanged() },
		"closed":          func(p *DesktopImportedPolicy) { _ = p.original.Close() },
		"proof-lane": func(p *DesktopImportedPolicy) {
			graph := externalTestRead(t, p.config)
			graph["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)["outbound"] = "proxy"
			p.config = externalTestJSON(t, graph)
		},
		"dns-substitution": func(p *DesktopImportedPolicy) {
			graph := externalTestRead(t, p.config)
			graph["dns"].(map[string]any)["servers"].([]any)[0].(map[string]any)["server"] = "1.1.1.1"
			p.config = externalTestJSON(t, graph)
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := desktopImportedPlan(t, desktopImportedOriginal(t, importedLaunchSource(t, "openvpn-udp", "", ""), "always"), desktopNodeTestSession, 0)
			mutate(p)
			// A matching caller-computed output seal cannot replace derivation
			// from the original constructor inputs and session/MTU capture.
			p.metadata.ConfigSHA256 = externalDigest([]byte(p.config))
			p.seal = p.currentSeal()
			if p.Validate() == nil || p.Config() != "" || p.OriginalController() != nil {
				t.Fatal("edited output or retired original was admitted after rehashing")
			}
			if config, _, _, err := ReadDesktopPhysicalPolicy(p); err == nil || config != "" {
				t.Fatal("changed imported policy escaped through shared physical projection")
			}
		})
	}
	for _, target := range []string{"linux", "darwin", "WINDOWS", ""} {
		original := desktopImportedOriginal(t, importedLaunchSource(t, "wireguard", "", ""), "always")
		if _, err := NewDesktopImportedPolicy(original, desktopNodeTestSession, target); err == nil {
			t.Fatal("unadmitted target acquired Windows native authority", target)
		}
	}
	for _, mtu := range []int{-1, 1279, 9001} {
		original := desktopImportedOriginal(t, importedLaunchSource(t, "wireguard", "", ""), "always")
		if _, err := NewDesktopImportedPolicyWithMTU(original, desktopNodeTestSession, "windows", mtu); err == nil {
			t.Fatal("invalid captured MTU admitted", mtu)
		}
	}
}

type desktopPhysicalWrapper struct{ DesktopPhysicalPolicy }

func (desktopPhysicalWrapper) Validate() error { return nil }

func TestDesktopImportedPolicyReadinessAndRestorationKeepDistinctOwners(t *testing.T) {
	original := desktopImportedOriginal(t, importedSOCKSFixture(t, "shadowsocks"), "always")
	first := desktopImportedPlan(t, original, desktopNodeTestSession, 1392)
	_, meta, capture, err := first.ReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	transfer := strings.Repeat("a", 64)
	record := DesktopNodeReadyRecord{Schema: 1, Kind: "routervpn-node-ready-v1", SessionID: meta.SessionID,
		SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, TransferSHA256: transfer,
		DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, InterfaceName: "router-vpn", InterfaceIndex: 771,
		MTU: 1392, ProvedAt: 1793366400123, DNSMilliseconds: 1.25}
	raw, err := CanonicalDesktopNodeReadyRecord(record, first, transfer)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ParseDesktopNodeReadyRecord(raw, first, transfer); err != nil || got != record {
		t.Fatal("native imported DNS/TUN record lost exact ownership", err)
	}
	input, err := original.ImportedLaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	rebuilt, err := ParseImportedLaunchInput(input)
	if err != nil {
		t.Fatal(err)
	}
	defer rebuilt.Close()
	restored := desktopImportedPlan(t, rebuilt, strings.Repeat("b", 32), 1392)
	rm := restored.Metadata()
	if rm.OriginalSourceSHA256 != meta.OriginalSourceSHA256 || rm.OriginalCaptureSHA256 != meta.OriginalCaptureSHA256 ||
		rm.SourceSHA256 == meta.SourceSHA256 || rm.ConfigSHA256 == meta.ConfigSHA256 || restored.OriginalController() == original {
		t.Fatal("restoration did not retain original inputs with a fresh native session")
	}
	if _, err := ParseDesktopNodeReadyRecord(raw, restored, transfer); err == nil {
		t.Fatal("old readiness became proof for restored native owner")
	}
	if _, _, _, err := ReadDesktopPhysicalPolicy(desktopPhysicalWrapper{first}); err == nil {
		t.Fatal("interface embedding substituted caller-defined native authority")
	}
	for _, value := range []DesktopPhysicalPolicy{nil, (*DesktopNodePolicy)(nil), (*DesktopImportedPolicy)(nil), &DesktopImportedPolicy{}} {
		if _, _, _, err := ReadDesktopPhysicalPolicy(value); err == nil {
			t.Fatal("empty policy acquired a native projection")
		}
	}
	meta.Roots[0].Tag = "changed-copy"
	capture.PhysicalRoots[0].Destinations[0].Port++
	_, fresh, current, err := first.ReadValidated()
	if err != nil || fresh.Roots[0].Tag == meta.Roots[0].Tag || current.PhysicalRoots[0].Destinations[0].Port == capture.PhysicalRoots[0].Destinations[0].Port {
		t.Fatal("returned metadata or captured slices mutated retained authority")
	}
	if _, err := original.ImportedPhysicalEgress(); !errors.Is(err, ErrDynamicPhysicalEgress) {
		t.Fatal("fixed tuple projection invented a dynamic SOCKS UDP destination", err)
	}
}
