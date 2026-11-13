package mobilemultihop

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func desktopCandidatePreparationFixture(t *testing.T, mode, target string, position, restore int, edit func(int, map[string]any)) *DesktopNodeCandidatePreparationPolicy {
	t.Helper()
	nodes := nodeChainModeFixtureNodes(t, []string{mode, mode, "shadowsocks"}, []string{"", "", ""})
	for i, node := range nodes {
		profile := predecessorCopy(node.profile)
		profile["kill_switch_policy"] = "on-connect"
		if edit != nil {
			edit(i, profile)
		}
		var err error
		nodes[i], err = NewNodeProfile(node.inputs.Mode, node.inputs.Files, startJSON(t, profile), node.inputs.Start, node.inputs.DNSBootstrap)
		if err != nil {
			t.Fatal(err)
		}
	}
	targetSource, _ := candidateSourceFixture(t, "external", "2022-blake3-aes-256-gcm")
	inventory := candidateInventoryFixture(t, "original-candidate-catalog", targetSource)
	base, err := NewNodeChainCandidatePreparation(startJSON(t, nodeChainFixtureSource(t, nodes)), position, inventory)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewDesktopNodeCandidatePreparationPolicy(base, desktopNodeTestSession, target, restore)
	if err != nil {
		t.Fatal("desktop prefix construction", err)
	}
	return policy
}

func TestDesktopNodeCandidatePreparationPolicyOnlyPrefixPhysicalGraph(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
			for _, position := range []int{0, 1} {
				t.Run(fmt.Sprintf("%s/%s/%d", target, mode, position), func(t *testing.T) {
					p := desktopCandidatePreparationFixture(t, mode, target, position, 0, nil)
					config, meta, capture, err := ReadDesktopPhysicalPolicy(p)
					if err != nil || config != p.Preparation().Config() || meta.Kind != "node-candidate-prefix" ||
						meta.ProfileID != p.original.proofs[position].ProfileID || meta.ConfigSHA256 != p.Preparation().ConfigSHA256() ||
						meta.SourceSHA256 != p.Preparation().SourceSHA256() || p.metadata.OriginalSourceSHA256 != p.original.OriginalSourceSHA256() ||
						len(p.Preparation().ProofInventory()) != position+1 || len(capture.PhysicalRoots) != 1 {
						t.Fatal("prefix lost original physical/source authority", err)
					}
					graph := startObject(t, config)
					if graph["route"].(map[string]any)["final"] != NodeChainExecutionGateTag ||
						externalTestFind(t, graph, NodeChainExecutionGateTag)["detour"] != SelectorTag ||
						!reflect.DeepEqual(externalTestFind(t, graph, SelectorTag)["outbounds"], []any{p.original.proofs[position].Tag}) {
						t.Fatal("prefix preparation opened application/DNS ingress or selected a suffix")
					}
					for _, proof := range p.original.original.proofs[position+1:] {
						if strings.Contains(config, proof.Tag) {
							t.Fatal("desktop preparation constructed old suffix", proof.Position)
						}
					}
					if capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != p.original.proofs[position].Tag {
						t.Fatal("prefix resolver became physical permission or old final DNS proof")
					}
					for i, root := range capture.PhysicalRoots {
						row := desktopNodeObject(t, graph, root.Family, root.Tag)
						if row["detour"] != DesktopNodePhysicalTag || desktopExternalObjectDigest(row) != p.metadata.Roots[i].DerivedSHA256 {
							t.Fatal("first physical root lost original owner")
						}
						delete(row, "detour")
						if desktopExternalObjectDigest(row) != root.ConfigSHA256 {
							t.Fatal("physical adaptation changed encrypted transport")
						}
					}
					for _, family := range []string{"services", "outbounds"} {
						rows := graph[family].([]any)
						owner := rows[len(rows)-1].(map[string]any)
						if owner["session_id"] != meta.SessionID || owner["source_sha256"] != meta.SourceSHA256 {
							t.Fatal("native owner source differs")
						}
						if family == "services" {
							delete(graph, family)
						} else {
							graph[family] = rows[:len(rows)-1]
						}
					}
					base := startObject(t, p.original.Config())
					tun := base["inbounds"].([]any)[0].(map[string]any)
					if target == "darwin" {
						delete(tun, "interface_name")
					} else {
						tun["interface_name"] = "router-vpn"
					}
					if !reflect.DeepEqual(base, graph) {
						t.Fatal("desktop prefix changed nested routes, credentials, TUN or DNS")
					}
					cover, digest, err := ReadDesktopPhysicalCoverPolicy(p)
					if err != nil || len(cover) != 0 || digest != "" {
						t.Fatal("prefix fabricated a cover owner", err)
					}
					mtu, err := p.Preparation().MTUPlan()
					if err != nil || len(mtu.Prefixes) != position+1 || mtu.Original != capture.ConfiguredMTU || mtu.Original > mtu.Ceiling {
						t.Fatal("prefix lost configured MTU envelope", err)
					}
				})
			}
		}
	}
}

func TestDesktopNodeCandidatePreparationPolicyTypedRoundTripAndSeparation(t *testing.T) {
	p := desktopCandidatePreparationFixture(t, "awg2-fast", "linux", 1, 1300, nil)
	round, err := ParseDesktopNodeCandidatePreparationPolicy(p.Source())
	if err != nil || round == p || round.Preparation() == p.Preparation() || round.original == p.original ||
		round.Config() != p.Config() || !reflect.DeepEqual(round.Metadata(), p.Metadata()) {
		t.Fatal("typed prefix child lost original complete source", err)
	}
	if _, err := ParseNodeChainCandidatePreparation(p.Source()); err == nil {
		t.Fatal("desktop prefix downgraded to generic source")
	}
	if _, err := ParseDesktopNodeCandidatePreparationPolicy(p.original.Source()); err == nil {
		t.Fatal("generic prefix upgraded to desktop native authority")
	}
	if _, err := ParseDesktopNodeChainLaunchInput(p.Source()); err == nil {
		t.Fatal("prefix upgraded to full ordered launch")
	}
	if _, err := NewDesktopNodeCandidatePreparationPolicy(p.Preparation(), desktopNodeTestSession, "linux", 1300); err == nil {
		t.Fatal("desktop prefix was projected twice")
	}
	for _, field := range []string{"kind", "source_sha256", "config_sha256", "capture_sha256", "session_id", "target_os", "preparation", "restored_mtu", "config"} {
		record := startObject(t, p.Source())
		if field == "restored_mtu" {
			record[field] = 1280
		} else {
			record[field] = "changed"
		}
		if _, err := ParseDesktopNodeCandidatePreparationPolicy(startJSON(t, record)); err == nil {
			t.Fatal("changed private source admitted", field)
		}
	}
	if _, err := ParseDesktopNodeCandidatePreparationPolicy(p.Source() + "\n"); err == nil {
		t.Fatal("noncanonical source admitted")
	}
	mtu, _ := round.Preparation().MTUPlan()
	_, _, capture, _ := round.PhysicalReadValidated()
	if mtu.Original != 1300 || capture.ConfiguredMTU != 1280 || round.Metadata().RestoredMTU != 1300 {
		t.Fatal("restored system MTU erased original configured bounds")
	}
}

func TestDesktopNodeCandidatePreparationPolicyPreservesSavedRestrictions(t *testing.T) {
	p := desktopCandidatePreparationFixture(t, "wg", "windows", 0, 0, func(i int, profile map[string]any) {
		if i == 2 {
			profile["kill_switch_policy"], profile["ipv6_mode"], profile["home_lan_access"] = "always", "off", false
			profile["dns_mode"], profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "custom", "tls", "198.51.100.44", 8853
			profile["dns_server_name"] = "unreachable-final.example"
		}
	})
	_, meta, capture, err := p.PhysicalReadValidated()
	if err != nil || meta.KillSwitchPolicy != "always" || meta.IPv6Mode != "off" || meta.HomeLANAccess ||
		capture.SelectedDNS.Host == "198.51.100.44" || strings.Contains(p.Config(), "unreachable-final.example") {
		t.Fatal("saved restrictions lost or unreachable final entered executable prefix", err)
	}
	if p.metadata.ApplicationOpen || p.metadata.DNSOpen {
		t.Fatal("source constructor claimed live readiness")
	}
}

func TestDesktopNodeCandidatePreparationPolicyRejectsWrongAdmissionAndMTU(t *testing.T) {
	p := desktopCandidatePreparationFixture(t, "wg", "linux", 0, 0, nil)
	for _, input := range []struct {
		session, target string
		mtu             int
	}{
		{"", "linux", 0}, {desktopNodeTestSession, "android", 0},
		{desktopNodeTestSession, "ios", 0}, {desktopNodeTestSession, "linux", 1279},
		{desktopNodeTestSession, "linux", 9001}, {desktopNodeTestSession, "linux", 9000},
	} {
		if _, err := NewDesktopNodeCandidatePreparationPolicy(p.original, input.session, input.target, input.mtu); err == nil {
			t.Fatal("unsupported platform, identity or prefix MTU ceiling admitted", input)
		}
	}
	fixed := desktopCandidatePreparationFixture(t, "wg", "linux", 0, 1280, func(i int, profile map[string]any) {
		if i == 2 {
			profile["mtu_policy"], profile["manual_mtu"] = "manual", float64(1280)
		}
	})
	if _, err := NewDesktopNodeCandidatePreparationPolicy(fixed.original, desktopNodeTestSession, "linux", 1300); err == nil {
		t.Fatal("prefix restore overrode saved final Fixed TUN policy")
	}
	if _, err := NewDesktopNodeCandidatePreparationPolicy(nil, desktopNodeTestSession, "linux", 0); err == nil {
		t.Fatal("nil prefix source admitted")
	}
}

func TestDesktopNodeCandidatePreparationPolicyRejectsMutatedOwner(t *testing.T) {
	for name, mutate := range map[string]func(*DesktopNodeCandidatePreparationPolicy){
		"original-source": func(p *DesktopNodeCandidatePreparationPolicy) { p.original.source += " " },
		"saved-final":     func(p *DesktopNodeCandidatePreparationPolicy) { p.original.original.nodes[2].inputs.ProfileJSON += " " },
		"runtime-final": func(p *DesktopNodeCandidatePreparationPolicy) {
			p.preparation.original.nodes[2].inputs.ProfileJSON += " "
		},
		"graph":  func(p *DesktopNodeCandidatePreparationPolicy) { p.preparation.config += " " },
		"prefix": func(p *DesktopNodeCandidatePreparationPolicy) { p.preparation.proofs[0].Tag = "foreign" },
		"candidate": func(p *DesktopNodeCandidatePreparationPolicy) {
			p.preparation.candidates.targets[0].Address = "192.0.2.99:443"
		},
		"physical":    func(p *DesktopNodeCandidatePreparationPolicy) { p.capture.PhysicalRoots[0].Destinations[0].Port++ },
		"session":     func(p *DesktopNodeCandidatePreparationPolicy) { p.inputs.sessionID = strings.Repeat("f", 32) },
		"target":      func(p *DesktopNodeCandidatePreparationPolicy) { p.inputs.targetOS = "windows" },
		"restore":     func(p *DesktopNodeCandidatePreparationPolicy) { p.inputs.restoredMTU = 1300 },
		"application": func(p *DesktopNodeCandidatePreparationPolicy) { p.metadata.ApplicationOpen = true },
		"dns":         func(p *DesktopNodeCandidatePreparationPolicy) { p.metadata.DNSOpen = true },
	} {
		t.Run(name, func(t *testing.T) {
			p := desktopCandidatePreparationFixture(t, "wg", "linux", 0, 0, nil)
			mutate(p)
			if p.Validate() == nil || p.Config() != "" || p.Source() != "" || p.Preparation() != nil {
				t.Fatal("changed original prefix owner remained usable")
			}
		})
	}
}

func TestDesktopNodeCandidatePreparationPolicyQueryCopies(t *testing.T) {
	p := desktopCandidatePreparationFixture(t, "wg", "linux", 0, 0, nil)
	_, _, capture, _ := p.PhysicalReadValidated()
	meta := p.Metadata()
	meta.Prefixes[0].Tag, meta.Roots[0].Tag = "foreign", "foreign"
	capture.PhysicalRoots[0].Networks[0] = "tcp"
	capture.PhysicalRoots[0].Destinations[0].Port = 1
	_, _, again, err := p.PhysicalReadValidated()
	if err != nil || p.Metadata().Prefixes[0].Tag == "foreign" || p.Metadata().Roots[0].Tag == "foreign" ||
		again.PhysicalRoots[0].Networks[0] != "udp" || again.PhysicalRoots[0].Destinations[0].Port == 1 {
		t.Fatal("public query mutated native authority", err)
	}
	raw, _ := json.Marshal(p.Metadata())
	for _, node := range p.original.original.nodes {
		for _, secret := range []string{predecessorText(node.profile, "router_api"), predecessorText(node.profile, "api_token")} {
			if secret != "" && strings.Contains(string(raw), secret) {
				t.Fatal("public metadata leaked private proof")
			}
		}
	}
}

func TestDesktopNodeCandidatePreparationPolicyCannotBecomeOrdinaryReady(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		t.Run(target, func(t *testing.T) {
			p := desktopCandidatePreparationFixture(t, "wg", target, 0, 0, nil)
			_, meta, capture, err := ReadDesktopPhysicalPolicy(p)
			if err != nil {
				t.Fatal(err)
			}
			name := "router-vpn"
			if target == "darwin" {
				name = "utun13"
			}
			transfer := strings.Repeat("a", 64)
			record := DesktopNodeReadyRecord{Schema: 1, Kind: "routervpn-node-ready-v1", SessionID: meta.SessionID,
				SourceSHA256: meta.SourceSHA256, ConfigSHA256: meta.ConfigSHA256, TransferSHA256: transfer,
				DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, InterfaceName: name, InterfaceIndex: 771,
				MTU: capture.ConfiguredMTU, ProvedAt: 1793366400123, DNSMilliseconds: 1.25}
			if err := record.Validate(p, transfer); err == nil || !strings.Contains(err.Error(), "candidate prefix preparation cannot become ordinary Router readiness") {
				t.Fatal("prefix source accepted or misclassified as ordinary connected readiness", err)
			}
			raw, _ := json.Marshal(record)
			if _, err := ParseDesktopNodeReadyRecord(raw, p, transfer); err == nil {
				t.Fatal("canonical positive fields upgraded prefix into ordinary readiness")
			}
		})
	}
}
