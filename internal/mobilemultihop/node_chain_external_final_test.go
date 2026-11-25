package mobilemultihop

import (
	"encoding/json"
	"fmt"
	"testing"
)

func externalFinalSourceFixture(t *testing.T, count int, dns string) NodeChainSource {
	t.Helper()
	positions := make([]int, count-2)
	for i := range positions {
		positions[i] = i + 1
	}
	source := nodeChainMultipleImportedFixture(t, nodeChainImportedLayout{"external-final", count, positions}, "wg", "")
	entry, err := ParseNodeLaunchInput(source.Nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	var record nodeChainImportedInput
	if err := json.Unmarshal([]byte(nodeChainIndependentImportedFixture(t, count-1)), &record); err != nil {
		t.Fatal(err)
	}
	s := externalTestRead(t, record.Capture)
	p := s["profile"].(map[string]any)
	p["dns_mode"], p["multihop_entry_mode"], p["multihop_entry_id"], p["multihop_exit_id"], p["multihop_enabled"], p["multihop_execution"] = dns, "wg", entry.profile["id"], s["exit_id"], true, "local"
	if dns == "custom" {
		p["dns_protocol"], p["dns_host"], p["dns_port"] = "tcp", "198.51.100.198", float64(5353)
	}
	s["entry"], s["entry_tag"], s["predecessor_config"] = entry.profile, externalEntryTag, entry.Config()
	final, err := NodeChainExternalFinalInput(record.Config, startJSON(t, s))
	if err != nil {
		t.Fatal("original external final input", err)
	}
	source.Schema, source.Nodes[count-1], source.IdentitySources[count-1] = 8, final, ""
	return source
}
func TestNodeChainExternalFinalLocal(t *testing.T) {
	for _, count := range []int{3, 4, 9, 96} {
		for _, dns := range []string{"home", "custom"} {
			t.Run(fmt.Sprintf("%d/%s", count, dns), func(t *testing.T) {
				source := externalFinalSourceFixture(t, count, dns)
				c, err := NewNodeChain(startJSON(t, source))
				if err != nil || !c.HasExternalFinal() {
					t.Fatal("ordered compile", err)
				}
				physical, err := c.PhysicalEgress()
				if err != nil || len(physical) != 1 {
					t.Fatal("physical roots", physical, err)
				}
				proofs := c.ProofInventory()
				if len(proofs) != count || !externalFinalProofs(proofs) {
					t.Fatal("original proofs")
				}
				graph := externalTestRead(t, c.Config())
				for i := 1; i < count; i++ {
					if out := externalTestFind(t, graph, proofs[i].Tag); out["detour"] != proofs[i-1].Tag {
						t.Fatal("lost predecessor", i)
					}
				}
				plan, err := c.MTUPlan()
				if err != nil || len(plan.Prefixes) != count {
					t.Fatal("MTU", err)
				}
				desktop, err := NewDesktopNodeChainPolicy(c, "0123456789abcdef0123456789abcdef", "linux", 0)
				if err != nil {
					t.Fatal("desktop projection", err)
				}
				_, _, capture, err := desktop.ReadValidated()
				want := proofs[count-1].Tag
				if dns == "home" {
					want = proofs[0].Tag
				}
				if desktop.Metadata().ProfileID != proofs[count-1].ProfileID || desktop.Metadata().NodeID != "" || desktop.Metadata().ExternalFinal == nil {
					t.Fatal("public exit lost its own proven identity")
				}
				first := desktop.Metadata().ExternalFinal
				first.SourceSHA256 = "foreign"
				if actual := desktop.Metadata().ExternalFinal; actual == nil || actual.SourceSHA256 != proofs[count-1].SourceSHA256 {
					t.Fatal("metadata reader changed original")
				}
				replay, err := c.LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				restored, err := ParseNodeChainLaunchInput(replay)
				if err != nil || !restored.HasExternalFinal() || restored.Config() != c.Config() {
					t.Fatal("restore changed selected exit", err)
				}
				if _, err := c.PlanForMTU(c.Config(), plan.Original); err != nil {
					t.Fatal("original per-prefix MTU", err)
				}
				if err != nil || capture.SelectedDNS.Detour != want || capture.SelectedDNS.Mode != dns {
					t.Fatal("selected DNS", capture.SelectedDNS, err)
				}
			})
		}
	}
}

func TestNodeChainExternalFinalRuntime(t *testing.T) {
	for _, fault := range []string{"none", "first-stream", "final-address", "dns", "retired"} {
		t.Run(fault, func(t *testing.T) {
			c, err := NewNodeChain(startJSON(t, externalFinalSourceFixture(t, 4, "home")))
			if err != nil {
				t.Fatal(err)
			}
			e := newNodeChainTestEngine(t, c)
			switch fault {
			case "first-stream":
				e.publicBodies[c.proofs[1].Tag] = "ip=203.0.113.151\n"
			case "final-address":
				e.publicBodies[c.FinalTag()] = "ip=203.0.113.152\n"
			case "dns":
				e.dnsFail = true
			case "retired":
				e.identity.NetworkID = "retired"
			}
			err = c.Run(t.Context(), e)
			if fault != "none" && fault != "retired" {
				if err == nil || c.Progress().Ready {
					t.Fatal("invalid route ready", fault)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseContext(t.Context())
			if fault == "retired" {
				e.mu.Lock()
				e.identity.NetworkID = "different"
				e.mu.Unlock()
				if c.HealthyContext(t.Context()) == nil {
					t.Fatal("replacement network borrowed original proof")
				}
				return
			}
			p := c.Progress()
			if !p.Ready || !p.DNSProven || !p.PublicProven || p.Prefixes[3].Kind != "public-path" {
				t.Fatal("unproved external exit", p)
			}
			service, err := c.NewHopMeasurementContext(t.Context(), &nodeChainMeasurementFixture{chain: c})
			if err != nil {
				t.Fatal(err)
			}
			if err := service.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNodeChainExternalFinalRefusesSubstitution(t *testing.T) {
	source := externalFinalSourceFixture(t, 4, "home")
	for _, fault := range []string{"schema-six", "ordinary-middle-as-final", "final-as-middle", "paired-companion", "reordered-entry", "borrowed-entry-profile", "borrowed-socket", "borrowed-key", "wrong-home", "forged-public", "remote-execution"} {
		t.Run(fault, func(t *testing.T) {
			s := source
			s.Nodes = append([]string(nil), source.Nodes...)
			s.IdentitySources = append([]string(nil), source.IdentitySources...)
			final := len(s.Nodes) - 1
			var r nodeChainImportedInput
			if err := json.Unmarshal([]byte(s.Nodes[final]), &r); err != nil {
				t.Fatal(err)
			}
			m := externalTestRead(t, r.Capture)
			profile := m["profile"].(map[string]any)
			switch fault {
			case "schema-six":
				s.Schema = 6
			case "ordinary-middle-as-final":
				s.Nodes[final] = s.Nodes[1]
			case "final-as-middle":
				s.Nodes[1] = s.Nodes[final]
			case "paired-companion":
				s.IdentitySources[final] = s.IdentitySources[0]
			case "reordered-entry":
				s.Nodes[0], s.Nodes[1] = s.Nodes[1], s.Nodes[0]
			case "borrowed-entry-profile":
				m["entry"].(map[string]any)["api_token"] = "different-original-token"
			case "wrong-home":
				profile["dns_host"] = "192.168.77.33"
			case "forged-public":
				m["expected_public_ip"] = "198.51.100.199"
			case "remote-execution":
				s.Execution = "server"
			case "borrowed-socket", "borrowed-key":
				var mid nodeChainImportedInput
				if err := json.Unmarshal([]byte(s.Nodes[1]), &mid); err != nil {
					t.Fatal(err)
				}
				target := externalTestRead(t, r.Config)
				out := externalTestFind(t, target, ExternalFinalTag)
				previous := externalTestFind(t, externalTestRead(t, mid.Config), ExternalFinalTag)
				ss := profile["external"].(map[string]any)["shadowsocks"].(map[string]any)
				if fault == "borrowed-key" {
					ss["password"], out["password"] = previous["password"], previous["password"]
				} else {
					ss["server"], out["server"], ss["port"], out["server_port"] = previous["server"], previous["server"], previous["server_port"], previous["server_port"]
				}
				r.Config = startJSON(t, target)
			}
			if s.Nodes[final] == source.Nodes[final] {
				r.Capture = startJSON(t, m)
				s.Nodes[final] = startJSON(t, r)
			}
			if _, err := NewNodeChain(startJSON(t, s)); err == nil {
				t.Fatal("accepted substitution")
			}
		})
	}
}

func TestNodeChainExternalFinalOriginalEntryCandidate(t *testing.T) {
	source := externalFinalSourceFixture(t, 3, "home")
	c, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	inventory, _ := entryInventory(t)
	prep, err := NewNodeChainMultipleImportedCandidatePreparation(startJSON(t, source), 0, inventory)
	if err != nil {
		t.Fatal("original WG entry preparation", err)
	}
	for _, mtu := range []int{0, 1280} {
		policy, err := NewDesktopNodeCandidatePreparationPolicy(prep, desktopNodeTestSession, "linux", mtu)
		if err != nil {
			t.Fatal("closed-ingress original prefix", mtu, err)
		}
		if err = policy.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, execution := range []string{"server", "auto"} {
		if _, err := NewNodeChainMultipleImportedExecutionPreparation(c, execution); err == nil {
			t.Fatal("public exit acquired paired remote execution")
		}
	}
}

func TestNodeChainExternalFinalInteriorIPv6Policy(t *testing.T) {
	for _, mode := range []string{"home", "custom"} {
		t.Run(mode, func(t *testing.T) {
			source := externalFinalSourceFixture(t, 4, mode)
			var middle nodeChainImportedInput
			if err := json.Unmarshal([]byte(source.Nodes[2]), &middle); err != nil {
				t.Fatal(err)
			}
			capture := externalTestRead(t, middle.Capture)
			capture["profile"].(map[string]any)["ipv6_mode"] = "off"
			var err error
			source.Nodes[2], err = NodeChainImportedMemberInput(middle.Config, startJSON(t, capture))
			if err != nil {
				t.Fatal(err)
			}
			chain, err := NewNodeChain(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			dns := externalTestRead(t, chain.Config())["dns"].(map[string]any)
			if dns["strategy"] != "ipv4_only" {
				t.Fatal("selected DNS ignored intermediate IPv6 Off")
			}
			policy, err := NewDesktopNodeChainPolicy(chain, desktopNodeTestSession, "linux", 0)
			if err != nil {
				t.Fatal(err)
			}
			_, _, physical, err := policy.ReadValidated()
			want := chain.FinalTag()
			if mode == "home" {
				want = chain.ProofInventory()[0].Tag
			}
			if err != nil || physical.IPv6Mode != "off" || physical.SelectedDNS.Mode != mode || physical.SelectedDNS.Detour != want {
				t.Fatal("changed the selected DNS owner or intermediate IPv6 policy", err)
			}
		})
	}
}
