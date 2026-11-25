package mobilemultihop

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

func externalFinalSourceFixture(t *testing.T, count int, dns string) NodeChainSource {
	t.Helper()
	return externalFinalModeFixture(t, count, dns, "wg")
}

func externalFinalModeFixture(t *testing.T, count int, dns, mode string) NodeChainSource {
	t.Helper()
	return externalFinalEntryLayerFixture(t, count, dns, mode, "")
}

func externalFinalEntryLayerFixture(t *testing.T, count int, dns, mode, layer string) NodeChainSource {
	t.Helper()
	positions := make([]int, count-2)
	for i := range positions {
		positions[i] = i + 1
	}
	source := nodeChainMultipleImportedFixture(t, nodeChainImportedLayout{"external-final", count, positions}, mode, "")
	if layer != "" {
		first := nodeChainModeFixtureNodes(t, []string{mode}, []string{layer})[0]
		var assets map[string]string
		if err := json.Unmarshal([]byte(first.inputs.Start), &assets); err != nil {
			t.Fatal(err)
		}
		graph := externalTestRead(t, string(mustDecodeChainAsset(t, assets["sing-box.json"])))
		outer := graph["outbounds"].([]any)[0].(map[string]any)
		outer["password"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{239}, 32))
		assets["sing-box.json"] = base64.StdEncoding.EncodeToString([]byte(startJSON(t, graph)))
		first, err := NewNodeProfile(mode, first.inputs.Files, first.inputs.ProfileJSON, startJSON(t, assets), first.inputs.DNSBootstrap)
		if err != nil {
			t.Fatal(err)
		}
		source.Nodes[0], err = first.LaunchInput()
		if err != nil {
			t.Fatal(err)
		}
	}
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
	p["dns_mode"], p["multihop_entry_mode"], p["multihop_entry_id"], p["multihop_exit_id"], p["multihop_enabled"], p["multihop_execution"] = dns, mode, entry.profile["id"], s["exit_id"], true, "local"
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
				launch, err := desktop.ReadValidatedLaunch()
				if err != nil || launch.Metadata.ExternalFinal == nil {
					t.Fatal("missing original launch exit", err)
				}
				original := desktop.Metadata()
				if !sameDesktopNodeChainMetadata(original, launch.Metadata) || original.ExternalFinal == launch.Metadata.ExternalFinal {
					t.Fatal("launch did not return an independent copy of the original exit")
				}
				*launch.Metadata.ExternalFinal = NodeChainExternalFinalMetadata{ProfileID: "foreign", SourceSHA256: "foreign", ExpectedPublicIP: "192.0.2.254"}
				if actual := desktop.Metadata(); !sameDesktopNodeChainMetadata(actual, original) ||
					actual.ExternalFinal.SourceSHA256 != proofs[count-1].SourceSHA256 || desktop.Validate() != nil {
					t.Fatal("mutating the launch exit changed the retained original")
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

func TestNodeChainExternalFinalEntryLayers(t *testing.T) {
	for _, spec := range []struct {
		mode, layer, dns string
		count            int
	}{
		{"wg", "aes-256-gcm", "home", 3}, {"wg", "aes-256-gcm+xor-whitening", "custom", 9},
		{"awg2-fast", "aes-256-gcm", "custom", 9}, {"awg2-fast", "aes-256-gcm+xor-whitening", "home", 3},
		{"awg2-strong", "aes-256-gcm", "home", 9}, {"awg2-strong", "aes-256-gcm+xor-whitening", "custom", 96},
	} {
		t.Run(spec.mode+"/"+spec.layer, func(t *testing.T) {
			source := externalFinalEntryLayerFixture(t, spec.count, spec.dns, spec.mode, spec.layer)
			chain, err := NewNodeChain(startJSON(t, source))
			if err != nil {
				t.Fatal("complete source", err)
			}
			first := chain.proofs[0]
			if !chain.HasExternalFinal() || first.StartLayer != spec.layer || first.Mode != spec.mode {
				t.Fatal("original paired first layer missing")
			}
			outer := nodeChainNamespace(0, first.SourceSHA256, "node", NativeStartLayerTag)
			graph := externalTestRead(t, chain.Config())
			if externalTestFind(t, graph, first.Tag)["detour"] != outer {
				t.Fatal("packet escaped its original outer transport")
			}
			owner := externalTestFind(t, graph, outer)
			transport, err := nodeMultihopPredecessor(chain.nodes[0])
			if err != nil {
				t.Fatal(err)
			}
			for k, v := range transport.nodes[NativeStartLayerTag] {
				if k != "tag" && !reflect.DeepEqual(owner[k], v) {
					t.Fatal("changed outer credential, protocol or endpoint", k)
				}
			}
			plan, err := chain.MTUPlan()
			if err != nil || len(plan.Prefixes) != len(chain.proofs) {
				t.Fatal("layered prefix MTU", err)
			}
			if _, err = chain.PlanForMTU(chain.Config(), plan.Original); err != nil {
				t.Fatal("live layer MTU readback", err)
			}
			desktop, err := NewDesktopNodeChainPolicy(chain, "0123456789abcdef0123456789abcdef", "linux", 0)
			if err != nil {
				t.Fatal("desktop layer", err)
			}
			_, _, capture, err := desktop.ReadValidated()
			projected := desktop.NodeChain()
			if projected == nil {
				t.Fatal("sealed physical layer projection missing")
			}
			if _, e := projected.PlanForMTU(desktop.Config(), plan.Original); e != nil {
				t.Fatal("physical owner readback", e)
			}
			detour := chain.FinalTag()
			if spec.dns == "home" {
				detour = first.Tag
			}
			if err != nil || capture.SelectedDNS.Detour != detour || len(capture.PhysicalRoots) != 1 {
				t.Fatal("selected DNS or physical root", err)
			}
			if spec.count < 96 {
				inv := candidateInventoryFixture(t, "original", nodeChainIndependentImportedFixture(t, 49))
				if _, err = chain.NewPublicCandidatePreparation(spec.count-2, inv); err != nil {
					t.Fatal("closed layered prefix", err)
				}
			}
		})
	}
}

func TestNodeChainExternalFinalLayerRejectsSharedCredential(t *testing.T) {
	source := externalFinalEntryLayerFixture(t, 3, "home", "awg2-fast", "aes-256-gcm+xor-whitening")
	chain, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	entry, err := nodeMultihopPredecessor(chain.nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	candidate := nodeChainIndependentImportedFixture(t, 49)
	var record nodeChainImportedInput
	if json.Unmarshal([]byte(candidate), &record) != nil {
		t.Fatal("original candidate")
	}
	graph, policy := externalTestRead(t, record.Config), externalTestRead(t, record.Capture)
	key := entry.nodes[NativeStartLayerTag]["password"]
	externalTestFind(t, graph, ExternalFinalTag)["password"] = key
	policy["profile"].(map[string]any)["external"].(map[string]any)["shadowsocks"].(map[string]any)["password"] = key
	input, err := NodeChainImportedMemberInput(startJSON(t, graph), startJSON(t, policy))
	if err != nil {
		t.Fatal("independent standalone candidate", err)
	}
	if _, err = chain.NewPublicCandidatePreparation(1, candidateInventoryFixture(t, "same-layer", input)); err == nil {
		t.Fatal("public candidate reused the physical layer credential")
	}
	source.Nodes[1] = input
	if _, err = NewNodeChain(startJSON(t, source)); err == nil {
		t.Fatal("imported suffix reused the physical layer credential")
	}
}

func TestNodeChainExternalFinalAWGEntry(t *testing.T) {
	for _, mode := range []string{"awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			source := externalFinalModeFixture(t, 9, "home", mode)
			chain, err := NewNodeChain(startJSON(t, source))
			if err != nil {
				t.Fatal("original AWG external-final route", err)
			}
			first, last := chain.proofs[0], chain.proofs[len(chain.proofs)-1]
			if !chain.HasExternalFinal() || first.Mode != mode || !proofID.MatchString(first.NodeID) || last.Kind != "public-path" {
				t.Fatal("lost original packet entry, Home DNS or public exit", first, last)
			}
			projected, err := NewDesktopNodeChainPolicy(chain, "0123456789abcdef0123456789abcdef", "linux", 0)
			if err != nil {
				t.Fatal("desktop policy", err)
			}
			_, _, capturePolicy, err := projected.ReadValidated()
			if err != nil || capturePolicy.SelectedDNS.Detour != first.Tag || len(capturePolicy.PhysicalRoots) != 1 {
				t.Fatal("lost original Home resolver or physical owner", err)
			}
			original, err := nodeMultihopPredecessor(chain.nodes[0])
			if err != nil {
				t.Fatal(err)
			}
			physical := externalTestFind(t, externalTestRead(t, chain.Config()), first.Tag)
			for key, value := range original.final {
				if key != "tag" && !reflect.DeepEqual(physical[key], value) {
					t.Fatal("selected AWG entry changed a captured endpoint field", key)
				}
			}
			plan, err := chain.MTUPlan()
			if err != nil {
				t.Fatal("original prefix bounds", err)
			}
			bound, err := chain.PlanForMTU(chain.Config(), plan.Original)
			if err != nil || len(plan.Prefixes) != len(chain.proofs) || bound.Ceiling != plan.Ceiling {
				t.Fatal("actual per-prefix MTU", err)
			}
			candidate := candidateInventoryFixture(t, "original", nodeChainIndependentImportedFixture(t, 49))
			if _, err := chain.NewPublicCandidatePreparation(7, candidate); err != nil {
				t.Fatal("public candidate through the captured AWG entry", err)
			}
			mobileFinal, err := NodeChainExternalFinalFromEntry(source.Nodes[0], nodeChainIndependentImportedFixture(t, 8))
			if err != nil {
				t.Fatal("mobile original entry to external final", err)
			}
			mobile := source
			mobile.Nodes = append([]string(nil), source.Nodes...)
			mobile.Nodes[len(mobile.Nodes)-1] = mobileFinal
			if replay, err := NewNodeChain(startJSON(t, mobile)); err != nil || replay.proofs[0] != first {
				t.Fatal("mobile replay changed packet entry", err)
			}
			var final nodeChainImportedInput
			if err := json.Unmarshal([]byte(source.Nodes[8]), &final); err != nil {
				t.Fatal(err)
			}
			capture := externalTestRead(t, final.Capture)
			other := "awg2-fast"
			if mode == other {
				other = "awg2-strong"
			}
			capture["profile"].(map[string]any)["multihop_entry_mode"] = other
			final.Capture = startJSON(t, capture)
			source.Nodes[8] = startJSON(t, final)
			if _, err := NewNodeChain(startJSON(t, source)); err == nil {
				t.Fatal("substituted AWG variant admitted")
			}
		})
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
