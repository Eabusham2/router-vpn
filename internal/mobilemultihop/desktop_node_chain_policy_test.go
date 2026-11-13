package mobilemultihop

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func desktopChainFixture(t *testing.T, count int, layer string, edit func(int, map[string]any)) *NodeChain {
	t.Helper()
	nodes := nodeChainFixtureNodes(t, count, layer)
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
	chain, err := NewNodeChain(startJSON(t, nodeChainFixtureSource(t, nodes)))
	if err != nil {
		t.Fatal(err)
	}
	return chain
}

func desktopChainPolicy(t *testing.T, chain *NodeChain, target string, restore int) *DesktopNodeChainPolicy {
	t.Helper()
	policy, err := NewDesktopNodeChainPolicy(chain, desktopNodeTestSession, target, restore)
	if err != nil {
		t.Fatal("complete ordered desktop projection", err)
	}
	return policy
}

func TestDesktopNodeChainPolicyExactPhysicalProjection(t *testing.T) {
	for _, target := range []string{"linux", "windows", "darwin"} {
		for _, test := range []struct {
			count   int
			layer   string
			restore int
		}{{3, "", 0}, {4, "aes-256-gcm+xor-whitening", 1400}} {
			t.Run(fmt.Sprintf("%s/%d/%s", target, test.count, test.layer), func(t *testing.T) {
				original := desktopChainFixture(t, test.count, test.layer, nil)
				before, _ := original.LaunchInput()
				policy := desktopChainPolicy(t, original, target, test.restore)
				config, meta, capture, err := policy.ReadValidated()
				chain := policy.NodeChain()
				if err != nil || chain == nil || chain == original || config != chain.Config() || meta.ConfigSHA256 != chain.ConfigSHA256() ||
					meta.OriginalSourceSHA256 != original.SourceSHA256() || chain.SourceSHA256() != original.SourceSHA256() ||
					meta.OriginalConfigSHA256 != original.ConfigSHA256() || chain.OriginalConfigSHA256() != original.ConfigSHA256() ||
					meta.SourceSHA256 == chain.SourceSHA256() || len(meta.Prefixes) != test.count || chain.Progress().Ready {
					t.Fatal("physical owner changed source, split executable identity or invented admission", err)
				}
				if meta.ProfileID != original.proofs[test.count-1].ProfileID || meta.NodeID != original.proofs[test.count-1].NodeID ||
					capture.SelectedDNS.Detour != chain.FinalTag() || capture.SelectedDNS.Physical ||
					capture.SelectedDNS.ConfigSHA256 != chain.DNSCapture().ResolverSHA256 || capture.ConfiguredMTU != 1280 {
					t.Fatal("chain borrowed another control profile, resolver or measured MTU")
				}
				sharedConfig, shared, sharedCapture, err := ReadDesktopPhysicalPolicy(policy)
				if err != nil || sharedConfig != config || shared.Kind != "node-chain" || shared.SourceSHA256 != meta.SourceSHA256 ||
					shared.ConfigSHA256 != chain.ConfigSHA256() || !reflect.DeepEqual(capture, sharedCapture) {
					t.Fatal("closed native policy reader lost the concrete chain", err)
				}
				projected, err := ProjectNodeChain(original, target, test.restore)
				if err != nil {
					t.Fatal(err)
				}
				graph := startObject(t, config)
				for i, root := range capture.PhysicalRoots {
					row := desktopNodeObject(t, graph, root.Family, root.Tag)
					if row["detour"] != DesktopNodePhysicalTag || meta.Roots[i].DerivedSHA256 != desktopExternalObjectDigest(row) ||
						!strings.HasPrefix(root.Tag, "routervpn-chain-0-") {
						t.Fatal("middle node acquired a physical bypass")
					}
					delete(row, "detour")
					if desktopExternalObjectDigest(row) != root.ConfigSHA256 || meta.Roots[i].OriginalSHA256 != root.ConfigSHA256 {
						t.Fatal("outer credentials, packet budget or first transport changed")
					}
				}
				for _, pair := range []struct{ family, tag, kind string }{
					{"outbounds", DesktopNodePhysicalTag, DesktopNodePhysicalType}, {"services", DesktopNodeNetworkTag, DesktopNodeNetworkType},
				} {
					row := desktopNodeObject(t, graph, pair.family, pair.tag)
					if len(row) != 4 || row["type"] != pair.kind || row["session_id"] != desktopNodeTestSession || row["source_sha256"] != meta.SourceSHA256 {
						t.Fatal("physical native graph lost original session/platform owner")
					}
					rows := graph[pair.family].([]any)
					if pair.family == "services" {
						delete(graph, pair.family)
					} else {
						graph[pair.family] = rows[:len(rows)-1]
					}
				}
				if !reflect.DeepEqual(graph, startObject(t, projected.Config())) {
					t.Fatal("native projection changed inner prefix, DNS, route or TUN policy")
				}
				plan, err := chain.MTUPlan()
				expected, expectedErr := projected.MTUPlan()
				if err != nil || expectedErr != nil || !reflect.DeepEqual(plan, expected) || len(plan.Prefixes) != test.count {
					t.Fatal("native physical service erased an original MTU envelope", err, expectedErr)
				}
				launch, err := chain.LaunchInput()
				child, childErr := ParseDesktopNodeChainLaunchInput(launch)
				generic, genericErr := ParseNodeChainLaunchInput(launch)
				if err != nil || childErr != nil || genericErr != nil || child.Config() != config || generic.Config() != config ||
					!reflect.DeepEqual(child.Metadata(), meta) || child.NodeChain().SourceSHA256() != chain.SourceSHA256() {
					t.Fatal("child failed to reconstruct one exact typed physical graph", err, childErr, genericErr)
				}
				after, _ := original.LaunchInput()
				if before != after || policy.OriginalChain() != original {
					t.Fatal("desktop projection changed original capture or original owner pointer")
				}
				replayed, retained, replayErr := parseNodeChainLaunchInput(launch)
				if replayErr != nil || replayed == nil || retained == nil || retained.chain != replayed ||
					retained.original == nil || retained.original == original || retained == child || retained.chain == child.chain || retained.original == child.original {
					t.Fatal("typed replay lost its constructed owner or reused another parse", replayErr)
				}
				retainedLaunch, replayErr := retained.chain.LaunchInput()
				if replayErr != nil || retainedLaunch != launch || retained.Validate() != nil {
					t.Fatal("retained constructor changed exact launch bytes", replayErr)
				}
				retained.original.nodes[1].inputs.ProfileJSON += " "
				if retained.Validate() == nil || child.Validate() != nil || policy.Validate() != nil {
					t.Fatal("reused replay cached a changed middle source or aliased another owner")
				}
			})
		}
	}
}

func TestDesktopNodeChainPolicyCombinesProtectionAndKeepsFinalDNS(t *testing.T) {
	chain := desktopChainFixture(t, 4, "", func(position int, profile map[string]any) {
		profile["kill_switch_policy"] = "off"
		if position == 0 {
			profile["home_lan_access"], profile["home_lan_cidrs"] = false, []string{"10.20.0.0/16"}
		}
		if position == 1 {
			profile["ipv6_mode"], profile["kill_switch_policy"] = "off", "always"
		}
		if position == 3 {
			profile["dns_mode"], profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "custom", "tls", "198.51.100.44", 8853
			profile["dns_server_name"] = "selected.example"
		}
	})
	policy := desktopChainPolicy(t, chain, "linux", 0)
	_, meta, capture, err := policy.ReadValidated()
	cover, coverDigest, coverErr := ReadDesktopPhysicalCoverPolicy(policy)
	if coverErr != nil || len(cover) != 0 || coverDigest != "" {
		t.Fatal("ordered native graph fabricated a cover worker", coverErr)
	}
	if err != nil || meta.ProfileID != chain.proofs[3].ProfileID || meta.KillSwitchPolicy != "always" || meta.IPv6Mode != "off" || meta.HomeLANAccess ||
		capture.SelectedDNS.Type != "tls" || capture.SelectedDNS.Host != "198.51.100.44" || capture.SelectedDNS.Port != 8853 ||
		capture.SelectedDNS.ServerName != "selected.example" || capture.SelectedDNS.Detour != chain.FinalTag() || capture.SelectedDNS.Physical ||
		len(capture.PrivateDestinations) != 0 || len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Destinations[0].Host != "198.51.100.10" {
		t.Fatal("middle restrictions or final resolver became another profile's physical permission", err)
	}
	meta.Prefixes[1].Tag, meta.Roots[0].Tag = "foreign-middle", "foreign-root"
	capture.PhysicalRoots[0].Destinations[0].Port = 1
	capture.PhysicalRoots[0].Networks[0] = "tcp"
	_, again, fresh, err := policy.ReadValidated()
	if err != nil || again.Prefixes[1].Tag == "foreign-middle" || again.Roots[0].Tag == "foreign-root" || fresh.PhysicalRoots[0].Destinations[0].Port == 1 ||
		fresh.PhysicalRoots[0].Networks[0] != "udp" {
		t.Fatal("returned metadata or capture aliases native policy", err)
	}
}

func TestDesktopNodeChainPolicyRejectsChangedOriginalAndPhysicalGraph(t *testing.T) {
	for name, mutate := range map[string]func(*DesktopNodeChainPolicy){
		"source":          func(p *DesktopNodeChainPolicy) { p.metadata.OriginalSourceSHA256 = strings.Repeat("f", 64) },
		"physical-source": func(p *DesktopNodeChainPolicy) { p.metadata.SourceSHA256 = strings.Repeat("f", 64) },
		"session":         func(p *DesktopNodeChainPolicy) { p.inputs.sessionID = strings.Repeat("f", 32) },
		"target":          func(p *DesktopNodeChainPolicy) { p.inputs.targetOS = "windows" },
		"restore":         func(p *DesktopNodeChainPolicy) { p.inputs.restoredMTU = 1400 },
		"control":         func(p *DesktopNodeChainPolicy) { p.metadata.ProfileID = p.chain.proofs[0].ProfileID },
		"original-source": func(p *DesktopNodeChainPolicy) { p.original.sourceJSON += " " },
		"middle-source":   func(p *DesktopNodeChainPolicy) { p.original.nodes[1].inputs.ProfileJSON += " " },
		"replacement-proof-source": func(p *DesktopNodeChainPolicy) {
			previous := p.chain.nodes[1]
			profile := predecessorCopy(previous.profile)
			profile["api_token"] = "another-authenticated-private-node-owner"
			replacement, err := NewNodeProfile(previous.inputs.Mode, previous.inputs.Files, startJSON(t, profile), previous.inputs.Start, previous.inputs.DNSBootstrap)
			if err != nil {
				t.Fatal(err)
			}
			p.chain.nodes[1] = replacement
		},
		"omitted-prefix": func(p *DesktopNodeChainPolicy) { p.chain.proofs = append(p.chain.proofs[:1], p.chain.proofs[2:]...) },
		"middle-physical": func(p *DesktopNodeChainPolicy) {
			graph := startObject(t, p.chain.config)
			middle := desktopNodeObject(t, graph, "endpoints", p.chain.proofs[1].Tag)
			middle["detour"] = DesktopNodePhysicalTag
			p.chain.config = startJSON(t, graph)
		},
		"selected-dns-physical": func(p *DesktopNodeChainPolicy) {
			graph := startObject(t, p.chain.config)
			for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
				row := raw.(map[string]any)
				if row["tag"] == p.chain.dns.ResolverTag {
					row["detour"] = DesktopNodePhysicalTag
				}
			}
			p.chain.config = startJSON(t, graph)
		},
		"network-service": func(p *DesktopNodeChainPolicy) {
			graph := startObject(t, p.chain.config)
			graph["services"].([]any)[0].(map[string]any)["session_id"] = strings.Repeat("f", 32)
			p.chain.config = startJSON(t, graph)
		},
	} {
		t.Run(name, func(t *testing.T) {
			policy := desktopChainPolicy(t, desktopChainFixture(t, 3, "", nil), "linux", 0)
			mutate(policy)
			// Hashes alone cannot replace original constructor authority.
			policy.chain.dns.ConfigSHA256 = externalDigest([]byte(policy.chain.config))
			policy.chain.seal = policy.chain.captureSeal()
			policy.metadata.ConfigSHA256 = policy.chain.dns.ConfigSHA256
			policy.seal = policy.currentSeal()
			if policy.Validate() == nil || policy.Config() != "" || policy.NodeChain() != nil {
				t.Fatal("recomputed hashes admitted a substituted original or physical graph")
			}
			if _, _, _, err := ReadDesktopPhysicalPolicy(policy); err == nil {
				t.Fatal("closed native reader accepted changed chain authority")
			}
			if name == "middle-physical" || name == "selected-dns-physical" || name == "network-service" {
				if _, err := policy.chain.MTUPlan(); err == nil {
					t.Fatal("read-only MTU projection erased an injected physical bypass")
				}
			}
		})
	}
}

func TestDesktopNodeChainPolicyLaunchOwnerReceiptAndClosedConstructor(t *testing.T) {
	chain := desktopChainFixture(t, 3, "", nil)
	policy := desktopChainPolicy(t, chain, "linux", 0)
	launch, err := policy.NodeChain().LaunchInput()
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]any{
		"session_id": strings.Repeat("f", 32), "target_os": "windows", "restored_mtu": 1400,
		"projection_kind": "", "source_sha256": strings.Repeat("f", 64), "config_sha256": strings.Repeat("f", 64),
	} {
		t.Run(name, func(t *testing.T) {
			var record nodeChainLaunchRecord
			if json.Unmarshal([]byte(launch), &record) != nil {
				t.Fatal("launch fixture unavailable")
			}
			value := startObject(t, launch)
			value[name] = change
			raw, _ := json.Marshal(value)
			if json.Unmarshal(raw, &record) != nil {
				t.Fatal("receipt mutation unavailable")
			}
			canonical, _ := json.Marshal(record)
			if actual, retained, err := parseNodeChainLaunchInput(string(canonical)); err == nil || actual != nil || retained != nil {
				t.Fatal("failed receipt validation leaked a partially constructed owner")
			}
			if actual, err := ParseDesktopNodeChainLaunchInput(string(canonical)); err == nil || actual != nil {
				t.Fatal("changed owner replayed an earlier source/config receipt")
			}
		})
	}
	for _, field := range []string{"metadata", "original-config"} {
		var record nodeChainLaunchRecord
		if json.Unmarshal([]byte(launch), &record) != nil {
			t.Fatal("launch fixture unavailable")
		}
		if field == "metadata" {
			record.MetadataSHA256 = strings.Repeat("f", 64)
		} else {
			record.OriginalConfigSHA256 = strings.Repeat("f", 64)
		}
		canonical, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if actual, retained, err := parseNodeChainLaunchInput(string(canonical)); err == nil || actual != nil || retained != nil {
			t.Fatal("reused constructor bypassed an original metadata/config receipt", field)
		}
		if actual, err := ParseDesktopNodeChainLaunchInput(string(canonical)); err == nil || actual != nil {
			t.Fatal("typed replay accepted a foreign metadata/config receipt", field)
		}
	}
	for _, malformed := range []string{"", launch + "\n", strings.TrimSuffix(launch, "}") + `,"foreign":true}`} {
		if actual, retained, err := parseNodeChainLaunchInput(malformed); err == nil || actual != nil || retained != nil {
			t.Fatal("noncanonical launch leaked a chain or desktop owner")
		}
		if actual, err := ParseDesktopNodeChainLaunchInput(malformed); err == nil || actual != nil {
			t.Fatal("typed replay adopted noncanonical launch bytes")
		}
	}
	plain, _ := chain.LaunchInput()
	if _, err := ParseDesktopNodeChainLaunchInput(plain); err == nil {
		t.Fatal("unprojected source acquired native physical authority")
	}
	if _, err := NewDesktopNodeChainPolicy(policy.NodeChain(), desktopNodeTestSession, "linux", 0); err == nil {
		t.Fatal("already physical chain was projected twice")
	}
	for _, bad := range []struct {
		session, target string
		restore         int
	}{
		{"", "linux", 0}, {desktopNodeTestSession, "ios", 0}, {desktopNodeTestSession, "android", 0},
		{desktopNodeTestSession, "linux", 1279}, {desktopNodeTestSession, "linux", 9001},
	} {
		if _, err := NewDesktopNodeChainPolicy(chain, bad.session, bad.target, bad.restore); err == nil {
			t.Fatal("unsupported native owner capture accepted", bad.target, bad.restore)
		}
	}
	allOff := desktopChainFixture(t, 3, "", func(_ int, profile map[string]any) { profile["kill_switch_policy"] = "off" })
	if _, err := NewDesktopNodeChainPolicy(allOff, desktopNodeTestSession, "linux", 0); err == nil {
		t.Fatal("protected desktop authority silently adopted disabled protection")
	}
	if _, _, _, err := ReadDesktopPhysicalPolicy(desktopPhysicalWrapper{policy}); err == nil {
		t.Fatal("caller wrapper substituted a closed constructor")
	}
	var missing *DesktopNodeChainPolicy
	if _, _, _, err := ReadDesktopPhysicalPolicy(missing); err == nil {
		t.Fatal("typed nil acquired native owner authority")
	}
}
