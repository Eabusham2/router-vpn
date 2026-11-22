package mobilemultihop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"router-vpn/internal/hopmeasure"
)

// Each imported source must first pass its existing complete standalone member
// and single-import path constructors. A duplicate ID or invalid key would not
// establish the independently selected multi-import requirement.
func nodeChainIndependentImportedFixture(t *testing.T, index int) string {
	t.Helper()
	config, capture, _, _ := importedEntryFixture(t, "", "")
	graph, selected := externalTestRead(t, config), externalTestRead(t, capture)
	profile := selected["profile"].(map[string]any)
	out := externalTestFind(t, graph, ExternalFinalTag)
	ss := profile["external"].(map[string]any)["shadowsocks"].(map[string]any)
	id := fmt.Sprintf("independent-import-%d", index)
	host := fmt.Sprintf("203.0.113.%d", 40+index)
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(90 + index)}, 32))
	profile["id"], selected["exit_id"] = id, id
	selected["expected_public_ip"] = fmt.Sprintf("198.51.100.%d", 40+index)
	profile["external"].(map[string]any)["expected_public_ip"] = selected["expected_public_ip"]
	out["server"], out["server_port"], out["password"] = host, float64(21000+index), key
	ss["server"], ss["port"], ss["password"] = host, float64(21000+index), key
	input, err := NodeChainImportedMemberInput(startJSON(t, graph), startJSON(t, selected))
	if err != nil {
		t.Fatal("independent complete imported source was invalid", index, err)
	}
	member, err := parseNodeChainImportedMember(input)
	if err != nil || member.id() != id || member.selection.ExpectedPublicIP != selected["expected_public_ip"] {
		t.Fatal("independent imported identity changed", index, err)
	}
	return input
}

func TestNodeChainMultipleIndependentImportedRequirement(t *testing.T) {
	base := nodeChainImportedFixture(t, "wg", "")
	first, second := nodeChainIndependentImportedFixture(t, 1), nodeChainIndependentImportedFixture(t, 2)
	for i, input := range []string{first, second} {
		one := base
		one.Nodes = append([]string(nil), base.Nodes...)
		one.Nodes[1] = input
		if _, err := NewNodeChain(startJSON(t, one)); err != nil {
			t.Fatal("original single-import positive failed before composition", i, err)
		}
	}
	var a, b nodeChainImportedInput
	if json.Unmarshal([]byte(first), &a) != nil || json.Unmarshal([]byte(second), &b) != nil || a.Config == b.Config || a.Capture == b.Capture {
		t.Fatal("multiple-import witness reused an original source")
	}
	source := NodeChainSource{
		Schema: 6, Execution: "local",
		Nodes:           []string{base.Nodes[0], first, second, base.Nodes[2]},
		IdentitySources: []string{base.IdentitySources[0], "", "", base.IdentitySources[2]},
	}
	chain, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal("two independent valid imports still have no complete ordered graph", err)
	}
	proofs := chain.ProofInventory()
	if len(proofs) != 4 || proofs[1].ProfileID != "independent-import-1" || proofs[2].ProfileID != "independent-import-2" || proofs[1].SourceSHA256 == proofs[2].SourceSHA256 {
		t.Fatal("independent imported identities were substituted during composition")
	}
}

type nodeChainImportedLayout struct {
	name      string
	count     int
	positions []int
}

var nodeChainImportedLayouts = []nodeChainImportedLayout{
	{"single", 3, []int{1}}, {"adjacent", 4, []int{1, 2}},
	{"separated", 5, []int{1, 3}}, {"before-paired-suffix", 6, []int{1, 3}},
	{"maximum-sparse", 8, []int{1, 4, 6}}, {"maximum-public", 8, []int{1, 2, 3, 4, 5, 6}},
}

func nodeChainMultipleImportedFixture(t *testing.T, layout nodeChainImportedLayout, mode, layer string) NodeChainSource {
	t.Helper()
	modes, layers, identities := make([]string, layout.count), make([]string, layout.count), make([]string, layout.count)
	for i := range modes {
		modes[i], identities[i] = mode, "wg"
	}
	modes[len(modes)-1], layers[len(layers)-1] = "shadowsocks", layer
	nodes := nodeChainModeFixtureNodes(t, modes, layers)
	wg := nodeChainModeFixtureNodes(t, identities, make([]string, layout.count))
	source := nodeChainFixtureSource(t, nodes)
	source.Schema, source.IdentitySources = 6, make([]string, layout.count)
	for i := range source.Nodes {
		source.IdentitySources[i] = wg[i].inputs.Files
	}
	for _, position := range layout.positions {
		if position <= 0 || position >= layout.count-1 {
			t.Fatal("fixture import is not interior")
		}
		source.Nodes[position], source.IdentitySources[position] = nodeChainIndependentImportedFixture(t, position), ""
	}
	return source
}

func TestNodeChainMultipleImportedCompleteCapture(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		for _, layout := range nodeChainImportedLayouts {
			for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
				name := layer
				if name == "" {
					name = "off"
				}
				t.Run(mode+"_"+layout.name+"_"+name, func(t *testing.T) {
					source := nodeChainMultipleImportedFixture(t, layout, mode, layer)
					chain, err := NewNodeChain(startJSON(t, source))
					if err != nil {
						t.Fatal("complete imported source rejected", err)
					}
					if chain.importedNodes == nil || len(chain.proofs) != layout.count || chain.Progress().Ready {
						t.Fatal("complete source omitted positions or invented readiness")
					}
					graph := externalTestRead(t, chain.Config())
					public, _, err := chain.PublicMeasurementCaptures()
					if err != nil || len(public) != len(layout.positions) {
						t.Fatal("public inventory omitted an import", err)
					}
					for i, capture := range public {
						position := layout.positions[i]
						proof := chain.proofs[position]
						if capture.Position != position || capture.Tag != proof.Tag || capture.SourceSHA256 != proof.SourceSHA256 || proof.ProfileID != fmt.Sprintf("independent-import-%d", position) || proof.Kind != "public-path" || proof.NodeID != "" {
							t.Fatal("per-position public source changed", i)
						}
					}
					for i, proof := range chain.proofs {
						out := externalTestFind(t, graph, proof.Tag)
						if proof.Position != i || i > 0 && out["detour"] != chain.proofs[i-1].Tag {
							t.Fatal("an imported or paired prefix was bypassed", i)
						}
					}
					selected := false
					for _, raw := range graph["dns"].(map[string]any)["servers"].([]any) {
						resolver := raw.(map[string]any)
						if resolver["tag"] == chain.dns.ResolverTag {
							selected = resolver["detour"] == chain.FinalTag() && resolver["server"] == fmt.Sprintf("10.%d.0.53", 80+layout.count-1)
						}
					}
					first, firstErr := chain.nodes[0].PhysicalEgress()
					physical, physicalErr := chain.PhysicalEgress()
					if !selected || firstErr != nil || physicalErr != nil || !reflect.DeepEqual(first, physical) {
						t.Fatal("final DNS or the sole first physical root changed")
					}
					plan, err := chain.MTUPlan()
					if err != nil || len(plan.Prefixes) != layout.count || plan.Ceiling < 1280 {
						t.Fatal("complete per-hop envelope lost", err)
					}
					launch, err := chain.LaunchInput()
					if err != nil {
						t.Fatal(err)
					}
					reopened, err := ParseNodeChainLaunchInput(launch)
					if err != nil || reopened.Config() != chain.Config() || reopened.Metadata() != chain.Metadata() || reopened.sourceJSON != chain.sourceJSON {
						t.Fatal("complete original replay changed", err)
					}
					if _, _, err := chain.PublicMeasurementCapture(); err == nil {
						t.Fatal("new source acquired a legacy single-public capability")
					}
				})
			}
		}
	}
}

func TestNodeChainMultipleImportedProjectionAndDevicePolicy(t *testing.T) {
	for _, position := range []int{1, 3} {
		for _, target := range []string{"linux", "windows", "darwin", "android", "ios"} {
			t.Run(fmt.Sprintf("%s_%d", target, position), func(t *testing.T) {
				source := nodeChainMultipleImportedFixture(t, nodeChainImportedLayouts[3], "awg2-strong", "aes-256-gcm+xor-whitening")
				var member nodeChainImportedInput
				if json.Unmarshal([]byte(source.Nodes[position]), &member) != nil {
					t.Fatal("fixture member unavailable")
				}
				capture := externalTestRead(t, member.Capture)
				profile := capture["profile"].(map[string]any)
				profile["kill_switch_policy"], profile["home_lan_access"], profile["ipv6_mode"] = "always", false, "off"
				var err error
				source.Nodes[position], err = NodeChainImportedMemberInput(member.Config, startJSON(t, capture))
				if err != nil {
					t.Fatal(err)
				}
				chain, err := NewNodeChain(startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				projected, err := ProjectNodeChain(chain, target, 1280)
				if err != nil || projected.importedNodes == chain.importedNodes || projected.importedNodes.owner != projected {
					t.Fatal("projection borrowed original imported owners", err)
				}
				public, ipv6, err := projected.PublicMeasurementCaptures()
				if err != nil || ipv6 || len(public) != 2 {
					t.Fatal("an earlier imported device policy was omitted", err)
				}
				launch, err := projected.LaunchInput()
				if err != nil {
					t.Fatal(err)
				}
				reopened, err := ParseNodeChainLaunchInput(launch)
				if err != nil || reopened.Config() != projected.Config() || reopened.Metadata() != projected.Metadata() {
					t.Fatal("projected replay changed", err)
				}
				plan, err := projected.PlanForMTU(projected.Config(), 1280)
				if err != nil || plan.Ceiling < 1280 {
					t.Fatal("projected per-hop MTU plan lost", err)
				}
				if target == "android" || target == "ios" {
					return
				}
				policy, err := NewDesktopNodeChainPolicy(chain, strings.Repeat("a", 32), target, 1280)
				if err != nil {
					t.Fatal(err)
				}
				_, meta, physical, err := policy.ReadValidated()
				if err != nil || meta.KillSwitchPolicy != "always" || meta.HomeLANAccess || physical.IPv6Mode != "off" || len(physical.PhysicalRoots) != 1 || len(meta.Prefixes) != 6 {
					t.Fatal("complete imported protection or physical source lost", err)
				}
			})
		}
	}
}

func TestNodeChainMultipleImportedRejectsChangedOriginalOwners(t *testing.T) {
	for _, fault := range []string{"nil-set", "copy-set", "foreign-set", "copy-chain", "swap-imports", "omit-import", "copy-first-import", "copy-last-import", "copy-policy", "copy-entry", "copy-final", "changed-input", "resealed-source", "reorder-proofs", "legacy-middle"} {
		t.Run(fault, func(t *testing.T) {
			source := nodeChainMultipleImportedFixture(t, nodeChainImportedLayouts[2], "wg", "")
			chain, err := NewNodeChain(startJSON(t, source))
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "nil-set":
				chain.importedNodes = nil
			case "copy-set":
				copy := *chain.importedNodes
				chain.importedNodes = &copy
			case "foreign-set":
				other, e := NewNodeChain(startJSON(t, source))
				if e != nil {
					t.Fatal(e)
				}
				chain.importedNodes = other.importedNodes
			case "copy-chain":
				copy := *chain
				chain = &copy
			case "swap-imports":
				chain.importedNodes.members[1], chain.importedNodes.members[3] = chain.importedNodes.members[3], chain.importedNodes.members[1]
			case "omit-import":
				chain.importedNodes.members[1] = nil
			case "copy-first-import":
				copy := *chain.importedNodes.members[1]
				chain.importedNodes.members[1] = &copy
			case "copy-last-import":
				copy := *chain.importedNodes.members[3]
				chain.importedNodes.members[3] = &copy
			case "copy-policy":
				copy := *chain.importedNodes.members[1].policy
				chain.importedNodes.members[1].policy = &copy
			case "copy-entry":
				copy := *chain.nodes[0]
				chain.nodes[0] = &copy
			case "copy-final":
				copy := *chain.nodes[4]
				chain.nodes[4] = &copy
			case "changed-input":
				chain.importedNodes.members[1].input += " "
			case "resealed-source":
				chain.sourceJSON += " "
				chain.seal = chain.captureSeal()
			case "reorder-proofs":
				chain.proofs[1], chain.proofs[3] = chain.proofs[3], chain.proofs[1]
				chain.seal = chain.captureSeal()
			case "legacy-middle":
				chain.importedMiddle = chain.importedNodes.members[3]
			}
			if chain.validateCapture() == nil {
				t.Fatal("changed complete imported ownership accepted", fault)
			}
			if _, err := chain.LaunchInput(); err == nil {
				t.Fatal("changed import retained launch authority")
			}
			if _, _, err := chain.PublicMeasurementCaptures(); err == nil {
				t.Fatal("changed import retained a public route")
			}
		})
	}
}

func TestNodeChainMultipleImportedKeepsOlderCapabilitiesClosed(t *testing.T) {
	source := nodeChainMultipleImportedFixture(t, nodeChainImportedLayouts[1], "wg", "")
	chain, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	for _, schema := range []int{1, 2, 3, 4, 5} {
		t.Run(fmt.Sprintf("schema_%d", schema), func(t *testing.T) {
			old := source
			old.Schema = schema
			if _, err := NewNodeChain(startJSON(t, old)); err == nil {
				t.Fatal("older source acquired multiple imported positions")
			}
		})
	}
	for _, execution := range []string{"server", "auto"} {
		t.Run(execution, func(t *testing.T) {
			if _, err := NewNodeChainExecutionPreparation(startJSON(t, source), execution); err == nil {
				t.Fatal("Local multiple imports acquired unproved Server authority")
			}
		})
	}
	input, _ := candidateSourceFixture(t, "paired", NativeStartLayerMethod)
	inventory := candidateInventoryFixture(t, "original-catalog", input)
	old, err := NewNodeChain(startJSON(t, nodeChainImportedFixture(t, "wg", "")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.NewCandidatePlan(0, inventory); err != nil {
		t.Fatal("candidate positive prerequisite failed", err)
	}
	if _, err := chain.NewCandidatePlan(0, inventory); err == nil {
		t.Fatal("multiple-import candidate acquired missing connected native capability")
	}
	if _, err := NewNodeChainCandidatePreparation(startJSON(t, source), 0, inventory); err == nil {
		t.Fatal("multiple-import source acquired missing saved-prefix policy")
	}
	if _, err := NewNodeChainSOCKSSource(startJSON(t, source)); err == nil {
		t.Fatal("Local imports borrowed typed SOCKS authority")
	}
	if _, err := NewNodeChainCONNECTSource(startJSON(t, source)); err == nil {
		t.Fatal("Local imports borrowed typed CONNECT authority")
	}
}

func TestNodeChainMultipleImportedProvesEachOriginalPublicIdentity(t *testing.T) {
	for _, fault := range []string{"valid", "first-public", "second-public", "swapped-public", "dns", "retired-network", "untrusted-tls"} {
		t.Run(fault, func(t *testing.T) {
			chain, err := NewNodeChain(startJSON(t, nodeChainMultipleImportedFixture(t, nodeChainImportedLayouts[2], "wg", "")))
			if err != nil {
				t.Fatal(err)
			}
			engine := newNodeChainTestEngine(t, chain)
			first, second := chain.proofs[1].Tag, chain.proofs[3].Tag
			if engine.publicBodies[first] == engine.publicBodies[second] || engine.publicPeers[first] == engine.publicPeers[second] {
				t.Fatal("independent public fixtures reused identity or server")
			}
			switch fault {
			case "first-public":
				engine.publicBodies[first] = engine.publicBodies[second]
			case "second-public":
				engine.publicBodies[second] = engine.publicBodies[first]
			case "swapped-public":
				engine.publicPeers[first], engine.publicPeers[second] = engine.publicPeers[second], engine.publicPeers[first]
			case "dns":
				engine.dnsFail = true
			case "retired-network":
				engine.changeOnDNS = true
			case "untrusted-tls":
				chain.runtime.testTLS = nil
			}
			err = chain.Run(t.Context(), engine)
			if fault != "valid" {
				if err == nil || chain.Progress().Ready {
					t.Fatal("one public proof or selected DNS masked another failure", fault)
				}
				if fault == "first-public" || fault == "second-public" || fault == "swapped-public" {
					engine.mu.Lock()
					calls, dns := append([]string(nil), engine.calls...), engine.dnsCalls
					engine.mu.Unlock()
					want := 2
					if fault == "second-public" {
						want = 4
					}
					if len(calls) != want || dns != 0 {
						t.Fatal("a failed imported position reached a later proof", calls, dns)
					}
				}
				return
			}
			if err != nil || chain.HealthyContext(t.Context()) != nil {
				t.Fatal("independent complete path failed", err)
			}
			engine.mu.Lock()
			calls, dns := append([]string(nil), engine.calls...), engine.dnsCalls
			engine.mu.Unlock()
			if !reflect.DeepEqual(calls, append(chain.PrefixTags(), chain.PrefixTags()...)) || dns != 1 {
				t.Fatal("repeat proof omitted or substituted an imported tag", calls, dns)
			}
			progress := chain.Progress()
			if !progress.Ready || !progress.DNSProven || !progress.PublicProven || len(progress.Prefixes) != 5 || progress.Prefixes[1].Kind != "public-path" || progress.Prefixes[3].Kind != "public-path" {
				t.Fatal("complete imported readiness lost", progress)
			}
		})
	}
}

func TestNodeChainMultipleImportedMeasurementRoutesAndCancellation(t *testing.T) {
	chain, err := NewNodeChain(startJSON(t, nodeChainMultipleImportedFixture(t, nodeChainImportedLayouts[1], "wg", "")))
	if err != nil {
		t.Fatal(err)
	}
	engine := newNodeChainTestEngine(t, chain)
	owner := &nodeChainMeasurementFixture{chain: chain}
	if _, err := chain.NewHopMeasurementContext(t.Context(), owner); err == nil {
		t.Fatal("unproved multiple imports acquired measurement")
	}
	if err := chain.Run(t.Context(), engine); err != nil {
		t.Fatal(err)
	}
	service, err := chain.NewHopMeasurementContext(t.Context(), owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	measured := &nodeChainMeasurementEngine{source: chain, owner: owner, identity: engine.identity}
	for _, position := range []int{1, 2} {
		tag := chain.proofs[position].Tag
		engine.mu.Lock()
		engine.expected[tag], engine.peers[tag] = hopmeasure.PublicAddress, engine.publicPeers[tag]
		engine.mu.Unlock()
		conn, err := measured.Dial(t.Context(), tag, hopmeasure.PublicAddress)
		if err != nil || conn == nil {
			t.Fatal("original imported measurement route failed", position, err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		if conn, err := measured.Dial(t.Context(), tag, "10.80.0.1:8787"); err == nil || conn != nil {
			t.Fatal("imported measurement acquired a private credential scope")
		}
	}
	if conn, err := measured.Dial(t.Context(), chain.proofs[0].Tag, hopmeasure.PublicAddress); err == nil || conn != nil {
		t.Fatal("private prefix borrowed public benchmark scope")
	}
	engine.mu.Lock()
	engine.identity.NetworkID = "replacement-network"
	engine.mu.Unlock()
	if conn, err := measured.Dial(t.Context(), chain.proofs[1].Tag, hopmeasure.PublicAddress); err == nil || conn != nil {
		t.Fatal("retired multiple-import path measured a replacement")
	}

	fresh, err := NewNodeChain(chain.sourceJSON)
	if err != nil {
		t.Fatal(err)
	}
	freshEngine := newNodeChainTestEngine(t, fresh)
	entered := make(chan struct{})
	var once sync.Once
	freshEngine.beforeDial = func(ctx context.Context, tag string) (net.Conn, bool) {
		if tag == fresh.proofs[2].Tag {
			once.Do(func() { close(entered) })
			<-ctx.Done()
		}
		return nil, false
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- fresh.Run(ctx, freshEngine) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("actual second imported proof did not enter")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled public proof succeeded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled proof did not join")
	}
	closeCtx, finish := context.WithTimeout(context.Background(), time.Second)
	defer finish()
	if err := fresh.CloseContext(closeCtx); err != nil || fresh.Progress().Ready {
		t.Fatal("cancelled imported owner remained ready", err)
	}
}

func TestNodeChainMultipleImportedExtendedLocalCapture(t *testing.T) {
	for _, count := range []int{9, 16} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			positions := make([]int, count-2)
			for i := range positions {
				positions[i] = i + 1
			}
			layout := nodeChainImportedLayout{"extended", count, positions}
			source := nodeChainMultipleImportedFixture(t, layout, "wg", "")
			chain, err := NewNodeChain(startJSON(t, source))
			if err != nil {
				t.Fatal("extended original capture", err)
			}
			if chain.ExtendedLocalNodeCount() != count {
				t.Fatal("extended capture lost original membership")
			}
			plan, err := chain.MTUPlan()
			if err != nil || len(plan.Prefixes) != count {
				t.Fatal("extended prefix MTU inventory", err)
			}
			if _, err = chain.PlanForMTU(chain.Config(), plan.Original); err != nil {
				t.Fatal("actual MTU readback", err)
			}
			launch, err := chain.LaunchInput()
			if err != nil {
				t.Fatal("extended launch", err)
			}
			reopened, err := ParseNodeChainLaunchInput(launch)
			if err != nil || reopened.ExtendedLocalNodeCount() != count || reopened.Config() != chain.Config() {
				t.Fatal("extended original replay", err)
			}
			inventory, _ := entryInventory(t)
			candidates, err := chain.NewCandidatePlan(0, inventory)
			if err != nil || candidates.multiple == nil || candidates.chain != chain {
				t.Fatal("candidate admission lost the original extended capture", err)
			}
			if _, err := chain.NewCandidatePlan(1, inventory); err == nil {
				t.Fatal("a stream member acquired destination TCP handshake measurement")
			}
			closed, err := NewNodeChainCandidatePreparation(startJSON(t, source), 0, inventory)
			if err != nil || closed.OriginalSourceSHA256() != chain.SourceSHA256() || !closed.IsMultipleImported() {
				t.Fatal("closed candidate prefix lost its full original extended source", err)
			}
			readback, err := ParseNodeChainCandidatePreparationCapture(closed.Source())
			if err != nil || readback.CaptureSHA256() != closed.CaptureSHA256() {
				t.Fatal("independent candidate prefix readback lost its original source", err)
			}
			// Duplicating the last private source must fail before any route opens.
			source.Nodes[count-2] = source.Nodes[count-3]
			if _, err = NewNodeChain(startJSON(t, source)); err == nil {
				t.Fatal("accepted a copied late source")
			}
		})
	}
}
