package mobilemultihop

import (
	"reflect"
	"strings"
	"sync"
	"testing"
)

func connectIntegrityFixture(t *testing.T) *NodeChainCONNECTSource {
	t.Helper()
	value, err := NewNodeChainCONNECTSource(startJSON(t, nodeChainCONNECTFixture(t, "wg", "https-connect", "", "2022-blake3-aes-128-gcm", "password")))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestNodeChainCONNECTIntegrityPreservesOriginalCompiler(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				input := startJSON(t, nodeChainCONNECTFixture(t, mode, protocol, "", "2022-blake3-aes-128-gcm", "password"))
				source, err := NewNodeChainCONNECTSource(input)
				if err != nil {
					t.Fatal(err)
				}
				config, metadata, err := source.ReadValidated()
				if err != nil || source.integrity == nil || source.validateCompiled() != nil || source.integrity.owner != source || source.integrity.config != config || !reflect.DeepEqual(source.integrity.metadata, metadata) {
					t.Fatal("fresh receipt lost original compiler validation", err)
				}
				actual, err := source.Source()
				if err != nil || actual != input || metadata.NativeAdmission != "closed" || metadata.TransportCapability != "uot-v2" {
					t.Fatal("integrity receipt changed source, exact final carrier or admission", err)
				}
				if source.retainIntegrity() == nil {
					t.Fatal("existing integrity receipt was refreshed")
				}
			})
		}
	}
}

func TestNodeChainCONNECTIntegrityRejectsChangedInputs(t *testing.T) {
	cases := []struct {
		name   string
		change func(*NodeChainCONNECTSource)
	}{
		{"source", func(p *NodeChainCONNECTSource) { p.sourceJSON += " " }},
		{"config", func(p *NodeChainCONNECTSource) { p.config += " " }},
		{"seal", func(p *NodeChainCONNECTSource) { p.seal = "" }},
		{"proof", func(p *NodeChainCONNECTSource) { p.metadata.Proofs[1].Tag = "foreign" }},
		{"mtu", func(p *NodeChainCONNECTSource) { p.metadata.MTU.Prefixes[0].Ceiling++ }},
		{"device", func(p *NodeChainCONNECTSource) { p.metadata.Devices[1].HomeLANAccess = true }},
		{"pair", func(p *NodeChainCONNECTSource) {
			// Preserve the compiler capture, without copying runtime mutex ownership.
			p.pair = &NodeChain{
				sourceJSON:        p.pair.sourceJSON,
				sourceSHA:         p.pair.sourceSHA,
				config:            p.pair.config,
				metadata:          p.pair.metadata,
				seal:              p.pair.seal,
				nodes:             p.pair.nodes,
				importedMiddle:    p.pair.importedMiddle,
				socksSource:       p.pair.socksSource,
				connectSource:     p.pair.connectSource,
				proofs:            p.pair.proofs,
				dns:               p.pair.dns,
				physical:          p.pair.physical,
				originalConfigSHA: p.pair.originalConfigSHA,
				projection:        p.pair.projection,
			}
		}},
		{"pair-source", func(p *NodeChainCONNECTSource) { p.pair.sourceJSON += " " }},
		{"pair-config", func(p *NodeChainCONNECTSource) { p.pair.config += " " }},
		{"pair-metadata", func(p *NodeChainCONNECTSource) { p.pair.metadata += " " }},
		{"pair-seal", func(p *NodeChainCONNECTSource) { p.pair.seal = "" }},
		{"pair-proof", func(p *NodeChainCONNECTSource) { p.pair.proofs[0].Tag = "foreign" }},
		{"pair-dns", func(p *NodeChainCONNECTSource) { p.pair.dns.FinalTag = "foreign" }},
		{"pair-physical", func(p *NodeChainCONNECTSource) { p.pair.physical[0].Host = "203.0.113.99" }},
		{"pair-projection", func(p *NodeChainCONNECTSource) { p.pair.projection.SessionID = "foreign" }},
		{"node-owner", func(p *NodeChainCONNECTSource) { copy := *p.pair.nodes[0]; p.pair.nodes[0] = &copy }},
		{"node-config", func(p *NodeChainCONNECTSource) { p.pair.nodes[0].config += " " }},
		{"node-input", func(p *NodeChainCONNECTSource) { p.pair.nodes[0].inputs.Files += " " }},
		{"node-profile", func(p *NodeChainCONNECTSource) { p.pair.nodes[0].profile["api_token"] = "foreign" }},
		{"member-owner", func(p *NodeChainCONNECTSource) { copy := *p.middle; p.middle = &copy }},
		{"member-input", func(p *NodeChainCONNECTSource) { p.middle.input += " " }},
		{"member-source", func(p *NodeChainCONNECTSource) { p.middle.source = "foreign" }},
		{"member-seal", func(p *NodeChainCONNECTSource) { p.middle.seal = "" }},
		{"member-profile", func(p *NodeChainCONNECTSource) { p.middle.selection.Profile["api_token"] = "foreign" }},
		{"policy-owner", func(p *NodeChainCONNECTSource) { copy := *p.middle.policy; p.middle.policy = &copy }},
		{"policy-config", func(p *NodeChainCONNECTSource) { p.middle.policy.config += " " }},
		{"policy-metadata", func(p *NodeChainCONNECTSource) { p.middle.policy.metadata += " " }},
		{"policy-source", func(p *NodeChainCONNECTSource) { p.middle.policy.source = "foreign" }},
		{"policy-seal", func(p *NodeChainCONNECTSource) { p.middle.policy.desktopSeal = "" }},
		{"policy-profile", func(p *NodeChainCONNECTSource) { p.middle.policy.capture.Profile["api_token"] = "foreign" }},
		{"carrier", func(p *NodeChainCONNECTSource) { p.metadata.TransportCapability = "udp" }},
		{"admission", func(p *NodeChainCONNECTSource) { p.metadata.NativeAdmission = "open" }},
		{"metadata-dns", func(p *NodeChainCONNECTSource) { p.metadata.DNS.FinalTag = "foreign" }},
		{"metadata-physical", func(p *NodeChainCONNECTSource) { p.metadata.Physical[0].Host = "203.0.113.99" }},
		{"pair-source-sha", func(p *NodeChainCONNECTSource) { p.pair.sourceSHA = "foreign" }},
		{"pair-original-config-sha", func(p *NodeChainCONNECTSource) { p.pair.originalConfigSHA = "foreign" }},
		{"pair-imported", func(p *NodeChainCONNECTSource) { p.pair.importedMiddle = &nodeChainImportedMember{} }},
		{"pair-socks", func(p *NodeChainCONNECTSource) { p.pair.socksSource = &NodeChainSOCKSSource{} }},
		{"pair-connect", func(p *NodeChainCONNECTSource) { p.pair.connectSource = &NodeChainCONNECTSource{} }},
		{"pair-node-count", func(p *NodeChainCONNECTSource) { p.pair.nodes = append(p.pair.nodes, p.pair.nodes[0]) }},
		{"final-owner", func(p *NodeChainCONNECTSource) { copy := *p.pair.nodes[1]; p.pair.nodes[1] = &copy }},
		{"final-service-asset", func(p *NodeChainCONNECTSource) { p.pair.nodes[1].inputs.Files += " " }},
		{"final-token", func(p *NodeChainCONNECTSource) { p.pair.nodes[1].profile["api_token"] = "foreign" }},
		{"middle-tls-name", func(p *NodeChainCONNECTSource) {
			p.middle.selection.Profile["external"].(map[string]any)["https_connect"].(map[string]any)["server_name"] = "foreign.invalid"
		}},
		{"middle-credentials", func(p *NodeChainCONNECTSource) {
			p.middle.selection.Profile["external"].(map[string]any)["https_connect"].(map[string]any)["password"] = "foreign"
		}},
		{"missing-receipt", func(p *NodeChainCONNECTSource) { p.integrity = nil }},
		{"foreign-receipt", func(p *NodeChainCONNECTSource) { other := connectIntegrityFixture(t); p.integrity = other.integrity }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			source := connectIntegrityFixture(t)
			originalPair := source.pair
			test.change(source)
			if test.name == "pair" && (source.pair == originalPair || !reflect.DeepEqual(source.pair, originalPair)) {
				t.Fatal("pair identity fixture must change only the inert compiler pointer")
			}
			if config, _, err := source.ReadValidated(); err == nil || config != "" {
				t.Fatal("changed captured input retained integrity authority")
			}
			if input, err := source.Source(); err == nil || input != "" {
				t.Fatal("changed captured input returned stale private source")
			}
		})
	}
	t.Run("copied-source", func(t *testing.T) {
		source := connectIntegrityFixture(t)
		copy := *source
		if _, _, err := copy.ReadValidated(); err == nil {
			t.Fatal("copied source borrowed original integrity owner")
		}
	})
}

func TestNodeChainCONNECTIntegrityConcurrentReadbackOwnsCopies(t *testing.T) {
	source := connectIntegrityFixture(t)
	originalConfig, original, err := source.ReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	failures := make(chan string, 8)
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 20 {
				config, meta, err := source.ReadValidated()
				if err != nil || config != originalConfig || !reflect.DeepEqual(meta, original) {
					failures <- "concurrent read changed original capture"
					return
				}
				meta.Proofs[1].Tag = "foreign"
				meta.Physical[0].Host = "203.0.113.99"
				meta.MTU.Prefixes[0].Ceiling++
				meta.Devices[1].HomeLANAccess = true
			}
		}()
	}
	group.Wait()
	close(failures)
	for failure := range failures {
		t.Fatal(failure)
	}
	if source.validateCompiled() != nil {
		t.Fatal("returned metadata mutated the original compiler input")
	}
}

func TestNodeChainCONNECTIntegrityFieldInventory(t *testing.T) {
	// New compiler fields require an explicit integrity review, rather than a
	// silently incomplete future snapshot. Runtime state remains observed by
	// the original engine; it is deliberately outside source integrity.
	values := []struct {
		value  any
		fields string
	}{
		{NodeChainCONNECTSource{}, "sourceJSON config seal pair middle metadata integrity"},
		{NodeChain{}, "sourceJSON sourceSHA config metadata seal nodes importedMiddle socksSource connectSource proofs dns physical runtime originalConfigSHA projection"},
		{NodeProfile{}, "config source metadata mode profile inputs desktopSeal"},
		{nodeChainCONNECTMember{}, "input source seal selection policy"},
		{ExternalPolicy{}, "config metadata source capture desktopSeal"},
	}
	for _, value := range values {
		kind := reflect.TypeOf(value.value)
		actual := make([]string, kind.NumField())
		for i := range actual {
			actual[i] = kind.Field(i).Name
		}
		if strings.Join(actual, " ") != value.fields {
			t.Fatal("compiler input fields changed without integrity review", kind.Name())
		}
	}
}
