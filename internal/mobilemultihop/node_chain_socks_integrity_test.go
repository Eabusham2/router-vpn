package mobilemultihop

import (
	"reflect"
	"strings"
	"sync"
	"testing"
)

func socksIntegrityFixture(t *testing.T) *NodeChainSOCKSSource {
	t.Helper()
	value, err := NewNodeChainSOCKSSource(startJSON(t, nodeChainSOCKSFixture(t, "wg", "", "password")))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestNodeChainSOCKSIntegrityPreservesOriginalCompiler(t *testing.T) {
	for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
		t.Run(mode, func(t *testing.T) {
			input := startJSON(t, nodeChainSOCKSFixture(t, mode, "", "password"))
			source, err := NewNodeChainSOCKSSource(input)
			if err != nil {
				t.Fatal(err)
			}
			config, metadata, err := source.ReadValidated()
			if err != nil || source.integrity == nil || source.validateCompiled() != nil ||
				source.integrity.owner != source || source.integrity.config != config ||
				!reflect.DeepEqual(source.integrity.metadata, metadata) {
				t.Fatal("fresh receipt lost original compiler validation", err)
			}
			actual, err := source.Source()
			if err != nil || actual != input || metadata.NativeAdmission != "closed" {
				t.Fatal("integrity receipt changed source or admission", err)
			}
			for _, target := range []string{"linux", "windows", "darwin"} {
				policy, err := NewDesktopNodeChainSOCKSPolicy(source, strings.Repeat("a", 32), target, 0)
				if err != nil {
					t.Fatal(target, err)
				}
				native, err := policy.NativeSource()
				if err != nil || native == source || native.integrity == source.integrity ||
					native.integrity == nil || native.integrity.owner != native ||
					native.desktop.original != source || native.validateCompiled() != nil {
					t.Fatal("derived source borrowed an original receipt", target, err)
				}
				if _, _, err := native.ReadValidated(); err != nil {
					t.Fatal(target, err)
				}
			}
		})
	}
}

func TestNodeChainSOCKSIntegrityRejectsChangedInputs(t *testing.T) {
	cases := []struct {
		name   string
		change func(*NodeChainSOCKSSource)
	}{
		{"source", func(p *NodeChainSOCKSSource) { p.sourceJSON += " " }},
		{"config", func(p *NodeChainSOCKSSource) { p.config += " " }},
		{"seal", func(p *NodeChainSOCKSSource) { p.seal = "" }},
		{"proof", func(p *NodeChainSOCKSSource) { p.metadata.Proofs[1].Tag = "foreign" }},
		{"mtu", func(p *NodeChainSOCKSSource) { p.metadata.MTU.Prefixes[0].Ceiling++ }},
		{"device", func(p *NodeChainSOCKSSource) { p.metadata.Devices[1].HomeLANAccess = true }},
		{"pair", func(p *NodeChainSOCKSSource) { copy := *p.pair; p.pair = &copy }},
		{"pair-source", func(p *NodeChainSOCKSSource) { p.pair.sourceJSON += " " }},
		{"pair-config", func(p *NodeChainSOCKSSource) { p.pair.config += " " }},
		{"pair-metadata", func(p *NodeChainSOCKSSource) { p.pair.metadata += " " }},
		{"pair-seal", func(p *NodeChainSOCKSSource) { p.pair.seal = "" }},
		{"pair-proof", func(p *NodeChainSOCKSSource) { p.pair.proofs[0].Tag = "foreign" }},
		{"pair-dns", func(p *NodeChainSOCKSSource) { p.pair.dns.FinalTag = "foreign" }},
		{"pair-physical", func(p *NodeChainSOCKSSource) { p.pair.physical[0].Host = "203.0.113.99" }},
		{"pair-projection", func(p *NodeChainSOCKSSource) { p.pair.projection.SessionID = "foreign" }},
		{"node-owner", func(p *NodeChainSOCKSSource) { copy := *p.pair.nodes[0]; p.pair.nodes[0] = &copy }},
		{"node-config", func(p *NodeChainSOCKSSource) { p.pair.nodes[0].config += " " }},
		{"node-input", func(p *NodeChainSOCKSSource) { p.pair.nodes[0].inputs.Files += " " }},
		{"node-profile", func(p *NodeChainSOCKSSource) { p.pair.nodes[0].profile["api_token"] = "foreign" }},
		{"member-owner", func(p *NodeChainSOCKSSource) { copy := *p.middle; p.middle = &copy }},
		{"member-input", func(p *NodeChainSOCKSSource) { p.middle.input += " " }},
		{"member-source", func(p *NodeChainSOCKSSource) { p.middle.source = "foreign" }},
		{"member-seal", func(p *NodeChainSOCKSSource) { p.middle.seal = "" }},
		{"member-profile", func(p *NodeChainSOCKSSource) { p.middle.selection.Profile["api_token"] = "foreign" }},
		{"policy-owner", func(p *NodeChainSOCKSSource) { copy := *p.middle.policy; p.middle.policy = &copy }},
		{"policy-config", func(p *NodeChainSOCKSSource) { p.middle.policy.config += " " }},
		{"policy-metadata", func(p *NodeChainSOCKSSource) { p.middle.policy.metadata += " " }},
		{"policy-source", func(p *NodeChainSOCKSSource) { p.middle.policy.source = "foreign" }},
		{"policy-seal", func(p *NodeChainSOCKSSource) { p.middle.policy.desktopSeal = "" }},
		{"policy-profile", func(p *NodeChainSOCKSSource) { p.middle.policy.capture.Profile["api_token"] = "foreign" }},
		{"missing-receipt", func(p *NodeChainSOCKSSource) { p.integrity = nil }},
		{"foreign-receipt", func(p *NodeChainSOCKSSource) { other := socksIntegrityFixture(t); p.integrity = other.integrity }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			source := socksIntegrityFixture(t)
			test.change(source)
			if config, _, err := source.ReadValidated(); err == nil || config != "" {
				t.Fatal("changed captured input retained integrity authority")
			}
			if input, err := source.Source(); err == nil || input != "" {
				t.Fatal("changed captured input returned stale private source")
			}
		})
	}
	t.Run("copied-source", func(t *testing.T) {
		source := socksIntegrityFixture(t)
		copy := *source
		if _, _, err := copy.ReadValidated(); err == nil {
			t.Fatal("copied source borrowed original integrity owner")
		}
	})
}

func TestNodeChainSOCKSIntegrityRejectsChangedDesktopBinding(t *testing.T) {
	cases := []struct {
		name   string
		change func(*NodeChainSOCKSSource)
	}{
		{"binding-owner", func(p *NodeChainSOCKSSource) { copy := *p.desktop; p.desktop = &copy }},
		{"original-owner", func(p *NodeChainSOCKSSource) { copy := *p.desktop.original; p.desktop.original = &copy }},
		{"original-source", func(p *NodeChainSOCKSSource) { p.desktop.original.sourceJSON += " " }},
		{"projection", func(p *NodeChainSOCKSSource) { p.desktop.projection.SessionID = "foreign" }},
		{"metadata", func(p *NodeChainSOCKSSource) { p.desktop.metadata.Roots[0].Tag = "foreign" }},
		{"native-metadata", func(p *NodeChainSOCKSSource) { p.desktop.nativeMetadata.Proofs[1].Tag = "foreign" }},
		{"seal", func(p *NodeChainSOCKSSource) { p.desktop.seal = "" }},
		{"removed", func(p *NodeChainSOCKSSource) { p.desktop = nil }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, policy := desktopSOCKSPolicyFixture(t, "wg", "", "windows", 0)
			source, err := policy.NativeSource()
			if err != nil {
				t.Fatal(err)
			}
			test.change(source)
			if config, _, err := source.ReadValidated(); err == nil || config != "" {
				t.Fatal("changed desktop binding retained integrity authority")
			}
		})
	}
}

func TestNodeChainSOCKSIntegrityConcurrentReadbackOwnsCopies(t *testing.T) {
	source := socksIntegrityFixture(t)
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

func TestNodeChainSOCKSIntegrityFieldInventory(t *testing.T) {
	// New compiler fields require an explicit integrity review, rather than a
	// silently incomplete future snapshot. Runtime state remains observed by
	// the original engine; it is deliberately outside source integrity.
	values := []struct {
		value  any
		fields string
	}{
		{NodeChainSOCKSSource{}, "sourceJSON config seal pair middle metadata desktop integrity"},
		{NodeChain{}, "sourceJSON sourceSHA config metadata seal nodes importedMiddle socksSource connectSource proofs dns physical runtime originalConfigSHA projection"},
		{NodeProfile{}, "config source metadata mode profile inputs desktopSeal"},
		{nodeChainSOCKSMember{}, "input source seal selection policy"},
		{ExternalPolicy{}, "config metadata source capture desktopSeal"},
		{nodeChainSOCKSDesktopBinding{}, "original projection metadata nativeMetadata seal"},
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
