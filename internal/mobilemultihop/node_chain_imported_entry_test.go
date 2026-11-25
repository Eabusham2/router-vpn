package mobilemultihop

import (
	"reflect"
	"testing"
)

func nodeChainImportedEntryFixture(t *testing.T) NodeChainSource {
	t.Helper()
	source := nodeChainMultipleImportedFixture(t, nodeChainImportedLayouts[0], "wg", "")
	source.Schema = 7
	source.Nodes[0], source.IdentitySources[0] = nodeChainIndependentImportedFixture(t, 0), ""
	return source
}

func TestNodeChainImportedEntry(t *testing.T) {
	source := nodeChainImportedEntryFixture(t)
	chain, err := NewNodeChain(startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	if !chain.HasImportedEntry() {
		t.Fatal("original custom-entry readback missing")
	}
	foreign := nodeChainOwnershipCopy(chain)
	if foreign.HasImportedEntry() {
		t.Fatal("copied graph borrowed custom-entry classification")
	}
	legacy, err := NewNodeChain(startJSON(t, nodeChainMultipleImportedFixture(t, nodeChainImportedLayouts[0], "wg", "")))
	if err != nil || legacy.HasImportedEntry() {
		t.Fatal("legacy paired entry gained custom-entry classification", err)
	}
	entry, middle, final := chain.proofs[0], chain.proofs[1], chain.proofs[2]
	if entry.Kind != "public-path" || middle.Kind != "public-path" || entry.Tag == middle.Tag || entry.SourceSHA256 == middle.SourceSHA256 || final.NodeID == "" || chain.dns.FinalTag != final.Tag {
		t.Fatal("lost original prefix identities or final DNS")
	}
	want, err := chain.importedSSMemberAt(0).policy.DirectPhysicalEgress([]string{"tcp", "udp"})
	if err != nil || len(want) != 2 || !nodeChainSamePhysical(chain.physical, want) {
		t.Fatal("physical sockets escaped the original first proxy", err)
	}
	for _, target := range []string{"android", "ios"} {
		projected, err := ProjectNodeChain(chain, target, 0)
		if err != nil {
			t.Fatal(target, err)
		}
		launch, err := projected.LaunchInput()
		if err != nil {
			t.Fatal(target, err)
		}
		parsed, err := ParseNodeChainLaunchInput(launch)
		if err != nil || parsed.Config() != projected.Config() || !parsed.HasImportedEntry() || !reflect.DeepEqual(parsed.proofs, chain.proofs) {
			t.Fatal("changed provider readback", target, err)
		}
	}
	for _, target := range []string{"linux", "windows", "darwin"} {
		policy, err := NewDesktopNodeChainPolicy(chain, desktopNodeTestSession, target, 0)
		if err != nil {
			t.Fatal(target, err)
		}
		config, meta, capture, err := policy.ReadValidated()
		if err != nil || config != policy.Config() || len(capture.PhysicalRoots) != 1 || capture.PhysicalRoots[0].Tag != entry.Tag || !nodeChainSamePhysical(capture.PhysicalRoots[0].Destinations, want) || capture.SelectedDNS.Detour != final.Tag || capture.SelectedDNS.Physical || !reflect.DeepEqual(meta.Prefixes, chain.proofs) {
			t.Fatal("desktop physical, DNS or per-position sources changed", target, err)
		}
		launch, err := policy.NodeChain().LaunchInput()
		if err != nil {
			t.Fatal(target, err)
		}
		parsed, err := ParseDesktopNodeChainLaunchInput(launch)
		if err != nil {
			t.Fatal("typed desktop child launch", target, err)
		}
		restored, restoredMeta, restoredCapture, err := parsed.ReadValidated()
		if err != nil || restored != config || !reflect.DeepEqual(meta, restoredMeta) || !reflect.DeepEqual(restoredCapture, capture) {
			t.Fatal("changed desktop physical owner readback", target, err)
		}
	}
	if _, err := NewNodeChainMultipleImportedExecutionPreparation(chain, "server"); err == nil {
		t.Fatal("custom entry borrowed paired Server authority")
	}
	if _, err := chain.NewMultipleImportedCandidatePlan(0, ""); err == nil {
		t.Fatal("custom entry acquired packet handshake timing")
	}
	engine := newNodeChainTestEngine(t, chain)
	if err := chain.Run(t.Context(), engine); err != nil {
		t.Fatal(err)
	}
	progress := chain.Progress()
	if !progress.Ready || !progress.DNSProven || !progress.PublicProven || len(progress.Prefixes) != 3 || progress.Prefixes[0].Kind != "public-path" || progress.Prefixes[1].Kind != "public-path" {
		t.Fatal(progress)
	}
	service, err := chain.NewHopMeasurementContext(t.Context(), &nodeChainMeasurementFixture{chain: chain})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if err := chain.CloseContext(t.Context()); err != nil || chain.Progress().Ready {
		t.Fatal("did not join", err)
	}
}

func TestNodeChainImportedEntryOriginalAuthorities(t *testing.T) {
	for _, fault := range []string{"wrong-entry", "wrong-middle", "wrong-final", "dns", "retired-network", "legacy-schema", "duplicate-import", "paired-first"} {
		t.Run(fault, func(t *testing.T) {
			source := nodeChainImportedEntryFixture(t)
			switch fault {
			case "legacy-schema":
				source.Schema = 6
			case "duplicate-import":
				source.Nodes[1] = source.Nodes[0]
			case "paired-first":
				base := nodeChainImportedFixture(t, "wg", "")
				source.Nodes[0], source.IdentitySources[0] = base.Nodes[0], base.IdentitySources[0]
			}
			chain, err := NewNodeChain(startJSON(t, source))
			switch fault {
			case "legacy-schema", "duplicate-import", "paired-first":
				if err == nil {
					t.Fatal("admitted changed source roles")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			engine := newNodeChainTestEngine(t, chain)
			switch fault {
			case "wrong-entry":
				engine.publicBodies[chain.proofs[0].Tag] = engine.publicBodies[chain.proofs[1].Tag]
			case "wrong-middle":
				engine.publicBodies[chain.proofs[1].Tag] = engine.publicBodies[chain.proofs[0].Tag]
			case "wrong-final":
				engine.wrong = 2
			case "dns":
				engine.dnsFail = true
			case "retired-network":
				engine.changeOnDNS = true
			}
			if err := chain.Run(t.Context(), engine); err == nil || chain.Progress().Ready {
				t.Fatal("missing per-position identity, selected DNS or native generation was accepted")
			}
		})
	}
}
