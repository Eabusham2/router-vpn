package mobilemultihop

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/routechoice"
)

func desktopMultipleImportedExecutionFixture(t *testing.T, layout nodeChainImportedLayout, target, execution string, offset int) (*DesktopNodeChainPolicy, *NodeChainExecutionPreparation, NodeChainExecutionSource) {
	t.Helper()
	mode := []string{"wg", "awg2-fast", "awg2-strong"}[offset%3]
	layer := []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"}[offset%3]
	local, _, source := multipleImportedExecutionFixture(t, layout, mode, layer, execution, "")
	original, err := NewDesktopNodeChainPolicy(local, strings.Repeat("c", 32), target, 0)
	if err != nil {
		t.Fatal("original complete native policy", err)
	}
	prep, err := NewDesktopNodeChainMultipleImportedExecutionPreparation(original, execution)
	if err != nil {
		t.Fatal("typed complete native preparation", err)
	}
	return original, prep, source
}

func TestDesktopMultipleImportedExecutionPhysicalLinux(t *testing.T) {
	testDesktopMultipleImportedExecutionPhysical(t, "linux", 0)
}
func TestDesktopMultipleImportedExecutionPhysicalWindows(t *testing.T) {
	testDesktopMultipleImportedExecutionPhysical(t, "windows", 1)
}
func TestDesktopMultipleImportedExecutionPhysicalDarwin(t *testing.T) {
	testDesktopMultipleImportedExecutionPhysical(t, "darwin", 2)
}

func testDesktopMultipleImportedExecutionPhysical(t *testing.T, target string, offset int) {
	for index, layout := range multipleImportedServerLayouts {
		for ci, execution := range []string{"server", "auto"} {
			t.Run(layout.name+"/"+execution, func(t *testing.T) {
				original, prep, source := desktopMultipleImportedExecutionFixture(t, layout, target, execution, index+ci+offset)
				physical, err := prep.MultipleImportedDesktopPhysicalPolicy()
				if err != nil || !prep.RequiresDesktopMultipleImportedExecutionObserver() {
					t.Fatal("missing typed original owner", err)
				}
				retained, err := physical.OriginalDesktopMultipleImportedPolicy()
				local, sourceErr := prep.OriginalMultipleImportedSource()
				if err != nil || sourceErr != nil || retained != original || local != original.original || prep.multiple.desktop.native != original.chain {
					t.Fatal("source or physical owner replaced", err, sourceErr)
				}
				config, meta, capture, err := ReadDesktopPhysicalPolicy(physical)
				_, _, prior, priorErr := original.PhysicalReadValidated()
				if err != nil || priorErr != nil || config != prep.Config() || meta.Kind != "node-chain-multiple-imported-execution" || meta.TargetOS != target || meta.SourceSHA256 != original.metadata.SourceSHA256 || meta.ConfigSHA256 != prep.ConfigSHA256() || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != SelectorTag || !reflect.DeepEqual(capture.PhysicalRoots, prior.PhysicalRoots) || !reflect.DeepEqual(capture.PrivateDestinations, prior.PrivateDestinations) || capture.ConfiguredMTU != prior.ConfiguredMTU {
					t.Fatal("original roots, DNS or MTU replaced", err, priorErr)
				}
				policy, err := NewNodeChainMultipleImportedExecutionPolicy(prep, startJSON(t, source))
				if err != nil {
					t.Fatal(err)
				}
				projection, err := prep.BindExecution(policy)
				if err != nil {
					t.Fatal("original native transition", err)
				}
				adopted, err := projection.MultipleImportedDesktopPhysicalPolicy()
				if err != nil || adopted != physical {
					t.Fatal("physical authority replaced at adoption", err)
				}
				native, after := externalTestRead(t, original.chain.Config()), externalTestRead(t, projection.Config())
				if after["route"].(map[string]any)["final"] != NodeChainExecutionGateTag || !reflect.DeepEqual(native["services"], after["services"]) || !reflect.DeepEqual(native["inbounds"], after["inbounds"]) {
					t.Fatal("original TUN/services or closed application gate changed")
				}
				for _, proof := range local.proofs {
					if !reflect.DeepEqual(externalTestFind(t, native, proof.Tag), externalTestFind(t, after, proof.Tag)) {
						t.Fatal("original native transport changed", proof.Position)
					}
				}
				bound, err := projection.MTUPlan()
				want, wantErr := original.chain.MTUPlan()
				if err != nil || wantErr != nil || !reflect.DeepEqual(bound, want) {
					t.Fatal("complete native packet envelope changed", err, wantErr)
				}
				for _, parser := range []func(string) (*NodeChainExecutionPreparation, error){ParseNodeChainExecutionPreparation, ParseNodeChainMultipleImportedExecutionPreparation, ParseNodeChainOpenVPNExecutionPreparation, ParseDesktopNodeChainOpenVPNExecutionPreparation, ParseDesktopNodeChainCONNECTExecutionPreparation, ParseDesktopNodeChainSOCKSExecutionPreparation} {
					if _, err := parser(prep.Source()); err == nil {
						t.Fatal("foreign family accepted typed desktop source")
					}
				}
				if _, err := prep.DesktopPhysicalPolicy(); err == nil {
					t.Fatal("generic physical wrapper accepted typed owner")
				}
				reopened, err := ParseDesktopNodeChainMultipleImportedExecutionPreparation(prep.Source())
				if err != nil || reopened.Config() != prep.Config() || reopened.Source() != prep.Source() || reopened.multiple.source == local || reopened.multiple.desktop.original == original {
					t.Fatal("independent child reconstruction borrowed original owner", err)
				}
				if _, err := reopened.BindExecution(policy); err == nil {
					t.Fatal("equal-content child borrowed parent policy")
				}
			})
		}
	}
}

func TestDesktopMultipleImportedExecutionOwnerRefusals(t *testing.T) {
	for _, fault := range []string{"nil-preparation", "copied-preparation", "copied-physical", "copied-adjunct", "copied-policy", "copied-native", "equal-policy", "equal-source", "source", "native-config", "native-proof", "native-dns", "native-physical", "native-mtu", "registry", "capture", "metadata", "preparation-source", "preparation-config", "sealed-launch", "saved-record", "mixed-mobile"} {
		t.Run(fault, func(t *testing.T) {
			original, prep, _ := desktopMultipleImportedExecutionFixture(t, multipleImportedServerLayouts[1], "linux", "auto", 0)
			physical, err := prep.MultipleImportedDesktopPhysicalPolicy()
			if err != nil {
				t.Fatal(err)
			}
			requested := prep
			switch fault {
			case "nil-preparation":
				requested = nil
			case "copied-preparation":
				copy := *prep
				requested = &copy
			case "copied-physical":
				copy := *physical
				physical = &copy
			case "copied-adjunct":
				copy := *prep.multiple.desktop
				prep.multiple.desktop = &copy
			case "copied-policy":
				copy := *original
				prep.multiple.desktop.original = &copy
			case "copied-native":
				copy := *original.chain
				prep.multiple.desktop.native = &copy
			case "equal-policy":
				equal, e := NewDesktopNodeChainPolicy(original.original, original.inputs.sessionID, original.inputs.targetOS, original.inputs.restoredMTU)
				if e != nil || equal.Config() != original.Config() {
					t.Fatal("equal policy fixture", e)
				}
				prep.multiple.desktop.original = equal
			case "equal-source":
				equal, e := ParseNodeChainLaunchInput(prep.source.MultipleImportedLocalLaunch)
				if e != nil || equal.Config() != original.original.Config() {
					t.Fatal("equal source fixture", e)
				}
				prep.multiple.desktop.source = equal
			case "source":
				original.original.sourceJSON += " "
			case "native-config":
				original.chain.config += " "
			case "native-proof":
				original.chain.proofs[1].Tag += "-foreign"
			case "native-dns":
				original.chain.dns.ConfigSHA256 = strings.Repeat("a", 64)
			case "native-physical":
				original.chain.physical[0].Port++
			case "native-mtu":
				original.chain.projection.RestoredMTU++
			case "registry":
				copy := *prep.multiple.owners
				prep.multiple.owners = &copy
			case "capture":
				physical.owner.capture.SelectedDNS.Detour = "direct"
			case "metadata":
				prep.source.DesktopMultipleImported.Prefixes[1].ProfileID = "foreign"
			case "preparation-source":
				prep.sourceJSON += " "
			case "preparation-config":
				prep.config += " "
			case "sealed-launch":
				prep.source.MultipleImportedLocalLaunch += " "
			case "saved-record":
				prep.source.DesktopLast = "foreign"
			case "mixed-mobile":
				prep.mobile = &nodeChainExecutionMobileProjection{chain: prep.local}
			}
			owner, meta, err := physical.ReadOriginalValidated(requested)
			if err == nil || owner != nil || !reflect.DeepEqual(meta, DesktopNodeChainMetadata{}) {
				t.Fatal("foreign or mutated native owner admitted", fault)
			}
		})
	}
}

func desktopMultipleImportedExecutionReadyFixture(t *testing.T, layout nodeChainImportedLayout, target, selected string) (*NodeChainExecutionProjection, DesktopNodeChainMultipleImportedExecutionReadyRecord, string) {
	t.Helper()
	_, prep, source := desktopMultipleImportedExecutionFixture(t, layout, target, "auto", 0)
	policy, err := NewNodeChainMultipleImportedExecutionPolicy(prep, startJSON(t, source))
	if err != nil {
		t.Fatal(err)
	}
	p, err := prep.BindExecution(policy)
	if err != nil {
		t.Fatal(err)
	}
	physical, err := p.MultipleImportedDesktopPhysicalPolicy()
	if err != nil {
		t.Fatal(err)
	}
	_, meta, capture, err := physical.PhysicalReadValidated()
	if err != nil {
		t.Fatal(err)
	}
	proofs, err := p.ProofInventory(selected)
	if err != nil {
		t.Fatal(err)
	}
	choice := routechoice.Candidate{Execution: routechoice.Execution(selected), Transport: "ordered-node-chain", EntryID: proofs[0].ProfileID, ExitID: proofs[len(proofs)-1].ProfileID}
	score, err := routechoice.Score(choice, 2*time.Millisecond, 4*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	progress := NodeChainExecutionProgress{NodeChainProgress: NodeChainProgress{Stage: "selected", Complete: true, Ready: true, Execution: selected, DNSProven: true, PublicProven: true}, Comparison: routechoice.Result{Target: Targets[0], Winner: &choice, Final: &score}}
	for _, proof := range proofs {
		row := NodeChainPrefixProgress{Position: proof.Position, ProfileID: proof.ProfileID, ResponseMS: 1.5, Proven: true}
		if proof.Kind == "public-path" {
			row.Kind, row.Label = "public-path", nodeChainMultipleImportedExecutionPublicLabel
		}
		progress.Prefixes = append(progress.Prefixes, row)
	}
	transfer, name := strings.Repeat("c", 64), "router-vpn"
	if target == "darwin" {
		name = "utun9"
	}
	return p, DesktopNodeChainMultipleImportedExecutionReadyRecord{Schema: 1, Kind: "routervpn-node-chain-multiple-imported-execution-ready-v1", SourceSHA256: meta.SourceSHA256, PreparationSourceSHA256: prep.SourceSHA256(), PreparationConfigSHA256: prep.ConfigSHA256(), TransferSHA256: transfer, DNSConfigSHA256: capture.SelectedDNS.ConfigSHA256, Identity: NodeChainIdentity{EngineID: "original-box", SessionID: meta.SessionID, NetworkID: "original-network", SourceSHA256: p.SourceSHA256(), ConfigSHA256: p.ConfigSHA256()}, SelectionEpoch: 3, Generation: 1, Reader: 1, InterfaceName: name, InterfaceIndex: 9, MTU: 1280, ObservedAt: time.Now().UnixMilli(), Progress: progress}, transfer
}

func TestDesktopMultipleImportedExecutionAdoptionAndReady(t *testing.T) {
	for index, layout := range multipleImportedServerLayouts {
		for _, selected := range []string{"local", "server"} {
			t.Run(layout.name+"/"+selected, func(t *testing.T) {
				child, ready, transfer := desktopMultipleImportedExecutionReadyFixture(t, layout, []string{"linux", "windows", "darwin"}[index%3], selected)
				parent, err := ParseDesktopNodeChainMultipleImportedExecutionPreparation(child.preparation.Source())
				if err != nil {
					t.Fatal(err)
				}
				record, err := NewDesktopNodeChainMultipleImportedExecutionAdoptionRecord(child, ready.Identity, transfer)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				projection, identity, err := ParseDesktopNodeChainMultipleImportedExecutionAdoptionRecord(raw, parent, transfer)
				if err != nil || projection.Config() != child.Config() || identity != ready.Identity {
					t.Fatal("original parent adoption", err)
				}
				owner, _ := projection.MultipleImportedDesktopPhysicalPolicy()
				expected, _ := parent.MultipleImportedDesktopPhysicalPolicy()
				foreign, _ := child.MultipleImportedDesktopPhysicalPolicy()
				if owner != expected || owner == foreign {
					t.Fatal("child physical authority substituted")
				}
				heartbeat, err := CanonicalDesktopNodeChainMultipleImportedExecutionReadyRecord(ready, child, transfer)
				if err != nil {
					t.Fatal("complete selected proof inventory", err)
				}
				if _, err := ParseDesktopNodeChainMultipleImportedExecutionAdoptedReadyRecord(heartbeat, projection, identity, transfer); err != nil {
					t.Fatal(err)
				}
				if _, err := ParseDesktopNodeChainExecutionAdoptedReadyRecord(heartbeat, projection, identity, transfer); err == nil {
					t.Fatal("generic heartbeat parser accepted typed source")
				}
				identity.EngineID = "replacement-box"
				if _, err := ParseDesktopNodeChainMultipleImportedExecutionAdoptedReadyRecord(heartbeat, projection, identity, transfer); err == nil {
					t.Fatal("replaced native Box admitted")
				}
				record.Request.Users[0].Password = "caller-mutated"
				if child.validateCapture() != nil {
					t.Fatal("receipt aliased source credentials")
				}
			})
		}
	}
}

func TestDesktopMultipleImportedExecutionReadyRefusals(t *testing.T) {
	p, original, transfer := desktopMultipleImportedExecutionReadyFixture(t, multipleImportedServerLayouts[4], "linux", "server")
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	faults := []string{"kind", "source", "preparation", "config", "physical", "dns", "epoch", "reader", "generation", "interface", "mtu", "unready", "missing-prefix", "foreign-prefix", "target", "score", "ineligible"}
	for _, position := range multipleImportedServerLayouts[4].positions {
		for _, fault := range []string{"kind", "label", "unproved", "nonfinite"} {
			faults = append(faults, fmt.Sprintf("public-%d-%s", position, fault))
		}
	}
	for _, fault := range faults {
		t.Run(fault, func(t *testing.T) {
			var r DesktopNodeChainMultipleImportedExecutionReadyRecord
			if json.Unmarshal(encoded, &r) != nil {
				t.Fatal("fixture copy")
			}
			switch fault {
			case "kind":
				r.Kind = "routervpn-node-chain-execution-ready-v1"
			case "source":
				r.Identity.SourceSHA256 = r.PreparationSourceSHA256
			case "preparation":
				r.PreparationSourceSHA256 = r.Identity.SourceSHA256
			case "config":
				r.Identity.ConfigSHA256 = r.PreparationConfigSHA256
			case "physical":
				r.SourceSHA256 = strings.Repeat("f", 64)
			case "dns":
				r.DNSConfigSHA256 = strings.Repeat("f", 64)
			case "epoch":
				r.SelectionEpoch = 0
			case "reader":
				r.Reader = 0
			case "generation":
				r.Generation = 0
			case "interface":
				r.InterfaceName = "utun9"
			case "mtu":
				r.MTU = 9000
			case "unready":
				r.Progress.Ready = false
			case "missing-prefix":
				r.Progress.Prefixes = r.Progress.Prefixes[:len(r.Progress.Prefixes)-1]
			case "foreign-prefix":
				r.Progress.Prefixes[2].Kind = "public-path"
			case "target":
				r.Progress.Comparison.Target = "127.0.0.1"
			case "score":
				*r.Progress.Comparison.Final.ScoreMS = 2
			case "ineligible":
				r.Progress.Comparison.Final.Eligible = false
			default:
				var position int
				var name string
				if _, err := fmt.Sscanf(fault, "public-%d-%s", &position, &name); err != nil {
					t.Fatal(err)
				}
				row := &r.Progress.Prefixes[position]
				switch name {
				case "kind":
					row.Kind = "private-node"
				case "label":
					row.Label = "ICMP ping"
				case "unproved":
					row.Proven = false
				case "nonfinite":
					row.ResponseMS = math.NaN()
				}
			}
			if r.Validate(p, transfer) == nil {
				t.Fatal("altered selected proof accepted", fault)
			}
		})
	}
}

func TestDesktopMultipleImportedExecutionSavedChoiceBinding(t *testing.T) {
	for _, selected := range []string{"local", "server"} {
		t.Run(selected, func(t *testing.T) {
			p, _, _ := desktopMultipleImportedExecutionReadyFixture(t, multipleImportedServerLayouts[4], "darwin", selected)
			prep, source := p.preparation, p.policy.source
			digest, err := source.Server.Digest()
			if err != nil {
				t.Fatal(err)
			}
			last := NodeChainExecutionLast{record: nodeChainExecutionLastRecord{Schema: 1, LocalSourceSHA256: prep.LocalSourceSHA256(), LocalInputSHA256: externalDigest([]byte(prep.LocalSource())), Setting: p.Execution(), Execution: selected, Target: Targets[0], Descriptor: source.Server, DescriptorSHA256: digest, DNSPolicySHA256: source.Request.DNSPolicySHA256, EntryHost: p.policy.front.Host, Peer: source.Request.Peer, FirstPort: source.FirstPort, LastPort: source.LastPort, Port: source.Request.Port, DesktopTargetOS: "darwin"}}
			last.record.Digest = nodeChainExecutionLastDigest(last.record)
			raw, _ := json.Marshal(last.record)
			last.raw = string(raw)
			if err := last.ValidateMultipleImportedDesktopProjection(p); err != nil {
				t.Fatal(err)
			}
			fresh, err := NewDesktopNodeChainPolicy(prep.multiple.source, strings.Repeat("f", 32), "darwin", 1280)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := NewDesktopNodeChainMultipleImportedExecutionLastPreparation(fresh, "auto", last.JSON())
			if err != nil {
				t.Fatal("saved selected choice", err)
			}
			saved, present, err := restored.MultipleImportedDesktopLast()
			if err != nil || !present || saved.JSON() != last.JSON() || saved.Execution() != selected {
				t.Fatal("restore changed proved choice or target", err)
			}
			parsed, err := ParseDesktopNodeChainMultipleImportedExecutionPreparation(restored.Source())
			if err != nil || parsed.Config() != restored.Config() {
				t.Fatal("restoring child source", err)
			}
			if _, _, err := restored.DesktopLast(); err == nil {
				t.Fatal("generic restore accepted typed source")
			}
			for _, owner := range []*NodeChainExecutionPreparation{restored, parsed} {
				snapshot := owner.multiple.originalSeal
				if !snapshot.matches(owner) || snapshot.seal != owner.captureMultipleImportedDesktopSeal() {
					t.Fatal("saved choice lost the canonical snapshot of its final private source")
				}
				owner.source.DesktopLast += " "
				if snapshot.matches(owner) || owner.captureSeal() == owner.seal || owner.validateCapture() == nil {
					t.Fatal("changed saved choice reused original physical preparation digest")
				}
			}
		})
	}
}

func TestDesktopMultipleImportedExecutionSourceRefusals(t *testing.T) {
	_, prep, _ := desktopMultipleImportedExecutionFixture(t, multipleImportedServerLayouts[1], "linux", "auto", 0)
	for _, fault := range []string{"schema", "setting", "source", "launch", "raw-launch", "desktop", "generic", "openvpn", "target", "session", "physical", "mtu", "prefix", "unknown"} {
		t.Run(fault, func(t *testing.T) {
			var source NodeChainExecutionPreparationSource
			if json.Unmarshal([]byte(prep.Source()), &source) != nil {
				t.Fatal("fixture copy")
			}
			switch fault {
			case "schema":
				source.Schema = 1
			case "setting":
				source.Execution = "local"
			case "source":
				source.LocalSource += " "
			case "launch":
				source.MultipleImportedLocalLaunch += " "
			case "raw-launch":
				source.MultipleImportedLocalLaunch = source.LocalSource
			case "desktop":
				source.DesktopMultipleImported = nil
			case "generic":
				source.Desktop = source.DesktopMultipleImported
			case "openvpn":
				source.DesktopOpenVPN = source.DesktopMultipleImported
			case "target":
				source.DesktopMultipleImported.TargetOS = "darwin"
			case "session":
				source.DesktopMultipleImported.SessionID = strings.Repeat("f", 32)
			case "physical":
				source.DesktopMultipleImported.ConfigSHA256 = strings.Repeat("a", 64)
			case "mtu":
				source.DesktopMultipleImported.RestoredMTU = 1400
			case "prefix":
				source.DesktopMultipleImported.Prefixes[1].SourceSHA256 = strings.Repeat("b", 64)
			}
			raw, err := json.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "unknown" {
				raw = append([]byte(`{"extra":true,`), raw[1:]...)
			}
			if _, err := ParseDesktopNodeChainMultipleImportedExecutionPreparation(string(raw)); err == nil {
				t.Fatal("altered original preparation admitted", fault)
			}
		})
	}
}

func TestDesktopMultipleImportedExecutionAdoptionRefusals(t *testing.T) {
	p, ready, transfer := desktopMultipleImportedExecutionReadyFixture(t, multipleImportedServerLayouts[4], "linux", "server")
	original, err := NewDesktopNodeChainMultipleImportedExecutionAdoptionRecord(p, ready.Identity, transfer)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"schema", "kind", "preparation-source", "preparation-config", "physical", "transfer", "config", "session", "members", "packet-position", "public-identity", "credential", "port", "whitespace"} {
		t.Run(fault, func(t *testing.T) {
			var r DesktopNodeChainMultipleImportedExecutionAdoptionRecord
			if json.Unmarshal(encoded, &r) != nil {
				t.Fatal("fixture copy")
			}
			switch fault {
			case "schema":
				r.Schema++
			case "kind":
				r.Kind = "routervpn-node-chain-execution-adoption-v1"
			case "preparation-source":
				r.PreparationSourceSHA256 = r.Identity.SourceSHA256
			case "preparation-config":
				r.PreparationConfigSHA256 = r.Identity.ConfigSHA256
			case "physical":
				r.PhysicalSourceSHA256 = strings.Repeat("a", 64)
			case "transfer":
				r.TransferSHA256 = strings.Repeat("b", 64)
			case "config":
				r.Identity.ConfigSHA256 = r.PreparationConfigSHA256
			case "session":
				r.Identity.SessionID = "replacement"
			case "members":
				r.Server.Members = r.Server.Members[:len(r.Server.Members)-1]
			case "packet-position":
				r.Request.LocalPacketPositions[0] = 1
			case "public-identity":
				r.Server.Members[0].NodeID = "foreign-private-node"
			case "credential":
				r.Request.Users[0].Password = "malformed"
			case "port":
				r.Request.Port = r.LastPort + 1
			}
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "whitespace" {
				raw = append(raw, '\n')
			}
			if _, _, err := ParseDesktopNodeChainMultipleImportedExecutionAdoptionRecord(raw, p.preparation, transfer); err == nil {
				t.Fatal("foreign or incomplete original handoff admitted", fault)
			}
		})
	}
}

func TestDesktopMultipleImportedFinalPhysicalSeal(t *testing.T) {
	for _, kind := range []string{"original", "physical-source", "config", "proof", "private-profile", "physical-root"} {
		t.Run(kind, func(t *testing.T) {
			original, prep, _ := desktopMultipleImportedExecutionFixture(t, multipleImportedServerLayouts[2], "linux", "server", 0)
			c := original.chain
			if c.importedNodes == nil || !c.importedNodes.localSeal.matches(c) || c.importedNodes.localSeal.seal != c.seal || c.projection.Kind != nodeChainDesktopPhysicalKind || prep.validateCapture() != nil {
				t.Fatal("final original physical graph is missing its verified canonical snapshot")
			}
			switch kind {
			case "original":
				saved := c.importedNodes.localSeal
				c.importedNodes.localSeal = nil
				recomputed := c.captureSeal()
				c.importedNodes.localSeal = saved
				if recomputed != c.seal {
					t.Fatal("physical snapshot differs from fresh canonical encoding")
				}
				return
			case "physical-source":
				c.projection.PhysicalSourceSHA256 = strings.Repeat("a", 64)
			case "config":
				c.config += " "
			case "proof":
				c.proofs[0].Tag += "-foreign"
			case "private-profile":
				c.nodes[0].profile["changed-fixture-field"] = true
			case "physical-root":
				original.metadata.Roots[0].DerivedSHA256 = strings.Repeat("b", 64)
			}
			if prep.validateCapture() == nil || original.Validate() == nil {
				t.Fatal("changed original physical graph retained seal authority")
			}
		})
	}
}

func TestDesktopMultipleImportedConstructionFreshRead(t *testing.T) {
	for _, kind := range []string{"original", "preparation", "policy", "source", "native", "config", "physical-metadata", "mutable-prefix", "mutable-root", "mixed-connect"} {
		t.Run(kind, func(t *testing.T) {
			policy, prep, _ := desktopMultipleImportedExecutionFixture(t, multipleImportedServerLayouts[2], "linux", "server", 0)
			physical, err := prep.MultipleImportedDesktopPhysicalPolicy()
			if err != nil {
				t.Fatal(err)
			}
			source, native := policy.original, policy.chain
			config, metadata, _, err := physical.PhysicalReadValidated()
			if err != nil {
				t.Fatal(err)
			}
			cache := prep.multiple.originalSeal
			if !cache.matches(prep) || cache.seal != prep.captureMultipleImportedDesktopSeal() {
				t.Fatal("desktop preparation did not retain its exact canonical seal")
			}
			switch kind {
			case "preparation":
				copy := *prep
				prep = &copy
			case "policy":
				copy := *policy
				policy = &copy
			case "source":
				copy := *source
				source = &copy
			case "native":
				copy := *native
				native = &copy
			case "config":
				config += " "
			case "physical-metadata":
				metadata.SourceSHA256 = strings.Repeat("a", 64)
			case "mutable-prefix":
				prep.source.DesktopMultipleImported.Prefixes[0].Tag += "-changed"
			case "mutable-root":
				prep.source.DesktopMultipleImported.Roots[0].DerivedSHA256 = strings.Repeat("b", 64)
			case "mixed-connect":
				prep.connect = &nodeChainCONNECTExecutionBinding{}
			}
			if kind == "mutable-prefix" || kind == "mutable-root" {
				if cache.matches(prep) || prep.captureSeal() == prep.seal {
					t.Fatal("mutated physical metadata reused its original canonical digest")
				}
			}
			err = physical.ValidateConstruction(prep, policy, source, native, config, metadata)
			if (err == nil) != (kind == "original") {
				t.Fatal("construction admitted changed original owner or physical input", err)
			}
		})
	}
}
