package mobilemultihop

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func desktopCONNECTExecutionFixture(t *testing.T, mode, protocol, target, execution string) (*DesktopNodeChainCONNECTPolicy, *NodeChainExecutionPreparation) {
	t.Helper()
	input := nodeChainCONNECTFixture(t, mode, protocol, "", NativeStartLayerMethod, "password")
	source, err := NewNodeChainCONNECTSource(startJSON(t, input))
	if err != nil {
		t.Fatal(err)
	}
	original, err := NewDesktopNodeChainCONNECTPolicy(source, strings.Repeat("c", 32), target, 0)
	if err != nil {
		t.Fatal(err)
	}
	prep, err := NewDesktopNodeChainCONNECTExecutionPreparation(original, execution)
	if err != nil {
		t.Fatal("typed desktop preparation", err)
	}
	return original, prep
}

func TestDesktopCONNECTExecutionSourceReadRetainsOriginal(t *testing.T) {
	for _, protocol := range []string{"http-connect", "https-connect"} {
		for _, fault := range []string{"original", "nil-preparation", "equal-preparation", "copied-preparation", "copied-physical", "changed-source", "changed-policy", "changed-physical"} {
			t.Run(protocol+"/"+fault, func(t *testing.T) {
				original, prep := desktopCONNECTExecutionFixture(t, "wg", protocol, "linux", "auto")
				physical, err := prep.CONNECTDesktopPhysicalPolicy()
				if err != nil {
					t.Fatal(err)
				}
				requested := prep
				switch fault {
				case "nil-preparation":
					requested = nil
				case "equal-preparation":
					requested, err = NewDesktopNodeChainCONNECTExecutionPreparation(original, "auto")
					if err != nil || requested.Source() != prep.Source() {
						t.Fatal("fixture lost byte-identical independent preparation", err)
					}
				case "copied-preparation":
					copy := *prep
					requested = &copy
				case "copied-physical":
					copy := *physical
					physical = &copy
				case "changed-source":
					original.original.sourceJSON += " "
				case "changed-policy":
					original.inputs.restoredMTU = 1300
				case "changed-physical":
					physical.owner.capture.ConfiguredMTU = 1300
				}
				owner, meta, err := physical.ReadOriginalValidated(requested)
				if fault != "original" {
					if err == nil || owner != nil || !reflect.DeepEqual(meta, DesktopNodeChainMetadata{}) {
						t.Fatal("CONNECT source read lent replaced or altered authority", fault, err)
					}
					return
				}
				if err != nil || owner != original || meta.SourceSHA256 != original.metadata.SourceSHA256 || len(meta.Prefixes) != 3 || len(meta.Roots) == 0 {
					t.Fatal("CONNECT source read lost original source or metadata", err)
				}
				meta.Prefixes[0].ProfileID = "caller-replacement"
				meta.Roots[0].Tag = "caller-replacement"
				owner, again, err := physical.ReadOriginalValidated(prep)
				if err != nil || owner != original || !reflect.DeepEqual(again, original.metadata.DesktopNodeChainMetadata) {
					t.Fatal("CONNECT metadata read lent original mutable slices", err)
				}
			})
		}
	}
}
func TestDesktopCONNECTExecutionOriginalPhysical(t *testing.T) {
	for ti, target := range []string{"linux", "windows", "darwin"} {
		for pi, protocol := range []string{"http-connect", "https-connect"} {
			for ei, execution := range []string{"server", "auto"} {
				mode := []string{"wg", "awg2-fast", "awg2-strong"}[(ti+pi+ei)%3]
				t.Run(target+"/"+mode+"/"+protocol+"/"+execution, func(t *testing.T) {
					original, p := desktopCONNECTExecutionFixture(t, mode, protocol, target, execution)
					physical, err := p.CONNECTDesktopPhysicalPolicy()
					if err != nil {
						t.Fatal(err)
					}
					owner, err := physical.OriginalDesktopCONNECTPolicy()
					if err != nil || owner != original {
						t.Fatal("foreign desktop owner")
					}
					native, err := p.OriginalCONNECTSource()
					if err != nil || native != original.native || p.local.nodes[0] != original.original.pair.nodes[0] || p.local.nodes[2] != original.original.pair.nodes[1] {
						t.Fatal("foreign original native/prefix/final")
					}
					config, meta, capture, err := physical.PhysicalReadValidated()
					if err != nil || config != p.Config() || meta.Kind != "node-chain-connect-execution" || meta.TargetOS != target || meta.SessionID != original.inputs.sessionID || meta.SourceSHA256 != original.metadata.SourceSHA256 || capture.SelectedDNS.Physical || capture.SelectedDNS.Detour != SelectorTag {
						t.Fatal("physical scope changed", err)
					}
					_, _, before, err := original.PhysicalReadValidated()
					if err != nil || !reflect.DeepEqual(capture.PhysicalRoots, before.PhysicalRoots) || !reflect.DeepEqual(capture.PrivateDestinations, before.PrivateDestinations) || capture.ConfiguredMTU != before.ConfiguredMTU {
						t.Fatal("physical roots or MTU changed")
					}
					graph := externalTestRead(t, config)
					if graph["route"].(map[string]any)["final"] != NodeChainExecutionGateTag {
						t.Fatal("open preparation")
					}
					if _, err = p.DesktopPhysicalPolicy(); err == nil {
						t.Fatal("typed preparation borrowed paired physical wrapper")
					}
					if _, err = ParseNodeChainExecutionPreparation(p.Source()); err == nil {
						t.Fatal("generic parser admitted typed desktop")
					}
					if _, err = ParseNodeChainCONNECTExecutionPreparation(p.Source()); err == nil {
						t.Fatal("mobile parser admitted typed desktop")
					}
					q, err := ParseDesktopNodeChainCONNECTExecutionPreparation(p.Source())
					if err != nil || q.Config() != p.Config() || q.Source() != p.Source() || q.connect.source == p.connect.source || q.connect.desktop.original == original {
						t.Fatal("typed parse lost independent original construction", err)
					}
					capture.PhysicalRoots[0].Tag = "foreign"
					_, _, again, err := physical.PhysicalReadValidated()
					if err != nil || again.PhysicalRoots[0].Tag == "foreign" {
						t.Fatal("readback lent mutable capture")
					}
				})
			}
		}
	}
}
func TestDesktopCONNECTExecutionForeignCaptureRefused(t *testing.T) {
	for _, fault := range []string{"policy", "native", "source", "self", "preparation", "binding", "physical", "session", "target", "mtu", "metadata", "selected-dns", "lower-root", "source-metadata"} {
		t.Run(fault, func(t *testing.T) {
			original, p := desktopCONNECTExecutionFixture(t, "wg", "https-connect", "windows", "auto")
			d := p.connect.desktop
			physical := d.physical
			switch fault {
			case "policy":
				fresh, err := NewDesktopNodeChainCONNECTPolicy(original.original, original.inputs.sessionID, "windows", 0)
				if err != nil {
					t.Fatal(err)
				}
				d.original = fresh
			case "native":
				copy := *d.native
				d.native = &copy
			case "source":
				fresh, err := NewNodeChainCONNECTSource(d.source.sourceJSON)
				if err != nil {
					t.Fatal(err)
				}
				d.source = fresh
			case "self":
				copy := *d
				p.connect.desktop = &copy
			case "preparation":
				copy := *p
				d.preparation = &copy
			case "binding":
				copy := *p.connect
				d.binding = &copy
			case "physical":
				copy := *d.physical
				d.physical = &copy
			case "session":
				original.inputs.sessionID = strings.Repeat("d", 32)
			case "target":
				original.inputs.targetOS = "linux"
			case "mtu":
				original.inputs.restoredMTU = 1280
			case "metadata":
				d.metadata.TargetOS = "linux"
			case "selected-dns":
				d.capture.SelectedDNS.Physical = true
			case "lower-root":
				d.capture.PhysicalRoots[0].Tag = "foreign"
			case "source-metadata":
				p.source.DesktopCONNECT.SessionID = strings.Repeat("d", 32)
			}
			if p.validateCapture() == nil || physical.Validate() == nil {
				t.Fatal("foreign desktop CONNECT owner accepted", fault)
			}
		})
	}
}
func TestDesktopCONNECTExecutionSerializedDerivationRefused(t *testing.T) {
	_, p := desktopCONNECTExecutionFixture(t, "wg", "https-connect", "windows", "server")
	for _, fault := range []string{"missing", "paired", "target", "session", "mtu", "local", "last"} {
		t.Run(fault, func(t *testing.T) {
			var value NodeChainExecutionPreparationSource
			if json.Unmarshal([]byte(p.Source()), &value) != nil {
				t.Fatal("source")
			}
			switch fault {
			case "missing":
				value.DesktopCONNECT = nil
			case "paired":
				value.Desktop = &DesktopNodeChainMetadata{}
			case "target":
				value.DesktopCONNECT.TargetOS = "ios"
			case "session":
				value.DesktopCONNECT.SessionID = strings.Repeat("d", 32)
			case "mtu":
				value.DesktopCONNECT.RestoredMTU = 1280
			case "local":
				value.Execution = "local"
			case "last":
				value.DesktopLast = "foreign"
			}
			if _, err := ParseDesktopNodeChainCONNECTExecutionPreparation(startJSON(t, value)); err == nil {
				t.Fatal("uncaptured desktop derivation accepted", fault)
			}
		})
	}
}
func TestDesktopCONNECTExecutionOriginalTransition(t *testing.T) {
	source := connectExecutionFixtureSource(t, "auto")
	original, err := NewNodeChainCONNECTSource(source.LocalSource)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewDesktopNodeChainCONNECTPolicy(original, strings.Repeat("e", 32), "windows", 0)
	if err != nil {
		t.Fatal(err)
	}
	prep, err := NewDesktopNodeChainCONNECTExecutionPreparation(policy, "auto")
	if err != nil {
		t.Fatal(err)
	}
	execution, err := NewNodeChainCONNECTExecutionPolicy(prep, startJSON(t, source))
	if err != nil {
		t.Fatal("desktop execution projection", err)
	}
	projection, err := prep.BindExecution(execution)
	if err != nil {
		t.Fatal("original desktop transition", err)
	}
	originalPhysical, _ := prep.CONNECTDesktopPhysicalPolicy()
	physical, err := projection.CONNECTDesktopPhysicalPolicy()
	if err != nil || physical != originalPhysical {
		t.Fatal("transition replaced physical owner", err)
	}
	transition, err := projection.Transition()
	if err != nil || transition.PreparationConfigSHA256 != prep.ConfigSHA256() || transition.EntryTag != policy.native.metadata.Proofs[0].Tag {
		t.Fatal("transition source", err)
	}
}

func TestDesktopCONNECTExecutionExactPhysicalAnalysis(t *testing.T) {
	original, p := desktopCONNECTExecutionFixture(t, "awg2-fast", "https-connect", "darwin", "auto")
	d := p.connect.desktop
	tag := p.ProofInventory()[0].Tag
	baseline := externalTestRead(t, original.native.config)
	baseline["route"].(map[string]any)["final"] = d.native.metadata.Proofs[2].Tag
	if _, err := d.physicalEgress(startJSON(t, baseline), tag); err != nil {
		t.Fatal("original captured physical analysis", err)
	}
	for _, fault := range []string{"root", "wrapper", "service", "final-uot", "extra-root", "foreign-entry"} {
		t.Run(fault, func(t *testing.T) {
			graph := externalTestRead(t, startJSON(t, baseline))
			entry := tag
			switch fault {
			case "root":
				root := d.metadata.Roots[0]
				for _, raw := range graph[root.Family].([]any) {
					row := raw.(map[string]any)
					if row["tag"] == root.Tag {
						row["detour"] = "foreign"
					}
				}
			case "wrapper":
				externalTestFind(t, graph, DesktopNodePhysicalTag)["session_id"] = strings.Repeat("f", 32)
			case "service":
				graph["services"].([]any)[0].(map[string]any)["source_sha256"] = strings.Repeat("f", 64)
			case "final-uot":
				delete(externalTestFind(t, graph, d.native.metadata.Proofs[2].Tag), "udp_over_tcp")
			case "extra-root":
				graph["outbounds"] = append(graph["outbounds"].([]any), map[string]any{"type": "direct", "tag": DesktopNodePhysicalTag})
			case "foreign-entry":
				entry = d.native.metadata.Proofs[2].Tag
			}
			if _, err := d.physicalEgress(startJSON(t, graph), entry); err == nil {
				t.Fatal("changed physical owner accepted", fault)
			}
		})
	}
}
